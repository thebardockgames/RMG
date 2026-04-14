/*
 * Rosalie's Mupen GUI - https://github.com/Rosalie241/RMG
 *  Copyright (C) 2020-2026 Rosalie Wanders <rosalie@mailbox.org>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 3.
 *  You should have received a copy of the GNU General Public License
 *  along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
#define CORE_INTERNAL
#include "Debugger.hpp"

#include "Emulation.hpp"
#include "Error.hpp"
#include "Library.hpp"
#include "Settings.hpp"

#include "m64p/Api.hpp"
#include "m64p/api/m64p_types.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <optional>
#include <set>
#include <sstream>
#include <thread>

namespace
{
constexpr uint32_t kMaxRdramSize = UINT32_C(0x00800000);
constexpr uint32_t kMinInstructionSize = UINT32_C(4);
constexpr uint32_t kMaxEventBatchSize = UINT32_C(1024);
constexpr uint32_t kMaxWatchpointSnapshotBytes = UINT32_C(64);
constexpr uint32_t kDefaultInstructionTraceMaxRecords = UINT32_C(2000000);
constexpr uint32_t kMaxInstructionTraceBatchSize = UINT32_C(50000);
constexpr size_t kMaxQueuedEvents = 4096;
constexpr uint64_t kViEventThrottleMs = 250;

std::mutex g_breakpointMutex;
std::vector<CoreDebuggerBreakpoint> g_managedBreakpoints;
std::mutex g_symbolMutex;
std::vector<CoreDebuggerSymbol> g_symbols;
std::set<std::string> g_symbolSources;
std::mutex g_eventMutex;
std::deque<CoreDebuggerEvent> g_events;
uint64_t g_nextEventId = 1;
std::mutex g_instructionTraceMutex;
std::vector<CoreDebuggerInstructionTraceRecord> g_instructionTrace;
CoreDebuggerInstructionTraceStatus g_instructionTraceStatus;
uint32_t g_instructionTraceMaxRecords = 0;
uint32_t g_lastCallbackPc = 0;
int g_lastObservedRunState = -1;
uint32_t g_lastTriggeredAddress = 0;
uint32_t g_lastTriggeredFlags = 0;
uint32_t g_lastTriggeredPc = 0;
uint64_t g_lastViEventTimestampMs = 0;
bool g_breakpointEventsArmed = false;
bool g_debuggerCallbacksConfigured = false;

std::string trim_copy(const std::string& text)
{
    size_t begin = 0;
    while (begin < text.size() &&
           std::isspace(static_cast<unsigned char>(text[begin])))
    {
        begin++;
    }

    size_t end = text.size();
    while (end > begin &&
           std::isspace(static_cast<unsigned char>(text[end - 1])))
    {
        end--;
    }

    return text.substr(begin, end - begin);
}

std::vector<std::string> split_whitespace(const std::string& text)
{
    std::istringstream stream(text);
    std::vector<std::string> tokens;
    std::string token;
    while (stream >> token)
    {
        tokens.push_back(token);
    }

    return tokens;
}

bool looks_like_hex_token(const std::string& token)
{
    if (token.empty())
    {
        return false;
    }

    size_t offset = 0;
    if (token.size() > 2 &&
        token[0] == '0' &&
        (token[1] == 'x' || token[1] == 'X'))
    {
        offset = 2;
    }

    if ((token.size() - offset) < 6)
    {
        return false;
    }

    for (size_t index = offset; index < token.size(); index++)
    {
        if (!std::isxdigit(static_cast<unsigned char>(token[index])))
        {
            return false;
        }
    }

    return true;
}

bool try_parse_hex_address_token(const std::string& token, uint32_t* value)
{
    if (value == nullptr ||
        !looks_like_hex_token(token))
    {
        return false;
    }

    std::string normalized = token;
    if (normalized.size() > 2 &&
        normalized[0] == '0' &&
        (normalized[1] == 'x' || normalized[1] == 'X'))
    {
        normalized = normalized.substr(2);
    }

    try
    {
        unsigned long long parsedValue = std::stoull(normalized, nullptr, 16);
        *value = static_cast<uint32_t>(parsedValue & UINT32_C(0xffffffff));
        return true;
    }
    catch (const std::exception&)
    {
        return false;
    }
}

bool parse_symbol_assignment(const std::vector<std::string>& tokens, CoreDebuggerSymbol* symbol)
{
    if (symbol == nullptr ||
        tokens.size() < 3 ||
        tokens[1] != "=")
    {
        return false;
    }

    uint32_t address = 0;
    if (!try_parse_hex_address_token(tokens[2], &address))
    {
        return false;
    }

    symbol->address = address;
    symbol->name = tokens[0];
    return true;
}

bool parse_symbol_row(const std::vector<std::string>& tokens, CoreDebuggerSymbol* symbol)
{
    if (symbol == nullptr ||
        tokens.size() < 2)
    {
        return false;
    }

    uint32_t address = 0;
    if (!try_parse_hex_address_token(tokens[0], &address))
    {
        return false;
    }

    std::string name;
    if (tokens.size() >= 3 &&
        tokens[1].size() == 1 &&
        std::isalpha(static_cast<unsigned char>(tokens[1][0])))
    {
        name = tokens[2];
    }
    else
    {
        name = tokens.back();
    }

    if (name.empty() ||
        looks_like_hex_token(name))
    {
        return false;
    }

    symbol->address = address;
    symbol->name = name;
    return true;
}

bool parse_symbol_line(const std::string& line, const std::string& source, CoreDebuggerSymbol* symbol)
{
    if (symbol == nullptr)
    {
        return false;
    }

    std::string sanitized = line;
    for (const std::string& marker : {std::string("//"), std::string("#"), std::string(";")})
    {
        size_t markerIndex = sanitized.find(marker);
        if (markerIndex != std::string::npos)
        {
            sanitized = sanitized.substr(0, markerIndex);
        }
    }

    sanitized = trim_copy(sanitized);
    if (sanitized.empty())
    {
        return false;
    }

    std::vector<std::string> tokens = split_whitespace(sanitized);
    if (tokens.empty())
    {
        return false;
    }

    CoreDebuggerSymbol parsedSymbol;
    bool parsed = parse_symbol_assignment(tokens, &parsedSymbol) ||
                  parse_symbol_row(tokens, &parsedSymbol);
    if (!parsed)
    {
        return false;
    }

    parsedSymbol.source = source;
    *symbol = std::move(parsedSymbol);
    return true;
}

void push_debugger_event(const std::string& type,
                         const std::string& message,
                         int runState,
                         uint32_t pc,
                         uint32_t address,
                         uint32_t endAddress,
                         uint32_t flags,
                         uint32_t rangeAddress = 0);
void set_error_from_m64p(const std::string& prefix, m64p_error ret);
bool set_debugger_trace_enabled(bool enabled);
uint64_t monotonic_timestamp_us(void);
uint32_t classify_trace_record_flags(uint32_t pc, uint32_t word, uint32_t* branchTarget, bool* hasBranchTarget);
void capture_instruction_trace_record(uint32_t pc);

bool capture_event_register_snapshot(CoreDebuggerEvent::RegisterSnapshot* snapshot)
{
    if (snapshot == nullptr)
    {
        return false;
    }

    *snapshot = {};
    const std::array<std::pair<const char*, uint64_t*>, 35> registers = {
        std::pair{"pc", &snapshot->pc},
        std::pair{"zero", &snapshot->zero},
        std::pair{"at", &snapshot->at},
        std::pair{"hi", &snapshot->hi},
        std::pair{"lo", &snapshot->lo},
        std::pair{"ra", &snapshot->ra},
        std::pair{"sp", &snapshot->sp},
        std::pair{"gp", &snapshot->gp},
        std::pair{"s8", &snapshot->fp},
        std::pair{"a0", &snapshot->a0},
        std::pair{"a1", &snapshot->a1},
        std::pair{"a2", &snapshot->a2},
        std::pair{"a3", &snapshot->a3},
        std::pair{"v0", &snapshot->v0},
        std::pair{"v1", &snapshot->v1},
        std::pair{"s0", &snapshot->s0},
        std::pair{"s1", &snapshot->s1},
        std::pair{"s2", &snapshot->s2},
        std::pair{"s3", &snapshot->s3},
        std::pair{"s4", &snapshot->s4},
        std::pair{"s5", &snapshot->s5},
        std::pair{"s6", &snapshot->s6},
        std::pair{"s7", &snapshot->s7},
        std::pair{"t0", &snapshot->t0},
        std::pair{"t1", &snapshot->t1},
        std::pair{"t2", &snapshot->t2},
        std::pair{"t3", &snapshot->t3},
        std::pair{"t4", &snapshot->t4},
        std::pair{"t5", &snapshot->t5},
        std::pair{"t6", &snapshot->t6},
        std::pair{"t7", &snapshot->t7},
        std::pair{"t8", &snapshot->t8},
        std::pair{"t9", &snapshot->t9},
        std::pair{"k0", &snapshot->k0},
        std::pair{"k1", &snapshot->k1},
    };

    for (const auto& [name, value] : registers)
    {
        if (!CoreDebuggerReadCpuRegister(name, *value))
        {
            *snapshot = {};
            return false;
        }
    }

    snapshot->valid = true;
    return true;
}

bool capture_event_memory_snapshot(uint32_t startAddress,
                                   uint32_t endAddress,
                                   CoreDebuggerEvent::MemorySnapshot* snapshot)
{
    if (snapshot == nullptr)
    {
        return false;
    }

    *snapshot = {};
    if (endAddress < startAddress)
    {
        return false;
    }

    const uint64_t requestedSize = static_cast<uint64_t>(endAddress) - static_cast<uint64_t>(startAddress) + 1ULL;
    const uint32_t readSize = static_cast<uint32_t>(std::min<uint64_t>(requestedSize, kMaxWatchpointSnapshotBytes));

    std::vector<uint8_t> bytes;
    if (!CoreDebuggerReadMemory(startAddress, readSize, bytes))
    {
        return false;
    }

    snapshot->valid = true;
    snapshot->truncated = requestedSize > readSize;
    snapshot->address = startAddress;
    snapshot->endAddress = static_cast<uint32_t>(startAddress + readSize - 1);
    snapshot->bytes = std::move(bytes);
    return true;
}

bool lookup_managed_breakpoint_range(uint32_t address, uint32_t flags, CoreDebuggerBreakpoint* breakpoint)
{
    if (breakpoint == nullptr)
    {
        return false;
    }

    std::scoped_lock lock(g_breakpointMutex);

    bool found = false;
    uint32_t bestSize = UINT32_MAX;
    const uint32_t kindMask = flags & (M64P_BKP_FLAG_EXEC | M64P_BKP_FLAG_READ | M64P_BKP_FLAG_WRITE);
    for (const CoreDebuggerBreakpoint& candidate : g_managedBreakpoints)
    {
        if (address < candidate.address || address > candidate.endAddress)
        {
            continue;
        }

        if (kindMask != 0 && (candidate.flags & kindMask) == 0)
        {
            continue;
        }

        const uint32_t candidateSize = candidate.endAddress - candidate.address;
        if (!found || candidateSize < bestSize)
        {
            *breakpoint = candidate;
            bestSize = candidateSize;
            found = true;
        }
    }

    return found;
}

void push_debugger_event(const std::string& type,
                         const std::string& message,
                         int runState,
                         uint32_t pc,
                         uint32_t address,
                         uint32_t endAddress,
                         uint32_t flags,
                         uint32_t rangeAddress)
{
    CoreDebuggerEvent event;
    event.timestampMs = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                                  std::chrono::system_clock::now().time_since_epoch())
                                                  .count());
    event.type = type;
    event.message = message;
    event.runState = runState;
    event.pc = pc;
    event.address = address;
    event.rangeAddress = rangeAddress == 0 ? address : rangeAddress;
    event.endAddress = endAddress;
    event.flags = flags;

    const bool shouldCaptureRegisterSnapshot = type == "debugger.watchpoint_hit" ||
                                               type == "debugger.breakpoint_hit";
    if (shouldCaptureRegisterSnapshot)
    {
        capture_event_register_snapshot(&event.registerSnapshot);
    }

    if (type == "debugger.watchpoint_hit")
    {
        capture_event_memory_snapshot(event.rangeAddress, event.endAddress, &event.memorySnapshot);
    }

    std::scoped_lock lock(g_eventMutex);
    event.id = g_nextEventId++;

    g_events.push_back(std::move(event));
    while (g_events.size() > kMaxQueuedEvents)
    {
        g_events.pop_front();
    }
}

bool set_debugger_trace_enabled(bool enabled)
{
    if (!m64p::Debugger.IsHooked() ||
        m64p::Debugger.DebugSetTraceEnabled == nullptr)
    {
        CoreSetError("Core debugger trace API unavailable");
        return false;
    }

    const m64p_error ret = m64p::Debugger.DebugSetTraceEnabled(enabled ? 1 : 0);
    if (ret != M64ERR_SUCCESS)
    {
        set_error_from_m64p("CoreDebuggerTrace Failed: ", ret);
        return false;
    }

    return true;
}

uint64_t monotonic_timestamp_us(void)
{
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
                                     std::chrono::steady_clock::now().time_since_epoch())
                                     .count());
}

uint32_t classify_trace_record_flags(uint32_t pc, uint32_t word, uint32_t* branchTarget, bool* hasBranchTarget)
{
    if (branchTarget != nullptr)
    {
        *branchTarget = 0;
    }
    if (hasBranchTarget != nullptr)
    {
        *hasBranchTarget = false;
    }

    const uint32_t opcode = (word >> 26) & UINT32_C(0x3f);
    const uint32_t rs = (word >> 21) & UINT32_C(0x1f);
    const uint32_t rt = (word >> 16) & UINT32_C(0x1f);
    const uint32_t funct = word & UINT32_C(0x3f);
    const int32_t signedImmediate = static_cast<int16_t>(word & UINT32_C(0xffff));
    const uint32_t jumpTarget = (pc & UINT32_C(0xf0000000)) | ((word & UINT32_C(0x03ffffff)) << 2);
    const uint32_t branchAddress = static_cast<uint32_t>(pc + 4 + (signedImmediate << 2));

    auto setDirectTarget = [branchTarget, hasBranchTarget](uint32_t target) {
        if (branchTarget != nullptr)
        {
            *branchTarget = target;
        }
        if (hasBranchTarget != nullptr)
        {
            *hasBranchTarget = true;
        }
    };

    uint32_t flags = 0;
    switch (opcode)
    {
        case 0x00:
            if (funct == 0x08)
            {
                flags = CORE_DEBUGGER_TRACE_FLAG_CONTROL_FLOW | CORE_DEBUGGER_TRACE_FLAG_INDIRECT;
                if (rs == 31)
                {
                    flags |= CORE_DEBUGGER_TRACE_FLAG_RETURN;
                }
                break;
            }
            if (funct == 0x09)
            {
                flags = CORE_DEBUGGER_TRACE_FLAG_CONTROL_FLOW |
                        CORE_DEBUGGER_TRACE_FLAG_CALL |
                        CORE_DEBUGGER_TRACE_FLAG_INDIRECT |
                        CORE_DEBUGGER_TRACE_FLAG_LINK;
                break;
            }
            break;
        case 0x01:
            if (rt == 0x00 || rt == 0x01)
            {
                flags = CORE_DEBUGGER_TRACE_FLAG_CONTROL_FLOW |
                        CORE_DEBUGGER_TRACE_FLAG_BRANCH |
                        CORE_DEBUGGER_TRACE_FLAG_CONDITIONAL;
                setDirectTarget(branchAddress);
            }
            else if (rt == 0x10 || rt == 0x11)
            {
                flags = CORE_DEBUGGER_TRACE_FLAG_CONTROL_FLOW |
                        CORE_DEBUGGER_TRACE_FLAG_BRANCH |
                        CORE_DEBUGGER_TRACE_FLAG_CONDITIONAL |
                        CORE_DEBUGGER_TRACE_FLAG_CALL |
                        CORE_DEBUGGER_TRACE_FLAG_LINK;
                setDirectTarget(branchAddress);
            }
            break;
        case 0x02:
            flags = CORE_DEBUGGER_TRACE_FLAG_CONTROL_FLOW;
            setDirectTarget(jumpTarget);
            break;
        case 0x03:
            flags = CORE_DEBUGGER_TRACE_FLAG_CONTROL_FLOW |
                    CORE_DEBUGGER_TRACE_FLAG_CALL |
                    CORE_DEBUGGER_TRACE_FLAG_LINK;
            setDirectTarget(jumpTarget);
            break;
        case 0x04:
        case 0x05:
        case 0x06:
        case 0x07:
        case 0x14:
        case 0x15:
        case 0x16:
        case 0x17:
            flags = CORE_DEBUGGER_TRACE_FLAG_CONTROL_FLOW |
                    CORE_DEBUGGER_TRACE_FLAG_BRANCH |
                    CORE_DEBUGGER_TRACE_FLAG_CONDITIONAL;
            setDirectTarget(branchAddress);
            break;
        case 0x10:
            if (rs == 0x10 && funct == 0x18)
            {
                flags = CORE_DEBUGGER_TRACE_FLAG_CONTROL_FLOW |
                        CORE_DEBUGGER_TRACE_FLAG_RETURN |
                        CORE_DEBUGGER_TRACE_FLAG_EXCEPTION_RETURN;
            }
            break;
        default:
            break;
    }

    return flags;
}

void capture_instruction_trace_record(uint32_t pc)
{
    CoreDebuggerInstructionTraceRecord record;
    record.index = 0;
    record.timestampUs = monotonic_timestamp_us();
    record.pc = pc;

    if (m64p::Debugger.DebugMemRead32 != nullptr)
    {
        record.word = static_cast<uint32_t>(m64p::Debugger.DebugMemRead32(pc));
    }

    record.flags = classify_trace_record_flags(pc, record.word, &record.branchTarget, &record.hasBranchTarget);

    std::scoped_lock lock(g_instructionTraceMutex);
    if (!g_instructionTraceStatus.active)
    {
        return;
    }

    if (g_instructionTraceStatus.totalCaptured == 0)
    {
        g_instructionTraceStatus.startTimestampUs = record.timestampUs;
    }
    g_instructionTraceStatus.latestTimestampUs = record.timestampUs;

    if (!g_instructionTrace.empty())
    {
        g_instructionTrace.back().nextPc = pc;
        g_instructionTrace.back().hasNextPc = true;
    }

    if (g_instructionTraceMaxRecords != 0 &&
        g_instructionTrace.size() >= g_instructionTraceMaxRecords)
    {
        g_instructionTraceStatus.truncated = true;
        g_instructionTraceStatus.active = false;
        g_instructionTraceStatus.droppedRecords++;
        set_debugger_trace_enabled(false);
        return;
    }

    record.index = g_instructionTraceStatus.totalCaptured;
    g_instructionTrace.push_back(record);
    g_instructionTraceStatus.totalCaptured++;
    g_instructionTraceStatus.bufferedCount = static_cast<uint32_t>(g_instructionTrace.size());
}

void debugger_ui_init_callback(void)
{
    g_lastObservedRunState = -1;
    g_lastCallbackPc = 0;
    g_lastTriggeredAddress = 0;
    g_lastTriggeredFlags = 0;
    g_lastTriggeredPc = 0;
    g_lastViEventTimestampMs = 0;
    g_breakpointEventsArmed = false;
    push_debugger_event("debugger.init", "Debugger frontend callbacks initialized", 0, 0, 0, 0, 0);
}

void debugger_ui_update_callback(unsigned int pc)
{
    if (!m64p::Debugger.IsHooked() ||
        m64p::Debugger.DebugGetState == nullptr)
    {
        return;
    }

    int runState = m64p::Debugger.DebugGetState(M64P_DBG_RUN_STATE);
    const uint32_t callbackPc = static_cast<uint32_t>(pc);
    const bool traceActive = g_instructionTraceStatus.active;
    if (traceActive && runState == M64P_DBG_RUNSTATE_RUNNING)
    {
        capture_instruction_trace_record(callbackPc);
    }

    if ((!traceActive || runState != M64P_DBG_RUNSTATE_RUNNING) &&
        (runState != g_lastObservedRunState || callbackPc != g_lastCallbackPc))
    {
        push_debugger_event("debugger.update",
                            "Debugger UI update callback",
                            runState,
                            callbackPc,
                            0,
                            0,
                            0);
        g_lastObservedRunState = runState;
    }
    g_lastCallbackPc = callbackPc;

    if (m64p::Debugger.DebugBreakpointTriggeredBy != nullptr)
    {
        uint32_t breakpointFlags = 0;
        uint32_t breakpointAddress = 0;
        m64p::Debugger.DebugBreakpointTriggeredBy(&breakpointFlags, &breakpointAddress);

        if (g_breakpointEventsArmed &&
            runState == M64P_DBG_RUNSTATE_PAUSED &&
            (breakpointFlags != 0 || breakpointAddress != 0) &&
            (breakpointFlags != g_lastTriggeredFlags ||
             breakpointAddress != g_lastTriggeredAddress ||
             callbackPc != g_lastTriggeredPc))
        {
            CoreDebuggerBreakpoint matchedBreakpoint;
            const bool hasMatchedBreakpoint = lookup_managed_breakpoint_range(breakpointAddress,
                                                                              breakpointFlags,
                                                                              &matchedBreakpoint);
            std::string eventType = (breakpointFlags & (M64P_BKP_FLAG_READ | M64P_BKP_FLAG_WRITE)) != 0
                                        ? "debugger.watchpoint_hit"
                                        : "debugger.breakpoint_hit";

            push_debugger_event(eventType,
                                "Debugger breakpoint/watchpoint triggered",
                                runState,
                                callbackPc,
                                breakpointAddress,
                                hasMatchedBreakpoint ? matchedBreakpoint.endAddress : breakpointAddress,
                                breakpointFlags,
                                hasMatchedBreakpoint ? matchedBreakpoint.address : breakpointAddress);

            g_lastTriggeredFlags = breakpointFlags;
            g_lastTriggeredAddress = breakpointAddress;
            g_lastTriggeredPc = callbackPc;
            g_breakpointEventsArmed = false;
        }
        else if (!g_breakpointEventsArmed)
        {
            g_lastTriggeredFlags = 0;
            g_lastTriggeredAddress = 0;
            g_lastTriggeredPc = 0;
        }
    }
}

void debugger_ui_vi_callback(void)
{
    int runState = 0;
    if (m64p::Debugger.IsHooked() &&
        m64p::Debugger.DebugGetState != nullptr)
    {
        runState = m64p::Debugger.DebugGetState(M64P_DBG_RUN_STATE);
    }

    const uint64_t nowMs = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                                     std::chrono::system_clock::now().time_since_epoch())
                                                     .count());

    if ((nowMs - g_lastViEventTimestampMs) < kViEventThrottleMs)
    {
        return;
    }

    g_lastViEventTimestampMs = nowMs;
    push_debugger_event("debugger.vi", "Video interrupt callback", runState, g_lastCallbackPc, 0, 0, 0);
}

void set_error_from_m64p(const std::string& prefix, m64p_error ret)
{
    CoreSetError(prefix + m64p::Core.ErrorMessage(ret));
}

bool ensure_debugger_available(void)
{
    if (!m64p::Core.IsHooked())
    {
        CoreSetError("Core debugger API unavailable: core is not initialized");
        return false;
    }

    if (!m64p::Debugger.IsHooked())
    {
        CoreSetError("Core debugger API unavailable: core library was not built with debugger exports");
        return false;
    }

    if (!CoreIsEmulationRunning() &&
        !CoreIsEmulationPaused())
    {
        CoreSetError("Core debugger API unavailable: emulation is not running");
        return false;
    }

    return true;
}

bool ensure_full_debugger_available(void)
{
    if (!ensure_debugger_available())
    {
        return false;
    }

    if (!g_debuggerCallbacksConfigured)
    {
        CoreSetError("Core debugger API unavailable: full debugger support is not active in the core build");
        return false;
    }

    return true;
}

bool ensure_debugger_paused(void)
{
    if (!ensure_full_debugger_available())
    {
        return false;
    }

    if (m64p::Debugger.DebugGetState(M64P_DBG_RUN_STATE) != M64P_DBG_RUNSTATE_PAUSED)
    {
        CoreSetError("Core debugger operation requires the debugger run state to be paused");
        return false;
    }

    return true;
}

uint32_t read_be_u32(const std::vector<uint8_t>& bytes, size_t offset);

bool read_current_instruction(uint32_t* pcValue, uint32_t* instructionWord, CoreDebuggerInstruction* instruction)
{
    if (pcValue == nullptr || instructionWord == nullptr)
    {
        return false;
    }

    uint64_t pc = 0;
    if (!CoreDebuggerReadCpuRegister("pc", pc))
    {
        return false;
    }

    std::vector<uint8_t> bytes;
    if (!CoreDebuggerReadMemory(static_cast<uint32_t>(pc), 4, bytes) || bytes.size() != 4)
    {
        return false;
    }

    const uint32_t word = read_be_u32(bytes, 0);
    *pcValue = static_cast<uint32_t>(pc);
    *instructionWord = word;

    if (instruction != nullptr)
    {
        if (!CoreDebuggerDecodeInstruction(*pcValue, word, *instruction))
        {
            return false;
        }
    }

    return true;
}

bool instruction_is_call_like(uint32_t instructionWord)
{
    const uint32_t opcode = instructionWord >> 26;
    if (opcode == 0x03)
    {
        return true;
    }

    if (opcode == 0x00)
    {
        const uint32_t funct = instructionWord & 0x3F;
        return funct == 0x09;
    }

    if (opcode == 0x01)
    {
        const uint32_t rt = (instructionWord >> 16) & 0x1F;
        return rt == 0x10 || rt == 0x11 || rt == 0x12 || rt == 0x13;
    }

    return false;
}

std::string normalize_register_name(std::string name)
{
    std::transform(name.begin(), name.end(), name.begin(), [](unsigned char value) {
        return static_cast<char>(std::tolower(value));
    });
    return name;
}

bool try_parse_indexed_register(const std::string& name, const std::string& prefix, size_t* index)
{
    if (index == nullptr ||
        name.size() <= prefix.size() ||
        name.rfind(prefix, 0) != 0)
    {
        return false;
    }

    int parsedIndex = 0;
    for (size_t i = prefix.size(); i < name.size(); i++)
    {
        if (!std::isdigit(static_cast<unsigned char>(name[i])))
        {
            return false;
        }

        parsedIndex *= 10;
        parsedIndex += name[i] - '0';
    }

    if (parsedIndex < 0 || parsedIndex > 31)
    {
        return false;
    }

    *index = static_cast<size_t>(parsedIndex);
    return true;
}

bool lookup_gpr_index(const std::string& name, size_t* index)
{
    static constexpr std::array<const char*, 32> kGprNames = {
        "zero", "at", "v0", "v1", "a0", "a1", "a2", "a3",
        "t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7",
        "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7",
        "t8", "t9", "k0", "k1", "gp", "sp", "s8", "ra",
    };

    if (try_parse_indexed_register(name, "r", index) ||
        try_parse_indexed_register(name, "gpr", index))
    {
        return true;
    }

    if (name == "fp")
    {
        *index = 30;
        return true;
    }

    for (size_t i = 0; i < kGprNames.size(); i++)
    {
        if (name == kGprNames[i])
        {
            *index = i;
            return true;
        }
    }

    return false;
}

bool lookup_cop0_index(const std::string& name, size_t* index)
{
    static constexpr std::array<const char*, 32> kCop0Names = {
        "index", "random", "entrylo0", "entrylo1", "context", "pagemask", "wired", "cop0_7",
        "badvaddr", "count", "entryhi", "compare", "status", "cause", "epc", "prid",
        "config", "lladdr", "watchlo", "watchhi", "xcontext", "cop0_21", "cop0_22", "cop0_23",
        "cop0_24", "cop0_25", "perr", "cacheerr", "taglo", "taghi", "errorepc", "cop0_31",
    };

    if (try_parse_indexed_register(name, "cop0_", index) ||
        try_parse_indexed_register(name, "c0_", index))
    {
        return true;
    }

    for (size_t i = 0; i < kCop0Names.size(); i++)
    {
        if (name == kCop0Names[i])
        {
            *index = i;
            return true;
        }
    }

    return false;
}

enum class CpuRegisterKind
{
    ProgramCounter,
    Hi,
    Lo,
    GeneralPurpose,
    Cop0,
};

struct CpuRegisterReference
{
    CpuRegisterKind kind = CpuRegisterKind::ProgramCounter;
    size_t index = 0;
};

bool try_resolve_cpu_register(const std::string& name, CpuRegisterReference* reference)
{
    if (reference == nullptr)
    {
        return false;
    }

    std::string normalized = normalize_register_name(name);
    if (normalized == "pc")
    {
        *reference = {CpuRegisterKind::ProgramCounter, 0};
        return true;
    }

    if (normalized == "hi")
    {
        *reference = {CpuRegisterKind::Hi, 0};
        return true;
    }

    if (normalized == "lo")
    {
        *reference = {CpuRegisterKind::Lo, 0};
        return true;
    }

    size_t index = 0;
    if (lookup_gpr_index(normalized, &index))
    {
        *reference = {CpuRegisterKind::GeneralPurpose, index};
        return true;
    }

    if (lookup_cop0_index(normalized, &index))
    {
        *reference = {CpuRegisterKind::Cop0, index};
        return true;
    }

    return false;
}

bool read_cpu_register(const CpuRegisterReference& reference, uint64_t* value)
{
    if (value == nullptr)
    {
        return false;
    }

    switch (reference.kind)
    {
        case CpuRegisterKind::ProgramCounter:
        {
            const void* pointer = m64p::Debugger.DebugGetCPUDataPtr(M64P_CPU_PC);
            if (pointer == nullptr)
            {
                CoreSetError("CoreDebuggerReadCpuRegister Failed: could not retrieve PC pointer");
                return false;
            }

            *value = *reinterpret_cast<const uint32_t*>(pointer);
            return true;
        }
        case CpuRegisterKind::Hi:
        {
            const void* pointer = m64p::Debugger.DebugGetCPUDataPtr(M64P_CPU_REG_HI);
            if (pointer == nullptr)
            {
                CoreSetError("CoreDebuggerReadCpuRegister Failed: could not retrieve HI pointer");
                return false;
            }

            *value = *reinterpret_cast<const uint64_t*>(pointer);
            return true;
        }
        case CpuRegisterKind::Lo:
        {
            const void* pointer = m64p::Debugger.DebugGetCPUDataPtr(M64P_CPU_REG_LO);
            if (pointer == nullptr)
            {
                CoreSetError("CoreDebuggerReadCpuRegister Failed: could not retrieve LO pointer");
                return false;
            }

            *value = *reinterpret_cast<const uint64_t*>(pointer);
            return true;
        }
        case CpuRegisterKind::GeneralPurpose:
        {
            const void* pointer = m64p::Debugger.DebugGetCPUDataPtr(M64P_CPU_REG_REG);
            if (pointer == nullptr)
            {
                CoreSetError("CoreDebuggerReadCpuRegister Failed: could not retrieve GPR pointer");
                return false;
            }

            const uint64_t* registers = reinterpret_cast<const uint64_t*>(pointer);
            *value = registers[reference.index];
            return true;
        }
        case CpuRegisterKind::Cop0:
        {
            const void* pointer = m64p::Debugger.DebugGetCPUDataPtr(M64P_CPU_REG_COP0);
            if (pointer == nullptr)
            {
                CoreSetError("CoreDebuggerReadCpuRegister Failed: could not retrieve COP0 pointer");
                return false;
            }

            const uint32_t* registers = reinterpret_cast<const uint32_t*>(pointer);
            *value = registers[reference.index];
            return true;
        }
    }

    return false;
}

bool write_cpu_register(const std::string& registerName, const CpuRegisterReference& reference, uint64_t value)
{
    switch (reference.kind)
    {
        case CpuRegisterKind::ProgramCounter:
        {
            void* pointer = m64p::Debugger.DebugGetCPUDataPtr(M64P_CPU_PC);
            if (pointer == nullptr)
            {
                CoreSetError("CoreDebuggerWriteCpuRegister Failed: could not retrieve PC pointer");
                return false;
            }

            *reinterpret_cast<uint32_t*>(pointer) = static_cast<uint32_t>(value);
            return true;
        }
        case CpuRegisterKind::Hi:
        {
            void* pointer = m64p::Debugger.DebugGetCPUDataPtr(M64P_CPU_REG_HI);
            if (pointer == nullptr)
            {
                CoreSetError("CoreDebuggerWriteCpuRegister Failed: could not retrieve HI pointer");
                return false;
            }

            *reinterpret_cast<uint64_t*>(pointer) = value;
            return true;
        }
        case CpuRegisterKind::Lo:
        {
            void* pointer = m64p::Debugger.DebugGetCPUDataPtr(M64P_CPU_REG_LO);
            if (pointer == nullptr)
            {
                CoreSetError("CoreDebuggerWriteCpuRegister Failed: could not retrieve LO pointer");
                return false;
            }

            *reinterpret_cast<uint64_t*>(pointer) = value;
            return true;
        }
        case CpuRegisterKind::GeneralPurpose:
        {
            if (reference.index == 0)
            {
                CoreSetError("CoreDebuggerWriteCpuRegister Failed: cannot write to the zero register");
                return false;
            }

            void* pointer = m64p::Debugger.DebugGetCPUDataPtr(M64P_CPU_REG_REG);
            if (pointer == nullptr)
            {
                CoreSetError("CoreDebuggerWriteCpuRegister Failed: could not retrieve GPR pointer");
                return false;
            }

            uint64_t* registers = reinterpret_cast<uint64_t*>(pointer);
            registers[reference.index] = value;
            return true;
        }
        case CpuRegisterKind::Cop0:
        {
            void* pointer = m64p::Debugger.DebugGetCPUDataPtr(M64P_CPU_REG_COP0);
            if (pointer == nullptr)
            {
                CoreSetError("CoreDebuggerWriteCpuRegister Failed: could not retrieve COP0 pointer");
                return false;
            }

            uint32_t* registers = reinterpret_cast<uint32_t*>(pointer);
            registers[reference.index] = static_cast<uint32_t>(value);
            return true;
        }
    }

    CoreSetError("CoreDebuggerWriteCpuRegister Failed: unsupported register name \"" + registerName + "\"");
    return false;
}

uint32_t normalize_memory_address(uint32_t address)
{
    if ((address & UINT32_C(0xe0000000)) == UINT32_C(0x80000000) ||
        (address & UINT32_C(0xe0000000)) == UINT32_C(0xa0000000))
    {
        return address & UINT32_C(0x1fffffff);
    }

    return address;
}

uint32_t get_rdram_size(void);

std::optional<uint32_t> normalize_runtime_symbol_address(uint32_t address, bool allowPhysical)
{
    if ((address & UINT32_C(0xe0000000)) == UINT32_C(0x80000000) ||
        (address & UINT32_C(0xe0000000)) == UINT32_C(0xa0000000))
    {
        uint32_t normalized = normalize_memory_address(address);
        if (normalized >= get_rdram_size())
        {
            return std::nullopt;
        }

        return UINT32_C(0x80000000) | normalized;
    }

    if (!allowPhysical)
    {
        return std::nullopt;
    }

    uint32_t normalized = address;
    if (normalized >= get_rdram_size())
    {
        return std::nullopt;
    }

    return UINT32_C(0x80000000) | normalized;
}

uint32_t get_rdram_size(void)
{
    return CoreSettingsGetBoolValue(SettingsID::Core_DisableExtraMem)
               ? UINT32_C(0x00400000)
               : UINT32_C(0x00800000);
}

uint32_t get_host_byte_lane_mask(void)
{
    static const uint32_t mask = []() -> uint32_t {
        const uint32_t probe = 1;
        return *reinterpret_cast<const uint8_t*>(&probe) == 1 ? UINT32_C(0x3) : UINT32_C(0x0);
    }();

    return mask;
}

uint8_t* get_rdram_pointer(void)
{
    if (m64p::Debugger.DebugMemGetPointer == nullptr)
    {
        return nullptr;
    }

    return static_cast<uint8_t*>(m64p::Debugger.DebugMemGetPointer(M64P_DBG_PTR_RDRAM));
}

bool try_access_rdram_byte(uint32_t address, uint8_t** pointer)
{
    if (pointer == nullptr)
    {
        return false;
    }

    uint32_t physicalAddress = normalize_memory_address(address);
    if (physicalAddress >= get_rdram_size())
    {
        return false;
    }

    uint8_t* rdram = get_rdram_pointer();
    if (rdram == nullptr)
    {
        return false;
    }

    *pointer = rdram + (physicalAddress ^ get_host_byte_lane_mask());
    return true;
}

bool try_read_rdram_byte(uint32_t address, uint8_t* value)
{
    uint8_t* pointer = nullptr;
    if (!try_access_rdram_byte(address, &pointer) || value == nullptr)
    {
        return false;
    }

    *value = *pointer;
    return true;
}

bool try_write_rdram_byte(uint32_t address, uint8_t value)
{
    uint8_t* pointer = nullptr;
    if (!try_access_rdram_byte(address, &pointer))
    {
        return false;
    }

    *pointer = value;
    return true;
}

uint32_t read_be_u32(const std::vector<uint8_t>& bytes, size_t offset)
{
    return (static_cast<uint32_t>(bytes[offset]) << 24) |
           (static_cast<uint32_t>(bytes[offset + 1]) << 16) |
           (static_cast<uint32_t>(bytes[offset + 2]) << 8) |
           static_cast<uint32_t>(bytes[offset + 3]);
}

std::vector<CoreDebuggerBreakpoint>::iterator find_managed_breakpoint(uint32_t address)
{
    return std::find_if(g_managedBreakpoints.begin(), g_managedBreakpoints.end(), [address](const CoreDebuggerBreakpoint& breakpoint) {
        return breakpoint.address == address;
    });
}

void sort_and_deduplicate_symbols(void)
{
    std::sort(g_symbols.begin(), g_symbols.end(), [](const CoreDebuggerSymbol& lhs, const CoreDebuggerSymbol& rhs) {
        if (lhs.address != rhs.address)
        {
            return lhs.address < rhs.address;
        }

        if (lhs.name != rhs.name)
        {
            return lhs.name < rhs.name;
        }

        return lhs.source < rhs.source;
    });

    g_symbols.erase(std::unique(g_symbols.begin(),
                                g_symbols.end(),
                                [](const CoreDebuggerSymbol& lhs, const CoreDebuggerSymbol& rhs) {
                                    return lhs.address == rhs.address &&
                                           lhs.name == rhs.name &&
                                           lhs.source == rhs.source;
                                }),
                    g_symbols.end());
}

std::vector<CoreDebuggerSymbol>::const_iterator find_symbol_by_address(uint32_t address)
{
    auto iterator = std::upper_bound(g_symbols.begin(),
                                     g_symbols.end(),
                                     address,
                                     [](uint32_t value, const CoreDebuggerSymbol& symbol) {
                                         return value < symbol.address;
                                     });

    if (iterator == g_symbols.begin())
    {
        return g_symbols.end();
    }

    --iterator;
    return iterator;
}

bool normalize_symbol_limit(uint32_t* limit)
{
    if (limit == nullptr)
    {
        return false;
    }

    if (*limit == 0 || *limit > kMaxEventBatchSize)
    {
        *limit = std::min<uint32_t>(std::max<uint32_t>(*limit, 1U), kMaxEventBatchSize);
    }

    return true;
}
} // namespace

CORE_EXPORT bool CoreDebuggerConfigureCallbacks(void)
{
    if (!m64p::Debugger.IsHooked() ||
        m64p::Debugger.DebugSetCallbacks == nullptr)
    {
        return false;
    }

    m64p_error ret = m64p::Debugger.DebugSetCallbacks(&debugger_ui_init_callback,
                                                      &debugger_ui_update_callback,
                                                      &debugger_ui_vi_callback);
    if (ret != M64ERR_SUCCESS)
    {
        g_debuggerCallbacksConfigured = false;
        set_error_from_m64p("CoreDebuggerConfigureCallbacks Failed: ", ret);
        return false;
    }

    g_debuggerCallbacksConfigured = true;
    return true;
}

CORE_EXPORT void CoreDebuggerResetSession(void)
{
    if (m64p::Debugger.IsHooked() &&
        m64p::Debugger.DebugSetTraceEnabled != nullptr)
    {
        m64p::Debugger.DebugSetTraceEnabled(0);
    }

    {
        std::scoped_lock lock(g_breakpointMutex);
        g_managedBreakpoints.clear();
    }

    {
        std::scoped_lock lock(g_eventMutex);
        g_events.clear();
        g_nextEventId = 1;
    }

    {
        std::scoped_lock lock(g_instructionTraceMutex);
        g_instructionTrace.clear();
        g_instructionTraceStatus = {};
        g_instructionTraceMaxRecords = 0;
    }

    g_lastCallbackPc = 0;
    g_lastObservedRunState = -1;
    g_lastTriggeredAddress = 0;
    g_lastTriggeredFlags = 0;
    g_lastTriggeredPc = 0;
}

CORE_EXPORT bool CoreDebuggerSupported(void)
{
    return m64p::Debugger.IsHooked();
}

CORE_EXPORT bool CoreDebuggerReadMemory(uint32_t address, uint32_t size, std::vector<uint8_t>& bytes)
{
    if (!ensure_debugger_available())
    {
        return false;
    }

    if (size == 0)
    {
        CoreSetError("CoreDebuggerReadMemory Failed: size must be greater than zero");
        return false;
    }

    bytes.clear();
    bytes.reserve(size);

    for (uint32_t offset = 0; offset < size; offset++)
    {
        uint8_t value = 0;
        if (!try_read_rdram_byte(address + offset, &value))
        {
            CoreSetError("CoreDebuggerReadMemory Failed: requested address range is outside readable RDRAM");
            bytes.clear();
            return false;
        }

        bytes.push_back(value);
    }

    return true;
}

CORE_EXPORT bool CoreDebuggerWriteMemory(uint32_t address, const std::vector<uint8_t>& bytes)
{
    if (!ensure_debugger_paused())
    {
        return false;
    }

    if (bytes.empty())
    {
        CoreSetError("CoreDebuggerWriteMemory Failed: byte payload must not be empty");
        return false;
    }

    for (size_t offset = 0; offset < bytes.size(); offset++)
    {
        if (!try_write_rdram_byte(address + static_cast<uint32_t>(offset), bytes[offset]))
        {
            CoreSetError("CoreDebuggerWriteMemory Failed: requested address range is outside writable RDRAM");
            return false;
        }
    }

    return true;
}

CORE_EXPORT bool CoreDebuggerReadCpuRegister(std::string name, uint64_t& value)
{
    if (!ensure_debugger_available())
    {
        return false;
    }

    CpuRegisterReference reference;
    if (!try_resolve_cpu_register(name, &reference))
    {
        CoreSetError("CoreDebuggerReadCpuRegister Failed: unsupported register name \"" + normalize_register_name(name) + "\"");
        return false;
    }

    return read_cpu_register(reference, &value);
}

CORE_EXPORT bool CoreDebuggerWriteCpuRegister(std::string name, uint64_t value)
{
    if (!ensure_debugger_paused())
    {
        return false;
    }

    CpuRegisterReference reference;
    if (!try_resolve_cpu_register(name, &reference))
    {
        CoreSetError("CoreDebuggerWriteCpuRegister Failed: unsupported register name \"" + normalize_register_name(name) + "\"");
        return false;
    }

    return write_cpu_register(normalize_register_name(name), reference, value);
}

CORE_EXPORT bool CoreDebuggerGetState(CoreDebuggerState& state)
{
    if (!ensure_full_debugger_available())
    {
        return false;
    }

    state.runState = m64p::Debugger.DebugGetState(M64P_DBG_RUN_STATE);
    state.previousPc = static_cast<uint32_t>(m64p::Debugger.DebugGetState(M64P_DBG_PREVIOUS_PC));
    state.breakpointCount = m64p::Debugger.DebugGetState(M64P_DBG_NUM_BREAKPOINTS);
    state.dynacore = m64p::Debugger.DebugGetState(M64P_DBG_CPU_DYNACORE);
    state.nextInterrupt = static_cast<uint32_t>(m64p::Debugger.DebugGetState(M64P_DBG_CPU_NEXT_INTERRUPT));
    return true;
}

CORE_EXPORT bool CoreDebuggerVirtualToPhysical(uint32_t virtualAddress, uint32_t& physicalAddress)
{
    if (!ensure_debugger_available())
    {
        return false;
    }

    if (g_debuggerCallbacksConfigured &&
        m64p::Debugger.DebugVirtualToPhysical != nullptr)
    {
        physicalAddress = m64p::Debugger.DebugVirtualToPhysical(virtualAddress);
        if (physicalAddress == 0 &&
            virtualAddress != 0)
        {
            uint32_t normalizedAddress = normalize_memory_address(virtualAddress);
            if (normalizedAddress != virtualAddress ||
                virtualAddress < kMaxRdramSize)
            {
                physicalAddress = normalizedAddress;
                return true;
            }

            CoreSetError("CoreDebuggerVirtualToPhysical Failed: translation returned 0");
            return false;
        }

        return true;
    }

    physicalAddress = normalize_memory_address(virtualAddress);
    if (physicalAddress != virtualAddress ||
        virtualAddress < kMaxRdramSize)
    {
        return true;
    }

    CoreSetError("CoreDebuggerVirtualToPhysical Failed: address translation requires a core built with full debugger support");
    return false;
}

CORE_EXPORT bool CoreDebuggerDecodeInstruction(uint32_t address, uint32_t instructionWord, CoreDebuggerInstruction& instruction)
{
    if (!ensure_full_debugger_available())
    {
        return false;
    }

    if (m64p::Debugger.DebugDecodeOp == nullptr)
    {
        CoreSetError("CoreDebuggerDecodeInstruction Failed: DebugDecodeOp symbol is unavailable");
        return false;
    }

    std::array<char, 64> op{};
    std::array<char, 128> args{};

    m64p::Debugger.DebugDecodeOp(instructionWord, op.data(), args.data(), static_cast<int>(address));

    instruction.address = address;
    instruction.word = instructionWord;
    instruction.physicalAddress = normalize_memory_address(address);
    instruction.mnemonic = op.data();
    instruction.arguments = args.data();
    return true;
}

CORE_EXPORT bool CoreDebuggerDisassemble(uint32_t address,
                                         uint32_t instructionCount,
                                         std::vector<CoreDebuggerInstruction>& instructions)
{
    if (!ensure_full_debugger_available())
    {
        return false;
    }

    if (instructionCount == 0)
    {
        CoreSetError("CoreDebuggerDisassemble Failed: instructionCount must be greater than zero");
        return false;
    }

    std::vector<uint8_t> bytes;
    if (!CoreDebuggerReadMemory(address, instructionCount * kMinInstructionSize, bytes))
    {
        return false;
    }

    instructions.clear();
    instructions.reserve(instructionCount);

    for (uint32_t index = 0; index < instructionCount; index++)
    {
        CoreDebuggerInstruction instruction;
        uint32_t currentAddress = address + (index * kMinInstructionSize);
        uint32_t instructionWord = read_be_u32(bytes, static_cast<size_t>(index) * kMinInstructionSize);
        if (!CoreDebuggerDecodeInstruction(currentAddress, instructionWord, instruction))
        {
            instructions.clear();
            return false;
        }

        instructions.push_back(instruction);
    }

    return true;
}

CORE_EXPORT bool CoreDebuggerPauseExecution(void)
{
    if (!ensure_full_debugger_available())
    {
        return false;
    }

    m64p_error ret = m64p::Debugger.DebugSetRunState(M64P_DBG_RUNSTATE_PAUSED);
    if (ret != M64ERR_SUCCESS)
    {
        set_error_from_m64p("CoreDebuggerPauseExecution Failed: ", ret);
        return false;
    }

    g_lastTriggeredFlags = 0;
    g_lastTriggeredAddress = 0;
    g_lastTriggeredPc = 0;
    g_breakpointEventsArmed = false;
    push_debugger_event("execution.pause_requested", "Pause requested through MCP bridge", M64P_DBG_RUNSTATE_PAUSED, 0, 0, 0, 0);
    return true;
}

CORE_EXPORT bool CoreDebuggerResumeExecution(void)
{
    if (!ensure_full_debugger_available())
    {
        return false;
    }

    m64p_error ret = m64p::Debugger.DebugSetRunState(M64P_DBG_RUNSTATE_RUNNING);
    if (ret != M64ERR_SUCCESS)
    {
        set_error_from_m64p("CoreDebuggerResumeExecution Failed: ", ret);
        return false;
    }

    ret = m64p::Debugger.DebugStep();
    if (ret != M64ERR_SUCCESS)
    {
        set_error_from_m64p("CoreDebuggerResumeExecution Failed to release the debugger semaphore: ", ret);
        return false;
    }

    g_lastTriggeredFlags = 0;
    g_lastTriggeredAddress = 0;
    g_lastTriggeredPc = 0;
    g_breakpointEventsArmed = true;
    push_debugger_event("execution.resume_requested", "Resume requested through MCP bridge", M64P_DBG_RUNSTATE_RUNNING, 0, 0, 0, 0);
    return true;
}

CORE_EXPORT bool CoreDebuggerStepInstructions(uint32_t count, uint32_t& currentPc)
{
    if (!ensure_debugger_paused())
    {
        return false;
    }

    if (count == 0)
    {
        CoreSetError("CoreDebuggerStepInstructions Failed: count must be greater than zero");
        return false;
    }

    for (uint32_t index = 0; index < count; index++)
    {
        m64p_error ret = m64p::Debugger.DebugStep();
        if (ret != M64ERR_SUCCESS)
        {
            set_error_from_m64p("CoreDebuggerStepInstructions Failed: ", ret);
            return false;
        }
    }

    uint64_t pc = 0;
    if (!CoreDebuggerReadCpuRegister("pc", pc))
    {
        return false;
    }

    currentPc = static_cast<uint32_t>(pc);
    g_lastTriggeredFlags = 0;
    g_lastTriggeredAddress = 0;
    g_lastTriggeredPc = 0;
    g_breakpointEventsArmed = false;
    push_debugger_event("execution.step",
                        "Instruction step requested through MCP bridge",
                        M64P_DBG_RUNSTATE_PAUSED,
                        currentPc,
                        0,
                        0,
                        0);
    return true;
}

CORE_EXPORT bool CoreDebuggerRunUntil(uint32_t address, uint32_t timeoutMs, uint32_t& currentPc, bool& hitTarget)
{
    if (!ensure_debugger_paused())
    {
        return false;
    }

    uint64_t startingPc = 0;
    if (!CoreDebuggerReadCpuRegister("pc", startingPc))
    {
        return false;
    }

    currentPc = static_cast<uint32_t>(startingPc);
    hitTarget = (currentPc == address);
    if (hitTarget)
    {
        push_debugger_event("execution.run_until_completed",
                            "Run-until target already matches the current PC",
                            M64P_DBG_RUNSTATE_PAUSED,
                            currentPc,
                            address,
                            address,
                            0);
        return true;
    }

    int temporaryBreakpointIndex = -1;
    {
        std::scoped_lock lock(g_breakpointMutex);
        for (const CoreDebuggerBreakpoint& breakpoint : g_managedBreakpoints)
        {
            if (breakpoint.address == address &&
                breakpoint.endAddress == address &&
                (breakpoint.flags & M64P_BKP_FLAG_EXEC) != 0)
            {
                temporaryBreakpointIndex = -2;
                break;
            }
        }
    }

    const auto cleanupTemporaryBreakpoint = [address, &temporaryBreakpointIndex]() {
        if (temporaryBreakpointIndex < 0 ||
            m64p::Debugger.DebugBreakpointCommand == nullptr)
        {
            return;
        }

        m64p::Debugger.DebugBreakpointCommand(M64P_BKP_CMD_REMOVE_IDX, temporaryBreakpointIndex, nullptr);

        std::scoped_lock lock(g_breakpointMutex);
        auto iterator = std::find_if(g_managedBreakpoints.begin(),
                                     g_managedBreakpoints.end(),
                                     [address](const CoreDebuggerBreakpoint& breakpoint) {
                                         return breakpoint.address == address &&
                                                breakpoint.endAddress == address &&
                                                (breakpoint.flags & M64P_BKP_FLAG_EXEC) != 0;
                                     });
        if (iterator != g_managedBreakpoints.end())
        {
            g_managedBreakpoints.erase(iterator);
        }

        temporaryBreakpointIndex = -1;
    };

    if (temporaryBreakpointIndex == -1)
    {
        const uint32_t flags = M64P_BKP_FLAG_ENABLED | M64P_BKP_FLAG_EXEC;
        if (!CoreDebuggerAddBreakpoint(address, address, flags, temporaryBreakpointIndex))
        {
            return false;
        }
    }

    push_debugger_event("execution.run_until_requested",
                        "Run-until requested through MCP bridge",
                        M64P_DBG_RUNSTATE_PAUSED,
                        currentPc,
                        address,
                        address,
                        M64P_BKP_FLAG_EXEC);

    if (!CoreDebuggerResumeExecution())
    {
        cleanupTemporaryBreakpoint();
        return false;
    }

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
    int runState = M64P_DBG_RUNSTATE_RUNNING;
    while (std::chrono::steady_clock::now() < deadline)
    {
        runState = m64p::Debugger.DebugGetState(M64P_DBG_RUN_STATE);
        if (runState == M64P_DBG_RUNSTATE_PAUSED)
        {
            break;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    runState = m64p::Debugger.DebugGetState(M64P_DBG_RUN_STATE);
    if (runState != M64P_DBG_RUNSTATE_PAUSED)
    {
        if (!CoreDebuggerPauseExecution())
        {
            cleanupTemporaryBreakpoint();
            return false;
        }

        const auto pauseDeadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(250);
        while (std::chrono::steady_clock::now() < pauseDeadline)
        {
            if (m64p::Debugger.DebugGetState(M64P_DBG_RUN_STATE) == M64P_DBG_RUNSTATE_PAUSED)
            {
                break;
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    }

    if (!CoreDebuggerReadCpuRegister("pc", startingPc))
    {
        cleanupTemporaryBreakpoint();
        return false;
    }

    currentPc = static_cast<uint32_t>(startingPc);
    hitTarget = (currentPc == address);

    cleanupTemporaryBreakpoint();

    push_debugger_event(hitTarget ? "execution.run_until_completed"
                                  : "execution.run_until_stopped",
                        hitTarget ? "Run-until completed at the requested address"
                                  : "Run-until stopped before reaching the requested address",
                        M64P_DBG_RUNSTATE_PAUSED,
                        currentPc,
                        address,
                        address,
                        M64P_BKP_FLAG_EXEC);
    return true;
}

CORE_EXPORT bool CoreDebuggerStepOver(uint32_t timeoutMs, uint32_t& currentPc, bool& steppedOverCall)
{
    if (!ensure_debugger_paused())
    {
        return false;
    }

    uint32_t instructionPc = 0;
    uint32_t instructionWord = 0;
    CoreDebuggerInstruction instruction;
    if (!read_current_instruction(&instructionPc, &instructionWord, &instruction))
    {
        return false;
    }

    steppedOverCall = instruction_is_call_like(instructionWord);
    if (!steppedOverCall)
    {
        return CoreDebuggerStepInstructions(1, currentPc);
    }

    const uint32_t targetAddress = instructionPc + 8;
    bool hitTarget = false;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
    do
    {
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline)
        {
            break;
        }

        const auto remainingMs = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
        if (!CoreDebuggerRunUntil(targetAddress,
                                  static_cast<uint32_t>(std::max<int64_t>(remainingMs, 1)),
                                  currentPc,
                                  hitTarget))
        {
            return false;
        }
    } while (!hitTarget);

    push_debugger_event(hitTarget ? "execution.step_over_completed"
                                  : "execution.step_over_stopped",
                        hitTarget ? "Step-over completed at the post-call address"
                                  : "Step-over stopped before reaching the post-call address",
                        M64P_DBG_RUNSTATE_PAUSED,
                        currentPc,
                        targetAddress,
                        targetAddress,
                        M64P_BKP_FLAG_EXEC);
    return true;
}

CORE_EXPORT bool CoreDebuggerStepOut(uint32_t timeoutMs, uint32_t& currentPc, uint32_t& returnAddress, bool& hitTarget)
{
    if (!ensure_debugger_paused())
    {
        return false;
    }

    uint64_t ra = 0;
    if (!CoreDebuggerReadCpuRegister("ra", ra))
    {
        return false;
    }

    returnAddress = static_cast<uint32_t>(ra);
    if (returnAddress == 0)
    {
        CoreSetError("CoreDebuggerStepOut Failed: register ra is 0x00000000");
        return false;
    }

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
    do
    {
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline)
        {
            break;
        }

        const auto remainingMs = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
        if (!CoreDebuggerRunUntil(returnAddress,
                                  static_cast<uint32_t>(std::max<int64_t>(remainingMs, 1)),
                                  currentPc,
                                  hitTarget))
        {
            return false;
        }
    } while (!hitTarget);

    push_debugger_event(hitTarget ? "execution.step_out_completed"
                                  : "execution.step_out_stopped",
                        hitTarget ? "Step-out completed at the return address"
                                  : "Step-out stopped before reaching the return address",
                        M64P_DBG_RUNSTATE_PAUSED,
                        currentPc,
                        returnAddress,
                        returnAddress,
                        M64P_BKP_FLAG_EXEC);
    return true;
}

CORE_EXPORT bool CoreDebuggerAddBreakpoint(uint32_t address, uint32_t endAddress, uint32_t flags, int& breakpointIndex)
{
    if (!ensure_debugger_paused())
    {
        return false;
    }

    if (endAddress < address)
    {
        CoreSetError("CoreDebuggerAddBreakpoint Failed: endAddress must be greater than or equal to address");
        return false;
    }

    m64p_breakpoint breakpoint{};
    breakpoint.address = address;
    breakpoint.endaddr = endAddress;
    breakpoint.flags = flags;

    breakpointIndex = m64p::Debugger.DebugBreakpointCommand(M64P_BKP_CMD_ADD_STRUCT, 0, &breakpoint);
    if (breakpointIndex < 0)
    {
        CoreSetError("CoreDebuggerAddBreakpoint Failed: core rejected the breakpoint request");
        return false;
    }

    {
        std::scoped_lock lock(g_breakpointMutex);
        g_managedBreakpoints.push_back({address, endAddress, flags});
    }

    push_debugger_event("debugger.breakpoint_added",
                        "Breakpoint/watchpoint added",
                        M64P_DBG_RUNSTATE_PAUSED,
                        0,
                        address,
                        endAddress,
                        flags);
    return true;
}

CORE_EXPORT bool CoreDebuggerRemoveBreakpoint(uint32_t address)
{
    if (!ensure_debugger_paused())
    {
        return false;
    }

    if (m64p::Debugger.DebugBreakpointLookup == nullptr)
    {
        CoreSetError("CoreDebuggerRemoveBreakpoint Failed: breakpoint lookup API is unavailable");
        return false;
    }

    int breakpointIndex = m64p::Debugger.DebugBreakpointLookup(address, 1, 0);
    if (breakpointIndex < 0)
    {
        CoreSetError("CoreDebuggerRemoveBreakpoint Failed: no breakpoint exists at the requested address");
        return false;
    }

    int ret = m64p::Debugger.DebugBreakpointCommand(M64P_BKP_CMD_REMOVE_IDX,
                                                    static_cast<unsigned int>(breakpointIndex),
                                                    nullptr);
    if (ret < 0)
    {
        CoreSetError("CoreDebuggerRemoveBreakpoint Failed: core rejected the breakpoint removal");
        return false;
    }

    {
        std::scoped_lock lock(g_breakpointMutex);
        auto iterator = find_managed_breakpoint(address);
        if (iterator != g_managedBreakpoints.end())
        {
            g_managedBreakpoints.erase(iterator);
        }
    }

    push_debugger_event("debugger.breakpoint_removed",
                        "Breakpoint/watchpoint removed",
                        M64P_DBG_RUNSTATE_PAUSED,
                        0,
                        address,
                        address,
                        0);
    return true;
}

CORE_EXPORT bool CoreDebuggerListBreakpoints(std::vector<CoreDebuggerBreakpoint>& breakpoints)
{
    if (!ensure_full_debugger_available())
    {
        return false;
    }

    std::scoped_lock lock(g_breakpointMutex);
    breakpoints = g_managedBreakpoints;
    return true;
}

CORE_EXPORT bool CoreDebuggerClearBreakpoints(void)
{
    if (!ensure_debugger_paused())
    {
        return false;
    }

    CoreDebuggerState state;
    if (!CoreDebuggerGetState(state))
    {
        return false;
    }

    for (int index = state.breakpointCount - 1; index >= 0; index--)
    {
        int ret = m64p::Debugger.DebugBreakpointCommand(M64P_BKP_CMD_REMOVE_IDX,
                                                        static_cast<unsigned int>(index),
                                                        nullptr);
        if (ret < 0)
        {
            CoreSetError("CoreDebuggerClearBreakpoints Failed: core rejected breakpoint removal");
            return false;
        }
    }

    {
        std::scoped_lock lock(g_breakpointMutex);
        g_managedBreakpoints.clear();
    }

    push_debugger_event("debugger.breakpoints_cleared",
                        "All breakpoints/watchpoints cleared",
                        M64P_DBG_RUNSTATE_PAUSED,
                        0,
                        0,
                        0,
                        0);
    return true;
}

CORE_EXPORT bool CoreDebuggerLoadSymbolFile(const std::string& path,
                                            bool replaceExisting,
                                            uint32_t& loadedCount,
                                            uint32_t& skippedCount)
{
    std::ifstream input(path);
    if (!input.is_open())
    {
        CoreSetError("CoreDebuggerLoadSymbolFile Failed: could not open \"" + path + "\"");
        return false;
    }

    std::vector<CoreDebuggerSymbol> parsedSymbols;
    std::string line;
    loadedCount = 0;
    skippedCount = 0;

    const std::string normalizedPath = std::filesystem::path(path).lexically_normal().string();

    while (std::getline(input, line))
    {
        CoreDebuggerSymbol symbol;
        if (!parse_symbol_line(line, normalizedPath, &symbol))
        {
            skippedCount++;
            continue;
        }

        parsedSymbols.push_back(std::move(symbol));
        loadedCount++;
    }

    {
        std::scoped_lock lock(g_symbolMutex);
        if (replaceExisting)
        {
            g_symbols.clear();
            g_symbolSources.clear();
        }

        g_symbols.insert(g_symbols.end(), parsedSymbols.begin(), parsedSymbols.end());
        if (!parsedSymbols.empty())
        {
            g_symbolSources.insert(normalizedPath);
        }

        sort_and_deduplicate_symbols();
    }

    push_debugger_event("symbols.loaded",
                        "Symbol file loaded",
                        0,
                        0,
                        0,
                        0,
                        0);
    return true;
}

CORE_EXPORT void CoreDebuggerClearSymbols(void)
{
    {
        std::scoped_lock lock(g_symbolMutex);
        g_symbols.clear();
        g_symbolSources.clear();
    }

    push_debugger_event("symbols.cleared", "All loaded symbols were cleared", 0, 0, 0, 0, 0);
}

CORE_EXPORT bool CoreDebuggerGetSymbolStats(CoreDebuggerSymbolStats& stats)
{
    std::scoped_lock lock(g_symbolMutex);
    stats.symbolCount = static_cast<uint32_t>(g_symbols.size());
    stats.sourceCount = static_cast<uint32_t>(g_symbolSources.size());
    stats.sources.assign(g_symbolSources.begin(), g_symbolSources.end());
    return true;
}

CORE_EXPORT bool CoreDebuggerResolveSymbol(uint32_t address, CoreDebuggerResolvedSymbol& symbol)
{
    std::scoped_lock lock(g_symbolMutex);

    symbol = {};
    symbol.queryAddress = address;
    if (g_symbols.empty())
    {
        return true;
    }

    std::optional<uint32_t> normalizedQuery = normalize_runtime_symbol_address(address, true);
    if (!normalizedQuery.has_value())
    {
        return true;
    }

    auto iterator = find_symbol_by_address(*normalizedQuery);
    if (iterator == g_symbols.end() && !g_symbols.empty())
    {
        iterator = std::prev(g_symbols.end());
    }

    while (iterator != g_symbols.end())
    {
        std::optional<uint32_t> normalizedSymbol = normalize_runtime_symbol_address(iterator->address, false);
        if (normalizedSymbol.has_value() &&
            *normalizedSymbol <= *normalizedQuery)
        {
            symbol.found = true;
            symbol.exact = *normalizedSymbol == *normalizedQuery;
            symbol.symbolAddress = iterator->address;
            symbol.offset = *normalizedQuery - *normalizedSymbol;
            symbol.size = iterator->size;
            symbol.name = iterator->name;
            symbol.source = iterator->source;
            return true;
        }

        if (iterator == g_symbols.begin())
        {
            break;
        }

        --iterator;
    }

    return true;
}

CORE_EXPORT bool CoreDebuggerLookupSymbols(const std::string& query, uint32_t limit, std::vector<CoreDebuggerSymbol>& symbols)
{
    symbols.clear();

    std::string normalizedQuery = normalize_register_name(query);
    if (normalizedQuery.empty())
    {
        return true;
    }

    normalize_symbol_limit(&limit);

    std::scoped_lock lock(g_symbolMutex);
    for (const CoreDebuggerSymbol& symbol : g_symbols)
    {
        std::string normalizedName = normalize_register_name(symbol.name);
        if (normalizedName.find(normalizedQuery) == std::string::npos)
        {
            continue;
        }

        symbols.push_back(symbol);
        if (symbols.size() >= limit)
        {
            break;
        }
    }

    return true;
}

CORE_EXPORT bool CoreDebuggerGetEventStats(CoreDebuggerEventStats& stats)
{
    std::scoped_lock lock(g_eventMutex);
    stats.latestId = g_events.empty() ? 0 : g_events.back().id;
    stats.queuedCount = static_cast<uint32_t>(g_events.size());
    return true;
}

CORE_EXPORT bool CoreDebuggerGetEvents(uint64_t sinceId,
                                       uint32_t limit,
                                       std::vector<CoreDebuggerEvent>& events,
                                       uint64_t& latestId)
{
    events.clear();
    normalize_symbol_limit(&limit);

    std::scoped_lock lock(g_eventMutex);
    latestId = g_events.empty() ? 0 : g_events.back().id;

    for (const CoreDebuggerEvent& event : g_events)
    {
        if (event.id <= sinceId)
        {
            continue;
        }

        events.push_back(event);
        if (events.size() >= limit)
        {
            break;
        }
    }

    return true;
}

CORE_EXPORT bool CoreDebuggerStartInstructionTrace(uint32_t maxRecords, bool clearExisting)
{
    if (!ensure_debugger_available())
    {
        return false;
    }

    if (maxRecords == 0)
    {
        maxRecords = kDefaultInstructionTraceMaxRecords;
    }

    {
        std::scoped_lock lock(g_instructionTraceMutex);
        if (clearExisting)
        {
            g_instructionTrace.clear();
            g_instructionTraceStatus = {};
        }

        g_instructionTrace.reserve(std::max<size_t>(g_instructionTrace.capacity(), maxRecords));
        g_instructionTraceMaxRecords = maxRecords;
        g_instructionTraceStatus.active = true;
        g_instructionTraceStatus.truncated = false;
        g_instructionTraceStatus.maxRecords = maxRecords;
        if (g_instructionTraceStatus.startTimestampUs == 0)
        {
            g_instructionTraceStatus.startTimestampUs = monotonic_timestamp_us();
        }
    }

    return set_debugger_trace_enabled(true);
}

CORE_EXPORT bool CoreDebuggerStopInstructionTrace(void)
{
    if (!m64p::Debugger.IsHooked() ||
        m64p::Debugger.DebugSetTraceEnabled == nullptr)
    {
        CoreSetError("Core debugger trace API unavailable");
        return false;
    }

    {
        std::scoped_lock lock(g_instructionTraceMutex);
        g_instructionTraceStatus.active = false;
        if (g_instructionTraceStatus.latestTimestampUs == 0)
        {
            g_instructionTraceStatus.latestTimestampUs = monotonic_timestamp_us();
        }
    }

    return set_debugger_trace_enabled(false);
}

CORE_EXPORT bool CoreDebuggerClearInstructionTrace(void)
{
    {
        std::scoped_lock lock(g_instructionTraceMutex);
        g_instructionTrace.clear();
        g_instructionTraceStatus = {};
        g_instructionTraceMaxRecords = 0;
    }

    if (m64p::Debugger.IsHooked() &&
        m64p::Debugger.DebugSetTraceEnabled != nullptr)
    {
        m64p::Debugger.DebugSetTraceEnabled(0);
    }

    return true;
}

CORE_EXPORT bool CoreDebuggerGetInstructionTraceStatus(CoreDebuggerInstructionTraceStatus& status)
{
    std::scoped_lock lock(g_instructionTraceMutex);
    status = g_instructionTraceStatus;
    status.bufferedCount = static_cast<uint32_t>(g_instructionTrace.size());
    status.maxRecords = g_instructionTraceMaxRecords;
    return true;
}

CORE_EXPORT bool CoreDebuggerGetInstructionTrace(uint64_t startIndex,
                                                 uint32_t limit,
                                                 std::vector<CoreDebuggerInstructionTraceRecord>& records,
                                                 CoreDebuggerInstructionTraceStatus& status)
{
    records.clear();
    if (limit == 0)
    {
        CoreSetError("CoreDebuggerGetInstructionTrace Failed: limit must be greater than zero");
        return false;
    }

    limit = std::min(limit, kMaxInstructionTraceBatchSize);

    std::scoped_lock lock(g_instructionTraceMutex);
    status = g_instructionTraceStatus;
    status.bufferedCount = static_cast<uint32_t>(g_instructionTrace.size());
    status.maxRecords = g_instructionTraceMaxRecords;

    if (startIndex >= g_instructionTrace.size())
    {
        return true;
    }

    const size_t endIndex = std::min<size_t>(g_instructionTrace.size(), static_cast<size_t>(startIndex + limit));
    records.reserve(endIndex - static_cast<size_t>(startIndex));
    for (size_t index = static_cast<size_t>(startIndex); index < endIndex; index++)
    {
        records.push_back(g_instructionTrace[index]);
    }

    return true;
}
