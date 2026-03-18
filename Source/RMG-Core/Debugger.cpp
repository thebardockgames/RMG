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
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <mutex>

namespace
{
constexpr uint32_t kMaxRdramSize = UINT32_C(0x00800000);
constexpr uint32_t kMinInstructionSize = UINT32_C(4);

std::mutex g_breakpointMutex;
std::vector<CoreDebuggerBreakpoint> g_managedBreakpoints;
bool g_debuggerCallbacksConfigured = false;

void debugger_ui_init_callback(void)
{
}

void debugger_ui_update_callback(unsigned int pc)
{
    (void)pc;
}

void debugger_ui_vi_callback(void)
{
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
    std::scoped_lock lock(g_breakpointMutex);
    g_managedBreakpoints.clear();
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

    return true;
}
