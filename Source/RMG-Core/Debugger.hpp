/*
 * Rosalie's Mupen GUI - https://github.com/Rosalie241/RMG
 *  Copyright (C) 2020-2026 Rosalie Wanders <rosalie@mailbox.org>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 3.
 *  You should have received a copy of the GNU General Public License
 *  along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
#ifndef CORE_DEBUGGER_HPP
#define CORE_DEBUGGER_HPP

#include <cstdint>
#include <string>
#include <vector>

struct CoreDebuggerState
{
    int runState = 0;
    uint32_t previousPc = 0;
    int breakpointCount = 0;
    int dynacore = 0;
    uint32_t nextInterrupt = 0;
};

struct CoreDebuggerInstruction
{
    uint32_t address = 0;
    uint32_t physicalAddress = 0;
    uint32_t word = 0;
    std::string mnemonic;
    std::string arguments;
};

struct CoreDebuggerBreakpoint
{
    uint32_t address = 0;
    uint32_t endAddress = 0;
    uint32_t flags = 0;
};

struct CoreDebuggerSymbol
{
    uint32_t address = 0;
    uint32_t size = 0;
    std::string name;
    std::string source;
};

struct CoreDebuggerResolvedSymbol
{
    bool found = false;
    bool exact = false;
    uint32_t queryAddress = 0;
    uint32_t symbolAddress = 0;
    uint32_t offset = 0;
    uint32_t size = 0;
    std::string name;
    std::string source;
};

struct CoreDebuggerSymbolStats
{
    uint32_t symbolCount = 0;
    uint32_t sourceCount = 0;
    std::vector<std::string> sources;
};

struct CoreDebuggerEvent
{
    struct RegisterSnapshot
    {
        bool valid = false;
        uint64_t pc = 0;
        uint64_t ra = 0;
        uint64_t sp = 0;
        uint64_t gp = 0;
        uint64_t a0 = 0;
        uint64_t a1 = 0;
        uint64_t a2 = 0;
        uint64_t a3 = 0;
        uint64_t v0 = 0;
        uint64_t v1 = 0;
        uint64_t s0 = 0;
        uint64_t s1 = 0;
        uint64_t t0 = 0;
        uint64_t t1 = 0;
    };

    struct MemorySnapshot
    {
        bool valid = false;
        bool truncated = false;
        uint32_t address = 0;
        uint32_t endAddress = 0;
        std::vector<uint8_t> bytes;
    };

    uint64_t id = 0;
    uint64_t timestampMs = 0;
    std::string type;
    std::string message;
    int runState = 0;
    uint32_t pc = 0;
    uint32_t address = 0;
    uint32_t rangeAddress = 0;
    uint32_t endAddress = 0;
    uint32_t flags = 0;
    RegisterSnapshot registerSnapshot;
    MemorySnapshot memorySnapshot;
};

struct CoreDebuggerEventStats
{
    uint64_t latestId = 0;
    uint32_t queuedCount = 0;
};

void CoreDebuggerResetSession(void);
bool CoreDebuggerConfigureCallbacks(void);
bool CoreDebuggerSupported(void);
bool CoreDebuggerReadMemory(uint32_t address, uint32_t size, std::vector<uint8_t>& bytes);
bool CoreDebuggerWriteMemory(uint32_t address, const std::vector<uint8_t>& bytes);
bool CoreDebuggerReadCpuRegister(std::string name, uint64_t& value);
bool CoreDebuggerWriteCpuRegister(std::string name, uint64_t value);
bool CoreDebuggerGetState(CoreDebuggerState& state);
bool CoreDebuggerVirtualToPhysical(uint32_t virtualAddress, uint32_t& physicalAddress);
bool CoreDebuggerDecodeInstruction(uint32_t address, uint32_t instructionWord, CoreDebuggerInstruction& instruction);
bool CoreDebuggerDisassemble(uint32_t address, uint32_t instructionCount, std::vector<CoreDebuggerInstruction>& instructions);
bool CoreDebuggerPauseExecution(void);
bool CoreDebuggerResumeExecution(void);
bool CoreDebuggerStepInstructions(uint32_t count, uint32_t& currentPc);
bool CoreDebuggerRunUntil(uint32_t address, uint32_t timeoutMs, uint32_t& currentPc, bool& hitTarget);
bool CoreDebuggerStepOver(uint32_t timeoutMs, uint32_t& currentPc, bool& steppedOverCall);
bool CoreDebuggerStepOut(uint32_t timeoutMs, uint32_t& currentPc, uint32_t& returnAddress, bool& hitTarget);
bool CoreDebuggerAddBreakpoint(uint32_t address, uint32_t endAddress, uint32_t flags, int& breakpointIndex);
bool CoreDebuggerRemoveBreakpoint(uint32_t address);
bool CoreDebuggerListBreakpoints(std::vector<CoreDebuggerBreakpoint>& breakpoints);
bool CoreDebuggerClearBreakpoints(void);
bool CoreDebuggerLoadSymbolFile(const std::string& path, bool replaceExisting, uint32_t& loadedCount, uint32_t& skippedCount);
void CoreDebuggerClearSymbols(void);
bool CoreDebuggerGetSymbolStats(CoreDebuggerSymbolStats& stats);
bool CoreDebuggerResolveSymbol(uint32_t address, CoreDebuggerResolvedSymbol& symbol);
bool CoreDebuggerLookupSymbols(const std::string& query, uint32_t limit, std::vector<CoreDebuggerSymbol>& symbols);
bool CoreDebuggerGetEventStats(CoreDebuggerEventStats& stats);
bool CoreDebuggerGetEvents(uint64_t sinceId,
                           uint32_t limit,
                           std::vector<CoreDebuggerEvent>& events,
                           uint64_t& latestId);

#endif // CORE_DEBUGGER_HPP
