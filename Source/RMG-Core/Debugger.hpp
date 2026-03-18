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
bool CoreDebuggerAddBreakpoint(uint32_t address, uint32_t endAddress, uint32_t flags, int& breakpointIndex);
bool CoreDebuggerRemoveBreakpoint(uint32_t address);
bool CoreDebuggerListBreakpoints(std::vector<CoreDebuggerBreakpoint>& breakpoints);
bool CoreDebuggerClearBreakpoints(void);

#endif // CORE_DEBUGGER_HPP
