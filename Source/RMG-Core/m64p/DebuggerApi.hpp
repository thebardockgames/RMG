/*
 * Rosalie's Mupen GUI - https://github.com/Rosalie241/RMG
 *  Copyright (C) 2020-2026 Rosalie Wanders <rosalie@mailbox.org>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 3.
 *  You should have received a copy of the GNU General Public License
 *  along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
#ifndef M64P_DEBUGGERAPI_HPP
#define M64P_DEBUGGERAPI_HPP

#include "api/m64p_common.h"
#include "api/m64p_debugger.h"

#include <string>

namespace m64p
{
class DebuggerApi
{
  public:
    DebuggerApi();
    ~DebuggerApi();

    DebuggerApi(const DebuggerApi&) = delete;

    bool Hook(m64p_dynlib_handle handle);
    bool Unhook(void);
    bool IsHooked(void);

    m64p_dynlib_handle GetHandle(void);
    std::string GetLastError(void);

    ptr_DebugSetCallbacks DebugSetCallbacks;
    ptr_DebugSetCoreCompare DebugSetCoreCompare;
    ptr_DebugSetRunState DebugSetRunState;
    ptr_DebugGetState DebugGetState;
    ptr_DebugStep DebugStep;
    ptr_DebugDecodeOp DebugDecodeOp;
    ptr_DebugMemGetRecompInfo DebugMemGetRecompInfo;
    ptr_DebugMemGetMemInfo DebugMemGetMemInfo;
    ptr_DebugMemGetPointer DebugMemGetPointer;
    ptr_DebugMemRead64 DebugMemRead64;
    ptr_DebugMemRead32 DebugMemRead32;
    ptr_DebugMemRead16 DebugMemRead16;
    ptr_DebugMemRead8 DebugMemRead8;
    ptr_DebugMemWrite64 DebugMemWrite64;
    ptr_DebugMemWrite32 DebugMemWrite32;
    ptr_DebugMemWrite16 DebugMemWrite16;
    ptr_DebugMemWrite8 DebugMemWrite8;
    ptr_DebugGetCPUDataPtr DebugGetCPUDataPtr;
    ptr_DebugBreakpointLookup DebugBreakpointLookup;
    ptr_DebugBreakpointCommand DebugBreakpointCommand;
    ptr_DebugBreakpointTriggeredBy DebugBreakpointTriggeredBy;
    ptr_DebugVirtualToPhysical DebugVirtualToPhysical;

  private:
    bool hooked = false;

    std::string errorMessage;
    m64p_dynlib_handle handle;
};
} // namespace m64p

#endif // M64P_DEBUGGERAPI_HPP
