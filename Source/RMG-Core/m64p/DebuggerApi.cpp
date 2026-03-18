/*
 * Rosalie's Mupen GUI - https://github.com/Rosalie241/RMG
 *  Copyright (C) 2020-2026 Rosalie Wanders <rosalie@mailbox.org>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 3.
 *  You should have received a copy of the GNU General Public License
 *  along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
#include "DebuggerApi.hpp"
#include "Macros.hpp"

using namespace m64p;

DebuggerApi::DebuggerApi(void)
{
    this->Unhook();
}

DebuggerApi::~DebuggerApi(void)
{
}

bool DebuggerApi::Hook(m64p_dynlib_handle handle)
{
    this->errorMessage = "DebuggerApi::Hook Failed: ";

    this->DebugSetCallbacks =
        reinterpret_cast<ptr_DebugSetCallbacks>(CoreGetLibrarySymbol(handle, "DebugSetCallbacks"));
    this->DebugSetCoreCompare =
        reinterpret_cast<ptr_DebugSetCoreCompare>(CoreGetLibrarySymbol(handle, "DebugSetCoreCompare"));
    this->DebugSetRunState =
        reinterpret_cast<ptr_DebugSetRunState>(CoreGetLibrarySymbol(handle, "DebugSetRunState"));
    this->DebugGetState =
        reinterpret_cast<ptr_DebugGetState>(CoreGetLibrarySymbol(handle, "DebugGetState"));
    this->DebugStep =
        reinterpret_cast<ptr_DebugStep>(CoreGetLibrarySymbol(handle, "DebugStep"));
    this->DebugDecodeOp =
        reinterpret_cast<ptr_DebugDecodeOp>(CoreGetLibrarySymbol(handle, "DebugDecodeOp"));
    this->DebugMemGetRecompInfo =
        reinterpret_cast<ptr_DebugMemGetRecompInfo>(CoreGetLibrarySymbol(handle, "DebugMemGetRecompInfo"));
    this->DebugMemGetMemInfo =
        reinterpret_cast<ptr_DebugMemGetMemInfo>(CoreGetLibrarySymbol(handle, "DebugMemGetMemInfo"));
    this->DebugMemGetPointer =
        reinterpret_cast<ptr_DebugMemGetPointer>(CoreGetLibrarySymbol(handle, "DebugMemGetPointer"));
    this->DebugMemRead64 =
        reinterpret_cast<ptr_DebugMemRead64>(CoreGetLibrarySymbol(handle, "DebugMemRead64"));
    this->DebugMemRead32 =
        reinterpret_cast<ptr_DebugMemRead32>(CoreGetLibrarySymbol(handle, "DebugMemRead32"));
    this->DebugMemRead16 =
        reinterpret_cast<ptr_DebugMemRead16>(CoreGetLibrarySymbol(handle, "DebugMemRead16"));
    this->DebugMemRead8 =
        reinterpret_cast<ptr_DebugMemRead8>(CoreGetLibrarySymbol(handle, "DebugMemRead8"));
    this->DebugMemWrite64 =
        reinterpret_cast<ptr_DebugMemWrite64>(CoreGetLibrarySymbol(handle, "DebugMemWrite64"));
    this->DebugMemWrite32 =
        reinterpret_cast<ptr_DebugMemWrite32>(CoreGetLibrarySymbol(handle, "DebugMemWrite32"));
    this->DebugMemWrite16 =
        reinterpret_cast<ptr_DebugMemWrite16>(CoreGetLibrarySymbol(handle, "DebugMemWrite16"));
    this->DebugMemWrite8 =
        reinterpret_cast<ptr_DebugMemWrite8>(CoreGetLibrarySymbol(handle, "DebugMemWrite8"));
    this->DebugGetCPUDataPtr =
        reinterpret_cast<ptr_DebugGetCPUDataPtr>(CoreGetLibrarySymbol(handle, "DebugGetCPUDataPtr"));
    this->DebugBreakpointLookup =
        reinterpret_cast<ptr_DebugBreakpointLookup>(CoreGetLibrarySymbol(handle, "DebugBreakpointLookup"));
    this->DebugBreakpointCommand =
        reinterpret_cast<ptr_DebugBreakpointCommand>(CoreGetLibrarySymbol(handle, "DebugBreakpointCommand"));
    this->DebugBreakpointTriggeredBy =
        reinterpret_cast<ptr_DebugBreakpointTriggeredBy>(CoreGetLibrarySymbol(handle, "DebugBreakpointTriggeredBy"));
    this->DebugVirtualToPhysical =
        reinterpret_cast<ptr_DebugVirtualToPhysical>(CoreGetLibrarySymbol(handle, "DebugVirtualToPhysical"));

    if (this->DebugGetState == nullptr ||
        this->DebugMemGetMemInfo == nullptr ||
        this->DebugMemRead8 == nullptr ||
        this->DebugGetCPUDataPtr == nullptr)
    {
        this->errorMessage += "required debugger symbols were not exported by the core library";
        this->Unhook();
        return false;
    }

    this->handle = handle;
    this->hooked = true;
    return true;
}

bool DebuggerApi::Unhook(void)
{
    this->DebugSetCallbacks = nullptr;
    this->DebugSetCoreCompare = nullptr;
    this->DebugSetRunState = nullptr;
    this->DebugGetState = nullptr;
    this->DebugStep = nullptr;
    this->DebugDecodeOp = nullptr;
    this->DebugMemGetRecompInfo = nullptr;
    this->DebugMemGetMemInfo = nullptr;
    this->DebugMemGetPointer = nullptr;
    this->DebugMemRead64 = nullptr;
    this->DebugMemRead32 = nullptr;
    this->DebugMemRead16 = nullptr;
    this->DebugMemRead8 = nullptr;
    this->DebugMemWrite64 = nullptr;
    this->DebugMemWrite32 = nullptr;
    this->DebugMemWrite16 = nullptr;
    this->DebugMemWrite8 = nullptr;
    this->DebugGetCPUDataPtr = nullptr;
    this->DebugBreakpointLookup = nullptr;
    this->DebugBreakpointCommand = nullptr;
    this->DebugBreakpointTriggeredBy = nullptr;
    this->DebugVirtualToPhysical = nullptr;

    this->handle = nullptr;
    this->hooked = false;
    return true;
}

bool DebuggerApi::IsHooked(void)
{
    return this->hooked;
}

m64p_dynlib_handle DebuggerApi::GetHandle(void)
{
    return this->handle;
}

std::string DebuggerApi::GetLastError(void)
{
    return this->errorMessage;
}
