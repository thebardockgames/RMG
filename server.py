from __future__ import annotations

import asyncio
import json
import os
import uuid
from collections import deque
from dataclasses import dataclass
from typing import Any

from mcp.server.fastmcp import FastMCP
import websockets
from websockets.exceptions import ConnectionClosed


DEFAULT_BRIDGE_HOST = os.environ.get("RMG_MCP_HOST", "127.0.0.1")
DEFAULT_BRIDGE_PORT = int(os.environ.get("RMG_MCP_PORT", "8765"))
DEFAULT_BRIDGE_TIMEOUT = float(os.environ.get("RMG_MCP_TIMEOUT_SECONDS", "2.0"))


class BridgeProtocolError(RuntimeError):
    """Raised when the local RMG bridge returns an invalid payload."""


def _normalize_hex(text: str, *, even_length: bool = False) -> str:
    value = text.strip()
    if value.lower().startswith("0x"):
        value = value[2:]

    if not value:
        raise ValueError("hex value must not be empty")

    int(value, 16)

    if even_length and (len(value) % 2) != 0:
        value = "0" + value

    return "0x" + value.upper()


def _normalize_breakpoint_kind(kind: str) -> str:
    normalized = kind.strip().lower()
    aliases = {
        "x": "execute",
        "exec": "execute",
        "execute": "execute",
        "r": "read",
        "read": "read",
        "w": "write",
        "write": "write",
    }
    if normalized not in aliases:
        raise ValueError("kind must be one of: execute, read, write")
    return aliases[normalized]


def _normalize_watchpoint_access(access: str) -> list[str]:
    normalized = access.strip().lower().replace("-", "_")
    aliases = {
        "r": ["read"],
        "read": ["read"],
        "w": ["write"],
        "write": ["write"],
        "rw": ["read", "write"],
        "wr": ["read", "write"],
        "read_write": ["read", "write"],
        "write_read": ["read", "write"],
        "x": ["execute"],
        "exec": ["execute"],
        "execute": ["execute"],
    }
    if normalized not in aliases:
        raise ValueError("access must be one of: read, write, read_write, execute")
    return aliases[normalized]


def _normalize_symbol_name(symbol_name: str) -> str:
    normalized = symbol_name.strip()
    if not normalized:
        raise ValueError("symbol_name must not be empty")
    return normalized


@dataclass(slots=True)
class BridgeConfig:
    host: str = DEFAULT_BRIDGE_HOST
    port: int = DEFAULT_BRIDGE_PORT
    timeout_seconds: float = DEFAULT_BRIDGE_TIMEOUT

    @property
    def uri(self) -> str:
        return f"ws://{self.host}:{self.port}"


class RmgBridgeClient:
    """Async JSON client for the local WebSocket bridge embedded in RMG."""

    def __init__(self, config: BridgeConfig) -> None:
        self._config = config
        self._lock = asyncio.Lock()
        self._ws: Any | None = None
        self._event_buffer: deque[dict[str, Any]] = deque(maxlen=1024)

    async def close(self) -> None:
        async with self._lock:
            if self._ws is not None:
                await self._ws.close()
                self._ws = None

    async def request(self, action: str, **payload: Any) -> dict[str, Any]:
        async with self._lock:
            return await self._request_locked(action, **payload)

    async def _request_locked(self, action: str, **payload: Any) -> dict[str, Any]:
        request_id = str(uuid.uuid4())
        request_body = {"id": request_id, "action": action, **payload}

        await self._ensure_connected()
        assert self._ws is not None

        try:
            await asyncio.wait_for(self._ws.send(json.dumps(request_body)), timeout=self._config.timeout_seconds)
            raw_response = await self._recv_response_locked(request_id)
        except ConnectionClosed:
            await self._reset_connection()
            await self._ensure_connected()
            assert self._ws is not None
            await asyncio.wait_for(self._ws.send(json.dumps(request_body)), timeout=self._config.timeout_seconds)
            raw_response = await self._recv_response_locked(request_id)

        response = self._decode_response(raw_response)
        response_id = response.get("id")
        if response_id is not None and response_id != request_id:
            raise BridgeProtocolError(
                f"Bridge returned mismatched id. expected={request_id} received={response_id}"
            )

        if response.get("status") != "ok":
            raise RuntimeError(str(response.get("error", "Unknown bridge error")))

        return response

    async def _recv_response_locked(self, request_id: str) -> Any:
        assert self._ws is not None

        while True:
            raw_message = await asyncio.wait_for(self._ws.recv(), timeout=self._config.timeout_seconds)
            payload = self._decode_response(raw_message)

            if payload.get("type") == "event":
                self._event_buffer.append(payload)
                continue

            response_id = payload.get("id")
            if response_id is not None and response_id != request_id:
                raise BridgeProtocolError(
                    f"Bridge returned mismatched id. expected={request_id} received={response_id}"
                )

            return raw_message

    async def _ensure_connected(self) -> None:
        if self._ws is not None:
            return

        self._ws = await websockets.connect(self._config.uri, open_timeout=self._config.timeout_seconds)

    async def _reset_connection(self) -> None:
        if self._ws is not None:
            try:
                await self._ws.close()
            finally:
                self._ws = None

    def drain_buffered_events(self) -> list[dict[str, Any]]:
        events = list(self._event_buffer)
        self._event_buffer.clear()
        return events

    @staticmethod
    def _decode_response(raw_response: Any) -> dict[str, Any]:
        if not isinstance(raw_response, str):
            raise BridgeProtocolError("Bridge returned a non-text WebSocket frame")

        try:
            payload = json.loads(raw_response)
        except json.JSONDecodeError as exc:
            raise BridgeProtocolError(f"Bridge returned invalid JSON: {exc}") from exc

        if not isinstance(payload, dict):
            raise BridgeProtocolError("Bridge returned a JSON value that is not an object")

        return payload


bridge = RmgBridgeClient(BridgeConfig())

mcp = FastMCP(
    name="rmg-n64-debugger",
    instructions=(
        "Lee, escribe y depura el estado de una instancia local de RMG mediante un bridge WebSocket. "
        "Usa estas herramientas para descompilacion, recompilacion, analisis de ensamblador MIPS, "
        "inspeccion de RDRAM, control de ejecucion y breakpoints."
    ),
    json_response=True,
)


@mcp.tool()
async def read_rdram(address_hex: str, size_bytes: int) -> str:
    """Read bytes from emulated N64 RDRAM using a CPU address like 0x80000000."""

    if size_bytes <= 0:
        raise ValueError("size_bytes must be greater than zero")

    response = await bridge.request("read_ram", address=_normalize_hex(address_hex), size=size_bytes)
    data = response.get("data")
    if not isinstance(data, str):
        raise BridgeProtocolError("Bridge returned a non-string payload for read_ram")
    return data


@mcp.tool()
async def write_rdram(address_hex: str, data_hex: str) -> dict[str, Any]:
    """Write bytes into RDRAM. The debugger should be paused before patching memory."""

    response = await bridge.request(
        "write_ram",
        address=_normalize_hex(address_hex),
        data=_normalize_hex(data_hex, even_length=True),
    )
    data = response.get("data")
    if not isinstance(data, dict):
        raise BridgeProtocolError("Bridge returned a non-object payload for write_ram")
    return data


@mcp.tool()
async def read_symbol(symbol_name: str, size_bytes: int, offset_bytes: int = 0) -> str:
    """Read bytes starting at an exact loaded symbol name plus an optional byte offset."""

    if size_bytes <= 0:
        raise ValueError("size_bytes must be greater than zero")

    response = await bridge.request(
        "read_ram",
        symbol=_normalize_symbol_name(symbol_name),
        offset=offset_bytes,
        size=size_bytes,
    )
    data = response.get("data")
    if not isinstance(data, str):
        raise BridgeProtocolError("Bridge returned a non-string payload for read_symbol")
    return data


@mcp.tool()
async def write_symbol(symbol_name: str, data_hex: str, offset_bytes: int = 0) -> dict[str, Any]:
    """Write bytes at an exact loaded symbol name plus an optional byte offset."""

    response = await bridge.request(
        "write_ram",
        symbol=_normalize_symbol_name(symbol_name),
        offset=offset_bytes,
        data=_normalize_hex(data_hex, even_length=True),
    )
    data = response.get("data")
    if not isinstance(data, dict):
        raise BridgeProtocolError("Bridge returned a non-object payload for write_symbol")
    return data


@mcp.tool()
async def read_mips_register(register_name: str) -> str:
    """Read one VR4300 register by name, for example pc, ra, sp, a0, t0 or status."""

    normalized_name = register_name.strip()
    if not normalized_name:
        raise ValueError("register_name must not be empty")

    response = await bridge.request("read_register", register=normalized_name)
    data = response.get("data")
    if not isinstance(data, str):
        raise BridgeProtocolError("Bridge returned a non-string payload for read_register")
    return data


@mcp.tool()
async def write_mips_register(register_name: str, value_hex: str) -> str:
    """Write one VR4300 register. The debugger should be paused before mutating registers."""

    normalized_name = register_name.strip()
    if not normalized_name:
        raise ValueError("register_name must not be empty")

    response = await bridge.request(
        "write_register",
        register=normalized_name,
        value=_normalize_hex(value_hex),
    )
    data = response.get("data")
    if not isinstance(data, str):
        raise BridgeProtocolError("Bridge returned a non-string payload for write_register")
    return data


@mcp.tool()
async def debugger_state() -> dict[str, Any]:
    """Return debugger run state, previous PC, dynacore information and breakpoint counts."""

    response = await bridge.request("debugger_state")
    data = response.get("data")
    if not isinstance(data, dict):
        raise BridgeProtocolError("Bridge returned a non-object payload for debugger_state")
    return data


@mcp.tool()
async def cpu_snapshot() -> dict[str, Any]:
    """Return a broad CPU snapshot including PC, HI/LO, GPRs, COP0 and debugger state."""

    response = await bridge.request("cpu_snapshot")
    data = response.get("data")
    if not isinstance(data, dict):
        raise BridgeProtocolError("Bridge returned a non-object payload for cpu_snapshot")
    return data


@mcp.tool()
async def translate_address(address_hex: str) -> dict[str, Any]:
    """Translate a virtual CPU address to a physical address when the core can resolve it."""

    response = await bridge.request("translate_address", address=_normalize_hex(address_hex))
    data = response.get("data")
    if not isinstance(data, dict):
        raise BridgeProtocolError("Bridge returned a non-object payload for translate_address")
    return data


@mcp.tool()
async def resolve_symbol_name(symbol_name: str, offset_bytes: int = 0) -> dict[str, Any]:
    """Resolve an exact symbol name to its virtual and physical address, optionally applying a byte offset."""

    response = await bridge.request(
        "translate_address",
        symbol=_normalize_symbol_name(symbol_name),
        offset=offset_bytes,
    )
    data = response.get("data")
    if not isinstance(data, dict):
        raise BridgeProtocolError("Bridge returned a non-object payload for resolve_symbol_name")
    return data


@mcp.tool()
async def disassemble_rdram(address_hex: str, instruction_count: int = 8) -> list[dict[str, Any]]:
    """Disassemble MIPS instructions from RDRAM starting at the given address."""

    if instruction_count <= 0:
        raise ValueError("instruction_count must be greater than zero")

    response = await bridge.request(
        "disassemble",
        address=_normalize_hex(address_hex),
        instruction_count=instruction_count,
    )
    data = response.get("data")
    if not isinstance(data, list):
        raise BridgeProtocolError("Bridge returned a non-array payload for disassemble")
    return [item for item in data if isinstance(item, dict)]


@mcp.tool()
async def disassemble_symbol(
    symbol_name: str,
    instruction_count: int = 8,
    offset_bytes: int = 0,
) -> list[dict[str, Any]]:
    """Disassemble instructions starting from an exact symbol name plus an optional byte offset."""

    if instruction_count <= 0:
        raise ValueError("instruction_count must be greater than zero")

    response = await bridge.request(
        "disassemble",
        symbol=_normalize_symbol_name(symbol_name),
        offset=offset_bytes,
        instruction_count=instruction_count,
    )
    data = response.get("data")
    if not isinstance(data, list):
        raise BridgeProtocolError("Bridge returned a non-array payload for disassemble_symbol")
    return [item for item in data if isinstance(item, dict)]


@mcp.tool()
async def pause_emulation() -> dict[str, Any]:
    """Pause execution at debugger granularity so memory, registers and breakpoints can be edited safely."""

    response = await bridge.request("pause_execution")
    data = response.get("data")
    if not isinstance(data, dict):
        raise BridgeProtocolError("Bridge returned a non-object payload for pause_execution")
    return data


@mcp.tool()
async def resume_emulation() -> dict[str, Any]:
    """Resume execution after a debugger pause."""

    response = await bridge.request("resume_execution")
    data = response.get("data")
    if not isinstance(data, dict):
        raise BridgeProtocolError("Bridge returned a non-object payload for resume_execution")
    return data


@mcp.tool()
async def step_instruction(count: int = 1) -> dict[str, Any]:
    """Execute one or more MIPS instructions while the debugger is paused."""

    if count <= 0:
        raise ValueError("count must be greater than zero")

    response = await bridge.request("step_instruction", count=count)
    data = response.get("data")
    if not isinstance(data, dict):
        raise BridgeProtocolError("Bridge returned a non-object payload for step_instruction")
    return data


@mcp.tool()
async def add_breakpoint(
    address_hex: str,
    kind: str = "execute",
    end_address_hex: str | None = None,
    enabled: bool = True,
    log: bool = False,
) -> dict[str, Any]:
    """Add a breakpoint for execute, read or write access."""

    payload: dict[str, Any] = {
        "address": _normalize_hex(address_hex),
        "kind": _normalize_breakpoint_kind(kind),
        "enabled": enabled,
        "log": log,
    }
    if end_address_hex is not None and end_address_hex.strip():
        payload["end_address"] = _normalize_hex(end_address_hex)

    response = await bridge.request("add_breakpoint", **payload)
    data = response.get("data")
    if not isinstance(data, dict):
        raise BridgeProtocolError("Bridge returned a non-object payload for add_breakpoint")
    return data


@mcp.tool()
async def remove_breakpoint(address_hex: str) -> dict[str, Any]:
    """Remove a breakpoint by its starting address."""

    response = await bridge.request("remove_breakpoint", address=_normalize_hex(address_hex))
    data = response.get("data")
    if not isinstance(data, dict):
        raise BridgeProtocolError("Bridge returned a non-object payload for remove_breakpoint")
    return data


@mcp.tool()
async def remove_symbol_breakpoint(symbol_name: str, offset_bytes: int = 0) -> dict[str, Any]:
    """Remove an execute breakpoint using an exact symbol name plus an optional byte offset."""

    response = await bridge.request(
        "remove_breakpoint",
        symbol=_normalize_symbol_name(symbol_name),
        offset=offset_bytes,
    )
    data = response.get("data")
    if not isinstance(data, dict):
        raise BridgeProtocolError("Bridge returned a non-object payload for remove_symbol_breakpoint")
    return data


@mcp.tool()
async def remove_symbol_watchpoint(symbol_name: str, offset_bytes: int = 0) -> dict[str, Any]:
    """Remove a memory watchpoint using an exact symbol name plus an optional byte offset."""

    resolved = await bridge.request(
        "translate_address",
        symbol=_normalize_symbol_name(symbol_name),
        offset=offset_bytes,
    )
    payload = resolved.get("data")
    if not isinstance(payload, dict):
        raise BridgeProtocolError("Bridge returned a non-object payload for translate_address")

    physical_address = payload.get("physical_address")
    if not isinstance(physical_address, str):
        raise BridgeProtocolError("Bridge returned a non-string physical_address for remove_symbol_watchpoint")

    response = await bridge.request("remove_breakpoint", address=physical_address)
    data = response.get("data")
    if not isinstance(data, dict):
        raise BridgeProtocolError("Bridge returned a non-object payload for remove_symbol_watchpoint")
    return data


@mcp.tool()
async def list_breakpoints() -> dict[str, Any]:
    """List breakpoints tracked through the MCP bridge and report the core breakpoint count."""

    response = await bridge.request("list_breakpoints")
    data = response.get("data")
    if not isinstance(data, dict):
        raise BridgeProtocolError("Bridge returned a non-object payload for list_breakpoints")
    return data


@mcp.tool()
async def clear_breakpoints() -> dict[str, Any]:
    """Remove all breakpoints from the running core and clear the bridge registry."""

    response = await bridge.request("clear_breakpoints")
    data = response.get("data")
    if not isinstance(data, dict):
        raise BridgeProtocolError("Bridge returned a non-object payload for clear_breakpoints")
    return data


@mcp.tool()
async def add_watchpoint(
    address_hex: str,
    access: str = "read_write",
    end_address_hex: str | None = None,
    enabled: bool = True,
    log: bool = False,
) -> dict[str, Any]:
    """Add a watchpoint for read, write or execute access. Memory watchpoints are translated to physical addresses automatically."""

    payload: dict[str, Any] = {
        "address": _normalize_hex(address_hex),
        "kinds": _normalize_watchpoint_access(access),
        "enabled": enabled,
        "log": log,
    }
    if end_address_hex is not None and end_address_hex.strip():
        payload["end_address"] = _normalize_hex(end_address_hex)

    response = await bridge.request("add_watchpoint", **payload)
    data = response.get("data")
    if not isinstance(data, dict):
        raise BridgeProtocolError("Bridge returned a non-object payload for add_watchpoint")
    return data


@mcp.tool()
async def add_symbol_breakpoint(
    symbol_name: str,
    kind: str = "execute",
    offset_bytes: int = 0,
    end_offset_bytes: int | None = None,
    size_bytes: int | None = None,
    enabled: bool = True,
    log: bool = False,
) -> dict[str, Any]:
    """Add an execute breakpoint using an exact symbol name plus an optional byte offset or byte range."""

    normalized_kind = _normalize_breakpoint_kind(kind)
    if normalized_kind != "execute":
        raise ValueError("add_symbol_breakpoint only supports execute breakpoints; use add_symbol_watchpoint for memory access")

    payload: dict[str, Any] = {
        "symbol": _normalize_symbol_name(symbol_name),
        "offset": offset_bytes,
        "kind": normalized_kind,
        "enabled": enabled,
        "log": log,
    }
    if end_offset_bytes is not None:
        payload["end_symbol"] = payload["symbol"]
        payload["end_offset"] = end_offset_bytes
    elif size_bytes is not None:
        if size_bytes <= 0:
            raise ValueError("size_bytes must be greater than zero")
        payload["size"] = size_bytes

    response = await bridge.request("add_breakpoint", **payload)
    data = response.get("data")
    if not isinstance(data, dict):
        raise BridgeProtocolError("Bridge returned a non-object payload for add_symbol_breakpoint")
    return data


@mcp.tool()
async def add_symbol_watchpoint(
    symbol_name: str,
    access: str = "read_write",
    offset_bytes: int = 0,
    size_bytes: int = 4,
    enabled: bool = True,
    log: bool = False,
) -> dict[str, Any]:
    """Add a watchpoint using an exact symbol name plus an optional byte offset and byte size."""

    if size_bytes <= 0:
        raise ValueError("size_bytes must be greater than zero")

    response = await bridge.request(
        "add_watchpoint",
        symbol=_normalize_symbol_name(symbol_name),
        offset=offset_bytes,
        kinds=_normalize_watchpoint_access(access),
        size=size_bytes,
        enabled=enabled,
        log=log,
    )
    data = response.get("data")
    if not isinstance(data, dict):
        raise BridgeProtocolError("Bridge returned a non-object payload for add_symbol_watchpoint")
    return data


@mcp.tool()
async def load_symbols(symbol_path: str, replace_existing: bool = True) -> dict[str, Any]:
    """Load a linker map or symbol text file so addresses can be resolved to names and labels."""

    response = await bridge.request(
        "load_symbols",
        path=symbol_path.strip(),
        replace=replace_existing,
    )
    data = response.get("data")
    if not isinstance(data, dict):
        raise BridgeProtocolError("Bridge returned a non-object payload for load_symbols")
    return data


@mcp.tool()
async def clear_symbols() -> dict[str, Any]:
    """Clear all currently loaded symbols and map-file metadata."""

    response = await bridge.request("clear_symbols")
    data = response.get("data")
    if not isinstance(data, dict):
        raise BridgeProtocolError("Bridge returned a non-object payload for clear_symbols")
    return data


@mcp.tool()
async def symbol_status() -> dict[str, Any]:
    """Report how many symbols are loaded and which source files they came from."""

    response = await bridge.request("symbol_status")
    data = response.get("data")
    if not isinstance(data, dict):
        raise BridgeProtocolError("Bridge returned a non-object payload for symbol_status")
    return data


@mcp.tool()
async def resolve_symbol(address_hex: str) -> dict[str, Any]:
    """Resolve a CPU address to the nearest loaded symbol, including offset within that symbol."""

    response = await bridge.request("resolve_symbol", address=_normalize_hex(address_hex))
    data = response.get("data")
    if not isinstance(data, dict):
        raise BridgeProtocolError("Bridge returned a non-object payload for resolve_symbol")
    return data


@mcp.tool()
async def lookup_symbol(query: str, limit: int = 20) -> list[dict[str, Any]]:
    """Find loaded symbols by partial name match for fast navigation through decomp labels or map entries."""

    if limit <= 0:
        raise ValueError("limit must be greater than zero")

    response = await bridge.request("lookup_symbol", query=query.strip(), limit=limit)
    data = response.get("data")
    if not isinstance(data, list):
        raise BridgeProtocolError("Bridge returned a non-array payload for lookup_symbol")
    return [item for item in data if isinstance(item, dict)]


@mcp.tool()
async def get_debug_events(
    since_id: int = 0,
    limit: int = 100,
    event_types: str = "",
) -> dict[str, Any]:
    """Fetch structured debugger events such as breakpoint hits, watchpoint hits, stepping and symbol loading."""

    if since_id < 0:
        raise ValueError("since_id must be zero or greater")
    if limit <= 0:
        raise ValueError("limit must be greater than zero")

    payload: dict[str, Any] = {
        "since_id": since_id,
        "limit": limit,
    }
    if event_types.strip():
        payload["event_types"] = event_types

    response = await bridge.request("get_debug_events", **payload)
    data = response.get("data")
    if not isinstance(data, dict):
        raise BridgeProtocolError("Bridge returned a non-object payload for get_debug_events")
    return data


@mcp.tool()
async def bridge_status() -> dict[str, Any]:
    """Check connectivity to the local RMG bridge."""

    try:
        response = await bridge.request("ping")
    except Exception as exc:  # noqa: BLE001
        return {
            "status": "error",
            "bridge_uri": bridge._config.uri,
            "detail": str(exc),
        }

    return {
        "status": "ok",
        "bridge_uri": bridge._config.uri,
        "reply": response.get("data"),
    }


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
