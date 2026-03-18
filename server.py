from __future__ import annotations

import asyncio
import json
import os
import time
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


def _flatten_json(prefix: str, value: Any, output: dict[str, Any]) -> None:
    if isinstance(value, dict):
        for key in sorted(value):
            child_prefix = f"{prefix}.{key}" if prefix else str(key)
            _flatten_json(child_prefix, value[key], output)
        return

    if isinstance(value, list):
        for index, item in enumerate(value):
            child_prefix = f"{prefix}[{index}]"
            _flatten_json(child_prefix, item, output)
        return

    output[prefix] = value


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


def _require_trace_path(path: str) -> str:
    normalized = os.path.abspath(path.strip())
    if not normalized:
        raise ValueError("trace path must not be empty")
    if not os.path.isfile(normalized):
        raise FileNotFoundError(f"trace file does not exist: {normalized}")
    return normalized


def _load_jsonl_trace(path: str) -> list[dict[str, Any]]:
    normalized_path = _require_trace_path(path)
    events: list[dict[str, Any]] = []
    with open(normalized_path, "r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue

            try:
                payload = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSONL in {normalized_path} at line {line_number}: {exc}") from exc

            if not isinstance(payload, dict):
                raise ValueError(f"invalid JSONL in {normalized_path} at line {line_number}: expected object")

            events.append(payload)

    return events


def _trace_symbol_name(value: Any) -> str | None:
    if not isinstance(value, dict):
        return None

    name = value.get("name")
    if isinstance(name, str) and name:
        return name
    return None


def _trace_event_signature(
    event: dict[str, Any],
    *,
    ignore_timestamps: bool,
    ignore_event_ids: bool,
) -> dict[str, Any]:
    signature: dict[str, Any] = {
        "type": event.get("type"),
        "run_state": event.get("run_state"),
        "pc": event.get("pc"),
        "address": event.get("address"),
        "end_address": event.get("end_address"),
        "flags": event.get("flags"),
        "kinds": event.get("kinds"),
        "message": event.get("message"),
        "pc_symbol": _trace_symbol_name(event.get("pc_symbol")),
        "address_symbol": _trace_symbol_name(event.get("address_symbol")),
    }

    if not ignore_event_ids:
        signature["id"] = event.get("id")
    if not ignore_timestamps:
        signature["timestamp_ms"] = event.get("timestamp_ms")

    instruction = event.get("instruction")
    if isinstance(instruction, dict):
        signature["instruction"] = {
            "address": instruction.get("address"),
            "word": instruction.get("word"),
            "mnemonic": instruction.get("mnemonic"),
            "arguments": instruction.get("arguments"),
            "text": instruction.get("text"),
        }

    return signature


def _trace_type_counts(events: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for event in events:
        event_type = event.get("type")
        if isinstance(event_type, str) and event_type:
            counts[event_type] = counts.get(event_type, 0) + 1
    return counts


def _trace_summary(path: str, events: list[dict[str, Any]]) -> dict[str, Any]:
    pcs = [event.get("pc") for event in events if isinstance(event.get("pc"), str)]
    return {
        "path": os.path.abspath(path),
        "event_count": len(events),
        "type_counts": _trace_type_counts(events),
        "first_pc": pcs[0] if pcs else None,
        "last_pc": pcs[-1] if pcs else None,
    }


def _diff_trace_signatures(left: dict[str, Any], right: dict[str, Any]) -> list[str]:
    left_flat: dict[str, Any] = {}
    right_flat: dict[str, Any] = {}
    _flatten_json("", left, left_flat)
    _flatten_json("", right, right_flat)

    keys = sorted(set(left_flat) | set(right_flat))
    return [key for key in keys if left_flat.get(key) != right_flat.get(key)]


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

    async def request(self, action: str, timeout_seconds: float | None = None, **payload: Any) -> dict[str, Any]:
        async with self._lock:
            return await self._request_locked(action, timeout_seconds=timeout_seconds, **payload)

    async def _request_locked(self, action: str, timeout_seconds: float | None = None, **payload: Any) -> dict[str, Any]:
        request_id = str(uuid.uuid4())
        request_body = {"id": request_id, "action": action, **payload}
        effective_timeout = self._config.timeout_seconds if timeout_seconds is None else timeout_seconds

        await self._ensure_connected()
        assert self._ws is not None

        try:
            await asyncio.wait_for(self._ws.send(json.dumps(request_body)), timeout=effective_timeout)
            raw_response = await self._recv_response_locked(request_id, timeout_seconds=effective_timeout)
        except ConnectionClosed:
            await self._reset_connection()
            await self._ensure_connected()
            assert self._ws is not None
            await asyncio.wait_for(self._ws.send(json.dumps(request_body)), timeout=effective_timeout)
            raw_response = await self._recv_response_locked(request_id, timeout_seconds=effective_timeout)

        response = self._decode_response(raw_response)
        response_id = response.get("id")
        if response_id is not None and response_id != request_id:
            raise BridgeProtocolError(
                f"Bridge returned mismatched id. expected={request_id} received={response_id}"
            )

        if response.get("status") != "ok":
            raise RuntimeError(str(response.get("error", "Unknown bridge error")))

        return response

    async def _recv_response_locked(self, request_id: str, timeout_seconds: float) -> Any:
        assert self._ws is not None

        while True:
            raw_message = await asyncio.wait_for(self._ws.recv(), timeout=timeout_seconds)
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
async def reset_emulation(reset_type: str = "soft") -> dict[str, Any]:
    """Reset the currently running ROM. Use soft for console-style reset or hard for full machine reset."""

    normalized = reset_type.strip().lower()
    if normalized not in {"soft", "hard"}:
        raise ValueError("reset_type must be either 'soft' or 'hard'")

    response = await bridge.request("reset_emulation", type=normalized)
    data = response.get("data")
    if not isinstance(data, dict):
        raise BridgeProtocolError("Bridge returned a non-object payload for reset_emulation")
    return data


@mcp.tool()
async def restart_rom() -> dict[str, Any]:
    """Shut down and relaunch the current ROM through RMG's normal startup path."""

    response = await bridge.request("restart_rom", timeout_seconds=max(bridge._config.timeout_seconds, 10.0))
    data = response.get("data")
    if not isinstance(data, dict):
        raise BridgeProtocolError("Bridge returned a non-object payload for restart_rom")
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
async def step_over(timeout_ms: int = 5000) -> dict[str, Any]:
    """Advance past the current instruction, running through a call if the current opcode links and branches."""

    if timeout_ms <= 0:
        raise ValueError("timeout_ms must be greater than zero")

    response = await bridge.request(
        "step_over",
        timeout_seconds=max(bridge._config.timeout_seconds, (timeout_ms / 1000.0) + 1.0),
        timeout_ms=timeout_ms,
    )
    data = response.get("data")
    if not isinstance(data, dict):
        raise BridgeProtocolError("Bridge returned a non-object payload for step_over")
    return data


@mcp.tool()
async def step_out(timeout_ms: int = 5000) -> dict[str, Any]:
    """Run until the current function returns to the address stored in $ra."""

    if timeout_ms <= 0:
        raise ValueError("timeout_ms must be greater than zero")

    response = await bridge.request(
        "step_out",
        timeout_seconds=max(bridge._config.timeout_seconds, (timeout_ms / 1000.0) + 1.0),
        timeout_ms=timeout_ms,
    )
    data = response.get("data")
    if not isinstance(data, dict):
        raise BridgeProtocolError("Bridge returned a non-object payload for step_out")
    return data


@mcp.tool()
async def run_until_address(address_hex: str, timeout_ms: int = 5000) -> dict[str, Any]:
    """Resume execution until the CPU reaches a target address or the timeout expires."""

    if timeout_ms <= 0:
        raise ValueError("timeout_ms must be greater than zero")

    response = await bridge.request(
        "run_until",
        timeout_seconds=max(bridge._config.timeout_seconds, (timeout_ms / 1000.0) + 1.0),
        address=_normalize_hex(address_hex),
        timeout_ms=timeout_ms,
    )
    data = response.get("data")
    if not isinstance(data, dict):
        raise BridgeProtocolError("Bridge returned a non-object payload for run_until")
    return data


@mcp.tool()
async def run_until_symbol(symbol_name: str, offset_bytes: int = 0, timeout_ms: int = 5000) -> dict[str, Any]:
    """Resume execution until the CPU reaches an exact loaded symbol plus an optional byte offset."""

    if timeout_ms <= 0:
        raise ValueError("timeout_ms must be greater than zero")

    response = await bridge.request(
        "run_until",
        timeout_seconds=max(bridge._config.timeout_seconds, (timeout_ms / 1000.0) + 1.0),
        symbol=_normalize_symbol_name(symbol_name),
        offset=offset_bytes,
        timeout_ms=timeout_ms,
    )
    data = response.get("data")
    if not isinstance(data, dict):
        raise BridgeProtocolError("Bridge returned a non-object payload for run_until_symbol")
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
    pc_start_hex: str = "",
    pc_end_hex: str = "",
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
    if pc_start_hex.strip() or pc_end_hex.strip():
        if not pc_start_hex.strip() or not pc_end_hex.strip():
            raise ValueError("pc_start_hex and pc_end_hex must be provided together")
        payload["pc_start"] = _normalize_hex(pc_start_hex)
        payload["pc_end"] = _normalize_hex(pc_end_hex)

    response = await bridge.request("get_debug_events", **payload)
    data = response.get("data")
    if not isinstance(data, dict):
        raise BridgeProtocolError("Bridge returned a non-object payload for get_debug_events")
    return data


@mcp.tool()
async def capture_instruction_trace(
    duration_ms: int = 1000,
    poll_interval_ms: int = 25,
    event_types: str = "debugger.update,execution.step,debugger.breakpoint_hit,debugger.watchpoint_hit,execution.run_until_completed,execution.run_until_stopped",
    pc_start_hex: str = "",
    pc_end_hex: str = "",
    output_path: str = "",
) -> dict[str, Any]:
    """Poll structured execution events for a short time window and optionally export them as JSONL."""

    if duration_ms <= 0:
        raise ValueError("duration_ms must be greater than zero")
    if poll_interval_ms <= 0:
        raise ValueError("poll_interval_ms must be greater than zero")

    initial = await get_debug_events(limit=1)
    latest = initial.get("latest_id", "0")
    try:
        since_id = int(str(latest))
    except ValueError as exc:
        raise BridgeProtocolError("Bridge returned a non-integer latest_id") from exc

    deadline = time.monotonic() + (duration_ms / 1000.0)
    collected: list[dict[str, Any]] = []

    while time.monotonic() < deadline:
        batch = await get_debug_events(
            since_id=since_id,
            limit=512,
            event_types=event_types,
            pc_start_hex=pc_start_hex,
            pc_end_hex=pc_end_hex,
        )

        events = batch.get("events")
        if not isinstance(events, list):
            raise BridgeProtocolError("Bridge returned a non-array events payload for capture_instruction_trace")

        for event in events:
            if isinstance(event, dict):
                collected.append(event)

        latest = batch.get("latest_id", since_id)
        try:
            since_id = int(str(latest))
        except ValueError as exc:
            raise BridgeProtocolError("Bridge returned a non-integer latest_id during capture_instruction_trace") from exc

        await asyncio.sleep(poll_interval_ms / 1000.0)

    export_summary: dict[str, Any] | None = None
    if output_path.strip():
        normalized_output = os.path.abspath(output_path.strip())
        output_dir = os.path.dirname(normalized_output)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
        with open(normalized_output, "w", encoding="utf-8", newline="\n") as handle:
            for event in collected:
                handle.write(json.dumps(event, ensure_ascii=True))
                handle.write("\n")

        export_summary = {
            "path": normalized_output,
            "format": "jsonl",
            "written_events": len(collected),
        }

    return {
        "event_count": len(collected),
        "latest_id": since_id,
        "duration_ms": duration_ms,
        "poll_interval_ms": poll_interval_ms,
        "event_types": event_types,
        "pc_start_hex": pc_start_hex.strip() or None,
        "pc_end_hex": pc_end_hex.strip() or None,
        "events": collected,
        "export": export_summary,
    }


@mcp.tool()
async def compare_trace_files(
    trace_a_path: str,
    trace_b_path: str,
    max_differences: int = 20,
    ignore_timestamps: bool = True,
    ignore_event_ids: bool = True,
) -> dict[str, Any]:
    """Compare two JSONL trace files and report the first useful divergences for recompilation work."""

    if max_differences <= 0:
        raise ValueError("max_differences must be greater than zero")

    trace_a = _load_jsonl_trace(trace_a_path)
    trace_b = _load_jsonl_trace(trace_b_path)

    summary_a = _trace_summary(trace_a_path, trace_a)
    summary_b = _trace_summary(trace_b_path, trace_b)

    common_prefix = 0
    divergences: list[dict[str, Any]] = []

    compare_count = min(len(trace_a), len(trace_b))
    for index in range(compare_count):
        left_signature = _trace_event_signature(
            trace_a[index],
            ignore_timestamps=ignore_timestamps,
            ignore_event_ids=ignore_event_ids,
        )
        right_signature = _trace_event_signature(
            trace_b[index],
            ignore_timestamps=ignore_timestamps,
            ignore_event_ids=ignore_event_ids,
        )

        if left_signature == right_signature:
            common_prefix += 1
            continue

        divergences.append(
            {
                "index": index,
                "differing_fields": _diff_trace_signatures(left_signature, right_signature),
                "trace_a": left_signature,
                "trace_b": right_signature,
            }
        )
        if len(divergences) >= max_differences:
            break

    tail_difference: dict[str, Any] | None = None
    if len(trace_a) != len(trace_b):
        if len(trace_a) > len(trace_b):
            tail_difference = {
                "trace": "a",
                "extra_events": len(trace_a) - len(trace_b),
                "first_extra_index": len(trace_b),
            }
        else:
            tail_difference = {
                "trace": "b",
                "extra_events": len(trace_b) - len(trace_a),
                "first_extra_index": len(trace_a),
            }

    exact_match = common_prefix == compare_count and len(trace_a) == len(trace_b)

    return {
        "exact_match": exact_match,
        "common_prefix_events": common_prefix,
        "compared_events": compare_count,
        "same_length": len(trace_a) == len(trace_b),
        "trace_a": summary_a,
        "trace_b": summary_b,
        "tail_difference": tail_difference,
        "divergence_count": len(divergences),
        "first_divergence_index": divergences[0]["index"] if divergences else None,
        "divergences": divergences,
    }


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
