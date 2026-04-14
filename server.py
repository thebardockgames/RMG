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


def _coerce_int(value: Any, default: int = 0) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return default
        return int(stripped, 10)
    return default


def _normalize_u64_hex(value: Any) -> str:
    if not isinstance(value, str):
        return "0000000000000000"

    stripped = value.strip()
    if stripped.lower().startswith("0x"):
        stripped = stripped[2:]
    if not stripped:
        return "0000000000000000"

    parsed = int(stripped, 16) & 0xFFFFFFFFFFFFFFFF
    return f"{parsed:016X}"


def _split_u64_words(value: Any) -> tuple[str, str]:
    normalized = _normalize_u64_hex(value)
    return normalized[:8], normalized[8:]


def _format_register_dump(registers: dict[str, Any], hi: Any, lo: Any) -> tuple[list[str], str]:
    ordered_registers = [
        ("R0", "zero"),
        ("AT", "at"),
        ("V0", "v0"),
        ("V1", "v1"),
        ("A0", "a0"),
        ("A1", "a1"),
        ("A2", "a2"),
        ("A3", "a3"),
        ("T0", "t0"),
        ("T1", "t1"),
        ("T2", "t2"),
        ("T3", "t3"),
        ("T4", "t4"),
        ("T5", "t5"),
        ("T6", "t6"),
        ("T7", "t7"),
        ("S0", "s0"),
        ("S1", "s1"),
        ("S2", "s2"),
        ("S3", "s3"),
        ("S4", "s4"),
        ("S5", "s5"),
        ("S6", "s6"),
        ("S7", "s7"),
        ("T8", "t8"),
        ("T9", "t9"),
        ("K0", "k0"),
        ("K1", "k1"),
        ("GP", "gp"),
        ("SP", "sp"),
        ("FP", "s8"),
        ("RA", "ra"),
    ]

    lines: list[str] = []
    for label, key in ordered_registers:
        upper, lower = _split_u64_words(registers.get(key))
        lines.append(f"{label:<2} {upper} {lower}")

    hi_upper, hi_lower = _split_u64_words(hi)
    lo_upper, lo_lower = _split_u64_words(lo)
    lines.append(f"HI {hi_upper} {hi_lower}")
    lines.append(f"LO {lo_upper} {lo_lower}")
    return lines, "\n".join(lines)


def _extract_registers_from_event(event: dict[str, Any], cpu_state: dict[str, Any]) -> dict[str, Any]:
    snapshot = event.get("snapshot")
    if isinstance(snapshot, dict):
        event_registers = snapshot.get("registers")
        if isinstance(event_registers, dict) and event_registers:
            merged = dict(cpu_state.get("gpr", {})) if isinstance(cpu_state.get("gpr"), dict) else {}
            merged.update(event_registers)
            return merged

    gpr = cpu_state.get("gpr")
    return dict(gpr) if isinstance(gpr, dict) else {}


def _extract_hit_summary(event: dict[str, Any]) -> dict[str, Any]:
    instruction = event.get("instruction")
    pc_symbol = event.get("pc_symbol")
    address_symbol = event.get("address_symbol")
    range_symbol = event.get("range_symbol")
    summary: dict[str, Any] = {
        "event_id": event.get("id"),
        "type": event.get("type"),
        "pc": event.get("pc"),
        "pc_symbol": _trace_symbol_name(pc_symbol),
        "address": event.get("address"),
        "address_symbol": _trace_symbol_name(address_symbol),
        "range_address": event.get("range_address"),
        "range_symbol": _trace_symbol_name(range_symbol),
        "end_address": event.get("end_address"),
        "kinds": event.get("kinds"),
        "message": event.get("message"),
    }
    if isinstance(instruction, dict):
        summary["instruction"] = instruction
    return summary


def _condense_debugger_state(state: dict[str, Any]) -> dict[str, Any]:
    return {
        "run_state": state.get("run_state"),
        "previous_pc": state.get("previous_pc"),
        "previous_pc_symbol": state.get("previous_pc_symbol"),
        "dynacore": state.get("dynacore"),
        "dynacore_raw": state.get("dynacore_raw"),
        "breakpoint_count": state.get("breakpoint_count"),
        "next_interrupt": state.get("next_interrupt"),
    }


def _event_matches_execute_target(event: dict[str, Any], address_hex: str) -> bool:
    return event.get("type") == "debugger.breakpoint_hit" and (
        event.get("pc") == address_hex or event.get("address") == address_hex or event.get("range_address") == address_hex
    )


def _event_matches_watch_target(
    event: dict[str, Any],
    requested_address_hex: str,
    installed_range_hex: str | None,
    installed_end_hex: str | None,
) -> bool:
    if event.get("type") != "debugger.watchpoint_hit":
        return False

    candidate_values = {
        event.get("address"),
        event.get("range_address"),
        requested_address_hex,
        installed_range_hex,
    }

    if event.get("range_address") not in candidate_values and event.get("address") not in candidate_values:
        return False

    if installed_end_hex is not None and event.get("end_address") not in {installed_end_hex, None, ""}:
        return False

    return True


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

        self._ws = await websockets.connect(
            self._config.uri,
            open_timeout=self._config.timeout_seconds,
            max_size=None,
        )

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
async def start_instruction_trace(max_records: int = 2_000_000, clear_existing: bool = True) -> dict[str, Any]:
    """Start a real per-instruction trace inside the running RMG core."""

    if max_records <= 0:
        raise ValueError("max_records must be greater than zero")

    response = await bridge.request(
        "start_instruction_trace",
        max_records=max_records,
        clear_existing=clear_existing,
    )
    data = response.get("data")
    if not isinstance(data, dict):
        raise BridgeProtocolError("Bridge returned a non-object payload for start_instruction_trace")
    return data


@mcp.tool()
async def stop_instruction_trace() -> dict[str, Any]:
    """Stop the active per-instruction trace in the RMG core."""

    response = await bridge.request("stop_instruction_trace")
    data = response.get("data")
    if not isinstance(data, dict):
        raise BridgeProtocolError("Bridge returned a non-object payload for stop_instruction_trace")
    return data


@mcp.tool()
async def instruction_trace_status() -> dict[str, Any]:
    """Fetch the status of the current per-instruction trace buffer."""

    response = await bridge.request("instruction_trace_status")
    data = response.get("data")
    if not isinstance(data, dict):
        raise BridgeProtocolError("Bridge returned a non-object payload for instruction_trace_status")
    return data


@mcp.tool()
async def get_instruction_trace(start_index: int = 0, limit: int = 10_000) -> dict[str, Any]:
    """Fetch a batch of per-instruction trace records from the RMG core."""

    if start_index < 0:
        raise ValueError("start_index must be zero or greater")
    if limit <= 0:
        raise ValueError("limit must be greater than zero")

    response = await bridge.request(
        "get_instruction_trace",
        start_index=start_index,
        limit=limit,
    )
    data = response.get("data")
    if not isinstance(data, dict):
        raise BridgeProtocolError("Bridge returned a non-object payload for get_instruction_trace")
    return data


@mcp.tool()
async def capture_instruction_trace(
    duration_ms: int = 1000,
    max_records: int = 2_000_000,
    reset_type: str = "hard",
    reset_before_capture: bool = True,
    resume_after_reset: bool = True,
    output_path: str = "",
) -> dict[str, Any]:
    """Capture a real per-instruction trace for a short time window and optionally export it as JSONL."""

    if duration_ms <= 0:
        raise ValueError("duration_ms must be greater than zero")
    if max_records <= 0:
        raise ValueError("max_records must be greater than zero")
    if reset_type not in {"soft", "hard"}:
        raise ValueError("reset_type must be 'soft' or 'hard'")

    if reset_before_capture:
        await bridge.request(
            "reset_emulation",
            timeout_seconds=max(bridge._config.timeout_seconds, 10.0),
            type=reset_type,
        )

    await bridge.request("clear_instruction_trace")
    start_status = await start_instruction_trace(max_records=max_records, clear_existing=True)

    if resume_after_reset:
        try:
            await bridge.request("resume_execution")
        except Exception:
            pass

    await asyncio.sleep(duration_ms / 1000.0)
    stop_status = await stop_instruction_trace()

    collected: list[dict[str, Any]] = []
    next_index = 0
    final_status = stop_status
    while True:
        batch = await get_instruction_trace(start_index=next_index, limit=10_000)
        records = batch.get("records")
        if not isinstance(records, list):
            raise BridgeProtocolError("Bridge returned a non-array records payload for capture_instruction_trace")
        for record in records:
            if isinstance(record, dict):
                collected.append(record)

        status = batch.get("status")
        if isinstance(status, dict):
            final_status = status

        returned_count = batch.get("returned_count", len(records))
        try:
            returned_count_int = int(returned_count)
        except (TypeError, ValueError) as exc:
            raise BridgeProtocolError("Bridge returned a non-integer returned_count for get_instruction_trace") from exc

        if returned_count_int <= 0:
            break

        next_index = int(str(batch.get("next_index", next_index + returned_count_int)))

    export_summary: dict[str, Any] | None = None
    if output_path.strip():
        normalized_output = os.path.abspath(output_path.strip())
        output_dir = os.path.dirname(normalized_output)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
        with open(normalized_output, "w", encoding="utf-8", newline="\n") as handle:
            for record in collected:
                handle.write(json.dumps(record, ensure_ascii=True))
                handle.write("\n")

        export_summary = {
            "path": normalized_output,
            "format": "jsonl",
            "written_records": len(collected),
        }

    return {
        "record_count": len(collected),
        "duration_ms": duration_ms,
        "max_records": max_records,
        "reset_type": reset_type if reset_before_capture else None,
        "start_status": start_status,
        "status": final_status,
        "records": collected,
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


async def _capture_debug_hits(
    *,
    add_action: str,
    remove_action: str,
    add_payload: dict[str, Any],
    remove_payload: dict[str, Any],
    match_event: Any,
    expected_event_type: str,
    hit_count: int,
    timeout_ms: int,
    poll_interval_ms: int = 25,
    reset_before_capture: bool = False,
    reset_type: str = "hard",
) -> dict[str, Any]:
    if hit_count <= 0:
        raise ValueError("hit_count must be greater than zero")
    if timeout_ms <= 0:
        raise ValueError("timeout_ms must be greater than zero")
    if poll_interval_ms <= 0:
        raise ValueError("poll_interval_ms must be greater than zero")
    if reset_type not in {"soft", "hard"}:
        raise ValueError("reset_type must be 'soft' or 'hard'")

    hits: list[dict[str, Any]] = []
    cleanup: dict[str, Any] | None = None
    initial_state = await debugger_state()
    if add_action == "add_watchpoint" and initial_state.get("run_state") != "paused":
        await pause_emulation()

    installation = await bridge.request(add_action, **add_payload)
    installation_data = installation.get("data")
    if not isinstance(installation_data, dict):
        raise BridgeProtocolError(f"Bridge returned a non-object payload for {add_action}")

    baseline = await get_debug_events(since_id=0, limit=1)
    since_id = _coerce_int(baseline.get("latest_id"))
    deadline = time.monotonic() + (timeout_ms / 1000.0)
    reset_result: dict[str, Any] | None = None

    try:
        if reset_before_capture:
            reset_result = await reset_emulation(reset_type=reset_type)
            baseline = await get_debug_events(since_id=0, limit=1)
            since_id = _coerce_int(baseline.get("latest_id"))

        if initial_state.get("run_state") != "running":
            await resume_emulation()

        while len(hits) < hit_count and time.monotonic() < deadline:
            remaining_time = max(0.1, deadline - time.monotonic())
            payload = await bridge.request(
                "get_debug_events",
                timeout_seconds=max(bridge._config.timeout_seconds, remaining_time + 1.0),
                since_id=since_id,
                limit=max(32, min(256, hit_count * 4)),
                event_types=expected_event_type,
            )
            data = payload.get("data")
            if not isinstance(data, dict):
                raise BridgeProtocolError("Bridge returned a non-object payload for get_debug_events")

            since_id = max(since_id, _coerce_int(data.get("latest_id"), since_id))
            events = data.get("events")
            if not isinstance(events, list) or not events:
                await asyncio.sleep(poll_interval_ms / 1000.0)
                continue

            matched_hit = False
            for event in events:
                if not isinstance(event, dict) or not match_event(event):
                    continue

                cpu_state = await cpu_snapshot()
                registers = _extract_registers_from_event(event, cpu_state)
                register_dump_lines, register_dump = _format_register_dump(registers, cpu_state.get("hi"), cpu_state.get("lo"))

                hit_record: dict[str, Any] = {
                    "index": len(hits) + 1,
                    "captured_at_ms": int(time.time() * 1000),
                    "event": event,
                    "cpu_snapshot": cpu_state,
                    "registers": registers,
                    "register_dump_lines": register_dump_lines,
                    "register_dump": register_dump,
                }

                watch_payload = None
                if expected_event_type == "debugger.watchpoint_hit":
                    memory_snapshot = None
                    if isinstance(event.get("snapshot"), dict):
                        memory_snapshot = event["snapshot"].get("memory")

                    watch_payload = {
                        "access": event.get("kinds"),
                        "address": event.get("address"),
                        "end_address": event.get("end_address"),
                        "range_address": event.get("range_address"),
                        "range_symbol": _trace_symbol_name(event.get("range_symbol")),
                        "memory_after": memory_snapshot,
                    }

                if watch_payload is not None:
                    hit_record["watch"] = watch_payload

                hits.append(hit_record)
                matched_hit = True
                if len(hits) >= hit_count:
                    break

            if len(hits) < hit_count and matched_hit and time.monotonic() < deadline:
                await resume_emulation()
                continue

            if not matched_hit:
                await asyncio.sleep(poll_interval_ms / 1000.0)
    finally:
        try:
            cleanup_response = await bridge.request(remove_action, **remove_payload)
            cleanup = cleanup_response.get("data") if isinstance(cleanup_response.get("data"), dict) else None
        except Exception as exc:  # noqa: BLE001
            cleanup = {"status": "error", "detail": str(exc)}

    final_state = await debugger_state()
    condensed_initial_state = _condense_debugger_state(initial_state)
    condensed_final_state = _condense_debugger_state(final_state)

    for hit in hits:
        event = hit.pop("event")
        hit["event"] = _extract_hit_summary(event)
        hit.pop("cpu_snapshot", None)

    capture_kind = "watchpoint" if expected_event_type == "debugger.watchpoint_hit" else "execute_breakpoint"
    return {
        "status": "ok",
        "capture": {
            "kind": capture_kind,
            "event_type": expected_event_type,
            "hit_count_requested": hit_count,
            "hit_count_captured": len(hits),
            "timed_out": len(hits) < hit_count,
            "timeout_ms": timeout_ms,
            "poll_interval_ms": poll_interval_ms,
            "reset_before_capture": reset_before_capture,
            "reset_type": reset_type if reset_before_capture else None,
            "latest_event_id": since_id,
        },
        "session": {
            "bridge_uri": bridge._config.uri,
            "initial_state": condensed_initial_state,
            "final_state": condensed_final_state,
            "reset_result": reset_result,
            "installation": installation_data,
            "cleanup": cleanup,
        },
        "hits": hits,
    }


@mcp.tool()
async def capture_execute_breakpoint_hits(
    address_hex: str,
    hit_count: int = 50,
    timeout_ms: int = 5000,
    end_address_hex: str = "",
    poll_interval_ms: int = 25,
    reset_before_capture: bool = False,
    reset_type: str = "hard",
) -> dict[str, Any]:
    """Capture the first N execute-breakpoint hits at an address, including a full register dump for each hit."""

    address = _normalize_hex(address_hex)
    end_address = _normalize_hex(end_address_hex) if end_address_hex.strip() else ""

    add_payload: dict[str, Any] = {
        "address": address,
        "kind": "execute",
        "enabled": True,
        "log": False,
    }
    if end_address:
        add_payload["end_address"] = end_address

    remove_payload = {"address": address}
    result = await _capture_debug_hits(
        add_action="add_breakpoint",
        remove_action="remove_breakpoint",
        add_payload=add_payload,
        remove_payload=remove_payload,
        match_event=lambda event: _event_matches_execute_target(event, address),
        expected_event_type="debugger.breakpoint_hit",
        hit_count=hit_count,
        timeout_ms=timeout_ms,
        poll_interval_ms=poll_interval_ms,
        reset_before_capture=reset_before_capture,
        reset_type=reset_type,
    )
    result["capture"]["address"] = address
    result["capture"]["end_address"] = end_address or None
    return result


@mcp.tool()
async def capture_watchpoint_hits(
    address_hex: str,
    access: str = "read_write",
    hit_count: int = 20,
    timeout_ms: int = 5000,
    size_bytes: int = 4,
    end_address_hex: str = "",
    poll_interval_ms: int = 25,
    reset_before_capture: bool = False,
    reset_type: str = "hard",
) -> dict[str, Any]:
    """Capture the first N read/write watchpoint hits at an address, including actor PC, instruction, memory snapshot and full registers."""

    if size_bytes <= 0:
        raise ValueError("size_bytes must be greater than zero")

    address = _normalize_hex(address_hex)
    normalized_end = _normalize_hex(end_address_hex) if end_address_hex.strip() else ""
    add_payload: dict[str, Any] = {
        "address": address,
        "kinds": _normalize_watchpoint_access(access),
        "enabled": True,
        "log": False,
    }
    if normalized_end:
        add_payload["end_address"] = normalized_end
    else:
        add_payload["size"] = size_bytes

    translated_start = await bridge.request("translate_address", address=address)
    translated_start_data = translated_start.get("data")
    if not isinstance(translated_start_data, dict):
        raise BridgeProtocolError("Bridge returned a non-object payload for translate_address")

    physical_start = translated_start_data.get("physical_address")
    if not isinstance(physical_start, str):
        raise BridgeProtocolError("Bridge returned a non-string physical_address for translate_address")

    physical_end: str | None = None
    if normalized_end:
        translated_end = await bridge.request("translate_address", address=normalized_end)
        translated_end_data = translated_end.get("data")
        if not isinstance(translated_end_data, dict):
            raise BridgeProtocolError("Bridge returned a non-object payload for translate_address")
        physical_end_value = translated_end_data.get("physical_address")
        if not isinstance(physical_end_value, str):
            raise BridgeProtocolError("Bridge returned a non-string physical_address for translate_address end")
        physical_end = physical_end_value
    else:
        start_value = int(physical_start, 16)
        physical_end = f"0x{start_value + size_bytes - 1:08X}"

    result = await _capture_debug_hits(
        add_action="add_watchpoint",
        remove_action="remove_breakpoint",
        add_payload=add_payload,
        remove_payload={"address": physical_start},
        match_event=lambda event: _event_matches_watch_target(
            event,
            address,
            physical_start,
            physical_end,
        ),
        expected_event_type="debugger.watchpoint_hit",
        hit_count=hit_count,
        timeout_ms=timeout_ms,
        poll_interval_ms=poll_interval_ms,
        reset_before_capture=reset_before_capture,
        reset_type=reset_type,
    )
    requested_end_address = normalized_end or f"0x{int(address, 16) + size_bytes - 1:08X}"
    result["capture"]["address"] = address
    result["capture"]["end_address"] = requested_end_address
    result["capture"]["access"] = _normalize_watchpoint_access(access)
    result["capture"]["size_bytes"] = size_bytes
    result["session"]["translated_range"] = {
        "requested_address": address,
        "requested_end_address": requested_end_address,
        "physical_address": physical_start,
        "physical_end_address": physical_end,
    }
    return result


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
