from __future__ import annotations

import re
import sys
import time
from dataclasses import dataclass
from enum import IntEnum
from typing import Optional

import serial
from serial.tools import list_ports
from serial.tools.list_ports_common import ListPortInfo

_OPCODE_RE = re.compile(r"^[A-Za-z0-9_]{1,7}$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_INTERFACE_INDEX_PATTERNS = (
    re.compile(r"\bmi[_-]?(\d{2})\b", re.IGNORECASE),
    re.compile(r"\bif(?:ace)?[_-]?(\d{2})\b", re.IGNORECASE),
    re.compile(r"\binterface\s*(\d+)\b", re.IGNORECASE),
    re.compile(r":\d+\.(\d+)\b"),
)
_DEVICE_TRAILING_DIGITS_RE = re.compile(r"(\d+)$")


class WalletUIState(IntEnum):
    BOOT = 0x00
    LOCKED = 0x01
    PIN_ENTRY = 0x02
    UNLOCKED = 0x03
    ONBOARDING = 0x04
    ERROR = 0xFF


UI_STATE_BOOT_HEX = f"{WalletUIState.BOOT:02x}"
UI_STATE_LOCKED_HEX = f"{WalletUIState.LOCKED:02x}"
UI_STATE_PIN_ENTRY_HEX = f"{WalletUIState.PIN_ENTRY:02x}"
UI_STATE_UNLOCKED_HEX = f"{WalletUIState.UNLOCKED:02x}"
UI_STATE_ONBOARDING_HEX = f"{WalletUIState.ONBOARDING:02x}"
UI_STATE_ERROR_HEX = f"{WalletUIState.ERROR:02x}"


class PortDiscoveryError(RuntimeError):
    """Raised when the toy wallet CDC protocol port cannot be chosen safely."""


class ProtocolError(RuntimeError):
    """Raised when the firmware response is malformed."""


@dataclass(frozen=True)
class ProtocolResponse:
    status: str
    hex_arg: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.status == "ok"


def discover_protocol_port(
    vid: int,
    pid: int,
    interface_hint: str = "Host Proto",
    interface_index_hint: Optional[int] = 2,
) -> str:
    matches = [port for port in list_ports.comports() if port.vid == vid and port.pid == pid]
    if not matches:
        raise PortDiscoveryError(
            f"No USB CDC ports found for toy wallet VID:PID {vid:04x}:{pid:04x}."
        )

    scored = sorted(
        ((_port_score(port, interface_hint), port) for port in matches),
        key=lambda item: item[0],
        reverse=True,
    )
    top_score = scored[0][0]
    top = [port for score, port in scored if score == top_score]

    if len(top) == 1:
        return top[0].device

    if interface_index_hint is not None:
        hinted = [port for port in top if _extract_interface_index(port) == interface_index_hint]
        if len(hinted) == 1:
            return hinted[0].device
        if hinted:
            top = hinted

    interface_indices = [
        interface_idx
        for interface_idx in (_extract_interface_index(port) for port in top)
        if interface_idx is not None
    ]
    if interface_indices:
        max_iface = max(interface_indices)
        iface_best = [port for port in top if _extract_interface_index(port) == max_iface]
        if len(iface_best) == 1:
            return iface_best[0].device
        if iface_best:
            top = iface_best

    platform_best = _filter_by_platform_device(top)
    if len(platform_best) == 1:
        return platform_best[0].device
    if platform_best:
        top = platform_best

    responsive = _probe_candidates_for_ping(top)
    if len(responsive) == 1:
        return responsive[0].device
    if responsive:
        top = responsive

    numeric_best = _pick_highest_numeric_suffix(top)
    if numeric_best is not None:
        return numeric_best.device

    candidates = ", ".join(sorted(port.device for port in top))
    raise PortDiscoveryError(
        f"Multiple candidate toy wallet CDC ports found: {candidates}. "
        "Set --toy-wallet-port or TOY_WALLET_PORT."
    )


def _port_score(port: ListPortInfo, interface_hint: str) -> int:
    score = 0
    if interface_hint:
        hint = interface_hint.lower()
        for field in (port.interface, port.description, port.product, port.name, port.hwid):
            if field and hint in field.lower():
                score += 4
                break

    interface_idx = _extract_interface_index(port)
    if interface_idx is not None:
        score += min(interface_idx, 4)

    interface = (port.interface or "").lower()
    if "host" in interface:
        score += 1
    if "proto" in interface:
        score += 1
    score += _platform_device_score(port.device)
    return score


def _extract_interface_index(port: ListPortInfo) -> Optional[int]:
    fields = [
        port.interface or "",
        port.hwid or "",
        port.location or "",
        port.description or "",
    ]
    for field in fields:
        for pattern in _INTERFACE_INDEX_PATTERNS:
            match = pattern.search(field)
            if match:
                return int(match.group(1), 10)
    return None


def _platform_device_score(device: str) -> int:
    lowered = device.lower()
    if sys.platform == "darwin":
        if lowered.startswith("/dev/cu."):
            return 2
        if lowered.startswith("/dev/tty."):
            return 1
        return 0

    if sys.platform.startswith("linux"):
        if lowered.startswith("/dev/ttyacm"):
            return 3
        if lowered.startswith("/dev/ttyusb"):
            return 2
        if lowered.startswith("/dev/ttys"):
            return 1
        return 0

    if sys.platform.startswith("win") and lowered.startswith("com"):
        return 2

    return 0


def _filter_by_platform_device(ports: list[ListPortInfo]) -> list[ListPortInfo]:
    if not ports:
        return ports
    ranked = [(_platform_device_score(port.device), port) for port in ports]
    max_rank = max(score for score, _ in ranked)
    if max_rank <= 0:
        return []
    return [port for score, port in ranked if score == max_rank]


def _probe_candidates_for_ping(
    ports: list[ListPortInfo], baudrate: int = 115200, timeout_s: float = 0.6
) -> list[ListPortInfo]:
    responsive: list[ListPortInfo] = []
    for port in ports:
        if _probe_port_for_ping(port.device, baudrate=baudrate, timeout_s=timeout_s):
            responsive.append(port)
    return responsive


def _probe_port_for_ping(device: str, baudrate: int, timeout_s: float) -> bool:
    serial_port: Optional[serial.Serial] = None
    try:
        serial_port = serial.Serial(
            device,
            baudrate=baudrate,
            timeout=timeout_s,
            write_timeout=timeout_s,
        )
        try:
            serial_port.dtr = True
            serial_port.rts = True
        except (OSError, ValueError, AttributeError):
            pass
        time.sleep(0.12)
        serial_port.reset_input_buffer()
        serial_port.reset_output_buffer()
        serial_port.write(b"ping\n")
        serial_port.flush()

        deadline = time.monotonic() + max(timeout_s * 2.0, 0.5)
        while time.monotonic() < deadline:
            raw = serial_port.readline()
            if not raw:
                continue
            try:
                line = raw.decode("ascii", errors="strict").rstrip("\r\n")
            except UnicodeDecodeError:
                continue
            if line == "ping":
                continue
            if line == "ok":
                return True
        return False
    except (serial.SerialException, OSError):
        return False
    finally:
        if serial_port and serial_port.is_open:
            serial_port.close()


def _pick_highest_numeric_suffix(ports: list[ListPortInfo]) -> Optional[ListPortInfo]:
    if not ports:
        return None
    parsed: list[tuple[int, ListPortInfo]] = []
    for port in ports:
        match = _DEVICE_TRAILING_DIGITS_RE.search(port.device)
        if match:
            parsed.append((int(match.group(1), 10), port))
    if not parsed:
        return None
    highest = max(value for value, _ in parsed)
    winners = [port for value, port in parsed if value == highest]
    if len(winners) == 1:
        return winners[0]
    return None


class ToyWalletCDCClient:
    def __init__(self, port: str, baudrate: int = 115200, timeout: float = 2.0) -> None:
        self.port = port
        self.baudrate = baudrate
        self.timeout = timeout
        self._serial: Optional[serial.Serial] = None

    def __enter__(self) -> "ToyWalletCDCClient":
        self.open()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def open(self) -> None:
        if self._serial and self._serial.is_open:
            return
        self._serial = serial.Serial(
            self.port,
            baudrate=self.baudrate,
            timeout=self.timeout,
            write_timeout=self.timeout,
        )
        try:
            self._serial.dtr = True
            self._serial.rts = True
        except (OSError, ValueError, AttributeError):
            pass
        time.sleep(0.12)
        self._serial.reset_input_buffer()
        self._serial.reset_output_buffer()

    def close(self) -> None:
        if self._serial and self._serial.is_open:
            self._serial.close()
        self._serial = None

    def request(
        self, opcode: str, arg_hex: Optional[str] = None, timeout: Optional[float] = None
    ) -> ProtocolResponse:
        if not _OPCODE_RE.fullmatch(opcode):
            raise ValueError(f"Invalid opcode {opcode!r}.")
        if timeout is not None and timeout <= 0:
            raise ValueError("timeout must be > 0 when provided.")
        if arg_hex is not None:
            if len(arg_hex) == 0 or len(arg_hex) % 2 != 0 or not _HEX_RE.fullmatch(arg_hex):
                raise ValueError("arg_hex must be an even-length hex string.")
            line = f"{opcode} {arg_hex}"
        else:
            line = opcode
        return self.command(line, timeout=timeout)

    def command(self, line: str, timeout: Optional[float] = None) -> ProtocolResponse:
        if "\n" in line or "\r" in line:
            raise ValueError("Command line must not contain CR/LF characters.")
        if timeout is not None and timeout <= 0:
            raise ValueError("timeout must be > 0 when provided.")
        serial_port = self._require_open()
        original_timeout = serial_port.timeout
        original_write_timeout = serial_port.write_timeout
        try:
            effective_timeout = timeout if timeout is not None else self.timeout
            if timeout is not None:
                serial_port.timeout = timeout
                serial_port.write_timeout = timeout
            serial_port.write(f"{line}\n".encode("ascii"))
            serial_port.flush()

            deadline = time.monotonic() + effective_timeout
            while time.monotonic() < deadline:
                raw = serial_port.readline()
                if not raw:
                    continue
                response = raw.decode("ascii", errors="strict").rstrip("\r\n")
                if self._is_echo_line(response, line):
                    continue
                return self._parse_response(response)
            raise TimeoutError(f"No response from toy wallet on {self.port} for command {line!r}.")
        finally:
            if timeout is not None:
                serial_port.timeout = original_timeout
                serial_port.write_timeout = original_write_timeout

    def _require_open(self) -> serial.Serial:
        if self._serial is None or not self._serial.is_open:
            raise RuntimeError("Serial port is not open.")
        return self._serial

    @staticmethod
    def _parse_response(response: str) -> ProtocolResponse:
        parts = response.split(" ")
        if len(parts) == 1 and parts[0] == "ok":
            return ProtocolResponse(status="ok")
        if len(parts) == 1 and parts[0] == "err":
            return ProtocolResponse(status="err")
        if len(parts) == 2 and parts[0] == "ok":
            hex_arg = parts[1]
            if len(hex_arg) % 2 != 0 or not _HEX_RE.fullmatch(hex_arg):
                raise ProtocolError(f"Malformed hex payload in response: {response!r}")
            return ProtocolResponse(status="ok", hex_arg=hex_arg.lower())
        raise ProtocolError(f"Malformed response line: {response!r}")

    @staticmethod
    def _is_echo_line(response: str, command_line: str) -> bool:
        if not response:
            return True
        return response == command_line
