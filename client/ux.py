#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import re
import select
import sys
import time
from typing import Optional

import serial
from serial.tools import list_ports
from serial.tools.list_ports_common import ListPortInfo

DEFAULT_VID = 0xCAFE
DEFAULT_PID = 0x4002
DEFAULT_BAUDRATE = 115200
DEFAULT_PROBE_TIMEOUT_S = 0.6
DEFAULT_SERIAL_TIMEOUT_S = 0.05
DEFAULT_BANNER_PULSE_S = 0.2
EXIT_KEY = "\x1d"  # Ctrl-]

_INTERFACE_INDEX_PATTERNS = (
    re.compile(r"\bmi[_-]?(\d{2})\b", re.IGNORECASE),
    re.compile(r"\bif(?:ace)?[_-]?(\d{2})\b", re.IGNORECASE),
    re.compile(r"\binterface\s*(\d+)\b", re.IGNORECASE),
    re.compile(r":\d+\.(\d+)\b"),
)
_DEVICE_TRAILING_DIGITS_RE = re.compile(r"(\d+)$")


class UXDiscoveryError(RuntimeError):
    """Raised when the CDC0 UX port cannot be selected safely."""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Toy wallet CDC0 UX console (screen-like helper for macOS/Linux/Windows)."
    )
    parser.add_argument("port", nargs="?", help="Explicit serial port for CDC0 UX channel.")
    parser.add_argument("--vid", type=lambda value: int(value, 0), default=DEFAULT_VID)
    parser.add_argument("--pid", type=lambda value: int(value, 0), default=DEFAULT_PID)
    parser.add_argument("--baudrate", type=int, default=DEFAULT_BAUDRATE)
    parser.add_argument("--probe-timeout", type=float, default=DEFAULT_PROBE_TIMEOUT_S)
    parser.add_argument("--serial-timeout", type=float, default=DEFAULT_SERIAL_TIMEOUT_S)
    parser.add_argument(
        "--banner-pulse",
        type=float,
        default=DEFAULT_BANNER_PULSE_S,
        help="Seconds to drop/re-raise DTR after open to re-trigger CDC0 boot banner.",
    )
    return parser.parse_args()


def discover_ux_port(
    vid: int,
    pid: int,
    *,
    baudrate: int = DEFAULT_BAUDRATE,
    probe_timeout_s: float = DEFAULT_PROBE_TIMEOUT_S,
) -> str:
    matches = [port for port in list_ports.comports() if port.vid == vid and port.pid == pid]
    if not matches:
        raise UXDiscoveryError(f"No toy wallet ports found for VID:PID {vid:04x}:{pid:04x}.")

    protocol_by_meta = _pick_protocol_by_metadata(matches)
    if protocol_by_meta is not None:
        ux_candidates = [port for port in matches if port.device != protocol_by_meta.device]
        if len(ux_candidates) == 1:
            return ux_candidates[0].device

    ordered = sorted(matches, key=_candidate_sort_key)
    protocol_port: Optional[ListPortInfo] = None
    for port in ordered:
        if _probe_port_for_protocol_ping_ok(
            port.device,
            baudrate=baudrate,
            timeout_s=probe_timeout_s,
        ):
            protocol_port = port
            break

    if protocol_port is not None:
        ux_candidates = [port for port in matches if port.device != protocol_port.device]
        if len(ux_candidates) == 1:
            return ux_candidates[0].device
        if len(ux_candidates) > 1:
            by_iface = _pick_lowest_interface_index(ux_candidates)
            if by_iface is not None:
                return by_iface.device
            by_suffix = _pick_lowest_numeric_suffix(ux_candidates)
            if by_suffix is not None:
                return by_suffix.device
            devices = ", ".join(port.device for port in ux_candidates)
            raise UXDiscoveryError(
                f"Multiple CDC0 candidates detected ({devices}). "
                "Pass the port explicitly: python client/ux.py <port>."
            )
        raise UXDiscoveryError(
            f"Detected protocol port {protocol_port.device}, but no matching CDC0 peer was found."
        )

    ux_candidates: list[ListPortInfo] = []
    protocol_ports: list[ListPortInfo] = []

    for port in ordered:
        ping_ok = _probe_port_for_protocol_ping_ok(
            port.device,
            baudrate=baudrate,
            timeout_s=probe_timeout_s,
        )
        if ping_ok:
            protocol_ports.append(port)
        else:
            ux_candidates.append(port)

    if len(ux_candidates) == 1:
        return ux_candidates[0].device

    if len(ux_candidates) > 1:
        by_iface = _pick_lowest_interface_index(ux_candidates)
        if by_iface is not None:
            return by_iface.device

        by_suffix = _pick_lowest_numeric_suffix(ux_candidates)
        if by_suffix is not None:
            return by_suffix.device

        devices = ", ".join(port.device for port in ux_candidates)
        raise UXDiscoveryError(
            f"Multiple CDC0 candidates detected ({devices}). "
            "Pass the port explicitly: python client/ux.py <port>."
        )

    protocol_devices = ", ".join(port.device for port in protocol_ports) or "<none>"
    raise UXDiscoveryError(
        "Could not find CDC0 candidate by ping-negative probe. "
        f"Ports that answered ping with protocol ok: {protocol_devices}."
    )


def _candidate_sort_key(port: ListPortInfo) -> tuple[int, int, int, int, str]:
    iface_index = _extract_interface_index(port)
    suffix = _extract_numeric_suffix(port.device)
    return (
        -_platform_device_score(port.device),
        0 if iface_index is not None else 1,
        -(iface_index if iface_index is not None else -1),
        -(suffix if suffix is not None else -1),
        port.device.lower(),
    )


def _collect_port_identity_text(port: ListPortInfo) -> str:
    return " ".join(
        field.lower()
        for field in (
            port.interface,
            port.description,
            port.product,
            port.name,
            port.hwid,
            port.location,
        )
        if field
    )


def _is_protocol_hint(port: ListPortInfo) -> bool:
    text = _collect_port_identity_text(port)
    return "host proto" in text or ("host" in text and "proto" in text)


def _pick_protocol_by_metadata(ports: list[ListPortInfo]) -> Optional[ListPortInfo]:
    hinted = [port for port in ports if _is_protocol_hint(port)]
    if len(hinted) == 1:
        return hinted[0]
    return None


def _extract_interface_index(port: ListPortInfo) -> Optional[int]:
    fields = (port.interface or "", port.hwid or "", port.location or "", port.description or "")
    for field in fields:
        for pattern in _INTERFACE_INDEX_PATTERNS:
            match = pattern.search(field)
            if match:
                return int(match.group(1), 10)
    return None


def _extract_numeric_suffix(device: str) -> Optional[int]:
    match = _DEVICE_TRAILING_DIGITS_RE.search(device)
    if not match:
        return None
    return int(match.group(1), 10)


def _pick_lowest_interface_index(ports: list[ListPortInfo]) -> Optional[ListPortInfo]:
    indexed: list[tuple[int, ListPortInfo]] = []
    for port in ports:
        iface = _extract_interface_index(port)
        if iface is not None:
            indexed.append((iface, port))

    if not indexed:
        return None

    minimum = min(idx for idx, _ in indexed)
    winners = [port for idx, port in indexed if idx == minimum]
    if len(winners) == 1:
        return winners[0]
    return None


def _pick_lowest_numeric_suffix(ports: list[ListPortInfo]) -> Optional[ListPortInfo]:
    parsed: list[tuple[int, ListPortInfo]] = []
    for port in ports:
        suffix = _extract_numeric_suffix(port.device)
        if suffix is not None:
            parsed.append((suffix, port))

    if not parsed:
        return None

    minimum = min(value for value, _ in parsed)
    winners = [port for value, port in parsed if value == minimum]
    if len(winners) == 1:
        return winners[0]
    return None


def _platform_device_score(device: str) -> int:
    lowered = device.lower()
    if sys.platform == "darwin":
        if lowered.startswith("/dev/cu."):
            return 3
        if lowered.startswith("/dev/tty."):
            return 2
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


def _probe_port_for_protocol_ping_ok(device: str, *, baudrate: int, timeout_s: float) -> bool:
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
            if not line or line == "ping":
                continue
            return line == "ok"
        return False
    except (serial.SerialException, OSError):
        return False
    finally:
        if serial_port and serial_port.is_open:
            serial_port.close()


def run_console(serial_port: serial.Serial) -> None:
    print(f"[ux] Connected: {serial_port.port}", flush=True)
    print("[ux] Press Ctrl-] to exit.", flush=True)

    if os.name == "nt":
        _console_loop_windows(serial_port)
    elif os.name == "posix":
        _console_loop_posix(serial_port)
    else:
        raise RuntimeError(f"Unsupported OS for this script: {os.name!r}")


def _console_loop_windows(serial_port: serial.Serial) -> None:
    import msvcrt

    while True:
        _drain_serial(serial_port)

        if msvcrt.kbhit():
            ch = msvcrt.getwch()
            if ch in ("\x00", "\xe0"):
                # Windows emits a lead byte for function/arrow keys.
                if msvcrt.kbhit():
                    msvcrt.getwch()
                continue
            if ch in (EXIT_KEY, "\x03"):
                return
            _write_keystroke(serial_port, ch)

        time.sleep(0.01)


def _console_loop_posix(serial_port: serial.Serial) -> None:
    if not sys.stdin.isatty():
        raise RuntimeError("stdin must be a TTY for interactive console mode.")

    import termios
    import tty

    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setcbreak(fd)
        while True:
            _drain_serial(serial_port)
            readable, _, _ = select.select([sys.stdin], [], [], 0.02)
            if not readable:
                continue
            ch = sys.stdin.read(1)
            if ch in (EXIT_KEY, "\x03"):
                return
            _write_keystroke(serial_port, ch)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)


def _drain_serial(serial_port: serial.Serial) -> None:
    try:
        waiting = serial_port.in_waiting
        chunk = serial_port.read(waiting if waiting > 0 else 1)
    except serial.SerialException:
        raise RuntimeError("Serial connection lost.")
    if not chunk:
        return
    sys.stdout.write(chunk.decode("utf-8", errors="replace"))
    sys.stdout.flush()


def _write_keystroke(serial_port: serial.Serial, ch: str) -> None:
    payload = b"\n" if ch == "\r" else ch.encode("utf-8", errors="ignore")
    if not payload:
        return
    serial_port.write(payload)
    serial_port.flush()


def main() -> int:
    args = parse_args()
    port = args.port

    try:
        if not port:
            port = discover_ux_port(
                args.vid,
                args.pid,
                baudrate=args.baudrate,
                probe_timeout_s=args.probe_timeout,
            )
            print(f"[ux] Auto-selected CDC0 port: {port}", flush=True)

        with serial.Serial(
            port,
            baudrate=args.baudrate,
            timeout=args.serial_timeout,
            write_timeout=args.serial_timeout,
        ) as serial_port:
            try:
                serial_port.dtr = False
                serial_port.rts = False
                if args.banner_pulse > 0:
                    time.sleep(args.banner_pulse)
                serial_port.dtr = True
                serial_port.rts = True
            except (OSError, ValueError, AttributeError):
                pass
            time.sleep(0.12)
            run_console(serial_port)
        return 0
    except UXDiscoveryError as exc:
        print(f"[ux] discovery error: {exc}", file=sys.stderr)
        return 2
    except (serial.SerialException, OSError, PermissionError, RuntimeError) as exc:
        print(f"[ux] error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
