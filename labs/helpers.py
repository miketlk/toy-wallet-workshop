from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from typing import Optional
import re

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from client import (
    PortDiscoveryError,
    ProtocolResponse,
    ToyWalletCDCClient,
    UI_STATE_UNLOCKED_HEX,
    discover_protocol_port,
)

DEFAULT_VID = 0xCAFE
DEFAULT_PID = 0x4002
DEFAULT_INTERFACE_HINT = "Host Proto"
DEFAULT_INTERFACE_INDEX = 2
DEFAULT_SERIAL_TIMEOUT_S = 2.0
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_DIGITS_RE = re.compile(r"^[0-9]+$")


def add_wallet_cli_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--port", help="Explicit serial port path. If omitted, auto-discovery is used."
    )
    parser.add_argument("--vid", type=lambda value: int(value, 0), default=DEFAULT_VID)
    parser.add_argument("--pid", type=lambda value: int(value, 0), default=DEFAULT_PID)
    parser.add_argument("--interface", default=DEFAULT_INTERFACE_HINT)
    parser.add_argument(
        "--interface-index",
        default=str(DEFAULT_INTERFACE_INDEX),
        help="Preferred USB interface index (use 'auto' or 'none' to disable hint).",
    )
    parser.add_argument("--serial-timeout", type=float, default=DEFAULT_SERIAL_TIMEOUT_S)


def parse_optional_int(value: str) -> Optional[int]:
    normalized = value.strip().lower()
    if normalized in ("", "auto", "none"):
        return None
    return int(value, 0)


def resolve_wallet_port(args: argparse.Namespace) -> str:
    if args.port:
        return args.port
    interface_index_hint = parse_optional_int(args.interface_index)
    return discover_protocol_port(
        vid=args.vid,
        pid=args.pid,
        interface_hint=args.interface,
        interface_index_hint=interface_index_hint,
    )


def create_wallet_client(
    args: argparse.Namespace, *, port: Optional[str] = None
) -> ToyWalletCDCClient:
    wallet_port = port if port is not None else resolve_wallet_port(args)
    return ToyWalletCDCClient(port=wallet_port, timeout=args.serial_timeout)


def timestamp() -> str:
    return time.strftime("%H:%M:%S")


def log(message: str) -> None:
    print(f"[{timestamp()}] {message}", flush=True)


def format_duration_hhmmss(total_seconds: float) -> str:
    seconds = int(round(total_seconds))
    hours, remainder = divmod(seconds, 3600)
    minutes, secs = divmod(remainder, 60)
    return f"{hours:02d}:{minutes:02d}:{secs:02d}"


def is_unlocked(
    wallet: ToyWalletCDCClient, unlocked_state_hex: str = UI_STATE_UNLOCKED_HEX
) -> bool:
    response = wallet.request("state")
    return response.ok and response.hex_arg == unlocked_state_hex


def timed_pin_request(
    wallet: ToyWalletCDCClient, pin_hex: str, timeout_s: float = None
) -> tuple[ProtocolResponse, float]:
    start_ns = time.perf_counter_ns()
    response = wallet.request("pin", pin_hex, timeout=timeout_s)
    elapsed_s = (time.perf_counter_ns() - start_ns) / 1_000_000_000.0
    return response, elapsed_s


def parse_ok_hex_response(response: ProtocolResponse) -> bytes:
    if not response.ok or response.hex_arg is None:
        raise RuntimeError(f"expected 'ok <hex>' response, got status={response.status!r}")
    return bytes.fromhex(response.hex_arg)


def encode_info_len_hex(length: int, max_bytes: int = 4) -> str:
    if length < 0:
        raise ValueError("length must be >= 0")
    byte_len = max(1, (length.bit_length() + 7) // 8)
    if byte_len > max_bytes:
        raise ValueError(f"length {length} does not fit in {max_bytes} bytes")
    return f"{length:0{byte_len * 2}x}"


def normalize_pin_hex(pin_hex: str) -> str:
    pin = pin_hex.strip().lower()
    if len(pin) == 0 or (len(pin) % 2) != 0 or not _HEX_RE.fullmatch(pin):
        raise ValueError("pin must be a non-empty even-length hex string")
    return pin


def normalize_pin_digits(pin_digits: str) -> str:
    pin = pin_digits.strip()
    if len(pin) == 0 or not _DIGITS_RE.fullmatch(pin):
        raise ValueError("pin must be a non-empty decimal digit string")
    return pin


def pin_digits_to_hex(pin_digits: str) -> str:
    return "".join(f"{int(d):02x}" for d in normalize_pin_digits(pin_digits))


def format_bytes_as_u32_le_words(data: bytes) -> str:
    words = []
    for i in range(0, len(data), 4):
        chunk = data[i : i + 4]
        if len(chunk) == 4:
            words.append(f"0x{int.from_bytes(chunk, byteorder='little'):08X}")
        else:
            padded = chunk.ljust(4, b"\x00")
            words.append(
                f"0x{int.from_bytes(padded, byteorder='little'):08X}(partial:{chunk.hex()})"
            )
    return " ".join(words)


class PayloadComposer:
    def __init__(self) -> None:
        self._buf = bytearray()

    def __len__(self) -> int:
        return len(self._buf)

    def put(self, value: bytes | bytearray | int, repeat: int = 1, thumb: bool = False) -> None:
        if repeat < 0:
            raise ValueError("repeat must be >= 0")
        if repeat == 0:
            return

        if isinstance(value, (bytes, bytearray)):
            if thumb:
                raise ValueError("thumb is only allowed when value is int")
            self._buf.extend(bytes(value) * repeat)
            return

        if isinstance(value, int):
            if repeat == 1:
                if value < 0 or value > 0xFFFFFFFF:
                    raise ValueError("u32 value must be in [0, 0xFFFFFFFF]")
                encoded = (value | 1) if thumb else value
                self._buf.extend(encoded.to_bytes(4, byteorder="little", signed=False))
                return

            if thumb:
                raise ValueError("thumb is only allowed for single u32 put(int)")
            if value < 0 or value > 0xFF:
                raise ValueError("repeated byte value must be in [0, 255]")
            self._buf.extend(bytes([value]) * repeat)
            return

        raise TypeError("value must be bytes, bytearray, or int")

    def to_bytes(self) -> bytes:
        return bytes(self._buf)

    def __bytes__(self) -> bytes:
        return self.to_bytes()
