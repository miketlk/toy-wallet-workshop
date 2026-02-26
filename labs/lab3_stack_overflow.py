#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys

from helpers import (
    add_wallet_cli_args,
    create_wallet_client,
    format_bytes_as_u32_le_words,
    is_unlocked,
    log,
    resolve_wallet_port,
    normalize_pin_digits,
    pin_digits_to_hex,
)
from client.toy_wallet_usb import PortDiscoveryError, ToyWalletCDCClient


def build_overflow_payload(
    ret_addr: int,
    payload_bytes: int,
) -> bytes:
    # TODO(workshop, ~10 min):
    # Build a stack-overflow payload for the `pass` command:
    # - start with payload_bytes of filler bytes (e.g. "A" or 0x41)
    # - append ret_addr as 4-byte little-endian
    # - return raw payload bytes

    raise NotImplementedError("TODO: implement build_overflow_payload")


def send_pass_command(
    wallet: ToyWalletCDCClient,
    hex_data: str,
    timeout_s: float = 2.0,
) -> None:
    response = wallet.request("pass", hex_data, timeout=timeout_s)
    if not response.ok:
        raise RuntimeError(f"'pass' command failed: {response.status!r}")
    log(f"'pass' command completed: {response}")


def main():
    parser = argparse.ArgumentParser(
        description="Create stack buffer overflow in 'pass' command on RP2040 toy wallet."
    )
    add_wallet_cli_args(parser)
    parser.add_argument(
        "--pin",
        required=True,
        help="PIN as decimal digits (required, e.g. 0123456789).",
    )
    parser.add_argument(
        "--ret-addr",
        type=lambda value: int(value.strip().lower().replace(" ", ""), 0),
        required=True,
        help="Return address to hijack to (required, e.g. 0x10010000)",
    )
    parser.add_argument(
        "--payload-bytes",
        type=lambda value: int(value, 0),
        required=True,
        help="Number of filler bytes before return-address overwrite (required, accepts 0xNN).",
    )

    args = parser.parse_args()

    try:
        port = resolve_wallet_port(args)
        log(f"Using wallet port: {port}")
        wallet = create_wallet_client(args, port=port)
    except PortDiscoveryError as e:
        log(f"Failed to discover wallet: {e}")
        sys.exit(1)

    with wallet:
        if not is_unlocked(wallet):
            pin_digits = normalize_pin_digits(args.pin)
            pin_hex = pin_digits_to_hex(pin_digits)
            pin_response = wallet.request("pin", pin_hex, timeout=3.0)
            if not pin_response.ok:
                raise RuntimeError("PIN unlock failed")

        payload = build_overflow_payload(
            ret_addr=args.ret_addr,
            payload_bytes=args.payload_bytes,
        )
        hex_data = payload.hex()

        ret_bytes = args.ret_addr.to_bytes(4, byteorder="little")

        log(f"Built overflow payload ({len(payload)} bytes)")
        log(f"Filler bytes before return address: {args.payload_bytes}")
        log(f"Payload (32-bit LE words): {format_bytes_as_u32_le_words(payload)}")
        log(f"Return address: 0x{args.ret_addr:08X} (LE bytes: {ret_bytes.hex()})")

        send_pass_command(wallet, hex_data)

        log(f"Return address hijacked to 0x{args.ret_addr:08X}")


if __name__ == "__main__":
    main()
