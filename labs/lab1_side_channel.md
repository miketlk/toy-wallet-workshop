# Lab 1: Timing Side-Channel PIN Recovery

Next: [Lab 2: Flash Memory Over-Read and Function Pointer Leak](lab2_bufer_overread.md)

## Goal
Recover the wallet device PIN by exploiting a timing side channel in firmware PIN verification.

You will use this recovered PIN to continue with the next labs.

## Why this experiment matters
This lab demonstrates a classic timing side-channel failure: a secret comparison that takes different time depending on how many leading bytes are correct.

Even when the protocol only returns `ok` or `err`, timing can leak secret data. In real systems, this can break authentication without brute-forcing the full secret space.

## Vulnerable firmware behavior
The lab targets the following firmware function:

```c
bool pin_compare(const uint8_t *pin, const uint8_t *expected_pin, size_t expected_digits) {
  for (size_t i = 0; i < expected_digits; i++) {
    if (pin[i] != expected_pin[i]) {
      return false;
    }
    sleep_ms(200);
  }
  return true;
}
```

### What leaks
- The function exits early on first mismatch.
- It sleeps 200 ms after each matched digit to make delay measurable on casual computer/OS.
- So, a guess with more correct prefix digits takes measurably longer.

From the host, you can measure response time of repeated `pin` requests and infer:
1. PIN length (the one length where timing becomes variable).
2. Each next PIN digit (the slowest candidate for that position).

## What you need to do
1. Open `lab1_side_channel.py`.
2. Implement the TODO in `run_round(...)`.
3. The round logic should:
- Try digits `0..9` for the current position.
- Build guesses with `guess_pin_digits(...)`.
- Send `pin` and measure elapsed time with `timed_pin_request(...)`.
- Record attempts `(digit, elapsed_seconds, pin_digits)`.
- Return early if unlock is detected.
4. Run the lab script against your connected device.

## Run command
```bash
python lab1_side_channel.py
```

Useful options:
- `--port <device>`: explicit serial port.
- `--threshold-ms <N>`: timing gap threshold (default `100`).
- `--digit-delay-ms <N>`: expected per-digit delay (default `200`).
- `--max-digits <N>`: max tested PIN length (default `32`).

## Expected progression in output
You should see logs similar to:
- `probe length=...`
- `length gap=...ms`
- `length=<N>` once the script identifies probable PIN length
- `found=...` as each digit is recovered
- `pin=<digits>` when recovered and verified

## Success criteria
- The script ends successfully and prints `pin=<digits>`.
- The recovered PIN unlocks the device.
- You can pass this PIN to the next lab (for example, `lab2_bufer_overread.py --pin <digits>`).

## Defensive takeaway
Secret comparisons must be constant-time. Returning early on mismatch creates measurable timing differences that leak authentication material.
