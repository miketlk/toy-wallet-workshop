# Lab 3: Remote Stack Overflow and Return Address Hijack

Previous: [Lab 2: Flash Memory Over-Read and Function Pointer Leak](lab2_bufer_overread.md)  
Next: [Lab 4 (Bonus): ROP Exploitation to Print Attacker-Controlled String](lab4_bonus_rop.md)

## Prerequisites
1. Complete Lab 1 and recover the device PIN.
2. Complete Lab 2 and recover the flash address of the `backup` command handler.

You need both values for this lab.

## Objective
Force execution of the firewalled `backup` handler by sending an oversized `pass` payload, overflowing a stack buffer in `cmd_pass`, and overwriting the saved return address.

The return address should be replaced with the leaked `backup` handler address from Lab 2.

## Why this experiment matters
This lab connects memory corruption with control-flow hijacking:
- Lab 2 gave you a valid code pointer in flash.
- Lab 3 uses a stack overflow to redirect execution to that pointer.

It demonstrates how separate "small" bugs chain into a full exploit path.

## Vulnerable firmware behavior
Target function in firmware:

```c
// Decode a hexadecimal string into an array of bytes
bool decode_hex(const char *hex, size_t hex_len, uint8_t *out, size_t out_cap, size_t *out_len) {
  if ((hex_len % 2u) != 0u) {
    return false;
  }

  // (!) Missing bounds check: hex_len is not compared against out_cap

  for (size_t i = 0; i < hex_len; i++) {
    if (!is_hex_char(hex[i])) {
      return false;
    }
  }
  for (size_t i = 0; i < hex_len / 2u; i++) {
    out[i] = (uint8_t)((hex_nibble(hex[2u * i]) << 4u) | hex_nibble(hex[2u * i + 1u]));
  }
  *out_len = hex_len / 2u;
  return true;
}

// Handle passphrase entry command: 'pass'
bool cmd_pass(const char *arg, size_t arg_len) {
  if (arg == NULL) {
    return false;
  }
  size_t decoded_len = 0;
  uint8_t decoded[MAX_PASS_BYTES];

  if (!decode_hex(arg, arg_len, decoded, sizeof(decoded), &decoded_len)) {
    return false;
  }

  memcpy(g_passphrase, decoded, MIN(decoded_len, sizeof(g_passphrase)));
  g_passphrase[decoded_len] = '\0';
  g_passphrase_len = decoded_len;
  memset(decoded, 0, sizeof(decoded));
  proto_send_ok();
  log_line(LOG_INF, "AUTH", "Passphrase updated");
  return true;
}
```

### Why this can be exploitable
- `pass` is remotely reachable over protocol CDC.
- `decoded` lives on the stack.
- If decode/copy logic allows writing past `decoded`, nearby saved state (including saved `lr`) can be corrupted.
- On function return, corrupted saved `pc` can redirect execution.

In this lab, you redirect control flow to the leaked `backup` handler address.

## `cmd_pass` disassembly

```asm
cmd_pass:
    push {r4, r5, r6, r7, lr}     ; save callee-saved regs + return address
    sub sp, #84                   ; allocate stack frame
    cmp r0, #0                    ; arg == NULL ?
    beq fail_return

    movs r3, #0
    str r3, [sp, #76]             ; decoded_len local
    add r3, sp, #76               ; &decoded_len
    str r3, [sp, #0]              ; pass out_len pointer on stack
    movs r3, #64                  ; decoded buffer capacity
    add r2, sp, #12               ; decoded buffer starts at sp+12
    bl decode_hex                 ; decode user hex into stack buffer
    subs r4, r0, #0               ; check decode result
    bne decode_ok

fail_return:
    movs r4, #0
return_common:
    movs r0, r4
    add sp, #84
    pop {r4, r5, r6, r7, pc}      ; return via saved PC (hijack target)

decode_ok:
    ldr r5, [sp, #76]             ; decoded_len
    movs r2, r5
    cmp r5, #65
    bls copy_and_finish

clamp_len:
    movs r2, #65
    ; fall through into copy_and_finish

copy_and_finish:
    ldr r6, [pc, #48]             ; &g_passphrase
    add r7, sp, #12               ; source: decoded buffer on stack
    movs r1, r7
    movs r0, r6                   ; destination: g_passphrase
    bl __wrap___aeabi_memcpy
    movs r3, #0
    strb r3, [r6, r5]             ; g_passphrase[decoded_len] = '\0'
    ldr r3, [pc, #36]             ; &g_passphrase_len
    str r5, [r3, #0]              ; g_passphrase_len = decoded_len
    movs r2, #64
    movs r1, #0
    movs r0, r7
    bl __wrap_memset              ; wipe decoded stack buffer
    bl proto_send_ok
    ldr r2, [pc, #24]
    ldr r1, [pc, #24]
    movs r0, #1
    bl log_line
    b return_common
```

## What you need to do
1. Open `lab3_stack_overflow.py`.
2. Implement `build_overflow_payload(...)` TODO.
3. Analyze `cmd_pass` in C and disassembly to determine the correct number of filler bytes needed before the saved return address.
4. Build payload as:
- participant-derived filler bytes (`--payload-bytes`)
- leaked `backup` handler address encoded as 4-byte little-endian overwrite value
5. Send payload through `pass` command.

## Run command
```bash
python lab3_stack_overflow.py --pin <LAB1_PIN> --ret-addr <LAB2_ADDR> --payload-bytes <YOUR_GUESS>
```

Example:
```bash
python lab3_stack_overflow.py --pin 0123456789 --ret-addr 0x30012345 --payload-bytes 123
```

Required option:
- `--payload-bytes <N>`: number of filler bytes before return address overwrite, derived from `cmd_pass` stack layout analysis.

## 💡 Hint:
- In `cmd_pass` disassembly, find `sub sp, #N`: this `N` is the local stack frame size.
- That local frame is separate from registers saved by `push {..., lr}`.
- Find where `decoded[]` starts: `add r?, sp, #D` means decoded base is `sp + D`.
- At return, `pop {..., pc}` restores saved registers; each saved register uses 4 bytes.
- Compute `--payload-bytes` as distance from decoded base to saved `pc`.
- If you get stuck, first compute the offset to saved `r4`, then add 4 bytes per register until `pc`.

## Stability note
Corrupting saved registers and adjacent stack variables can make the device hang or stop responding. After an unsuccessful attempt, you may need to unplug and replug the USB cable to force a hard reset before retrying.

## Expected progression in output
You should see logs such as:
- `Built overflow payload (...) bytes`
- `Return address: 0x... (LE bytes: ...)`
- `'pass' command completed: ...`
- `Return address hijacked to 0x...`

On successful control-flow hijack, the `backup` function executes and mnemonic backup output appears on the device UX channel (CDC 0), despite normal state gating logic.

## Success criteria
- You trigger `cmd_pass` overflow remotely.
- Saved return address is overwritten with leaked `backup` handler address.
- Firmware executes `backup` handler code path.
- You observe backup mnemonic output on CDC 0.

## Defensive takeaway
Bounds checks must be enforced at decode/write time, not only in later copies. Stack memory corruption plus leaked code addresses enables reliable return-address hijacking and bypass of protection logic.
