# Lab 4 (Bonus): ROP Exploitation to Print Attacker-Controlled String

Previous: [Lab 3: Remote Stack Overflow and Return Address Hijack](lab3_stack_overflow.md)

## Prerequisites
1. Complete Lab 1 and recover the PIN.
2. Complete Lab 3 and understand the `pass` stack overflow entry point.

## Objective
Use `pass` overflow to execute a short ROP chain that calls `cdc_puts` with attacker-controlled arguments, printing a string stored in `g_passphrase`.

## Files in this lab
- `lab4_bonus_rop.py`: exploit script participants complete.
- `lab4_validator.py`: standalone constants validator against disassembly.
- `toy_wallet.dis`: provided partial disassembly for constants/gadget analysis.

## Participant Workflow

### Step 1: Fill memory constants

In `lab4_bonus_rop.py` create an instance of `MemoryLayout` class - `MEMORY_LAYOUT` and populate:
- `cdc_puts_addr`
- `g_passphrase_addr`
- `pop_gadget_addr` (`pop {r0, r1, r2, pc}`)
- `saved_r4_offset`
- `saved_pc_offset`

These values must be obtained from disassembly analysis.

### Step 2: Self-check

After filling `MEMORY_LAYOUT`, validate assumptions:

```bash
python lab4_validator.py toy_wallet.dis
```

`lab4_validator.py` checks:
- `cdc_puts` symbol at configured address
- `pop {r0, r1, r2, pc}` gadget at configured address
- `.word` literal matching configured `g_passphrase`
- derived `saved_r4_offset` and `saved_pc_offset` from `cmd_pass` frame shape

### Step 3: Construct payload

Implement payload construction in `build_rop_payload(...)`:
- stage message bytes + `\0`
- pad to `saved_r4_offset`
- overwrite saved `r4..r7`
- reach `saved_pc_offset`
- overwrite saved PC with pop gadget address (Thumb bit set)
- place words for popped `r0`, `r1`, `r2`, `pc`
- final `pc` should be `cdc_puts` (Thumb bit set)

## Useful C and Disassembly Snippets

### `cdc_puts` target

```c
static void cdc_puts(uint8_t itf, const char *s) {
  if (itf < CDC_ID_MIN || itf > CDC_ID_MAX) {
    return;
  }
  char prev = '\0';
  while (*s != '\0') {
    char c = *s++;
    if (c == '\n' && prev != '\r') {
      cdc_write_all(itf, (const uint8_t *)"\r", 1);
    }
    cdc_write_all(itf, (const uint8_t *)&c, 1);
    prev = c;
  }
}
```

```asm
1000062c <cdc_puts>:
1000062c: b570       push    {r4, r5, r6, lr}
1000062e: b082       sub     sp, #8
...
1000066e: bd70       pop     {r4, r5, r6, pc}
```

### Overflow context in `cmd_pass`

```c
static bool cmd_pass(const char *arg, size_t arg_len) {
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

```asm
10000b44 <cmd_pass>:
10000b44: b5f0       push    {r4, r5, r6, r7, lr}
10000b46: b095       sub     sp, #84
...
10000b56: aa03       add     r2, sp, #12
...
10000b64: bdf0       pop     {r4, r5, r6, r7, pc}
...
10000ba4: 20001604   .word   0x20001604
```

### Pop gadget found inside a system function

```asm
100039e0 <float_table_shim_on_use_helper>:
100039e0:	b507      	push	{r0, r1, r2, lr}
100039e2:	4660      	mov	r0, ip
...
10003a08:	5050      	str	r0, [r2, r1]
10003a0a:	9003      	str	r0, [sp, #12]
10003a0c:	bd07      	pop	{r0, r1, r2, pc}
10003a0e:	0000      	.short	0x0000
10003a10:	200024b8 	.word	0x200024b8
```


## Run Exploit
```bash
python lab4_bonus_rop.py --pin <LAB1_PIN>
python lab4_bonus_rop.py --pin <LAB1_PIN> --message "Your message"
```

## Expected Behavior
- Script builds and sends `pass` payload.
- Target may timeout after control-flow hijack (acceptable).
- Message appears on CDC0 output if chain succeeds.

## Success Criteria
- `lab4_validator.py` passes with your constants.
- `build_rop_payload` successfully hijacks control flow.
- `cdc_puts` prints your attacker-controlled string from `g_passphrase`.
