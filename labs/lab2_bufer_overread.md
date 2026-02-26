# Lab 2: Flash Memory Over-Read and Function Pointer Leak

Previous: [Lab 1: Timing Side-Channel PIN Recovery](lab1_side_channel.md)  
Next: [Lab 3: Remote Stack Overflow and Return Address Hijack](lab3_stack_overflow.md)

## Prerequisite
Complete Lab 1 first and recover the device PIN.

You need that PIN to unlock the device before the `info` command can be used for this lab.

## Objective
Leak memory past `wallet_info_t` and extract the flash address of the function that handles the `backup` command.

This leaked address is required input for Lab 3.

## Why this experiment matters
This lab shows how a read-only disclosure bug can become a control-flow attack enabler.

Here, a metadata endpoint (`info`) is allowed to return more bytes than intended, disclosing adjacent flash data that includes a command dispatch table with function pointers.

Even without code execution in this step, leaking internal addresses breaks important assumptions and enables later exploitation.

## Vulnerable firmware behavior
The attack path is the `info` length parsing and response logic:

```c
static bool parse_info_len(const char *arg, size_t arg_len, size_t *len_out) {
  if (arg == NULL) {
    *len_out = sizeof(wallet_info_t);
    return true;
  }

  if (arg_len < 2u || arg_len > 8u || (arg_len % 2u) != 0u) {
    return false;
  }

  size_t parsed = 0;
  for (size_t i = 0; i < arg_len; i++) {
    parsed = (parsed << 4u) | hex_nibble(arg[i]);
  }
  if (parsed > MAX_PROTO_HEX_BYTES) {
    parsed = MAX_PROTO_HEX_BYTES;
  }
  if (parsed > sizeof(g_flash_data)) {
    parsed = sizeof(g_flash_data);
  }
  *len_out = parsed;
  return true;
}

static bool cmd_info(const char *arg, size_t arg_len) {
  size_t len = 0;
  if (!parse_info_len(arg, arg_len, &len)) {
    return false;
  }

  const uint8_t *base = (const uint8_t *)&g_flash_data.info;
  proto_send_ok_hex(base, len);
  return true;
}
```

### What leaks
- Response starts at `&g_flash_data.info`.
- Bound check is missing, but calling `parse_info_len` with a return value check creates the illusion that everything is verified.
- Requested length can extend beyond `wallet_info_t` into adjacent fields in `flash_data_t`.
- The next field is `cmd_table_t`, which stores opcode strings plus handler function pointers.

Relevant flash layout:
1. `wallet_info_t info` (256 bytes)
2. `cmd_table_t table` (7 entries x 12 bytes = 84 bytes)
3. `uint32_t crc32` (4 bytes)

Total useful leak length is 344 bytes by default.

## What you need to do
1. Open `lab2_bufer_overread.py`.
2. Implement the TODO in `dump_cmd_table(...)`.
3. Parse leaked bytes after the first 256 bytes as 12-byte command entries:
- first 8 bytes: zero-terminated opcode
- next 4 bytes: little-endian handler address
4. Identify the entry where opcode is `backup` and record its handler address.

## Run command
```bash
python lab2_bufer_overread.py --pin <PIN_FROM_LAB1>
```

Useful options:
- `--leak-len <N>`: bytes requested via `info` (default includes info + table + crc).
- `--port <device>`: explicit serial port.
- `--timeout <seconds>`: request timeout.

## Expected progression in output
You should see logs similar to:
- `requested=344 bytes`
- `received=344 bytes`
- `overread=88 bytes`
- parsed command entries like `[i] <opcode> handler=0xXXXXXXXX`

One of the parsed lines should include:
- opcode `backup`
- its handler address in flash, e.g. `handler=0x...`

## Success criteria
- You successfully leak past `wallet_info_t` into `cmd_table_t`.
- You extract the `backup` handler flash address.
- You keep this address for Lab 3 as the target control-flow destination.

## Defensive takeaway
Never expose raw internal memory ranges through user-controlled lengths. Even "read-only" over-reads can disclose secrets and physical code layout in flash memory.
