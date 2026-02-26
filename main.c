/**
 * RP2040 Toy Wallet workshop firmware.
 * This firmware is intentionally insecure and must never be used in production.
 */

#include <bsp/board_api.h>
#include <pico/stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <tusb.h>

#include "secrets.h"

#ifndef SECRET_PIN_HEX
#error "SECRET_PIN_HEX must be defined in secrets.h"
#endif

#ifndef SECRET_MNEMONIC
#error "SECRET_MNEMONIC must be defined in secrets.h"
#endif

static const char k_secret_pin[] = SECRET_PIN_HEX;
static const char k_secret_mnemonic[] = SECRET_MNEMONIC;

#ifndef WORKSHOP_VULN
#define WORKSHOP_VULN 1
#endif

#define FW_VERSION "0.3.0"
#if WORKSHOP_VULN
#define BUILD_REV "ws-ab12cd"
#else
#define BUILD_REV "ab12cd"
#endif

#define MAX_CDC1_LINE_LEN 512u
#define CDC1_LINE_TIMEOUT_MS 3000u
#define MAX_PROTO_HEX_BYTES 512u
#define MAX_PASS_BYTES 64u
#define DELAY_PER_DIGIT_MS 200u
#define MAX_OPCODE_LEN 7u
#define OPCODE_FIELD_SIZE (MAX_OPCODE_LEN + 1u)

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

typedef enum {
  CDC_ID_MIN = 0,
  CDC_UX_ITF = CDC_ID_MIN,  // UX interface for user interaction and logging
  CDC_PROTO_ITF,            // Protocol interface for communication with the host
  CDC_ID_MAX = CDC_PROTO_ITF
} cdc_id_t;

typedef enum {
  UI_BOOT = 0x00,
  UI_LOCKED = 0x01,
  UI_PIN_ENTRY = 0x02,
  UI_UNLOCKED = 0x03,
  UI_ONBOARDING = 0x04,
  UI_ERROR = 0xFF
} ui_state_t;

typedef enum { LOG_DBG, LOG_INF, LOG_WRN, LOG_ERR } log_level_t;

typedef struct __attribute__((packed)) {
  char model[16];
  char tokens[64];
  char fw_version[16];
  char build_rev[16];
  char hw_rev[16];
  char serial[16];
  uint8_t reserved[112];
} wallet_info_t;

typedef bool (*cmd_handler_t)(const char *arg, size_t arg_len);

typedef struct __attribute__((packed)) {
  char opcode[OPCODE_FIELD_SIZE];
  cmd_handler_t handler;
} cmd_entry_t;

typedef struct __attribute__((packed)) {
  cmd_entry_t entries[7];
} cmd_table_t;

typedef struct __attribute__((packed)) {
  wallet_info_t info;
  cmd_table_t table;
  uint32_t crc32;
} flash_data_t;

enum {
  EXPECTED_PIN_HEX_LEN = (int)(sizeof(k_secret_pin) - 1u),
  EXPECTED_PIN_BYTES = (int)((sizeof(k_secret_pin) - 1u) / 2u),
};

_Static_assert(sizeof(wallet_info_t) == 256, "wallet_info_t size must stay fixed");
_Static_assert(sizeof(cmd_entry_t) == 12, "cmd_entry_t size must stay fixed");
_Static_assert(sizeof(cmd_table_t) == 84, "cmd_table_t size must stay fixed");
_Static_assert(sizeof(k_secret_pin) > 1u, "k_secret_pin must not be empty");
_Static_assert(((sizeof(k_secret_pin) - 1u) % 2u) == 0u,
               "k_secret_pin must have an even number of hex chars");

typedef struct {
  char line[MAX_CDC1_LINE_LEN];
  size_t len;
  size_t discarded;
  bool in_progress;
  bool overflow;
  bool prev_rx_was_cr;
  absolute_time_t start_time;
} cdc1_line_buf_t;

static ui_state_t g_state = UI_BOOT;
static bool g_cdc0_presented = false;
static cdc1_line_buf_t g_cdc1 = {0};
static uint8_t g_passphrase[MAX_PASS_BYTES + 1];
static size_t g_passphrase_len = 0;

static bool cmd_ping(const char *arg, size_t arg_len);
static bool cmd_state(const char *arg, size_t arg_len);
static bool cmd_pin(const char *arg, size_t arg_len);
static bool cmd_info(const char *arg, size_t arg_len);
static bool cmd_backup(const char *arg, size_t arg_len);
static bool cmd_pass(const char *arg, size_t arg_len);
static bool cmd_lock(const char *arg, size_t arg_len);

static const flash_data_t g_flash_data __attribute__((section(".rodata.flash_data"), used)) = {
    .info = {.model = "TOYWALLET",
             .tokens = "BTC,tBTC",
             .fw_version = FW_VERSION,
             .build_rev = BUILD_REV,
             .hw_rev = "PICO-R1",
             .serial = "TW-0000000001",
             .reserved = {0}},
    .table = {.entries = {{"ping", cmd_ping},
                          {"state", cmd_state},
                          {"pin", cmd_pin},
                          {"info", cmd_info},
                          {"backup", cmd_backup},
                          {"pass", cmd_pass},
                          {"lock", cmd_lock}}},
    .crc32 = 0};

static const char *state_to_name(ui_state_t state) {
  switch (state) {
    case UI_BOOT:
      return "BOOT";
    case UI_LOCKED:
      return "LOCKED";
    case UI_PIN_ENTRY:
      return "PIN_ENTRY";
    case UI_UNLOCKED:
      return "UNLOCKED";
    case UI_ONBOARDING:
      return "ONBOARDING";
    case UI_ERROR:
      return "ERROR";
    default:
      return "UNKNOWN";
  }
}

static const char *log_level_name(log_level_t level) {
  switch (level) {
    case LOG_DBG:
      return "DBG";
    case LOG_INF:
      return "INF";
    case LOG_WRN:
      return "WRN";
    case LOG_ERR:
      return "ERR";
    default:
      return "UNK";
  }
}

static uint64_t uptime_ms(void) { return to_ms_since_boot(get_absolute_time()); }

static void cdc_write_all(uint8_t itf, const uint8_t *data, size_t len) {
  size_t written = 0;
  while (written < len) {
    tud_task();
    if (!tud_cdc_n_connected(itf)) {
      return;
    }
    uint32_t avail = tud_cdc_n_write_available(itf);
    if (avail == 0) {
      sleep_ms(1);
      continue;
    }
    uint32_t chunk = (uint32_t)((len - written) < avail ? (len - written) : avail);
    uint32_t out = tud_cdc_n_write(itf, data + written, chunk);
    written += out;
    tud_cdc_n_write_flush(itf);
  }
}

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

static void log_line(log_level_t level, const char *tag, const char *message) {
  char line[256];
  snprintf(line, sizeof(line), "[T+%06llu] %s %s: %s\n", (unsigned long long)uptime_ms(),
           log_level_name(level), tag, message);
  cdc_puts(CDC_UX_ITF, line);
}

static void logf_line(log_level_t level, const char *tag, const char *fmt, ...) {
  char msg[192];
  va_list args;
  va_start(args, fmt);
  vsnprintf(msg, sizeof(msg), fmt, args);
  va_end(args);
  log_line(level, tag, msg);
}

static void set_state(ui_state_t state) {
  if (g_state != state) {
    g_state = state;
    logf_line(LOG_INF, "STATE", "-> %s", state_to_name(g_state));
  }
}

static void print_ui_frame(void) {
  char line[192];
  snprintf(line, sizeof(line), "[UI] ToyWallet %s (rev %s)\n", g_flash_data.info.fw_version,
           g_flash_data.info.build_rev);
  cdc_puts(CDC_UX_ITF, line);
  snprintf(line, sizeof(line), "[UI] STATE: %s\n", state_to_name(g_state));
  cdc_puts(CDC_UX_ITF, line);

  switch (g_state) {
    case UI_LOCKED:
    case UI_PIN_ENTRY:
      cdc_puts(CDC_UX_ITF, "[UI] Device locked. Use host protocol to enter PIN.\n");
      break;
    case UI_UNLOCKED:
      cdc_puts(CDC_UX_ITF, "[UI] Device unlocked.\n");
      cdc_puts(CDC_UX_ITF, "[UI] Press 'e' on CDC0 to enter onboarding mode.\n");
      break;
    case UI_ONBOARDING:
      cdc_puts(CDC_UX_ITF, "[UI] Onboarding mode.\n");
      cdc_puts(CDC_UX_ITF, "[UI] backup command is enabled on CDC1.\n");
      break;
    case UI_ERROR:
      cdc_puts(CDC_UX_ITF, "[UI] Error state.\n");
      break;
    case UI_BOOT:
    default:
      break;
  }
}

static void print_boot_banner(void) {
  cdc_puts(CDC_UX_ITF, "=== RP2040 TOY WALLET (WORKSHOP ONLY) ===\n");
  cdc_puts(CDC_UX_ITF, "This firmware is intentionally insecure and not for production use.\n");
  print_ui_frame();
}

static bool is_hex_char(char c) {
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

static uint8_t hex_nibble(char c) {
  if (c >= '0' && c <= '9') {
    return (uint8_t)(c - '0');
  }
  if (c >= 'a' && c <= 'f') {
    return (uint8_t)(c - 'a' + 10);
  }
  return (uint8_t)(c - 'A' + 10);
}

static bool decode_hex(const char *hex, size_t hex_len, uint8_t *out, size_t out_cap,
                       size_t *out_len) {
  if ((hex_len % 2u) != 0u) {
    return false;
  }

#if !(WORKSHOP_VULN)
  // In the vulnerable workshop version, we intentionally omit this length check to allow buffer
  // overflows.
  if ((hex_len / 2u) > out_cap) {
    return false;
  }
#endif

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

static bool encode_hex(const uint8_t *in, size_t in_len, char *out, size_t out_cap) {
  static const char lut[] = "0123456789abcdef";
  if ((in_len * 2u + 1u) > out_cap) {
    return false;
  }
  for (size_t i = 0; i < in_len; i++) {
    out[2u * i] = lut[(in[i] >> 4u) & 0x0f];
    out[2u * i + 1u] = lut[in[i] & 0x0f];
  }
  out[2u * in_len] = '\0';
  return true;
}

static void proto_send_ok(void) { cdc_puts(CDC_PROTO_ITF, "ok\n"); }

static void proto_send_err(void) { cdc_puts(CDC_PROTO_ITF, "err\n"); }

static void proto_send_ok_hex(const uint8_t *data, size_t len) {
  char hex[MAX_PROTO_HEX_BYTES * 2u + 1u];
  if (!encode_hex(data, len, hex, sizeof(hex))) {
    proto_send_err();
    return;
  }
  cdc_puts(CDC_PROTO_ITF, "ok ");
  cdc_puts(CDC_PROTO_ITF, hex);
  cdc_puts(CDC_PROTO_ITF, "\n");
}

static bool valid_opcode(const char *opcode, size_t len) {
  if (len == 0 || len > MAX_OPCODE_LEN) {
    return false;
  }
  for (size_t i = 0; i < len; i++) {
    char c = opcode[i];
    bool ok =
        (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || (c == '_');
    if (!ok) {
      return false;
    }
  }
  return true;
}

static bool parse_command(char *line, char *opcode_out, size_t opcode_cap, char **arg_out,
                          size_t *arg_len_out) {
  char *p = line;
  while (*p == ' ') {
    p++;
  }
  if (*p == '\0') {
    return false;
  }

  char *opcode = p;
  while (*p != '\0' && *p != ' ') {
    p++;
  }
  size_t opcode_len = (size_t)(p - opcode);
  if (!valid_opcode(opcode, opcode_len) || opcode_len >= opcode_cap) {
    return false;
  }
  memcpy(opcode_out, opcode, opcode_len);
  opcode_out[opcode_len] = '\0';

  while (*p == ' ') {
    *p++ = '\0';
  }
  if (*p == '\0') {
    *arg_out = NULL;
    *arg_len_out = 0;
    return true;
  }

  char *arg = p;
  while (*p != '\0' && *p != ' ') {
    p++;
  }
  char *arg_end = p;
  while (*p == ' ') {
    p++;
  }
  if (*p != '\0') {
    return false;
  }

  size_t arg_len = (size_t)(arg_end - arg);
  if (arg_len == 0 || (arg_len % 2u) != 0u) {
    return false;
  }
  for (size_t i = 0; i < arg_len; i++) {
    if (!is_hex_char(arg[i])) {
      return false;
    }
  }

  *arg_end = '\0';
  *arg_out = arg;
  *arg_len_out = arg_len;
  return true;
}

// Determines if a given opcode is allowed in the current UI state.
static bool allows_opcode_in_state(const char *opcode) {
  static const char *always_allowed[] = {"ping", "state", "pin", "lock"};
  for (size_t i = 0; i < ARRAY_SIZE(always_allowed); i++) {
    if (strcmp(opcode, always_allowed[i]) == 0) {
      return true;
    }
  }
  if (strcmp(opcode, "pass") == 0 || strcmp(opcode, "info") == 0) {
    return (g_state == UI_UNLOCKED || g_state == UI_ONBOARDING);
  }
  if (strcmp(opcode, "backup") == 0) {
    return g_state == UI_ONBOARDING;
  }
  return false;
}

static bool cmd_ping(const char *arg, size_t arg_len) {
  (void)arg;
  if (arg_len != 0) {
    return false;
  }
  proto_send_ok();
  return true;
}

static bool cmd_state(const char *arg, size_t arg_len) {
  (void)arg;
  if (arg_len != 0) {
    return false;
  }
  uint8_t state_byte = (uint8_t)g_state;
  proto_send_ok_hex(&state_byte, 1);
  return true;
}

static bool pin_compare(const uint8_t *pin, const uint8_t *expected_pin, size_t expected_digits) {
#if WORKSHOP_VULN
  // WORKSHOP ONLY: intentionally unsafe behavior for educational purposes
  for (size_t i = 0; i < expected_digits; i++) {
    if (pin[i] != expected_pin[i]) {
      return false;
    }
    sleep_ms(DELAY_PER_DIGIT_MS);
  }
  return true;
#else
  uint8_t diff = 0;
  for (size_t i = 0; i < expected_digits; i++) {
    diff |= (uint8_t)(pin[i] ^ expected_pin[i]);
    sleep_ms(DELAY_PER_DIGIT_MS);
  }
  return diff == 0;
#endif
}

static bool cmd_pin(const char *arg, size_t arg_len) {
  if (arg == NULL || arg_len != (size_t)EXPECTED_PIN_HEX_LEN) {
    return false;
  }
  uint8_t pin[EXPECTED_PIN_BYTES];
  uint8_t expected_pin[EXPECTED_PIN_BYTES];
  size_t out_len = 0;
  size_t expected_out_len = 0;
  if (!decode_hex(arg, arg_len, pin, sizeof(pin), &out_len) ||
      out_len != (size_t)EXPECTED_PIN_BYTES) {
    return false;
  }
  if (!decode_hex(k_secret_pin, (size_t)EXPECTED_PIN_HEX_LEN, expected_pin, sizeof(expected_pin),
                  &expected_out_len) ||
      expected_out_len != (size_t)EXPECTED_PIN_BYTES) {
    memset(pin, 0, sizeof(pin));
    memset(expected_pin, 0, sizeof(expected_pin));
    return false;
  }

  log_line(LOG_INF, "AUTH", "PIN attempt");
  set_state(UI_PIN_ENTRY);

  if (pin_compare(pin, expected_pin, (size_t)EXPECTED_PIN_BYTES)) {
    set_state(UI_UNLOCKED);
    proto_send_ok();
    print_ui_frame();
    log_line(LOG_INF, "AUTH", "PIN success");
  } else {
    set_state(UI_LOCKED);
    proto_send_err();
    log_line(LOG_WRN, "AUTH", "PIN failed");
  }
  memset(pin, 0, sizeof(pin));
  memset(expected_pin, 0, sizeof(expected_pin));
  return true;
}

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
#if !(WORKSHOP_VULN)
  if (len > sizeof(g_flash_data.info)) {
    return false;
  }
#endif
  const uint8_t *base = (const uint8_t *)&g_flash_data.info;
  proto_send_ok_hex(base, len);
  return true;
}

static bool cmd_backup(const char *arg, size_t arg_len) {
  (void)arg;
  (void)arg_len;

  cdc_puts(CDC_UX_ITF, "\n=== BACKUP MNEMONIC (12 words) ===\n\n");
  cdc_puts(CDC_UX_ITF, k_secret_mnemonic);
  cdc_puts(CDC_UX_ITF, "\n\n==================================\n\n");

  proto_send_ok();
  log_line(LOG_INF, "AUTH", "Seed backup executed");
  return true;
}

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

static bool cmd_lock(const char *arg, size_t arg_len) {
  (void)arg;
  if (arg_len != 0) {
    return false;
  }
  set_state(UI_LOCKED);
  print_ui_frame();
  proto_send_ok();
  return true;
}

static void dispatch_proto_command(char *line) {
  char opcode[OPCODE_FIELD_SIZE];
  char *arg = NULL;
  size_t arg_len = 0;

  if (!parse_command(line, opcode, sizeof(opcode), &arg, &arg_len)) {
    proto_send_err();
    log_line(LOG_WRN, "PROTO", "Invalid command syntax");
    return;
  }

  if (!allows_opcode_in_state(opcode)) {
    proto_send_err();
    logf_line(LOG_WRN, "PROTO", "State gate blocked opcode '%s' in %s", opcode,
              state_to_name(g_state));
    return;
  }

  for (size_t i = 0; i < ARRAY_SIZE(g_flash_data.table.entries); i++) {
    const cmd_entry_t *entry = &g_flash_data.table.entries[i];
    if (strcmp(opcode, entry->opcode) == 0) {
      if (!entry->handler(arg, arg_len)) {
        proto_send_err();
        logf_line(LOG_WRN, "PROTO", "Command '%s' rejected", opcode);
      }
      return;
    }
  }

  proto_send_err();
  logf_line(LOG_WRN, "PROTO", "Unknown opcode '%s'", opcode);
}

static void handle_cdc0_char(char c) {
  if (c == '\r' || c == '\n') {
    return;
  }

  switch (c) {
    case 'e':
#if WORKSHOP_VULN
      cdc_puts(CDC_UX_ITF, "Onboarding and backup are DISABLED in workshop mode.\n");
      cdc_puts(CDC_UX_ITF, "Good luck breaking it ;-)\n");
#else
      if (g_state == UI_UNLOCKED) {
        set_state(UI_ONBOARDING);
        print_ui_frame();
      }
#endif
      break;
    case 'b':
      if (g_state == UI_ONBOARDING) {
        set_state(UI_UNLOCKED);
        print_ui_frame();
      }
      break;
    case 'l':
      if (g_state == UI_UNLOCKED || g_state == UI_ONBOARDING) {
        set_state(UI_LOCKED);
        print_ui_frame();
      }
      break;
    default:
      break;
  }
}

static void poll_cdc0(void) {
  while (tud_cdc_n_available(CDC_UX_ITF)) {
    char c;
    (void)tud_cdc_n_read(CDC_UX_ITF, &c, 1);
    handle_cdc0_char(c);
  }
}

static void cdc1_reset_line(void) {
  g_cdc1.len = 0;
  g_cdc1.discarded = 0;
  g_cdc1.in_progress = false;
  g_cdc1.overflow = false;
  g_cdc1.prev_rx_was_cr = false;
}

static void cdc1_finish_line(void) {
  if (g_cdc1.overflow) {
    proto_send_err();
    logf_line(LOG_WRN, "PROTO", "CDC1 line too long; discarded %u bytes",
              (unsigned)g_cdc1.discarded);
    cdc1_reset_line();
    return;
  }
  g_cdc1.line[g_cdc1.len] = '\0';
  dispatch_proto_command(g_cdc1.line);
  cdc1_reset_line();
}

static void cdc1_echo_char(char c) {
  if (c == '\r') {
    cdc_write_all(CDC_PROTO_ITF, (const uint8_t *)"\r\n", 2);
    g_cdc1.prev_rx_was_cr = true;
    return;
  }
  if (c == '\n') {
    if (!g_cdc1.prev_rx_was_cr) {
      cdc_write_all(CDC_PROTO_ITF, (const uint8_t *)"\r\n", 2);
    }
    g_cdc1.prev_rx_was_cr = false;
    return;
  }
  g_cdc1.prev_rx_was_cr = false;
  cdc_write_all(CDC_PROTO_ITF, (const uint8_t *)&c, 1);
}

static void poll_cdc1(void) {
  while (tud_cdc_n_available(CDC_PROTO_ITF)) {
    char c;
    if (tud_cdc_n_read(CDC_PROTO_ITF, &c, 1) != 1) {
      break;
    }
    cdc1_echo_char(c);

    if (c == '\r' || c == '\n') {
      if (g_cdc1.in_progress) {
        cdc1_finish_line();
      }
      continue;
    }

    if (!g_cdc1.in_progress) {
      g_cdc1.in_progress = true;
      g_cdc1.start_time = get_absolute_time();
      g_cdc1.len = 0;
      g_cdc1.discarded = 0;
      g_cdc1.overflow = false;
    }

    if (g_cdc1.len >= (MAX_CDC1_LINE_LEN - 1u)) {
      g_cdc1.overflow = true;
      g_cdc1.discarded++;
      continue;
    }

    g_cdc1.line[g_cdc1.len++] = c;
  }
}

static void check_cdc1_timeout(void) {
  if (!g_cdc1.in_progress) {
    return;
  }
  int64_t age_us = absolute_time_diff_us(g_cdc1.start_time, get_absolute_time());
  if (age_us > (int64_t)CDC1_LINE_TIMEOUT_MS * 1000ll) {
    size_t dropped = g_cdc1.len + g_cdc1.discarded;
    logf_line(LOG_WRN, "PROTO", "CDC1 line timeout; discarded %u bytes", (unsigned)dropped);
    cdc1_reset_line();
  }
}

int main(void) {
  board_init();
  tusb_init();

  if (board_init_after_tusb) {
    board_init_after_tusb();
  }

  log_line(LOG_INF, "USB", "CDC interfaces ready");
  set_state(UI_LOCKED);

  while (1) {
    tud_task();
    poll_cdc0();
    poll_cdc1();
    check_cdc1_timeout();

    if (tud_cdc_n_connected(CDC_UX_ITF) && !g_cdc0_presented) {
      g_cdc0_presented = true;
      print_boot_banner();
    } else if (!tud_cdc_n_connected(CDC_UX_ITF)) {
      g_cdc0_presented = false;
    }
  }
  return 0;
}
