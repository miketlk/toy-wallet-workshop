#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
from pathlib import Path

from helpers import log
from lab4_bonus_rop import MEMORY_LAYOUT, MemoryLayout


def verify_disassembly(
    dis_file: Path,
    *,
    layout: MemoryLayout,
) -> None:
    if not dis_file.exists():
        raise FileNotFoundError(f"disassembly file not found: {dis_file}")

    text = dis_file.read_text(encoding="utf-8", errors="replace")
    checks: list[tuple[str, str]] = [
        ("cdc_puts entry", rf"^{layout.cdc_puts_addr:08x} <cdc_puts>:$"),
        (
            "pop gadget",
            rf"^{layout.pop_gadget_addr:08x}:\s+[0-9a-f]+\s+pop\s+\{{r0, r1, r2, pc\}}$",
        ),
        ("g_passphrase literal", rf"\.word\s+0x{layout.g_passphrase_addr:08x}\b"),
    ]
    for label, pattern in checks:
        if re.search(pattern, text, flags=re.MULTILINE) is None:
            raise RuntimeError(
                f"disassembly verification failed for {label}; expected pattern: {pattern}"
            )

    cmd_pass_shape = re.search(
        (
            r"^10000b44 <cmd_pass>:\n"
            r"^10000b44:\s+[0-9a-f]+\s+push\s+\{r4, r5, r6, r7, lr\}\s*$\n"
            r"^10000b46:\s+[0-9a-f]+\s+sub\s+sp,\s+#(?P<frame>\d+)\b.*$\n"
            r"(?:^.*$\n){0,24}?"
            r"^10000b56:\s+[0-9a-f]+\s+add\s+r2,\s+sp,\s+#(?P<decoded>\d+)\b.*$\n"
            r"(?:^.*$\n){0,32}?"
            r"^10000b64:\s+[0-9a-f]+\s+pop\s+\{r4, r5, r6, r7, pc\}\s*$"
        ),
        text,
        flags=re.MULTILINE,
    )
    if cmd_pass_shape is None:
        raise RuntimeError("disassembly verification failed for cmd_pass frame shape")

    frame_size = int(cmd_pass_shape.group("frame"))
    decoded_off = int(cmd_pass_shape.group("decoded"))
    if frame_size <= decoded_off:
        raise RuntimeError(
            f"unexpected cmd_pass frame math: frame={frame_size}, decoded_off={decoded_off}"
        )

    derived_saved_r4 = frame_size - decoded_off
    derived_saved_pc = derived_saved_r4 + 16  # r4,r5,r6,r7 before saved pc

    if derived_saved_r4 != layout.saved_r4_offset:
        raise RuntimeError(
            "disassembly verification failed for saved_r4_offset: "
            f"derived={derived_saved_r4}, expected={layout.saved_r4_offset}"
        )
    if derived_saved_pc != layout.saved_pc_offset:
        raise RuntimeError(
            "disassembly verification failed for saved_pc_offset: "
            f"derived={derived_saved_pc}, expected={layout.saved_pc_offset}"
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate Lab4 gadget/layout assumptions against a disassembly file."
    )
    parser.add_argument(
        "disassembly",
        type=Path,
        help="Path to disassembly file (e.g., toy_wallet.dis).",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    layout: MemoryLayout = MEMORY_LAYOUT
    try:
        verify_disassembly(args.disassembly, layout=layout)
        print(
            "Verified disassembly gadgets/layout:\n"
            f"\ncdc_puts_addr=0x{layout.cdc_puts_addr:08X}"
            f"\npop_gadget_addr=0x{layout.pop_gadget_addr:08X}"
            f"\ng_passphrase_addr=0x{layout.g_passphrase_addr:08X}"
            f"\nsaved_r4_offset={layout.saved_r4_offset}"
            f"\nsaved_pc_offset={layout.saved_pc_offset}\n"
        )
        return 0
    except Exception as e:
        log(f"verification failed: {e}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
