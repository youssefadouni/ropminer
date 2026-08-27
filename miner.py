import argparse
import json
from pathlib import Path

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from capstone import CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET

from emulator import get_stack_offset


MAX_LOOKBACK = 64


def load_pe(path):
    return pefile.PE(str(path))


def get_text_section(pe):
    """
    Return executable PE section bytes and its virtual address.
    """
    for section in pe.sections:
        if section.Characteristics & 0x20000000:
            return (
                section.get_data(),
                pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress,
            )

    return None, None


def get_disassembler():
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    return md


def find_ret_offsets(code):
    """
    Find RET and RET imm16 instructions.

    Returns:
        (offset, instruction_size)
    """
    offsets = []

    i = 0
    while i < len(code):
        if code[i] == 0xC3:
            offsets.append((i, 1))

        elif code[i] == 0xC2 and i + 2 < len(code):
            offsets.append((i, 3))

        i += 1

    return offsets


def has_branch(instructions):
    """
    Reject gadgets containing control-flow instructions
    before their final RET.
    """
    for instruction in instructions[:-1]:
        if (
            CS_GRP_JUMP in instruction.groups
            or CS_GRP_CALL in instruction.groups
            or CS_GRP_RET in instruction.groups
        ):
            return True

    return False


def mine_gadgets(code, image_base, md, ret_offsets):
    gadgets = {}

    for ret_offset, ret_size in ret_offsets:
        end = ret_offset + ret_size
        stop_scan = False

        for lookback in range(1, MAX_LOOKBACK + 1):
            if stop_scan:
                break

            start = ret_offset - lookback

            if start < 0:
                break

            gadget_bytes = code[start:end]

            instructions = list(
                md.disasm(
                    gadget_bytes,
                    image_base + start,
                )
            )

            if not instructions:
                continue

            last = instructions[-1]

            if last.address + last.size != image_base + end:
                continue

            if has_branch(instructions):
                stop_scan = True
                break

            result = get_stack_offset(gadget_bytes)

            if result is None:
                continue

            if result["stack_offset"] <= 0:
                continue

            address = hex(image_base + start)

            gadgets[address] = result

    return gadgets


def main():
    parser = argparse.ArgumentParser(
        description="Mine x86 ROP gadgets from a 32-bit PE."
    )

    parser.add_argument(
        "input",
        type=Path,
        help="Path to a 32-bit PE executable or DLL",
    )

    parser.add_argument(
        "output",
        type=Path,
        help="Output JSON gadget database",
    )

    args = parser.parse_args()

    print(f"[+] Input: {args.input}")

    try:
        pe = load_pe(args.input)
    except Exception as exc:
        raise SystemExit(f"[-] Failed to load PE: {exc}")

    try:
        if pe.PE_TYPE != 0x10B:
            raise SystemExit("[-] Input is not a PE32 binary")

        code, image_base = get_text_section(pe)

        if code is None:
            raise SystemExit("[-] No executable section found")

        print(f"[+] Executable section size: {len(code)} bytes")
        print(f"[+] Executable section VA: {hex(image_base)}")

        md = get_disassembler()

        ret_offsets = find_ret_offsets(code)

        print(f"[+] RET/RETN candidates: {len(ret_offsets)}")

        gadgets = mine_gadgets(
            code,
            image_base,
            md,
            ret_offsets,
        )

    finally:
        pe.close()

    with open(args.output, "w") as f:
        json.dump(gadgets, f, indent=4)

    print(f"[+] Valid gadgets: {len(gadgets)}")
    print(f"[+] Saved: {args.output}")


if __name__ == "__main__":
    main()
