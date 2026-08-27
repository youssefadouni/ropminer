import pefile
from capstone import *

PE_PATH = "data/msvcrt.dll"

pe = pefile.PE(PE_PATH)

# Find .text
text = None
for section in pe.sections:
    if section.Name.rstrip(b"\x00").decode() == ".text":
        text = section
        break

code = text.get_data()

image_base = pe.OPTIONAL_HEADER.ImageBase
text_va = image_base + text.VirtualAddress

# First RET from our previous experiment
ret_offset = 0x1657

# Look 20 bytes before it
start_offset = ret_offset - 20

window = code[start_offset:ret_offset + 1]

md = Cs(CS_ARCH_X86, CS_MODE_32)

print(f"Disassembling from 0x{text_va + start_offset:x}\n")

for ins in md.disasm(window, text_va + start_offset):
    marker = ""

    if ins.address == text_va + ret_offset:
        marker = "  <---- RET"

    print(
        f"0x{ins.address:x}: "
        f"{ins.mnemonic:<8} "
        f"{ins.op_str}"
        f"{marker}"
    )
