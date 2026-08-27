import pefile
from capstone import *
PE_PATH = "data/msvcrt.dll"

pe = pefile.PE(PE_PATH)
text_section = None

for section in pe.sections:
    name = section.Name.rstrip(b"\x00").decode()

    if name == ".text":
        text_section = section
        break
code = text_section.get_data()
image_base = pe.OPTIONAL_HEADER.ImageBase

code_address = image_base + text_section.VirtualAddress
md = Cs(CS_ARCH_X86, CS_MODE_32)
count = 0

for instruction in md.disasm(code, code_address):
    print(
        f"0x{instruction.address:x}: "
        f"{instruction.mnemonic} "
        f"{instruction.op_str}"
    )

    count += 1

    if count == 20:
        break
