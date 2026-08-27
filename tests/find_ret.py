import pefile

PE_PATH = "data/msvcrt.dll"

# Load PE
pe = pefile.PE(PE_PATH)

# Find the .text section
text_section = None

for section in pe.sections:
    name = section.Name.rstrip(b"\x00").decode()

    if name == ".text":
        text_section = section
        break

# Extract bytes
code = text_section.get_data()

# Calculate virtual address
image_base = pe.OPTIONAL_HEADER.ImageBase
text_va = image_base + text_section.VirtualAddress

print(f".text starts at 0x{text_va:x}")
print()

count = 0

for i, byte in enumerate(code):

    if byte == 0xC3:

        print(
            f"RET #{count+1}: "
            f"offset = {i:08x} "
            f"VA = 0x{text_va + i:x}"
        )

        count += 1

        if count == 20:
            break

print()
print(f"Found first {count} RET instructions.")
