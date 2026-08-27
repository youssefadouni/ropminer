import pefile

PE_PATH = "data/msvcrt.dll"

pe = pefile.PE(PE_PATH)

image_base = pe.OPTIONAL_HEADER.ImageBase

print(f"File: {PE_PATH}")
print(f"Image Base: 0x{image_base:x}")

for section in pe.sections:
    name = section.Name.rstrip(b"\x00").decode(errors="replace")

    if name == ".text":
        text_data = section.get_data()
        text_va = image_base + section.VirtualAddress

        print("\n.text section found!")
        print(f"Virtual Address: 0x{text_va:x}")
        print(f"Size: {len(text_data)} bytes")
        print(f"Characteristics: 0x{section.Characteristics:x}")

        print("\nFirst 32 bytes:")
        print(text_data[:32].hex(" "))

        break
