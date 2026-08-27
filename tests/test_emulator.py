from emulator import get_stack_offset

gadget = bytes([
    0x58,   # pop eax
    0xC3    # ret
])

result = get_stack_offset(gadget)

print(result)
