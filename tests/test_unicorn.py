from unicorn import Uc, UC_ARCH_X86, UC_MODE_32
from unicorn.x86_const import UC_X86_REG_ESP

# Create a 32-bit x86 emulator
mu = Uc(UC_ARCH_X86, UC_MODE_32)

# Define memory locations
CODE_ADDRESS = 0x1000000
STACK_ADDRESS = 0x2000000

# Allocate memory for code and stack
mu.mem_map(CODE_ADDRESS, 0x1000)
mu.mem_map(STACK_ADDRESS, 0x1000)

# Machine code: POP EAX; RET; NOP
CODE = b"\x58\xc3\x90"

# Write code into emulator memory
mu.mem_write(CODE_ADDRESS, CODE)

# Set up the stack
STACK_POINTER = STACK_ADDRESS + 0x800
mu.reg_write(UC_X86_REG_ESP, STACK_POINTER)

# The RET instruction will jump to the NOP instruction
return_address = CODE_ADDRESS + 2

# Put a value for POP EAX and the return address on the stack
mu.mem_write(
    STACK_POINTER,
    b"\x11\x11\x11\x11" +
    return_address.to_bytes(4, byteorder="little")
)

# Record ESP before execution
initial_esp = mu.reg_read(UC_X86_REG_ESP)

# Execute the gadget
mu.emu_start(
    CODE_ADDRESS,
    CODE_ADDRESS + len(CODE)
)

# Record ESP after execution
final_esp = mu.reg_read(UC_X86_REG_ESP)

# Calculate how much the gadget moved the stack
stack_offset = final_esp - initial_esp

print(f"Initial ESP: 0x{initial_esp:08x}")
print(f"Final ESP:   0x{final_esp:08x}")
print(f"Stack offset: {stack_offset} bytes")
