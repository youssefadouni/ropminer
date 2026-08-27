import struct

from unicorn import *
from unicorn.x86_const import *


CODE_ADDRESS = 0x1000000

STACK_ADDRESS = 0x2000000
STACK_SIZE = 2 * 1024 * 1024

RETURN_ADDRESS = 0x90909090


REGISTERS = {
    "EAX": UC_X86_REG_EAX,
    "EBX": UC_X86_REG_EBX,
    "ECX": UC_X86_REG_ECX,
    "EDX": UC_X86_REG_EDX,
    "ESI": UC_X86_REG_ESI,
    "EDI": UC_X86_REG_EDI,
    "EBP": UC_X86_REG_EBP,
    "ESP": UC_X86_REG_ESP,
}

# Distinct initial values for each register
INITIAL_VALUES = {
    "EAX": 0x11111111,
    "EBX": 0x22222222,
    "ECX": 0x33333333,
    "EDX": 0x44444444,
    "ESI": 0x55555555,
    "EDI": 0x66666666,
    "EBP": 0x77777777,
}


def get_stack_offset(opcode_bytes):

    mu = Uc(UC_ARCH_X86, UC_MODE_32)

    mu.mem_map(CODE_ADDRESS, 0x1000)
    mu.mem_map(STACK_ADDRESS, STACK_SIZE)

    mu.mem_write(CODE_ADDRESS, opcode_bytes)

    esp_init = STACK_ADDRESS + STACK_SIZE // 2

    # Initialize registers with distinct values
    for name, value in INITIAL_VALUES.items():
        mu.reg_write(REGISTERS[name], value)

    mu.reg_write(UC_X86_REG_ESP, esp_init)

    # Dummy return address
    mu.mem_write(
        esp_init,
        struct.pack("<I", RETURN_ADDRESS)
    )

    before = {}

    for name, reg in REGISTERS.items():
        before[name] = mu.reg_read(reg)

    try:

        mu.emu_start(
            CODE_ADDRESS,
            RETURN_ADDRESS,
            timeout=10000
        )

    except UcError as e:

        # Expected after RET
        if e.errno != UC_ERR_FETCH_UNMAPPED:
            return None

    after = {}

    for name, reg in REGISTERS.items():
        after[name] = mu.reg_read(reg)

    modified = []

    for reg in REGISTERS:

        # Stack movement is already represented separately
        if reg == "ESP":
            continue

        if before[reg] != after[reg]:
            modified.append(reg)

    stack_offset = after["ESP"] - before["ESP"]

    return {
        "stack_offset": stack_offset,
        "modified_registers": modified
    }
