# Gadget Dataset Mining

## Purpose

ROPminer builds a database of valid ROP gadgets from the PE files used in the evaluation. Each gadget is associated with its address and dynamic stack effect. This information is used by the RCI component.

## PE and .text Extraction

For each Windows PE file, ROPminer uses `pefile` to locate the executable `.text` section. Gadget mining is performed on the bytes of this section.

## Finding Gadget Endpoints

The miner scans the `.text` bytes for return instructions such as `RET` and `RETN`. These instructions are treated as possible gadget endpoints.

## Backward Gadget Mining

For each return instruction, the miner examines preceding bytes to identify possible gadget starting positions. Candidate sequences are disassembled using Capstone in 32-bit x86 mode.

A candidate is retained when it successfully disassembles into instructions terminating at the identified return instruction.

## Dynamic Analysis with Unicorn

For every valid gadget, Unicorn is used to determine its dynamic stack effect.

The emulator initializes a 32-bit x86 environment, assigns distinct values to registers, places a dummy return address on the stack, and executes the gadget.

The stack offset is calculated from the change in `ESP`:

S = ESP_after - ESP_before

Modified registers are also recorded.

## Gadget Database

The resulting database stores information about each gadget, including:

- Gadget address
- Instructions
- Stack offset
- Modified registers

This database is used by the RCI detector.

## Connection to RCI

When a potential gadget is identified at position `i`, its stack offset `S` is used to calculate the expected next position:

j = i + S

The RCI detector then uses the HMM forward-backward posterior probabilities at positions `i` and `j` to evaluate the expected gadget-chain relationship.

## Overall Process

PE file  
↓  
.text section  
↓  
Find RET / RETN  
↓  
Search backwards  
↓  
Capstone disassembly  
↓  
Valid gadgets  
↓  
Unicorn execution  
↓  
Stack offset and register effects  
↓  
Gadget database  
↓  
RCI analysis
