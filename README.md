# ROPminer

Learning-Based Static Detection of Return-Oriented Programming (ROP) Chains

## Overview

ROPminer is a research prototype that combines Hidden Markov Models (HMMs) with ROP Chain Integrity (RCI) analysis to identify potential ROP activity in Windows PE executables.

The system consists of:

- **HMM analysis** of executable byte sequences
- **Gadget mining** using RET/RETN endpoints
- **Unicorn emulation** to determine gadget stack effects
- **Forward-backward inference** to obtain posterior probabilities
- **RCI analysis** to identify potential gadget-chain violations

## Architecture

```text
PE File
   |
   +--------------------+
   |                    |
   v                    v
HMM Analysis       Gadget Miner
   |                    |
   v                    v
Forward-Backward   Valid Gadgets
   |                    |
   |                    v
   |                Unicorn
   |                    |
   +---------+----------+
             |
             v
        RCI Analysis
             |
             v
   Candidates / Violations
             |
             v
      Final Assessment
