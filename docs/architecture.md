# ROPminer Architecture

## System Overview

ROPminer combines Hidden Markov Models (HMMs) with ROP Chain Integrity (RCI) analysis.

The pipeline is:

PE file -> executable section -> HMM analysis -> forward-backward posterior -> RCI analysis

In parallel, the executable section is processed by the gadget miner:

PE file -> RET/RETN detection -> gadget mining -> Unicorn emulation -> stack effects -> RCI

## Main Components

### miner.py
Extracts executable PE sections, locates RET/RETN instructions, and mines valid ROP gadgets.

### emulator.py
Uses Unicorn to emulate candidate 32-bit x86 gadgets and determine stack movement and register effects.

### hmm_trainer.py
Trains the benign and malicious HMM models.

### hmm_detector.py
Computes HMM likelihoods and forward-backward posterior probabilities.

### rci_detector.py
Combines posterior information with gadget information for RCI analysis.

### batch_final_evaluation.py
Runs the final HMM + RCI evaluation over the dataset.

### final_metrics.py
Calculates the final classification metrics.

## HMM Models

Two models are used: a benign HMM and a malicious HMM.

The observation alphabet contains 256 possible byte values, from 0x00 through 0xFF.

Each HMM contains initial-state probabilities (Pi), transition probabilities (A), and emission probabilities (B).

## Likelihood Ratio

Z_HMM = log P(O | malicious) - log P(O | benign)

A positive value favors the malicious model; a negative value favors the benign model.

## Forward-Backward

Forward-backward inference provides posterior probabilities for individual observations and states. These posteriors are used by the RCI stage.

## Gadget Mining

The miner extracts the executable section, finds RET/RETN endpoints, scans backwards, disassembles candidate sequences, and retains valid gadgets.

## Unicorn Emulation

Unicorn dynamically executes candidate gadgets in a controlled 32-bit x86 environment. The resulting stack movement and register modifications are recorded.

## RCI

RCI combines HMM posterior information with mined gadget locations and stack effects to identify potential integrity violations and calculate the RCI adjustment.

## Final Outputs

The final evaluation records HMM likelihoods, HMM likelihood ratios, RCI adjustments, gadget counts, candidate counts, and violation counts.

Final results are stored in dataset/final_rci_results.json.
