# ROPminer Methodology

## 1. Overview

ROPminer is a two-stage analysis system combining a Hidden Markov Model (HMM) with ROP Chain Integrity (RCI) analysis.

The system analyzes executable byte sequences and uses two separately trained HMMs:

- a benign HMM trained on benign executable samples;
- a malicious HMM trained on malicious samples.

The likelihoods produced by the two models are compared using a log-likelihood ratio.

The RCI stage uses posterior state probabilities from forward-backward inference together with statically mined ROP gadgets to identify suspicious gadget transitions.

## 2. Byte Observations

Executable data is represented as raw byte observations.

There are 256 possible observation symbols, corresponding to byte values:

0x00 through 0xFF.

The HMM therefore operates over a discrete observation alphabet of size 256.

## 3. HMM Models

Two separate HMMs are trained.

### Benign model

The benign model learns statistical patterns from benign executable samples.

### Malicious model

The malicious model learns statistical patterns from malicious executable samples.

Using two models allows the same observation sequence to be evaluated under both hypotheses.

## 4. HMM Parameters

Each HMM contains:

- initial-state probabilities (Pi);
- state-transition probabilities (A);
- emission probabilities (B).

Pi describes the probability of beginning in each state.

A describes the probability of transitioning from one state to another.

B describes the probability of observing a byte from each state.

## 5. Likelihood Ratio

For an observation sequence O, the system computes:

Z_HMM = log P(O | malicious) - log P(O | benign)

A positive value indicates that the malicious model assigns greater likelihood to the sequence.

A negative value indicates that the benign model assigns greater likelihood.

## 6. Forward-Backward

Forward-backward inference provides posterior state probabilities for individual observations.

These posterior probabilities provide information beyond the single overall HMM likelihood.

ROPminer uses this information during RCI analysis to determine whether observed byte positions are consistent with potential gadget locations and transitions.

## 7. Gadget Mining

The gadget miner first obtains the executable section of a PE file.

RET/RETN instructions are identified as candidate gadget endpoints.

The miner scans backwards from each endpoint and disassembles the resulting byte sequences.

Candidate gadgets containing unsupported control-flow instructions are rejected.

Valid gadgets are retained together with their stack-effect information.

## 8. Unicorn Emulation

Unicorn is used to dynamically evaluate candidate gadget behavior.

Candidate instruction sequences are executed in a controlled 32-bit x86 emulation environment.

Distinct initial register values allow register modifications to be detected.

The emulator also measures the resulting stack movement.

The resulting stack offset is used by the RCI stage to determine the corresponding next stack location.

## 9. RCI

The RCI stage combines:

1. posterior probabilities from the HMM;
2. mined gadget locations;
3. gadget stack offsets.

For a gadget beginning at position i with stack offset S, the corresponding next position is derived from the gadget's stack movement.

Potential gadget transitions are evaluated against posterior state probabilities.

Violations contribute an RCI penalty to the relevant model likelihood.

## 10. Final Analysis

The system can report both:

- the ordinary HMM likelihood ratio;
- the HMM likelihood ratio after RCI adjustment.

The implementation also records the number of detected gadget candidates and RCI violations.

## 11. Evaluation

The current controlled evaluation contains:

- 100 benign samples;
- 100 malicious samples.

The RCI violation-count experiment produced the strongest separation in the current dataset.

At a threshold of at least one malicious-model RCI violation:

- TP = 99
- TN = 100
- FP = 0
- FN = 1
- Accuracy = 99.5%
- Precision = 100%
- Recall = 99.0%
- F1 = 99.5%

These results describe the current controlled dataset and should not be interpreted as a general real-world malware detection rate.
