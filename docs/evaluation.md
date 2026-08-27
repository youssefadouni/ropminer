# Evaluation

## Dataset

The final controlled evaluation contains:

- 100 benign samples
- 100 malicious samples
- 200 samples total

## HMM Baseline

The best HMM likelihood-ratio threshold evaluated produced:

- TP: 69
- TN: 83
- FP: 17
- FN: 31
- Accuracy: 76.0%
- Precision: 80.2%
- Recall: 69.0%
- F1: 74.2%

## RCI Violation Signal

Using the malicious-model RCI violation count as an independent signal:

| Threshold | TP | TN | FP | FN | Accuracy | Precision | Recall | F1 |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| >= 1 | 99 | 100 | 0 | 1 | 99.5% | 100% | 99.0% | 99.5% |
| >= 2 | 68 | 100 | 0 | 32 | 84.0% | 100% | 68.0% | 81.0% |
| >= 3 | 28 | 100 | 0 | 72 | 64.0% | 100% | 28.0% | 43.8% |
| >= 4 | 26 | 100 | 0 | 74 | 63.0% | 100% | 26.0% | 41.3% |

## HMM + RCI Likelihood Adjustment

The implementation also calculates an RCI likelihood adjustment and an HMM + RCI likelihood ratio. In the current evaluation, this adjustment does not substantially improve the HMM likelihood-ratio classifier.

Therefore, the 99.5% result should specifically be described as the performance of the RCI violation-count signal.

## Held-Out Injection Test

A separate test_injected.exe sample was evaluated outside the 200-sample dataset.

Results:

- 118 valid gadgets
- 2 RCI candidates
- 2 RCI violations
- malicious classification

## Interpretation

The results demonstrate strong separation on the current controlled dataset. They should not be interpreted as a general real-world malware detection rate. Independent datasets would be required to establish generalization.
