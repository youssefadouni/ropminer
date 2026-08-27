# Reproducibility

## Requirements

Python 3 with the dependencies listed in requirements.txt.

Install dependencies:

    python -m venv .venv
    source .venv/bin/activate
    pip install -r requirements.txt

## Syntax Validation

    python -m py_compile miner.py emulator.py hmm_trainer.py hmm_detector.py rci_detector.py batch_final_evaluation.py final_metrics.py

## Module Validation

    python -c "import miner, emulator, hmm_trainer, hmm_detector, rci_detector"

## Gadget Mining

    python miner.py INPUT_PE OUTPUT_JSON

## HMM Detection

    python hmm_detector.py SEQUENCE_JSON

## HMM + RCI Detection

    python rci_detector.py PE_FILE SEQUENCE_JSON SEQUENCE_NAME

## Batch Evaluation

    python batch_final_evaluation.py

The final results are written to dataset/final_rci_results.json.

## Metrics

    python final_metrics.py

## Models

    models/hmm_ben.pkl
    models/hmm_mal.pkl

Large raw datasets, generated HMM sequences, gadget caches, payloads, and temporary binaries are excluded from Git.
