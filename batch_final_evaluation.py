import json
import time
from pathlib import Path

import miner

from hmm_detector import load_model, prepare_model, forward_backward
from rci_detector import (
    find_gadget_candidates,
    calculate_rci_adjustment,
)


BASE = Path(".")

BENIGN_SEQ = BASE / "dataset/hmm/benign_sequences.json"
MALICIOUS_SEQ = BASE / "dataset/hmm/malicious_sequences.json"

BENIGN_DIR = BASE / "dataset/benign"
MALICIOUS_DIR = BASE / "dataset/malicious"

MODEL_BENIGN = BASE / "models/hmm_ben.pkl"
MODEL_MALICIOUS = BASE / "models/hmm_mal.pkl"

OUTPUT = BASE / "dataset/final_rci_results.json"
GADGET_CACHE = BASE / "dataset/gadget_cache"
GADGET_CACHE.mkdir(parents=True, exist_ok=True)


def load_sequences(path):
    with open(path) as f:
        return json.load(f)


def mine_gadgets(path):
    """Load a cached gadget database, or mine and cache it."""

    path = Path(path)
    cache_file = GADGET_CACHE / f"{path.name}.json"

    if cache_file.exists():
        with open(cache_file) as f:
            return json.load(f)

    pe = miner.load_pe(path)

    try:
        code, image_base = miner.get_text_section(pe)

        if code is None:
            gadgets = {}
        else:
            md = miner.get_disassembler()
            ret_offsets = miner.find_ret_offsets(code)

            gadgets = miner.mine_gadgets(
                code,
                image_base,
                md,
                ret_offsets,
            )
    finally:
        pe.close()

    with open(cache_file, "w") as f:
        json.dump(gadgets, f)

    return gadgets


def analyze(observations, gadgets, model, threshold=0.50):
    log_likelihood, posterior = forward_backward(
        observations,
        model,
    )

    candidates = find_gadget_candidates(
        observations,
        posterior,
        model["states"],
        gadgets,
        threshold,
    )

    log_penalty, factors, violations = calculate_rci_adjustment(
        observations,
        posterior,
        model["states"],
        candidates,
    )

    return {
        "log_likelihood": float(log_likelihood),
        "log_penalty": float(log_penalty),
        "rci_likelihood": float(
            log_likelihood + log_penalty
        ),
        "candidates": len(candidates),
        "violations": len(violations),
    }


def save_results(results):
    with open(OUTPUT, "w") as f:
        json.dump(results, f, indent=2)


def main():
    start_time = time.time()

    benign_sequences = load_sequences(BENIGN_SEQ)
    malicious_sequences = load_sequences(MALICIOUS_SEQ)

    print("==============================================")
    print("OPTIMIZED FINAL HMM + POSTERIOR RCI")
    print("==============================================")
    print(f"Benign sequences:    {len(benign_sequences)}")
    print(f"Malicious sequences: {len(malicious_sequences)}")
    print()

    # Load and prepare each model ONCE.
    print("[+] Loading benign HMM...")
    benign_model = prepare_model(
        load_model(MODEL_BENIGN)
    )

    print("[+] Loading malicious HMM...")
    malicious_model = prepare_model(
        load_model(MODEL_MALICIOUS)
    )

    print("[+] Models ready.")
    print()

    results = []

    datasets = [
        ("benign", benign_sequences, BENIGN_DIR),
        ("malicious", malicious_sequences, MALICIOUS_DIR),
    ]

    total = len(benign_sequences) + len(malicious_sequences)
    completed = 0

    for label, sequences, directory in datasets:

        print(f"=== {label.upper()} ===")

        for index, sequence in enumerate(sequences, 1):

            name = sequence["name"]
            pe_path = directory / name

            sample_start = time.time()

            gadgets = mine_gadgets(pe_path)

            benign_result = analyze(
                sequence["observations"],
                gadgets,
                benign_model,
            )

            malicious_result = analyze(
                sequence["observations"],
                gadgets,
                malicious_model,
            )

            results.append({
                "name": name,
                "label": 1 if label == "malicious" else 0,
                "payload_name": sequence.get("payload_name"),
                "payload_group": sequence.get("payload_group"),
                "gadgets": len(gadgets),

                "benign_hmm": benign_result["log_likelihood"],
                "benign_rci_adjustment": benign_result["log_penalty"],
                "benign_rci_likelihood": benign_result[
                    "rci_likelihood"
                ],
                "benign_candidates": benign_result["candidates"],
                "benign_violations": benign_result["violations"],

                "malicious_hmm": malicious_result["log_likelihood"],
                "malicious_rci_adjustment": malicious_result[
                    "log_penalty"
                ],
                "malicious_rci_likelihood": malicious_result[
                    "rci_likelihood"
                ],
                "malicious_candidates": malicious_result[
                    "candidates"
                ],
                "malicious_violations": malicious_result[
                    "violations"
                ],
            })

            # Checkpoint after every sample.
            save_results(results)

            completed += 1

            elapsed = time.time() - start_time
            per_sample = elapsed / completed
            remaining = per_sample * (total - completed)

            print(
                f"[{index:03d}/{len(sequences):03d}] "
                f"{label:9s} {name} "
                f"| {time.time() - sample_start:.1f}s "
                f"| total {elapsed/60:.1f}m "
                f"| ETA {remaining/60:.1f}m",
                flush=True,
            )

    print()
    print("==============================================")
    print("COMPLETE")
    print("==============================================")
    print(f"Results: {len(results)}")
    print(f"Saved:   {OUTPUT}")
    print(
        f"Total time: {(time.time() - start_time)/60:.1f} minutes"
    )


if __name__ == "__main__":
    main()
