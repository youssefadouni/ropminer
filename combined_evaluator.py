import json
import re
from pathlib import Path

import numpy as np


HMM_BENIGN = "dataset/hmm_benign_scores.txt"
HMM_MALICIOUS = "dataset/hmm_malicious_scores.txt"
RCI_FILE = "dataset/rci_scores_baseline.json"


def load_hmm_scores(path):
    scores = {}

    with open(path) as f:
        for line in f:
            match = re.search(
                r"^(.*?)\s+Z=([-+0-9.eE]+)\s*$",
                line.strip(),
            )

            if not match:
                continue

            name = match.group(1).strip()
            score = float(match.group(2))

            scores[name] = score

    return scores


def load_rci_scores(path):
    with open(path) as f:
        data = json.load(f)

    return {
        Path(item["name"]).name: item["score"]
        for item in data
        if item["score"] is not None
    }


def normalize_hmm(all_scores):
    """
    Robust min-max normalization.

    This puts HMM scores into [0, 1] while reducing
    the effect of extreme outliers.
    """

    values = np.array(
        list(all_scores.values()),
        dtype=float,
    )

    low = np.percentile(values, 5)
    high = np.percentile(values, 95)

    if high <= low:
        return {
            name: 0.0
            for name in all_scores
        }

    normalized = {}

    for name, value in all_scores.items():

        score = (value - low) / (high - low)

        score = max(
            0.0,
            min(1.0, score),
        )

        normalized[name] = score

    return normalized


def calculate_metrics(records):
    tp = sum(
        r["prediction"] == 1
        and r["label"] == 1
        for r in records
    )

    tn = sum(
        r["prediction"] == 0
        and r["label"] == 0
        for r in records
    )

    fp = sum(
        r["prediction"] == 1
        and r["label"] == 0
        for r in records
    )

    fn = sum(
        r["prediction"] == 0
        and r["label"] == 1
        for r in records
    )

    accuracy = (
        (tp + tn) / len(records)
        if records
        else 0.0
    )

    precision = (
        tp / (tp + fp)
        if tp + fp
        else 0.0
    )

    recall = (
        tp / (tp + fn)
        if tp + fn
        else 0.0
    )

    f1 = (
        2 * precision * recall
        / (precision + recall)
        if precision + recall
        else 0.0
    )

    return {
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


def evaluate(
    records,
    hmm_weight,
    rci_weight,
    threshold,
):
    evaluated = []

    for record in records:

        combined = (
            hmm_weight * record["hmm_norm"]
            + rci_weight * record["rci"]
        )

        prediction = int(
            combined >= threshold
        )

        evaluated.append({
            **record,
            "combined": combined,
            "prediction": prediction,
        })

    return calculate_metrics(evaluated)


def main():

    hmm_benign = load_hmm_scores(
        HMM_BENIGN
    )

    hmm_malicious = load_hmm_scores(
        HMM_MALICIOUS
    )

    rci = load_rci_scores(
        RCI_FILE
    )

    all_hmm = {
        **hmm_benign,
        **hmm_malicious,
    }

    hmm_norm = normalize_hmm(
        all_hmm
    )

    records = []

    for name, score in hmm_benign.items():

        if name not in rci:
            print(
                "[!] Missing RCI:",
                name,
            )
            continue

        records.append({
            "name": name,
            "label": 0,
            "hmm": score,
            "hmm_norm": hmm_norm[name],
            "rci": rci[name],
        })

    for name, score in hmm_malicious.items():

        if name not in rci:
            print(
                "[!] Missing RCI:",
                name,
            )
            continue

        records.append({
            "name": name,
            "label": 1,
            "hmm": score,
            "hmm_norm": hmm_norm[name],
            "rci": rci[name],
        })

    print("=== DATASET ALIGNMENT ===")
    print("HMM benign:     ", len(hmm_benign))
    print("HMM malicious:  ", len(hmm_malicious))
    print("RCI samples:    ", len(rci))
    print("Combined:       ", len(records))

    print()

    #
    # Evaluate the individual normalized HMM signal.
    #

    print("=== HMM / RCI INDIVIDUAL BASELINES ===")

    hmm_records = []

    for record in records:
        hmm_records.append({
            **record,
            "prediction": int(
                record["hmm_norm"] >= 0.5
            ),
        })

    hmm_metrics = calculate_metrics(
        hmm_records
    )

    print()
    print("HMM normalized threshold = 0.5")
    print_metrics(hmm_metrics)

    rci_records = []

    for record in records:
        rci_records.append({
            **record,
            "prediction": int(
                record["rci"] > 0.0
            ),
        })

    rci_metrics = calculate_metrics(
        rci_records
    )

    print()
    print("RCI threshold = 0")
    print_metrics(rci_metrics)

    #
    # Grid search over combinations.
    #

    results = []

    weights = [
        (0.0, 1.0),
        (0.1, 0.9),
        (0.2, 0.8),
        (0.3, 0.7),
        (0.4, 0.6),
        (0.5, 0.5),
        (0.6, 0.4),
        (0.7, 0.3),
        (0.8, 0.2),
        (0.9, 0.1),
        (1.0, 0.0),
    ]

    thresholds = [
        0.20,
        0.25,
        0.30,
        0.35,
        0.40,
        0.45,
        0.50,
        0.55,
        0.60,
        0.65,
        0.70,
        0.75,
        0.80,
    ]

    for hmm_weight, rci_weight in weights:

        for threshold in thresholds:

            metrics = evaluate(
                records,
                hmm_weight,
                rci_weight,
                threshold,
            )

            results.append({
                "hmm_weight": hmm_weight,
                "rci_weight": rci_weight,
                "threshold": threshold,
                **metrics,
            })

    results.sort(
        key=lambda x: (
            x["f1"],
            x["accuracy"],
        ),
        reverse=True,
    )

    print()
    print("=== BEST COMBINATIONS ===")

    print(
        f"{'HMM':>5} "
        f"{'RCI':>5} "
        f"{'THR':>5} "
        f"{'ACC':>7} "
        f"{'PREC':>7} "
        f"{'REC':>7} "
        f"{'F1':>7} "
        f"{'FP':>4} "
        f"{'FN':>4}"
    )

    for result in results[:15]:

        print(
            f"{result['hmm_weight']:5.1f} "
            f"{result['rci_weight']:5.1f} "
            f"{result['threshold']:5.2f} "
            f"{result['accuracy']:7.3f} "
            f"{result['precision']:7.3f} "
            f"{result['recall']:7.3f} "
            f"{result['f1']:7.3f} "
            f"{result['fp']:4d} "
            f"{result['fn']:4d}"
        )

    #
    # Save everything.
    #

    output = Path(
        "dataset/combined_evaluation.json"
    )

    with open(output, "w") as f:
        json.dump(
            {
                "dataset_size": len(records),
                "hmm_baseline": hmm_metrics,
                "rci_baseline": rci_metrics,
                "grid_search": results,
            },
            f,
            indent=2,
        )

    print()
    print("Saved:", output)


def print_metrics(metrics):

    print(
        f"Accuracy : {metrics['accuracy']:.3f}"
    )

    print(
        f"Precision: {metrics['precision']:.3f}"
    )

    print(
        f"Recall   : {metrics['recall']:.3f}"
    )

    print(
        f"F1       : {metrics['f1']:.3f}"
    )

    print(
        f"TP={metrics['tp']} "
        f"TN={metrics['tn']} "
        f"FP={metrics['fp']} "
        f"FN={metrics['fn']}"
    )


if __name__ == "__main__":
    main()
