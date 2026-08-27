import json
import struct
from pathlib import Path

from miner import (
    load_pe,
    get_text_section,
    get_disassembler,
    find_ret_offsets,
    mine_gadgets,
)


PUSH_IMM32 = 0x68


def mine_for_pe(path):
    pe = load_pe(path)

    code, image_base = get_text_section(pe)

    if code is None:
        pe.close()
        return {}

    md = get_disassembler()
    ret_offsets = find_ret_offsets(code)

    gadgets = mine_gadgets(
        code,
        image_base,
        md,
        ret_offsets,
    )

    pe.close()

    return gadgets


def find_push_gadget_candidates(data, gadget_db):
    addresses = {
        int(address, 16)
        for address in gadget_db
    }

    candidates = []

    for i in range(len(data) - 4):

        if data[i] != PUSH_IMM32:
            continue

        address = struct.unpack_from(
            "<I",
            data,
            i + 1,
        )[0]

        if address in addresses:
            candidates.append({
                "offset": i,
                "address": address,
            })

    return candidates


def calculate_rci(data, gadget_db):
    candidates = find_push_gadget_candidates(
        data,
        gadget_db,
    )

    if not candidates:
        return {
            "candidates": 0,
            "chains": 0,
            "score": 0.0,
        }

    candidate_offsets = {
        candidate["offset"]
        for candidate in candidates
    }

    chains = 0

    for candidate in candidates:

        next_offset = candidate["offset"] + 5

        if next_offset in candidate_offsets:
            chains += 1

    score = chains / len(candidates)

    return {
        "candidates": len(candidates),
        "chains": chains,
        "score": score,
    }


def get_pe_files(directory):
    directory = Path(directory)

    paths = []

    for pattern in (
        "*.exe",
        "*.EXE",
        "*.dll",
        "*.DLL",
    ):
        paths.extend(directory.glob(pattern))

    return sorted(
        set(paths),
        key=lambda p: p.name.lower(),
    )


def process_file(path, label, index, total):
    print(
        f"[{index:03d}/{total:03d}] "
        f"{label:9s} {path.name}",
        flush=True,
    )

    try:
        gadget_db = mine_for_pe(path)

        data = path.read_bytes()

        result = calculate_rci(
            data,
            gadget_db,
        )

        return {
            "name": path.name,
            "path": str(path),
            "label": label,
            "gadgets": len(gadget_db),
            **result,
            "error": None,
        }

    except Exception as e:

        return {
            "name": path.name,
            "path": str(path),
            "label": label,
            "gadgets": 0,
            "candidates": None,
            "chains": None,
            "score": None,
            "error": str(e),
        }


def process_directory(directory, label):
    paths = get_pe_files(directory)

    print()
    print(
        f"Found {len(paths)} PE files in {directory}"
    )

    records = []

    for i, path in enumerate(paths, 1):

        records.append(
            process_file(
                path,
                label,
                i,
                len(paths),
            )
        )

    return records


def print_summary(records, label):

    subset = [
        r for r in records
        if r["label"] == label
    ]

    valid = [
        r for r in subset
        if r["score"] is not None
    ]

    scores = [
        r["score"]
        for r in valid
    ]

    print()
    print(label.upper())
    print("samples:", len(valid))

    if not scores:
        print("No valid scores.")
        return

    print("min:     ", min(scores))
    print("max:     ", max(scores))
    print("mean:    ", sum(scores) / len(scores))
    print(
        "nonzero: ",
        sum(x > 0 for x in scores),
    )


def main():

    benign = process_directory(
        "dataset/benign",
        "benign",
    )

    malicious = process_directory(
        "dataset/malicious",
        "malicious",
    )

    records = benign + malicious

    output = Path(
        "dataset/rci_scores.json"
    )

    with open(output, "w") as f:
        json.dump(
            records,
            f,
            indent=2,
        )

    print()
    print("Saved:", output)

    print()
    print("=== SUMMARY ===")

    print_summary(
        records,
        "benign",
    )

    print_summary(
        records,
        "malicious",
    )

    threshold = 0.0

    benign_valid = [
        r for r in benign
        if r["score"] is not None
    ]

    malicious_valid = [
        r for r in malicious
        if r["score"] is not None
    ]

    false_positives = sum(
        r["score"] > threshold
        for r in benign_valid
    )

    true_positives = sum(
        r["score"] > threshold
        for r in malicious_valid
    )

    true_negatives = (
        len(benign_valid)
        - false_positives
    )

    false_negatives = (
        len(malicious_valid)
        - true_positives
    )

    total = (
        len(benign_valid)
        + len(malicious_valid)
    )

    accuracy = (
        true_positives + true_negatives
    ) / total if total else 0.0

    print()
    print("=== RCI BASELINE ===")
    print("Threshold:", threshold)
    print()
    print("Benign samples:   ", len(benign_valid))
    print("Malicious samples:", len(malicious_valid))
    print()
    print("True negatives:   ", true_negatives)
    print("False positives:  ", false_positives)
    print("True positives:   ", true_positives)
    print("False negatives:  ", false_negatives)
    print()
    print("Accuracy:", accuracy)


if __name__ == "__main__":
    main()
