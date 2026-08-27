# rci_detector.py

import argparse
import json
import math
import pickle
import struct
from pathlib import Path

import numpy as np

from hmm_detector import (
    forward_backward,
    load_model,
    prepare_model,
)


BASE = Path(__file__).resolve().parent

BENIGN_MODEL = BASE / "models" / "hmm_ben.pkl"
MALICIOUS_MODEL = BASE / "models" / "hmm_mal.pkl"


def load_sequence(path, name):
    with open(path, "r") as f:
        sequences = json.load(f)

    for sequence in sequences:
        if sequence["name"] == name:
            return sequence

    raise ValueError(
        f"Sequence '{name}' not found in {path}"
    )


def mine_gadget_database(path):
    from miner import (
        load_pe,
        get_text_section,
        get_disassembler,
        find_ret_offsets,
        mine_gadgets,
    )

    pe = load_pe(path)

    try:
        code, image_base = get_text_section(pe)

        if code is None:
            return {}

        md = get_disassembler()
        ret_offsets = find_ret_offsets(code)

        return mine_gadgets(
            code,
            image_base,
            md,
            ret_offsets,
        )
    finally:
        pe.close()


def find_gadget_candidates(
    observations,
    posterior,
    states,
    gadgets,
    threshold,
):
    state_index = {
        state: i
        for i, state in enumerate(states)
    }

    addr1 = state_index["addr1"]

    candidates = []

    observation_bytes = bytes(observations)

    for address, information in gadgets.items():

        address_int = int(address, 16)

        address_bytes = struct.pack(
            "<I",
            address_int,
        )

        stack_offset = information[
            "stack_offset"
        ]

        start = 0

        while True:

            position = observation_bytes.find(
                address_bytes,
                start,
            )

            if position == -1:
                break

            if position < len(posterior):

                probability = float(
                    posterior[position, addr1]
                )

                if probability >= threshold:
                    candidates.append({
                        "position": position,
                        "address": address_int,
                        "stack_offset": stack_offset,
                        "confidence": probability,
                    })

            start = position + 1

    return candidates


def calculate_rci_adjustment(
    observations,
    posterior,
    states,
    candidates,
):
    state_index = {
        state: i
        for i, state in enumerate(states)
    }

    addr1 = state_index["addr1"]

    log_penalty = 0.0
    violations = []
    factors = []

    for candidate in candidates:

        i = candidate["position"]

        stack_offset = candidate[
            "stack_offset"
        ]

        j = i + stack_offset

        p_i_addr1 = float(
            posterior[i, addr1]
        )

        if j < 0 or j >= len(observations):
            p_j_addr1 = 0.0
        else:
            p_j_addr1 = float(
                posterior[j, addr1]
            )

        p_j_not_addr1 = (
            1.0 - p_j_addr1
        )

        factor = (
            1.0
            - p_i_addr1
            * p_j_not_addr1
        )

        factor = max(
            factor,
            1e-300,
        )

        log_penalty += math.log(
            factor
        )

        factors.append(factor)

        if (
            p_i_addr1 >= 0.50
            and p_j_not_addr1 >= 0.50
        ):
            violations.append({
                "i": i,
                "j": j,
                "address": candidate[
                    "address"
                ],
                "p_i_addr1": p_i_addr1,
                "p_j_addr1": p_j_addr1,
                "p_j_not_addr1": p_j_not_addr1,
                "factor": factor,
            })

    return (
        log_penalty,
        factors,
        violations,
    )


def analyze_with_model(
    observations,
    gadgets,
    model_path,
    threshold,
):
    model = prepare_model(
        load_model(model_path)
    )

    log_likelihood, posterior = (
        forward_backward(
            observations,
            model,
        )
    )

    candidates = find_gadget_candidates(
        observations,
        posterior,
        model["states"],
        gadgets,
        threshold,
    )

    (
        log_penalty,
        factors,
        violations,
    ) = calculate_rci_adjustment(
        observations,
        posterior,
        model["states"],
        candidates,
    )

    adjusted_log_likelihood = (
        log_likelihood
        + log_penalty
    )

    return {
        "log_likelihood": log_likelihood,
        "posterior": posterior,
        "candidates": candidates,
        "log_penalty": log_penalty,
        "factors": factors,
        "violations": violations,
        "adjusted_log_likelihood":
            adjusted_log_likelihood,
    }


def main():

    parser = argparse.ArgumentParser(
        description=(
            "HMM + ROP Chain Integrity analysis"
        )
    )

    parser.add_argument(
        "pe",
        help="PE file",
    )

    parser.add_argument(
        "sequence",
        help="HMM sequence JSON",
    )

    parser.add_argument(
        "name",
        help="Sequence name",
    )

    parser.add_argument(
        "--threshold",
        type=float,
        default=0.50,
        help=(
            "Minimum P(addr1) for "
            "candidate detection"
        ),
    )

    args = parser.parse_args()

    print(
        f"[+] Mining gadgets from: {args.pe}"
    )

    gadgets = mine_gadget_database(
        args.pe
    )

    print(
        f"[+] Gadgets: {len(gadgets)}"
    )

    sequence = load_sequence(
        args.sequence,
        args.name,
    )

    observations = sequence[
        "observations"
    ]

    print(
        f"[+] Sequence length: "
        f"{len(observations)}"
    )

    print()
    print("[+] Running benign HMM...")

    benign = analyze_with_model(
        observations,
        gadgets,
        BENIGN_MODEL,
        args.threshold,
    )

    print(
        "[+] Running malicious HMM..."
    )

    malicious = analyze_with_model(
        observations,
        gadgets,
        MALICIOUS_MODEL,
        args.threshold,
    )

    z_normal = (
        malicious["log_likelihood"]
        - benign["log_likelihood"]
    )

    z_rci = (
        malicious["adjusted_log_likelihood"]
        - benign["adjusted_log_likelihood"]
    )

    rci_candidates = len(
        malicious["candidates"]
    )

    rci_violations = len(
        malicious["violations"]
    )

    rci_decision = (
        "MALICIOUS"
        if rci_violations >= 1
        else "BENIGN"
    )

    print()
    print(
        "=========================================="
    )
    print(
        "        HMM + RCI DETECTION RESULT"
    )
    print(
        "=========================================="
    )

    print()
    print("BENIGN HMM")
    print(
        f"  log likelihood: "
        f"{benign['log_likelihood']:.6f}"
    )
    print(
        f"  RCI adjustment: "
        f"{benign['log_penalty']:.6f}"
    )
    print(
        f"  RCI likelihood: "
        f"{benign['adjusted_log_likelihood']:.6f}"
    )
    print(
        f"  candidates: "
        f"{len(benign['candidates'])}"
    )
    print(
        f"  violations: "
        f"{len(benign['violations'])}"
    )

    print()
    print("MALICIOUS HMM")
    print(
        f"  log likelihood: "
        f"{malicious['log_likelihood']:.6f}"
    )
    print(
        f"  RCI adjustment: "
        f"{malicious['log_penalty']:.6f}"
    )
    print(
        f"  RCI likelihood: "
        f"{malicious['adjusted_log_likelihood']:.6f}"
    )
    print(
        f"  candidates: "
        f"{rci_candidates}"
    )
    print(
        f"  violations: "
        f"{rci_violations}"
    )

    print()
    print("LIKELIHOOD RATIOS")
    print(
        f"  HMM Z: "
        f"{z_normal:.6f}"
    )
    print(
        f"  HMM + RCI Z: "
        f"{z_rci:.6f}"
    )

    print()
    print("RCI CLASSIFICATION")
    print(
        f"  candidates: "
        f"{rci_candidates}"
    )
    print(
        f"  violations: "
        f"{rci_violations}"
    )
    print(
        "  decision: "
        f"{rci_decision}"
    )

    print()
    print(
        "=========================================="
    )


if __name__ == "__main__":
    main()
