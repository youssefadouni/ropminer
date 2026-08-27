import argparse
import json
import pickle
from pathlib import Path

import numpy as np


STATES = [
    "addr1",
    "addr2",
    "addr3",
    "addr4",
    "const1",
    "const2",
    "const3",
    "const4",
    "junk",
    "data",
    "EOF",
]

STATE_TO_ID = {
    state: i
    for i, state in enumerate(STATES)
}

N_STATES = len(STATES)
N_SYMBOLS = 256


def load_labeled_sequences(path):
    """
    Load supervised HMM training sequences.

    Expected JSON format:

    [
        {
            "observations": [1, 2, 3, ...],
            "states": ["data", "data", "addr1", ...]
        },
        ...
    ]
    """

    with open(path, "r") as f:
        sequences = json.load(f)

    if not isinstance(sequences, list):
        raise ValueError("Training data must be a list of sequences.")

    validated = []

    for index, sequence in enumerate(sequences):
        if "observations" not in sequence:
            raise ValueError(
                f"Sequence {index} has no 'observations' field."
            )

        if "states" not in sequence:
            raise ValueError(
                f"Sequence {index} has no 'states' field."
            )

        observations = sequence["observations"]
        states = sequence["states"]

        if len(observations) != len(states):
            raise ValueError(
                f"Sequence {index}: observations and states "
                f"have different lengths."
            )

        if not observations:
            raise ValueError(
                f"Sequence {index} is empty."
            )

        for byte in observations:
            if not isinstance(byte, int) or not 0 <= byte <= 255:
                raise ValueError(
                    f"Invalid byte {byte} in sequence {index}."
                )

        for state in states:
            if state not in STATE_TO_ID:
                raise ValueError(
                    f"Unknown state '{state}' in sequence {index}."
                )

        validated.append(
            {
                "observations": observations,
                "states": states,
            }
        )

    return validated


def train_supervised(sequences, smoothing=1e-12):
    """
    Train A, B and pi using the supervised counting equations
    specified in the internship manual / ROPminer paper.

    A[i,j] = K[i,j] / sum_j K[i,j]

    B[i,o] = M[i,o] / sum_o M[i,o]

    pi[i] = N[i] / sum_i N[i]

    Small additive smoothing is used so that probabilities are
    never exactly zero.
    """

    transition_counts = np.zeros(
        (N_STATES, N_STATES),
        dtype=np.float64,
    )

    emission_counts = np.zeros(
        (N_STATES, N_SYMBOLS),
        dtype=np.float64,
    )

    initial_counts = np.zeros(
        N_STATES,
        dtype=np.float64,
    )

    for sequence in sequences:

        observations = sequence["observations"]
        states = [
            STATE_TO_ID[state]
            for state in sequence["states"]
        ]

        # Initial state
        initial_counts[states[0]] += 1

        # Emissions
        for state, observation in zip(states, observations):
            emission_counts[state, observation] += 1

        # Transitions
        for current_state, next_state in zip(
            states[:-1],
            states[1:],
        ):
            transition_counts[
                current_state,
                next_state,
            ] += 1

    # Add tiny smoothing to avoid zero-probability rows.
    transition_counts += smoothing
    emission_counts += smoothing
    initial_counts += smoothing

    A = transition_counts / transition_counts.sum(
        axis=1,
        keepdims=True,
    )

    B = emission_counts / emission_counts.sum(
        axis=1,
        keepdims=True,
    )

    pi = initial_counts / initial_counts.sum()

    return {
        "states": STATES,
        "n_states": N_STATES,
        "n_symbols": N_SYMBOLS,
        "transition_matrix": A,
        "emission_matrix": B,
        "initial_probabilities": pi,
    }


def save_model(model, path):
    """
    Serialize the trained model.
    """

    with open(path, "wb") as f:
        pickle.dump(model, f)


def print_summary(model):
    A = model["transition_matrix"]
    B = model["emission_matrix"]
    pi = model["initial_probabilities"]

    print()
    print("========== HMM SUMMARY ==========")
    print(f"States:       {model['n_states']}")
    print(f"Observations: {model['n_symbols']}")
    print()

    print("Initial probabilities:")
    for state, probability in zip(STATES, pi):
        print(f"  {state:7s}: {probability:.6f}")

    print()
    print("Transition matrix shape:")
    print(f"  {A.shape}")

    print()
    print("Emission matrix shape:")
    print(f"  {B.shape}")

    print()
    print("Row sums:")
    print(f"  A rows: {np.round(A.sum(axis=1), 6)}")
    print(f"  B rows: {np.round(B.sum(axis=1), 6)}")

    print()
    print("=================================")


def main():
    parser = argparse.ArgumentParser(
        description="Train the supervised 11-state ROPminer HMM."
    )

    parser.add_argument(
        "input",
        type=Path,
        help="JSON file containing labeled training sequences",
    )

    parser.add_argument(
        "output",
        type=Path,
        help="Output pickle file",
    )

    args = parser.parse_args()

    print(f"[+] Loading training data: {args.input}")

    sequences = load_labeled_sequences(args.input)

    print(f"[+] Training sequences: {len(sequences)}")

    model = train_supervised(sequences)

    save_model(model, args.output)

    print(f"[+] Model saved: {args.output}")

    print_summary(model)


if __name__ == "__main__":
    main()
