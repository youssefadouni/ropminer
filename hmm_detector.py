import argparse
import json
import pickle
from pathlib import Path

import numpy as np


def load_model(path):
    with open(path, "rb") as f:
        return pickle.load(f)


def logsumexp(values):
    maximum = np.max(values)

    if not np.isfinite(maximum):
        return maximum

    return maximum + np.log(
        np.sum(np.exp(values - maximum))
    )


def prepare_model(model):
    """
    Convert the HMM probabilities to log probabilities once.
    """

    tiny = np.finfo(np.float64).tiny

    A = np.asarray(
        model["transition_matrix"],
        dtype=np.float64,
    )

    B = np.asarray(
        model["emission_matrix"],
        dtype=np.float64,
    )

    pi = np.asarray(
        model["initial_probabilities"],
        dtype=np.float64,
    )

    return {
        "log_A": np.log(np.maximum(A, tiny)),
        "log_B": np.log(np.maximum(B, tiny)),
        "log_pi": np.log(np.maximum(pi, tiny)),
        "states": model["states"],
    }


def forward_backward(observations, model):
    """
    Vectorized forward-backward algorithm.

    Returns:
        log P(X | model)
        posterior[state_t | X, model]
    """

    observations = np.asarray(
        observations,
        dtype=np.int64,
    )

    if len(observations) == 0:
        raise ValueError("Observation sequence is empty.")

    log_A = model["log_A"]
    log_B = model["log_B"]
    log_pi = model["log_pi"]

    length = len(observations)
    n_states = len(log_pi)

    # ---------------------------------------------------------
    # FORWARD
    # ---------------------------------------------------------

    alpha = np.empty(
        (length, n_states),
        dtype=np.float64,
    )

    alpha[0] = (
        log_pi
        + log_B[:, observations[0]]
    )

    for t in range(1, length):
        # Shape:
        #   alpha[t-1, :, None] -> (states, 1)
        #   log_A              -> (states, states)
        #
        # Result contains every source -> destination score.
        scores = (
            alpha[t - 1, :, None]
            + log_A
        )

        # Stable log-sum-exp over source states.
        maximum = np.max(
            scores,
            axis=0,
        )

        summed = maximum + np.log(
            np.sum(
                np.exp(
                    scores - maximum
                ),
                axis=0,
            )
        )

        alpha[t] = (
            summed
            + log_B[:, observations[t]]
        )

    log_likelihood = (
        np.max(alpha[-1])
        + np.log(
            np.sum(
                np.exp(
                    alpha[-1]
                    - np.max(alpha[-1])
                )
            )
        )
    )

    # ---------------------------------------------------------
    # BACKWARD
    # ---------------------------------------------------------

    beta = np.empty(
        (length, n_states),
        dtype=np.float64,
    )

    beta[-1] = 0.0

    for t in range(length - 2, -1, -1):

        scores = (
            log_A
            + log_B[:, observations[t + 1]][None, :]
            + beta[t + 1][None, :]
        )

        maximum = np.max(
            scores,
            axis=1,
        )

        beta[t] = (
            maximum
            + np.log(
                np.sum(
                    np.exp(
                        scores - maximum[:, None]
                    ),
                    axis=1,
                )
            )
        )

    # ---------------------------------------------------------
    # POSTERIOR
    # ---------------------------------------------------------

    log_posterior = alpha + beta

    normalization = np.max(
        log_posterior,
        axis=1,
        keepdims=True,
    )

    posterior = np.exp(
        log_posterior
        - normalization
    )

    posterior /= posterior.sum(
        axis=1,
        keepdims=True,
    )

    return log_likelihood, posterior

def load_sequences(path):
    with open(path, "r") as f:
        return json.load(f)


def score_sequence(
    sequence,
    benign_model,
    malicious_model,
):
    observations = sequence["observations"]

    benign_log_likelihood, benign_posterior = (
        forward_backward(
            observations,
            benign_model,
        )
    )

    malicious_log_likelihood, malicious_posterior = (
        forward_backward(
            observations,
            malicious_model,
        )
    )

    likelihood_ratio = (
        malicious_log_likelihood
        - benign_log_likelihood
    )

    return {
        "name": sequence["name"],

        "benign_log_likelihood":
            benign_log_likelihood,

        "malicious_log_likelihood":
            malicious_log_likelihood,

        "likelihood_ratio":
            likelihood_ratio,

        "benign_posterior":
            benign_posterior,

        "malicious_posterior":
            malicious_posterior,
    }


def print_state_summary(
    posterior,
    states,
):
    """
    Print the most likely hidden state at each
    byte position.

    This is mainly for debugging and understanding.
    """

    most_likely = np.argmax(
        posterior,
        axis=1,
    )

    print()
    print("Most likely states:")

    for position, state_id in enumerate(
        most_likely
    ):
        probability = posterior[
            position,
            state_id,
        ]

        print(
            f"  byte {position:4d}: "
            f"{states[state_id]:7s} "
            f"P={probability:.4f}"
        )


def main():

    parser = argparse.ArgumentParser(
        description=(
            "Score PE sequences using the "
            "ROPminer HMMs."
        )
    )

    parser.add_argument(
        "sequence",
        type=Path,
        help="JSON sequence file",
    )

    parser.add_argument(
        "--benign",
        default="models/hmm_ben.pkl",
        help="Benign HMM",
    )

    parser.add_argument(
        "--malicious",
        default="models/hmm_mal.pkl",
        help="Malicious HMM",
    )

    parser.add_argument(
        "--show-states",
        action="store_true",
        help=(
            "Show the most likely hidden state "
            "for every byte"
        ),
    )

    args = parser.parse_args()

    # ---------------------------------------------------------
    # Load models
    # ---------------------------------------------------------

    benign_raw = load_model(
        args.benign
    )

    malicious_raw = load_model(
        args.malicious
    )

    benign_model = prepare_model(
        benign_raw
    )

    malicious_model = prepare_model(
        malicious_raw
    )

    # ---------------------------------------------------------
    # Load sequences
    # ---------------------------------------------------------

    sequences = load_sequences(
        args.sequence
    )

    print(
        f"Sequences: {len(sequences)}"
    )

    print()

    scores = []

    for sequence in sequences:

        result = score_sequence(
            sequence,
            benign_model,
            malicious_model,
        )

        score = result[
            "likelihood_ratio"
        ]

        scores.append(score)

        print(
            f"{sequence['name']:35s} "
            f"Z={score:.3f}"
        )

        if args.show_states:

            print_state_summary(
                result[
                    "malicious_posterior"
                ],
                malicious_model["states"],
            )

    # ---------------------------------------------------------
    # Summary
    # ---------------------------------------------------------

    if scores:

        print()
        print(
            "================================"
        )

        print(
            f"Min Z:  {min(scores):.3f}"
        )

        print(
            f"Max Z:  {max(scores):.3f}"
        )

        print(
            f"Mean Z: {np.mean(scores):.3f}"
        )

        print(
            "================================"
        )


if __name__ == "__main__":
    main()
