import json


RESULTS = "dataset/final_rci_results.json"


def calculate_metrics(data, threshold):
    tp = tn = fp = fn = 0

    for sample in data:
        prediction = int(
            sample["malicious_violations"] >= threshold
        )

        label = sample["label"]

        if label == 1 and prediction == 1:
            tp += 1
        elif label == 0 and prediction == 0:
            tn += 1
        elif label == 0 and prediction == 1:
            fp += 1
        elif label == 1 and prediction == 0:
            fn += 1

    accuracy = (
        (tp + tn) / len(data)
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


def main():

    with open(RESULTS) as f:
        data = json.load(f)

    print("=" * 50)
    print("FINAL ROPMINER RESULTS")
    print("=" * 50)

    print()
    print("Dataset")
    print("-------")
    print("Total:    ", len(data))
    print(
        "Benign:   ",
        sum(x["label"] == 0 for x in data),
    )
    print(
        "Malicious:",
        sum(x["label"] == 1 for x in data),
    )

    print()
    print("RCI THRESHOLDS")
    print("-------------")

    for threshold in range(1, 5):

        m = calculate_metrics(
            data,
            threshold,
        )

        print()
        print(
            f"Threshold >= {threshold}"
        )

        print(
            f"  TP:        {m['tp']}"
        )
        print(
            f"  TN:        {m['tn']}"
        )
        print(
            f"  FP:        {m['fp']}"
        )
        print(
            f"  FN:        {m['fn']}"
        )
        print(
            f"  Accuracy:  {m['accuracy']:.4f}"
        )
        print(
            f"  Precision: {m['precision']:.4f}"
        )
        print(
            f"  Recall:    {m['recall']:.4f}"
        )
        print(
            f"  F1:        {m['f1']:.4f}"
        )

    best = calculate_metrics(
        data,
        1,
    )

    print()
    print("=" * 50)
    print("OFFICIAL CONFIGURATION")
    print("=" * 50)

    print(
        "RCI threshold: >= 1 violation"
    )

    print(
        f"TP:        {best['tp']}"
    )
    print(
        f"TN:        {best['tn']}"
    )
    print(
        f"FP:        {best['fp']}"
    )
    print(
        f"FN:        {best['fn']}"
    )
    print(
        f"Accuracy:  {best['accuracy']:.4%}"
    )
    print(
        f"Precision: {best['precision']:.4%}"
    )
    print(
        f"Recall:    {best['recall']:.4%}"
    )
    print(
        f"F1:        {best['f1']:.4%}"
    )


if __name__ == "__main__":
    main()
