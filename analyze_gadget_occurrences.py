import json
import struct
from pathlib import Path


GADGET_DB = Path("gadgets_dict.json")

DATASETS = {
    "benign": Path("dataset/benign"),
    "malicious": Path("dataset/malicious"),
}


def load_gadgets():
    with open(GADGET_DB) as f:
        data = json.load(f)

    return {
        int(address, 16)
        for address in data
    }


def find_occurrences(data, gadget_addresses):
    matches = []

    for i in range(len(data) - 3):
        address = struct.unpack_from("<I", data, i)[0]

        if address in gadget_addresses:
            matches.append((i, address))

    return matches


def main():
    gadgets = load_gadgets()

    print(f"Known gadget addresses: {len(gadgets)}")
    print()

    for dataset_name, directory in DATASETS.items():

        files = sorted(
            p for p in directory.iterdir()
            if p.is_file()
            and p.suffix.lower() in {".exe", ".dll"}
        )

        total_matches = 0
        files_with_matches = 0

        print(f"=== {dataset_name.upper()} ===")

        for path in files:
            data = path.read_bytes()

            matches = find_occurrences(data, gadgets)

            if matches:
                files_with_matches += 1
                total_matches += len(matches)

            print(
                f"{path.name:45s} "
                f"{len(matches):6d} matches"
            )

        print()
        print(f"Files:              {len(files)}")
        print(f"Files with matches: {files_with_matches}")
        print(f"Total matches:      {total_matches}")
        print()


if __name__ == "__main__":
    main()
