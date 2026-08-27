import json
import re
import struct
from pathlib import Path


STATES = [
    "addr1", "addr2", "addr3", "addr4",
    "const1", "const2", "const3", "const4",
    "junk", "data", "EOF"
]


def parse_patch_info(stdout):
    """
    Extract the injected patch file offset and size
    from ROPInjector output.
    """

    size_match = re.search(
        r"Final patch is (\d+) bytes long",
        stdout,
    )

    offset_match = re.search(
        r"file offset:0x([0-9A-Fa-f]+)",
        stdout,
    )

    if not size_match or not offset_match:
        raise ValueError(
            "Could not find patch size/offset in ROPInjector output"
        )

    return (
        int(offset_match.group(1), 16),
        int(size_match.group(1)),
    )


def parse_gadget_addresses(stdout):
    """
    Extract gadget addresses from ROPInjector's
    generated 'push XXXXXXXX' instructions.
    """

    addresses = []

    for match in re.finditer(
        r"\bpush\s+([0-9A-Fa-f]{8})\b",
        stdout,
    ):
        address = int(match.group(1), 16)

        if address not in addresses:
            addresses.append(address)

    return addresses


def label_malicious(sample, stdout):
    """
    Label the bytes of a malicious PE.

    The injected patch starts at the file offset reported
    by ROPInjector.

    Gadget addresses found in the ROPInjector output are
    labeled as:

        addr1 addr2 addr3 addr4

    Everything else inside the patch is junk.
    """

    path = Path(sample)
    data = bytearray(path.read_bytes())

    patch_offset, patch_size = parse_patch_info(stdout)

    patch_end = min(
        patch_offset + patch_size,
        len(data),
    )

    states = ["data"] * len(data)

    # The injected patch is initially junk.
    for i in range(patch_offset, patch_end):
        states[i] = "junk"

    # Recover gadget addresses from ROPInjector output.
    addresses = parse_gadget_addresses(stdout)

    for address in addresses:

        address_bytes = struct.pack(
            "<I",
            address,
        )

        # Search only inside the injected patch.
        for i in range(
            patch_offset,
            patch_end - 3,
        ):

            if data[i:i + 4] == address_bytes:

                states[i] = "addr1"
                states[i + 1] = "addr2"
                states[i + 2] = "addr3"
                states[i + 3] = "addr4"

    observations = list(data)

    # EOF terminal observation.
    observations.append(0)
    states.append("EOF")

    return observations, states


def label_benign(path):
    data = path.read_bytes()

    observations = list(data)
    states = ["data"] * len(data)

    observations.append(0)
    states.append("EOF")

    return observations, states


def main():

    manifest_path = Path(
        "dataset/malicious/generation_manifest.json"
    )

    with open(manifest_path) as f:
        manifest = json.load(f)

    malicious_sequences = []

    print("=== MALICIOUS SEQUENCES ===")

    for entry in manifest:

        if not entry["success"]:
            continue

        observations, states = label_malicious(
            entry["output"],
            entry["stdout"],
        )

        malicious_sequences.append({
            "name": Path(entry["output"]).name,
            "observations": observations,
            "states": states,
            "payload_name": entry["payload_name"],
            "payload_group": entry["payload_group"],
        })

        counts = {
            state: states.count(state)
            for state in STATES
            if state in states
        }

        print(
            f"{entry['index']:03d} "
            f"{Path(entry['output']).name:25s} "
            f"{entry['payload_name']:35s} "
            f"addr_bytes="
            f"{sum(1 for s in states if s.startswith('addr')):3d} "
            f"junk={counts.get('junk', 0):3d}"
        )

    benign_sequences = []

    print()
    print("=== BENIGN SEQUENCES ===")

    benign_dir = Path("dataset/benign")

    for path in sorted(benign_dir.iterdir()):

        if not path.is_file():
            continue

        observations, states = label_benign(path)

        benign_sequences.append({
            "name": path.name,
            "observations": observations,
            "states": states,
        })

    print()
    print(
        f"Benign sequences:    "
        f"{len(benign_sequences)}"
    )

    print(
        f"Malicious sequences: "
        f"{len(malicious_sequences)}"
    )

    if len(benign_sequences) != 100:
        raise RuntimeError(
            f"Expected 100 benign sequences, "
            f"found {len(benign_sequences)}"
        )

    if len(malicious_sequences) != 100:
        raise RuntimeError(
            f"Expected 100 malicious sequences, "
            f"found {len(malicious_sequences)}"
        )

    output_dir = Path("dataset/hmm")
    output_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    with open(
        output_dir / "benign_sequences.json",
        "w",
    ) as f:
        json.dump(
            benign_sequences,
            f,
        )

    with open(
        output_dir / "malicious_sequences.json",
        "w",
    ) as f:
        json.dump(
            malicious_sequences,
            f,
        )

    print()
    print("Saved:")
    print(
        " ",
        output_dir / "benign_sequences.json",
    )
    print(
        " ",
        output_dir / "malicious_sequences.json",
    )


if __name__ == "__main__":
    main()
