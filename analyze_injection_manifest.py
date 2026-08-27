import json
import re
from pathlib import Path

MANIFEST = Path("dataset/malicious/generation_manifest.json")


def parse_stats(stdout):
    result = {}

    match = re.search(
        r"Final patch is (\d+) bytes long",
        stdout,
    )
    if match:
        result["patch_size"] = int(match.group(1))

    match = re.search(
        r"Patch will be written @ RVA:0x([0-9a-fA-F]+), "
        r"file offset:0x([0-9a-fA-F]+)",
        stdout,
    )
    if match:
        result["patch_rva"] = int(match.group(1), 16)
        result["patch_file_offset"] = int(match.group(2), 16)

    match = re.search(
        r"Replaced (\d+)/(\d+) instructions in (\d+) segments",
        stdout,
    )
    if match:
        result["replaced_instructions"] = int(match.group(1))
        result["total_instructions"] = int(match.group(2))
        result["rop_segments"] = int(match.group(3))

    match = re.search(
        r"(\d+)/(\d+) replacements achieved by (\d+) injected gadgets",
        stdout,
    )
    if match:
        result["successful_replacements"] = int(match.group(1))
        result["replacement_total"] = int(match.group(2))
        result["injected_gadgets"] = int(match.group(3))

    match = re.search(
        r"Shellcode consists of (\d+) instructions",
        stdout,
    )
    if match:
        result["shellcode_instructions"] = int(match.group(1))

    return result


def main():
    with open(MANIFEST) as f:
        manifest = json.load(f)

    records = []

    for entry in manifest:
        stats = parse_stats(entry["stdout"])

        records.append({
            "index": entry["index"],
            "source": entry["source"],
            "output": entry["output"],
            "success": entry["success"],
            **stats,
        })

    output = Path("dataset/malicious/injection_metadata.json")

    with open(output, "w") as f:
        json.dump(records, f, indent=2)

    print(f"Processed: {len(records)} samples")
    print(f"Saved:     {output}")

    sizes = [
        r["patch_size"]
        for r in records
        if "patch_size" in r
    ]

    gadgets = [
        r["injected_gadgets"]
        for r in records
        if "injected_gadgets" in r
    ]

    print()
    print("=== PATCH SIZE ===")
    print("min:", min(sizes))
    print("max:", max(sizes))
    print("avg:", sum(sizes) / len(sizes))

    print()
    print("=== INJECTED GADGETS ===")

    from collections import Counter
    print(Counter(gadgets))

    print()
    print("=== FIRST 10 PATCHES ===")

    for r in records[:10]:
        print(
            f"{r['index']:03d}: "
            f"RVA={r.get('patch_rva', '?'):#x} "
            f"offset={r.get('patch_file_offset', '?'):#x} "
            f"size={r.get('patch_size', '?')}"
        )


if __name__ == "__main__":
    main()
