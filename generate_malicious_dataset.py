import json
import re
import subprocess
from pathlib import Path

BASE_DIR = Path.home() / "ropminer"

INPUT_DIR = BASE_DIR / "dataset" / "injector_targets"
OUTPUT_DIR = BASE_DIR / "dataset" / "malicious"
SHELLCODE = Path("/tmp/test_shellcode.txt")
MANIFEST = OUTPUT_DIR / "generation_manifest.json"

ROPINJECTOR = BASE_DIR / "ROPInjector" / "Release" / "ropinjector.exe"

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# Controlled development payload:
# NOP, NOP, RET
SHELLCODE.write_text(r"\x90\x90\xc3")

targets = sorted(
    p for p in INPUT_DIR.iterdir()
    if p.is_file() and p.suffix.lower() == ".exe"
)

if len(targets) != 100:
    raise RuntimeError(
        f"Expected exactly 100 injector targets, found {len(targets)}"
    )

results = []

print(f"ROPInjector: {ROPINJECTOR}")
print(f"Targets:     {len(targets)}")
print(f"Payload:     inert NOP/NOP/RET")
print()

for i, source in enumerate(targets, 1):
    output = OUTPUT_DIR / f"malicious_{i:03d}.exe"

    if output.exists():
        raise RuntimeError(
            f"Refusing to overwrite existing file: {output}"
        )

    print(f"[{i:03d}/100] {source.name}")

    command = [
        str(ROPINJECTOR),
        str(source),
        str(SHELLCODE),
        str(output),
        "text",
    ]

    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
    )

    stdout = completed.stdout
    stderr = completed.stderr

    # ROPInjector prints its final statistics on a line beginning with
    # [+] "source" patched successfully...
    success = (
        completed.returncode == 0
        and output.exists()
        and output.stat().st_size > 0
        and "patched successfully" in stdout
    )

    result = {
        "index": i,
        "source": str(source),
        "output": str(output),
        "payload": "inert_test_shellcode",
        "returncode": completed.returncode,
        "success": success,
        "output_size": output.stat().st_size if output.exists() else None,
        "stdout": stdout,
        "stderr": stderr,
    }

    results.append(result)

    if not success:
        with open(MANIFEST, "w") as f:
            json.dump(results, f, indent=4)

        raise RuntimeError(
            f"Injection failed for {source.name}. "
            f"See {MANIFEST}"
        )

print()
print("All 100 injections completed successfully.")

with open(MANIFEST, "w") as f:
    json.dump(results, f, indent=4)

print(f"Manifest saved to: {MANIFEST}")
