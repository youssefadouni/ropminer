import json
import subprocess
from pathlib import Path


BASE = Path.home() / "ropminer"

INPUT_DIR = BASE / "dataset" / "injector_targets"
OUTPUT_DIR = BASE / "dataset" / "malicious"
PAYLOAD_DIR = BASE / "dataset" / "payloads"

ROPINJECTOR = (
    BASE / "ROPInjector" / "Release" / "ropinjector.exe"
)

MANIFEST = OUTPUT_DIR / "generation_manifest.json"


PAYLOADS = [
    ("windows_exec", PAYLOAD_DIR / "windows_exec.bin"),
    (
        "windows_meterpreter_reverse_tcp",
        PAYLOAD_DIR / "windows_meterpreter_reverse_tcp.bin",
    ),
    (
        "windows_shell_bind_tcp",
        PAYLOAD_DIR / "windows_shell_bind_tcp.bin",
    ),
    (
        "windows_messagebox",
        PAYLOAD_DIR / "windows_messagebox.bin",
    ),
    (
        "windows_download_exec",
        PAYLOAD_DIR / "windows_download_exec.bin",
    ),
]


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    targets = sorted(
        p for p in INPUT_DIR.iterdir()
        if p.is_file() and p.suffix.lower() == ".exe"
    )

    if len(targets) != 100:
        raise RuntimeError(
            f"Expected 100 injector targets, found {len(targets)}"
        )

    for name, payload in PAYLOADS:
        if not payload.exists():
            raise RuntimeError(
                f"Missing payload: {payload}"
            )

    if not ROPINJECTOR.exists():
        raise RuntimeError(
            f"ROPInjector not found: {ROPINJECTOR}"
        )

    existing = list(
        OUTPUT_DIR.glob("malicious_*.exe")
    )

    if existing:
        raise RuntimeError(
            "dataset/malicious already contains output files. "
            "Refusing to overwrite them."
        )

    manifest = []

    print("==============================================")
    print("CONTROLLED MALICIOUS DATASET GENERATION")
    print("==============================================")
    print(f"Targets:    {len(targets)}")
    print(f"Payloads:   {len(PAYLOADS)}")
    print("Per class:  20")
    print()

    index = 0

    for payload_index, (payload_name, payload_path) in enumerate(
        PAYLOADS,
        start=1,
    ):
        print(
            f"--- Payload {payload_index}/5: "
            f"{payload_name} ---"
        )

        group = targets[index:index + 20]

        for local_index, source in enumerate(group, start=1):
            global_index = index + local_index

            output = (
                OUTPUT_DIR
                / f"malicious_{global_index:03d}.exe"
            )

            print(
                f"[{global_index:03d}/100] "
                f"{source.name} -> {output.name}"
            )

            command = [
                str(ROPINJECTOR),
                str(source),
                str(payload_path),
                str(output),
            ]

            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
            )

            stdout = completed.stdout
            stderr = completed.stderr

            success = (
                completed.returncode == 0
                and output.exists()
                and output.stat().st_size > 0
                and "patched successfully" in stdout
            )

            result = {
                "index": global_index,
                "payload_group": payload_index,
                "payload_name": payload_name,
                "payload_file": str(payload_path),
                "source": str(source),
                "output": str(output),
                "returncode": completed.returncode,
                "success": success,
                "output_size": (
                    output.stat().st_size
                    if output.exists()
                    else None
                ),
                "stdout": stdout,
                "stderr": stderr,
            }

            manifest.append(result)

            if not success:
                with open(MANIFEST, "w") as f:
                    json.dump(
                        manifest,
                        f,
                        indent=4,
                    )

                raise RuntimeError(
                    f"Injection failed for {source.name}. "
                    f"See {MANIFEST}"
                )

        index += 20
        print()

    with open(MANIFEST, "w") as f:
        json.dump(
            manifest,
            f,
            indent=4,
        )

    print("==============================================")
    print("DATASET GENERATION COMPLETE")
    print("==============================================")
    print("Total:      100")
    print("Successful: 100")
    print(f"Manifest:   {MANIFEST}")


if __name__ == "__main__":
    main()
