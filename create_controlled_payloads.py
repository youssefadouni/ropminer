from pathlib import Path

OUT = Path("dataset/payloads")
OUT.mkdir(parents=True, exist_ok=True)

payloads = {
    "windows_exec": bytes.fromhex(
        "90 90 90 90 C3"
    ),

    "windows_meterpreter_reverse_tcp": bytes.fromhex(
        "90 90 91 91 C3"
    ),

    "windows_shell_bind_tcp": bytes.fromhex(
        "90 90 92 92 C3"
    ),

    "windows_messagebox": bytes.fromhex(
        "90 90 93 93 C3"
    ),

    "windows_download_exec": bytes.fromhex(
        "90 90 95 95 C3"
    ),
}

for name, data in payloads.items():
    path = OUT / f"{name}.bin"
    path.write_bytes(data)
    print(f"{name:35s} {len(data):3d} bytes -> {path}")

print()
print(f"Created {len(payloads)} controlled payloads.")
