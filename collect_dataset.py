import os
import shutil
import pefile

SOURCE_DIR = "/mnt/c/Windows/SysWOW64"
DEST_DIR = "dataset/benign"

MAX_FILES = 100


def is_pe32(filepath):
    try:
        pe = pefile.PE(filepath)

        # Ignore 64-bit binaries
        if pe.PE_TYPE != pefile.OPTIONAL_HEADER_MAGIC_PE:
            return False

        return True

    except Exception:
        return False


def main():

    os.makedirs(DEST_DIR, exist_ok=True)

    collected = 0
    seen = set()

    for root, _, files in os.walk(SOURCE_DIR):

        for filename in files:

            if collected >= MAX_FILES:
                break

            if not (
                filename.lower().endswith(".exe")
                or filename.lower().endswith(".dll")
            ):
                continue

            src = os.path.join(root, filename)

            if not is_pe32(src):
                continue

            # Avoid duplicate filenames
            if filename.lower() in seen:
                continue

            seen.add(filename.lower())

            dst = os.path.join(DEST_DIR, filename)

            shutil.copy2(src, dst)

            collected += 1

            print(f"[{collected:3}] {filename}")

        if collected >= MAX_FILES:
            break

    print()
    print(f"Collected {collected} PE32 binaries.")


if __name__ == "__main__":
    main()
