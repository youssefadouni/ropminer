import json

from miner import gadgets
from emulator import emulate

database = []

total = len(gadgets)

print(f"\nProcessing {total} gadgets...\n")

for i, gadget in enumerate(gadgets):

    print(f"[{i+1}/{total}] {hex(gadget['address'])}")

    result = emulate(gadget["bytes"])

    database.append({
        "address": hex(gadget["address"]),
        "instructions": gadget["instructions"],
        "stack_delta": result["stack_delta"] if result["success"] else None,
        "success": result["success"],
        "error": result["error"],
        "instructions_executed": result["instructions_executed"]
    })

with open("gadgets_dict.json", "w") as f:
    json.dump(database, f, indent=4)

print("\n===================================")
print("Finished!")
print(f"Saved {len(database)} gadgets.")
print("Output file: gadgets_dict.json")
