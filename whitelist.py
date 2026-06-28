"""
Phase 2: Whitelist manager (whitelist.json)
"""
import json
import os
from typing import Optional

WHITELIST_FILE = os.path.join(os.path.dirname(__file__), "whitelist.json")


def _load() -> dict:
    if not os.path.exists(WHITELIST_FILE):
        return {"whitelist": []}
    with open(WHITELIST_FILE, "r") as f:
        return json.load(f)


def _save(data: dict) -> None:
    with open(WHITELIST_FILE, "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"[WHITELIST] Saved to {WHITELIST_FILE}")


def load_whitelist() -> list[dict]:
    return _load().get("whitelist", [])


def is_whitelisted(mac: str) -> bool:
    return any(e["mac"].upper() == mac.upper() for e in load_whitelist())


def add_entry(ip: str, mac: str, note: str = "") -> None:
    data = _load()
    mac = mac.upper()
    for entry in data["whitelist"]:
        if entry["mac"].upper() == mac:
            print(f"[WHITELIST] {mac} already in whitelist.")
            return
    data["whitelist"].append({"ip": ip, "mac": mac, "note": note})
    _save(data)
    print(f"[WHITELIST] Added: {ip} / {mac} ({note})")


def remove_entry(mac: str) -> bool:
    data = _load()
    before = len(data["whitelist"])
    data["whitelist"] = [e for e in data["whitelist"] if e["mac"].upper() != mac.upper()]
    if len(data["whitelist"]) < before:
        _save(data)
        print(f"[WHITELIST] Removed: {mac}")
        return True
    print(f"[WHITELIST] {mac} not found.")
    return False


def print_whitelist() -> None:
    entries = load_whitelist()
    if not entries:
        print("[WHITELIST] Empty.")
        return
    print(f"\n{'IP Address':<18} {'MAC Address':<20} Note")
    print("-" * 60)
    for e in entries:
        print(f"{e['ip']:<18} {e['mac']:<20} {e.get('note', '')}")
    print(f"\nTotal: {len(entries)} entry/entries")


def interactive_manage(scanned_devices: Optional[list[dict]] = None) -> None:
    """Interactive CLI for whitelist management."""
    while True:
        print("\n[WHITELIST MANAGER]")
        print("  1) List whitelist")
        print("  2) Add entry (manual)")
        if scanned_devices:
            print("  3) Add from last scan")
        print("  r) Remove entry")
        print("  q) Quit")
        choice = input("Choice: ").strip().lower()

        if choice == "1":
            print_whitelist()

        elif choice == "2":
            ip = input("  IP: ").strip()
            mac = input("  MAC (AA:BB:CC:DD:EE:FF): ").strip()
            note = input("  Note (optional): ").strip()
            add_entry(ip, mac, note)

        elif choice == "3" and scanned_devices:
            print("\nScanned devices:")
            for i, d in enumerate(scanned_devices):
                star = "*" if is_whitelisted(d["mac"]) else " "
                print(f"  {i+1}) {star} {d['ip']:<18} {d['mac']}")
            sel = input("Enter number(s) to add (comma-separated): ").strip()
            for s in sel.split(","):
                s = s.strip()
                if s.isdigit():
                    idx = int(s) - 1
                    if 0 <= idx < len(scanned_devices):
                        d = scanned_devices[idx]
                        note = input(f"  Note for {d['ip']}: ").strip()
                        add_entry(d["ip"], d["mac"], note)

        elif choice == "r":
            mac = input("  MAC to remove: ").strip()
            remove_entry(mac)

        elif choice == "q":
            break
