#!/usr/bin/env python3
"""
UPAS ARP Enforcement Tool
Usage: sudo python3 upas_tool.py --help
"""
import argparse
import sys

from scanner import scan_network, print_devices, ARPMonitor
from whitelist import (
    load_whitelist,
    add_entry,
    print_whitelist,
    interactive_manage,
    is_whitelisted,
)
from enforcer import enforce_single, enforce_all_illegal, _resolve_mac


def cmd_scan(args):
    print(f"[SCAN] Scanning {args.subnet} on {args.interface} ...")
    devices = scan_network(args.subnet, args.interface)
    print_devices(devices)

    if args.monitor:
        known_macs = {d["mac"] for d in devices}
        wl_macs = {e["mac"] for e in load_whitelist()}

        def on_new(ip, mac):
            tag = "[WHITELISTED]" if mac.upper() in {m.upper() for m in wl_macs} else "[UNKNOWN !!]"
            print(f"[{tag}] New device: {ip}  {mac}")

        monitor = ARPMonitor(args.interface, known_macs, on_new)
        try:
            monitor.start()
        except KeyboardInterrupt:
            print("\n[MONITOR] Stopped.")


def cmd_manage(args):
    scanned = None
    if args.subnet:
        print(f"[SCAN] Scanning {args.subnet} on {args.interface} before manage ...")
        scanned = scan_network(args.subnet, args.interface)
        print_devices(scanned)
    interactive_manage(scanned_devices=scanned)


def cmd_enforce(args):
    wl_entries = load_whitelist()
    if not wl_entries:
        print("[WARN] Whitelist is empty — all devices would be treated as illegal.")
        confirm = input("Continue? [y/N]: ").strip().lower()
        if confirm != "y":
            sys.exit(0)

    wl_macs = {e["mac"].upper() for e in wl_entries}

    if args.target_ip and args.target_mac:
        # Block a specific device
        print(f"[ENFORCE] Resolving gateway {args.gateway} ...")
        gw_mac = _resolve_mac(args.gateway, args.interface)
        enforce_single(
            illegal_ip=args.target_ip,
            illegal_mac=args.target_mac.upper(),
            gateway_ip=args.gateway,
            gateway_mac=gw_mac,
            interface=args.interface,
            interval=args.interval,
        )
    else:
        # Scan first, block everything not in whitelist
        if not args.subnet:
            print("[ERROR] Provide --subnet for auto-scan mode, or --target-ip + --target-mac for single-target mode.")
            sys.exit(1)
        print(f"[SCAN] Scanning {args.subnet} on {args.interface} ...")
        from scanner import scan_network as _scan
        devices = _scan(args.subnet, args.interface)
        print_devices(devices)
        enforce_all_illegal(
            scanned_devices=devices,
            whitelist_macs=wl_macs,
            gateway_ip=args.gateway,
            interface=args.interface,
            interval=args.interval,
        )


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="upas_tool.py",
        description="UPAS: ARP-based network access enforcement tool (home lab)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan subnet and show devices
  sudo python3 upas_tool.py --scan --interface eth0 --subnet 192.168.1.0/24

  # Scan + continuously monitor for new devices
  sudo python3 upas_tool.py --scan --monitor --interface eth0 --subnet 192.168.1.0/24

  # Interactive whitelist management (with pre-scan)
  sudo python3 upas_tool.py --manage --interface eth0 --subnet 192.168.1.0/24

  # Enforce: block all devices not in whitelist (auto-scan)
  sudo python3 upas_tool.py --enforce --interface eth0 --subnet 192.168.1.0/24 --gateway 192.168.1.1

  # Enforce: block a specific device
  sudo python3 upas_tool.py --enforce --interface eth0 --gateway 192.168.1.1 \\
      --target-ip 192.168.1.50 --target-mac AA:BB:CC:DD:EE:FF --interval 30
        """,
    )

    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument("--scan", action="store_true", help="Scan subnet for live devices")
    mode.add_argument("--manage", action="store_true", help="Interactive whitelist management")
    mode.add_argument("--enforce", action="store_true", help="ARP enforcement mode")

    p.add_argument("--interface", "-i", required=True, help="Network interface (e.g. eth0, ens18)")
    p.add_argument("--subnet", "-s", help="Target subnet (e.g. 192.168.1.0/24)")
    p.add_argument("--gateway", "-g", help="Gateway IP address")
    p.add_argument("--interval", type=int, default=30, help="Refresh interval in seconds (default: 30)")
    p.add_argument("--monitor", "-m", action="store_true", help="Continuous monitor after scan")
    p.add_argument("--target-ip", help="Single target IP to block (enforce mode)")
    p.add_argument("--target-mac", help="Single target MAC to block (enforce mode)")

    return p


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.enforce and not args.gateway:
        parser.error("--enforce requires --gateway")

    if args.scan:
        if not args.subnet:
            parser.error("--scan requires --subnet")
        cmd_scan(args)
    elif args.manage:
        cmd_manage(args)
    elif args.enforce:
        cmd_enforce(args)


if __name__ == "__main__":
    main()
