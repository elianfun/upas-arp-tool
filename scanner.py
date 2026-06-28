"""
Phase 1: ARP Scanner + Continuous Monitor
"""
import time
import threading
from datetime import datetime
from scapy.all import ARP, Ether, srp, sniff, conf


def scan_network(subnet: str, interface: str) -> list[dict]:
    """Send broadcast ARP request, return list of {ip, mac} dicts."""
    conf.verb = 0
    arp = ARP(pdst=subnet)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    result = srp(ether / arp, timeout=3, iface=interface, verbose=False)[0]
    devices = []
    for _, received in result:
        devices.append({
            "ip": received.psrc,
            "mac": received.hwsrc.upper(),
            "first_seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        })
    return devices


def print_devices(devices: list[dict]) -> None:
    print(f"\n{'IP Address':<18} {'MAC Address':<20} {'First Seen'}")
    print("-" * 62)
    for d in devices:
        print(f"{d['ip']:<18} {d['mac']:<20} {d.get('first_seen', '-')}")
    print(f"\nTotal: {len(devices)} device(s)")


class ARPMonitor:
    """Sniff ARP traffic and alert on new/unknown devices."""

    def __init__(self, interface: str, known_macs: set[str], on_new_device):
        self.interface = interface
        self.known_macs = known_macs
        self.on_new_device = on_new_device
        self._stop = threading.Event()

    def _process(self, pkt):
        if pkt.haslayer(ARP) and pkt[ARP].op == 1:  # ARP Who-has
            mac = pkt[ARP].hwsrc.upper()
            ip = pkt[ARP].psrc
            if mac not in self.known_macs and ip != "0.0.0.0":
                self.known_macs.add(mac)
                self.on_new_device(ip, mac)

    def start(self):
        print(f"[MONITOR] Listening on {self.interface} ... (Ctrl+C to stop)")
        sniff(
            iface=self.interface,
            filter="arp",
            prn=self._process,
            store=False,
            stop_filter=lambda _: self._stop.is_set(),
        )

    def stop(self):
        self._stop.set()
