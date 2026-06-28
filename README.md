# UPAS ARP Enforcement Tool

Home lab network access control via ARP spoofing — Python 3 + Scapy + Flask Web UI.

Replicates the core enforcement mechanism of UPAS (網路行為管控系統) using reactive ARP poisoning to isolate unauthorized devices on a LAN segment.

---

## Features

- **ARP Scan** — discover all live devices on a subnet
- **Continuous Monitor** — sniff ARP traffic, alert on new/unknown devices
- **Whitelist Management** — JSON-based allowlist, interactive CLI or Web UI
- **Reactive Enforcement** — sniffer-based ARP poisoning triggered only when traffic is detected, not brute-force broadcast
- **Hot Whitelist Reload** — changes to `whitelist.json` take effect within 3 seconds, no restart needed
- **Peer expiry** — watched peers removed automatically after inactivity (no endless re-poisoning)
- **Target offline detection** — stops sending packets when blocked device goes offline, resumes on reconnect
- **Web UI** — single-page Flask dashboard with live log streaming (SSE)
- **Clean Cleanup** — Ctrl-C or Web UI stop button restores all ARP entries immediately

---

## Architecture

```
upas_tool.py        ← CLI entry point (argparse, --scan / --manage / --enforce)
├── scanner.py      ← ARP broadcast scan + AsyncSniffer monitor
├── whitelist.py    ← whitelist.json CRUD
└── enforcer.py     ← Unicast ARP spoof / restore primitives

web_ui.py           ← Flask REST API + SSE log stream
└── templates/
    └── index.html  ← Single-page dark-theme UI (Bootstrap 5, vanilla JS)
```

### Enforcement Design

```
ARP Sniffer (always running)
  │
  ├─ [who-has ILLEGAL_IP?] from any device
  │     └─ immediate unicast poison reply to that device
  │        → add device to watch list
  │
  ├─ [who-has X?] from ILLEGAL_IP
  │     └─ immediate poison reply to illegal device
  │
  └─ [Gratuitous ARP] from ILLEGAL_IP (real MAC broadcast)
        └─ counter broadcast overwrite

Periodic loop (every N seconds, default 15)
  ├─ Re-poison active watched peers (only those with recent activity)
  ├─ Re-poison illegal device's gateway cache
  ├─ Expire silent peers (PEER_TIMEOUT = max(interval×4, 60s))
  ├─ Detect offline targets (TARGET_TIMEOUT = max(interval×6, 120s))
  └─ Whitelist watcher (every 3s) → hot-add/remove targets
```

**Why Unicast, not Broadcast:** Lower IDS signature, minimal network traffic, targeted effect.

**Why Reactive, not Proactive:** A 100-device network needs no full sweep every few seconds — only devices actively communicating with the target are poisoned.

---

## Requirements

| Component | Detail |
|---|---|
| Platform | Linux (KVM VM recommended; LXC lacks `NET_RAW`) |
| Python | 3.10+ |
| Packages | `python3-scapy`, `python3-flask` |
| Privileges | `sudo` required (raw socket) |
| Tested on | Ubuntu 22.04, Proxmox 8 / vmbr0 bridge |

```bash
sudo apt update
sudo apt install python3-scapy python3-flask net-tools -y
```

---

## Quick Start

### Web UI (recommended)

```bash
# Start the web server (requires sudo for raw socket)
sudo python3 web_ui.py
# → http://<vm-ip>:5000
```

**Workflow:**
1. **掃描偵測** tab → enter interface (`ens18`) and subnet (`192.168.88.0/24`) → Scan
2. Click **加入白名單** on legitimate devices
3. **封鎖執行** tab → enter Gateway IP → **開始封鎖**
4. Live log shows interceptions, peer additions, offline events
5. Change whitelist anytime — enforcement updates within 3 seconds

### CLI

```bash
# Scan subnet
sudo python3 upas_tool.py --scan -i ens18 -s 192.168.88.0/24

# Scan + continuous monitor for new devices
sudo python3 upas_tool.py --scan --monitor -i ens18 -s 192.168.88.0/24

# Interactive whitelist management (with pre-scan)
sudo python3 upas_tool.py --manage -i ens18 -s 192.168.88.0/24

# Enforce: block all non-whitelisted devices (auto-scan)
sudo python3 upas_tool.py --enforce -i ens18 -s 192.168.88.0/24 -g 192.168.88.1

# Enforce: block a specific device
sudo python3 upas_tool.py --enforce -i ens18 -g 192.168.88.1 \
    --target-ip 192.168.88.50 --target-mac AA:BB:CC:DD:EE:FF --interval 15
```

---

## Web UI Overview

| Tab | Function |
|---|---|
| 掃描偵測 | ARP scan, device table with whitelist status, quick-add button |
| 白名單管理 | View / add / remove whitelist entries |
| 封鎖執行 | Start/stop enforcement, live log (SSE), blocked target preview |

Status dot in navbar reflects current state: ⚫ idle / 🟢 running / 🟡 stopping.

---

## whitelist.json format

```json
{
  "whitelist": [
    {"ip": "192.168.88.1",  "mac": "18:FD:74:19:65:F2", "note": "MikroTik Gateway"},
    {"ip": "192.168.88.10", "mac": "AA:BB:CC:DD:EE:FF", "note": "My laptop"}
  ]
}
```

---

## REST API

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/scan` | `{interface, subnet}` → scan and return device list |
| `GET` | `/api/whitelist` | Return whitelist entries |
| `POST` | `/api/whitelist` | `{ip, mac, note}` → add entry |
| `DELETE` | `/api/whitelist/<mac>` | Remove entry |
| `GET` | `/api/enforce/status` | `{status, illegal_count, illegal[]}` |
| `POST` | `/api/enforce/start` | `{gateway, interface, interval}` → start enforcement |
| `POST` | `/api/enforce/stop` | Stop enforcement (triggers ARP restore) |
| `GET` | `/api/logs/stream` | SSE stream of enforcement log lines |

---

## Verification

**On MikroTik gateway:**
```
/ip arp print
```
Blocked device's IP should map to the enforcer VM's MAC.

**On any device (Linux):**
```bash
arp -n
ip neigh show
```
Blocked device's IP should map to enforcer MAC, not the real one.

**Capture with tcpdump:**
```bash
sudo tcpdump -i ens18 -n arp
# Should see unicast ARP replies with enforcer MAC as source
```

---

## Known Limitations

- **L2 race condition** — ARP poisoning competes with the target's own ARP replies; the sniffer + short periodic refresh mitigates but cannot eliminate this on a shared bridge
- **Switch-level isolation** — true reliable blocking requires port-based ACL at the managed switch layer (e.g. MikroTik `/interface bridge port` isolation); ARP-based control is a best-effort layer above that
- **Proxmox vmbr0** — the Linux bridge floods unknown MACs; blocking is effective because the enforcer MAC absorbs the traffic (ip_forward=0)

---

## Lab Environment

```
Proxmox KVM
├── Ubuntu 22.04 VM  (enforcer, this tool)   192.168.88.240
├── Ubuntu 22.04 VM  (target / victim)       192.168.88.x
└── MikroTik RB960PGS (gateway, RouterOS 6.49) 192.168.88.1
    └── vmbr0 bridge — all VMs on 192.168.88.0/24
```

---

> **For educational / home lab use only.**  
> Do not deploy on networks you do not own or have explicit authorization to test.
