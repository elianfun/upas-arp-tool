#!/usr/bin/env python3
"""UPAS Web UI — Flask management interface (sudo python3 web_ui.py)"""
import collections
import os
import queue
import sys
import threading
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, jsonify, request, Response, render_template
from scanner import scan_network
from whitelist import load_whitelist, add_entry, remove_entry, WHITELIST_FILE
from enforcer import spoof, restore, _resolve_mac

app = Flask(__name__)

# ── State ─────────────────────────────────────────────────────────────────────
_scan_results: list[dict] = []
_scan_version  = 0          # incremented after every scan; watcher uses this to detect new scan
_enforce_status = "idle"   # idle | running | stopping
_enforce_stop = threading.Event()
_enforce_thread = None

# ── Log pub/sub ───────────────────────────────────────────────────────────────
_log_history: collections.deque = collections.deque(maxlen=500)
_subscribers: list[queue.Queue] = []
_sub_lock = threading.Lock()


def _ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


def _log(msg: str) -> None:
    line = f"[{_ts()}] {msg}"
    print(line, flush=True)
    _log_history.append(line)
    with _sub_lock:
        for q in list(_subscribers):
            try:
                q.put_nowait(line)
            except queue.Full:
                pass


def _subscribe() -> queue.Queue:
    q: queue.Queue = queue.Queue(maxsize=500)
    for line in list(_log_history):
        try:
            q.put_nowait(line)
        except queue.Full:
            break
    with _sub_lock:
        _subscribers.append(q)
    return q


def _unsubscribe(q: queue.Queue) -> None:
    with _sub_lock:
        if q in _subscribers:
            _subscribers.remove(q)


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def api_scan():
    global _scan_results, _scan_version
    data = request.get_json(silent=True) or {}
    interface = data.get("interface", "ens18")
    subnet = data.get("subnet", "192.168.88.0/24")
    try:
        devices = scan_network(subnet, interface)
        wl = {e["mac"].upper() for e in load_whitelist()}
        for d in devices:
            d["whitelisted"] = d["mac"].upper() in wl
        _scan_results = devices
        _scan_version += 1   # signal watcher to re-sync targets
        return jsonify({"ok": True, "devices": devices})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/whitelist", methods=["GET"])
def api_wl_get():
    return jsonify(load_whitelist())


@app.route("/api/whitelist", methods=["POST"])
def api_wl_add():
    data = request.get_json(silent=True) or {}
    try:
        add_entry(data["ip"], data["mac"], data.get("note", ""))
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@app.route("/api/whitelist/<path:mac>", methods=["DELETE"])
def api_wl_del(mac):
    remove_entry(mac)
    return jsonify({"ok": True})


@app.route("/api/enforce/status")
def api_enf_status():
    wl_macs = {e["mac"].upper() for e in load_whitelist()}
    illegal = [d for d in _scan_results if d["mac"].upper() not in wl_macs]
    return jsonify({
        "status": _enforce_status,
        "scan_count": len(_scan_results),
        "illegal_count": len(illegal),
        "illegal": illegal,
    })


@app.route("/api/enforce/start", methods=["POST"])
def api_enf_start():
    global _enforce_thread, _enforce_stop, _enforce_status
    if _enforce_status == "running":
        return jsonify({"ok": False, "error": "Already running"}), 400
    if not _scan_results:
        return jsonify({"ok": False, "error": "Run a scan first"}), 400

    data = request.get_json(silent=True) or {}
    gateway_ip = data.get("gateway", "").strip()
    interface = data.get("interface", "ens18")
    interval = int(data.get("interval", 30))

    if not gateway_ip:
        return jsonify({"ok": False, "error": "gateway is required"}), 400

    wl_macs = {e["mac"].upper() for e in load_whitelist()}
    targets = [d for d in _scan_results if d["mac"].upper() not in wl_macs]
    if not targets:
        return jsonify({"ok": False, "error": "No illegal devices — all scanned devices are whitelisted"}), 400

    try:
        gw_mac = _resolve_mac(gateway_ip, interface)
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

    import time as _time
    import os as _os

    PEER_TIMEOUT   = max(interval * 4, 60)
    TARGET_TIMEOUT = max(interval * 6, 120)

    # ── Mutable target state (all under state_lock) ───────────────────────────
    state_lock       = threading.Lock()
    targets_list     = list(targets)
    target_ips       = {t["ip"] for t in targets_list}
    target_by_ip     = {t["ip"]: t for t in targets_list}
    target_last_seen = {t["ip"]: _time.time() for t in targets_list}
    target_online    = {t["ip"]: True for t in targets_list}

    watched_peers: dict[str, dict] = {}
    watched_lock  = threading.Lock()

    _enforce_stop   = threading.Event()
    _enforce_status = "running"

    def _poison(dst_ip: str, dst_mac: str, spoof_ip: str) -> None:
        spoof(dst_ip, dst_mac, spoof_ip, interface)

    def _handle_arp(pkt):
        from scapy.all import ARP, Ether, sendp
        if not pkt.haslayer(ARP):
            return
        arp = pkt[ARP]
        src_ip, src_mac = arp.psrc, arp.hwsrc.upper()
        dst_ip = arp.pdst

        with state_lock:
            t_ips   = set(target_ips)
            t_by_ip = dict(target_by_ip)
            if src_ip in t_ips:
                target_last_seen[src_ip] = _time.time()

        if arp.op == 1:
            if dst_ip in t_ips and src_ip not in t_ips and src_ip != "0.0.0.0":
                with watched_lock:
                    is_new = src_ip not in watched_peers
                    watched_peers[src_ip] = {"mac": src_mac, "last_seen": _time.time()}
                if is_new:
                    _log(f"[WATCH+] {src_ip} → {dst_ip} (timeout={PEER_TIMEOUT}s)")
                _poison(src_ip, src_mac, dst_ip)
            elif src_ip in t_ips and dst_ip != "0.0.0.0":
                _poison(src_ip, t_by_ip[src_ip]["mac"], dst_ip)

        elif arp.op == 2:
            t = t_by_ip.get(src_ip)
            if t and src_mac == t["mac"].upper():
                counter = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
                    op=2, psrc=src_ip, pdst="0.0.0.0", hwdst="ff:ff:ff:ff:ff:ff"
                )
                sendp(counter, iface=interface, verbose=False)
                _log(f"[COUNTER] Gratuitous ARP from {src_ip} → broadcast overwrite")

    def _sync_targets(reason: str):
        """Diff _scan_results against whitelist; add/remove targets in place."""
        new_wl_macs = {e["mac"].upper() for e in load_whitelist()}
        with state_lock:
            current     = list(targets_list)
            current_ips = set(target_ips)

        promoted = [t for t in current if t["mac"].upper() in new_wl_macs]
        demoted  = [d for d in _scan_results
                    if d["mac"].upper() not in new_wl_macs and d["ip"] not in current_ips]

        if not promoted and not demoted:
            return

        for t in promoted:
            restore(gateway_ip, gw_mac, t["ip"], t["mac"], interface)
            restore(t["ip"], t["mac"], gateway_ip, gw_mac, interface)
            with watched_lock:
                snap = {ip: d["mac"] for ip, d in watched_peers.items()}
            for peer_ip, peer_mac in snap.items():
                restore(peer_ip, peer_mac, t["ip"], t["mac"], interface)
            _log(f"[{reason}] {t['ip']} whitelisted → removed from targets, ARP restored")

        with state_lock:
            for t in promoted:
                if t in targets_list: targets_list.remove(t)
                target_ips.discard(t["ip"])
                target_by_ip.pop(t["ip"], None)
                target_last_seen.pop(t["ip"], None)
                target_online.pop(t["ip"], None)
            for d in demoted:
                targets_list.append(d)
                target_ips.add(d["ip"])
                target_by_ip[d["ip"]] = d
                target_last_seen[d["ip"]] = _time.time()
                target_online[d["ip"]] = True

        for d in demoted:
            _log(f"[{reason}] {d['ip']} ({d['mac']}) → added to targets")

    def _watch_whitelist():
        """Re-sync when whitelist.json changes OR a new scan completes (every 3 s poll)."""
        last_mtime    = _os.path.getmtime(WHITELIST_FILE) if _os.path.exists(WHITELIST_FILE) else 0
        last_scan_ver = _scan_version
        while not _enforce_stop.is_set():
            _enforce_stop.wait(3)
            if _enforce_stop.is_set():
                break
            try:
                curr_mtime = _os.path.getmtime(WHITELIST_FILE) if _os.path.exists(WHITELIST_FILE) else 0
            except OSError:
                curr_mtime = last_mtime

            wl_changed   = curr_mtime != last_mtime
            scan_changed = _scan_version != last_scan_ver

            if wl_changed:
                last_mtime = curr_mtime
                _sync_targets("WHITELIST")
            elif scan_changed:
                _sync_targets("SCAN")

            if scan_changed:
                last_scan_ver = _scan_version

    from scapy.all import AsyncSniffer
    sniffer = AsyncSniffer(iface=interface, filter="arp", prn=_handle_arp, store=False)

    def _loop():
        global _enforce_status
        sniffer.start()
        watcher = threading.Thread(target=_watch_whitelist, daemon=True, name="wl-watcher")
        watcher.start()
        with state_lock:
            init_ips = ", ".join(t["ip"] for t in targets_list)
        _log(f"ENFORCE START — target(s): {init_ips}")
        _log(f"refresh={interval}s | peer_timeout={PEER_TIMEOUT}s | target_timeout={TARGET_TIMEOUT}s | whitelist_watch=3s")
        try:
            while not _enforce_stop.is_set():
                now = _time.time()

                with state_lock:
                    current = list(targets_list)
                    for t in current:
                        ip     = t["ip"]
                        silent = now - target_last_seen.get(ip, 0)
                        was_on = target_online.get(ip, True)
                        is_on  = silent < TARGET_TIMEOUT
                        if was_on != is_on:
                            target_online[ip] = is_on
                            if not is_on:
                                _log(f"[OFFLINE] {ip} — no ARP for {int(silent)}s, pausing")
                            else:
                                _log(f"[ONLINE]  {ip} — ARP detected, resuming")
                    active = [t for t in current if target_online.get(t["ip"], True)]

                with watched_lock:
                    expired = [(ip, d) for ip, d in watched_peers.items()
                               if now - d["last_seen"] > PEER_TIMEOUT]
                    for ip, _ in expired:
                        del watched_peers[ip]
                for ip, d in expired:
                    for t in current:
                        restore(ip, d["mac"], t["ip"], t["mac"], interface)
                        restore(t["ip"], t["mac"], ip, d["mac"], interface)
                    _log(f"[EXPIRE] {ip} — silent {int(now - d['last_seen'])}s, removed & ARP restored")

                for t in active:
                    _poison(t["ip"], t["mac"], gateway_ip)
                with watched_lock:
                    snap = {ip: d["mac"] for ip, d in watched_peers.items()}
                if snap and active:
                    for peer_ip, peer_mac in snap.items():
                        for t in active:
                            _poison(peer_ip, peer_mac, t["ip"])
                    _log(f"Refresh: {len(active)} active target(s), {len(snap)} watched peer(s)")

                _enforce_stop.wait(interval)
        finally:
            sniffer.stop()
            _enforce_status = "stopping"
            _log("Stopping — restoring all ARP entries ...")
            with state_lock:
                final = list(targets_list)
            with watched_lock:
                snap = {ip: d["mac"] for ip, d in watched_peers.items()}
            for peer_ip, peer_mac in snap.items():
                for t in final:
                    restore(peer_ip, peer_mac, t["ip"], t["mac"], interface)
                    restore(t["ip"], t["mac"], peer_ip, peer_mac, interface)
            for t in final:
                restore(gateway_ip, gw_mac, t["ip"], t["mac"], interface)
                restore(t["ip"], t["mac"], gateway_ip, gw_mac, interface)
            _log("All ARP restored. Network fully recovered.")
            _enforce_status = "idle"

    _enforce_thread = threading.Thread(target=_loop, daemon=True, name="enforce")
    _enforce_thread.start()
    return jsonify({"ok": True, "targets": len(targets)})


@app.route("/api/enforce/stop", methods=["POST"])
def api_enf_stop():
    global _enforce_status
    if _enforce_status != "running":
        return jsonify({"ok": False, "error": "Not running"}), 400
    _enforce_stop.set()
    return jsonify({"ok": True})


@app.route("/api/logs/stream")
def api_logs_stream():
    q = _subscribe()

    def generate():
        try:
            while True:
                try:
                    line = q.get(timeout=20)
                    yield f"data: {line}\n\n"
                except queue.Empty:
                    yield "data: :ping\n\n"
        except GeneratorExit:
            pass
        finally:
            _unsubscribe(q)

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


if __name__ == "__main__":
    print("[UPAS] Web UI → http://0.0.0.0:5000")
    app.run(host="0.0.0.0", port=5000, threaded=True, debug=False)
