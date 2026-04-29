#!/usr/bin/env python3
"""
NeuralGuard - AI-Powered ARP Spoof Detection System  v2.5
Windows 11 / Python 3.13
"""

import os, sys, time, string, secrets, logging, threading, subprocess
from datetime import datetime

# ── auto-install ──────────────────────────────────────────────────────────────
def _pip(pkg, imp=None):
    try:
        __import__(imp or pkg)
    except ImportError:
        print(f"[*] Installing {pkg} ...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", pkg],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

_pip("scapy")
_pip("flask")
_pip("flask-socketio", "flask_socketio")
_pip("simple-websocket", "simple_websocket")   # fixes Werkzeug WebSocket bug on Py3.13
_pip("scikit-learn", "sklearn")
_pip("numpy")

# Silence noise
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("werkzeug").setLevel(logging.ERROR)
logging.getLogger("engineio").setLevel(logging.ERROR)
logging.getLogger("socketio").setLevel(logging.ERROR)

from scapy.all import ARP, sniff, get_if_list, get_if_addr, get_if_hwaddr
import numpy as np
from sklearn.ensemble import IsolationForest
from flask import Flask, jsonify, Response
from flask_socketio import SocketIO, emit as _sio_emit

# ── Flask / SocketIO ──────────────────────────────────────────────────────────
app = Flask(__name__)
app.config["SECRET_KEY"] = secrets.token_hex(16)

# threading + simple-websocket = no monkey-patch, no Werkzeug WebSocket crash
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode="threading",
    ping_timeout=60,
    ping_interval=25,
    logger=False,
    engineio_logger=False,
)

# ── Shared state ──────────────────────────────────────────────────────────────
_lock          = threading.RLock()
ip_mac_table   = {}    # ip -> real mac (ground truth, NEVER overwritten)
network_devices= []
alerts         = []
alerted_keys   = set() # (attacker_mac, spoofed_ip) - alert once per pair
packet_stats   = {"total": 0, "arp": 0, "alerts": 0}

gateway_ip = ""
my_ip      = ""
my_mac     = ""
IFACE      = ""

# ── AI model ──────────────────────────────────────────────────────────────────
_model        = IsolationForest(contamination=0.03, n_estimators=100, random_state=42)
_feat_buf     = []
_model_ready  = False
_model_lock   = threading.Lock()

# ── OUI lookup ────────────────────────────────────────────────────────────────
_OUI = {
    "00:50:56":"VMware",     "00:0C:29":"VMware",    "08:00:27":"VirtualBox",
    "52:54:00":"QEMU/KVM",   "00:1A:2B":"Cisco",     "00:1B:21":"Intel",
    "AC:DE:48":"Apple",      "F0:18:98":"Apple",     "3C:22:FB":"Apple",
    "A4:C3:F0":"Apple",      "00:50:F2":"Microsoft", "28:80:23":"Raspberry Pi",
    "B8:27:EB":"Raspberry Pi","DC:A6:32":"Raspberry Pi",
    "00:1A:11":"Google",     "40:4E:36":"Samsung",
    "00:16:3E":"Xen",        "00:15:5D":"Hyper-V",
}
def _vendor(mac):
    if not mac or len(mac) < 8: return "Unknown"
    return _OUI.get(mac[:8].upper().replace("-",":"), "Unknown")

# ── Thread-safe SocketIO emit ─────────────────────────────────────────────────
def _emit(event, data):
    """Emit from any thread safely."""
    try:
        socketio.emit(event, data)
    except Exception:
        pass

# ── Device registry ───────────────────────────────────────────────────────────
def _register(ip, mac, source="passive"):
    """Record ip->mac. First write wins — never overwritten."""
    mac = mac.lower().strip()
    if not ip or not mac or len(mac) != 17:
        return
    snap = None
    with _lock:
        if ip not in ip_mac_table:
            ip_mac_table[ip] = mac
            dev = {
                "ip": ip, "mac": mac, "vendor": _vendor(mac),
                "first_seen": datetime.now().strftime("%H:%M:%S"),
                "source": source, "status": "trusted",
            }
            network_devices.append(dev)
            snap = list(network_devices)
            print(f"  [+] [{source:8s}] {ip:17s} -> {mac}  ({_vendor(mac)})")
    if snap:
        _emit("device_update", {"devices": snap})

# ── Windows ARP cache seed ────────────────────────────────────────────────────
def _seed():
    """Load Windows ARP cache into ground-truth table."""
    try:
        out = subprocess.check_output(["arp", "-a"], text=True,
                                       stderr=subprocess.DEVNULL)
        n = 0
        for line in out.splitlines():
            p = line.split()
            if len(p) < 3: continue
            ip, mac, typ = p[0], p[1].replace("-",":").lower(), p[2].lower()
            if ip.count(".") != 3: continue
            if len(mac) != 17 or mac.count(":") != 5: continue
            if mac in ("ff:ff:ff:ff:ff:ff","00:00:00:00:00:00"): continue
            if mac.startswith("01:00:5e") or mac.startswith("33:33"): continue
            if typ == "incomplete": continue
            _register(ip, mac, source="arp-a")
            n += 1
        print(f"[*] ARP cache: {n} entries loaded.")
        if n < 3:
            print("[!] Few entries found — run ping sweep or check interface.")
    except Exception as e:
        print(f"[!] arp -a error: {e}")

# ── Ping sweep — forces Windows to populate ARP cache ────────────────────────
def _ping_sweep():
    """Ping every IP in subnet so Windows discovers all devices via ARP."""
    try:
        if not gateway_ip: return
        parts = gateway_ip.split(".")
        base  = f"{parts[0]}.{parts[1]}.{parts[2]}."
        print(f"[*] Ping sweep on {base}0/24 to discover all devices ...")
        procs = []
        for i in range(1, 255):
            ip = base + str(i)
            if ip == my_ip: continue
            procs.append(subprocess.Popen(
                ["ping", "-n", "1", "-w", "300", ip],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            ))
        # Wait for pings to finish
        for p in procs:
            try: p.wait(timeout=2)
            except Exception: p.kill()
        time.sleep(1)
        _seed()
        print("[*] Ping sweep done.")
    except Exception as e:
        print(f"[!] Ping sweep error: {e}")

def _refresher():
    """Re-read ARP cache every 30s for newly joined devices."""
    while True:
        time.sleep(30)
        _seed()

# ── Password generator ────────────────────────────────────────────────────────
def _mkpass(length=24):
    chars = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{}|;:,.<>?"
    while True:
        p = "".join(secrets.choice(chars) for _ in range(length))
        if (any(c.isupper() for c in p) and any(c.islower() for c in p)
                and any(c.isdigit() for c in p)
                and any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?" for c in p)):
            return {
                "password": p, "length": length,
                "entropy_bits": round(length*6.5, 1),
                "strength": "CRITICAL-GRADE",
                "algorithm": "CSPRNG (secrets) + NIST SP 800-63B",
                "char_sets": "Uppercase + Lowercase + Digits + Special",
            }

# ── AI helpers ────────────────────────────────────────────────────────────────
def _feats(sip, smac, tip, op):
    with _lock:
        k = float(sip in ip_mac_table)
        c = float(sip in ip_mac_table and ip_mac_table[sip] != smac)
    s = [float(o) for o in sip.split(".")]
    d = [float(o) for o in (tip or "0.0.0.0").split(".")]
    return s + d + [float(op), k, c]

def _retrain():
    global _model_ready
    with _model_lock:
        if len(_feat_buf) >= 30:
            _model.fit(np.array(_feat_buf[-600:]))
            _model_ready = True

def _anomalous(f):
    with _model_lock:
        if not _model_ready: return False
        return _model.predict(np.array([f]))[0] == -1

# ── ARP packet handler ────────────────────────────────────────────────────────
#
#  bettercap arp.spoof sends TWO streams of op=2 replies:
#
#  Stream A: "Gateway IP is at ATTACKER_MAC"  -> sent to phone
#    hwsrc=ATTACKER_MAC, psrc=GATEWAY_IP, pdst=PHONE_IP
#    Poisons phone's cache: phone sends traffic to attacker instead of gateway
#
#  Stream B: "Phone IP is at ATTACKER_MAC"    -> sent to gateway
#    hwsrc=ATTACKER_MAC, psrc=PHONE_IP, pdst=GATEWAY_IP
#    Poisons gateway's cache: gateway sends traffic to attacker instead of phone
#
#  Detection: in BOTH streams, psrc (sender_ip) is an IP whose REAL MAC we know.
#  hwsrc (sender_mac) is the ATTACKER MAC — different from the real MAC.
#  MAC mismatch on op=2 = ALERT.
#
#  net.probe: sends op=1 requests only -> we learn from them, NEVER alert.

def handle_arp(pkt):
    if not pkt.haslayer(ARP):
        return

    arp        = pkt[ARP]
    op         = int(arp.op)
    sender_ip  = arp.psrc
    sender_mac = arp.hwsrc.lower().strip()
    target_ip  = arp.pdst

    # Skip invalid / link-local
    if not sender_ip or sender_ip == "0.0.0.0":
        return
    if sender_ip.startswith("169.254."):
        return

    # Skip our own packets (IP check only — MAC check unreliable on Windows)
    if sender_ip == my_ip:
        return

    with _lock:
        packet_stats["total"] += 1
        packet_stats["arp"]   += 1
        total = packet_stats["total"]

    # Print a heartbeat every 50 packets so we know capture is working
    if total % 50 == 0:
        print(f"  [~] {total} ARP packets captured so far ...")

    f = _feats(sender_ip, sender_mac, target_ip, op)
    _feat_buf.append(f)
    if len(_feat_buf) % 20 == 0:
        threading.Thread(target=_retrain, daemon=True).start()

    # ── op=1 REQUEST: learn ground-truth MAC, never flag ──────────────────
    if op == 1:
        _register(sender_ip, sender_mac, source="passive")
        return

    # ── op=2 REPLY: spoof check ───────────────────────────────────────────
    # DO NOT register from replies — only op=1 and arp-a set ground truth.
    with _lock:
        known_mac = ip_mac_table.get(sender_ip)

    # Log every op=2 for visibility
    print(f"  [op2] {sender_ip} claims {sender_mac} | known={known_mac} | to={target_ip}")

    if known_mac is None:
        # No ground truth yet for this IP
        return

    if known_mac.lower() == sender_mac:
        # MAC matches known — legitimate
        return

    # ── MISMATCH → ATTACK ─────────────────────────────────────────────────
    attack_key = (sender_mac, sender_ip)
    with _lock:
        if attack_key in alerted_keys:
            return
        alerted_keys.add(attack_key)
        packet_stats["alerts"] += 1

    ai = _anomalous(f)

    # Victim = device being deceived (target_ip), excluding gateway
    victim_ip = target_ip
    if not victim_ip or victim_ip == sender_ip or victim_ip == gateway_ip:
        with _lock:
            cands = [ip for ip in ip_mac_table
                     if ip not in (sender_ip, gateway_ip, my_ip)]
        victim_ip = cands[0] if cands else (target_ip or "unknown")

    with _lock:
        victim_mac = ip_mac_table.get(victim_ip, "unknown")

    pwd    = _mkpass()
    method = ("Rule-based + AI" if ai else "Rule-based (MAC mismatch on ARP reply)")

    alert = {
        "id": len(alerts)+1,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "type": "ARP Spoofing / MITM Attack",
        "severity": "CRITICAL",
        "attacker": {"ip": sender_ip, "mac": sender_mac, "vendor": _vendor(sender_mac)},
        "victim":   {"ip": victim_ip,  "mac": victim_mac, "vendor": _vendor(victim_mac)},
        "legitimate_mac": known_mac,
        "detection_method": method,
        "password_recommendation": pwd,
    }

    with _lock:
        alerts.append(alert)

    print("\n" + "="*66)
    print("  !!! NeuralGuard - ARP SPOOF ATTACK DETECTED !!!")
    print("="*66)
    print(f"  Attacker IP   : {sender_ip}")
    print(f"  Attacker MAC  : {sender_mac}  [{_vendor(sender_mac)}]")
    print(f"  Real MAC was  : {known_mac}")
    print(f"  Victim IP     : {victim_ip}")
    print(f"  Victim MAC    : {victim_mac}")
    print(f"  Method        : {method}")
    print(f"  Time          : {alert['timestamp']}")
    print("-"*66)
    print(f"  Password      : {pwd['password']}")
    print(f"  Entropy       : {pwd['entropy_bits']} bits  |  {pwd['algorithm']}")
    print("="*66+"\n")

    _emit("new_alert", alert)

# ── Flask routes ──────────────────────────────────────────────────────────────
_HTML_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "index.html")
try:
    _HTML = open(_HTML_PATH, encoding="utf-8").read()
    print(f"[*] Dashboard HTML loaded.")
except FileNotFoundError:
    _HTML = "<h1 style='color:#00cfff;font-family:monospace'>NeuralGuard - index.html missing</h1>"

@app.route("/")
def index(): return Response(_HTML, mimetype="text/html")

@app.route("/api/alerts")
def api_alerts():
    with _lock: return jsonify(list(alerts))

@app.route("/api/devices")
def api_devices():
    with _lock: return jsonify(list(network_devices))

@app.route("/api/stats")
def api_stats():
    with _lock:
        d = dict(packet_stats)
        d["devices"] = len(network_devices)
        d["learned"] = len(ip_mac_table)
    return jsonify(d)

@app.errorhandler(404)
def e404(e): return jsonify({"error": "not found"}), 404

@app.errorhandler(500)
def e500(e): return jsonify({"error": str(e)}), 500

@socketio.on("connect")
def on_connect():
    print("[WS] Browser connected")
    with _lock:
        devs = list(network_devices)
        als  = list(alerts)
    # Use _sio_emit inside handler (sends only to this client)
    _sio_emit("device_update", {"devices": devs})
    for a in als:
        _sio_emit("new_alert", a)

@socketio.on("disconnect")
def on_disconnect():
    print("[WS] Browser disconnected")

# ── Sniff thread ──────────────────────────────────────────────────────────────
def _sniff(iface):
    print(f"[*] ARP capture started on: {iface}")
    try:
        sniff(iface=iface, filter="arp", prn=handle_arp, store=False)
    except Exception as e:
        print(f"[!] Sniff error: {e}")
        print("[!] Try reinstalling Npcap from https://npcap.com/")

# ── Network helpers ───────────────────────────────────────────────────────────
def _get_gateway():
    try:
        out = subprocess.check_output("ipconfig", text=True,
                                       stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            if "Default Gateway" in line:
                c = line.strip().split()[-1]
                if c.count(".") == 3 and not c.startswith("fe80"):
                    return c
    except Exception: pass
    return ""

def _pick_interface():
    print("\n[*] Available network interfaces:")
    ifaces = get_if_list()
    # filter junk
    clean = []
    for iface in ifaces:
        lo = iface.lower()
        if any(x in lo for x in ["loopback","docker","virbr","vmnet",
                                   "veth","dummy","npcap loopback"]):
            continue
        clean.append(iface)
    if not clean:
        clean = ifaces

    for i, iface in enumerate(clean):
        try:    ip = get_if_addr(iface)
        except: ip = "unknown"
        print(f"    [{i}] {iface}")
        print(f"         IP: {ip}")
    print()

    while True:
        try:
            raw = input(f"[?] Select interface (0-{len(clean)-1}, default 0): ").strip()
            if raw == "": return clean[0]
            n = int(raw)
            if 0 <= n < len(clean):
                print(f"    Using: {clean[n]}\n")
                return clean[n]
            print(f"[!] Enter 0 to {len(clean)-1}.")
        except ValueError:
            print("[!] Numbers only.")

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    print(r"""
  ███╗   ██╗███████╗██╗   ██╗██████╗  █████╗ ██╗      ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
  ████╗  ██║██╔════╝██║   ██║██╔══██╗██╔══██╗██║     ██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
  ██╔██╗ ██║█████╗  ██║   ██║██████╔╝███████║██║     ██║  ███╗██║   ██║███████║██████╔╝██║  ██║
  ██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██╔══██║██║     ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
  ██║ ╚████║███████╗╚██████╔╝██║  ██║██║  ██║███████╗╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
  ╚═╝  ╚═══╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
                 AI-Powered ARP Spoof Detection  |  NeuralGuard v2.5
""")

    global gateway_ip, my_ip, my_mac, IFACE

    IFACE      = _pick_interface()
    gateway_ip = _get_gateway()

    try:
        my_ip  = get_if_addr(IFACE)
        my_mac = get_if_hwaddr(IFACE).lower()
    except Exception:
        my_ip = my_mac = ""

    print(f"[*] Interface : {IFACE}")
    print(f"[*] My IP     : {my_ip or '(unknown)'}")
    print(f"[*] My MAC    : {my_mac or '(unknown)'}")
    print(f"[*] Gateway   : {gateway_ip or '(not detected)'}")

    if my_ip and my_mac:
        _register(my_ip, my_mac, source="self")

    # 1. Seed from Windows ARP cache immediately
    print("\n[*] Seeding from Windows ARP cache ...")
    _seed()

    # 2. Start ARP capture
    threading.Thread(target=_sniff, args=(IFACE,), daemon=True).start()

    # 3. Ping sweep in background to discover all devices
    threading.Thread(target=_ping_sweep, daemon=True).start()

    # 4. Refresh ARP cache every 30s
    threading.Thread(target=_refresher, daemon=True).start()

    print("[*] Dashboard -> http://127.0.0.1:5000")
    print("[*] Monitoring ... (Ctrl+C to stop)\n")

    socketio.run(
        app,
        host="0.0.0.0",
        port=5000,
        debug=False,
        use_reloader=False,
        allow_unsafe_werkzeug=True,
    )

if __name__ == "__main__":
    main()
