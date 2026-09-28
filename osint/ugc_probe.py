#!/usr/bin/env python3
"""
UGC endpoint probe — trouve le vrai URL de récupération de billet
Lance ça d'abord pour trouver l'endpoint actif, puis utilise ugc_bruteforce.py

python ugc_probe.py
"""

import re, json
try:
    import cloudscraper
    S = cloudscraper.create_scraper(browser={"browser":"chrome","platform":"windows"})
except ImportError:
    import requests, urllib3; urllib3.disable_warnings()
    S = requests.Session(); S.verify = False

S.headers.update({
    "User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124 Safari/537.36",
    "Accept-Language": "fr-FR,fr;q=0.9",
})

from bs4 import BeautifulSoup

CANDIDATES = [
    # anciens
    "https://www.ugc.fr/reservation/retrieveBooking.html",
    "https://www.ugc.fr/reservation/booking/retrieve",
    "https://www.ugc.fr/ebillet/retrieveBooking",
    # probables nouveaux
    "https://www.ugc.fr/mon-compte/mes-reservations",
    "https://www.ugc.fr/reservations",
    "https://www.ugc.fr/billet",
    "https://www.ugc.fr/billets",
    "https://www.ugc.fr/ma-reservation",
    "https://www.ugc.fr/gestion-reservation",
    "https://www.ugc.fr/api/reservations",
    "https://www.ugc.fr/api/booking",
    "https://www.ugc.fr/api/v1/booking",
    "https://www.ugc.fr/api/v2/booking",
    "https://reservation.ugc.fr/",
    "https://billets.ugc.fr/",
    "https://ebillet.ugc.fr/",
]

print("[*] Probing UGC endpoints...\n")
active = []
for url in CANDIDATES:
    try:
        r = S.get(url, timeout=8, allow_redirects=True)
        status = r.status_code
        mark = "✓" if status in (200, 301, 302) else "✗"
        print(f"  [{mark}] {status}  {url}")
        if status in (200, 301, 302):
            active.append((url, status, r.text[:500]))
    except Exception as e:
        print(f"  [!] ERR  {url} → {str(e)[:60]}")

# Spider la page principale pour trouver des liens vers la récupération de réservation
print("\n[*] Spidering ugc.fr homepage for booking links...")
try:
    r = S.get("https://www.ugc.fr/", timeout=10)
    soup = BeautifulSoup(r.text, "html.parser")

    # cherche tous les liens avec des mots-clés
    kw = ["reservation","billet","booking","retrieve","ebillet","ticket","commande"]
    links = []
    for a in soup.find_all("a", href=True):
        href = a["href"]
        text = a.get_text(strip=True).lower()
        if any(k in href.lower() or k in text for k in kw):
            full = href if href.startswith("http") else "https://www.ugc.fr" + href
            links.append((text[:40], full))

    if links:
        print(f"  Trouvé {len(links)} lien(s) pertinent(s):")
        for text, href in links:
            print(f"    [{text}] {href}")
    else:
        print("  Aucun lien direct trouvé sur la homepage")

    # cherche aussi les scripts JS pour des endpoints API
    print("\n[*] Scanning JS for API endpoints...")
    for script in soup.find_all("script", src=True):
        src = script["src"]
        if not src.startswith("http"):
            src = "https://www.ugc.fr" + src
        try:
            js = S.get(src, timeout=6).text
            # cherche les endpoints /api/ ou /reservation/
            apis = re.findall(r'["\']([/\w-]*(?:api|reservation|booking|billet)[/\w.-]*)["\']', js)
            for api in set(apis):
                if len(api) > 5:
                    print(f"    [JS] {api}")
        except Exception:
            pass

    # inline scripts
    for script in soup.find_all("script", src=False):
        js = script.get_text()
        apis = re.findall(r'["\']([/\w-]*(?:api|reservation|booking|billet)[/\w.-]*)["\']', js)
        for api in set(apis):
            if len(api) > 5:
                print(f"    [inline] {api}")

except Exception as e:
    print(f"  [!] Spider error: {e}")

# Cherche sur la page /mon-ugc si elle existe
print("\n[*] Checking /mon-ugc and account pages...")
for path in ["/mon-ugc", "/compte", "/mon-compte", "/espace-client", "/espace-perso"]:
    try:
        r = S.get(f"https://www.ugc.fr{path}", timeout=8, allow_redirects=True)
        if r.status_code == 200:
            print(f"  [✓] 200  https://www.ugc.fr{path}")
            soup2 = BeautifulSoup(r.text, "html.parser")
            for a in soup2.find_all("a", href=True):
                href = a["href"]
                if any(k in href.lower() for k in ["reservation","billet","booking"]):
                    print(f"       → {href}")
        else:
            print(f"  [✗] {r.status_code}  https://www.ugc.fr{path}")
    except Exception as e:
        print(f"  [!] {path} → {str(e)[:50]}")

print("\n" + "═"*60)
print("RÉSUMÉ:")
if active:
    print(f"  Endpoints actifs trouvés: {len(active)}")
    for url, status, _ in active:
        print(f"    → {url}  (HTTP {status})")
else:
    print("  Aucun endpoint direct trouvé")
    print("  → Mettre à jour ugc_bruteforce.py avec le bon endpoint manuellement")
    print("  → Ou utiliser Selenium/Playwright pour browser automation")
print("═"*60)
