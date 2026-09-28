#!/usr/bin/env python3
"""
Debug: compare réponse HTML carte valide vs invalide
Lance ça pour voir exactement ce que UGC retourne
"""
import requests, urllib3
urllib3.disable_warnings()
from bs4 import BeautifulSoup

try:
    import cloudscraper
    S = cloudscraper.create_scraper(browser={"browser":"chrome","platform":"windows"})
except ImportError:
    S = requests.Session(); S.verify = False

S.headers.update({"Accept-Language":"fr-FR,fr;q=0.9","Referer":"https://www.ugc.fr/"})

PAGE = "https://www.ugc.fr/les-offres-ugc.html"

def fetch_page():
    r = S.get(PAGE, timeout=12)
    return r.text

def submit_card(num: str, page_html: str):
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(page_html, "html.parser")

    # trouve le form
    action = PAGE
    payload = {}
    card_field = "numeroCarte"

    for form in soup.find_all("form"):
        inputs = form.find_all("input")
        names  = [i.get("name","").lower() for i in inputs]
        if any("carte" in n or "numero" in n or "card" in n for n in names):
            a = form.get("action","")
            action = ("https://www.ugc.fr" + a) if a and not a.startswith("http") else (a or PAGE)
            for inp in inputs:
                t  = inp.get("type","").lower()
                nm = inp.get("name","")
                if t == "hidden" and nm:
                    payload[nm] = inp.get("value","")
                if "carte" in nm.lower() or "numero" in nm.lower():
                    card_field = nm
            break

    payload[card_field] = num
    print(f"\n[*] POST → {action}")
    print(f"[*] payload: {payload}")

    r = S.post(action, data=payload, timeout=12, allow_redirects=True)
    return r

# ─── test avec numéro clairement invalide ─────────────────────────────────────
print("="*60)
print("STEP 1 — page GET (baseline)")
html = fetch_page()
soup0 = BeautifulSoup(html, "html.parser")
print(f"  Title: {soup0.find('title').get_text()[:80] if soup0.find('title') else '?'}")
# cherche les forms
forms = soup0.find_all("form")
print(f"  Forms: {len(forms)}")
for i, f in enumerate(forms):
    inputs = [(inp.get('name','?'), inp.get('type','text')) for inp in f.find_all('input')]
    print(f"    form[{i}] action={f.get('action','?')} inputs={inputs}")

# ─── soumission numéro invalide ───────────────────────────────────────────────
print("\n" + "="*60)
print("STEP 2 — carte invalide: 00000000000")
r_bad = submit_card("00000000000", html)
print(f"  HTTP {r_bad.status_code}")
soup_bad = BeautifulSoup(r_bad.text, "html.parser")

# diff: textes qui apparaissent dans la réponse mais pas dans la page originale
orig_texts = set(t.strip() for t in soup0.stripped_strings if len(t.strip()) > 5)
new_texts  = set(t.strip() for t in soup_bad.stripped_strings if len(t.strip()) > 5)
diff       = new_texts - orig_texts
print(f"  Nouveaux textes dans la réponse ({len(diff)}):")
for t in sorted(diff)[:20]:
    print(f"    → {repr(t)}")

# cherche des mots-clés de résultat
for kw in ["introuvable","invalide","incorrect","erreur","solde","places","valide","carte","€"]:
    if kw in r_bad.text.lower():
        # trouve le contexte
        idx = r_bad.text.lower().find(kw)
        ctx = r_bad.text[max(0,idx-50):idx+100].strip()
        print(f"  [KW] '{kw}' → ...{repr(ctx)}...")

# ─── soumission numéro au hasard ─────────────────────────────────────────────
print("\n" + "="*60)
print("STEP 3 — carte random: 12345678901")
r2 = submit_card("12345678901", html)
print(f"  HTTP {r2.status_code}")
new_texts2 = set(t.strip() for t in BeautifulSoup(r2.text,"html.parser").stripped_strings if len(t.strip()) > 5)
diff2 = new_texts2 - orig_texts
print(f"  Nouveaux textes ({len(diff2)}):")
for t in sorted(diff2)[:20]:
    print(f"    → {repr(t)}")

print("\n" + "="*60)
print("CONCLUSION: compare les deux diffs pour trouver les vrais indicateurs")
print("Si diff1 == diff2 → même réponse = faux positifs = pas de feedback UGC")
same = diff == diff2
print(f"  Réponses identiques: {'OUI (faux positifs confirmés)' if same else 'NON (feedback différent = on peut détecter ✓)'}")
