#!/usr/bin/env python3
"""
OSINT Reaper v1.0 — reconnaissance tool with local SQLite storage
pip install -r requirements.txt
python osint.py
"""

import sqlite3, requests, socket, json, re, os, hashlib
from datetime import datetime
from urllib.parse import urlparse
import dns.resolver

warnings_import = __import__("warnings")
warnings_import.filterwarnings("ignore")

# ─── DB ────────────────────────────────────────────────────────────────────────

DB_PATH = os.path.join(os.path.dirname(__file__), "osint_results.db")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS searches (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            ts      TEXT,
            kind    TEXT,
            query   TEXT,
            source  TEXT,
            result  TEXT,
            status  TEXT
        )
    """)
    conn.commit()
    return conn

def save(conn, kind, query, source, result, status):
    conn.execute(
        "INSERT INTO searches (ts,kind,query,source,result,status) VALUES (?,?,?,?,?,?)",
        (datetime.now().isoformat(), kind, query, source, str(result), status)
    )
    conn.commit()

def history(conn, limit=25):
    return conn.execute(
        "SELECT ts,kind,query,source,status FROM searches ORDER BY id DESC LIMIT ?",
        (limit,)
    ).fetchall()

# ─── HTTP ──────────────────────────────────────────────────────────────────────

S = requests.Session()
S.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
S.verify = False

def get(url, **kw):
    try:
        return S.get(url, timeout=8, **kw)
    except Exception:
        return None

# ─── USERNAME ──────────────────────────────────────────────────────────────────

PLATFORMS = {
    "GitHub":      "https://github.com/{}",
    "GitLab":      "https://gitlab.com/{}",
    "Twitter/X":   "https://x.com/{}",
    "Instagram":   "https://www.instagram.com/{}/",
    "TikTok":      "https://www.tiktok.com/@{}",
    "Reddit":      "https://www.reddit.com/user/{}/",
    "Pinterest":   "https://www.pinterest.com/{}/",
    "Twitch":      "https://www.twitch.tv/{}",
    "YouTube":     "https://www.youtube.com/@{}",
    "Steam":       "https://steamcommunity.com/id/{}",
    "Keybase":     "https://keybase.io/{}",
    "Medium":      "https://medium.com/@{}",
    "Dev.to":      "https://dev.to/{}",
    "HackerOne":   "https://hackerone.com/{}",
    "Bugcrowd":    "https://bugcrowd.com/{}",
    "Replit":      "https://replit.com/@{}",
    "Codepen":     "https://codepen.io/{}",
    "Soundcloud":  "https://soundcloud.com/{}",
    "Spotify":     "https://open.spotify.com/user/{}",
}

NOT_FOUND = [
    "not found","page not found","doesn't exist","user not found",
    "no user","404","cette page n'existe pas","profile not found",
    "sorry, this page isn't available"
]

def search_username(conn, username):
    print(f"\n\033[96m[*] Username: {username}\033[0m")
    print("─" * 55)
    found = []
    for platform, tpl in PLATFORMS.items():
        url = tpl.format(username)
        r = get(url, allow_redirects=True)
        if r is None:
            sym, color, status = "?", "\033[93m", "error"
        elif r.status_code == 200:
            body = r.text.lower()
            if any(x in body for x in NOT_FOUND):
                sym, color, status = "✗", "\033[91m", "not_found"
            else:
                sym, color, status = "✓", "\033[92m", "found"
                found.append(url)
        elif r.status_code in (404, 410):
            sym, color, status = "✗", "\033[91m", "not_found"
        else:
            sym, color, status = f"{r.status_code}", "\033[93m", f"http_{r.status_code}"
        print(f"  {color}[{sym}]\033[0m {platform:<14} {url}")
        save(conn, "username", username, platform, url, status)
    print(f"\n  \033[92m→ {len(found)} profile(s) found\033[0m")

# ─── EMAIL ─────────────────────────────────────────────────────────────────────

def search_email(conn, email):
    print(f"\n\033[96m[*] Email: {email}\033[0m")
    print("─" * 55)
    domain = email.split("@")[-1]

    # Gravatar
    h = hashlib.md5(email.strip().lower().encode()).hexdigest()
    r = get(f"https://www.gravatar.com/{h}.json")
    if r and r.status_code == 200:
        try:
            data = r.json().get("entry", [{}])[0]
            print(f"  \033[92m[✓] Gravatar\033[0m  displayName={data.get('displayName','?')}")
            print(f"      URL: https://gravatar.com/{h}")
            save(conn, "email", email, "Gravatar", data.get("displayName",""), "found")
        except Exception:
            pass
    else:
        print(f"  \033[91m[✗] No Gravatar profile\033[0m")
        save(conn, "email", email, "Gravatar", "", "not_found")

    # HIBP (no key = 401 but still useful to try)
    r2 = get(
        f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
        headers={"hibp-api-key": "", "User-Agent": "osint-reaper"}
    )
    if r2 and r2.status_code == 200:
        breaches = r2.json()
        print(f"  \033[91m[!] HIBP — PWNED in {len(breaches)} breach(es):\033[0m")
        for b in breaches[:8]:
            print(f"      · {b.get('Name','?')} ({b.get('BreachDate','?')})")
        save(conn, "email", email, "HIBP", json.dumps([b.get("Name") for b in breaches]), "found")
    elif r2 and r2.status_code == 404:
        print(f"  \033[92m[✓] HIBP — not found in known breaches\033[0m")
        save(conn, "email", email, "HIBP", "clean", "not_found")
    else:
        print(f"  \033[93m[~] HIBP — API key required for full breach data\033[0m")

    # MX records
    print(f"\n  \033[96m[MX]\033[0m {domain}:")
    try:
        for r in dns.resolver.resolve(domain, "MX"):
            print(f"      · {r.exchange} (prio {r.preference})")
        save(conn, "email", email, "DNS-MX", domain, "found")
    except Exception as e:
        print(f"      {e}")

# ─── DOMAIN ────────────────────────────────────────────────────────────────────

def search_domain(conn, domain):
    domain = domain.strip().removeprefix("http://").removeprefix("https://").rstrip("/")
    print(f"\n\033[96m[*] Domain: {domain}\033[0m")
    print("─" * 55)

    # DNS
    for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            vals = [str(a) for a in answers]
            print(f"  \033[92m[{rtype:<5}]\033[0m {', '.join(vals[:4])}")
            save(conn, "domain", domain, f"DNS-{rtype}", ", ".join(vals), "found")
        except Exception:
            pass

    # IP + geoIP
    try:
        ip = socket.gethostbyname(domain)
        print(f"\n  \033[96m[IP]\033[0m {ip}")
        r = get(f"https://ipinfo.io/{ip}/json")
        if r and r.status_code == 200:
            d = r.json()
            print(f"  \033[96m[GEO]\033[0m {d.get('city','?')}, {d.get('region','?')}, {d.get('country','?')}")
            print(f"  \033[96m[ORG]\033[0m {d.get('org','?')}")
            save(conn, "domain", domain, "IPInfo", json.dumps(d), "found")
    except Exception as e:
        print(f"  [IP] {e}")

    # Wayback Machine
    r = get(f"https://archive.org/wayback/available?url={domain}")
    if r and r.status_code == 200:
        snap = r.json().get("archived_snapshots", {}).get("closest", {})
        if snap.get("available"):
            print(f"  \033[96m[WBM]\033[0m Last snapshot: {snap.get('timestamp','?')}")
            print(f"       {snap.get('url','')}")
            save(conn, "domain", domain, "Wayback", snap.get("url",""), "found")

    # crt.sh subdomains
    r = get(f"https://crt.sh/?q=%.{domain}&output=json")
    if r and r.status_code == 200:
        try:
            certs = r.json()
            subs = sorted(set(
                c.get("name_value","").replace("*.","")
                for c in certs
                if domain in c.get("name_value","")
            ))[:20]
            if subs:
                print(f"\n  \033[96m[SUBS]\033[0m {len(subs)} subdomain(s) from crt.sh:")
                for s in subs:
                    print(f"       · {s}")
                save(conn, "domain", domain, "crt.sh", json.dumps(subs), "found")
        except Exception:
            pass

# ─── IP ────────────────────────────────────────────────────────────────────────

def search_ip(conn, ip):
    print(f"\n\033[96m[*] IP: {ip}\033[0m")
    print("─" * 55)
    r = get(f"https://ipinfo.io/{ip}/json")
    if r and r.status_code == 200:
        d = r.json()
        for k in ["ip","hostname","city","region","country","org","timezone","loc","postal"]:
            if d.get(k):
                print(f"  \033[92m[{k.upper():<10}]\033[0m {d[k]}")
        save(conn, "ip", ip, "IPInfo", json.dumps(d), "found")

    # Shodan InternetDB (free, no key)
    r2 = get(f"https://internetdb.shodan.io/{ip}")
    if r2 and r2.status_code == 200:
        d2 = r2.json()
        ports = d2.get("ports", [])
        vulns = d2.get("vulns", [])
        tags  = d2.get("tags", [])
        if ports:
            print(f"  \033[93m[PORTS]\033[0m {', '.join(str(p) for p in ports)}")
        if vulns:
            print(f"  \033[91m[VULNS]\033[0m {', '.join(vulns[:10])}")
        if tags:
            print(f"  \033[96m[TAGS] \033[0m {', '.join(tags)}")
        save(conn, "ip", ip, "Shodan-InternetDB", json.dumps(d2), "found")

# ─── PHONE ─────────────────────────────────────────────────────────────────────

def search_phone(conn, phone):
    clean = re.sub(r"[^\d+]", "", phone)
    print(f"\n\033[96m[*] Phone: {clean}\033[0m")
    print("─" * 55)
    r = get(f"https://phonevalidation.abstractapi.com/v1/?phone={clean}")
    if r and r.status_code == 200:
        try:
            d = r.json()
            print(f"  [VALID]   {d.get('valid','?')}")
            print(f"  [FORMAT]  {d.get('format',{}).get('international','?')}")
            print(f"  [COUNTRY] {d.get('country',{}).get('name','?')}")
            print(f"  [TYPE]    {d.get('type','?')}")
            print(f"  [CARRIER] {d.get('carrier','?')}")
            save(conn, "phone", clean, "AbstractAPI", json.dumps(d), "found")
            return
        except Exception:
            pass
    # fallback manual parse
    cc = clean[:3] if clean.startswith("+") else "?"
    print(f"  [NUMBER]  {clean}")
    print(f"  [CC]      {cc}")
    print(f"  \033[93m[~] Full carrier lookup needs an API key (AbstractAPI/Numverify)\033[0m")
    save(conn, "phone", clean, "manual", clean, "info")

# ─── HISTORY ───────────────────────────────────────────────────────────────────

def view_history(conn):
    rows = history(conn)
    if not rows:
        print("\n  No searches yet."); return
    print(f"\n  {'Time':<20} {'Type':<10} {'Query':<25} {'Source':<16} Status")
    print("  " + "─"*80)
    for ts, kind, query, source, status in rows:
        color = "\033[92m" if status=="found" else "\033[91m" if status=="not_found" else "\033[93m"
        print(f"  {ts[:19]:<20} {kind:<10} {query[:24]:<25} {source[:15]:<16} {color}{status}\033[0m")

# ─── MAIN ──────────────────────────────────────────────────────────────────────

BANNER = """\033[91m
  ╔══════════════════════════════════════╗
  ║   OSINT REAPER  v1.0                 ║
  ║   passive recon · SQLite storage     ║
  ╚══════════════════════════════════════╝\033[0m
"""

MENU = """
  \033[96m[1]\033[0m Username search    (19 platforms)
  \033[96m[2]\033[0m Email recon        (Gravatar · HIBP · MX)
  \033[96m[3]\033[0m Domain recon       (DNS · GeoIP · crt.sh · Wayback)
  \033[96m[4]\033[0m IP lookup          (IPInfo · Shodan InternetDB)
  \033[96m[5]\033[0m Phone recon
  \033[96m[6]\033[0m View history
  \033[96m[0]\033[0m Exit
"""

def main():
    print(BANNER)
    conn = init_db()
    print(f"  DB → {DB_PATH}\n")
    while True:
        print(MENU)
        choice = input("  > ").strip()
        if   choice == "0": print("\n  bye 👁️\n"); break
        elif choice == "1":
            u = input("  Username: ").strip()
            if u: search_username(conn, u)
        elif choice == "2":
            e = input("  Email: ").strip()
            if e: search_email(conn, e)
        elif choice == "3":
            d = input("  Domain: ").strip()
            if d: search_domain(conn, d)
        elif choice == "4":
            ip = input("  IP: ").strip()
            if ip: search_ip(conn, ip)
        elif choice == "5":
            p = input("  Phone (+33612345678): ").strip()
            if p: search_phone(conn, p)
        elif choice == "6":
            view_history(conn)
        else:
            print("  [?] choix invalide")

if __name__ == "__main__":
    main()
