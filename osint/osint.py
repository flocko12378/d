#!/usr/bin/env python3
"""
OSINT Reaper v2.0 — real database searches
Sources: COMB/ProxyNova, BreachDirectory, LeakCheck, Shodan InternetDB,
         crt.sh, HackerTarget, IPInfo, Gravatar, DNS, Wayback
pip install -r requirements.txt
python osint.py
"""

import sqlite3, requests, socket, json, re, os, hashlib, time
from datetime import datetime
import dns.resolver

import warnings
warnings.filterwarnings("ignore")
requests.packages.urllib3.disable_warnings()

# ─── CONFIG ────────────────────────────────────────────────────────────────────
# Put your API keys here for premium sources (optional — free sources work without)

CFG_PATH = os.path.join(os.path.dirname(__file__), "config.json")
DEFAULT_CFG = {
    "hibp_api_key":       "",   # https://haveibeenpwned.com/API/Key  ($3.50/mo)
    "dehashed_user":      "",   # https://dehashed.com  ($5/mo)
    "dehashed_key":       "",
    "leakcheck_key":      "",   # https://leakcheck.io  (free tier available)
    "shodan_key":         "",   # https://shodan.io     (free tier available)
    "abuseipdb_key":      "",   # https://www.abuseipdb.com
    "virustotal_key":     "",   # https://www.virustotal.com
    "hackertarget_key":   "",   # https://hackertarget.com (free tier = 100/day)
}

def load_cfg():
    if os.path.exists(CFG_PATH):
        with open(CFG_PATH) as f:
            return {**DEFAULT_CFG, **json.load(f)}
    with open(CFG_PATH, "w") as f:
        json.dump(DEFAULT_CFG, f, indent=2)
    print(f"\n  [!] config.json créé → {CFG_PATH}")
    print(f"  [!] Remplis les API keys pour les sources premium\n")
    return DEFAULT_CFG

CFG = load_cfg()

# ─── DB ────────────────────────────────────────────────────────────────────────

DB_PATH = os.path.join(os.path.dirname(__file__), "osint_results.db")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS results (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            ts      TEXT,
            kind    TEXT,
            query   TEXT,
            source  TEXT,
            data    TEXT,
            status  TEXT
        )
    """)
    conn.commit()
    return conn

def save(conn, kind, query, source, data, status):
    conn.execute(
        "INSERT INTO results (ts,kind,query,source,data,status) VALUES (?,?,?,?,?,?)",
        (datetime.now().isoformat(), kind, query, source, json.dumps(data, default=str), status)
    )
    conn.commit()

def history(conn, limit=30):
    return conn.execute(
        "SELECT ts,kind,query,source,status FROM results ORDER BY id DESC LIMIT ?",
        (limit,)
    ).fetchall()

def export_query(conn, query):
    rows = conn.execute(
        "SELECT ts,kind,source,data,status FROM results WHERE query=? ORDER BY id",
        (query,)
    ).fetchall()
    out = []
    for ts, kind, source, data, status in rows:
        try: data = json.loads(data)
        except: pass
        out.append({"ts":ts,"kind":kind,"source":source,"data":data,"status":status})
    path = os.path.join(os.path.dirname(__file__), f"export_{query.replace('@','_').replace('.','_')}.json")
    with open(path, "w") as f:
        json.dump(out, f, indent=2, default=str)
    return path

# ─── HTTP ──────────────────────────────────────────────────────────────────────

S = requests.Session()
S.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
S.verify = False

def get(url, **kw):
    try:
        r = S.get(url, timeout=10, **kw)
        time.sleep(0.3)   # rate limit courtesy
        return r
    except Exception as e:
        return None

def post(url, **kw):
    try:
        r = S.post(url, timeout=10, **kw)
        time.sleep(0.3)
        return r
    except Exception:
        return None

# ─── COLORS ────────────────────────────────────────────────────────────────────

G = "\033[92m"   # green
R = "\033[91m"   # red
Y = "\033[93m"   # yellow
C = "\033[96m"   # cyan
W = "\033[0m"    # reset
B = "\033[1m"    # bold

def tag(color, label, text):
    w = 12
    return f"  {color}[{label:<{w}}]{W} {text}"

# ══════════════════════════════════════════════════════════════════════════════
#  EMAIL RECON
# ══════════════════════════════════════════════════════════════════════════════

def recon_email(conn, email):
    print(f"\n{C}{B}[EMAIL] {email}{W}")
    print("─" * 60)

    # ── 1. COMB dataset via ProxyNova (FREE, no key, searches 3.2B records) ──
    print(tag(C, "COMB/ProxyNova", "searching 3.2B leaked records..."))
    r = get(f"https://api.proxynova.com/comb?query={email}&start=0&limit=10")
    if r and r.status_code == 200:
        try:
            d = r.json()
            total = d.get("count", 0)
            lines = d.get("lines", [])
            if total > 0:
                print(tag(R, "COMB", f"FOUND — {total} leak(s) matching this email:"))
                for line in lines[:10]:
                    # lines are "email:password" or "email:hash"
                    print(f"           → {line}")
                save(conn, "email", email, "COMB", {"count": total, "lines": lines}, "found")
            else:
                print(tag(G, "COMB", "Not found in COMB dataset"))
                save(conn, "email", email, "COMB", {}, "not_found")
        except Exception as e:
            print(tag(Y, "COMB", f"Parse error: {e}"))
    else:
        print(tag(Y, "COMB", f"API unavailable ({r.status_code if r else 'timeout'})"))

    # ── 2. BreachDirectory (FREE public API) ──────────────────────────────────
    print(tag(C, "BreachDirectory", "checking..."))
    r2 = get(
        f"https://breachdirectory.org/api",
        params={"func": "auto", "term": email},
        headers={"x-functions-key": ""}
    )
    # BreachDirectory also has a RapidAPI endpoint
    r2b = get(
        "https://breachdirectory.p.rapidapi.com/",
        params={"func": "auto", "term": email},
        headers={
            "X-RapidAPI-Key": "SIGN-UP-FOR-KEY",
            "X-RapidAPI-Host": "breachdirectory.p.rapidapi.com"
        }
    )
    found_bd = False
    for resp, label in [(r2, "BreachDir"), (r2b, "BreachDir/Rapid")]:
        if resp and resp.status_code == 200:
            try:
                d = resp.json()
                if d.get("success") and d.get("result"):
                    results = d["result"]
                    print(tag(R, label, f"FOUND — {len(results)} entry(ies):"))
                    for entry in results[:8]:
                        src   = entry.get("sources","?")
                        hsh   = entry.get("password","?")
                        plain = entry.get("plain_text","")
                        line  = f"hash={hsh}"
                        if plain: line += f"  plain={plain}"
                        line += f"  source={src}"
                        print(f"           → {line}")
                    save(conn, "email", email, label, results, "found")
                    found_bd = True
                    break
            except Exception:
                pass
    if not found_bd:
        print(tag(G, "BreachDirectory", "Not found (or API key needed for full access)"))

    # ── 3. LeakCheck public API (FREE tier: 1 check/day per IP) ──────────────
    print(tag(C, "LeakCheck", "checking..."))
    lc_params = {"check": email, "type": "email"}
    if CFG["leakcheck_key"]:
        lc_params["key"] = CFG["leakcheck_key"]
    r3 = get("https://leakcheck.io/api/public", params=lc_params)
    if r3 and r3.status_code == 200:
        try:
            d = r3.json()
            if d.get("success"):
                found_count = d.get("found", 0)
                sources     = d.get("sources", [])
                if found_count > 0:
                    print(tag(R, "LeakCheck", f"FOUND in {found_count} source(s):"))
                    for src in sources[:10]:
                        print(f"           → {src.get('name','?')} ({src.get('date','?')})"
                              f"  fields: {', '.join(src.get('fields',[]))}")
                    save(conn, "email", email, "LeakCheck", sources, "found")
                else:
                    print(tag(G, "LeakCheck", "Not found"))
                    save(conn, "email", email, "LeakCheck", {}, "not_found")
            else:
                print(tag(Y, "LeakCheck", d.get("error","unknown error")))
        except Exception as e:
            print(tag(Y, "LeakCheck", str(e)))
    else:
        print(tag(Y, "LeakCheck", f"Unavailable ({r3.status_code if r3 else 'timeout'})"))

    # ── 4. HaveIBeenPwned (needs $3.50/mo key for full data) ──────────────────
    print(tag(C, "HIBP", "checking..."))
    hibp_headers = {"User-Agent": "osint-reaper"}
    if CFG["hibp_api_key"]:
        hibp_headers["hibp-api-key"] = CFG["hibp_api_key"]
    r4 = get(
        f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
        headers=hibp_headers
    )
    if r4 and r4.status_code == 200:
        breaches = r4.json()
        print(tag(R, "HIBP", f"PWNED — {len(breaches)} breach(es):"))
        for b in breaches[:10]:
            print(f"           → {b.get('Name','?')} ({b.get('BreachDate','?')}) "
                  f"— {b.get('PwnCount',0):,} accounts")
        save(conn, "email", email, "HIBP", breaches, "found")
    elif r4 and r4.status_code == 404:
        print(tag(G, "HIBP", "Not found in known breaches"))
        save(conn, "email", email, "HIBP", {}, "not_found")
    elif r4 and r4.status_code == 401:
        print(tag(Y, "HIBP", "API key required → config.json → hibp_api_key"))
    else:
        print(tag(Y, "HIBP", f"Unavailable ({r4.status_code if r4 else 'timeout'})"))

    # ── 5. Dehashed (premium — email:password in plaintext) ───────────────────
    if CFG["dehashed_user"] and CFG["dehashed_key"]:
        print(tag(C, "Dehashed", "searching plaintext passwords..."))
        r5 = get(
            "https://api.dehashed.com/search",
            params={"query": f"email:{email}", "size": 10},
            auth=(CFG["dehashed_user"], CFG["dehashed_key"])
        )
        if r5 and r5.status_code == 200:
            try:
                d = r5.json()
                entries = d.get("entries", [])
                total   = d.get("total", 0)
                if entries:
                    print(tag(R, "Dehashed", f"FOUND — {total} total record(s):"))
                    for e in entries[:8]:
                        pwd  = e.get("password","")
                        hash_ = e.get("hashed_password","")
                        src  = e.get("database_name","?")
                        line = f"src={src}"
                        if pwd:   line += f"  pass={pwd}"
                        if hash_: line += f"  hash={hash_[:32]}..."
                        print(f"           → {line}")
                    save(conn, "email", email, "Dehashed", entries, "found")
                else:
                    print(tag(G, "Dehashed", "Not found"))
            except Exception as e:
                print(tag(Y, "Dehashed", str(e)))
    else:
        print(tag(Y, "Dehashed", "Skip (add dehashed_user + dehashed_key in config.json for plaintext passwords)"))

    # ── 6. Gravatar ───────────────────────────────────────────────────────────
    h = hashlib.md5(email.strip().lower().encode()).hexdigest()
    r6 = get(f"https://www.gravatar.com/{h}.json")
    if r6 and r6.status_code == 200:
        try:
            entry = r6.json().get("entry", [{}])[0]
            print(tag(G, "Gravatar", f"Profile → displayName={entry.get('displayName','?')}"))
            print(f"           URL: https://gravatar.com/{h}")
            save(conn, "email", email, "Gravatar", entry, "found")
        except Exception:
            pass
    else:
        print(tag(W, "Gravatar", "No profile"))

    # ── 7. MX / domain info ───────────────────────────────────────────────────
    domain = email.split("@")[-1]
    print(tag(C, "DNS", f"MX for {domain}:"))
    try:
        mxs = dns.resolver.resolve(domain, "MX")
        for mx in mxs:
            print(f"           → {mx.exchange} (prio {mx.preference})")
        save(conn, "email", email, "DNS-MX", [str(m.exchange) for m in mxs], "found")
    except Exception as e:
        print(f"           {e}")

# ══════════════════════════════════════════════════════════════════════════════
#  USERNAME SEARCH
# ══════════════════════════════════════════════════════════════════════════════

PLATFORMS = {
    "GitHub":      ("https://github.com/{}", [404]),
    "GitLab":      ("https://gitlab.com/{}", [404]),
    "Twitter/X":   ("https://x.com/{}", []),
    "Instagram":   ("https://www.instagram.com/{}/", []),
    "TikTok":      ("https://www.tiktok.com/@{}", []),
    "Reddit":      ("https://www.reddit.com/user/{}/about.json", [404]),
    "Twitch":      ("https://www.twitch.tv/{}", []),
    "YouTube":     ("https://www.youtube.com/@{}", []),
    "Steam":       ("https://steamcommunity.com/id/{}", []),
    "Pinterest":   ("https://www.pinterest.com/{}/", [404]),
    "Keybase":     ("https://keybase.io/{}", [404]),
    "Medium":      ("https://medium.com/@{}", [404]),
    "Dev.to":      ("https://dev.to/{}", [404]),
    "HackerOne":   ("https://hackerone.com/{}", [404]),
    "Bugcrowd":    ("https://bugcrowd.com/{}", [404]),
    "Replit":      ("https://replit.com/@{}", [404]),
    "Codepen":     ("https://codepen.io/{}", [404]),
    "Pastebin":    ("https://pastebin.com/u/{}", [404]),
    "DockerHub":   ("https://hub.docker.com/u/{}", [404]),
    "NPM":         ("https://www.npmjs.com/~{}", [404]),
    "PyPI":        ("https://pypi.org/user/{}/", [404]),
}

NOT_FOUND_BODY = [
    "not found","page not found","doesn't exist","user not found",
    "this page doesn't exist","sorry, this page","profile not found",
    "n'existe pas","404","user doesn't exist","aucun résultat"
]

def recon_username(conn, username):
    print(f"\n{C}{B}[USERNAME] {username}{W}")
    print("─" * 60)

    # Also search COMB for username:password combos
    print(tag(C, "COMB", f"searching leaked creds with username '{username}'..."))
    r = get(f"https://api.proxynova.com/comb?query={username}&start=0&limit=10")
    if r and r.status_code == 200:
        try:
            d = r.json()
            total = d.get("count", 0)
            lines = d.get("lines", [])
            # filter lines that contain this username (not just partial matches)
            hits = [l for l in lines if username.lower() in l.split(":")[0].lower()]
            if hits:
                print(tag(R, "COMB", f"FOUND — {total} record(s) (showing username matches):"))
                for line in hits[:8]:
                    print(f"           → {line}")
                save(conn, "username", username, "COMB", {"count":total,"lines":hits}, "found")
            elif total > 0:
                print(tag(Y, "COMB", f"{total} partial match(es) — not exact username"))
            else:
                print(tag(G, "COMB", "Not found in COMB"))
                save(conn, "username", username, "COMB", {}, "not_found")
        except Exception:
            pass
    else:
        print(tag(Y, "COMB", "Unavailable"))

    # Platform check
    print()
    found = []
    for platform, (tpl, bad_codes) in PLATFORMS.items():
        url = tpl.format(username)
        r = get(url, allow_redirects=True)
        if r is None:
            sym, color, status = "?", Y, "error"
        elif r.status_code in bad_codes:
            sym, color, status = "✗", R, "not_found"
        elif r.status_code == 200:
            body = r.text.lower()
            if any(x in body for x in NOT_FOUND_BODY):
                sym, color, status = "✗", R, "not_found"
            else:
                sym, color, status = "✓", G, "found"
                found.append(url)
        else:
            sym, color, status = f"{r.status_code}", Y, f"http_{r.status_code}"
        print(f"  {color}[{sym}]{W} {platform:<14} {url}")
        save(conn, "username", username, platform, url, status)

    print(f"\n  {G}→ {len(found)} profile(s) confirmed{W}")
    if found:
        for u in found:
            print(f"     · {u}")

# ══════════════════════════════════════════════════════════════════════════════
#  DOMAIN RECON
# ══════════════════════════════════════════════════════════════════════════════

def recon_domain(conn, domain):
    domain = domain.strip().removeprefix("https://").removeprefix("http://").split("/")[0]
    print(f"\n{C}{B}[DOMAIN] {domain}{W}")
    print("─" * 60)

    # DNS full record dump
    print(tag(C, "DNS", "resolving records..."))
    for rtype in ["A","AAAA","MX","NS","TXT","CNAME","SOA"]:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            vals    = [str(a) for a in answers]
            print(f"  {G}[{rtype:<5}]{W} {', '.join(vals[:4])}")
            save(conn, "domain", domain, f"DNS-{rtype}", vals, "found")
        except Exception:
            pass

    # IP + GeoIP
    try:
        ip = socket.gethostbyname(domain)
        print(f"\n  {C}[IP]{W}     {ip}")
        r = get(f"https://ipinfo.io/{ip}/json")
        if r and r.status_code == 200:
            d = r.json()
            print(tag(G, "GeoIP", f"{d.get('city','?')}, {d.get('region','?')}, {d.get('country','?')}"))
            print(tag(G, "ASN/ORG", d.get("org","?")))
            save(conn, "domain", domain, "IPInfo", d, "found")
    except Exception as e:
        print(tag(Y, "IP", str(e)))

    # Shodan InternetDB (free, no key needed)
    try:
        ip = socket.gethostbyname(domain)
        r = get(f"https://internetdb.shodan.io/{ip}")
        if r and r.status_code == 200:
            d = r.json()
            ports = d.get("ports", [])
            vulns = d.get("vulns", [])
            hostnames = d.get("hostnames", [])
            cpes  = d.get("cpes", [])
            if ports:    print(tag(Y,  "Open ports", ", ".join(str(p) for p in ports)))
            if hostnames:print(tag(C,  "Hostnames",  ", ".join(hostnames[:5])))
            if cpes:     print(tag(C,  "CPEs",       ", ".join(cpes[:3])))
            if vulns:
                print(tag(R, "CVEs", f"{len(vulns)} CVE(s) found:"))
                for v in vulns[:8]:
                    print(f"           → {v}")
            save(conn, "domain", domain, "Shodan-InternetDB", d, "found" if ports else "info")
    except Exception:
        pass

    # Full Shodan search (if key provided)
    if CFG["shodan_key"]:
        r = get(
            f"https://api.shodan.io/shodan/host/{ip}",
            params={"key": CFG["shodan_key"]}
        )
        if r and r.status_code == 200:
            d = r.json()
            print(tag(C, "Shodan", f"OS={d.get('os','?')} tags={d.get('tags',[])}"))
            for svc in d.get("data", [])[:5]:
                port = svc.get("port","?")
                prod = svc.get("product","?")
                ver  = svc.get("version","")
                print(f"           → port {port}: {prod} {ver}")
            save(conn, "domain", domain, "Shodan-Full", d.get("data",[])[:10], "found")

    # crt.sh — subdomains from certificate transparency
    print(tag(C, "crt.sh", "enumerating subdomains..."))
    r = get(f"https://crt.sh/?q=%.{domain}&output=json")
    if r and r.status_code == 200:
        try:
            certs = r.json()
            subs = sorted(set(
                name
                for c in certs
                for name in c.get("name_value","").split("\n")
                if domain in name and not name.startswith("*")
            ))
            if subs:
                print(tag(G, "Subdomains", f"{len(subs)} found:"))
                for s in subs[:20]:
                    print(f"           · {s}")
                save(conn, "domain", domain, "crt.sh", subs, "found")
        except Exception:
            pass

    # HackerTarget — DNS brute + zone transfer attempt
    print(tag(C, "HackerTarget", "DNS lookup..."))
    ht_url = f"https://api.hackertarget.com/dnslookup/?q={domain}"
    if CFG["hackertarget_key"]:
        ht_url += f"&apikey={CFG['hackertarget_key']}"
    r = get(ht_url)
    if r and r.status_code == 200 and "error" not in r.text.lower():
        print(tag(G, "HackerTarget", "DNS records:"))
        for line in r.text.strip().split("\n")[:15]:
            print(f"           {line}")
        save(conn, "domain", domain, "HackerTarget-DNS", r.text, "found")

    # Wayback Machine
    r = get(f"https://archive.org/wayback/available?url={domain}")
    if r and r.status_code == 200:
        snap = r.json().get("archived_snapshots",{}).get("closest",{})
        if snap.get("available"):
            print(tag(C, "Wayback", f"Last snapshot: {snap.get('timestamp','?')}"))
            print(f"           {snap.get('url','')}")
            save(conn, "domain", domain, "Wayback", snap, "found")

    # VirusTotal (if key)
    if CFG["virustotal_key"]:
        r = get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={"x-apikey": CFG["virustotal_key"]}
        )
        if r and r.status_code == 200:
            d = r.json().get("data",{}).get("attributes",{})
            rep   = d.get("reputation", 0)
            cats  = d.get("categories",{})
            stats = d.get("last_analysis_stats",{})
            malicious = stats.get("malicious",0)
            if malicious > 0:
                print(tag(R, "VirusTotal", f"MALICIOUS — {malicious} engine(s) flagged | rep={rep}"))
            else:
                print(tag(G, "VirusTotal", f"Clean — rep={rep} | cats={list(cats.values())[:3]}"))
            save(conn, "domain", domain, "VirusTotal", {"reputation":rep,"stats":stats}, "found")

# ══════════════════════════════════════════════════════════════════════════════
#  IP RECON
# ══════════════════════════════════════════════════════════════════════════════

def recon_ip(conn, ip):
    print(f"\n{C}{B}[IP] {ip}{W}")
    print("─" * 60)

    # IPInfo
    r = get(f"https://ipinfo.io/{ip}/json")
    if r and r.status_code == 200:
        d = r.json()
        for k in ["ip","hostname","city","region","country","org","timezone","loc","postal"]:
            if d.get(k):
                print(tag(G, k.upper(), d[k]))
        save(conn, "ip", ip, "IPInfo", d, "found")

    # Shodan InternetDB (free)
    r = get(f"https://internetdb.shodan.io/{ip}")
    if r and r.status_code == 200:
        d = r.json()
        ports = d.get("ports",[])
        vulns = d.get("vulns",[])
        tags_ = d.get("tags",[])
        cpes  = d.get("cpes",[])
        if ports:  print(tag(Y, "OPEN PORTS", ", ".join(str(p) for p in ports)))
        if cpes:   print(tag(C, "CPEs",       ", ".join(cpes[:4])))
        if tags_:  print(tag(C, "TAGS",       ", ".join(tags_)))
        if vulns:
            print(tag(R, "CVEs", f"{len(vulns)} vulnerability(ies):"))
            for v in vulns[:10]:
                print(f"           → {v}")
        save(conn, "ip", ip, "Shodan-InternetDB", d, "found")

    # AbuseIPDB (free 1000 checks/day with key)
    if CFG["abuseipdb_key"]:
        r = get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": CFG["abuseipdb_key"], "Accept": "application/json"}
        )
        if r and r.status_code == 200:
            d = r.json().get("data",{})
            score   = d.get("abuseConfidenceScore",0)
            reports = d.get("totalReports",0)
            isp     = d.get("isp","?")
            color   = R if score > 25 else G
            print(tag(color, "AbuseIPDB", f"Score={score}/100 | Reports={reports} | ISP={isp}"))
            save(conn, "ip", ip, "AbuseIPDB", d, "found" if score>0 else "clean")
    else:
        print(tag(Y, "AbuseIPDB", "Add abuseipdb_key in config.json for abuse reports"))

    # GreyNoise (free community API)
    r = get(
        f"https://api.greynoise.io/v3/community/{ip}",
        headers={"key": ""}
    )
    if r and r.status_code == 200:
        d = r.json()
        noise  = d.get("noise", False)
        riot   = d.get("riot", False)
        name   = d.get("name","?")
        cl     = d.get("classification","?")
        color  = R if noise and cl == "malicious" else G
        print(tag(color, "GreyNoise", f"noise={noise} | classification={cl} | name={name} | riot={riot}"))
        save(conn, "ip", ip, "GreyNoise", d, "found")
    else:
        print(tag(Y, "GreyNoise", "Free community check unavailable"))

    # VirusTotal IP
    if CFG["virustotal_key"]:
        r = get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": CFG["virustotal_key"]}
        )
        if r and r.status_code == 200:
            d   = r.json().get("data",{}).get("attributes",{})
            rep = d.get("reputation",0)
            stats = d.get("last_analysis_stats",{})
            mal   = stats.get("malicious",0)
            color = R if mal > 0 else G
            print(tag(color, "VirusTotal", f"rep={rep} | malicious={mal}/{sum(stats.values())} engines"))
            save(conn, "ip", ip, "VirusTotal", {"rep":rep,"stats":stats}, "found")

# ══════════════════════════════════════════════════════════════════════════════
#  HISTORY + EXPORT
# ══════════════════════════════════════════════════════════════════════════════

def view_history(conn):
    rows = history(conn)
    if not rows:
        print("\n  Aucun résultat."); return
    print(f"\n  {'Time':<20} {'Type':<10} {'Query':<28} {'Source':<18} Status")
    print("  " + "─"*85)
    for ts, kind, query, source, status in rows:
        color = G if status=="found" else R if status=="not_found" else Y
        print(f"  {ts[:19]:<20} {kind:<10} {query[:27]:<28} {source[:17]:<18} {color}{status}{W}")

# ══════════════════════════════════════════════════════════════════════════════
#  MAIN CLI
# ══════════════════════════════════════════════════════════════════════════════

BANNER = f"""{R}
  ╔══════════════════════════════════════════════╗
  ║   OSINT REAPER  v2.0                         ║
  ║   Real database recon · SQLite storage       ║
  ║                                              ║
  ║   Sources: COMB · BreachDir · LeakCheck      ║
  ║            Dehashed · HIBP · Shodan          ║
  ║            GreyNoise · VirusTotal · crt.sh   ║
  ╚══════════════════════════════════════════════╝{W}
"""

MENU = f"""
  {C}[1]{W} Email recon     (COMB · BreachDir · LeakCheck · Dehashed · HIBP)
  {C}[2]{W} Username search  (COMB + 21 platforms)
  {C}[3]{W} Domain recon     (DNS · Shodan · crt.sh · HackerTarget · VT)
  {C}[4]{W} IP lookup        (Shodan · AbuseIPDB · GreyNoise · VT)
  {C}[5]{W} View history
  {C}[6]{W} Export to JSON   (export all results for a query)
  {C}[7]{W} Edit config      (API keys)
  {C}[0]{W} Exit
"""

def edit_config():
    print(f"\n  Config: {CFG_PATH}")
    print(f"  Ouvre ce fichier dans un éditeur et ajoute tes API keys")
    print(f"\n  Sources gratuites (aucune clé requise):")
    print(f"    · COMB via ProxyNova (3.2B records)")
    print(f"    · LeakCheck (1 check/jour par IP)")
    print(f"    · Shodan InternetDB")
    print(f"    · crt.sh subdomains")
    print(f"    · GreyNoise community")
    print(f"    · HackerTarget DNS (100/jour)")
    print(f"\n  Sources premium (clés dans config.json):")
    print(f"    · HIBP — $3.50/mo — hibp_api_key")
    print(f"    · Dehashed — $5/mo — dehashed_user + dehashed_key  (plaintext passwords!)")
    print(f"    · Shodan — free tier — shodan_key")
    print(f"    · AbuseIPDB — free — abuseipdb_key")
    print(f"    · VirusTotal — free — virustotal_key")

def main():
    print(BANNER)
    conn = init_db()
    print(f"  {C}DB{W} → {DB_PATH}")
    print(f"  {C}CFG{W}→ {CFG_PATH}\n")

    while True:
        print(MENU)
        choice = input(f"  {C}>{W} ").strip()

        if choice == "0":
            print(f"\n  {G}bye 👁️{W}\n"); break

        elif choice == "1":
            q = input(f"  Email: ").strip()
            if q: recon_email(conn, q)

        elif choice == "2":
            q = input(f"  Username: ").strip()
            if q: recon_username(conn, q)

        elif choice == "3":
            q = input(f"  Domain (ex: example.com): ").strip()
            if q: recon_domain(conn, q)

        elif choice == "4":
            q = input(f"  IP: ").strip()
            if q: recon_ip(conn, q)

        elif choice == "5":
            view_history(conn)

        elif choice == "6":
            q = input(f"  Query à exporter: ").strip()
            if q:
                path = export_query(conn, q)
                print(f"\n  {G}Exporté → {path}{W}")

        elif choice == "7":
            edit_config()

        else:
            print(f"  {Y}[?] choix invalide{W}")

if __name__ == "__main__":
    main()
