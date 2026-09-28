#!/usr/bin/env python3
"""
discord_bot.py — OSINT search bot for Discord
Searches local breach DB + live APIs on command

pip install discord.py requests dnspython
Set BOT_TOKEN in config.json or env var DISCORD_BOT_TOKEN

Commands (in any channel the bot can read):
  !search <email>          — full email recon (breach DB + live APIs)
  !breach <email>          — local breach DB only
  !domain <domain>         — domain recon
  !ip <ip>                 — IP lookup
  !user <username>         — username platform check
  !stats                   — breach DB stats
  !help                    — show commands
"""

import discord, sqlite3, os, json, socket, hashlib, re, requests
from pathlib import Path
from datetime import datetime
from bs4 import BeautifulSoup
import dns.resolver
import warnings
warnings.filterwarnings("ignore")
requests.packages.urllib3.disable_warnings()

# ─── CONFIG ────────────────────────────────────────────────────────────────────

BASE    = Path(__file__).parent
DB_PATH = BASE / "breach.db"
CFG_PATH = BASE / "config.json"

def load_cfg():
    if CFG_PATH.exists():
        with open(CFG_PATH) as f:
            return json.load(f)
    return {}

CFG = load_cfg()
TOKEN = CFG.get("discord_bot_token") or os.environ.get("DISCORD_BOT_TOKEN", "")

# ─── BREACH DB ─────────────────────────────────────────────────────────────────

def get_db():
    if not DB_PATH.exists():
        return None
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def search_breach_db(email: str, limit=20):
    conn = get_db()
    if not conn:
        return [], "breach.db not found — run breach_loader.py import first"
    try:
        rows = conn.execute(
            "SELECT source, left_, right_ FROM records WHERE left_ = ? LIMIT ?",
            (email.lower(), limit)
        ).fetchall()
        total = conn.execute(
            "SELECT COUNT(*) FROM records WHERE left_ = ?",
            (email.lower(),)
        ).fetchone()[0]
        return rows, f"{total} total hit(s)"
    except Exception as e:
        return [], str(e)
    finally:
        conn.close()

def db_stats():
    conn = get_db()
    if not conn:
        return "breach.db not loaded"
    total = conn.execute("SELECT COUNT(*) FROM records").fetchone()[0]
    size  = DB_PATH.stat().st_size / (1024**3)
    sources = conn.execute(
        "SELECT source, COUNT(*) FROM records GROUP BY source ORDER BY 2 DESC LIMIT 5"
    ).fetchall()
    conn.close()
    lines = [f"**{total:,}** records  ({size:.2f} GB)"]
    for src, cnt in sources:
        lines.append(f"  · {src}: {cnt:,}")
    return "\n".join(lines)

# ─── LIVE APIs ─────────────────────────────────────────────────────────────────

S = requests.Session()
S.headers["User-Agent"] = "Mozilla/5.0"
S.verify = False

def safe_get(url, **kw):
    try:
        return S.get(url, timeout=8, **kw)
    except Exception:
        return None

def comb_search(query: str):
    r = safe_get(f"https://api.proxynova.com/comb?query={query}&start=0&limit=10")
    if r and r.status_code == 200:
        try:
            d    = r.json()
            cnt  = d.get("count", 0)
            lines = d.get("lines", [])
            return cnt, lines
        except Exception:
            pass
    return 0, []

def leakcheck_search(email: str):
    r = safe_get(f"https://leakcheck.io/api/public?check={email}&type=email")
    if r and r.status_code == 200:
        try:
            d = r.json()
            if d.get("success"):
                return d.get("found", 0), d.get("sources", [])
        except Exception:
            pass
    return 0, []

def gravatar_check(email: str):
    h = hashlib.md5(email.strip().lower().encode()).hexdigest()
    r = safe_get(f"https://www.gravatar.com/{h}.json")
    if r and r.status_code == 200:
        try:
            e = r.json().get("entry", [{}])[0]
            return e.get("displayName",""), f"https://gravatar.com/{h}"
        except Exception:
            pass
    return None, None

def ipinfo(ip: str):
    r = safe_get(f"https://ipinfo.io/{ip}/json")
    if r and r.status_code == 200:
        return r.json()
    return {}

def shodan_internetdb(ip: str):
    r = safe_get(f"https://internetdb.shodan.io/{ip}")
    if r and r.status_code == 200:
        return r.json()
    return {}

def _build_ugc_session():
    try:
        import cloudscraper
        s = cloudscraper.create_scraper(browser={"browser":"chrome","platform":"windows","mobile":False})
    except ImportError:
        s = requests.Session()
        s.verify = False
    s.headers.update({
        "User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124 Safari/537.36",
        "Accept-Language": "fr-FR,fr;q=0.9",
        "Referer":         "https://www.ugc.fr/",
        "Origin":          "https://www.ugc.fr",
    })
    return s

def _parse_csrf(html: str):
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

def check_ugc_reservation(reservation_number: str) -> dict:
    """Vérifie si une réservation UGC est valide. Retourne {valid, film, date, cinema, seats, raw}"""
    reservation_number = reservation_number.strip().upper()
    result = {"valid": None, "film": None, "date": None, "cinema": None, "seats": None, "raw": ""}

    UGC_URL   = "https://www.ugc.fr/reservation/retrieveBooking.html"
    ERROR_KW  = ["introuvable","invalid","not found","aucune","incorrect","erreur"]
    SUCCESS_KW = ["séance","votre billet","votre réservation","film","salle","places","montant"]

    try:
        sess = _build_ugc_session()
        # seed cookies + récupère CSRF token
        r1 = sess.get(UGC_URL, timeout=12)
        csrf_name, csrf_val = _parse_csrf(r1.text)

        payload = {"bookingNumber": reservation_number, "retrieveBooking": "true"}
        if csrf_name and csrf_val:
            payload[csrf_name] = csrf_val

        r = sess.post(UGC_URL, data=payload, timeout=12, allow_redirects=True)
        result["raw"] = r.status_code
        body = r.text
        low  = body.lower()

        if any(k in low for k in ERROR_KW):
            result["valid"] = False
            return result

        if any(k in low for k in SUCCESS_KW):
            result["valid"] = True
            soup = BeautifulSoup(body, "html.parser")
            for cls_pat, key in [
                (r"film|movie|title",         "film"),
                (r"date|seance|session",       "date"),
                (r"cinema|theater|venue|lieu", "cinema"),
                (r"place|seat|ticket",         "seats"),
            ]:
                el = soup.find(class_=re.compile(cls_pat, re.I))
                if el:
                    result[key] = el.get_text(strip=True)[:80]
            if not result["film"]:
                t = soup.find("title")
                if t:
                    result["film"] = t.get_text(strip=True)[:80]
            return result

        soup  = BeautifulSoup(body, "html.parser")
        texts = [t.strip() for t in soup.stripped_strings if len(t.strip()) > 15][:5]
        result["raw"] = f"HTTP {r.status_code} — " + " | ".join(texts)
        return result

    except Exception as e:
        result["raw"] = str(e)
        return result

def crtsh_subdomains(domain: str):
    r = safe_get(f"https://crt.sh/?q=%.{domain}&output=json")
    if r and r.status_code == 200:
        try:
            certs = r.json()
            subs = sorted(set(
                name
                for c in certs
                for name in c.get("name_value","").split("\n")
                if domain in name and not name.startswith("*")
            ))
            return subs
        except Exception:
            pass
    return []

# ─── PLATFORMS ─────────────────────────────────────────────────────────────────

PLATFORMS = [
    ("GitHub",   "https://github.com/{}",       [404]),
    ("GitLab",   "https://gitlab.com/{}",        [404]),
    ("Reddit",   "https://reddit.com/user/{}/about.json", [404]),
    ("HackerOne","https://hackerone.com/{}",     [404]),
    ("Bugcrowd", "https://bugcrowd.com/{}",      [404]),
    ("Replit",   "https://replit.com/@{}",       [404]),
    ("Dev.to",   "https://dev.to/{}",            [404]),
    ("Keybase",  "https://keybase.io/{}",        [404]),
    ("Medium",   "https://medium.com/@{}",       [404]),
    ("Twitch",   "https://twitch.tv/{}",         []),
]
NOT_FOUND_BODY = ["not found","doesn't exist","user not found","no user","404","page not found"]

def check_username(username: str):
    found = []
    for platform, tpl, bad_codes in PLATFORMS:
        url = tpl.format(username)
        r   = safe_get(url, allow_redirects=True)
        if not r:
            continue
        if r.status_code in bad_codes:
            continue
        if r.status_code == 200:
            body = r.text.lower()
            if not any(x in body for x in NOT_FOUND_BODY):
                found.append((platform, url))
    return found

# ─── DISCORD BOT ───────────────────────────────────────────────────────────────

intents = discord.Intents.default()
intents.message_content = True
client  = discord.Client(intents=intents)

PREFIX = "!"

def chunk(text: str, size=1990):
    """Split long text into Discord-safe chunks."""
    return [text[i:i+size] for i in range(0, len(text), size)]

async def send(channel, text: str):
    for part in chunk(text):
        await channel.send(f"```\n{part}\n```")

@client.event
async def on_ready():
    print(f"[BOT] Logged in as {client.user} — prefix: {PREFIX}")

@client.event
async def on_message(msg: discord.Message):
    if msg.author.bot:
        return
    if not msg.content.startswith(PREFIX):
        return

    parts = msg.content[len(PREFIX):].strip().split(None, 1)
    if not parts:
        return
    cmd  = parts[0].lower()
    args = parts[1].strip() if len(parts) > 1 else ""

    # ── !help ───────────────────────────────────────────────────────────────
    if cmd == "help":
        await msg.channel.send(
            "**OSINT Reaper Bot**\n"
            "`!search <email>` — full recon (local DB + COMB + LeakCheck + Gravatar)\n"
            "`!breach <email>` — local breach DB only\n"
            "`!domain <domain>` — DNS, subdomains, Shodan\n"
            "`!ip <ip>` — IP geolocation + Shodan + open ports\n"
            "`!user <username>` — check 10 platforms\n"
            "`!check ugc <numero>` — vérifie si une réservation UGC est valide\n"
            "`!stats` — breach DB statistics\n"
        )

    # ── !stats ──────────────────────────────────────────────────────────────
    elif cmd == "stats":
        await msg.channel.send(f"**Breach DB stats**\n{db_stats()}")

    # ── !breach <email> ─────────────────────────────────────────────────────
    elif cmd == "breach":
        if not args:
            await msg.channel.send("Usage: `!breach <email>`"); return
        await msg.channel.send(f"🔍 Searching local DB for `{args}`...")
        rows, info = search_breach_db(args)
        if not rows:
            await msg.channel.send(f"✅ `{args}` — not found in local breach DB\n_{info}_")
        else:
            lines = [f"⚠️ **{len(rows)} result(s)** for `{args}` ({info})\n"]
            for source, left_, right_ in rows[:15]:
                lines.append(f"`{left_}:{right_}`  — _{source}_")
            await msg.channel.send("\n".join(lines))

    # ── !search <email> ─────────────────────────────────────────────────────
    elif cmd == "search":
        if not args:
            await msg.channel.send("Usage: `!search <email>`"); return
        email = args.lower()
        await msg.channel.send(f"🔍 Full recon on `{email}`...")

        out = [f"**OSINT Reaper — {email}**", f"_{datetime.now().strftime('%Y-%m-%d %H:%M')}_\n"]

        # Local breach DB
        rows, info = search_breach_db(email)
        if rows:
            out.append(f"🔴 **Local Breach DB** — {info}")
            for src, left_, right_ in rows[:10]:
                out.append(f"  `{left_}:{right_}`  _{src}_")
        else:
            out.append(f"✅ **Local Breach DB** — not found")

        # COMB
        cnt, lines = comb_search(email)
        if cnt > 0:
            out.append(f"\n🔴 **COMB** — {cnt} record(s):")
            for l in lines[:5]:
                out.append(f"  `{l}`")
        else:
            out.append(f"\n✅ **COMB** — not found")

        # LeakCheck
        lc_found, lc_sources = leakcheck_search(email)
        if lc_found > 0:
            out.append(f"\n🔴 **LeakCheck** — found in {lc_found} source(s):")
            for s in lc_sources[:5]:
                out.append(f"  · {s.get('name','?')} ({s.get('date','?')})")
        else:
            out.append(f"\n✅ **LeakCheck** — not found")

        # Gravatar
        grav_name, grav_url = gravatar_check(email)
        if grav_name:
            out.append(f"\n📸 **Gravatar** — {grav_name}\n  {grav_url}")
        else:
            out.append(f"\n❌ **Gravatar** — no profile")

        # MX
        domain = email.split("@")[-1]
        try:
            mxs = dns.resolver.resolve(domain, "MX")
            mx_str = ", ".join(str(r.exchange) for r in mxs)
            out.append(f"\n📧 **MX** — {mx_str}")
        except Exception:
            pass

        full = "\n".join(out)
        for part in chunk(full, 1900):
            await msg.channel.send(part)

    # ── !domain <domain> ────────────────────────────────────────────────────
    elif cmd == "domain":
        if not args:
            await msg.channel.send("Usage: `!domain <domain>`"); return
        domain = args.removeprefix("https://").removeprefix("http://").split("/")[0]
        await msg.channel.send(f"🔍 Domain recon: `{domain}`...")

        out = [f"**Domain: {domain}**\n"]

        # DNS
        dns_lines = []
        for rtype in ["A","MX","NS","TXT"]:
            try:
                answers = dns.resolver.resolve(domain, rtype)
                vals    = [str(a) for a in answers]
                dns_lines.append(f"  [{rtype}] {', '.join(vals[:3])}")
            except Exception:
                pass
        if dns_lines:
            out.append("**DNS:**\n" + "\n".join(dns_lines))

        # IP + Shodan
        try:
            ip = socket.gethostbyname(domain)
            out.append(f"\n**IP:** `{ip}`")
            geo = ipinfo(ip)
            if geo:
                out.append(f"  {geo.get('city','?')}, {geo.get('country','?')} — {geo.get('org','?')}")
            sho = shodan_internetdb(ip)
            if sho.get("ports"):
                out.append(f"  **Open ports:** {', '.join(str(p) for p in sho['ports'])}")
            if sho.get("vulns"):
                out.append(f"  🔴 **CVEs:** {', '.join(sho['vulns'][:5])}")
        except Exception as e:
            out.append(f"IP resolution failed: {e}")

        # Subdomains
        subs = crtsh_subdomains(domain)
        if subs:
            out.append(f"\n**Subdomains ({len(subs)}):**")
            for s in subs[:15]:
                out.append(f"  · {s}")

        full = "\n".join(out)
        for part in chunk(full, 1900):
            await msg.channel.send(part)

    # ── !ip <ip> ────────────────────────────────────────────────────────────
    elif cmd == "ip":
        if not args:
            await msg.channel.send("Usage: `!ip <ip>`"); return
        ip = args.strip()
        await msg.channel.send(f"🔍 IP lookup: `{ip}`...")

        out = [f"**IP: {ip}**\n"]
        geo = ipinfo(ip)
        if geo:
            for k in ["ip","hostname","city","region","country","org","timezone"]:
                if geo.get(k):
                    out.append(f"  **{k}:** {geo[k]}")

        sho = shodan_internetdb(ip)
        if sho.get("ports"):
            out.append(f"\n**Open ports:** `{', '.join(str(p) for p in sho['ports'])}`")
        if sho.get("cpes"):
            out.append(f"**CPEs:** {', '.join(sho['cpes'][:3])}")
        if sho.get("tags"):
            out.append(f"**Tags:** {', '.join(sho['tags'])}")
        if sho.get("vulns"):
            out.append(f"🔴 **CVEs ({len(sho['vulns'])}):** {', '.join(sho['vulns'][:6])}")

        await msg.channel.send("\n".join(out))

    # ── !check ugc <reservation_number> ─────────────────────────────────────
    elif cmd == "check":
        parts2 = args.lower().split(None, 1)
        if not parts2 or parts2[0] != "ugc":
            await msg.channel.send("Usage: `!check ugc <reservation_number>`\nEx: `!check ugc 33500063B071466134`")
            return
        if len(parts2) < 2:
            await msg.channel.send("Usage: `!check ugc <reservation_number>`")
            return
        raw_num = parts2[1].strip().upper()
        await msg.channel.send(f"🎟️ Checking UGC reservation `{raw_num}`...")

        res = check_ugc_reservation(raw_num)

        if res["valid"] is True:
            lines = [f"✅ **VALID** — `{raw_num}`"]
            if res["film"]:   lines.append(f"🎬 **Film:** {res['film']}")
            if res["date"]:   lines.append(f"📅 **Séance:** {res['date']}")
            if res["cinema"]: lines.append(f"📍 **Cinéma:** {res['cinema']}")
            if res["seats"]:  lines.append(f"💺 **Places:** {res['seats']}")
            await msg.channel.send("\n".join(lines))

        elif res["valid"] is False:
            await msg.channel.send(f"❌ **INVALID** — réservation `{raw_num}` non trouvée sur UGC")

        else:
            await msg.channel.send(
                f"❓ **Inconnu** — réponse ambiguë (HTTP {res['raw']})\n"
                f"UGC a peut-être changé son interface — vérifie manuellement sur ugc.fr"
            )

    # ── !user <username> ────────────────────────────────────────────────────
    elif cmd == "user":
        if not args:
            await msg.channel.send("Usage: `!user <username>`"); return
        username = args.strip()
        await msg.channel.send(f"🔍 Username check: `{username}`...")

        # COMB search
        cnt, lines = comb_search(username)
        comb_hits  = [l for l in lines if username.lower() in l.split(":")[0].lower()]

        found_platforms = check_username(username)

        out = [f"**Username: {username}**\n"]
        if comb_hits:
            out.append(f"🔴 **COMB leak** — {cnt} record(s):")
            for l in comb_hits[:5]:
                out.append(f"  `{l}`")
        else:
            out.append("✅ **COMB** — not found")

        out.append(f"\n**Platforms ({len(found_platforms)} found):**")
        for platform, url in found_platforms:
            out.append(f"  ✓ [{platform}]({url})")

        await msg.channel.send("\n".join(out))

# ─── ENTRY ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if not TOKEN:
        print("""
[!] No Discord bot token found.

1. Go to https://discord.com/developers/applications
2. Create a New Application → Bot → Reset Token → copy token
3. Add to config.json:
   {
     "discord_bot_token": "YOUR_TOKEN_HERE"
   }
4. Invite bot to your server:
   https://discord.com/api/oauth2/authorize?client_id=YOUR_APP_ID&permissions=2048&scope=bot
   (permissions: Send Messages, Read Message History)
5. python discord_bot.py
""")
    else:
        print(f"[BOT] Starting with token {TOKEN[:10]}...")
        client.run(TOKEN)
