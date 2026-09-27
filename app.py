#!/usr/bin/env python3
"""
WebReaper Pro v5 — Flask + engine maison
pip install requests beautifulsoup4 flask
python app.py
"""

import threading, uuid, warnings, json, os, tempfile
from datetime import datetime
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

import requests
from bs4 import BeautifulSoup
from flask import Flask, jsonify, render_template_string, request as freq

warnings.filterwarnings("ignore")
app = Flask(__name__)

# Scan state stored in temp files — works across all threading/process configs
# SCAN_DIR/<sid>.jsonl  → one JSON object per line (append-only)
# SCAN_DIR/<sid>.done   → created when scan finishes
SCAN_DIR = tempfile.mkdtemp(prefix="webreaper_")

def _lines_path(sid): return os.path.join(SCAN_DIR, sid + ".jsonl")
def _done_path(sid):  return os.path.join(SCAN_DIR, sid + ".done")

def _write_line(sid, obj):
    with open(_lines_path(sid), "a", encoding="utf-8") as f:
        f.write(json.dumps(obj) + "\n")

def _read_lines(sid, offset=0):
    path = _lines_path(sid)
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as f:
        all_lines = [json.loads(l) for l in f if l.strip()]
    return all_lines[offset:]

def _is_done(sid):
    return os.path.exists(_done_path(sid))

def _mark_done(sid):
    open(_done_path(sid), "w").close()

# ══════════════════════════════════════════════════════════════
#  SCANNER ENGINE
# ══════════════════════════════════════════════════════════════

SQLI_PAYLOADS = ["'", "''", "1 OR 1=1", "1' OR '1'='1"]
SQLI_ERRORS   = [
    "sql syntax","mysql_fetch","you have an error","unclosed quotation",
    "ora-","sqlite","postgresql","mssql","syntax error","invalid query",
    "warning: mysql","pg_query","unterminated string",
]
XSS_PAYLOAD   = "<wr3aper>"
SSTI_PAYLOADS = ["{{7*7}}", "${7*7}", "<%=7*7%>"]
LFI_PAYLOADS  = ["../../../../etc/passwd", "....//....//....//etc/passwd",
                  "../../../../windows/win.ini"]
CMD_PAYLOADS  = [";id", "|id", "&&id", ";whoami"]
CMD_INDICATORS = ["uid=", "www-data", "root", "nobody", "[extensions]"]
REDIRECT_PAYLOADS = ["https://evil.com", "//evil.com"]
SENSITIVE_PATHS = [
    ".env","config.php","config.ini","database.yml","settings.py",
    ".git/HEAD",".svn/entries","phpinfo.php","info.php","test.php",
    "admin/","wp-admin/","administrator/","backup.zip","backup.tar.gz",
    "robots.txt","sitemap.xml","server-status","server-info","web.config",
    "package.json","Dockerfile","swagger.json","openapi.json",
]
SECURITY_HEADERS = [
    ("strict-transport-security", "MEDIUM", "Missing HSTS header"),
    ("x-frame-options",           "MEDIUM", "Missing X-Frame-Options (Clickjacking)"),
    ("x-content-type-options",    "LOW",    "Missing X-Content-Type-Options"),
    ("content-security-policy",   "MEDIUM", "Missing Content-Security-Policy"),
    ("x-xss-protection",          "LOW",    "Missing X-XSS-Protection"),
    ("referrer-policy",           "LOW",    "Missing Referrer-Policy"),
]
CORS_ORIGINS = ["https://evil.com", "null", "http://attacker.local"]
UA = "Mozilla/5.0 (WebReaper/5.0; Security Scanner)"


def make_session():
    s = requests.Session()
    s.headers["User-Agent"] = UA
    s.verify = False
    s.timeout = 12
    return s


def inject_param(url, key, value):
    p  = urlparse(url)
    qs = parse_qs(p.query, keep_blank_values=True)
    qs[key] = [value]
    new_q = urlencode({k: v[0] for k, v in qs.items()})
    return urlunparse(p._replace(query=new_q))


def safe_get(sess, url, **kw):
    try:
        return sess.get(url, allow_redirects=False, **kw)
    except Exception:
        return None


def safe_post(sess, url, data, **kw):
    try:
        return sess.post(url, data=data, allow_redirects=False, **kw)
    except Exception:
        return None


# ── crawl ──────────────────────────────────────────────────────

def crawl(sess, base, deep=False):
    base_host = urlparse(base).netloc
    limit     = 60 if deep else 25
    visited, queue, pages = set(), [base], []
    while queue and len(visited) < limit:
        url = queue.pop(0)
        if url in visited:
            continue
        visited.add(url)
        r = safe_get(sess, url)
        if r is None:
            continue
        pages.append((url, r))
        try:
            soup = BeautifulSoup(r.text, "html.parser")
            for tag in soup.find_all(["a", "form"]):
                href = tag.get("href") or tag.get("action")
                if not href:
                    continue
                full = urljoin(url, href)
                p    = urlparse(full)
                if p.netloc == base_host and full not in visited:
                    queue.append(full)
        except Exception:
            pass
    return pages


def get_forms(url, html):
    soup = BeautifulSoup(html, "html.parser")
    out  = []
    for form in soup.find_all("form"):
        action = urljoin(url, form.get("action") or url)
        method = form.get("method", "get").lower()
        inputs = {}
        for inp in form.find_all(["input", "textarea", "select"]):
            name  = inp.get("name")
            value = inp.get("value") or inp.get("placeholder") or "test"
            t     = inp.get("type", "text").lower()
            if name and t not in ("submit", "button", "image", "reset"):
                inputs[name] = value
        if inputs:
            out.append({"action": action, "method": method, "inputs": inputs})
    return out


def has_sqli_error(text):
    low = text.lower()
    return any(e in low for e in SQLI_ERRORS)


def test_sqli_url(sess, url, params, emit):
    for pname in params:
        for payload in SQLI_PAYLOADS:
            r = safe_get(sess, inject_param(url, pname, payload))
            if r and has_sqli_error(r.text):
                emit("HIGH", f"SQLi (error-based) → {url}", f"param={pname!r} payload={payload!r}")
                return


def test_sqli_form(sess, form, emit):
    for pname in form["inputs"]:
        for payload in SQLI_PAYLOADS:
            d = dict(form["inputs"]); d[pname] = payload
            r = (safe_post(sess, form["action"], d) if form["method"] == "post"
                 else safe_get(sess, form["action"], params=d))
            if r and has_sqli_error(r.text):
                emit("HIGH", f"SQLi (form) → {form['action']}", f"param={pname!r}")
                return


def test_xss_url(sess, url, params, emit):
    for pname in params:
        r = safe_get(sess, inject_param(url, pname, XSS_PAYLOAD))
        if r and XSS_PAYLOAD in r.text:
            emit("HIGH", f"XSS (reflected) → {url}", f"param={pname!r}")
            return


def test_xss_form(sess, form, emit):
    for pname in form["inputs"]:
        d = dict(form["inputs"]); d[pname] = XSS_PAYLOAD
        r = (safe_post(sess, form["action"], d) if form["method"] == "post"
             else safe_get(sess, form["action"], params=d))
        if r and XSS_PAYLOAD in r.text:
            emit("HIGH", f"XSS (form) → {form['action']}", f"param={pname!r}")
            return


def test_ssti_url(sess, url, params, emit):
    for pname in params:
        for payload in SSTI_PAYLOADS:
            r = safe_get(sess, inject_param(url, pname, payload))
            if r and "49" in r.text:
                emit("CRITICAL", f"SSTI → {url}", f"param={pname!r} payload={payload!r}")
                return


def test_lfi_url(sess, url, params, emit):
    for pname in params:
        for payload in LFI_PAYLOADS:
            r = safe_get(sess, inject_param(url, pname, payload))
            if r and ("root:x:0:" in r.text or "[extensions]" in r.text.lower()):
                emit("CRITICAL", f"LFI → {url}", f"param={pname!r}")
                return


def test_cmdi_url(sess, url, params, emit):
    for pname in params:
        for payload in CMD_PAYLOADS:
            r = safe_get(sess, inject_param(url, pname, payload))
            if r and any(ind in r.text for ind in CMD_INDICATORS):
                emit("CRITICAL", f"CMDi → {url}", f"param={pname!r} payload={payload!r}")
                return


def test_redirect_url(sess, url, params, emit):
    for pname in params:
        for payload in REDIRECT_PAYLOADS:
            r = safe_get(sess, inject_param(url, pname, payload))
            if r and r.status_code in (301, 302, 303, 307, 308):
                loc = r.headers.get("Location", "")
                if "evil.com" in loc:
                    emit("MEDIUM", f"Open Redirect → {url}", f"param={pname!r} → {loc}")
                    return


def test_headers(sess, base, emit):
    r = safe_get(sess, base)
    if r is None:
        return
    h = {k.lower(): v for k, v in r.headers.items()}
    for key, sev, msg in SECURITY_HEADERS:
        if key not in h:
            emit(sev, msg, base)
    if h.get("server"):
        emit("LOW", f"Server banner: {h['server']}", base)
    if "x-powered-by" in h:
        emit("LOW", f"X-Powered-By: {h['x-powered-by']}", base)


def test_cors(sess, base, emit):
    for origin in CORS_ORIGINS:
        r = safe_get(sess, base, headers={"Origin": origin})
        if r is None:
            continue
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "").lower()
        if acao in (origin, "*"):
            sev = "HIGH" if acac == "true" else "MEDIUM"
            emit(sev, "CORS misconfiguration", f"Origin={origin!r} allowed")
            return


def test_sensitive(sess, base, emit):
    base = base.rstrip("/")
    for path in SENSITIVE_PATHS:
        url = f"{base}/{path}"
        r   = safe_get(sess, url)
        if r is None:
            continue
        if r.status_code == 200:
            sev = ("CRITICAL" if any(x in path for x in
                   [".env","config","phpinfo","database","settings"])
                   else "HIGH")
            emit(sev, f"Sensitive file exposed ({path})", url)
        elif r.status_code == 403:
            emit("INFO", f"Protected path (403): {path}", url)


# ══════════════════════════════════════════════════════════════
#  SCAN COORDINATOR
# ══════════════════════════════════════════════════════════════

def scan_worker(sid, target, deep, brute):

    def emit(level, msg, detail=""):
        _write_line(sid, {
            "type": "finding", "level": level,
            "msg": msg, "detail": detail,
            "ts": datetime.now().strftime("%H:%M:%S"),
        })

    def log(msg):
        print(f"[{sid[:8]}] {msg}", flush=True)  # visible in CMD terminal
        _write_line(sid, {
            "type": "log", "msg": msg,
            "ts": datetime.now().strftime("%H:%M:%S"),
        })

    try:
        sess = make_session()
        log(f"Scanning {target}")

        log("Phase 1 — Security headers + CORS")
        test_headers(sess, target, emit)
        test_cors(sess, target, emit)

        log("Phase 2 — Sensitive files")
        test_sensitive(sess, target, emit)

        log(f"Phase 3 — Crawling ({'deep' if deep else 'standard'})")
        pages = crawl(sess, target, deep)
        log(f"  {len(pages)} pages found")

        log("Phase 4 — Injection tests")
        for url, resp in pages:
            parsed = urlparse(url)
            qs     = parse_qs(parsed.query, keep_blank_values=True)
            params = {k: v[0] for k, v in qs.items()}
            if params:
                test_sqli_url(sess, url, params, emit)
                test_xss_url(sess, url, params, emit)
                test_lfi_url(sess, url, params, emit)
                test_ssti_url(sess, url, params, emit)
                test_cmdi_url(sess, url, params, emit)
                test_redirect_url(sess, url, params, emit)
            for form in get_forms(url, resp.text):
                test_sqli_form(sess, form, emit)
                test_xss_form(sess, form, emit)

        if brute:
            log("Phase 5 — Brute force logins")
            USERS  = ["admin","root","user","administrator","test"]
            PASSES = ["admin","password","123456","root","admin123","pass"]
            for url, resp in pages:
                for form in get_forms(url, resp.text):
                    pw_f  = [n for n in form["inputs"] if "pass" in n.lower() or "pwd" in n.lower()]
                    usr_f = [n for n in form["inputs"] if any(x in n.lower() for x in ["user","login","email","name"])]
                    if not pw_f or not usr_f:
                        continue
                    uf, pf = usr_f[0], pw_f[0]
                    found = False
                    for u in USERS:
                        if found: break
                        for p in PASSES:
                            d = dict(form["inputs"]); d[uf] = u; d[pf] = p
                            r = (safe_post(sess, form["action"], d) if form["method"] == "post"
                                 else safe_get(sess, form["action"], params=d))
                            if r and r.status_code == 200 and any(
                                x in r.text.lower()
                                for x in ["welcome","dashboard","logout","profile","success"]
                            ):
                                emit("CRITICAL", f"Brute force → {form['action']}",
                                     f"{uf}={u!r}  {pf}={p!r}")
                                found = True; break

        total = sum(1 for l in _read_lines(sid) if l.get("type") == "finding")
        log(f"Done — {total} findings, {len(pages)} pages scanned")

    except Exception as e:
        print(f"[{sid[:8]}] CRASH: {e}", flush=True)
        _write_line(sid, {"type": "log", "msg": f"[!] Error: {e}",
                           "ts": datetime.now().strftime("%H:%M:%S")})

    _mark_done(sid)


# ══════════════════════════════════════════════════════════════
#  HTML
# ══════════════════════════════════════════════════════════════

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WebReaper Pro</title>
<style>
:root{
  --bg:#0a0a0a;--bg2:#111;--bg3:#181818;--brd:#222;
  --acc:#e03030;--txt:#ddd;--dim:#555;
  --crit:#ff4444;--high:#ff7b39;--med:#f0c040;
  --low:#4da6ff;--info:#50d080;
}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--txt);font-family:'Courier New',monospace;min-height:100vh}
header{background:var(--bg2);border-bottom:1px solid var(--brd);padding:14px 26px}
.logo{font-size:18px;font-weight:700;color:var(--acc);letter-spacing:3px}
.logo span{color:#333}
.sub{color:var(--dim);font-size:10px;margin-top:2px}
.wrap{max-width:1100px;margin:0 auto;padding:24px 16px}
.card{background:var(--bg2);border:1px solid var(--brd);border-radius:8px;padding:22px;margin-bottom:16px}
.ctitle{color:var(--acc);font-size:11px;letter-spacing:2px;margin-bottom:14px}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
input[type=text]{
  flex:1;min-width:240px;background:var(--bg3);border:1px solid var(--brd);border-radius:6px;
  color:var(--txt);padding:10px 14px;font-family:monospace;font-size:13px;outline:none;transition:border-color .2s
}
input[type=text]:focus{border-color:var(--acc)}
.opts{display:flex;gap:18px;margin-top:10px;flex-wrap:wrap}
.opts label{display:flex;align-items:center;gap:6px;font-size:12px;color:var(--dim);cursor:pointer}
.opts label:hover{color:var(--txt)}
input[type=checkbox]{accent-color:var(--acc);width:14px;height:14px}
button{background:var(--acc);color:#fff;border:none;border-radius:6px;padding:10px 24px;font-family:monospace;font-size:12px;font-weight:700;cursor:pointer;letter-spacing:1px;transition:background .15s}
button:hover:not(:disabled){background:#b82020}
button:disabled{background:#1a1a1a;color:#333;cursor:default}
#stop{background:#1a1a1a;border:1px solid var(--brd);display:none}
#stop:hover{background:#222}
.bar-wrap{height:2px;background:var(--bg3);border-radius:2px;margin-top:12px}
.bar{height:100%;background:var(--acc);width:0;transition:width .5s;border-radius:2px}
.stats{display:grid;grid-template-columns:repeat(5,1fr);gap:8px;margin-bottom:16px}
.stat{background:var(--bg2);border:1px solid var(--brd);border-radius:8px;padding:12px 8px;text-align:center}
.stat .n{font-size:24px;font-weight:700}.stat .l{font-size:9px;color:var(--dim);letter-spacing:1px;margin-top:2px}
.crit .n{color:var(--crit)}.high .n{color:var(--high)}.med .n{color:var(--med)}
.low .n{color:var(--low)}.info .n{color:var(--info)}
.log-card{background:var(--bg2);border:1px solid var(--brd);border-radius:8px;overflow:hidden}
.log-head{padding:10px 16px;border-bottom:1px solid var(--brd);display:flex;justify-content:space-between;align-items:center}
.filters{display:flex;gap:5px;flex-wrap:wrap}
.fb{background:var(--bg3);border:1px solid var(--brd);color:var(--dim);padding:3px 10px;border-radius:4px;font-size:10px;cursor:pointer;transition:all .15s;font-family:monospace;letter-spacing:.5px}
.fb:hover,.fb.on{border-color:var(--acc);color:var(--txt);background:rgba(224,48,48,.1)}
#cnt{color:#2a2a2a;font-size:10px}
#log{height:500px;overflow-y:auto;padding:12px;font-size:12px;line-height:1.9}
#log::-webkit-scrollbar{width:4px}
#log::-webkit-scrollbar-track{background:var(--bg3)}
#log::-webkit-scrollbar-thumb{background:var(--brd);border-radius:2px}
.e{display:flex;gap:8px;align-items:flex-start;padding:1px 0}
.e:hover{background:rgba(255,255,255,.015);border-radius:3px}
.ets{color:#2a2a2a;min-width:50px;font-size:10px;padding-top:2px}
.badge{font-size:9px;font-weight:700;padding:2px 7px;border-radius:3px;min-width:68px;text-align:center;letter-spacing:.5px;margin-top:2px;white-space:nowrap}
.CRITICAL{background:rgba(255,68,68,.15);color:var(--crit);border:1px solid rgba(255,68,68,.3)}
.HIGH{background:rgba(255,123,57,.15);color:var(--high);border:1px solid rgba(255,123,57,.3)}
.MEDIUM{background:rgba(240,192,64,.1);color:var(--med);border:1px solid rgba(240,192,64,.25)}
.LOW{background:rgba(77,166,255,.1);color:var(--low);border:1px solid rgba(77,166,255,.25)}
.INFO{background:rgba(80,208,128,.08);color:var(--info);border:1px solid rgba(80,208,128,.2)}
.ec{flex:1;min-width:0}
.ec .msg{color:var(--txt);word-break:break-all}
.ec .det{color:var(--dim);font-size:10.5px;margin-top:1px;padding-left:6px;border-left:2px solid var(--brd);word-break:break-all}
.elog{color:#3a3a3a;font-size:10.5px;padding:0 0 0 126px;word-break:break-all}
.edone{color:var(--info);padding:8px 0 0;border-top:1px solid var(--brd);margin-top:4px;font-size:11px}
.empty{display:flex;flex-direction:column;align-items:center;justify-content:center;height:240px;color:#222;gap:8px;font-size:12px}
.empty .icon{font-size:40px;opacity:.15}
</style>
</head>
<body>
<header>
  <div>
    <div class="logo">WEB<span>REAPER</span> <span style="color:#222;font-size:12px">PRO v5</span></div>
    <div class="sub">SQLi · XSS · LFI · SSTI · CMDi · Open Redirect · CORS · Headers · Sensitive Files · Brute Force</div>
  </div>
</header>
<div class="wrap">
  <div class="card">
    <div class="ctitle">// TARGET</div>
    <div class="row">
      <input type="text" id="target" placeholder="http://testphp.vulnweb.com">
      <button id="go" onclick="startScan()">▶ SCAN</button>
      <button id="stop" onclick="stopScan()">■ STOP</button>
    </div>
    <div class="opts">
      <label><input type="checkbox" id="deep"> Deep crawl</label>
      <label><input type="checkbox" id="brute"> Brute force logins</label>
    </div>
    <div class="bar-wrap"><div class="bar" id="bar"></div></div>
  </div>
  <div class="stats">
    <div class="stat crit"><div class="n" id="nc">0</div><div class="l">CRITICAL</div></div>
    <div class="stat high"><div class="n" id="nh">0</div><div class="l">HIGH</div></div>
    <div class="stat med" ><div class="n" id="nm">0</div><div class="l">MEDIUM</div></div>
    <div class="stat low" ><div class="n" id="nl">0</div><div class="l">LOW</div></div>
    <div class="stat info"><div class="n" id="ni">0</div><div class="l">INFO</div></div>
  </div>
  <div class="log-card">
    <div class="log-head">
      <div class="filters">
        <button class="fb on" onclick="filt('ALL',this)">ALL</button>
        <button class="fb" onclick="filt('CRITICAL',this)">CRIT</button>
        <button class="fb" onclick="filt('HIGH',this)">HIGH</button>
        <button class="fb" onclick="filt('MEDIUM',this)">MED</button>
        <button class="fb" onclick="filt('LOW',this)">LOW</button>
        <button class="fb" onclick="filt('INFO',this)">INFO</button>
        <button class="fb" onclick="filt('LOG',this)">LOG</button>
      </div>
      <span id="cnt">–</span>
    </div>
    <div id="log"><div class="empty"><div class="icon">⚡</div><div>Enter a URL and click SCAN</div></div></div>
  </div>
</div>
<script>
let timer=null,sid=null,offset=0,filter='ALL';
let entries=[],counts={CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0,INFO:0};

function filt(f,btn){
  filter=f;
  document.querySelectorAll('.fb').forEach(b=>b.classList.remove('on'));
  btn.classList.add('on');
  render();
}

function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}

function render(){
  const el=document.getElementById('log');
  let html='';
  for(const e of entries){
    if(e.type==='log'){
      if(filter!=='ALL'&&filter!=='LOG')continue;
      html+=`<div class="elog">${esc(e.msg)}</div>`;
    }else if(e.type==='finding'){
      if(filter!=='ALL'&&filter!==e.level)continue;
      html+=`<div class="e">
        <span class="ets">${e.ts||''}</span>
        <span class="badge ${e.level}">${e.level}</span>
        <span class="ec">
          <div class="msg">${esc(e.msg)}</div>
          ${e.detail?`<div class="det">${esc(e.detail)}</div>`:''}
        </span>
      </div>`;
    }
  }
  el.innerHTML=html||'<div class="empty"><div class="icon">⚡</div><div>No entries match filter</div></div>';
  el.scrollTop=el.scrollHeight;
  const f=entries.filter(e=>e.type==='finding').length;
  document.getElementById('cnt').textContent=f+' finding'+(f!==1?'s':'');
}

async function startScan(){
  const target=document.getElementById('target').value.trim();
  if(!target)return;
  stopScan();
  entries=[];
  Object.keys(counts).forEach(k=>counts[k]=0);
  ['nc','nh','nm','nl','ni'].forEach(id=>document.getElementById(id).textContent='0');
  render();
  document.getElementById('go').disabled=true;
  document.getElementById('stop').style.display='inline-block';
  document.getElementById('bar').style.width='3%';
  document.getElementById('cnt').textContent='scanning…';
  const deep=document.getElementById('deep').checked;
  const brute=document.getElementById('brute').checked;
  try{
    const r=await fetch('/start',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({target,deep,brute})
    });
    const d=await r.json();
    if(d.error){entries.push({type:'log',msg:'Error: '+d.error,ts:''});render();doneScan();return;}
    sid=d.scan_id; offset=0;
    timer=setInterval(poll,1000);
  }catch(e){entries.push({type:'log',msg:'Fetch error: '+e,ts:''});render();doneScan();}
}

async function poll(){
  if(!sid)return;
  try{
    const r=await fetch('/poll/'+sid+'?offset='+offset);
    const d=await r.json();
    console.log('[poll]',JSON.stringify(d).slice(0,200));
    for(const item of d.items){
      entries.push(item);
      if(item.type==='finding'&&counts[item.level]!==undefined){
        counts[item.level]++;
        const m={CRITICAL:'nc',HIGH:'nh',MEDIUM:'nm',LOW:'nl',INFO:'ni'};
        if(m[item.level])document.getElementById(m[item.level]).textContent=counts[item.level];
      }
    }
    offset+=d.items.length;
    document.getElementById('bar').style.width=Math.min(5+offset*1.5,95)+'%';
    render();
    if(d.done){console.log('[done] total items='+offset);document.getElementById('bar').style.width='100%';doneScan();}
  }catch(e){console.error('poll error:',e);}
}

function doneScan(){if(timer){clearInterval(timer);timer=null;}sid=null;document.getElementById('go').disabled=false;document.getElementById('stop').style.display='none';}
function stopScan(){if(sid)fetch('/stop/'+sid,{method:'POST'}).catch(()=>{});doneScan();}
document.getElementById('target').addEventListener('keydown',e=>{if(e.key==='Enter')startScan();});
</script>
</body>
</html>"""

# ══════════════════════════════════════════════════════════════
#  ROUTES
# ══════════════════════════════════════════════════════════════

@app.route("/")
def index():
    return render_template_string(HTML)

@app.route("/start", methods=["POST"])
def start():
    data   = freq.get_json(force=True)
    target = data.get("target", "").strip()
    deep   = bool(data.get("deep", False))
    brute  = bool(data.get("brute", False))
    if not target:
        return jsonify({"error": "No target provided"}), 400
    if not target.startswith(("http://", "https://")):
        target = "http://" + target
    sid = str(uuid.uuid4())
    print(f"[START] sid={sid[:8]} target={target}", flush=True)
    threading.Thread(target=scan_worker, args=(sid, target, deep, brute), daemon=True).start()
    return jsonify({"scan_id": sid})

@app.route("/poll/<sid>")
def poll(sid):
    lines = _read_lines(sid, int(freq.args.get("offset", 0)))
    done  = _is_done(sid)
    return jsonify({"items": lines, "done": done})

@app.route("/stop/<sid>", methods=["POST"])
def stop_scan(sid):
    _mark_done(sid)
    return jsonify({"ok": True})

if __name__ == "__main__":
    print(f"\n  WebReaper Pro v5")
    print(f"  Temp dir: {SCAN_DIR}")
    print(f"  http://localhost:5000\n")
    app.run(debug=False, host="0.0.0.0", port=5000, threaded=True, use_reloader=False)
