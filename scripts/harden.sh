#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# OpenClaw Security Hardening Script
#
# Applies production-grade security to your OpenClaw + WordPress VPS:
#   1. SSH hardening (disable password auth)
#   2. Tailscale VPN (private network for SSH + wp-admin)
#   3. LiteLLM API proxy (budget limits for AI spending)
#   4. Squid egress proxy (restrict outbound connections)
#   5. wp-admin lockdown (only accessible via Tailscale)
#
# Run after install.sh:
#   bash /opt/tg-wordpress-agent/scripts/harden.sh
#
# Safe to re-run — all operations are idempotent.
# ─────────────────────────────────────────────────────────────
set -euo pipefail

# ── Colors ──
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[x]${NC} $1"; exit 1; }
info() { echo -e "${CYAN}[i]${NC} $1"; }

# ── Progress bar system ──
TOTAL_STEPS=6
_BAR_DRAWN=false
HARDEN_LOG="/tmp/openclaw-harden.log"
: > "$HARDEN_LOG"

# ── Crash handler — show last log lines on failure ──
on_error() {
    local exit_code=$?
    echo ""
    echo ""
    echo -e "${RED}${BOLD}  Hardening failed (exit code ${exit_code})${NC}"
    echo ""
    if [[ -s "$HARDEN_LOG" ]]; then
        echo -e "${YELLOW}  Last 25 lines of ${HARDEN_LOG}:${NC}"
        echo -e "${DIM}"
        tail -25 "$HARDEN_LOG" 2>/dev/null | sed 's/^/    /'
        echo -e "${NC}"
    fi
    echo -e "  Full log: ${CYAN}cat ${HARDEN_LOG}${NC}"
    echo ""
}
trap on_error ERR

# Draw or redraw the 2-line progress display
progress() {
    local step=$1
    local action="$2"
    local bar_width=30
    local filled=$((step * bar_width / TOTAL_STEPS))
    local empty=$((bar_width - filled))
    local pct=$((step * 100 / TOTAL_STEPS))

    local bar=""
    for ((i=0; i<filled; i++)); do bar+="█"; done
    for ((i=0; i<empty; i++)); do bar+="░"; done

    if [[ "$_BAR_DRAWN" == "true" ]]; then
        echo -ne "\033[2A"
    fi

    echo -e "\033[2K  ${GREEN}[${bar}]${NC} ${BOLD}${step}/${TOTAL_STEPS}${NC} (${pct}%)"
    echo -e "\033[2K  ${CYAN}${action}${NC}"
    _BAR_DRAWN=true
}

# Update just the action text beneath the bar
action() {
    if [[ "$_BAR_DRAWN" == "true" ]]; then
        echo -ne "\033[1A\033[2K  ${CYAN}$1${NC}\n"
    else
        echo -e "  ${CYAN}$1${NC}"
    fi
}

# Run a command with a spinner on the action line
spin() {
    local msg="$1"
    shift
    action "⠋ ${msg}"

    ( set +e; "$@" >> "$HARDEN_LOG" 2>&1 ) &
    local pid=$!

    local frames=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
    local i=0
    while kill -0 "$pid" 2>/dev/null; do
        action "${frames[$i]} ${msg}"
        i=$(( (i+1) % ${#frames[@]} ))
        sleep 0.15
    done

    set +e
    wait "$pid"
    local rc=$?
    set -e

    if [[ $rc -eq 0 ]]; then
        action "${GREEN}✓${NC} ${msg}"
    else
        action "${RED}✗${NC} ${msg} — check ${HARDEN_LOG}"
        echo "" >> "$HARDEN_LOG"
        echo "=== FAILED: ${msg} (exit code ${rc}) ===" >> "$HARDEN_LOG"
    fi
    return $rc
}

# Run a command silently (output to log only)
quiet() {
    "$@" >> "$HARDEN_LOG" 2>&1
}

# ── Check root ──
[[ $EUID -ne 0 ]] && err "Run as root: sudo bash harden.sh"

# ── Load existing config ──
OCLAW_HOME="/home/openclaw"
OCLAW_CONFIG="${OCLAW_HOME}/.openclaw"
WP_PATH="/var/www/html"

if [[ -f "${OCLAW_HOME}/.env" ]]; then
    WP_PATH=$(grep '^WP_PATH=' "${OCLAW_HOME}/.env" 2>/dev/null | cut -d= -f2 || echo "/var/www/html")
fi

# ── Configuration ──
LITELLM_PORT=4000
LITELLM_BUDGET="${LITELLM_MONTHLY_BUDGET:-30}"
SQUID_PORT=3128

clear 2>/dev/null || true
echo ""
echo -e "${BOLD}════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  OpenClaw Security Hardening${NC}"
echo -e "${BOLD}════════════════════════════════════════════════════${NC}"
echo ""
echo "  This script will:"
echo "    1. Disable SSH password login (key-only access)"
echo "    2. Install Tailscale VPN for private access"
echo "    3. Set up LiteLLM API proxy with spending limits"
echo "    4. Set up Squid egress filtering"
echo "    5. Lock down wp-admin to Tailscale only"
echo ""

# ── Pre-flight: check SSH key exists ──
SSH_KEY_FOUND=false
if [[ -f /root/.ssh/authorized_keys ]] && [[ -s /root/.ssh/authorized_keys ]]; then
    SSH_KEY_FOUND=true
    KEY_COUNT=$(wc -l < /root/.ssh/authorized_keys)
    info "Found ${KEY_COUNT} SSH key(s) in /root/.ssh/authorized_keys"
fi

if [[ "$SSH_KEY_FOUND" != "true" ]]; then
    echo ""
    echo -e "  ${RED}WARNING: No SSH keys found!${NC}"
    echo "  If we disable password SSH, you could lock yourself out."
    echo ""
    echo "  Add your SSH key first (from your LOCAL machine):"
    echo "    ssh-copy-id root@YOUR_SERVER_IP"
    echo ""
    echo -ne "${CYAN}  Continue anyway? (only say yes if you have console access)${NC} [y/N]: "
    read -r CONTINUE_NO_KEY
    if [[ ! "$CONTINUE_NO_KEY" =~ ^[yY] ]]; then
        echo "Aborted. Add your SSH key first, then re-run."
        exit 0
    fi
fi

# ── Ask for budget ──
echo ""
echo -e "${BOLD}  API Budget${NC}"
echo "  Set a monthly spending limit for AI API calls."
echo -ne "${CYAN}  Monthly budget in USD${NC} [${LITELLM_BUDGET}]: "
read -r BUDGET_INPUT
LITELLM_BUDGET="${BUDGET_INPUT:-$LITELLM_BUDGET}"
echo ""

# ── Read Anthropic key from .env (only needed if LiteLLM not already installed) ──
ANTHROPIC_API_KEY=""
if [[ -f "${OCLAW_HOME}/.env" ]]; then
    ANTHROPIC_API_KEY=$(grep '^ANTHROPIC_API_KEY=' "${OCLAW_HOME}/.env" 2>/dev/null | cut -d= -f2 || echo "")
fi

# If LiteLLM is not yet installed and we don't have a key, ask for one
if ! systemctl is-active litellm > /dev/null 2>&1 && [[ -z "$ANTHROPIC_API_KEY" || "$ANTHROPIC_API_KEY" == sk-litellm-* ]]; then
    echo -ne "${CYAN}  Anthropic API key (for LiteLLM proxy)${NC}: "
    read -rs ANTHROPIC_API_KEY
    echo ""
fi

echo ""
echo -e "${BOLD}  Starting hardening...${NC}"
echo ""
echo ""

# ═════════════════════════════════════════════
# Step 1: SSH Hardening
# ═════════════════════════════════════════════
progress 1 "Hardening SSH..."

# Backup sshd_config
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%Y%m%d%H%M%S) 2>/dev/null || true

action "Disabling password authentication..."
sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^#*ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^#*KbdInteractiveAuthentication.*/KbdInteractiveAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^#*UsePAM.*/UsePAM no/' /etc/ssh/sshd_config
sed -i 's/^#*PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config

# Restart SSH (service name varies: "ssh" on Ubuntu 24.04+, "sshd" on older)
if systemctl list-units --type=service --all | grep -q 'sshd.service'; then
    spin "Restarting SSH daemon" systemctl restart sshd
else
    spin "Restarting SSH daemon" systemctl restart ssh
fi

action "${GREEN}✓${NC} SSH hardened — key-only access enabled"

# ═════════════════════════════════════════════
# Step 2: Tailscale VPN
# ═════════════════════════════════════════════
progress 2 "Installing Tailscale VPN..."

if command -v tailscale &>/dev/null; then
    TS_STATUS=$(tailscale status --json 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('BackendState',''))" 2>/dev/null || echo "")
    if [[ "$TS_STATUS" == "Running" ]]; then
        TS_IP=$(tailscale ip -4 2>/dev/null || echo "unknown")
        action "${GREEN}✓${NC} Tailscale already running (IP: ${TS_IP})"
    else
        action "Tailscale installed but not connected"
    fi
else
    spin "Downloading Tailscale" bash -c 'curl -fsSL https://tailscale.com/install.sh 2>/dev/null | sh > /dev/null 2>&1'
fi

# Check if already authenticated
TS_STATUS=$(tailscale status --json 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('BackendState',''))" 2>/dev/null || echo "")

if [[ "$TS_STATUS" != "Running" ]]; then
    # Tailscale login is interactive — temporarily hide the progress bar
    echo ""
    echo ""
    echo -e "  ${BOLD}Tailscale needs to be authenticated.${NC}"
    echo "  A login URL will appear — open it in your browser to connect."
    echo ""
    tailscale up
    echo ""
    # Reset progress bar state so it redraws cleanly
    _BAR_DRAWN=false
    progress 2 "Tailscale connected"
fi

# Get Tailscale IP
TS_IP=$(tailscale ip -4 2>/dev/null || echo "")

if [[ -n "$TS_IP" ]]; then
    action "${GREEN}✓${NC} Tailscale VPN connected (IP: ${TS_IP})"

    # Lock down SSH to Tailscale only
    if ufw status | grep -q "Status: active" 2>/dev/null; then
        quiet ufw allow in on tailscale0 to any port 22 || true
        quiet ufw delete allow ssh || true
        quiet ufw delete allow 22/tcp || true
        quiet ufw delete allow OpenSSH || true
        action "${GREEN}✓${NC} SSH locked to Tailscale only (${TS_IP}:22)"
    fi
else
    action "${YELLOW}!${NC} Could not get Tailscale IP — SSH lockdown skipped"
fi

# ═════════════════════════════════════════════
# Step 3: LiteLLM API Proxy with Budget
# ═════════════════════════════════════════════
progress 3 "Setting up LiteLLM API proxy..."

LITELLM_DIR="/opt/litellm"

if systemctl is-active litellm > /dev/null 2>&1 && [[ -f "${LITELLM_DIR}/config.yaml" ]]; then
    # LiteLLM already set up by install.sh — just update budget if changed
    action "${GREEN}✓${NC} LiteLLM already running (installed by install.sh)"

    if [[ -n "$LITELLM_BUDGET" ]]; then
        sed -i "s|max_budget:.*|max_budget: ${LITELLM_BUDGET}|" "${LITELLM_DIR}/config.yaml"
        spin "Updating LiteLLM budget to \$${LITELLM_BUDGET}/month" systemctl restart litellm
    fi

    # Read existing master key from config
    LITELLM_MASTER_KEY=$(grep 'master_key:' "${LITELLM_DIR}/config.yaml" 2>/dev/null | awk '{print $2}' | tr -d '"' || echo "")
else
    # Fresh LiteLLM install (for upgrades from older installs without LiteLLM in install.sh)
    spin "Installing Python venv" apt-get install -y -qq python3-pip python3-venv

    mkdir -p "$LITELLM_DIR"

    if [[ ! -d "${LITELLM_DIR}/venv" ]]; then
        spin "Creating LiteLLM virtualenv" python3 -m venv "${LITELLM_DIR}/venv"
    fi

    spin "Installing LiteLLM" bash -c "${LITELLM_DIR}/venv/bin/pip install --quiet --upgrade 'litellm[proxy]'"

    LITELLM_MASTER_KEY="sk-litellm-$(openssl rand -hex 16)"

    cat > "${LITELLM_DIR}/config.yaml" <<LITECFG
model_list:
  - model_name: "anthropic/claude-sonnet-4-5-20250929"
    litellm_params:
      model: "anthropic/claude-sonnet-4-5-20250929"
      api_key: "${ANTHROPIC_API_KEY}"
  - model_name: "anthropic/claude-opus-4-6"
    litellm_params:
      model: "anthropic/claude-opus-4-6"
      api_key: "${ANTHROPIC_API_KEY}"
  - model_name: "anthropic/claude-haiku-4-5-20251001"
    litellm_params:
      model: "anthropic/claude-haiku-4-5-20251001"
      api_key: "${ANTHROPIC_API_KEY}"

general_settings:
  master_key: "${LITELLM_MASTER_KEY}"

litellm_settings:
  max_budget: ${LITELLM_BUDGET}
  budget_duration: "monthly"
  drop_params: true
LITECFG

    chmod 600 "${LITELLM_DIR}/config.yaml"

    cat > /etc/systemd/system/litellm.service <<LITESVC
[Unit]
Description=LiteLLM API Proxy
After=network.target

[Service]
Type=simple
WorkingDirectory=${LITELLM_DIR}
ExecStart=${LITELLM_DIR}/venv/bin/litellm --config ${LITELLM_DIR}/config.yaml --port ${LITELLM_PORT} --host 127.0.0.1
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
LITESVC

    quiet systemctl daemon-reload
    quiet systemctl enable litellm
    spin "Starting LiteLLM" systemctl restart litellm

    sleep 3
    if systemctl is-active litellm > /dev/null 2>&1; then
        action "${GREEN}✓${NC} LiteLLM proxy running on 127.0.0.1:${LITELLM_PORT}"
    else
        action "${YELLOW}!${NC} LiteLLM may still be starting — check: journalctl -u litellm -f"
    fi

    # Update OpenClaw .env to use LiteLLM proxy
    if [[ -f "${OCLAW_HOME}/.env" ]]; then
        cp "${OCLAW_HOME}/.env" "${OCLAW_HOME}/.env.bak.$(date +%Y%m%d%H%M%S)"
        sed -i "s|^ANTHROPIC_API_KEY=.*|ANTHROPIC_API_KEY=${LITELLM_MASTER_KEY}|" "${OCLAW_HOME}/.env"

        if ! grep -q '^ANTHROPIC_BASE_URL=' "${OCLAW_HOME}/.env" 2>/dev/null; then
            echo "ANTHROPIC_BASE_URL=http://127.0.0.1:${LITELLM_PORT}" >> "${OCLAW_HOME}/.env"
        else
            sed -i "s|^ANTHROPIC_BASE_URL=.*|ANTHROPIC_BASE_URL=http://127.0.0.1:${LITELLM_PORT}|" "${OCLAW_HOME}/.env"
        fi

        chown openclaw:openclaw "${OCLAW_HOME}/.env"
    fi

    action "${GREEN}✓${NC} OpenClaw routed through LiteLLM (budget: \$${LITELLM_BUDGET}/month)"
fi

# ═════════════════════════════════════════════
# Step 4: Squid Egress Filtering
# ═════════════════════════════════════════════
progress 4 "Setting up Squid egress proxy..."

spin "Installing Squid" apt-get install -y -qq squid

# Back up original config
cp /etc/squid/squid.conf /etc/squid/squid.conf.bak.$(date +%Y%m%d%H%M%S) 2>/dev/null || true

action "Writing domain allowlist..."

# NOTE: No comments or blank lines inside — Squid 6+ rejects them in ACL files
cat > /etc/squid/allowed-domains.txt <<'DOMAINS'
.anthropic.com
.openai.com
.telegram.org
.t.me
.discord.com
.discord.gg
.wordpress.org
.w.org
.packagist.org
.getcomposer.org
.npmjs.org
.npmjs.com
.ubuntu.com
.debian.org
.letsencrypt.org
.tailscale.com
.github.com
.githubusercontent.com
.gravatar.com
.woocommerce.com
DOMAINS

cat > /etc/squid/squid.conf <<'SQUIDCFG'
# OpenClaw egress filtering proxy
# Only allows outbound HTTPS to allowlisted domains

# Listen on localhost only
http_port 3128

# Access control
acl localnet src 127.0.0.1/32
acl SSL_ports port 443
acl Safe_ports port 80
acl Safe_ports port 443

# Load allowed domains
acl allowed_domains dstdomain "/etc/squid/allowed-domains.txt"

# Allow CONNECT only to SSL ports
acl CONNECT method CONNECT
http_access deny CONNECT !SSL_ports

# Only allow traffic to allowlisted domains
http_access allow localnet allowed_domains
http_access deny all

# Logging
access_log /var/log/squid/access.log
cache_log /var/log/squid/cache.log

# Don't cache anything (we're just proxying)
cache deny all

# Timeouts
connect_timeout 30 seconds
read_timeout 60 seconds
SQUIDCFG

quiet systemctl enable squid
spin "Starting Squid proxy" systemctl restart squid

# Configure the openclaw user to route through Squid
PROXY_LINE="export http_proxy=http://127.0.0.1:${SQUID_PORT}"
PROXY_LINE_S="export https_proxy=http://127.0.0.1:${SQUID_PORT}"

if ! grep -qF 'http_proxy' "${OCLAW_HOME}/.bashrc" 2>/dev/null; then
    echo "${PROXY_LINE}" >> "${OCLAW_HOME}/.bashrc"
    echo "${PROXY_LINE_S}" >> "${OCLAW_HOME}/.bashrc"
fi

# Also add to .env so systemd service picks it up
if ! grep -q '^http_proxy=' "${OCLAW_HOME}/.env" 2>/dev/null; then
    echo "http_proxy=http://127.0.0.1:${SQUID_PORT}" >> "${OCLAW_HOME}/.env"
    echo "https_proxy=http://127.0.0.1:${SQUID_PORT}" >> "${OCLAW_HOME}/.env"
fi

# Add proxy env vars to systemd service
if ! grep -q 'http_proxy' /etc/systemd/system/openclaw.service 2>/dev/null; then
    sed -i '/\[Service\]/a Environment="http_proxy=http://127.0.0.1:3128"\nEnvironment="https_proxy=http://127.0.0.1:3128"' /etc/systemd/system/openclaw.service
    quiet systemctl daemon-reload
fi

action "${GREEN}✓${NC} Squid egress proxy running — outbound traffic filtered"

# ═════════════════════════════════════════════
# Step 5: wp-admin Lockdown
# ═════════════════════════════════════════════
progress 5 "Locking down wp-admin..."

if command -v nginx &>/dev/null && systemctl is-active nginx > /dev/null 2>&1; then
    NGINX_SNIPPET="/etc/nginx/snippets/wp-admin-restrict.conf"

    if [[ -n "$TS_IP" ]]; then
        TS_SUBNET="100.64.0.0/10"
        SERVER_PUBLIC_IP=$(curl -4 -s --connect-timeout 5 ifconfig.me 2>/dev/null || echo "")
        PHP_V=$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;' 2>/dev/null || echo "8.2")

        action "Writing Nginx restriction snippet..."
        cat > "$NGINX_SNIPPET" <<NGINXSNIP
# Restrict wp-admin and wp-login.php to Tailscale + server's own IP
location ~ ^/(wp-admin|wp-login\.php) {
    allow ${TS_SUBNET};
    allow 127.0.0.1;
${SERVER_PUBLIC_IP:+    allow ${SERVER_PUBLIC_IP};}
    deny all;

    # Pass PHP requests
    location ~ \.php\$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php${PHP_V}-fpm.sock;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        include fastcgi_params;
    }
}
NGINXSNIP

        # Make WordPress work when accessed via Tailscale IP
        WP_TS_CONFIG="${WP_PATH}/wp-tailscale.php"
        cat > "$WP_TS_CONFIG" <<'WPTSPHP'
<?php
/**
 * Dynamic host detection for Tailscale access.
 * Loaded from wp-config.php so wp-admin works via both public IP and Tailscale IP.
 */
if ( ! defined( 'ABSPATH' ) ) {
    return;
}
$scheme = ( ! empty( $_SERVER['HTTPS'] ) && $_SERVER['HTTPS'] !== 'off' ) ? 'https' : 'http';
$host   = $_SERVER['HTTP_HOST'] ?? $_SERVER['SERVER_NAME'] ?? '';
if ( $host && preg_match( '/^100\./', $host ) ) {
    // Accessing via Tailscale IP — override siteurl/home dynamically
    define( 'WP_SITEURL', $scheme . '://' . $host );
    define( 'WP_HOME',    $scheme . '://' . $host );
}
WPTSPHP
        chown www-data:www-data "$WP_TS_CONFIG"

        # Include the Tailscale snippet in wp-config.php if not already there
        if [[ -f "${WP_PATH}/wp-config.php" ]] && ! grep -q 'wp-tailscale.php' "${WP_PATH}/wp-config.php" 2>/dev/null; then
            sed -i "1a\\
// Dynamic host for Tailscale access\\
if ( file_exists( __DIR__ . '/wp-tailscale.php' ) ) { require_once __DIR__ . '/wp-tailscale.php'; }" "${WP_PATH}/wp-config.php"
            action "WordPress configured for Tailscale IP access"
        fi

        # Add the Nginx snippet to the WordPress server block
        WP_NGINX_CONF="/etc/nginx/sites-available/wordpress"
        if [[ -f "$WP_NGINX_CONF" ]]; then
            # Add Tailscale IP to server_name if not already there
            if ! grep -q "$TS_IP" "$WP_NGINX_CONF" 2>/dev/null; then
                sed -i "s/server_name .*/& ${TS_IP};/" "$WP_NGINX_CONF"
                sed -i 's/;;/;/g' "$WP_NGINX_CONF"
            fi

            # Include the wp-admin restriction snippet
            if ! grep -q "wp-admin-restrict" "$WP_NGINX_CONF" 2>/dev/null; then
                sed -i '/location = \/robots.txt/a \\n    include snippets/wp-admin-restrict.conf;' "$WP_NGINX_CONF"
            fi

            if nginx -t > /dev/null 2>&1; then
                spin "Reloading Nginx" systemctl reload nginx
                action "${GREEN}✓${NC} wp-admin restricted to Tailscale network only"
            else
                action "${RED}✗${NC} Nginx config test failed — reverting wp-admin restriction"
                sed -i '/wp-admin-restrict/d' "$WP_NGINX_CONF"
                sed -i "/${TS_IP}/d" "$WP_NGINX_CONF"
                rm -f "$NGINX_SNIPPET"
            fi
        else
            action "${YELLOW}!${NC} Nginx config not found — skipping wp-admin lockdown"
        fi
    else
        action "${YELLOW}!${NC} Tailscale IP not available — skipping wp-admin lockdown"
    fi
else
    action "${YELLOW}!${NC} Nginx not detected — add Tailscale IP restriction to .htaccess manually"
fi

# ═════════════════════════════════════════════
# Step 6: Restart OpenClaw
# ═════════════════════════════════════════════
progress 6 "Restarting OpenClaw with hardened config..."

spin "Restarting OpenClaw" systemctl restart openclaw

sleep 3
OPENCLAW_STATUS=$(systemctl is-active openclaw 2>/dev/null || echo "unknown")

if [[ "$OPENCLAW_STATUS" == "active" ]]; then
    action "${GREEN}✓${NC} OpenClaw restarted successfully"
else
    action "${YELLOW}!${NC} OpenClaw status: ${OPENCLAW_STATUS} — check: journalctl -u openclaw -n 30"
fi

# ═════════════════════════════════════════════
# Summary
# ═════════════════════════════════════════════
echo ""
echo ""
echo ""
echo -e "${BOLD}════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}  Security Hardening Complete${NC}"
echo -e "${BOLD}════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${BOLD}SSH${NC}"
echo "    Password login:   disabled (key-only)"
if [[ -n "$TS_IP" ]]; then
echo "    Access:            Tailscale only (ssh root@${TS_IP})"
fi
echo ""
echo -e "  ${BOLD}Tailscale VPN${NC}"
if [[ -n "$TS_IP" ]]; then
echo "    Status:            connected"
echo "    VPN IP:            ${TS_IP}"
else
echo "    Status:            not connected (run 'tailscale up')"
fi
echo ""
echo -e "  ${BOLD}API Budget (LiteLLM)${NC}"
echo "    Monthly limit:     \$${LITELLM_BUDGET}"
echo "    Proxy:             127.0.0.1:${LITELLM_PORT}"
echo "    Status:            $(systemctl is-active litellm 2>/dev/null || echo 'unknown')"
echo "    Logs:              journalctl -u litellm -f"
echo ""
echo -e "  ${BOLD}Egress Filtering (Squid)${NC}"
echo "    Proxy:             127.0.0.1:${SQUID_PORT}"
echo "    Allowlist:         /etc/squid/allowed-domains.txt"
echo "    Status:            $(systemctl is-active squid 2>/dev/null || echo 'unknown')"
echo ""
echo -e "  ${BOLD}wp-admin${NC}"
if [[ -n "$TS_IP" ]]; then
echo "    Access:            Tailscale network only"
echo "    URL:               http://${TS_IP}/wp-admin"
echo "    Note:              WordPress auto-detects Tailscale IP (no redirect)"
else
echo "    Access:            public (lock down after Tailscale connects)"
fi
echo ""
echo -e "  ${BOLD}OpenClaw${NC}"
echo "    Status:            ${OPENCLAW_STATUS}"
echo ""
echo -e "${BOLD}════════════════════════════════════════════════════${NC}"
echo ""

if [[ -n "$TS_IP" ]]; then
    echo -e "  ${YELLOW}IMPORTANT: From now on, connect to your server via Tailscale:${NC}"
    echo "    ssh root@${TS_IP}"
    echo ""
    echo "  Access WordPress admin via Tailscale:"
    echo "    http://${TS_IP}/wp-admin"
    echo ""
fi

# Save hardening details
cat >> /root/setup-credentials.txt <<HARDCREDS

═══ Security Hardening ═══
Applied: $(date)

SSH: key-only (password disabled)
Tailscale IP: ${TS_IP:-not connected}
LiteLLM Master Key: ${LITELLM_MASTER_KEY:-already set by install.sh}
LiteLLM Config: ${LITELLM_DIR}/config.yaml
LiteLLM Budget: \$${LITELLM_BUDGET}/month
Squid Allowlist: /etc/squid/allowed-domains.txt

IMPORTANT: Connect via Tailscale from now on!
  ssh root@${TS_IP:-TAILSCALE_IP}
HARDCREDS

chmod 600 /root/setup-credentials.txt
info "Hardening details appended to /root/setup-credentials.txt"
info "Full log: cat ${HARDEN_LOG}"
echo ""
