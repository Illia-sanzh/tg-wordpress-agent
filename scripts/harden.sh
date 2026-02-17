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

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[x]${NC} $1"; exit 1; }
info() { echo -e "${CYAN}[i]${NC} $1"; }

[[ $EUID -ne 0 ]] && err "Run as root: sudo bash harden.sh"

# ── Load existing config ──
OCLAW_HOME="/home/openclaw"
OCLAW_CONFIG="${OCLAW_HOME}/.openclaw"
WP_PATH="/var/www/html"

# Try to read WP_PATH from .env
if [[ -f "${OCLAW_HOME}/.env" ]]; then
    WP_PATH=$(grep '^WP_PATH=' "${OCLAW_HOME}/.env" 2>/dev/null | cut -d= -f2 || echo "/var/www/html")
fi

# ── Configuration ──
LITELLM_PORT=4000
LITELLM_BUDGET="${LITELLM_MONTHLY_BUDGET:-30}"  # Default $30/month
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

# ── Ask for Anthropic key (needed for LiteLLM) ──
ANTHROPIC_API_KEY=""
if [[ -f "${OCLAW_HOME}/.env" ]]; then
    ANTHROPIC_API_KEY=$(grep '^ANTHROPIC_API_KEY=' "${OCLAW_HOME}/.env" 2>/dev/null | cut -d= -f2 || echo "")
fi

if [[ -z "$ANTHROPIC_API_KEY" ]]; then
    echo -ne "${CYAN}  Anthropic API key (for LiteLLM proxy)${NC}: "
    read -rs ANTHROPIC_API_KEY
    echo ""
fi

echo ""
echo -e "${BOLD}  Starting hardening...${NC}"
echo ""

# ═════════════════════════════════════════════
# Step 1: SSH Hardening
# ═════════════════════════════════════════════
log "Step 1/5: Hardening SSH..."

# Backup sshd_config
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%Y%m%d%H%M%S) 2>/dev/null || true

# Disable password authentication
sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^#*ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^#*KbdInteractiveAuthentication.*/KbdInteractiveAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^#*UsePAM.*/UsePAM no/' /etc/ssh/sshd_config

# Disable root login with password (key still works)
sed -i 's/^#*PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config

# Restart SSH
systemctl restart sshd

info "Password SSH disabled. Key-only access enabled."

# ═════════════════════════════════════════════
# Step 2: Tailscale VPN
# ═════════════════════════════════════════════
log "Step 2/5: Installing Tailscale..."

if command -v tailscale &>/dev/null; then
    TS_STATUS=$(tailscale status --json 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('BackendState',''))" 2>/dev/null || echo "")
    if [[ "$TS_STATUS" == "Running" ]]; then
        TS_IP=$(tailscale ip -4 2>/dev/null || echo "unknown")
        info "Tailscale already running. IP: ${TS_IP}"
    else
        info "Tailscale installed but not connected."
    fi
else
    curl -fsSL https://tailscale.com/install.sh 2>/dev/null | sh > /dev/null 2>&1
fi

# Check if already authenticated
TS_STATUS=$(tailscale status --json 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('BackendState',''))" 2>/dev/null || echo "")

if [[ "$TS_STATUS" != "Running" ]]; then
    echo ""
    echo -e "  ${BOLD}Tailscale needs to be authenticated.${NC}"
    echo "  A login URL will appear — open it in your browser to connect."
    echo ""
    tailscale up
    echo ""
fi

# Get Tailscale IP
TS_IP=$(tailscale ip -4 2>/dev/null || echo "")

if [[ -n "$TS_IP" ]]; then
    log "Tailscale connected. VPN IP: ${TS_IP}"

    # Lock down SSH to Tailscale only
    # First, check if the Tailscale interface exists for UFW
    if ufw status | grep -q "Status: active" 2>/dev/null; then
        # Allow SSH on Tailscale interface
        ufw allow in on tailscale0 to any port 22 > /dev/null 2>&1 || true

        # Remove public SSH access
        ufw delete allow ssh > /dev/null 2>&1 || true
        ufw delete allow 22/tcp > /dev/null 2>&1 || true
        ufw delete allow OpenSSH > /dev/null 2>&1 || true

        info "SSH now only accessible via Tailscale (${TS_IP}:22)"
        warn "Use 'ssh root@${TS_IP}' to connect from now on."
    fi
else
    warn "Could not get Tailscale IP. SSH lockdown skipped."
    warn "Run 'tailscale up' manually, then re-run this script."
fi

# ═════════════════════════════════════════════
# Step 3: LiteLLM API Proxy with Budget
# ═════════════════════════════════════════════
log "Step 3/5: Setting up LiteLLM API proxy (budget: \$${LITELLM_BUDGET}/month)..."

# Install Python and pip if needed
apt-get install -y -qq python3-pip python3-venv > /dev/null 2>&1

# Create a dedicated venv for LiteLLM
LITELLM_DIR="/opt/litellm"
mkdir -p "$LITELLM_DIR"

if [[ ! -d "${LITELLM_DIR}/venv" ]]; then
    python3 -m venv "${LITELLM_DIR}/venv"
fi

"${LITELLM_DIR}/venv/bin/pip" install --quiet --upgrade litellm[proxy] 2>&1 | tail -1 || true

# Generate a proxy key for internal use
LITELLM_MASTER_KEY="sk-litellm-$(openssl rand -hex 16)"

# Write LiteLLM config
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

# Create systemd service for LiteLLM
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

systemctl daemon-reload
systemctl enable litellm > /dev/null 2>&1
systemctl restart litellm

# Wait for LiteLLM to start
sleep 3
if systemctl is-active litellm > /dev/null 2>&1; then
    info "LiteLLM proxy running on 127.0.0.1:${LITELLM_PORT}"
else
    warn "LiteLLM may still be starting. Check: journalctl -u litellm -f"
fi

# Update OpenClaw to use LiteLLM proxy instead of direct Anthropic
# Replace the Anthropic API key in .env with the LiteLLM proxy key
# and point to localhost
if [[ -f "${OCLAW_HOME}/.env" ]]; then
    # Back up current .env
    cp "${OCLAW_HOME}/.env" "${OCLAW_HOME}/.env.bak.$(date +%Y%m%d%H%M%S)"

    # Update to use LiteLLM
    sed -i "s|^ANTHROPIC_API_KEY=.*|ANTHROPIC_API_KEY=${LITELLM_MASTER_KEY}|" "${OCLAW_HOME}/.env"

    # Add LiteLLM base URL if not present
    if ! grep -q '^ANTHROPIC_BASE_URL=' "${OCLAW_HOME}/.env" 2>/dev/null; then
        echo "ANTHROPIC_BASE_URL=http://127.0.0.1:${LITELLM_PORT}" >> "${OCLAW_HOME}/.env"
    else
        sed -i "s|^ANTHROPIC_BASE_URL=.*|ANTHROPIC_BASE_URL=http://127.0.0.1:${LITELLM_PORT}|" "${OCLAW_HOME}/.env"
    fi

    chown openclaw:openclaw "${OCLAW_HOME}/.env"
fi

info "OpenClaw now routes API calls through LiteLLM (budget-limited)."

# ═════════════════════════════════════════════
# Step 4: Squid Egress Filtering
# ═════════════════════════════════════════════
log "Step 4/5: Setting up Squid egress proxy..."

apt-get install -y -qq squid > /dev/null 2>&1

# Back up original config
cp /etc/squid/squid.conf /etc/squid/squid.conf.bak.$(date +%Y%m%d%H%M%S) 2>/dev/null || true

# Create allowlist of domains the agent is allowed to reach
cat > /etc/squid/allowed-domains.txt <<'DOMAINS'
# AI API providers
.anthropic.com
.openai.com

# WordPress plugin/theme repositories
.wordpress.org
.w.org
downloads.wordpress.org
api.wordpress.org

# Package managers (needed for updates)
.packagist.org
.getcomposer.org
repo.packagist.org

# Node.js packages (needed for OpenClaw updates)
.npmjs.org
.npmjs.com
registry.npmjs.org

# Ubuntu/Debian repos (needed for apt)
.ubuntu.com
.debian.org
security.ubuntu.com

# Let's Encrypt (SSL certificates)
.letsencrypt.org
acme-v02.api.letsencrypt.org

# Tailscale coordination
.tailscale.com

# GitHub (for repo updates)
.github.com
.githubusercontent.com

# Gravatar (WordPress avatars)
.gravatar.com

# WooCommerce
.woocommerce.com
DOMAINS

# Write Squid config — only allow outbound to allowlisted domains
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

systemctl enable squid > /dev/null 2>&1
systemctl restart squid

if systemctl is-active squid > /dev/null 2>&1; then
    info "Squid egress proxy running. Only allowlisted domains can be reached."
else
    warn "Squid may have issues. Check: systemctl status squid"
fi

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
    systemctl daemon-reload
fi

info "OpenClaw outbound traffic now filtered through Squid."

# ═════════════════════════════════════════════
# Step 5: wp-admin Lockdown
# ═════════════════════════════════════════════
log "Step 5/5: Locking down wp-admin..."

# Detect which web server is running
if command -v nginx &>/dev/null && systemctl is-active nginx > /dev/null 2>&1; then
    # Create an Nginx snippet that restricts wp-admin and wp-login
    NGINX_SNIPPET="/etc/nginx/snippets/wp-admin-restrict.conf"

    if [[ -n "$TS_IP" ]]; then
        # Get the Tailscale subnet (usually 100.x.x.x/8)
        TS_SUBNET="100.64.0.0/10"

        cat > "$NGINX_SNIPPET" <<NGINXSNIP
# Restrict wp-admin and wp-login.php to Tailscale network only
location ~ ^/(wp-admin|wp-login\.php) {
    allow ${TS_SUBNET};
    allow 127.0.0.1;
    deny all;

    # Pass PHP requests
    location ~ \.php\$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')-fpm.sock;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        include fastcgi_params;
    }
}
NGINXSNIP

        # Include the snippet in the WordPress Nginx config if not already included
        WP_NGINX_CONF="/etc/nginx/sites-available/wordpress"
        if [[ -f "$WP_NGINX_CONF" ]] && ! grep -q "wp-admin-restrict" "$WP_NGINX_CONF" 2>/dev/null; then
            # Insert the include before the closing brace of the server block
            sed -i '/location = \/robots.txt/a \\n    include snippets/wp-admin-restrict.conf;' "$WP_NGINX_CONF"

            if nginx -t > /dev/null 2>&1; then
                systemctl reload nginx
                info "wp-admin restricted to Tailscale network only."
            else
                warn "Nginx config test failed. Reverting wp-admin restriction."
                sed -i '/wp-admin-restrict/d' "$WP_NGINX_CONF"
                rm -f "$NGINX_SNIPPET"
            fi
        else
            info "wp-admin restriction already configured or Nginx config not found at expected path."
        fi
    else
        warn "Tailscale IP not available. Skipping wp-admin lockdown."
        warn "Re-run after 'tailscale up' to apply wp-admin restrictions."
    fi
else
    info "Nginx not detected. If using Apache, add Tailscale IP restriction to .htaccess manually."
fi

# ═════════════════════════════════════════════
# Restart OpenClaw with all changes
# ═════════════════════════════════════════════
log "Restarting OpenClaw with hardened configuration..."
systemctl restart openclaw

sleep 3
OPENCLAW_STATUS=$(systemctl is-active openclaw 2>/dev/null || echo "unknown")

# ═════════════════════════════════════════════
# Summary
# ═════════════════════════════════════════════
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
LiteLLM Master Key: ${LITELLM_MASTER_KEY}
LiteLLM Config: ${LITELLM_DIR}/config.yaml
LiteLLM Budget: \$${LITELLM_BUDGET}/month
Squid Allowlist: /etc/squid/allowed-domains.txt

IMPORTANT: Connect via Tailscale from now on!
  ssh root@${TS_IP:-TAILSCALE_IP}
HARDCREDS

chmod 600 /root/setup-credentials.txt
info "Hardening details appended to /root/setup-credentials.txt"
echo ""
