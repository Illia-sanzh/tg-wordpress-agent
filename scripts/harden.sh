#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# OpenClaw Security Hardening Script
#
# Applies production-grade security to your OpenClaw + WordPress VPS:
#   1. SSH hardening (disable password auth)
#   2. Tailscale VPN (private network for SSH + wp-admin)
#   3. Squid egress proxy (restrict outbound connections)
#   4. wp-admin lockdown (only accessible via Tailscale)
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
TOTAL_STEPS=7
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
echo "    3. Set up Squid egress filtering"
echo "    4. Lock down wp-admin to Tailscale only"
echo "    5. Harden the OpenClaw systemd service (process isolation)"
echo "    6. Install LiteLLM API budget proxy (monthly spend limit)"
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
# Use systemctl cat to check if the service unit actually exists
if systemctl cat ssh.service > /dev/null 2>&1; then
    spin "Restarting SSH daemon" systemctl restart ssh
elif systemctl cat sshd.service > /dev/null 2>&1; then
    spin "Restarting SSH daemon" systemctl restart sshd
else
    warn "Could not detect SSH service name — restart SSH manually"
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
# Step 3: Squid Egress Filtering
# ═════════════════════════════════════════════
progress 3 "Setting up Squid egress proxy..."

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
# Step 4: wp-admin Lockdown
# ═════════════════════════════════════════════
progress 4 "Locking down wp-admin..."

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
# Step 5: Systemd Service Hardening
# ═════════════════════════════════════════════
progress 5 "Hardening OpenClaw systemd service..."

# Use a drop-in file so this is additive and idempotent.
# Equivalent to Podman container-level isolation: no new privileges,
# read-only system paths, private /tmp, and resource limits.
DROPIN_DIR="/etc/systemd/system/openclaw.service.d"
DROPIN_FILE="${DROPIN_DIR}/hardening.conf"

quiet mkdir -p "$DROPIN_DIR"

action "Writing systemd security drop-in..."
cat > "$DROPIN_FILE" <<'DROPIN'
# OpenClaw process isolation — applied by harden.sh
# Equivalent to rootless Podman container security boundaries.

[Service]
# ── Privilege escalation prevention (container --no-new-privileges) ──
# Prevent the process from gaining new privileges via setuid/setgid
NoNewPrivileges=yes

# ── Filesystem hardening (container read-only system image) ──
# Make /usr, /boot, /etc read-only for this service
ProtectSystem=strict

# Protect /home (other users), /root, /run/user from the service
ProtectHome=read-only

# Give the service its own private /tmp mount
# Prevents temp-file leaks between processes
PrivateTmp=yes

# Prevent access to physical device nodes
PrivateDevices=yes

# Explicitly allow writes where the service legitimately needs them.
# ReadOnlyPaths below will pin specific files read-only even inside these dirs.
ReadWritePaths=/home/openclaw /tmp /run

# ── Image immutability (container read-only image layers) ──
# The openclaw binary itself is immutable via ProtectSystem=strict (/usr/local).
# Additionally lock the credential and config files so a rogue agent cannot
# exfiltrate secrets by modifying them or swap in a malicious config at runtime.
ReadOnlyPaths=/home/openclaw/.env /home/openclaw/.openclaw/openclaw.json

# ── PID namespace isolation (container --pid=private) ──
# Give the service its own PID namespace. The process cannot see or signal
# host processes — equivalent to Podman's default PID isolation.
# Requires systemd 254+ (Ubuntu 24.04 ships systemd 255).
PrivatePIDs=yes

# ── Resource limits ──
MemoryMax=1500M
CPUQuota=70%
LimitNOFILE=65536

# ── Network isolation (container private network namespace) ──
# Force ALL outbound connections through Squid (127.0.0.1:3128).
# The process cannot reach the internet directly even if it ignores http_proxy env vars.
#
# How it works:
#   - IPAddressDeny=any  → block all outbound by default
#   - IPAddressAllow=localhost → allow only loopback (where Squid + LiteLLM listen)
#   - Squid/LiteLLM run as separate services so THEY are not blocked
#   - openclaw listens on 127.0.0.1:18789 → local connections still work
IPAddressDeny=any
IPAddressAllow=localhost

# ── Capability bounding (container --cap-drop=all) ──
# Drop every Linux capability. Combined with NoNewPrivileges=yes, the process
# cannot gain any elevated kernel privileges even if it tries.
CapabilityBoundingSet=
AmbientCapabilities=

# ── Syscall filtering (Podman default seccomp profile equivalent) ──
# Whitelist only the syscalls a normal service needs. Blocks dangerous calls like
# ptrace (process injection), mount, kexec, perf_event_open, kernel module loading.
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
SystemCallArchitectures=native

# ── Kernel hardening (container kernel namespace isolation) ──
# Prevent writing to kernel tunables (/proc/sys, /sys)
ProtectKernelTunables=yes

# Prevent loading/unloading kernel modules
ProtectKernelModules=yes

# Prevent reading kernel log buffer (dmesg)
ProtectKernelLogs=yes

# Make /sys/fs/cgroup read-only (prevent cgroup escapes)
ProtectControlGroups=yes

# Prevent changing the system clock
ProtectClock=yes

# Prevent changing the hostname or domainname
ProtectHostname=yes

# Prevent creating any new namespaces (mount, user, pid, net, ipc, etc.)
# This blocks a compromised process from escaping its sandbox via unshare(2).
RestrictNamespaces=yes

# Prevent changing binary execution domain (personality syscall)
LockPersonality=yes

# Prevent setting real-time scheduling priorities
RestrictRealtime=yes

# Prevent setting SUID/SGID bits on new files
RestrictSUIDSGID=yes

# Remove all IPC objects (message queues, semaphores, shared memory)
# owned by this service when it stops — no persistent inter-process state leaks
RemoveIPC=yes
DROPIN

quiet systemctl daemon-reload
action "${GREEN}✓${NC} Systemd hardening applied (NoNewPrivileges, PrivatePIDs, ProtectSystem=strict, IPAddressDeny, MemoryMax=1500M, ReadOnlyPaths for credentials)"

# ═════════════════════════════════════════════
# Step 6: API Key Isolation Proxy
# ═════════════════════════════════════════════
progress 6 "Installing API key isolation proxy..."

PROXY_ENV_FILE="${OCLAW_HOME}/keyproxy.env"
PROXY_SCRIPT="/usr/local/bin/openclaw-keyproxy"
PROXY_CONFIGURED=false
PROXY_SKIP=false

PROXY_ALREADY_INSTALLED=false
if grep -q '^ANTHROPIC_BASE_URL=' "${OCLAW_HOME}/.env" 2>/dev/null; then
    PROXY_ALREADY_INSTALLED=true
    action "Key proxy already installed — refreshing script..."
fi

if [[ "$PROXY_ALREADY_INSTALLED" == "false" ]]; then
    REAL_API_KEY=$(grep '^ANTHROPIC_API_KEY=' "${OCLAW_HOME}/.env" 2>/dev/null | cut -d= -f2- || echo "")

    if [[ -z "$REAL_API_KEY" ]]; then
        warn "ANTHROPIC_API_KEY not found in ${OCLAW_HOME}/.env — skipping key proxy setup"
        warn "Set ANTHROPIC_API_KEY and re-run harden.sh to enable key isolation"
        PROXY_SKIP=true
    else
        PROXY_KEY="sk-openclaw-$(openssl rand -hex 20)"

        action "Writing key proxy secrets file (root-only)..."
        cat > "$PROXY_ENV_FILE" <<PROXYENV
# Real Anthropic key — only root can read this; forwarded by keyproxy to Anthropic
REAL_KEY=${REAL_API_KEY}
# Proxy key — what OpenClaw sends; keyproxy validates and swaps for the real key
PROXY_KEY=${PROXY_KEY}
PROXYENV
        chmod 600 "$PROXY_ENV_FILE"
        chown root:root "$PROXY_ENV_FILE"

        action "Routing OpenClaw API calls through key proxy..."
        sed -i "s|^ANTHROPIC_API_KEY=.*|ANTHROPIC_API_KEY=${PROXY_KEY}|" "${OCLAW_HOME}/.env"
        echo "ANTHROPIC_BASE_URL=http://127.0.0.1:4000" >> "${OCLAW_HOME}/.env"

        cat >> /root/setup-credentials.txt <<PROXYCREDS

═══ API Key Isolation Proxy ═══
Service:      openclaw-keyproxy.service (127.0.0.1:4000, loopback only)
Script:       ${PROXY_SCRIPT}
Proxy key:    ${PROXY_KEY}
Real API key: secured in ${PROXY_ENV_FILE} (root-only, 600)

Spend tracking: https://console.anthropic.com/settings/usage
PROXYCREDS
    fi
fi

if [[ "$PROXY_SKIP" == "false" ]]; then
    # Remove LiteLLM if left over from a previous version of this script
    if systemctl is-enabled litellm &>/dev/null 2>&1; then
        spin "Removing old LiteLLM service" \
            bash -c 'systemctl stop litellm 2>/dev/null; systemctl disable litellm 2>/dev/null; rm -f /etc/systemd/system/litellm.service'
    fi
    rm -f "${DROPIN_DIR}/litellm-dep.conf"
    # Remove the temporary IP bypass drop-in that was added when LiteLLM was disabled for testing
    rm -f "${DROPIN_DIR}/ip-override.conf"

    action "Writing key isolation proxy script..."
    cat > "$PROXY_SCRIPT" <<'PYEOF'
#!/usr/bin/env python3
"""
openclaw-keyproxy — Anthropic API key isolation proxy
Accepts requests with PROXY_KEY, forwards to Anthropic with REAL_KEY.
No external dependencies — Python stdlib only.
"""
import http.client
import http.server
import os
import ssl
import sys
from socketserver import ThreadingMixIn

PROXY_KEY = os.environ.get('PROXY_KEY', '')
REAL_KEY  = os.environ.get('REAL_KEY', '')
PORT      = int(os.environ.get('PROXY_PORT', '4000'))

if not PROXY_KEY or not REAL_KEY:
    sys.exit('PROXY_KEY and REAL_KEY must be set in environment')

_PASS_REQ  = {'anthropic-version', 'anthropic-beta', 'content-type', 'accept', 'user-agent'}
_DROP_RESP = {'transfer-encoding', 'connection', 'keep-alive'}


class ProxyHandler(http.server.BaseHTTPRequestHandler):

    def do_GET(self):
        if self.path in ('/health', '/health/liveliness'):
            self._reply(200, b'ok', 'text/plain')
        else:
            self._reply(404, b'not found', 'text/plain')

    def do_POST(self):
        if self.headers.get('x-api-key', '') != PROXY_KEY:
            body = b'{"error":{"type":"authentication_error","message":"invalid x-api-key"}}'
            self._reply(401, body, 'application/json')
            return

        length = int(self.headers.get('Content-Length', 0))
        req_body = self.rfile.read(length) if length > 0 else b''

        fwd = {'x-api-key': REAL_KEY}
        for h in _PASS_REQ:
            v = self.headers.get(h)
            if v:
                fwd[h] = v
        if req_body:
            fwd['Content-Length'] = str(len(req_body))

        ctx = ssl.create_default_context()
        conn = http.client.HTTPSConnection('api.anthropic.com', context=ctx, timeout=600)
        try:
            conn.request('POST', self.path, body=req_body, headers=fwd)
            resp = conn.getresponse()
            self.send_response(resp.status)
            for k, v in resp.getheaders():
                if k.lower() not in _DROP_RESP:
                    self.send_header(k, v)
            self.end_headers()
            while True:
                chunk = resp.read(8192)
                if not chunk:
                    break
                self.wfile.write(chunk)
                self.wfile.flush()
        except Exception as exc:
            try:
                self._reply(502, str(exc).encode(), 'text/plain')
            except Exception:
                pass
        finally:
            conn.close()

    def _reply(self, code, body, ctype):
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        sys.stderr.write(f'keyproxy {fmt % args}\n')


class ThreadedServer(ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


if __name__ == '__main__':
    srv = ThreadedServer(('127.0.0.1', PORT), ProxyHandler)
    print(f'openclaw-keyproxy listening on 127.0.0.1:{PORT}', flush=True)
    srv.serve_forever()
PYEOF
    chmod 755 "$PROXY_SCRIPT"

    action "Creating key proxy systemd service..."
    cat > /etc/systemd/system/openclaw-keyproxy.service <<'PROXYSVC'
[Unit]
Description=OpenClaw API Key Isolation Proxy
After=network.target
Before=openclaw.service

[Service]
Type=simple
User=root
EnvironmentFile=/home/openclaw/keyproxy.env
ExecStart=/usr/bin/python3 /usr/local/bin/openclaw-keyproxy
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
PROXYSVC

    cat > "${DROPIN_DIR}/keyproxy-dep.conf" <<'DEPCFG'
[Unit]
Wants=openclaw-keyproxy.service
After=openclaw-keyproxy.service
DEPCFG

    quiet systemctl daemon-reload
    quiet systemctl enable openclaw-keyproxy

    if [[ "$PROXY_ALREADY_INSTALLED" == "true" ]]; then
        spin "Restarting key proxy" systemctl restart openclaw-keyproxy
    else
        spin "Starting key proxy" systemctl start openclaw-keyproxy
    fi

    PROXY_STATUS="starting"
    for _i in $(seq 1 5); do
        sleep 2
        if curl -sf "http://127.0.0.1:4000/health" > /dev/null 2>&1; then
            PROXY_STATUS="healthy"
            break
        fi
    done

    PROXY_CONFIGURED=true
    if [[ "$PROXY_STATUS" == "healthy" ]]; then
        action "${GREEN}✓${NC} Key proxy running — real API key isolated from OpenClaw"
    else
        action "${YELLOW}!${NC} Key proxy still starting — check: journalctl -u openclaw-keyproxy -n 20"
    fi
fi  # end: PROXY_SKIP check

# ═════════════════════════════════════════════
# Step 7: Restart OpenClaw
# ═════════════════════════════════════════════
progress 7 "Restarting OpenClaw with hardened config..."

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
echo -e "  ${BOLD}Key Isolation Proxy${NC}"
if [[ "$PROXY_CONFIGURED" == "true" ]]; then
echo "    Status:            $(systemctl is-active openclaw-keyproxy 2>/dev/null || echo 'unknown')"
echo "    Endpoint:          127.0.0.1:4000 (loopback only)"
echo "    Real API key:      ${PROXY_ENV_FILE} (root-only)"
echo "    Spend tracking:    https://console.anthropic.com/settings/usage"
else
echo "    Status:            not configured (ANTHROPIC_API_KEY missing from .env)"
fi
echo ""
echo -e "  ${BOLD}Systemd Service Hardening${NC}"
echo "    NoNewPrivileges:   yes"
echo "    CapabilityBoundingSet: (all dropped)"
echo "    SystemCallFilter:  @system-service (dangerous syscalls blocked)"
echo "    ProtectSystem:     strict (/, /usr, /etc read-only)"
echo "    PrivateTmp:        yes (isolated /tmp namespace)"
echo "    PrivatePIDs:       yes (own PID namespace — cannot see host processes)"
echo "    Network isolation: IPAddressDeny=any (loopback only → Squid + key proxy enforced)"
echo "    Immutability:      ReadOnlyPaths on .env + openclaw.json (credentials locked)"
echo "    Kernel hardening:  ProtectKernelTunables/Modules/Logs, ProtectControlGroups"
echo "                       ProtectClock, ProtectHostname, RestrictNamespaces"
echo "                       LockPersonality, RestrictRealtime, RestrictSUIDSGID"
echo "    MemoryMax:         1500 MB"
echo "    CPUQuota:          70%"
echo "    Drop-in:           ${DROPIN_FILE}"
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
Squid Allowlist: /etc/squid/allowed-domains.txt
Systemd drop-in: ${DROPIN_FILE}
  NoNewPrivileges=yes, ProtectSystem=strict, PrivateTmp=yes
  PrivatePIDs=yes (PID namespace isolation)
  ReadOnlyPaths: .env + openclaw.json (credential immutability)
  ProtectKernelTunables/Modules/Logs, ProtectControlGroups
  ProtectClock, ProtectHostname, RestrictNamespaces, LockPersonality
  RestrictRealtime, RestrictSUIDSGID, RemoveIPC
  MemoryMax=1500M, CPUQuota=70%

IMPORTANT: Connect via Tailscale from now on!
  ssh root@${TS_IP:-TAILSCALE_IP}
HARDCREDS

chmod 600 /root/setup-credentials.txt
info "Hardening details appended to /root/setup-credentials.txt"
info "Full log: cat ${HARDEN_LOG}"
echo ""
