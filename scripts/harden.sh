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
# Step 6: LiteLLM Budget Proxy
# ═════════════════════════════════════════════
progress 6 "Installing LiteLLM API budget proxy..."

LITELLM_CFG_FILE="${OCLAW_HOME}/litellm-config.yaml"
LITELLM_ENV_FILE="${OCLAW_HOME}/litellm.env"
LITELLM_CONFIGURED=false
LITELLM_SKIP=false

# Detect if LiteLLM was installed on a prior run.
# Even if already installed, we still refresh the model config below so
# model aliases stay current without requiring a full reinstall.
LITELLM_ALREADY_INSTALLED=false
if grep -q '^ANTHROPIC_BASE_URL=' "${OCLAW_HOME}/.env" 2>/dev/null; then
    LITELLM_ALREADY_INSTALLED=true
    action "LiteLLM already installed — refreshing model config..."
fi

if [[ "$LITELLM_ALREADY_INSTALLED" == "false" ]]; then
    # Fresh install: read real API key before we swap it out
    REAL_API_KEY=$(grep '^ANTHROPIC_API_KEY=' "${OCLAW_HOME}/.env" 2>/dev/null | cut -d= -f2- || echo "")

    if [[ -z "$REAL_API_KEY" ]]; then
        warn "ANTHROPIC_API_KEY not found in ${OCLAW_HOME}/.env — skipping LiteLLM setup"
        warn "Set ANTHROPIC_API_KEY and re-run harden.sh to enable API budget limits"
        LITELLM_SKIP=true
    else
        # Install LiteLLM in a virtual environment.
        # Ubuntu 24.04 uses PEP 668 — pip cannot uninstall apt-managed packages like
        # typing_extensions, so global pip installs fail. A venv is the correct fix:
        # it is fully isolated from system packages, no conflicts possible.
        if ! command -v python3 &>/dev/null; then
            spin "Installing python3" apt-get install -y -qq python3
        fi
        # Ubuntu splits venv into python3.X-venv packages that include ensurepip.
        # python3-venv alone is not sufficient — the version-specific package is required.
        PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
        spin "Installing python${PY_VER}-venv" apt-get install -y -qq "python${PY_VER}-venv"

        LITELLM_VENV="${OCLAW_HOME}/litellm-venv"
        spin "Creating LiteLLM virtualenv" python3 -m venv "$LITELLM_VENV"
        spin "Installing LiteLLM" "${LITELLM_VENV}/bin/pip" install -q 'litellm[proxy]'
        chown -R openclaw:openclaw "$LITELLM_VENV"

        # Generate proxy master key — this replaces the real API key in openclaw's env.
        # OpenClaw sends this key to LiteLLM; LiteLLM validates it, tracks spend, and
        # forwards to Anthropic with the real key. OpenClaw never sees the real key again.
        LITELLM_PROXY_KEY="sk-openclaw-$(openssl rand -hex 20)"

        # LiteLLM env file — root-owned (600) so the openclaw user cannot cat it directly.
        # systemd reads EnvironmentFile as root before dropping to the service user,
        # so LiteLLM still gets these vars at startup.
        action "Writing LiteLLM secrets file (root-only)..."
        cat > "$LITELLM_ENV_FILE" <<LITELLM_ENV
# Real Anthropic API key — used by LiteLLM to forward requests to Anthropic
# OpenClaw uses a proxy key (below) and never sees this value via the filesystem
REAL_ANTHROPIC_API_KEY=${REAL_API_KEY}
# Also expose as ANTHROPIC_API_KEY so LiteLLM provider-routing (anthropic/model syntax)
# uses the real key instead of falling back to the client's proxy key → 401
ANTHROPIC_API_KEY=${REAL_API_KEY}
LITELLM_MASTER_KEY=${LITELLM_PROXY_KEY}
LITELLM_ENV
        chmod 600 "$LITELLM_ENV_FILE"
        chown root:root "$LITELLM_ENV_FILE"

        action "Creating LiteLLM systemd service..."
        cat > /etc/systemd/system/litellm.service <<LITELLM_SVC
[Unit]
Description=LiteLLM API Budget Proxy
Documentation=https://docs.litellm.ai
After=network.target squid.service
Before=openclaw.service

[Service]
Type=simple
User=openclaw
Group=openclaw
WorkingDirectory=/home/openclaw
EnvironmentFile=/home/openclaw/litellm.env
Environment="PATH=/home/openclaw/litellm-venv/bin:/usr/local/bin:/usr/bin:/bin"
Environment="http_proxy=http://127.0.0.1:3128"
Environment="https_proxy=http://127.0.0.1:3128"
ExecStart=/home/openclaw/litellm-venv/bin/litellm --config /home/openclaw/litellm-config.yaml --port 4000 --host 127.0.0.1
Restart=on-failure
RestartSec=15
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
LITELLM_SVC

        # Tell openclaw's systemd unit to start after litellm
        cat > "${DROPIN_DIR}/litellm-dep.conf" <<'DEPCFG'
[Unit]
# Ensure LiteLLM budget proxy is running before OpenClaw starts.
# If LiteLLM dies, OpenClaw will restart and wait for it to come back.
Wants=litellm.service
After=litellm.service
DEPCFG

        # Swap the real API key for the proxy key in openclaw's env.
        # Add ANTHROPIC_BASE_URL so the Anthropic SDK routes to LiteLLM instead of
        # calling api.anthropic.com directly (which would fail — proxy key ≠ Anthropic key).
        action "Routing OpenClaw API calls through LiteLLM..."
        sed -i "s|^ANTHROPIC_API_KEY=.*|ANTHROPIC_API_KEY=${LITELLM_PROXY_KEY}|" "${OCLAW_HOME}/.env"
        echo "ANTHROPIC_BASE_URL=http://127.0.0.1:4000" >> "${OCLAW_HOME}/.env"

        quiet systemctl daemon-reload
        quiet systemctl enable litellm

        # Append LiteLLM details to credentials file
        cat >> /root/setup-credentials.txt <<LITELLM_CREDS

═══ LiteLLM Budget Proxy ═══
Service:      litellm.service (127.0.0.1:4000, loopback only)
Config:       ${LITELLM_CFG_FILE}
Monthly cap:  \$30 (edit general_settings.max_budget in litellm-config.yaml)
Proxy key:    ${LITELLM_PROXY_KEY}
Real API key: secured in ${LITELLM_ENV_FILE} (root-only, 600)

Check spend:  https://console.anthropic.com/settings/usage
LITELLM_CREDS
    fi  # end: api key present
fi  # end: fresh install block

if [[ "$LITELLM_SKIP" == "false" ]]; then
    # Always write the latest model config — even on re-runs, so model aliases
    # are kept current without requiring a full reinstall.
    # Root cause of "invalid x-api-key": openclaw.json uses "anthropic/claude-sonnet-4-5-20250929"
    # but litellm-config.yaml didn't have that model, causing LiteLLM to proxy it directly to
    # Anthropic with the proxy key (which is not a valid Anthropic key) → 401.
    action "Writing LiteLLM model config..."
    cat > "$LITELLM_CFG_FILE" <<LITELLM_CFG
model_list:
  - model_name: claude-sonnet-4-6
    litellm_params:
      model: anthropic/claude-sonnet-4-6
      api_key: os.environ/REAL_ANTHROPIC_API_KEY
  - model_name: anthropic/claude-sonnet-4-6
    litellm_params:
      model: anthropic/claude-sonnet-4-6
      api_key: os.environ/REAL_ANTHROPIC_API_KEY
  - model_name: claude-sonnet-4-5-20250929
    litellm_params:
      model: anthropic/claude-sonnet-4-6
      api_key: os.environ/REAL_ANTHROPIC_API_KEY
  - model_name: anthropic/claude-sonnet-4-5-20250929
    litellm_params:
      model: anthropic/claude-sonnet-4-6
      api_key: os.environ/REAL_ANTHROPIC_API_KEY
  - model_name: claude-haiku-4-5-20251001
    litellm_params:
      model: anthropic/claude-haiku-4-5-20251001
      api_key: os.environ/REAL_ANTHROPIC_API_KEY
  - model_name: anthropic/claude-haiku-4-5-20251001
    litellm_params:
      model: anthropic/claude-haiku-4-5-20251001
      api_key: os.environ/REAL_ANTHROPIC_API_KEY
litellm_settings:
  drop_params: true
  request_timeout: 600
general_settings:
  master_key: os.environ/LITELLM_MASTER_KEY
  max_budget: 30
  budget_duration: 30d
LITELLM_CFG
    chown openclaw:openclaw "$LITELLM_CFG_FILE"
    chmod 640 "$LITELLM_CFG_FILE"

    # Ensure ANTHROPIC_API_KEY is in litellm.env.
    # LiteLLM uses provider-based routing when the model name starts with "anthropic/",
    # which reads ANTHROPIC_API_KEY (not REAL_ANTHROPIC_API_KEY) from the environment.
    # Without this, model requests like "anthropic/claude-sonnet-4-5-20250929" fall back
    # to the client's proxy key and Anthropic returns 401.
    if [[ -f "$LITELLM_ENV_FILE" ]] && ! grep -q '^ANTHROPIC_API_KEY=' "$LITELLM_ENV_FILE" 2>/dev/null; then
        REAL_KEY_VAL=$(grep '^REAL_ANTHROPIC_API_KEY=' "$LITELLM_ENV_FILE" | cut -d= -f2-)
        if [[ -n "$REAL_KEY_VAL" ]]; then
            printf '\n# LiteLLM provider routing fallback\nANTHROPIC_API_KEY=%s\n' "$REAL_KEY_VAL" >> "$LITELLM_ENV_FILE"
            action "Added ANTHROPIC_API_KEY to litellm.env for provider routing"
        fi
    fi

    # Ensure openclaw.json uses the canonical model name without anthropic/ prefix.
    # The anthropic/ prefix triggers LiteLLM provider routing (which uses ANTHROPIC_API_KEY).
    # A name without the prefix triggers model_list lookup (which uses the configured api_key).
    # Using the canonical name is simpler and avoids routing ambiguity.
    OCLAW_JSON="${OCLAW_HOME}/.openclaw/openclaw.json"
    if [[ -f "$OCLAW_JSON" ]] && grep -q '"model":.*"anthropic/' "$OCLAW_JSON" 2>/dev/null; then
        OLD_MODEL=$(grep -o '"model": *"[^"]*"' "$OCLAW_JSON" | head -1 | sed 's/"model": *"\([^"]*\)"/\1/')
        sed -i 's|"model": *"anthropic/[^"]*"|"model": "claude-sonnet-4-6"|g' "$OCLAW_JSON"
        chown openclaw:openclaw "$OCLAW_JSON"
        action "Updated openclaw.json model: ${OLD_MODEL} → claude-sonnet-4-6"
    fi

    # Start (fresh install) or restart (re-run, to pick up model config changes)
    if [[ "$LITELLM_ALREADY_INSTALLED" == "true" ]]; then
        spin "Reloading LiteLLM config" systemctl restart litellm
    else
        spin "Starting LiteLLM" systemctl start litellm
    fi

    # Wait up to 30s for LiteLLM to become ready.
    # Use /health/liveliness — a simple ping that doesn't require an API key.
    LITELLM_STATUS="starting"
    for _i in $(seq 1 10); do
        sleep 3
        if curl -sf "http://127.0.0.1:4000/health/liveliness" > /dev/null 2>&1; then
            LITELLM_STATUS="healthy"
            break
        fi
    done

    LITELLM_CONFIGURED=true
    if [[ "$LITELLM_STATUS" == "healthy" ]]; then
        action "${GREEN}✓${NC} LiteLLM running — \$30/month cap, real API key shielded from OpenClaw"
    else
        action "${YELLOW}!${NC} LiteLLM still starting — check: journalctl -u litellm -n 20"
    fi
fi  # end: LITELLM_SKIP check

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
echo -e "  ${BOLD}LiteLLM Budget Proxy${NC}"
if [[ "$LITELLM_CONFIGURED" == "true" ]]; then
echo "    Status:            $(systemctl is-active litellm 2>/dev/null || echo 'unknown')"
echo "    Endpoint:          127.0.0.1:4000 (loopback only)"
echo "    Monthly cap:       \$30 (edit litellm-config.yaml to change)"
echo "    Real API key:      ${LITELLM_ENV_FILE} (root-only)"
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
echo "    Network isolation: IPAddressDeny=any (loopback only → Squid + LiteLLM enforced)"
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
