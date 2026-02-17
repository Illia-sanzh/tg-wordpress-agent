#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# VPS Setup Script for OpenClaw + WordPress + Telegram
# Tested on: Ubuntu 22.04 / 24.04 LTS
# Run as root: bash setup-vps.sh
#
# Supports two modes:
#   - Fresh install (default): installs the full stack
#   - Existing WordPress: set EXISTING_WORDPRESS=true to skip
#     web server, database, and WordPress installation
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
err()  { echo -e "${RED}[✗]${NC} $1"; exit 1; }
info() { echo -e "${CYAN}[i]${NC} $1"; }

# ── Progress bar system ──
TOTAL_STEPS=12
_BAR_DRAWN=false
INSTALL_LOG="/tmp/openclaw-install.log"
: > "$INSTALL_LOG"

# ── Crash handler — show last log lines on failure ──
on_error() {
    local exit_code=$?
    echo ""
    echo ""
    echo -e "${RED}${BOLD}  Installation failed (exit code ${exit_code})${NC}"
    echo ""
    if [[ -s "$INSTALL_LOG" ]]; then
        echo -e "${YELLOW}  Last 25 lines of ${INSTALL_LOG}:${NC}"
        echo -e "${DIM}"
        tail -25 "$INSTALL_LOG" 2>/dev/null | sed 's/^/    /'
        echo -e "${NC}"
    fi
    echo -e "  Full log: ${CYAN}cat ${INSTALL_LOG}${NC}"
    echo ""
}
trap on_error ERR

# ── Wait for apt lock (fresh VPS runs unattended-upgrades on boot) ──
wait_for_apt() {
    local waited=0
    while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || \
          fuser /var/lib/apt/lists/lock >/dev/null 2>&1 || \
          fuser /var/lib/dpkg/lock >/dev/null 2>&1; do
        if [[ $waited -eq 0 ]]; then
            action "Waiting for system package manager to finish..."
        fi
        sleep 3
        waited=$((waited + 3))
        if [[ $waited -ge 180 ]]; then
            err "apt lock held for over 3 minutes. Try: kill the unattended-upgrades process and re-run."
        fi
    done
    if [[ $waited -gt 0 ]]; then
        action "Package manager is now free (waited ${waited}s)"
    fi
}

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

action() {
    if [[ "$_BAR_DRAWN" == "true" ]]; then
        echo -ne "\033[1A\033[2K  ${CYAN}$1${NC}\n"
    else
        echo -e "  ${CYAN}$1${NC}"
    fi
}

spin() {
    local msg="$1"
    shift
    action "⠋ ${msg}"

    # Run in subshell to isolate from set -e
    ( set +e; "$@" >> "$INSTALL_LOG" 2>&1 ) &
    local pid=$!

    local frames=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
    local i=0
    while kill -0 "$pid" 2>/dev/null; do
        action "${frames[$i]} ${msg}"
        i=$(( (i+1) % ${#frames[@]} ))
        sleep 0.15
    done

    # Temporarily disable set -e so we can capture the exit code
    set +e
    wait "$pid"
    local rc=$?
    set -e

    if [[ $rc -eq 0 ]]; then
        action "${GREEN}✓${NC} ${msg}"
    else
        action "${RED}✗${NC} ${msg} — check ${INSTALL_LOG}"
        echo "" >> "$INSTALL_LOG"
        echo "=== FAILED: ${msg} (exit code ${rc}) ===" >> "$INSTALL_LOG"
    fi
    return $rc
}

quiet() {
    "$@" >> "$INSTALL_LOG" 2>&1
}

# ── Check root ──
[[ $EUID -ne 0 ]] && err "This script must be run as root"

# ── Mode: existing WordPress or fresh install? ──
EXISTING_WORDPRESS="${EXISTING_WORDPRESS:-false}"

# ── Configuration ──
WP_DOMAIN="${WP_DOMAIN:-your-domain.com}"
WP_PATH="${WP_PATH:-/var/www/html}"
WP_ADMIN_USER="${WP_ADMIN_USER:-admin}"
WP_ADMIN_PASS="${WP_ADMIN_PASS:-$(openssl rand -base64 16)}"
WP_ADMIN_EMAIL="${WP_ADMIN_EMAIL:-admin@$WP_DOMAIN}"
WP_DB_NAME="${WP_DB_NAME:-wordpress}"
WP_DB_USER="${WP_DB_USER:-wpuser}"
WP_DB_PASS="${WP_DB_PASS:-$(openssl rand -base64 24)}"
MYSQL_ROOT_PASS="${MYSQL_ROOT_PASS:-$(openssl rand -base64 24)}"
TELEGRAM_BOT_TOKEN="${TELEGRAM_BOT_TOKEN:-}"
TELEGRAM_USER_ID="${TELEGRAM_USER_ID:-}"
ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY:-}"

# ── Detect IP-only vs domain ──
IS_IP_ONLY=false
if [[ "$WP_DOMAIN" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    IS_IP_ONLY=true
    WP_PROTOCOL="http"
else
    WP_PROTOCOL="https"
fi

# ── Validate required inputs ──
[[ "$WP_DOMAIN" == "your-domain.com" ]] && err "Set WP_DOMAIN before running this script (export WP_DOMAIN=your-domain.com)"
[[ -z "$TELEGRAM_BOT_TOKEN" ]] && warn "TELEGRAM_BOT_TOKEN not set — you'll need to add it to the config manually later."
[[ -z "$ANTHROPIC_API_KEY" ]] && warn "ANTHROPIC_API_KEY not set — you'll need to add it to .env manually later."

echo ""
echo "════════════════════════════════════════════════════"
if [[ "$EXISTING_WORDPRESS" == "true" ]]; then
    echo -e "${CYAN} Mode: Existing WordPress${NC}"
    echo "  WordPress path: ${WP_PATH}"
    echo "  Skipping: Nginx, MariaDB, PHP, WordPress install"
    echo "  Installing: WP-CLI, Bridge Plugin, OpenClaw, Systemd Service"
else
    echo -e "${CYAN} Mode: Fresh Install${NC}"
    echo "  Will install: Full stack (Nginx, PHP, MariaDB, WordPress, OpenClaw)"
fi
echo "  Domain: ${WP_DOMAIN}"
echo "════════════════════════════════════════════════════"
echo ""
echo ""

export DEBIAN_FRONTEND=noninteractive

# ─────────────────────────────────────────────
# Phase 0: Ensure swap exists (prevents OOM on small VPS)
# ─────────────────────────────────────────────

if ! swapon --show | grep -q '/'; then
    echo -e "  ${CYAN}Creating swap file (prevents out-of-memory crashes)...${NC}"
    fallocate -l 2G /swapfile 2>/dev/null || dd if=/dev/zero of=/swapfile bs=1M count=2048 status=none
    chmod 600 /swapfile
    mkswap /swapfile > /dev/null 2>&1
    swapon /swapfile
    if ! grep -q '/swapfile' /etc/fstab 2>/dev/null; then
        echo '/swapfile none swap sw 0 0' >> /etc/fstab
    fi
    echo -e "  ${GREEN}✓${NC} 2GB swap enabled"
else
    echo -e "  ${GREEN}✓${NC} Swap already active"
fi
echo ""

# ─────────────────────────────────────────────
# Phase 1: System Packages
# ─────────────────────────────────────────────

progress 1 "Installing system packages..."

# Wait for any running apt/dpkg processes (e.g. unattended-upgrades on fresh VPS)
wait_for_apt

# Fix any interrupted dpkg from a previous failed run
dpkg --configure -a >> "$INSTALL_LOG" 2>&1 || true

if [[ "$EXISTING_WORDPRESS" == "true" ]]; then
    spin "Updating package lists" apt-get update -qq
    spin "Installing base tools" apt-get install -y -qq curl wget unzip git software-properties-common
else
    spin "Updating package lists" apt-get update -qq
    spin "Installing base tools" apt-get install -y -qq curl wget unzip git software-properties-common

    # Add PHP repository — Ubuntu 22.04 only has PHP 8.1 by default
    if ! apt-cache show php8.3-fpm > /dev/null 2>&1 && ! apt-cache show php8.2-fpm > /dev/null 2>&1; then
        action "Adding PHP repository (needed for PHP 8.2+)..."
        spin "Adding ondrej/php PPA" bash -c 'add-apt-repository -y ppa:ondrej/php && apt-get update -qq'
    fi

    # Detect best available PHP version
    PHP_V=""
    for v in 8.3 8.2 8.1; do
        if apt-cache show "php${v}-fpm" > /dev/null 2>&1; then
            PHP_V="$v"
            break
        fi
    done

    if [[ -z "$PHP_V" ]]; then
        err "No supported PHP version (8.1+) found. Check your OS version."
    fi

    action "Installing web server & PHP ${PHP_V} (this is the longest step)..."
    spin "Installing Nginx + PHP ${PHP_V} + MariaDB" apt-get install -y -qq \
        nginx \
        mariadb-server \
        "php${PHP_V}-fpm" "php${PHP_V}-mysql" "php${PHP_V}-xml" "php${PHP_V}-mbstring" "php${PHP_V}-curl" \
        "php${PHP_V}-zip" "php${PHP_V}-gd" "php${PHP_V}-intl" "php${PHP_V}-imagick" "php${PHP_V}-bcmath" \
        "php${PHP_V}-soap" "php${PHP_V}-opcache" \
        certbot python3-certbot-nginx \
        ufw fail2ban

    PHP_VERSION=$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')
    action "${GREEN}✓${NC} System packages installed (PHP ${PHP_VERSION})"
fi

# ─────────────────────────────────────────────
# Phase 2: Node.js (for OpenClaw)
# ─────────────────────────────────────────────

progress 2 "Setting up Node.js..."

if command -v node &>/dev/null && [[ "$(node -v | cut -d. -f1 | tr -d v)" -ge 22 ]]; then
    action "${GREEN}✓${NC} Node.js $(node -v) already installed"
else
    spin "Adding NodeSource repository" bash -c 'curl -fsSL https://deb.nodesource.com/setup_22.x | bash -'
    spin "Installing Node.js 22" apt-get install -y -qq nodejs
fi

spin "Installing pnpm" npm install -g pnpm || true

# ─────────────────────────────────────────────
# Phase 3: MariaDB Setup (fresh install only)
# ─────────────────────────────────────────────

progress 3 "Setting up database..."

if [[ "$EXISTING_WORDPRESS" != "true" ]]; then
    spin "Starting MariaDB" bash -c 'systemctl start mariadb && systemctl enable mariadb'

    action "Creating database and user..."
    mysql -e "ALTER USER 'root'@'localhost' IDENTIFIED BY '${MYSQL_ROOT_PASS}';" 2>/dev/null || true
    mysql -u root -p"${MYSQL_ROOT_PASS}" -e "
        CREATE DATABASE IF NOT EXISTS ${WP_DB_NAME} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
        CREATE USER IF NOT EXISTS '${WP_DB_USER}'@'localhost' IDENTIFIED BY '${WP_DB_PASS}';
        GRANT ALL PRIVILEGES ON ${WP_DB_NAME}.* TO '${WP_DB_USER}'@'localhost';
        FLUSH PRIVILEGES;
    " >> "$INSTALL_LOG" 2>&1
    action "${GREEN}✓${NC} Database ready"
else
    action "Skipped (existing WordPress)"
fi

# ─────────────────────────────────────────────
# Phase 4: WordPress Installation
# ─────────────────────────────────────────────

progress 4 "Installing WordPress..."

if ! command -v wp &>/dev/null; then
    spin "Downloading WP-CLI" bash -c 'curl -sO https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar && chmod +x wp-cli.phar && mv wp-cli.phar /usr/local/bin/wp'
else
    action "${GREEN}✓${NC} WP-CLI already installed"
fi

if [[ "$EXISTING_WORDPRESS" == "true" ]]; then
    # ── Existing WordPress: validate and create app password ──
    if [[ ! -f "${WP_PATH}/wp-config.php" ]]; then
        err "WordPress not found at ${WP_PATH} — check WP_PATH and try again."
    fi

    action "Found existing WordPress at ${WP_PATH}"

    if [[ "$WP_ADMIN_USER" == "admin" ]]; then
        DETECTED_ADMIN=$(wp user list --role=administrator --field=user_login --path="${WP_PATH}" --allow-root 2>/dev/null | head -1)
        if [[ -n "$DETECTED_ADMIN" ]]; then
            WP_ADMIN_USER="$DETECTED_ADMIN"
        fi
    fi

    WP_APP_PASSWORD=$(wp user application-password create "${WP_ADMIN_USER}" "openclaw-bridge" --porcelain --path="${WP_PATH}" --allow-root 2>/dev/null) || {
        warn "Could not create application password — it may already exist."
        WP_APP_PASSWORD="EXISTING_OR_MANUAL"
    }

    action "${GREEN}✓${NC} WordPress configured"
else
    mkdir -p "${WP_PATH}"
    cd "${WP_PATH}"

    spin "Downloading WordPress core" wp core download --allow-root
    spin "Configuring wp-config.php" wp config create \
        --dbname="${WP_DB_NAME}" \
        --dbuser="${WP_DB_USER}" \
        --dbpass="${WP_DB_PASS}" \
        --dbhost="localhost" \
        --allow-root

    spin "Running WordPress installer" wp core install \
        --url="${WP_PROTOCOL}://${WP_DOMAIN}" \
        --title="My AI-Managed Site" \
        --admin_user="${WP_ADMIN_USER}" \
        --admin_password="${WP_ADMIN_PASS}" \
        --admin_email="${WP_ADMIN_EMAIL}" \
        --allow-root

    action "Setting file permissions..."
    chown -R www-data:www-data "${WP_PATH}"
    find "${WP_PATH}" -type d -exec chmod 755 {} \;
    find "${WP_PATH}" -type f -exec chmod 644 {} \;

    WP_APP_PASSWORD=$(wp user application-password create "${WP_ADMIN_USER}" "openclaw-bridge" --porcelain --allow-root 2>/dev/null)
    action "${GREEN}✓${NC} WordPress installed"
fi

# ─────────────────────────────────────────────
# Phase 5: Install Plugins (Bridge + MCP Adapter + Abilities API)
# ─────────────────────────────────────────────
progress 5 "Installing WordPress plugins..."

if ! command -v composer &>/dev/null; then
    spin "Installing Composer" bash -c 'curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer'
fi

PLUGINS_DIR="${WP_PATH}/wp-content/plugins"

# ── Install Abilities API plugin ──
ABILITIES_DIR="${PLUGINS_DIR}/abilities-api"
if [[ ! -d "$ABILITIES_DIR" ]]; then
    spin "Downloading Abilities API plugin" bash -c "
        ABILITIES_ZIP=\$(mktemp /tmp/abilities-api-XXXX.zip)
        curl -sL 'https://github.com/WordPress/abilities-api/releases/latest/download/abilities-api.zip' -o \"\$ABILITIES_ZIP\" 2>/dev/null
        if [[ -f \"\$ABILITIES_ZIP\" ]] && unzip -t \"\$ABILITIES_ZIP\" > /dev/null 2>&1; then
            unzip -qo \"\$ABILITIES_ZIP\" -d '${PLUGINS_DIR}/' 2>/dev/null
        else
            git clone --depth 1 https://github.com/WordPress/abilities-api.git '${ABILITIES_DIR}' 2>/dev/null
        fi
        rm -f \"\$ABILITIES_ZIP\"
    "
fi

if [[ -d "$ABILITIES_DIR" ]]; then
    if [[ -f "$ABILITIES_DIR/composer.json" ]]; then
        cd "$ABILITIES_DIR"
        quiet composer install --no-dev --no-interaction || true
        cd "${WP_PATH}"
    fi
    chown -R www-data:www-data "$ABILITIES_DIR"
    quiet wp plugin activate abilities-api --path="${WP_PATH}" --allow-root || true
fi

# ── Install MCP Adapter plugin ──
MCP_DIR="${PLUGINS_DIR}/mcp-adapter"
if [[ ! -d "$MCP_DIR" ]]; then
    spin "Downloading MCP Adapter plugin" bash -c "
        MCP_ZIP=\$(mktemp /tmp/mcp-adapter-XXXX.zip)
        curl -sL 'https://github.com/WordPress/mcp-adapter/releases/latest/download/mcp-adapter.zip' -o \"\$MCP_ZIP\" 2>/dev/null
        if [[ -f \"\$MCP_ZIP\" ]] && unzip -t \"\$MCP_ZIP\" > /dev/null 2>&1; then
            unzip -qo \"\$MCP_ZIP\" -d '${PLUGINS_DIR}/' 2>/dev/null
        else
            git clone --depth 1 https://github.com/WordPress/mcp-adapter.git '${MCP_DIR}' 2>/dev/null
        fi
        rm -f \"\$MCP_ZIP\"
    "
fi

if [[ -d "$MCP_DIR" ]]; then
    if [[ -f "$MCP_DIR/composer.json" ]]; then
        cd "$MCP_DIR"
        quiet composer install --no-dev --no-interaction || true
        cd "${WP_PATH}"
    fi
    chown -R www-data:www-data "$MCP_DIR"
    quiet wp plugin activate mcp-adapter --path="${WP_PATH}" --allow-root || true
fi

# ── Install Bridge Plugin ──
PLUGIN_DIR="${PLUGINS_DIR}/openclaw-wp-bridge"

if [[ -d "$PLUGIN_DIR" ]]; then
    rm -rf "${PLUGIN_DIR}.bak"
    mv "$PLUGIN_DIR" "${PLUGIN_DIR}.bak"
fi

mkdir -p "$PLUGIN_DIR"

if [[ -d /opt/tg-wordpress-agent/wordpress-bridge-plugin ]]; then
    cp -r /opt/tg-wordpress-agent/wordpress-bridge-plugin/* "$PLUGIN_DIR/"
else
    warn "Bridge plugin source not found at /opt/tg-wordpress-agent/wordpress-bridge-plugin"
fi

if [[ -f "$PLUGIN_DIR/composer.json" ]]; then
    cd "$PLUGIN_DIR"
    spin "Installing bridge plugin dependencies" composer install --no-dev --no-interaction || warn "Composer had issues."
    cd "${WP_PATH}"
fi

chown -R www-data:www-data "$PLUGIN_DIR"
quiet wp plugin activate openclaw-wp-bridge --path="${WP_PATH}" --allow-root || true

spin "Installing MCP WordPress transport" npm install -g @automattic/mcp-wordpress-remote@latest || warn "MCP transport install failed."
action "${GREEN}✓${NC} All plugins installed"

# ─────────────────────────────────────────────
# Phase 6: Nginx Configuration (fresh install only)
# ─────────────────────────────────────────────

progress 6 "Configuring web server..."

if [[ "$EXISTING_WORDPRESS" != "true" ]]; then

    PHP_VERSION=$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')

    cat > /etc/nginx/sites-available/wordpress <<NGINX
server {
    listen 80;
    server_name ${WP_DOMAIN};
    root ${WP_PATH};
    index index.php index.html;

    client_max_body_size 64M;

    location / {
        try_files \$uri \$uri/ /index.php?\$args;
    }

    location ~ \.php\$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php${PHP_VERSION}-fpm.sock;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        include fastcgi_params;
    }

    location ~ /\.ht {
        deny all;
    }

    location = /favicon.ico { log_not_found off; access_log off; }
    location = /robots.txt  { log_not_found off; access_log off; }
}
NGINX

    ln -sf /etc/nginx/sites-available/wordpress /etc/nginx/sites-enabled/
    rm -f /etc/nginx/sites-enabled/default
    nginx -t >> "$INSTALL_LOG" 2>&1 && systemctl restart nginx >> "$INSTALL_LOG" 2>&1
    action "${GREEN}✓${NC} Nginx configured"
else
    action "Skipped (existing WordPress)"
fi

# ─────────────────────────────────────────────
# Phase 7: SSL Certificate (fresh install only)
# ─────────────────────────────────────────────

progress 7 "Setting up SSL..."

if [[ "$EXISTING_WORDPRESS" != "true" && "$IS_IP_ONLY" != "true" ]]; then
    spin "Obtaining SSL certificate" certbot --nginx -d "$WP_DOMAIN" --non-interactive --agree-tos -m "$WP_ADMIN_EMAIL" || warn "Certbot failed — set up SSL manually."
elif [[ "$IS_IP_ONLY" == "true" ]]; then
    action "Skipped (IP address — no SSL needed)"
else
    action "Skipped (existing WordPress)"
fi

# ─────────────────────────────────────────────
# Phase 8: Install & Configure OpenClaw
# ─────────────────────────────────────────────
progress 8 "Installing OpenClaw AI gateway..."

# Create a dedicated system user for openclaw
useradd -r -m -s /bin/bash openclaw 2>/dev/null || true

spin "Installing OpenClaw via npm" npm install -g openclaw@latest

action "Writing configuration..."
OCLAW_HOME="/home/openclaw"
OCLAW_CONFIG="${OCLAW_HOME}/.openclaw"
mkdir -p "${OCLAW_CONFIG}/workspace/skills/wordpress"

# Write config directly with correct format (don't copy template — inject values)
cat > "${OCLAW_CONFIG}/openclaw.json" <<OCJSON
{
    "agents": {
        "defaults": {
            "model": {
                "primary": "anthropic/claude-sonnet-4-5-20250929"
            }
        }
    },
    "gateway": {
        "port": 18789,
        "bind": "loopback",
        "mode": "local"
    },
    "channels": {
        "telegram": {
            "enabled": true,
            "botToken": "${TELEGRAM_BOT_TOKEN}",
            "dmPolicy": "pairing",
            "allowFrom": ["${TELEGRAM_USER_ID}"]
        }
    },
    "mcpServers": {
        "wordpress": {
            "command": "npx",
            "args": ["-y", "@automattic/mcp-wordpress-remote@latest"],
            "env": {
                "WP_API_URL": "${WP_PROTOCOL}://${WP_DOMAIN}/wp-json/mcp/mcp-adapter-default-server",
                "WP_API_USERNAME": "${WP_ADMIN_USER}",
                "WP_API_PASSWORD": "${WP_APP_PASSWORD}"
            }
        }
    }
}
OCJSON

# Copy agent instructions
if [[ -d /opt/tg-wordpress-agent/openclaw-config ]]; then
    cp /opt/tg-wordpress-agent/openclaw-config/AGENTS.md "${OCLAW_CONFIG}/workspace/AGENTS.md"
fi

if [[ -d /opt/tg-wordpress-agent/openclaw-skills/wordpress ]]; then
    cp /opt/tg-wordpress-agent/openclaw-skills/wordpress/SKILL.md "${OCLAW_CONFIG}/workspace/skills/wordpress/SKILL.md"
fi

# Set ownership
chown -R openclaw:openclaw "$OCLAW_HOME"

# Sudoers: allow openclaw to run WP-CLI and file operations as www-data
SUDOERS_FILE="/etc/sudoers.d/openclaw"
cat > "$SUDOERS_FILE" <<'SUDOERS'
# WP-CLI
openclaw ALL=(www-data) NOPASSWD: /usr/local/bin/wp
# File operations in WordPress directory
openclaw ALL=(www-data) NOPASSWD: /usr/bin/mkdir
openclaw ALL=(www-data) NOPASSWD: /usr/bin/cp
openclaw ALL=(www-data) NOPASSWD: /usr/bin/mv
openclaw ALL=(www-data) NOPASSWD: /usr/bin/rm
openclaw ALL=(www-data) NOPASSWD: /usr/bin/chmod
openclaw ALL=(www-data) NOPASSWD: /usr/bin/tee
openclaw ALL=(www-data) NOPASSWD: /usr/bin/touch
openclaw ALL=(www-data) NOPASSWD: /usr/local/bin/composer
SUDOERS
chmod 440 "$SUDOERS_FILE"
action "${GREEN}✓${NC} OpenClaw configured"

# ─────────────────────────────────────────────
# Phase 9: Environment Variables
# ─────────────────────────────────────────────
progress 9 "Configuring environment..."

cat > /home/openclaw/.env <<ENV
# Anthropic API key for Claude
ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}

# Telegram bot token (also in openclaw.json)
TELEGRAM_BOT_TOKEN=${TELEGRAM_BOT_TOKEN}

# WordPress REST API credentials
WP_SITE_URL=${WP_PROTOCOL}://${WP_DOMAIN}
WP_APP_USER=${WP_ADMIN_USER}
WP_APP_PASSWORD=${WP_APP_PASSWORD}

# WordPress path
WP_PATH=${WP_PATH}
ENV

chown openclaw:openclaw /home/openclaw/.env
chmod 600 /home/openclaw/.env

# Source .env from .bashrc (idempotent)
if ! grep -qF 'source ~/.env' /home/openclaw/.bashrc 2>/dev/null; then
    echo 'set -a; source ~/.env; set +a' >> /home/openclaw/.bashrc
fi

action "${GREEN}✓${NC} Environment configured"

# ─────────────────────────────────────────────
# Phase 10: Systemd Service for OpenClaw
# ─────────────────────────────────────────────
progress 10 "Starting OpenClaw service..."

cat > /etc/systemd/system/openclaw.service <<SERVICE
[Unit]
Description=OpenClaw AI Agent Gateway
After=network.target mariadb.service nginx.service

[Service]
Type=simple
User=openclaw
Group=openclaw
WorkingDirectory=/home/openclaw
EnvironmentFile=/home/openclaw/.env
ExecStart=/usr/bin/openclaw gateway --port 18789
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SERVICE

action "Enabling systemd service..."
quiet systemctl daemon-reload
quiet systemctl enable openclaw
systemctl start openclaw >> "$INSTALL_LOG" 2>&1
action "${GREEN}✓${NC} OpenClaw service started"

# ─────────────────────────────────────────────
# Phase 11: Firewall (fresh install only)
# ─────────────────────────────────────────────

progress 11 "Configuring firewall..."

if [[ "$EXISTING_WORDPRESS" != "true" ]]; then
    quiet ufw default deny incoming
    quiet ufw default allow outgoing
    quiet ufw allow ssh
    quiet ufw allow 'Nginx Full'
    quiet ufw --force enable
    action "${GREEN}✓${NC} Firewall configured"
else
    action "Skipped (existing WordPress)"
fi

# ─────────────────────────────────────────────
# Phase 12: Fail2Ban (fresh install only)
# ─────────────────────────────────────────────

progress 12 "Configuring fail2ban..."

if [[ "$EXISTING_WORDPRESS" != "true" ]]; then
    quiet systemctl enable fail2ban
    quiet systemctl start fail2ban
    action "${GREEN}✓${NC} Fail2ban started"
else
    action "Skipped (existing WordPress)"
fi

# ─────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────
echo ""
echo ""
echo ""
echo "════════════════════════════════════════════════════"
echo -e "${GREEN} Setup Complete!${NC}"
echo "════════════════════════════════════════════════════"
echo ""

if [[ "$EXISTING_WORDPRESS" != "true" ]]; then
    echo "WordPress:"
    echo "  URL:      ${WP_PROTOCOL}://${WP_DOMAIN}"
    echo "  Admin:    ${WP_ADMIN_USER}"
    echo "  Password: ${WP_ADMIN_PASS}"
    echo "  DB Pass:  ${WP_DB_PASS}"
    echo "  App Pass: ${WP_APP_PASSWORD}"
    echo ""
else
    echo "WordPress (existing site):"
    echo "  URL:      ${WP_PROTOCOL}://${WP_DOMAIN}"
    echo "  Path:     ${WP_PATH}"
    echo "  Admin:    ${WP_ADMIN_USER}"
    echo "  App Pass: ${WP_APP_PASSWORD}"
    echo ""
fi

echo "OpenClaw:"
echo "  Config:   ${OCLAW_CONFIG}/openclaw.json"
echo "  Skills:   ${OCLAW_CONFIG}/workspace/skills/"
echo "  Service:  systemctl status openclaw"
echo "  Logs:     journalctl -u openclaw -f"
echo ""
echo "Next Steps:"
if [[ -z "$TELEGRAM_BOT_TOKEN" ]]; then
    echo "  1. Add your Telegram bot token to ${OCLAW_CONFIG}/openclaw.json"
fi
if [[ -z "$ANTHROPIC_API_KEY" ]]; then
    echo "  2. Add your Anthropic API key to /home/openclaw/.env"
fi
if [[ -z "$TELEGRAM_BOT_TOKEN" || -z "$ANTHROPIC_API_KEY" ]]; then
    echo "  3. Restart OpenClaw: systemctl restart openclaw"
fi
echo "  → Message your Telegram bot to begin!"
if [[ "$WP_APP_PASSWORD" == "EXISTING_OR_MANUAL" ]]; then
    echo ""
    warn "Application password could not be created automatically."
    echo "  Create one manually in WP Admin → Users → Application Passwords"
    echo "  Then update /home/openclaw/.env with the password."
fi
echo ""
echo "IMPORTANT: Save these credentials securely and delete this output."
echo "════════════════════════════════════════════════════"

# Save credentials to a file
cat > /root/setup-credentials.txt <<CREDS
WordPress URL: ${WP_PROTOCOL}://${WP_DOMAIN}
WordPress Path: ${WP_PATH}
WordPress Admin: ${WP_ADMIN_USER}
WordPress Password: ${WP_ADMIN_PASS}
WordPress DB User: ${WP_DB_USER}
WordPress DB Pass: ${WP_DB_PASS}
MySQL Root Pass: ${MYSQL_ROOT_PASS}
WP Application Password: ${WP_APP_PASSWORD}
Mode: $(if [[ "$EXISTING_WORDPRESS" == "true" ]]; then echo "Existing WordPress"; else echo "Fresh Install"; fi)
CREDS

chmod 600 /root/setup-credentials.txt
info "Credentials saved to /root/setup-credentials.txt (delete after noting them down)"
