#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# OpenClaw WordPress Agent — Interactive Installer
#
# One command to set everything up:
#   curl -sL https://raw.githubusercontent.com/YOUR_REPO/main/scripts/install.sh | bash
#   — or —
#   bash /opt/tg-wordpress-agent/scripts/install.sh
#
# This script:
#   1. Asks a few simple questions (domain, tokens, etc.)
#   2. Auto-detects if WordPress is already installed
#   3. Installs everything with zero manual steps
#   4. Prints a summary with all credentials at the end
#
# Tested on: Ubuntu 22.04 / 24.04 LTS
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
TOTAL_STEPS=10
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

# Draw or redraw the 2-line progress display
# Usage: progress <step> "Action description"
progress() {
    local step=$1
    local action="$2"
    local bar_width=30
    local filled=$((step * bar_width / TOTAL_STEPS))
    local empty=$((bar_width - filled))
    local pct=$((step * 100 / TOTAL_STEPS))

    # Build bar
    local bar=""
    for ((i=0; i<filled; i++)); do bar+="█"; done
    for ((i=0; i<empty; i++)); do bar+="░"; done

    if [[ "$_BAR_DRAWN" == "true" ]]; then
        # Move up 2 lines, clear, redraw
        echo -ne "\033[2A"
    fi

    echo -e "\033[2K  ${GREEN}[${bar}]${NC} ${BOLD}${step}/${TOTAL_STEPS}${NC} (${pct}%)"
    echo -e "\033[2K  ${CYAN}${action}${NC}"
    _BAR_DRAWN=true
}

# Update just the action text beneath the bar (no stacking)
action() {
    if [[ "$_BAR_DRAWN" == "true" ]]; then
        echo -ne "\033[1A\033[2K  ${CYAN}$1${NC}\n"
    else
        echo -e "  ${CYAN}$1${NC}"
    fi
}

# Run a command with a spinner on the action line
# Usage: spin "message" command arg1 arg2 ...
spin() {
    local msg="$1"
    shift
    action "⠋ ${msg}"

    # Run in background — use subshell to isolate from set -e
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

# Run a command silently (output to log only)
quiet() {
    "$@" >> "$INSTALL_LOG" 2>&1
}

# ── Check root ──
[[ $EUID -ne 0 ]] && err "Run this script as root: sudo bash install.sh"

# ─────────────────────────────────────────────
# Interactive Setup — Ask the user for inputs
# ─────────────────────────────────────────────

clear 2>/dev/null || true
echo ""
echo -e "${BOLD}════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  OpenClaw WordPress Agent — Setup Wizard${NC}"
echo -e "${BOLD}════════════════════════════════════════════════════${NC}"
echo ""
echo "  This will set up an AI agent that manages your"
echo "  WordPress site through Telegram."
echo ""
echo "  You'll need:"
echo "    - A Telegram bot token (from @BotFather)"
echo "    - Your Telegram user ID (from @userinfobot)"
echo "    - An Anthropic API key (from console.anthropic.com)"
echo ""
echo -e "${BOLD}────────────────────────────────────────────────────${NC}"
echo ""

# Helper: prompt with default value
ask() {
    local prompt="$1"
    local default="$2"
    local var_name="$3"
    local value

    if [[ -n "$default" ]]; then
        echo -ne "${CYAN}${prompt}${NC} [${default}]: "
    else
        echo -ne "${CYAN}${prompt}${NC}: "
    fi

    read -r value
    value="${value:-$default}"

    if [[ -z "$value" ]]; then
        err "This field is required."
    fi

    eval "$var_name='$value'"
}

# Helper: prompt for sensitive input (hidden)
ask_secret() {
    local prompt="$1"
    local var_name="$2"
    local value

    echo -ne "${CYAN}${prompt}${NC}: "
    read -rs value
    echo ""

    if [[ -z "$value" ]]; then
        err "This field is required."
    fi

    eval "$var_name='$value'"
}

# Helper: yes/no prompt
ask_yn() {
    local prompt="$1"
    local default="$2"
    local var_name="$3"
    local value

    if [[ "$default" == "y" ]]; then
        echo -ne "${CYAN}${prompt}${NC} [Y/n]: "
    else
        echo -ne "${CYAN}${prompt}${NC} [y/N]: "
    fi

    read -r value
    value="${value:-$default}"

    case "$value" in
        [yY]*) eval "$var_name=true" ;;
        *)     eval "$var_name=false" ;;
    esac
}

# ── Step 1: Domain / IP ──
echo -e "${BOLD}Step 1: Your server address${NC}"
echo ""

SERVER_IP=$(curl -4 -s --connect-timeout 5 ifconfig.me 2>/dev/null || hostname -I 2>/dev/null | awk '{print $1}' || echo "")
if [[ -n "$SERVER_IP" ]]; then
    info "Detected server IP: ${SERVER_IP}"
fi

echo "  Enter your domain name (e.g., mysite.com) or server IP address."
echo "  If you don't have a domain, just use the IP address."
ask "  Domain or IP" "${SERVER_IP}" WP_DOMAIN
echo ""

# Detect if user entered an IP vs domain
IS_IP_ONLY=false
if [[ "$WP_DOMAIN" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    IS_IP_ONLY=true
    info "Using IP address — SSL will be skipped (requires a domain name)."
    WP_PROTOCOL="http"
else
    WP_PROTOCOL="https"
fi
echo ""

# ── Step 2: Telegram ──
echo -e "${BOLD}Step 2: Telegram bot${NC}"
echo ""
echo "  Create a bot with @BotFather in Telegram and paste the token here."
echo "  Get your user ID from @userinfobot."
echo ""
ask "  Bot token" "" TELEGRAM_BOT_TOKEN
ask "  Your Telegram user ID" "" TELEGRAM_USER_ID
echo ""

# ── Step 3: API Key ──
echo -e "${BOLD}Step 3: AI API key${NC}"
echo ""
echo "  Get an API key from console.anthropic.com"
echo ""
ask_secret "  Anthropic API key" ANTHROPIC_API_KEY
echo ""

# ── Step 4: WordPress detection ──
echo -e "${BOLD}Step 4: WordPress${NC}"
echo ""

# Auto-detect WordPress
WP_PATH="/var/www/html"
EXISTING_WORDPRESS=false

# Check common WordPress locations
for check_path in /var/www/html /var/www/wordpress /var/www/html/wordpress /home/*/public_html; do
    if [[ -f "${check_path}/wp-config.php" ]]; then
        WP_PATH="$check_path"
        EXISTING_WORDPRESS=true
        break
    fi
done

if [[ "$EXISTING_WORDPRESS" == "true" ]]; then
    echo -e "  ${GREEN}WordPress detected at: ${WP_PATH}${NC}"
    WP_VERSION=$(wp core version --path="${WP_PATH}" --allow-root 2>/dev/null || echo "unknown")
    SITE_URL=$(wp option get siteurl --path="${WP_PATH}" --allow-root 2>/dev/null || echo "unknown")
    info "  Version: ${WP_VERSION}"
    info "  URL: ${SITE_URL}"
    echo ""
    ask_yn "  Use this existing WordPress installation?" "y" USE_EXISTING

    if [[ "$USE_EXISTING" == "false" ]]; then
        EXISTING_WORDPRESS=false
        ask "  WordPress install path" "/var/www/html" WP_PATH
    fi
else
    echo "  No existing WordPress found."
    echo "  A fresh WordPress installation will be set up."
    echo ""
    ask "  WordPress install path" "/var/www/html" WP_PATH
fi

# For existing WordPress, detect admin user
WP_ADMIN_USER="admin"
if [[ "$EXISTING_WORDPRESS" == "true" ]]; then
    DETECTED_ADMIN=$(wp user list --role=administrator --field=user_login --path="${WP_PATH}" --allow-root 2>/dev/null | head -1)
    if [[ -n "$DETECTED_ADMIN" ]]; then
        WP_ADMIN_USER="$DETECTED_ADMIN"
        info "  Admin user: ${WP_ADMIN_USER}"
    fi
fi
echo ""

# ── Step 5: Email ──
echo -e "${BOLD}Step 5: Admin email${NC}"
echo ""
ask "  Email address (for WordPress admin & SSL)" "" WP_ADMIN_EMAIL
echo ""

# ── Confirmation ──
echo ""
echo -e "${BOLD}════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  Review your settings${NC}"
echo -e "${BOLD}════════════════════════════════════════════════════${NC}"
echo ""
echo "  Server:       ${WP_DOMAIN}"
echo "  WordPress:    $(if [[ "$EXISTING_WORDPRESS" == "true" ]]; then echo "Existing (${WP_PATH})"; else echo "Fresh install (${WP_PATH})"; fi)"
echo "  Bot token:    ${TELEGRAM_BOT_TOKEN:0:10}...${TELEGRAM_BOT_TOKEN: -5}"
echo "  User ID:      ${TELEGRAM_USER_ID}"
echo "  API key:      ${ANTHROPIC_API_KEY:0:10}..."
echo "  Email:        ${WP_ADMIN_EMAIL}"
echo ""

ask_yn "  Everything correct? Start installation?" "y" CONFIRM
if [[ "$CONFIRM" != "true" ]]; then
    echo "Cancelled. Run the script again to start over."
    exit 0
fi

echo ""
echo -e "${BOLD}Starting installation...${NC}"
echo ""
echo ""

# ─────────────────────────────────────────────
# Phase 0: Ensure swap exists (prevents OOM on small VPS)
# ─────────────────────────────────────────────

if ! swapon --show | grep -q '/'; then
    echo -e "  ${CYAN}Creating swap file (prevents out-of-memory crashes)...${NC}"
    fallocate -l 2G /swapfile 2>/dev/null || dd if=/dev/zero of=/swapfile bs=1M count=2048 status=none
    chmod 600 /swapfile
    mkswap /swapfile > /dev/null 2>&1
    swapon /swapfile
    # Make permanent
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

export DEBIAN_FRONTEND=noninteractive

progress 1 "Updating package lists..."

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
# Phase 2: Node.js
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
# Phase 3: MariaDB (fresh install only)
# ─────────────────────────────────────────────

progress 3 "Setting up database..."

WP_DB_NAME="wordpress"
WP_DB_USER="wpuser"
WP_DB_PASS="$(openssl rand -base64 24)"
MYSQL_ROOT_PASS="$(openssl rand -base64 24)"
WP_ADMIN_PASS="$(openssl rand -base64 16)"

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
# Phase 4: WordPress
# ─────────────────────────────────────────────

progress 4 "Installing WordPress..."

# Always ensure WP-CLI is installed
if ! command -v wp &>/dev/null; then
    spin "Downloading WP-CLI" bash -c 'curl -sO https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar && chmod +x wp-cli.phar && mv wp-cli.phar /usr/local/bin/wp'
else
    action "${GREEN}✓${NC} WP-CLI already installed"
fi

WP_APP_PASSWORD=""

if [[ "$EXISTING_WORDPRESS" == "true" ]]; then
    action "Creating application password..."
    WP_APP_PASSWORD=$(wp user application-password create "${WP_ADMIN_USER}" "openclaw-bridge" --porcelain --path="${WP_PATH}" --allow-root 2>/dev/null) || {
        warn "Could not create app password — may already exist."
        WP_APP_PASSWORD="MANUAL_SETUP_NEEDED"
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
# Phase 5: Bridge Plugin + MCP Adapter
# ─────────────────────────────────────────────
progress 5 "Installing WordPress plugins..."

# Install Composer if not present
if ! command -v composer &>/dev/null; then
    spin "Installing Composer" bash -c 'curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer'
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
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
else
    action "${GREEN}✓${NC} Abilities API already installed"
fi

if [[ -d "$ABILITIES_DIR" ]]; then
    if [[ -f "$ABILITIES_DIR/composer.json" ]]; then
        cd "$ABILITIES_DIR"
        quiet composer install --no-dev --no-interaction || true
        cd /tmp
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
else
    action "${GREEN}✓${NC} MCP Adapter already installed"
fi

if [[ -d "$MCP_DIR" ]]; then
    if [[ -f "$MCP_DIR/composer.json" ]]; then
        cd "$MCP_DIR"
        quiet composer install --no-dev --no-interaction || true
        cd /tmp
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

if [[ -d "${REPO_DIR}/wordpress-bridge-plugin" ]]; then
    cp -r "${REPO_DIR}/wordpress-bridge-plugin/"* "$PLUGIN_DIR/"
elif [[ -d /opt/tg-wordpress-agent/wordpress-bridge-plugin ]]; then
    cp -r /opt/tg-wordpress-agent/wordpress-bridge-plugin/* "$PLUGIN_DIR/"
else
    warn "Bridge plugin source not found — clone the repo first."
fi

if [[ -f "$PLUGIN_DIR/composer.json" ]]; then
    cd "$PLUGIN_DIR"
    spin "Installing bridge plugin dependencies" composer install --no-dev --no-interaction || warn "Composer had issues."
    cd /tmp
fi

chown -R www-data:www-data "$PLUGIN_DIR"
quiet wp plugin activate openclaw-wp-bridge --path="${WP_PATH}" --allow-root || true

spin "Installing MCP WordPress transport" npm install -g @automattic/mcp-wordpress-remote@latest || warn "MCP transport install failed."
action "${GREEN}✓${NC} All plugins installed"

# ─────────────────────────────────────────────
# Phase 6: Nginx (fresh install only)
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
    nginx -t > /dev/null 2>&1 && systemctl restart nginx
    action "${GREEN}✓${NC} Nginx configured"
else
    action "Skipped (existing WordPress)"
fi

# ─────────────────────────────────────────────
# Phase 7: SSL (domain only, not IP)
# ─────────────────────────────────────────────

progress 7 "Setting up SSL..."

if [[ "$EXISTING_WORDPRESS" != "true" && "$IS_IP_ONLY" == "false" ]]; then
    spin "Obtaining SSL certificate" certbot --nginx -d "$WP_DOMAIN" --non-interactive --agree-tos -m "$WP_ADMIN_EMAIL" || warn "SSL setup failed — run later: certbot --nginx -d $WP_DOMAIN"
elif [[ "$IS_IP_ONLY" == "true" ]]; then
    action "Skipped (IP address — no SSL needed)"
else
    action "Skipped (existing WordPress)"
fi

# ─────────────────────────────────────────────
# Phase 8: OpenClaw
# ─────────────────────────────────────────────
progress 8 "Installing OpenClaw AI gateway..."

# Create system user
useradd -r -m -s /bin/bash openclaw 2>/dev/null || true

# Install OpenClaw
spin "Installing OpenClaw via npm" npm install -g openclaw@latest

action "Writing configuration..."
OCLAW_HOME="/home/openclaw"
OCLAW_CONFIG="${OCLAW_HOME}/.openclaw"
mkdir -p "${OCLAW_CONFIG}/workspace/skills/wordpress"

# Write config with correct format (agents.defaults.model.primary, gateway.mode, mcpServers)
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

# Copy agent instructions and skills
if [[ -d "${REPO_DIR}/openclaw-config" ]]; then
    cp "${REPO_DIR}/openclaw-config/AGENTS.md" "${OCLAW_CONFIG}/workspace/AGENTS.md"
elif [[ -d /opt/tg-wordpress-agent/openclaw-config ]]; then
    cp /opt/tg-wordpress-agent/openclaw-config/AGENTS.md "${OCLAW_CONFIG}/workspace/AGENTS.md"
fi

if [[ -d "${REPO_DIR}/openclaw-skills/wordpress" ]]; then
    cp "${REPO_DIR}/openclaw-skills/wordpress/SKILL.md" "${OCLAW_CONFIG}/workspace/skills/wordpress/SKILL.md"
elif [[ -d /opt/tg-wordpress-agent/openclaw-skills/wordpress ]]; then
    cp /opt/tg-wordpress-agent/openclaw-skills/wordpress/SKILL.md "${OCLAW_CONFIG}/workspace/skills/wordpress/SKILL.md"
fi

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
# Phase 9: Environment & Service
# ─────────────────────────────────────────────
progress 9 "Starting OpenClaw service..."

cat > /home/openclaw/.env <<ENV
ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}
TELEGRAM_BOT_TOKEN=${TELEGRAM_BOT_TOKEN}
WP_SITE_URL=${WP_PROTOCOL}://${WP_DOMAIN}
WP_APP_USER=${WP_ADMIN_USER}
WP_APP_PASSWORD=${WP_APP_PASSWORD}
WP_PATH=${WP_PATH}
ENV

chown openclaw:openclaw /home/openclaw/.env
chmod 600 /home/openclaw/.env

# Source .env from .bashrc (idempotent)
if ! grep -qF 'source ~/.env' /home/openclaw/.bashrc 2>/dev/null; then
    echo 'set -a; source ~/.env; set +a' >> /home/openclaw/.bashrc
fi

# Create systemd service
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
# Phase 10: Firewall (fresh install only)
# ─────────────────────────────────────────────

progress 10 "Configuring firewall..."

if [[ "$EXISTING_WORDPRESS" != "true" ]]; then
    quiet ufw default deny incoming
    quiet ufw default allow outgoing
    quiet ufw allow ssh
    quiet ufw allow 'Nginx Full'
    quiet ufw --force enable
    quiet systemctl enable fail2ban
    quiet systemctl start fail2ban
    action "${GREEN}✓${NC} Firewall configured"
else
    action "Skipped (existing WordPress)"
fi

# ─────────────────────────────────────────────
# Done — Print Summary
# ─────────────────────────────────────────────

# Clear progress bar and show completion
echo ""
echo ""

# Wait a moment for OpenClaw to start
sleep 3
OPENCLAW_STATUS=$(systemctl is-active openclaw 2>/dev/null || echo "unknown")

echo ""
echo ""
echo -e "${BOLD}════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}  Setup Complete!${NC}"
echo -e "${BOLD}════════════════════════════════════════════════════${NC}"
echo ""

if [[ "$EXISTING_WORDPRESS" != "true" ]]; then
    echo -e "${BOLD}  WordPress${NC}"
    echo "  URL:        ${WP_PROTOCOL}://${WP_DOMAIN}"
    echo "  Admin:      ${WP_PROTOCOL}://${WP_DOMAIN}/wp-admin"
    echo "  Username:   ${WP_ADMIN_USER}"
    echo "  Password:   ${WP_ADMIN_PASS}"
    echo ""
fi

echo -e "${BOLD}  OpenClaw AI Agent${NC}"
echo "  Status:     ${OPENCLAW_STATUS}"
echo "  Config:     ${OCLAW_CONFIG}/openclaw.json"
echo "  Logs:       journalctl -u openclaw -f"
echo ""

echo -e "${BOLD}  Telegram Bot${NC}"
echo "  Bot token:  ${TELEGRAM_BOT_TOKEN:0:10}..."
echo "  User ID:    ${TELEGRAM_USER_ID}"
echo ""

echo -e "${BOLD}  What to do next:${NC}"
echo ""
echo "  1. Open Telegram and find your bot"
echo "  2. Send it any message (e.g., \"hello\")"
echo "  3. It will reply with a pairing code"
echo "  4. Approve it on this server:"
echo ""
echo -e "     ${CYAN}su - openclaw -c \"openclaw pairing approve telegram <CODE>\"${NC}"
echo ""
echo "  5. You're connected! Try: \"What plugins are installed?\""
echo ""
echo -e "${BOLD}════════════════════════════════════════════════════${NC}"

if [[ "$OPENCLAW_STATUS" != "active" ]]; then
    echo ""
    warn "OpenClaw is not running yet. Check logs with:"
    echo "  journalctl -u openclaw -n 30"
fi

# Save credentials
cat > /root/setup-credentials.txt <<CREDS
═══ OpenClaw WordPress Agent — Credentials ═══
Generated: $(date)

WordPress:
  URL:        ${WP_PROTOCOL}://${WP_DOMAIN}
  Path:       ${WP_PATH}
  Admin:      ${WP_ADMIN_USER}
  Password:   ${WP_ADMIN_PASS}
  App Pass:   ${WP_APP_PASSWORD}

Database:
  Name:       ${WP_DB_NAME}
  User:       ${WP_DB_USER}
  Password:   ${WP_DB_PASS}
  Root Pass:  ${MYSQL_ROOT_PASS}

Telegram:
  Bot Token:  ${TELEGRAM_BOT_TOKEN}
  User ID:    ${TELEGRAM_USER_ID}

OpenClaw:
  Config:     ${OCLAW_CONFIG}/openclaw.json
  Env:        /home/openclaw/.env

Mode: $(if [[ "$EXISTING_WORDPRESS" == "true" ]]; then echo "Existing WordPress"; else echo "Fresh Install"; fi)

DELETE THIS FILE after saving the credentials somewhere safe.
CREDS

chmod 600 /root/setup-credentials.txt
echo ""
info "All credentials saved to /root/setup-credentials.txt"
echo "  Delete it after you've noted them down: rm /root/setup-credentials.txt"
echo ""

# ─────────────────────────────────────────────
# Optional: Security Hardening
# ─────────────────────────────────────────────
echo ""
echo -e "${BOLD}════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  Security Hardening (Recommended)${NC}"
echo -e "${BOLD}════════════════════════════════════════════════════${NC}"
echo ""
echo "  For production use, we recommend hardening your setup:"
echo "    - Disable SSH password login (key-only)"
echo "    - Install Tailscale VPN (private access to SSH + wp-admin)"
echo "    - API budget limits (prevent runaway AI costs)"
echo "    - Egress filtering (restrict outbound connections)"
echo ""
echo -ne "${CYAN}  Run security hardening now?${NC} [Y/n]: "
read -r RUN_HARDEN
RUN_HARDEN="${RUN_HARDEN:-y}"

if [[ "$RUN_HARDEN" =~ ^[yY] ]]; then
    HARDEN_SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/harden.sh"
    if [[ -f "$HARDEN_SCRIPT" ]]; then
        bash "$HARDEN_SCRIPT"
    elif [[ -f /opt/tg-wordpress-agent/scripts/harden.sh ]]; then
        bash /opt/tg-wordpress-agent/scripts/harden.sh
    else
        warn "harden.sh not found. Run it manually later:"
        echo "  bash /opt/tg-wordpress-agent/scripts/harden.sh"
    fi
else
    echo ""
    info "Skipped. You can run it anytime later:"
    echo "  bash /opt/tg-wordpress-agent/scripts/harden.sh"
    echo ""
fi
