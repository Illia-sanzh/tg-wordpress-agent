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
NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[✗]${NC} $1"; exit 1; }
info() { echo -e "${CYAN}[i]${NC} $1"; }

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

# ─────────────────────────────────────────────
# Phase 1: System Packages
# ─────────────────────────────────────────────

if [[ "$EXISTING_WORDPRESS" == "true" ]]; then
    log "Phase 1: Installing minimal packages (existing WordPress mode)..."
    apt-get update
    apt-get install -y curl wget unzip git
else
    log "Phase 1: Installing system packages..."

    apt-get update && apt-get upgrade -y

    # PHP 8.2+ and extensions
    apt-get install -y \
        nginx \
        mariadb-server \
        php8.3-fpm php8.3-mysql php8.3-xml php8.3-mbstring php8.3-curl \
        php8.3-zip php8.3-gd php8.3-intl php8.3-imagick php8.3-bcmath \
        php8.3-soap php8.3-opcache \
        curl wget unzip git \
        certbot python3-certbot-nginx \
        ufw fail2ban

    # If php8.3 not available, fall back to 8.2
    if ! command -v php8.3 &>/dev/null; then
        warn "php8.3 not available, trying php8.2..."
        apt-get install -y \
            php8.2-fpm php8.2-mysql php8.2-xml php8.2-mbstring php8.2-curl \
            php8.2-zip php8.2-gd php8.2-intl php8.2-imagick php8.2-bcmath \
            php8.2-soap php8.2-opcache 2>/dev/null || true
    fi

    PHP_VERSION=$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')
    log "PHP version: $PHP_VERSION"
fi

# ─────────────────────────────────────────────
# Phase 2: Node.js (for OpenClaw)
# ─────────────────────────────────────────────

if command -v node &>/dev/null && [[ "$(node -v | cut -d. -f1 | tr -d v)" -ge 22 ]]; then
    log "Phase 2: Node.js $(node -v) already installed (>= 22). Skipping."
else
    log "Phase 2: Installing Node.js 22..."
    curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
    apt-get install -y nodejs
fi

npm install -g pnpm 2>/dev/null || true
log "Node $(node -v) / pnpm $(pnpm -v 2>/dev/null || echo 'not installed')"

# ─────────────────────────────────────────────
# Phase 3: MariaDB Setup (fresh install only)
# ─────────────────────────────────────────────

if [[ "$EXISTING_WORDPRESS" != "true" ]]; then
    log "Phase 3: Configuring MariaDB..."

    systemctl start mariadb
    systemctl enable mariadb

    mysql -e "ALTER USER 'root'@'localhost' IDENTIFIED BY '${MYSQL_ROOT_PASS}';" 2>/dev/null || true
    mysql -u root -p"${MYSQL_ROOT_PASS}" -e "
        CREATE DATABASE IF NOT EXISTS ${WP_DB_NAME} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
        CREATE USER IF NOT EXISTS '${WP_DB_USER}'@'localhost' IDENTIFIED BY '${WP_DB_PASS}';
        GRANT ALL PRIVILEGES ON ${WP_DB_NAME}.* TO '${WP_DB_USER}'@'localhost';
        FLUSH PRIVILEGES;
    "

    log "Database '${WP_DB_NAME}' ready."
else
    log "Phase 3: Skipping MariaDB setup (existing WordPress)."
fi

# ─────────────────────────────────────────────
# Phase 4: WordPress Installation
# ─────────────────────────────────────────────

# Always ensure WP-CLI is installed
if ! command -v wp &>/dev/null; then
    log "Phase 4: Installing WP-CLI..."
    curl -O https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar
    chmod +x wp-cli.phar
    mv wp-cli.phar /usr/local/bin/wp
else
    log "Phase 4: WP-CLI already installed."
fi
log "WP-CLI $(wp --version --allow-root 2>/dev/null || echo 'version check failed')"

if [[ "$EXISTING_WORDPRESS" == "true" ]]; then
    # ── Existing WordPress: validate and create app password ──
    if [[ ! -f "${WP_PATH}/wp-config.php" ]]; then
        err "WordPress not found at ${WP_PATH} — check WP_PATH and try again."
    fi

    log "Found existing WordPress at ${WP_PATH}"
    info "Site URL: $(wp option get siteurl --path="${WP_PATH}" --allow-root 2>/dev/null || echo 'unknown')"
    info "WP Version: $(wp core version --path="${WP_PATH}" --allow-root 2>/dev/null || echo 'unknown')"

    # Detect admin user if not specified
    if [[ "$WP_ADMIN_USER" == "admin" ]]; then
        DETECTED_ADMIN=$(wp user list --role=administrator --field=user_login --path="${WP_PATH}" --allow-root 2>/dev/null | head -1)
        if [[ -n "$DETECTED_ADMIN" ]]; then
            WP_ADMIN_USER="$DETECTED_ADMIN"
            info "Detected admin user: ${WP_ADMIN_USER}"
        fi
    fi

    # Create application password for REST API
    WP_APP_PASSWORD=$(wp user application-password create "${WP_ADMIN_USER}" "openclaw-bridge" --porcelain --path="${WP_PATH}" --allow-root 2>/dev/null) || {
        warn "Could not create application password — it may already exist."
        WP_APP_PASSWORD="EXISTING_OR_MANUAL"
    }

    log "Existing WordPress validated."
else
    # ── Fresh install ──
    log "Phase 4: Installing WordPress..."

    mkdir -p "${WP_PATH}"
    cd "${WP_PATH}"

    wp core download --allow-root
    wp config create \
        --dbname="${WP_DB_NAME}" \
        --dbuser="${WP_DB_USER}" \
        --dbpass="${WP_DB_PASS}" \
        --dbhost="localhost" \
        --allow-root

    wp core install \
        --url="https://${WP_DOMAIN}" \
        --title="My AI-Managed Site" \
        --admin_user="${WP_ADMIN_USER}" \
        --admin_password="${WP_ADMIN_PASS}" \
        --admin_email="${WP_ADMIN_EMAIL}" \
        --allow-root

    # Set permissions
    chown -R www-data:www-data "${WP_PATH}"
    find "${WP_PATH}" -type d -exec chmod 755 {} \;
    find "${WP_PATH}" -type f -exec chmod 644 {} \;

    # Generate application password for REST API access
    WP_APP_PASSWORD=$(wp user application-password create "${WP_ADMIN_USER}" "openclaw-bridge" --porcelain --allow-root)
    log "Application password created for REST API access."

    log "WordPress installed at ${WP_PATH}"
fi

# ─────────────────────────────────────────────
# Phase 5: Install OpenClaw WP Bridge Plugin
# ─────────────────────────────────────────────
log "Phase 5: Installing OpenClaw WP Bridge plugin..."

# Install Composer if not present
if ! command -v composer &>/dev/null; then
    curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer
fi

# Copy bridge plugin
PLUGIN_DIR="${WP_PATH}/wp-content/plugins/openclaw-wp-bridge"

# Back up existing plugin if present
if [[ -d "$PLUGIN_DIR" ]]; then
    warn "Bridge plugin already exists — backing up to ${PLUGIN_DIR}.bak"
    rm -rf "${PLUGIN_DIR}.bak"
    mv "$PLUGIN_DIR" "${PLUGIN_DIR}.bak"
fi

mkdir -p "$PLUGIN_DIR"

if [[ -d /opt/tg-wordpress-agent/wordpress-bridge-plugin ]]; then
    cp -r /opt/tg-wordpress-agent/wordpress-bridge-plugin/* "$PLUGIN_DIR/"
else
    warn "Bridge plugin source not found at /opt/tg-wordpress-agent/wordpress-bridge-plugin"
    warn "Copy it manually after cloning the repo."
fi

# Install Composer dependencies in plugin
if [[ -f "$PLUGIN_DIR/composer.json" ]]; then
    cd "$PLUGIN_DIR"
    composer install --no-dev 2>/dev/null || warn "Composer install for bridge plugin had issues — dependencies may need manual setup"
    cd "${WP_PATH}"
fi

chown -R www-data:www-data "$PLUGIN_DIR"

# Activate plugin
wp plugin activate openclaw-wp-bridge --path="${WP_PATH}" --allow-root 2>/dev/null || warn "Plugin activation deferred — activate manually after dependencies resolve."

log "Bridge plugin installed."

# ─────────────────────────────────────────────
# Phase 6: Nginx Configuration (fresh install only)
# ─────────────────────────────────────────────

if [[ "$EXISTING_WORDPRESS" != "true" ]]; then
    log "Phase 6: Configuring Nginx..."

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
    nginx -t && systemctl restart nginx

    log "Nginx configured."
else
    log "Phase 6: Skipping Nginx configuration (existing WordPress)."
    info "Your existing web server configuration is untouched."
fi

# ─────────────────────────────────────────────
# Phase 7: SSL Certificate (fresh install only)
# ─────────────────────────────────────────────

if [[ "$EXISTING_WORDPRESS" != "true" ]]; then
    log "Phase 7: Setting up SSL..."

    if [[ "$WP_DOMAIN" != "your-domain.com" ]]; then
        certbot --nginx -d "$WP_DOMAIN" --non-interactive --agree-tos -m "$WP_ADMIN_EMAIL" || warn "Certbot failed — set up SSL manually."
    else
        warn "Skipping SSL — set WP_DOMAIN to your actual domain first."
    fi
else
    log "Phase 7: Skipping SSL setup (existing WordPress)."
    info "Your existing SSL configuration is untouched."
fi

# ─────────────────────────────────────────────
# Phase 8: Install & Configure OpenClaw
# ─────────────────────────────────────────────
log "Phase 8: Installing OpenClaw..."

# Create a dedicated system user for openclaw
useradd -r -m -s /bin/bash openclaw 2>/dev/null || true

# Install OpenClaw globally
npm install -g openclaw@latest

# Set up OpenClaw config directory
OCLAW_HOME="/home/openclaw"
OCLAW_CONFIG="${OCLAW_HOME}/.openclaw"
mkdir -p "${OCLAW_CONFIG}/workspace/skills/wordpress"

# Copy configuration files from our repo
if [[ -d /opt/tg-wordpress-agent/openclaw-config ]]; then
    cp /opt/tg-wordpress-agent/openclaw-config/openclaw.json "${OCLAW_CONFIG}/openclaw.json"
    cp /opt/tg-wordpress-agent/openclaw-config/AGENTS.md "${OCLAW_CONFIG}/workspace/AGENTS.md"
fi

if [[ -d /opt/tg-wordpress-agent/openclaw-skills/wordpress ]]; then
    cp /opt/tg-wordpress-agent/openclaw-skills/wordpress/SKILL.md "${OCLAW_CONFIG}/workspace/skills/wordpress/SKILL.md"
fi

# Inject real values into config
if [[ -n "$TELEGRAM_BOT_TOKEN" ]]; then
    sed -i "s/YOUR_TELEGRAM_BOT_TOKEN_HERE/${TELEGRAM_BOT_TOKEN}/g" "${OCLAW_CONFIG}/openclaw.json"
fi
if [[ -n "$TELEGRAM_USER_ID" ]]; then
    sed -i "s/YOUR_TELEGRAM_USER_ID/${TELEGRAM_USER_ID}/g" "${OCLAW_CONFIG}/openclaw.json"
fi

# Set ownership
chown -R openclaw:openclaw "$OCLAW_HOME"

# Allow openclaw user to run WP-CLI as www-data (idempotent)
SUDOERS_LINE="openclaw ALL=(www-data) NOPASSWD: /usr/local/bin/wp"
SUDOERS_FILE="/etc/sudoers.d/openclaw"
if [[ ! -f "$SUDOERS_FILE" ]] || ! grep -qF "$SUDOERS_LINE" "$SUDOERS_FILE"; then
    echo "$SUDOERS_LINE" > "$SUDOERS_FILE"
    chmod 440 "$SUDOERS_FILE"
fi

log "OpenClaw installed and configured."

# ─────────────────────────────────────────────
# Phase 9: Environment Variables
# ─────────────────────────────────────────────
log "Phase 9: Setting environment variables..."

cat > /home/openclaw/.env <<ENV
# Anthropic API key for Claude
ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}

# Telegram bot token (also in openclaw.json)
TELEGRAM_BOT_TOKEN=${TELEGRAM_BOT_TOKEN}

# WordPress REST API credentials
WP_SITE_URL=https://${WP_DOMAIN}
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

log "Environment variables set."

# ─────────────────────────────────────────────
# Phase 10: Systemd Service for OpenClaw
# ─────────────────────────────────────────────
log "Phase 10: Creating systemd service..."

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

systemctl daemon-reload
systemctl enable openclaw
systemctl start openclaw

log "OpenClaw service started."

# ─────────────────────────────────────────────
# Phase 11: Firewall (fresh install only)
# ─────────────────────────────────────────────

if [[ "$EXISTING_WORDPRESS" != "true" ]]; then
    log "Phase 11: Configuring firewall..."

    ufw default deny incoming
    ufw default allow outgoing
    ufw allow ssh
    ufw allow 'Nginx Full'
    ufw --force enable

    log "Firewall configured."
else
    log "Phase 11: Skipping firewall configuration (existing WordPress)."
    info "Your existing firewall rules are untouched."
fi

# ─────────────────────────────────────────────
# Phase 12: Fail2Ban (fresh install only)
# ─────────────────────────────────────────────

if [[ "$EXISTING_WORDPRESS" != "true" ]]; then
    log "Phase 12: Configuring fail2ban..."
    systemctl enable fail2ban
    systemctl start fail2ban
    log "Fail2ban started."
else
    log "Phase 12: Skipping fail2ban configuration (existing WordPress)."
fi

# ─────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════"
echo -e "${GREEN} Setup Complete!${NC}"
echo "════════════════════════════════════════════════════"
echo ""

if [[ "$EXISTING_WORDPRESS" != "true" ]]; then
    echo "WordPress:"
    echo "  URL:      https://${WP_DOMAIN}"
    echo "  Admin:    ${WP_ADMIN_USER}"
    echo "  Password: ${WP_ADMIN_PASS}"
    echo "  DB Pass:  ${WP_DB_PASS}"
    echo "  App Pass: ${WP_APP_PASSWORD}"
    echo ""
else
    echo "WordPress (existing site):"
    echo "  URL:      https://${WP_DOMAIN}"
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
WordPress URL: https://${WP_DOMAIN}
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
log "Credentials saved to /root/setup-credentials.txt (delete after noting them down)"
