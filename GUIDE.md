# Complete Setup & VPS Management Guide

Manage your WordPress site entirely from Telegram — install plugins, create posts, change themes, manage WooCommerce, and more — all by sending messages to your bot.

This guide covers everything: first-time setup on a fresh VPS, installing on a server that already has WordPress, and day-to-day VPS management.

---

## Table of Contents

1. [How It Works](#how-it-works)
2. [What You Need](#what-you-need)
3. [Part 1: Create Your Telegram Bot](#part-1-create-your-telegram-bot)
4. [Part 2: Install on Your VPS](#part-2-install-on-your-vps)
   - [Option A: Fresh server (no WordPress yet)](#option-a-fresh-server-no-wordpress-yet)
   - [Option B: Server with existing WordPress](#option-b-server-with-existing-wordpress)
5. [Part 3: Connect & Test](#part-3-connect--test)
6. [Part 4: Managing Your VPS](#part-4-managing-your-vps)
   - [Service Management](#service-management)
   - [Viewing Logs](#viewing-logs)
   - [Updating Software](#updating-software)
   - [Backups & Restores](#backups--restores)
   - [Disk & Resource Monitoring](#disk--resource-monitoring)
   - [SSL Certificates](#ssl-certificates)
   - [Firewall & Security](#firewall--security)
   - [Adding a Second WordPress Site](#adding-a-second-wordpress-site)
7. [Configuration Reference](#configuration-reference)
8. [Troubleshooting](#troubleshooting)
9. [Uninstalling](#uninstalling)

---

## How It Works

```
┌──────────────┐     ┌───────────────────────────────┐     ┌─────────────────────┐
│   Telegram    │────▶│  OpenClaw Gateway              │────▶│  Your WordPress     │
│   (You)       │◀────│  + WordPress Skill             │◀────│  Site                │
│               │     │  + Claude AI                   │     │  + Bridge Plugin     │
└──────────────┘     └───────────────────────────────┘     └─────────────────────┘
                     ◀──────────── All on one VPS ────────────▶
```

You send a message in Telegram → the AI understands what you want → it runs the right commands on your WordPress site → reports back. That's it.

**Examples of things you can say:**
- "Install WooCommerce and create 3 sample products"
- "Change the site title to My Store"
- "Create a blog post about winter fashion trends"
- "Switch to the flavor theme"
- "Show me all active plugins"
- "Add a new page called About Us with some placeholder content"

---

## What You Need

| Item | Where to get it |
|------|-----------------|
| **A VPS** (Ubuntu 22.04 or 24.04) | [Hetzner](https://hetzner.com), [DigitalOcean](https://digitalocean.com), [Vultr](https://vultr.com), or any provider. Minimum 2 GB RAM / 2 vCPU. 4 GB recommended. |
| **A domain name** | Pointed to your VPS IP address (set an A record at your registrar). |
| **An Anthropic API key** | [console.anthropic.com](https://console.anthropic.com/) — this powers the AI. |
| **A Telegram account** | You already have one if you use Telegram. |

**Cost estimate:** A capable VPS runs ~$5–10/month. Anthropic API costs depend on usage (typically a few dollars/month for moderate use).

---

## Part 1: Create Your Telegram Bot

This takes about 2 minutes and is done entirely inside Telegram.

### Step 1: Create the bot

1. Open Telegram and search for **@BotFather**
2. Send `/newbot`
3. Pick a display name (e.g., "My WP Agent")
4. Pick a username ending in `bot` (e.g., `my_wp_agent_bot`)
5. BotFather gives you a **bot token** — it looks like this:
   ```
   7123456789:AAF1234abcd5678efgh    
   ```
   **Copy and save this.** You'll need it during setup.

### Step 2: Get your Telegram user ID

1. Search for **@userinfobot** in Telegram
2. Send it any message
3. It replies with your **User ID** (a number like `123456789`) 
4. **Save this number** — it ensures only you can control the bot.

### Step 3 (optional): Set bot commands

Send `/setcommands` to @BotFather, select your bot, and paste:

```
status - Show session info
new - Start a new conversation
reset - Reset the session
compact - Compress context window
think - Set thinking depth (off/low/medium/high)
```

---

## Part 2: Install on Your VPS

### Connect to your server

Open a terminal and SSH in:

```bash
ssh root@YOUR_VPS_IP
```

> **First time connecting?** You'll see a fingerprint warning — type `yes` to continue.  

### Clone this repository

```bash
git clone https://github.com/YOUR_USERNAME/tg-wordpress-agent.git /opt/tg-wordpress-agent
cd /opt/tg-wordpress-agent
```

Now choose the option that matches your situation:

---

### Option A: Fresh server (no WordPress yet)

Use this if your VPS is brand new or doesn't have WordPress installed.

**Set your details** (replace the placeholder values with your own):

```bash
export WP_DOMAIN="your-domain.com"
export WP_ADMIN_EMAIL="you@email.com"
export TELEGRAM_BOT_TOKEN="7123456789:AAF1234abcd5678efgh"
export TELEGRAM_USER_ID="123456789"
export ANTHROPIC_API_KEY="sk-ant-api03-..."
```

**Run the installer:**

```bash
bash /opt/tg-wordpress-agent/scripts/setup-vps.sh
```

The script installs everything automatically:
- Nginx web server + PHP + MariaDB database
- WordPress (latest version) with WP-CLI
- The OpenClaw bridge plugin
- Node.js + OpenClaw AI gateway
- SSL certificate (Let's Encrypt)
- Firewall + fail2ban security
- Systemd service (auto-starts on boot)

**When it finishes**, it prints your credentials. **Save these somewhere safe:**
- WordPress admin password
- WordPress application password (used by the AI agent)
- Database passwords

They're also saved to `/root/setup-credentials.txt` (delete this file after you've noted them down).

---

### Option B: Server with existing WordPress

Use this if WordPress is already running on your server (self-hosted with Nginx or Apache, any version 6.0+).

**Step 1: Set your details**

```bash
# Your existing domain and WordPress path
export WP_DOMAIN="your-domain.com"
export WP_PATH="/var/www/html"                    # ← Change if WP is elsewhere
export WP_ADMIN_USER="admin"                      # ← Your existing WP admin username
export WP_ADMIN_EMAIL="you@email.com"

# Telegram + AI
export TELEGRAM_BOT_TOKEN="7123456789:AAF1234abcd5678efgh"
export TELEGRAM_USER_ID="123456789"
export ANTHROPIC_API_KEY="sk-ant-api03-..."

# Tell the script to skip WordPress/Nginx/DB installation
export EXISTING_WORDPRESS="true"
```

**Step 2: Run the installer**

```bash
bash /opt/tg-wordpress-agent/scripts/setup-vps.sh
```

With `EXISTING_WORDPRESS=true`, the script **skips** the web stack installation and only:
- Installs WP-CLI (if not already present)
- Installs the OpenClaw bridge plugin into your existing site
- Installs Node.js + OpenClaw
- Creates the systemd service
- Creates an application password for REST API access

**Step 3: Verify the bridge plugin**

```bash
wp plugin status openclaw-wp-bridge --path=$WP_PATH --allow-root
```

You should see `Status: Active`. If not:

```bash
wp plugin activate openclaw-wp-bridge --path=$WP_PATH --allow-root
```

> **Using Apache instead of Nginx?** No problem. The bridge plugin and OpenClaw work with any web server. The setup script won't touch your existing Apache configuration.

---

## Part 3: Connect & Test

### 1. Check that everything is running

```bash
# WordPress responding?
curl -so /dev/null -w "%{http_code}" https://your-domain.com
# Should print: 200

# OpenClaw service running?
systemctl status openclaw
# Should show: active (running)

# View live OpenClaw logs
journalctl -u openclaw -f
# Press Ctrl+C to stop watching
```

### 2. Pair your Telegram bot

1. Open Telegram and find your bot (the one you created in Part 1)
2. Send any message, like `hello`
3. The bot will reply with a **pairing code** (e.g., `ABC123`)
4. On your VPS, approve it:

```bash
su - openclaw -c "openclaw pairing approve telegram ABC123"
```

5. The bot confirms you're connected. You're ready to go!

> **Tip:** If you set `dmPolicy` to `"open"` in the config, pairing is skipped and the bot responds immediately. Only do this if you've set `allowFrom` to restrict access to your user ID.

### 3. Try it out

Send these messages to your bot and see what happens:

| You say | What the AI does |
|---------|-----------------|
| "What's the site status?" | Shows WP version, theme, plugins, post count |
| "Install WooCommerce" | Installs and activates WooCommerce |
| "Create a blog post about coffee" | Generates content with AI and creates a draft |
| "List all plugins" | Returns your plugin list |
| "Change site title to My Store" | Updates the blogname option |
| "Switch to flavor theme" | Installs and activates the theme |
| "Show recent posts" | Lists latest published posts |
| "Add a product called Widget for $19.99" | Creates a WooCommerce product |

---

## Part 4: Managing Your VPS

This section covers everything you need for day-to-day server management.

### Service Management

Your VPS runs three main services. Here's how to control them:

#### OpenClaw (the AI agent)

```bash
# Check status
systemctl status openclaw

# Stop / start / restart
systemctl stop openclaw
systemctl start openclaw
systemctl restart openclaw        # Use after config changes

# Disable auto-start on boot
systemctl disable openclaw

# Re-enable auto-start
systemctl enable openclaw
```

#### Nginx (web server)

```bash
systemctl status nginx
systemctl restart nginx           # Use after config changes

# Test config before restarting (catches syntax errors)
nginx -t
```

#### MariaDB (database)

```bash
systemctl status mariadb
systemctl restart mariadb
```

#### PHP-FPM

```bash
# Check which PHP version is running
php -v

# Restart PHP (replace 8.3 with your version)
systemctl restart php8.3-fpm
```

#### Start/stop everything at once

```bash
# Stop all services
systemctl stop openclaw nginx php8.3-fpm mariadb

# Start all services
systemctl start mariadb php8.3-fpm nginx openclaw
```

---

### Viewing Logs

When something isn't working, logs tell you why.

#### OpenClaw logs (AI agent)

```bash
# Live stream (watch in real-time)
journalctl -u openclaw -f

# Last 100 lines
journalctl -u openclaw -n 100

# Logs from today only
journalctl -u openclaw --since today

# Logs from the last hour
journalctl -u openclaw --since "1 hour ago"
```

#### Nginx logs (web server)

```bash
# Error log (problems)
tail -50 /var/log/nginx/error.log

# Access log (all requests)
tail -50 /var/log/nginx/access.log

# Watch errors in real-time
tail -f /var/log/nginx/error.log
```

#### WordPress debug log

First, make sure debug logging is enabled:

```bash
wp config set WP_DEBUG true --raw --path=/var/www/html --allow-root
wp config set WP_DEBUG_LOG true --raw --path=/var/www/html --allow-root
wp config set WP_DEBUG_DISPLAY false --raw --path=/var/www/html --allow-root
```

Then view the log:

```bash
tail -50 /var/www/html/wp-content/debug.log
```

> **Turn off debug mode on production sites** when you're done troubleshooting:
> ```bash
> wp config set WP_DEBUG false --raw --path=/var/www/html --allow-root
> ```

#### MariaDB slow query log

```bash
# Enable slow query logging
mysql -u root -p -e "SET GLOBAL slow_query_log = 'ON'; SET GLOBAL long_query_time = 2;"

# View slow queries
tail -50 /var/log/mysql/mariadb-slow.log
```

---

### Updating Software

Keep everything up to date for security and performance.

#### Update OpenClaw

```bash
npm update -g openclaw@latest
systemctl restart openclaw

# Verify the version
openclaw --version
```

#### Update WordPress core, plugins, and themes

```bash
WP=/var/www/html

# Check what's available
wp core check-update --path=$WP --allow-root
wp plugin list --update=available --path=$WP --allow-root
wp theme list --update=available --path=$WP --allow-root

# Update everything
wp core update --path=$WP --allow-root
wp plugin update --all --path=$WP --allow-root
wp theme update --all --path=$WP --allow-root

# Clear caches after updating
wp cache flush --path=$WP --allow-root
```

> **Pro tip:** You can also tell your Telegram bot: *"Update all plugins"* — and it'll do it for you.

#### Update the bridge plugin

When this repository gets updates:

```bash
cd /opt/tg-wordpress-agent
git pull

# Re-copy the plugin
cp -r wordpress-bridge-plugin/* /var/www/html/wp-content/plugins/openclaw-wp-bridge/
cd /var/www/html/wp-content/plugins/openclaw-wp-bridge
composer install --no-dev
chown -R www-data:www-data /var/www/html/wp-content/plugins/openclaw-wp-bridge

# Re-copy skill files
cp /opt/tg-wordpress-agent/openclaw-skills/wordpress/SKILL.md /home/openclaw/.openclaw/workspace/skills/wordpress/
cp /opt/tg-wordpress-agent/openclaw-config/AGENTS.md /home/openclaw/.openclaw/workspace/

systemctl restart openclaw
```

#### Update system packages

```bash
apt update && apt upgrade -y

# Reboot if a kernel update was installed
# (check if required)
[ -f /var/run/reboot-required ] && echo "Reboot needed" || echo "No reboot needed"
```

#### Update Node.js

```bash
# Check current version
node -v

# Update to latest LTS
curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
apt-get install -y nodejs

# Reinstall global packages
npm install -g pnpm openclaw@latest
systemctl restart openclaw
```

---

### Backups & Restores

#### Create a full backup

```bash
# Create backup directory
mkdir -p /root/backups

# Backup the database
wp db export /root/backups/db-$(date +%Y%m%d-%H%M).sql --path=/var/www/html --allow-root

# Backup WordPress files
tar -czf /root/backups/wp-files-$(date +%Y%m%d-%H%M).tar.gz /var/www/html

# Backup OpenClaw config
tar -czf /root/backups/openclaw-config-$(date +%Y%m%d-%H%M).tar.gz /home/openclaw/.openclaw

# Backup Nginx config
cp /etc/nginx/sites-available/wordpress /root/backups/nginx-wordpress-$(date +%Y%m%d).conf
```

#### Automated daily backups

Create a cron job that runs daily at 3 AM:

```bash
cat > /etc/cron.d/wp-backup <<'CRON'
0 3 * * * root /usr/local/bin/wp db export /root/backups/db-$(date +\%Y\%m\%d).sql --path=/var/www/html --allow-root && find /root/backups -name "db-*.sql" -mtime +7 -delete
CRON
```

This keeps the last 7 days of database backups and automatically deletes older ones.

#### Restore from backup

```bash
# Restore database
wp db import /root/backups/db-20260215-0300.sql --path=/var/www/html --allow-root

# Restore files
tar -xzf /root/backups/wp-files-20260215-0300.tar.gz -C /

# Fix permissions after restore
chown -R www-data:www-data /var/www/html
```

#### Download a backup to your local machine

From your local terminal (not the VPS):

```bash
scp root@YOUR_VPS_IP:/root/backups/db-20260215-0300.sql ./
scp root@YOUR_VPS_IP:/root/backups/wp-files-20260215-0300.tar.gz ./
```

---

### Disk & Resource Monitoring

#### Check disk space

```bash
# Overall disk usage
df -h /

# What's using the most space in WordPress
du -sh /var/www/html/wp-content/uploads/
du -sh /var/www/html/wp-content/plugins/
du -sh /var/www/html/wp-content/themes/

# Find large files (over 100 MB)
find /var/www/html -size +100M -exec ls -lh {} \;

# Backup directory size
du -sh /root/backups/
```

#### Check memory and CPU

```bash
# Memory usage
free -h

# CPU and top processes
top -bn1 | head -20

# What's using the most memory
ps aux --sort=-%mem | head -10
```

#### Check database size

```bash
mysql -u root -p -e "
  SELECT table_schema AS 'Database',
         ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) AS 'Size (MB)'
  FROM information_schema.tables
  WHERE table_schema = 'wordpress'
  GROUP BY table_schema;
"
```

#### Clean up disk space

```bash
# Remove old backups (older than 30 days)
find /root/backups -mtime +30 -delete

# Clean apt cache
apt clean

# Remove old log entries
journalctl --vacuum-time=7d

# Optimize WordPress database
wp db optimize --path=/var/www/html --allow-root

# Clean WordPress transients
wp transient delete --all --path=/var/www/html --allow-root
```

---

### SSL Certificates

Let's Encrypt certificates auto-renew, but here's how to manage them manually.

#### Check certificate status

```bash
certbot certificates
```

#### Force renewal

```bash
certbot renew --force-renewal
systemctl reload nginx
```

#### Test auto-renewal

```bash
certbot renew --dry-run
```

#### Set up SSL for the first time (if skipped during setup)

```bash
certbot --nginx -d your-domain.com --non-interactive --agree-tos -m you@email.com
```

---

### Firewall & Security

#### View firewall rules

```bash
ufw status verbose
```

#### Default rules (set by the installer)

| Rule | Purpose |
|------|---------|
| SSH (22) | Allow | Server access |
| HTTP (80) | Allow | Web traffic (redirects to HTTPS) |
| HTTPS (443) | Allow | Encrypted web traffic |
| Everything else | Deny | Blocked by default |

OpenClaw's port (18789) is bound to localhost only — it's not accessible from the internet.

#### Check fail2ban status

```bash
# Overall status
fail2ban-client status

# SSH jail specifically
fail2ban-client status sshd

# See banned IPs
fail2ban-client get sshd banned
```

#### Unban an IP (if you accidentally locked yourself out)

```bash
fail2ban-client set sshd unbanip YOUR_IP_ADDRESS
```

#### Add WordPress login protection to fail2ban

```bash
cat > /etc/fail2ban/jail.d/wordpress.conf <<'JAIL'
[wordpress-login]
enabled  = true
port     = http,https
filter   = wordpress-login
logpath  = /var/log/nginx/access.log
maxretry = 5
bantime  = 3600
JAIL

cat > /etc/fail2ban/filter.d/wordpress-login.conf <<'FILTER'
[Definition]
failregex = ^<HOST> .* "POST /wp-login.php
FILTER

systemctl restart fail2ban
```

#### Check for rootkits (optional)

```bash
apt install -y rkhunter
rkhunter --check --skip-keypress
```

---

### Adding a Second WordPress Site

You can manage multiple WordPress sites from the same Telegram bot.

**Step 1: Set up the new site** (new database, new Nginx config, new directory)

```bash
# Create directory
mkdir -p /var/www/site2

# Create database
mysql -u root -p -e "
  CREATE DATABASE wordpress_site2 CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
  CREATE USER 'wp_site2'@'localhost' IDENTIFIED BY 'GENERATE_A_PASSWORD';
  GRANT ALL PRIVILEGES ON wordpress_site2.* TO 'wp_site2'@'localhost';
  FLUSH PRIVILEGES;
"

# Install WordPress
cd /var/www/site2
wp core download --allow-root
wp config create --dbname=wordpress_site2 --dbuser=wp_site2 --dbpass=GENERATE_A_PASSWORD --allow-root
wp core install --url=https://site2.com --title="Site 2" --admin_user=admin \
  --admin_password=$(openssl rand -base64 16) --admin_email=you@email.com --allow-root
chown -R www-data:www-data /var/www/site2
```

**Step 2: Add Nginx config** for the new domain, then get an SSL certificate.

**Step 3: Install the bridge plugin** on the new site:

```bash
cp -r /opt/tg-wordpress-agent/wordpress-bridge-plugin /var/www/site2/wp-content/plugins/openclaw-wp-bridge
cd /var/www/site2/wp-content/plugins/openclaw-wp-bridge && composer install --no-dev
chown -R www-data:www-data /var/www/site2/wp-content/plugins/openclaw-wp-bridge
wp plugin activate openclaw-wp-bridge --path=/var/www/site2 --allow-root
```

**Step 4: Update the agent** to know about the new site. Edit `/home/openclaw/.openclaw/workspace/AGENTS.md` and add the second site path. Then restart OpenClaw.

---

## Configuration Reference

### OpenClaw config — `/home/openclaw/.openclaw/openclaw.json`

```json
{
  "agent": {
    "model": "anthropic/claude-sonnet-4-5-20250929"
  },
  "gateway": {
    "port": 18789,
    "bind": "loopback"
  },
  "channels": {
    "telegram": {
      "enabled": true,
      "botToken": "YOUR_TOKEN",
      "dmPolicy": "pairing",
      "allowFrom": ["YOUR_USER_ID"],
      "sendPolicy": "reply"
    }
  }
}
```

| Setting | What it does |
|---------|-------------|
| `agent.model` | Which AI model to use. `claude-sonnet-4-5-20250929` is a good balance of speed and capability. Use `claude-opus-4-6` for the most capable model. |
| `gateway.port` | Internal port for OpenClaw. No need to change this. |
| `gateway.bind` | `"loopback"` means only accessible from the server itself (secure). |
| `channels.telegram.botToken` | Your bot token from BotFather. |
| `channels.telegram.allowFrom` | Array of Telegram user IDs that can use the bot. Add multiple IDs to allow a team. |
| `channels.telegram.dmPolicy` | `"pairing"` = must approve new users via CLI. `"open"` = anyone in `allowFrom` can use it immediately. |

### Environment variables — `/home/openclaw/.env`

| Variable | What it's for |
|----------|--------------|
| `ANTHROPIC_API_KEY` | Your Anthropic API key (powers the AI) |
| `TELEGRAM_BOT_TOKEN` | Telegram bot token (backup; also in openclaw.json) |
| `WP_SITE_URL` | Your WordPress site URL (e.g., `https://your-domain.com`) |
| `WP_APP_USER` | WordPress admin username for REST API calls |
| `WP_APP_PASSWORD` | Application password for REST API authentication |
| `WP_PATH` | Path to WordPress installation (e.g., `/var/www/html`) |

### Editing configuration

```bash
# Edit OpenClaw config
nano /home/openclaw/.openclaw/openclaw.json

# Edit environment variables
nano /home/openclaw/.env

# Always restart after changes
systemctl restart openclaw
```

---

## Troubleshooting

### The bot doesn't respond at all

1. **Check if OpenClaw is running:**
   ```bash
   systemctl status openclaw
   ```
   If it's not running, check the logs:
   ```bash
   journalctl -u openclaw -n 50
   ```

2. **Check the bot token** — make sure it matches what BotFather gave you:
   ```bash
   grep botToken /home/openclaw/.openclaw/openclaw.json
   ```

3. **Check the API key:**
   ```bash
   grep ANTHROPIC /home/openclaw/.env
   ```

### Bot says "pairing required"

Approve the pairing code shown in the bot's message:

```bash
su - openclaw -c "openclaw pairing approve telegram THE_CODE"
```

### WP-CLI commands fail with "permission denied"

The `openclaw` user needs sudo access to run WP-CLI as `www-data`:

```bash
# Check the sudoers entry exists
cat /etc/sudoers.d/openclaw
# Should show: openclaw ALL=(www-data) NOPASSWD: /usr/local/bin/wp

# If missing, add it:
echo "openclaw ALL=(www-data) NOPASSWD: /usr/local/bin/wp" > /etc/sudoers.d/openclaw
```

### Bridge plugin won't activate

```bash
# Check plugin status
wp plugin status openclaw-wp-bridge --path=/var/www/html --allow-root

# Check for PHP errors
wp plugin activate openclaw-wp-bridge --path=/var/www/html --allow-root --debug

# Reinstall Composer dependencies
cd /var/www/html/wp-content/plugins/openclaw-wp-bridge
composer install --no-dev
chown -R www-data:www-data .
```

### SSL certificate errors

```bash
# Check if cert exists
certbot certificates

# Re-issue if needed
certbot --nginx -d your-domain.com

# Test auto-renewal
certbot renew --dry-run
```

### WordPress shows "Error establishing database connection"

```bash
# Check MariaDB is running
systemctl status mariadb

# Test the database credentials
wp config get DB_NAME --path=/var/www/html --allow-root
wp config get DB_USER --path=/var/www/html --allow-root
wp db check --path=/var/www/html --allow-root
```

### Out of memory errors

```bash
# Check current memory
free -h

# If running out, add swap space:
fallocate -l 2G /swapfile
chmod 600 /swapfile
mkswap /swapfile
swapon /swapfile
echo '/swapfile none swap sw 0 0' >> /etc/fstab

# Or upgrade your VPS to 4 GB RAM
```

### OpenClaw keeps crashing / restarting

```bash
# Check for crash loops
systemctl status openclaw
journalctl -u openclaw --since "30 min ago"

# Common causes:
# - Invalid JSON in openclaw.json (validate with: python3 -m json.tool < /home/openclaw/.openclaw/openclaw.json)
# - Missing or expired API key
# - Node.js version too old (need v22+): node -v
```

### "Abilities API not available" error

The Abilities API package may not have installed correctly:

```bash
cd /var/www/html/wp-content/plugins/openclaw-wp-bridge
composer install --no-dev
systemctl restart php8.3-fpm
```

---

## Uninstalling

If you want to completely remove the AI agent while keeping WordPress intact:

```bash
# Stop and remove the OpenClaw service
systemctl stop openclaw
systemctl disable openclaw
rm /etc/systemd/system/openclaw.service
systemctl daemon-reload

# Remove the OpenClaw user and files
userdel -r openclaw

# Remove the bridge plugin
rm -rf /var/www/html/wp-content/plugins/openclaw-wp-bridge
wp plugin deactivate openclaw-wp-bridge --path=/var/www/html --allow-root 2>/dev/null

# Remove the repo
rm -rf /opt/tg-wordpress-agent

# Remove the sudoers entry
rm -f /etc/sudoers.d/openclaw

# Uninstall OpenClaw globally
npm uninstall -g openclaw
```

Your WordPress site continues to work normally — only the AI agent is removed.
