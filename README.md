# tg-wordpress-agent

Manage WordPress entirely from Telegram using AI. Combines [OpenClaw](https://github.com/openclaw/openclaw) (AI agent gateway), WordPress [Abilities API + MCP Adapter + AI Client SDK](https://make.wordpress.org/ai/2025/07/17/ai-building-blocks/), and WP-CLI into a single self-hosted system.

## What It Does

Send a Telegram message like **"Install WooCommerce and create 3 sample products"** — the AI agent understands your intent, runs the right WP-CLI commands and API calls, and reports back. No wp-admin needed.

**Capabilities:**
- Install/manage plugins and themes
- Create/edit/delete posts, pages, products
- Change site settings, designs, menus
- Upload media, manage users
- Generate content and images using AI
- Run arbitrary WP-CLI commands (with safety blocklist)
- Full WooCommerce management

## Architecture

```
Telegram → OpenClaw (grammY + Claude LLM) → WP-CLI / Abilities API → WordPress
```

Everything runs on a single VPS. OpenClaw handles the Telegram channel and LLM orchestration. The WordPress bridge plugin exposes site capabilities via the Abilities API and MCP Adapter. WP-CLI provides direct command execution.

## Quick Start

1. Create a Telegram bot via [@BotFather](https://t.me/BotFather)
2. Get an [Anthropic API key](https://console.anthropic.com/)
3. Provision an Ubuntu 22.04+ VPS with a domain
4. Run the setup:

```bash
git clone https://github.com/YOUR_USERNAME/tg-wordpress-agent.git /opt/tg-wordpress-agent

export WP_DOMAIN="your-domain.com"
export TELEGRAM_BOT_TOKEN="your-token"
export TELEGRAM_USER_ID="your-id"
export ANTHROPIC_API_KEY="sk-ant-..."

bash /opt/tg-wordpress-agent/scripts/setup-vps.sh
```

5. Approve Telegram pairing and start chatting

Full guide: **[GUIDE.md](GUIDE.md)**

## Project Structure

```
├── wordpress-bridge-plugin/    WP plugin: Abilities API + WP-CLI + REST endpoints
├── openclaw-skills/wordpress/  OpenClaw skill definition for WordPress management
├── openclaw-config/            Gateway config (Telegram, LLM) + agent system prompt
├── scripts/                    VPS setup automation + Telegram bot creation guide
├── agent-skills/               WordPress AI coding skills (upstream reference)
├── GUIDE.md                    Complete VPS deployment walkthrough
└── README.md                   This file
```

## Key Technologies

| Component | Role |
|-----------|------|
| [OpenClaw](https://github.com/openclaw/openclaw) | AI agent gateway — Telegram integration, LLM orchestration, skill system |
| [WP-CLI](https://wp-cli.org/) | Command-line WordPress management |
| [Abilities API](https://github.com/WordPress/abilities-api) | Machine-readable WordPress capability registry |
| [MCP Adapter](https://github.com/WordPress/mcp-adapter) | Translates abilities to Model Context Protocol for AI agents |
| [PHP AI Client SDK](https://github.com/WordPress/php-ai-client) | Provider-agnostic AI generation from within WordPress |

## License

GPL-2.0-or-later
