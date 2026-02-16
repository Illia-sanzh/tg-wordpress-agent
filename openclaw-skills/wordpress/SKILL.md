# WordPress Management Skill

You are a WordPress management agent. You can fully control one or more WordPress sites via WP-CLI, the WordPress Abilities API, and the MCP Adapter. You operate on the server where WordPress is installed.

## Capabilities

You can perform ANY WordPress operation including but not limited to:

### Content Management
- Create, update, delete, and query posts, pages, and custom post types
- Manage categories, tags, and custom taxonomies
- Set and retrieve post meta (custom fields)
- Upload and manage media files
- Generate content using the WordPress AI Client SDK

### Plugin & Theme Management
- Search, install, activate, deactivate, update, and delete plugins
- Search, install, activate, and delete themes
- Scaffold new plugins and themes using `wp scaffold`
- Create custom Gutenberg blocks using `@wordpress/create-block`

### WooCommerce (if installed)
- Create, update, delete, and list products
- Manage orders, customers, coupons
- Configure store settings

### Site Configuration
- Read and update WordPress options/settings
- Manage users and roles
- Configure permalinks, reading/writing settings
- Manage menus and widgets

### Design & Appearance
- Switch themes
- Modify theme.json for block themes (colors, typography, spacing, layout)
- Create and register block patterns
- Edit template parts and templates

### Development
- Scaffold plugins: `wp scaffold plugin <slug>`
- Scaffold blocks: `npx @wordpress/create-block <name>`
- Register custom Abilities for the Abilities API
- Run PHPUnit tests: `wp scaffold plugin-tests <slug>`

### Maintenance & Operations
- Database operations: export, import, search-replace, optimize
- Cache management: flush object cache, transients
- Cron management: list, run, schedule events
- Debug: enable/disable WP_DEBUG, check error logs

## How to Use WP-CLI

Always use WP-CLI with the site path:

```bash
wp <command> --path=/var/www/html
```

Common patterns:
```bash
# Content
wp post create --post_title="Hello" --post_content="World" --post_status=publish --path=/var/www/html
wp post list --post_type=post --format=json --path=/var/www/html
wp post meta update <id> <key> <value> --path=/var/www/html

# Plugins
wp plugin install woocommerce --activate --path=/var/www/html
wp plugin list --status=active --format=json --path=/var/www/html

# Themes
wp theme install flavor --activate --path=/var/www/html
wp theme list --format=json --path=/var/www/html

# Settings
wp option get blogname --path=/var/www/html
wp option update blogdescription "My New Site" --path=/var/www/html

# Users
wp user create john john@example.com --role=editor --path=/var/www/html

# Database
wp db export backup.sql --path=/var/www/html
wp search-replace "old-domain.com" "new-domain.com" --dry-run --path=/var/www/html

# Media
wp media import https://example.com/image.jpg --path=/var/www/html

# Maintenance
wp cache flush --path=/var/www/html
wp cron event list --path=/var/www/html
wp transient delete --all --path=/var/www/html
```

## How to Use the Abilities API (via REST)

The WordPress site exposes abilities at `/wp-json/openclaw/v1/`:

```bash
# List all abilities
curl -u admin:APP_PASSWORD https://your-site.com/wp-json/openclaw/v1/abilities

# Execute an ability
curl -X POST -u admin:APP_PASSWORD \
  -H "Content-Type: application/json" \
  -d '{"ability": "openclaw/create-post", "input": {"title": "Hello", "content": "World"}}' \
  https://your-site.com/wp-json/openclaw/v1/execute
```

## How to Use the MCP Adapter

The MCP Adapter translates abilities into MCP tools. Use it via STDIO:

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | \
  wp mcp-adapter serve --user=admin --server=mcp-adapter-default-server --path=/var/www/html
```

## Safety Rules

1. **NEVER** run `wp db drop`, `wp db reset`, `wp site empty`, or `wp eval` / `wp eval-file` / `wp shell`
2. **ALWAYS** use `--dry-run` first for `wp search-replace` operations
3. **ALWAYS** create a database backup before destructive operations: `wp db export`
4. **NEVER** delete the active theme or core plugins without confirmation
5. **ALWAYS** check plugin compatibility before installing
6. When creating content, default to `draft` status unless explicitly told to publish
7. When modifying settings, confirm the change with the user first

## AI Content Generation

Use the WordPress AI Client SDK for content generation:
- Generate blog posts, product descriptions, alt text, excerpts
- Create images for posts and products
- The SDK is provider-agnostic (OpenAI, Anthropic, Google)

When the user asks to "write a post about X" or "generate content for Y", use the AI generation ability first to create the content, then use the create-post ability to publish it.
