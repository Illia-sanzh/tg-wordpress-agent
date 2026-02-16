# How to Create Your Telegram Bot

## Step 1: Create the Bot via BotFather

1. Open Telegram and search for **@BotFather**
2. Send `/newbot`
3. Choose a **display name** (e.g., "My WordPress Agent")
4. Choose a **username** ending in `bot` (e.g., `my_wp_agent_bot`)
5. BotFather will give you a **bot token** like: `7123456789:AAF1234abcd5678efgh`
6. Save this token — you'll need it for the setup

## Step 2: Get Your Telegram User ID

1. Search for **@userinfobot** on Telegram
2. Send it any message
3. It replies with your **User ID** (a number like `123456789`)
4. Save this — it's your `allowFrom` value

## Step 3: Configure Bot Commands (optional)

Send to @BotFather:
```
/setcommands
```

Then select your bot and paste:
```
status - Show session info
new - Start a new conversation
reset - Reset the session
compact - Compress context window
think - Set thinking depth (off/low/medium/high)
```

## Step 4: Set Bot Description (optional)

Send to @BotFather:
```
/setdescription
```

Then: "AI-powered WordPress management bot. Send me commands to manage your WordPress site."

## What You'll Have

- **Bot Token**: Goes into `openclaw.json` → `channels.telegram.botToken`
- **Your User ID**: Goes into `openclaw.json` → `channels.telegram.allowFrom`
