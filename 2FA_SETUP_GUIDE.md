# 🔐 Two-Factor Authentication (2FA) Setup Guide

This guide explains how to set up Two-Factor Authentication for the Student Management System.

## Overview

The system supports two notification channels for 2FA codes:
- **Telegram** - Receive codes via a Telegram Bot
- **Discord** - Receive codes via Discord Webhooks

## 📱 Telegram Setup

### Step 1: Create a Telegram Bot

1. Open Telegram and search for `@BotFather`
2. Start a chat and send `/newbot`
3. Follow the prompts:
   - Enter a name for your bot (e.g., "Student System 2FA")
   - Enter a username for your bot (must end in `bot`, e.g., `student_2fa_bot`)
4. **Save the API Token** - It looks like this:
   ```
   123456789:ABCdefGHIjklMNOpqrsTUVwxyz
   ```

### Step 2: Get Your Chat ID

1. Open a chat with your new bot
2. Send any message (like `/start`)
3. Open this URL in your browser (replace `YOUR_TOKEN` with your actual token):
   ```
   https://api.telegram.org/botYOUR_TOKEN/getUpdates
   ```
4. Look for `"chat":{"id":` in the response. Your **Chat ID** is the number after it.
   - Example: If you see `"chat":{"id":987654321,`, your Chat ID is `987654321`

### Step 3: Configure Environment Variables

Set these environment variables on your system:

**Windows (Command Prompt - Temporary):**
```cmd
set TELEGRAM_BOT_TOKEN=123456789:ABCdefGHIjklMNOpqrsTUVwxyz
set TELEGRAM_CHAT_ID=987654321
set TFA_NOTIFICATION_CHANNEL=telegram
```

**Windows (PowerShell - Temporary):**
```powershell
$env:TELEGRAM_BOT_TOKEN = "123456789:ABCdefGHIjklMNOpqrsTUVwxyz"
$env:TELEGRAM_CHAT_ID = "987654321"
$env:TFA_NOTIFICATION_CHANNEL = "telegram"
```

**Windows (Permanent - System Environment Variables):**
1. Press `Win + R`, type `sysdm.cpl`, press Enter
2. Go to "Advanced" tab → "Environment Variables"
3. Under "User variables", click "New"
4. Add each variable:
   - `TELEGRAM_BOT_TOKEN` = your bot token
   - `TELEGRAM_CHAT_ID` = your chat ID
   - `TFA_NOTIFICATION_CHANNEL` = `telegram`

---

## 💬 Discord Setup

### Step 1: Create a Discord Webhook

1. Open Discord and go to your server
2. Right-click on the channel where you want to receive codes
3. Select **"Edit Channel"** → **"Integrations"** → **"Webhooks"**
4. Click **"New Webhook"**
5. Give it a name (e.g., "2FA Bot")
6. Click **"Copy Webhook URL"**
   - It looks like: `https://discord.com/api/webhooks/1234567890/abcdefghijklmnop`

### Step 2: Configure Environment Variables

Set these environment variables:

**Windows (Command Prompt - Temporary):**
```cmd
set DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/1234567890/abcdefghijklmnop
set TFA_NOTIFICATION_CHANNEL=discord
```

**Windows (PowerShell - Temporary):**
```powershell
$env:DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/1234567890/abcdefghijklmnop"
$env:TFA_NOTIFICATION_CHANNEL = "discord"
```

**Windows (Permanent):**
Same as Telegram - use System Environment Variables.

---

## 🔄 Using Both Channels

To receive codes on both Telegram and Discord:

```cmd
set TELEGRAM_BOT_TOKEN=your_token
set TELEGRAM_CHAT_ID=your_chat_id
set DISCORD_WEBHOOK_URL=your_webhook_url
set TFA_NOTIFICATION_CHANNEL=both
```

---

## ⚙️ Alternative: Direct Configuration

If you don't want to use environment variables, you can edit the configuration directly in the source code:

Edit `src/com/itc/studentmgmt/security/TwoFactorAuthService.java`:

```java
// Find these lines and update the values:
private static final String TELEGRAM_BOT_TOKEN = getEnvOrDefault(
    "TELEGRAM_BOT_TOKEN", 
    "YOUR_ACTUAL_BOT_TOKEN_HERE"  // ← Replace this
);

private static final String TELEGRAM_CHAT_ID = getEnvOrDefault(
    "TELEGRAM_CHAT_ID", 
    "YOUR_ACTUAL_CHAT_ID_HERE"  // ← Replace this
);

private static final String DISCORD_WEBHOOK_URL = getEnvOrDefault(
    "DISCORD_WEBHOOK_URL", 
    "YOUR_ACTUAL_WEBHOOK_URL_HERE"  // ← Replace this
);
```

After editing, recompile the project:
```cmd
javac -encoding UTF-8 -cp "lib/*" -d bin -sourcepath src src/main/main.java src/com/itc/studentmgmt/**/*.java
```

---

## 🚀 Running the Application

After configuring 2FA, run the application:

```cmd
cd D:\DataSecurity
java -cp "bin;lib/*" main.main
```

On startup, you'll see the 2FA configuration status:
```
═══════════════════════════════════════════════════════════════
                    2FA CONFIGURATION STATUS
═══════════════════════════════════════════════════════════════

📱 Telegram: ✅ Configured
   Bot Token: 123456789:...
   Chat ID: 987654321

💬 Discord: ❌ Not configured
   Set DISCORD_WEBHOOK_URL environment variable

🔔 Active Channel: TELEGRAM
═══════════════════════════════════════════════════════════════
```

---

## 🔒 How 2FA Works

1. **Login with credentials** - Enter username and password
2. **Receive code** - A 6-digit code is sent to your Telegram/Discord
3. **Enter code** - Type the code in the verification dialog
4. **Access granted** - You're logged in!

### Security Features:
- Codes expire after **5 minutes**
- Maximum **3 attempts** before the code is invalidated
- Timing-safe code comparison (prevents timing attacks)
- All 2FA events are logged for security auditing

---

## ❓ Troubleshooting

### "2FA not configured" message
- Check that environment variables are set correctly
- Restart the terminal/application after setting variables

### Not receiving Telegram messages
- Make sure you've started a chat with your bot (send `/start`)
- Verify the Chat ID is correct
- Check that your bot token is valid

### Not receiving Discord messages
- Verify the webhook URL is correct
- Check that the webhook wasn't deleted
- Make sure the URL starts with `https://discord.com/api/webhooks/`

### Code expired too quickly
- The default expiration is 5 minutes
- Make sure your system clock is accurate

---

## 📋 Quick Reference

| Variable | Description | Example |
|----------|-------------|---------|
| `TELEGRAM_BOT_TOKEN` | Bot token from @BotFather | `123456789:ABC...` |
| `TELEGRAM_CHAT_ID` | Your chat ID | `987654321` |
| `DISCORD_WEBHOOK_URL` | Discord webhook URL | `https://discord.com/api/webhooks/...` |
| `TFA_NOTIFICATION_CHANNEL` | Channel to use | `telegram`, `discord`, or `both` |

---

## 🔗 Useful Links

- [Telegram Bot API Documentation](https://core.telegram.org/bots/api)
- [Discord Webhooks Guide](https://support.discord.com/hc/en-us/articles/228383668-Intro-to-Webhooks)
- [BotFather on Telegram](https://t.me/botfather)
