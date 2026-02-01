# 🔑 IMPORTANT: Where to Add Your Credentials
## Quick Reference for Database & 2FA Configuration

---

## ⚠️ MUST CHANGE: Database Credentials

### File: `src/com/itc/studentmgmt/database/DatabaseConnection.java`

**Go to Lines 50-52:**

```java
// Current values:
private static final String DB_USERNAME = "root";
private static final String DB_PASSWORD = "MRHENGXD123";

// Change to YOUR MySQL credentials:
private static final String DB_USERNAME = "your_mysql_username";
private static final String DB_PASSWORD = "your_mysql_password";
```

**Example if your MySQL username is "admin" and password is "mypass123":**
```java
private static final String DB_USERNAME = "admin";
private static final String DB_PASSWORD = "mypass123";
```

**That's it! The database will be created automatically.**

---

## 🔐 OPTIONAL: Enable Two-Factor Authentication (2FA)

### Skip this section if you don't want 2FA!

### File: `src/com/itc/studentmgmt/security/TwoFactorAuthService.java`

---

## Option 1: Telegram Bot (Recommended)

### Step 1: Get Your Telegram Bot Token

1. Open Telegram and search for `@BotFather`
2. Send `/newbot` command
3. Follow instructions to create your bot
4. You'll receive a token like: `123456789:ABCdefGHIjklMNOpqrsTUVwxyz`

### Step 2: Get Your Chat ID

1. Send a message to your bot
2. Visit: `https://api.telegram.org/bot<YOUR_BOT_TOKEN>/getUpdates`
3. Look for `"chat":{"id":123456789}`
4. That number is your chat ID

### Step 3: Add to Code

**Go to Lines 58-68 in TwoFactorAuthService.java:**

```java
// BEFORE (with placeholders):
private static final String TELEGRAM_BOT_TOKEN = getEnvOrDefault(
    "TELEGRAM_BOT_TOKEN", 
    "YOUR_TELEGRAM_BOT_TOKEN_HERE"  // ← Replace this
);

private static final String TELEGRAM_CHAT_ID = getEnvOrDefault(
    "TELEGRAM_CHAT_ID", 
    "YOUR_TELEGRAM_CHAT_ID_HERE"  // ← Replace this
);

// AFTER (with your actual values):
private static final String TELEGRAM_BOT_TOKEN = getEnvOrDefault(
    "TELEGRAM_BOT_TOKEN", 
    "123456789:ABCdefGHIjklMNOpqrsTUVwxyz"  // ← Your bot token
);

private static final String TELEGRAM_CHAT_ID = getEnvOrDefault(
    "TELEGRAM_CHAT_ID", 
    "987654321"  // ← Your chat ID
);
```

### Step 4: Set Notification Channel

**Go to Lines 76-80:**

```java
// Change from:
private static final String NOTIFICATION_CHANNEL = getEnvOrDefault(
    "TFA_NOTIFICATION_CHANNEL", 
    "none"  // ← Change this
);

// To:
private static final String NOTIFICATION_CHANNEL = getEnvOrDefault(
    "TFA_NOTIFICATION_CHANNEL", 
    "telegram"  // ← Now using Telegram
);
```

---

## Option 2: Discord Webhook

### Step 1: Create Discord Webhook

1. Open Discord server settings
2. Go to Integrations → Webhooks
3. Click "New Webhook"
4. Copy the webhook URL (looks like: `https://discord.com/api/webhooks/123456789/abc...`)

### Step 2: Add to Code

**Go to Lines 70-74 in TwoFactorAuthService.java:**

```java
// BEFORE:
private static final String DISCORD_WEBHOOK_URL = getEnvOrDefault(
    "DISCORD_WEBHOOK_URL", 
    "YOUR_DISCORD_WEBHOOK_URL_HERE"  // ← Replace this
);

// AFTER:
private static final String DISCORD_WEBHOOK_URL = getEnvOrDefault(
    "DISCORD_WEBHOOK_URL", 
    "https://discord.com/api/webhooks/123456789/abc..."  // ← Your webhook URL
);
```

### Step 3: Set Notification Channel

**Go to Lines 76-80:**

```java
// Change from:
private static final String NOTIFICATION_CHANNEL = getEnvOrDefault(
    "TFA_NOTIFICATION_CHANNEL", 
    "none"  // ← Change this
);

// To:
private static final String NOTIFICATION_CHANNEL = getEnvOrDefault(
    "TFA_NOTIFICATION_CHANNEL", 
    "discord"  // ← Now using Discord
);
```

---

## 📝 Summary Checklist

### Required Changes:
- [ ] Database username (DatabaseConnection.java, line 50)
- [ ] Database password (DatabaseConnection.java, line 52)

### Optional Changes (for 2FA):

**If using Telegram:**
- [ ] Telegram bot token (TwoFactorAuthService.java, line 60)
- [ ] Telegram chat ID (TwoFactorAuthService.java, line 66)
- [ ] Set notification channel to "telegram" (line 78)

**If using Discord:**
- [ ] Discord webhook URL (TwoFactorAuthService.java, line 72)
- [ ] Set notification channel to "discord" (line 78)

---

## 🔨 After Making Changes

### 1. Save All Files
Make sure you save:
- `DatabaseConnection.java`
- `TwoFactorAuthService.java` (if you changed it)

### 2. Recompile
```cmd
cd D:\DataSecurity
javac -encoding UTF-8 -cp "lib/*" -d bin -sourcepath src src/main/main.java src/com/itc/studentmgmt/security/*.java src/com/itc/studentmgmt/service/*.java src/com/itc/studentmgmt/ui/*.java src/com/itc/studentmgmt/model/*.java src/com/itc/studentmgmt/database/*.java src/com/itc/studentmgmt/dao/*.java
```

### 3. Run
```cmd
java -cp "bin;lib/*" main.main
```

### 4. Test
- Try logging in
- If 2FA enabled, check if you receive the code
- Verify database connection works

---

## 🧪 Testing Your 2FA Setup

### Test Telegram:
```cmd
java -cp "bin;lib/*" com.itc.studentmgmt.security.TwoFactorAuthTest
```

**Expected Output:**
```
Testing 2FA code generation and sending...
Generated code: 123456
Sending via Telegram...
✅ 2FA code sent successfully!
```

**Check your Telegram app - you should receive a message!**

### Test Discord:
Same command as above, but check your Discord channel instead.

---

## ❌ If 2FA Doesn't Work

### Check These:
1. **Bot token/Webhook URL is correct**
   - No extra spaces
   - Complete URL/token
   - Not the placeholder "YOUR_..."

2. **Notification channel is set**
   - Should be "telegram" or "discord"
   - Not "none"

3. **Internet connection**
   - Can you access Telegram/Discord?
   - Firewall blocking requests?

4. **For Telegram:**
   - Did you send a message to the bot first?
   - Is the chat ID correct?

5. **For Discord:**
   - Is the webhook URL still valid?
   - Does the webhook channel still exist?

---

## 💡 Pro Tip: Use Environment Variables

Instead of hardcoding, you can use environment variables:

### Windows:
```cmd
set TELEGRAM_BOT_TOKEN=123456789:ABCdefGHIjklMNOpqrsTUVwxyz
set TELEGRAM_CHAT_ID=987654321
set TFA_NOTIFICATION_CHANNEL=telegram
```

### Then run:
```cmd
java -cp "bin;lib/*" main.main
```

**Benefit:** No need to edit code, more secure!

---

## 🎯 Quick Examples

### Example 1: MySQL with default port
```java
// DatabaseConnection.java lines 50-52
private static final String DB_USERNAME = "root";
private static final String DB_PASSWORD = "MySecurePass123";
```

### Example 2: Telegram 2FA
```java
// TwoFactorAuthService.java

// Lines 60 and 66:
private static final String TELEGRAM_BOT_TOKEN = getEnvOrDefault(
    "TELEGRAM_BOT_TOKEN", 
    "1234567890:ABCDefGhiJklMnoPQRstuVWXyz0123456"
);

private static final String TELEGRAM_CHAT_ID = getEnvOrDefault(
    "TELEGRAM_CHAT_ID", 
    "9876543210"
);

// Line 78:
private static final String NOTIFICATION_CHANNEL = getEnvOrDefault(
    "TFA_NOTIFICATION_CHANNEL", 
    "telegram"
);
```

### Example 3: Discord 2FA
```java
// TwoFactorAuthService.java

// Line 72:
private static final String DISCORD_WEBHOOK_URL = getEnvOrDefault(
    "DISCORD_WEBHOOK_URL", 
    "https://discord.com/api/webhooks/1234567890/AbCdEfGhIjKlMnOpQrStUvWxYz"
);

// Line 78:
private static final String NOTIFICATION_CHANNEL = getEnvOrDefault(
    "TFA_NOTIFICATION_CHANNEL", 
    "discord"
);
```

---

## 📚 More Help

For detailed 2FA setup:
- See [2FA_SETUP_GUIDE.md](2FA_SETUP_GUIDE.md)

For other configuration:
- See [CONFIGURATION_GUIDE.md](CONFIGURATION_GUIDE.md)

For getting started:
- See [QUICK_START.md](QUICK_START.md)

---

## ✅ Ready to Go!

Once you've made these changes:
1. ✅ Database credentials set
2. ✅ 2FA configured (optional)
3. ✅ Recompiled
4. ✅ Tested

**You're ready to use the Student Management System!** 🎉
