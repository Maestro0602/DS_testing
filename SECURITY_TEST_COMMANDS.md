# 🔐 Security Testing Commands - All Working Commands

This document contains all the tested and working commands for the Student Management System security features.

---

## 📋 Table of Contents

1. [Database Setup](#database-setup)
2. [Compilation](#compilation)
3. [Security Testing](#security-testing)
4. [2FA Testing](#2fa-testing)
5. [Running the Application](#running-the-application)
6. [Viewing Logs](#viewing-logs)
7. [Troubleshooting](#troubleshooting)

---

## 🗄️ Database Setup

### Fix Database Issues (If Needed)
```powershell
# Navigate to project directory
cd d:\DataSecurity

# Compile the database fix utility
javac -encoding UTF-8 -cp "lib/*" FixDatabase.java

# Run the fix
java -cp ".;lib/*" FixDatabase
```

**What it does:**
- ✅ Drops and recreates incompatible tables
- ✅ Fixes foreign key constraints
- ✅ Creates proper table structure matching the code

---

## 🔨 Compilation

### Compile All Java Files
```powershell
cd d:\DataSecurity

javac -encoding UTF-8 -cp "lib/*" -d bin -sourcepath src (Get-ChildItem -Path src -Recurse -Filter "*.java").FullName
```

**What it does:**
- ✅ Compiles all `.java` files in the `src` directory
- ✅ Uses UTF-8 encoding to handle special characters
- ✅ Outputs compiled `.class` files to `bin` directory
- ✅ Resolves all dependencies from `lib` folder

**Expected output:** Silent completion (no errors)

**Verify compilation:**
```powershell
# Check number of compiled class files
(Get-ChildItem -Path bin -Recurse -Filter "*.class" | Measure-Object).Count
```
Should show **56 class files** compiled.

---

## 🛡️ Security Testing

### Full Security Simulation (All 5 Phases)
```powershell
cd d:\DataSecurity

java -cp "bin;lib/*" com.itc.studentmgmt.security.SecuritySimulationRunner full
```

**What it tests:**
- ✅ **Phase 1: Reconnaissance** - Rate limiting counters (15 requests)
- ✅ **Phase 2: Credential Stuffing** - Brute force detection (98 blocked attempts)
- ✅ **Phase 3: Injection Attempts** - SQL injection (9/10 detected), XSS (10/10 detected), Path traversal (10 logged)
- ✅ **Phase 4: Session Token Abuse** - Invalid tokens rejected (10), Replay attempts blocked (5)
- ✅ **Phase 5: Ransomware-Like Behavior** - Abnormal data access detection (60 records accessed)

**Expected Results:**
```
✅ 98 rate limits triggered
✅ 19 injection attacks detected
✅ 10 session abuse attempts blocked
✅ 3 IPs blocked
✅ 32+ security alerts generated
✅ Simulation completed in ~11-12 seconds
```

### Individual Phase Testing

#### Phase 1 Only - Reconnaissance
```powershell
java -cp "bin;lib/*" com.itc.studentmgmt.security.SecuritySimulationRunner 1
```

#### Phase 2 Only - Credential Stuffing
```powershell
java -cp "bin;lib/*" com.itc.studentmgmt.security.SecuritySimulationRunner 2
```

#### Phase 3 Only - Injection Attempts
```powershell
java -cp "bin;lib/*" com.itc.studentmgmt.security.SecuritySimulationRunner 3
```

#### Phase 4 Only - Session Token Abuse
```powershell
java -cp "bin;lib/*" com.itc.studentmgmt.security.SecuritySimulationRunner 4
```

#### Phase 5 Only - Ransomware-Like Behavior
```powershell
java -cp "bin;lib/*" com.itc.studentmgmt.security.SecuritySimulationRunner 5
```

---

## 📱 2FA Testing

### Test Two-Factor Authentication
```powershell
cd d:\DataSecurity

java -cp "bin;lib/*" com.itc.studentmgmt.security.TwoFactorAuthTest
```

**Expected Output (when configured):**
```
===========================================
    TWO-FACTOR AUTHENTICATION TEST
===========================================

Configuration Status:
  ✓ Telegram: Configured
    Bot Token: 8339279272...
    Chat ID: 1006124574
  
  ✗ Discord: Not configured

  Active Channel: TELEGRAM

[*] Testing 2FA code generation and sending...

[+] SUCCESS! Check your Telegram/Discord for the test code.
    This confirms 2FA is working correctly!

===========================================
    TEST COMPLETE
===========================================
```

### Configure 2FA Environment Variables

**For Telegram (PowerShell - Temporary):**
```powershell
$env:TELEGRAM_BOT_TOKEN = "YOUR_BOT_TOKEN_HERE"
$env:TELEGRAM_CHAT_ID = "YOUR_CHAT_ID_HERE"
$env:TFA_NOTIFICATION_CHANNEL = "telegram"
```

**For Discord (PowerShell - Temporary):**
```powershell
$env:DISCORD_WEBHOOK_URL = "YOUR_WEBHOOK_URL_HERE"
$env:TFA_NOTIFICATION_CHANNEL = "discord"
```

**For Both (PowerShell - Temporary):**
```powershell
$env:TELEGRAM_BOT_TOKEN = "YOUR_BOT_TOKEN_HERE"
$env:TELEGRAM_CHAT_ID = "YOUR_CHAT_ID_HERE"
$env:DISCORD_WEBHOOK_URL = "YOUR_WEBHOOK_URL_HERE"
$env:TFA_NOTIFICATION_CHANNEL = "both"
```

---

## 🚀 Running the Application

### Start the Student Management System
```powershell
cd d:\DataSecurity

java -cp "bin;lib/*" main.main
```

**Expected Output:**
```
╔═══════════════════════════════════════════════════════╗
║                                                       ║
║          STUDENT MANAGEMENT SYSTEM v2.0               ║
║          Institute of Technology Cambodia             ║
║                                                       ║
║          🔐 Secured with Argon2id Encryption          ║
║                                                       ║
╚═══════════════════════════════════════════════════════╝

✓ Testing database connection...
✓ Database 'stu_manage' is ready
✓ Users table ready
✓ Students table ready
✓ Audit logs table ready
✓ Announcements table ready
✓ Schedules table ready
✓ Student enrollments table ready
✓ Database connection established successfully!
✓ Database connection successful!

════════════════════════════════════════════════════════
                    2FA CONFIGURATION STATUS
════════════════════════════════════════════════════════

✓ Telegram: ✓ Configured
   Bot Token: 8339279272...
   Chat ID: 1006124574

✗ Discord: ✗ Not configured
   Set DISCORD_WEBHOOK_URL environment variable

✓ Active Channel: TELEGRAM
════════════════════════════════════════════════════════

✓ Launching application...
```

**Default Login Credentials:**
- **Admin:** `admin` / `admin123`
- **Teacher:** `teacher1` / `teacher123`
- **Student:** `student1` / `student123`

---

## 📊 Viewing Logs

### Check Security Audit Logs
```powershell
cd d:\DataSecurity\security_logs

# View latest log file
Get-Content (Get-ChildItem -Filter "audit_*.log" | Sort-Object LastWriteTime -Descending | Select-Object -First 1).Name
```

### List All Log Files
```powershell
Get-ChildItem d:\DataSecurity\security_logs\audit_*.log | Select-Object Name, Length, LastWriteTime
```

### View Specific Log File
```powershell
Get-Content d:\DataSecurity\security_logs\audit_2026-02-02.log
```

### Count Security Events
```powershell
# Count total events in latest log
(Get-Content (Get-ChildItem d:\DataSecurity\security_logs\audit_*.log | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName).Count
```

---

## 🔧 Troubleshooting

### Check Java Version
```powershell
java -version
```
**Required:** Java JDK 11 or higher

### Check MySQL Status
```powershell
# Check if MySQL service is running (Windows)
Get-Service -Name MySQL* | Select-Object Name, Status
```

### Verify Database Connection
```powershell
# Test direct connection to MySQL
mysql -u root -p -e "SHOW DATABASES;"
```

### Clean and Rebuild
```powershell
cd d:\DataSecurity

# Remove old compiled files
Remove-Item -Recurse -Force bin/*

# Recompile everything
javac -encoding UTF-8 -cp "lib/*" -d bin -sourcepath src (Get-ChildItem -Path src -Recurse -Filter "*.java").FullName

# Verify compilation
(Get-ChildItem -Path bin -Recurse -Filter "*.class" | Measure-Object).Count
```

### Database Reset (Complete Reset)
```powershell
# Drop entire database and recreate
mysql -u root -p -e "DROP DATABASE IF EXISTS stu_manage; CREATE DATABASE stu_manage CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"

# Run the fix utility to recreate tables
java -cp ".;lib/*" FixDatabase
```

---

## 📈 Test Results Summary

### Security Simulation Results ✅

| Test Phase | Tests Run | Results |
|------------|-----------|---------|
| **Phase 1: Reconnaissance** | 15 requests | ✅ All tracked |
| **Phase 2: Credential Stuffing** | 100 attempts | ✅ 98 blocked after 2 attempts |
| **Phase 3: SQL Injection** | 10 payloads | ✅ 9/10 detected (90%) |
| **Phase 3: XSS** | 10 payloads | ✅ 10/10 detected (100%) |
| **Phase 3: Path Traversal** | 10 attempts | ✅ 10/10 logged (100%) |
| **Phase 4: Invalid Tokens** | 10 tokens | ✅ 10/10 rejected (100%) |
| **Phase 4: Token Replay** | 5 attempts | ✅ 5/5 blocked (100%) |
| **Phase 5: Mass Data Access** | 60 records | ✅ Abnormal behavior detected |

**Total Security Events Generated:** 166+ events  
**IPs Blocked:** 3 (10.0.0.50, 172.16.0.99, 192.168.100.200)  
**Critical Alerts:** 32+  
**Simulation Duration:** ~11.85 seconds

### Security Features Tested ✅

- ✅ **Intrusion Detection System (IDS)** - Active and working
- ✅ **Rate Limiting (IP & User-based)** - Blocking after thresholds exceeded
- ✅ **Brute Force Protection** - Detected and blocked credential stuffing
- ✅ **SQL Injection Detection** - 90% detection rate
- ✅ **XSS Detection** - 100% detection rate
- ✅ **Path Traversal Logging** - All attempts logged
- ✅ **Session Token Validation** - HMAC validation working
- ✅ **Token Replay Protection** - All replay attempts blocked
- ✅ **Threat Scoring System** - Auto-blocking based on threat scores
- ✅ **Security Audit Logging** - All events logged with blockchain-style hash chain
- ✅ **Alert Generation** - Real-time security alerts
- ✅ **Abnormal Behavior Detection** - Mass data access patterns detected

---

## 🎯 Quick Reference Commands

### Most Common Commands
```powershell
# Compile everything
cd d:\DataSecurity; javac -encoding UTF-8 -cp "lib/*" -d bin -sourcepath src (Get-ChildItem -Path src -Recurse -Filter "*.java").FullName

# Run full security test
java -cp "bin;lib/*" com.itc.studentmgmt.security.SecuritySimulationRunner full

# Test 2FA
java -cp "bin;lib/*" com.itc.studentmgmt.security.TwoFactorAuthTest

# Run application
java -cp "bin;lib/*" main.main

# View latest security log
Get-Content (Get-ChildItem d:\DataSecurity\security_logs\audit_*.log | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName

# Fix database
javac -encoding UTF-8 -cp "lib/*" FixDatabase.java; java -cp ".;lib/*" FixDatabase
```

---

## 📝 Notes

- All commands are tested and working on **Windows PowerShell**
- **Java JDK 11+** is required
- **MySQL 8.0+** should be running on `localhost:3306`
- Update database credentials in `DatabaseConnection.java` if needed (default: root/MRHENGXD123)
- Security logs are stored in `security_logs/audit_YYYY-MM-DD.log`
- Default users are created automatically on first run
- 2FA requires Telegram Bot Token or Discord Webhook URL to be configured

---

## ✅ Success Indicators

When everything is working correctly, you should see:

1. **Compilation:** No errors, 56 class files compiled
2. **Database:** All 6 tables created successfully
3. **Security Tests:** All phases complete with statistics shown
4. **2FA:** Test code sent to configured channel
5. **Application:** Login screen appears with no errors
6. **Logs:** New log files created in `security_logs/` folder

---

**Last Updated:** February 2, 2026  
**Version:** 2.0.0  
**Status:** ✅ All Tests Passing
