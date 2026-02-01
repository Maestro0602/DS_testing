# 📝 CONFIGURATION GUIDE
# Student Management System - Where to Find and Change Settings

This file explains where all the important configuration settings are located
and how to customize them for your environment.

═══════════════════════════════════════════════════════════════════════════════

## 📍 FILE LOCATIONS QUICK REFERENCE

| Setting              | File Path                                                     | Line # |
|---------------------|---------------------------------------------------------------|--------|
| Database Credentials | `src/com/itc/studentmgmt/database/DatabaseConnection.java`   | 50-52  |
| Telegram Bot Token  | `src/com/itc/studentmgmt/security/TwoFactorAuthService.java` | 58-62  |
| Telegram Chat ID    | `src/com/itc/studentmgmt/security/TwoFactorAuthService.java` | 64-68  |
| Discord Webhook URL | `src/com/itc/studentmgmt/security/TwoFactorAuthService.java` | 70-74  |
| 2FA Channel Setting | `src/com/itc/studentmgmt/security/TwoFactorAuthService.java` | 76-80  |
| Enable/Disable 2FA  | `src/com/itc/studentmgmt/service/AuthenticationService.java` | 321    |
| UI Color Scheme     | `src/com/itc/studentmgmt/ui/EnhancedMainFrame.java`          | 17-22  |
| Default User Passwords | `src/com/itc/studentmgmt/database/DatabaseConnection.java` | 211-239|

═══════════════════════════════════════════════════════════════════════════════

## 🗄️ DATABASE CONFIGURATION

### File: `src/com/itc/studentmgmt/database/DatabaseConnection.java`

```java
// Lines 50-52 - Change these values:

// ⚠️ CHANGE THESE TO YOUR MySQL CREDENTIALS
private static final String DB_USERNAME = "root";           // ← Your MySQL username
private static final String DB_PASSWORD = "MRHENGXD123";    // ← Your MySQL password
```

### What the database does:
- Auto-creates the database `stu_manage` if it doesn't exist
- Auto-creates all required tables:
  - **users** - User accounts (admin, teachers, students)
  - **students** - Student detailed information
  - **schedules** - Class schedules
  - **announcements** - System announcements
  - **student_enrollments** - Course enrollment records
  - **audit_logs** - Security and activity logging
- Auto-creates default users on first run (lines 211-239):
  - **Admin**: admin / admin123
  - **Teacher**: teacher1 / teacher123
  - **Student**: student1 / student123

═══════════════════════════════════════════════════════════════════════════════

## 🔐 TWO-FACTOR AUTHENTICATION (2FA)

### File: `src/com/itc/studentmgmt/security/TwoFactorAuthService.java`

### OPTION 1: Configure in Code (Simple)

Edit lines 51-75:

```java
// TELEGRAM CONFIGURATION (Lines 51-60)
private static final String TELEGRAM_BOT_TOKEN = getEnvOrDefault(
    "TELEGRAM_BOT_TOKEN", 
    "YOUR_TELEGRAM_BOT_TOKEN_HERE"    // ← Replace with your bot token
);

private static final String TELEGRAM_CHAT_ID = getEnvOrDefault(
    "TELEGRAM_CHAT_ID", 
    "YOUR_TELEGRAM_CHAT_ID_HERE"      // ← Replace with your chat ID
);

// DISCORD CONFIGURATION (Lines 63-66)
private static final String DISCORD_WEBHOOK_URL = getEnvOrDefault(
    "DISCORD_WEBHOOK_URL", 
    "YOUR_DISCORD_WEBHOOK_URL_HERE"   // ← Replace with your webhook URL
);

// NOTIFICATION CHANNEL (Lines 72-75)
private static final String NOTIFICATION_CHANNEL = getEnvOrDefault(
    "TFA_NOTIFICATION_CHANNEL", 
    "telegram"                        // ← Options: "telegram", "discord", "both"
);
```

### OPTION 2: Use Environment Variables (Recommended for Production)

Set these environment variables instead of editing the code:

**Windows Command Prompt:**
```cmd
set TELEGRAM_BOT_TOKEN=123456789:ABCdefGHIjklMNOpqrsTUVwxyz
set TELEGRAM_CHAT_ID=987654321
set DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
set TFA_NOTIFICATION_CHANNEL=telegram
```

**Windows PowerShell:**
```powershell
$env:TELEGRAM_BOT_TOKEN = "123456789:ABCdefGHIjklMNOpqrsTUVwxyz"
$env:TELEGRAM_CHAT_ID = "987654321"
$env:DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/..."
$env:TFA_NOTIFICATION_CHANNEL = "telegram"
```

═══════════════════════════════════════════════════════════════════════════════

## 🔄 ENABLE/DISABLE 2FA

### File: `src/com/itc/studentmgmt/service/AuthenticationService.java`

Find line ~321:
```java
// Enable/Disable 2FA - set to true to require 2FA for all logins
private static final boolean TWO_FACTOR_ENABLED = true;   // ← Change to false to disable
```

═══════════════════════════════════════════════════════════════════════════════

## 📱 HOW TO GET TELEGRAM BOT TOKEN

1. Open Telegram
2. Search for `@BotFather`
3. Send `/newbot`
4. Follow the prompts to create your bot
5. Copy the token (looks like: `123456789:ABCdefGHIjklMNOpqrsTUVwxyz`)

## 📱 HOW TO GET TELEGRAM CHAT ID

1. Start a chat with your bot (send `/start`)
2. Open this URL in your browser:
   ```
   https://api.telegram.org/bot<YOUR_TOKEN>/getUpdates
   ```
3. Find `"chat":{"id":123456789` in the response
4. The number after `"id":` is your Chat ID

## 💬 HOW TO GET DISCORD WEBHOOK URL

1. Go to your Discord server
2. Right-click the channel → Edit Channel
3. Go to Integrations → Webhooks → New Webhook
4. Copy the Webhook URL

═══════════════════════════════════════════════════════════════════════════════

## 🚀 RUNNING THE APPLICATION

### Step 1: Make sure MySQL is running

### Step 2: Compile the code
```cmd
cd D:\DataSecurity
javac -encoding UTF-8 -cp "lib/*" -d bin -sourcepath src src/main/main.java src/com/itc/studentmgmt/**/*.java
```

### Step 3: Run the application
```cmd
java -cp "bin;lib/*" main.main
```

═══════════════════════════════════════════════════════════════════════════════

## 📁 PROJECT STRUCTURE

```
D:\DataSecurity\
├── lib/                          # JAR dependencies
│   ├── bcprov-jdk18on-1.77.jar  # Bouncy Castle crypto
│   ├── HikariCP-5.1.0.jar       # Connection pooling
│   ├── mysql-connector-j-8.2.0.jar  # MySQL driver
│   ├── json-20231013.jar        # JSON for API calls
│   └── slf4j-*.jar              # Logging
│
├── src/
│   ├── main/
│   │   └── main.java            # Application entry point
│   │
│   └── com/itc/studentmgmt/
│       ├── database/
│       │   └── DatabaseConnection.java   # ⚠️ DB CREDENTIALS HERE
│       │
│       ├── security/
│       │   ├── TwoFactorAuthService.java # ⚠️ 2FA TOKENS HERE
│       │   ├── PasswordSecurityUtil.java
│       │   ├── SecureSessionManager.java
│       │   └── SecurityAuditLogger.java
│       │
│       ├── service/
│       │   └── AuthenticationService.java # ⚠️ 2FA ENABLE/DISABLE
│       │
│       ├── model/
│       │   ├── User.java
│       │   ├── UserRole.java
│       │   └── Student.java
│       │
│       ├── dao/
│       │   ├── UserDAO.java
│       │   └── StudentDAO.java
│       │
│       └── ui/
│           ├── LoginFrame.java   # Login screen
│           └── MainFrame.java    # Main dashboard
│
├── 2FA_SETUP_GUIDE.md           # Detailed 2FA setup instructions
├── CONFIGURATION_GUIDE.md       # This file
└── README.md
```

═══════════════════════════════════════════════════════════════════════════════

## ❓ TROUBLESHOOTING

### "Database connection failed"
- Check MySQL is running: `net start mysql` or `mysqld`
- Verify username/password in DatabaseConnection.java
- Check MySQL is on port 3306

### "2FA not configured"
- Add your Telegram bot token and chat ID
- Or add your Discord webhook URL
- Make sure values don't contain "YOUR_" placeholder text

### "Login failed"
- Default credentials: admin / admin123
- If you changed passwords, reset by dropping the database

### Compilation errors
- Use `-encoding UTF-8` flag
- Include `-cp "lib/*"` for dependencies

═══════════════════════════════════════════════════════════════════════════════

## 📞 QUICK COPY-PASTE COMMANDS

### Compile:
```cmd
javac -encoding UTF-8 -cp "lib/*" -d bin -sourcepath src src/main/main.java src/com/itc/studentmgmt/**/*.java
```

### Run:
```cmd
java -cp "bin;lib/*" main.main
```

### Test 2FA:
```cmd
java -cp "bin;lib/*" com.itc.studentmgmt.security.TwoFactorAuthTest
```

═══════════════════════════════════════════════════════════════════════════════

## 🎨 UI FEATURES & CUSTOMIZATION

### NEW: Enhanced Main Frame with Sidebar Navigation
**File:** `src/com/itc/studentmgmt/ui/EnhancedMainFrame.java`

The application now features a modern sidebar navigation with role-based menus:

**For Students:**
- 📊 Dashboard (Home view with schedule, announcements, stats)
- 📚 My Courses (View enrolled courses)
- 📅 Schedule (Full class schedule)
- 📊 Grades (View grades - coming soon)
- 👤 Profile (Student information)

**For Teachers:**
- 📊 Dashboard (Teacher-specific view - coming soon)
- 👥 Students (Manage student records)
- 📚 My Classes (View assigned classes)
- 📝 Grading (Enter grades - coming soon)
- 📢 Announcements (Post announcements)

**For Admins:**
- 📊 Dashboard (Admin overview - coming soon)
- 👥 Users (Manage all users)
- 📚 Courses (Course management)
- 📅 Schedules (Schedule management)
- 📢 Announcements (System-wide announcements)
- ⚙️ Settings (System configuration)

### Customize UI Colors
**Files:** EnhancedMainFrame.java, StudentDashboard.java, LoginFrame.java

```java
// Lines 17-22 in EnhancedMainFrame.java:
private static final Color PRIMARY_COLOR = new Color(41, 128, 185);     // Blue
private static final Color SECONDARY_COLOR = new Color(52, 152, 219);   // Light Blue
private static final Color BACKGROUND_COLOR = new Color(236, 240, 241); // Light Gray
private static final Color SIDEBAR_COLOR = new Color(52, 73, 94);       // Dark Gray
private static final Color TEXT_COLOR = new Color(44, 62, 80);          // Dark Text
private static final Color CARD_COLOR = Color.WHITE;                     // Card Background
```

**To change colors:** Replace RGB values with your preferred colors
- Example: `new Color(231, 76, 60)` for red
- Example: `new Color(46, 204, 113)` for green

═══════════════════════════════════════════════════════════════════════════════

## 📊 NEW DATABASE FEATURES

### Student Information (Enhanced)
The `students` table now includes:
- Basic Info: ID, Name, Email
- Contact: Phone, Address
- Academic: Major, GPA, Enrollment Date, Status
- Dates: Date of Birth, Created/Updated timestamps

### Schedules System
Create and manage class schedules with:
- Course code and name
- Teacher assignment
- Day of week, time, room
- Semester information

### Announcements System
Post announcements with:
- Title and content
- Target role (STUDENT, TEACHER, ALL)
- Creator tracking
- Timestamp

### Course Enrollment
Track student enrollments with:
- Student-to-course linking
- Grade tracking
- Enrollment status

═══════════════════════════════════════════════════════════════════════════════

## 🚀 RUNNING THE ENHANCED APPLICATION

1. **First Time Setup:**
   ```cmd
   cd D:\DataSecurity
   javac -encoding UTF-8 -cp "lib/*" -d bin -sourcepath src src/main/main.java src/com/itc/studentmgmt/security/*.java src/com/itc/studentmgmt/service/*.java src/com/itc/studentmgmt/ui/*.java src/com/itc/studentmgmt/model/*.java src/com/itc/studentmgmt/database/*.java src/com/itc/studentmgmt/dao/*.java
   ```

2. **Run the Application:**
   ```cmd
   java -cp "bin;lib/*" main.main
   ```

3. **Login with Default Account:**
   - Username: `student1`
   - Password: `student123`
   - Or use `teacher1`/`teacher123` or `admin`/`admin123`

4. **Explore the New UI:**
   - Navigate using the sidebar
   - View your personalized dashboard
   - Check schedules and announcements
   - Manage your profile

═══════════════════════════════════════════════════════════════════════════════

## 🎯 KEY FEATURES SUMMARY

✅ **Modern UI:** Card-based design with sidebar navigation
✅ **Role-Based Access:** Different views for students, teachers, and admins
✅ **Auto-Database Setup:** Creates everything on first run
✅ **Schedule Management:** View and manage class schedules
✅ **Announcements:** Post and view announcements by role
✅ **Student Dashboard:** Modern welcome screen with stats
✅ **2FA Security:** Optional Telegram/Discord two-factor authentication
✅ **Audit Logging:** All activities are logged for security

═══════════════════════════════════════════════════════════════════════════════

## 📚 NEED MORE HELP?

Check these detailed guides:
- **2FA_SETUP_GUIDE.md** - Complete 2FA configuration instructions
- **README.md** - Project overview and features
- **TESTING_GUIDE.md** - How to test all features

═══════════════════════════════════════════════════════════════════════════════

**Last Updated:** With enhanced UI features, Student Dashboard, and role-based navigation
**Version:** 2.0 - Modern Student Management System
