# ⚡ Quick Start Guide
## Get the Student Management System Running in 5 Minutes

---

## 📋 Prerequisites

Before you start, make sure you have:

✅ **Java 11 or higher** installed
```cmd
java -version
```
Should show Java 11+ (e.g., "11.0.x" or "17.0.x")

✅ **MySQL Server** running
```cmd
net start mysql
```
Or check MySQL service in Task Manager

✅ **Required Libraries** in `lib/` folder:
- `bcprov-jdk18on-1.77.jar` (BouncyCastle)
- `json-20231013.jar` (JSON processing)
- `HikariCP-5.1.0.jar` (Connection pooling)
- `slf4j-api-2.0.9.jar` (Logging)
- `slf4j-simple-2.0.9.jar` (Logging impl)

---

## 🚀 Step 1: Configure Database

**File to Edit:** `src/com/itc/studentmgmt/database/DatabaseConnection.java`

**Current Settings (Lines 50-52):**
```java
private static final String DB_USERNAME = "root";
private static final String DB_PASSWORD = "MRHENGXD123";
```

**If your MySQL credentials are different, change them now.**

**That's it!** The database and all tables will be created automatically on first run.

---

## 🔨 Step 2: Compile the Application

Open Command Prompt in the `D:\DataSecurity` folder and run:

```cmd
javac -encoding UTF-8 -cp "lib/*" -d bin -sourcepath src src/main/main.java src/com/itc/studentmgmt/security/*.java src/com/itc/studentmgmt/service/*.java src/com/itc/studentmgmt/ui/*.java src/com/itc/studentmgmt/model/*.java src/com/itc/studentmgmt/database/*.java src/com/itc/studentmgmt/dao/*.java
```

**Expected Result:** No output = successful compilation

**If you see errors:**
- Check Java version: `java -version`
- Verify all `.jar` files are in `lib/` folder
- Make sure you're in the `D:\DataSecurity` directory

---

## 🎯 Step 3: Run the Application

```cmd
java -cp "bin;lib/*" main.main
```

**Expected Output:**
```
═══════════════════════════════════════
  Student Management System v2.0
  Secure Login with Optional 2FA
═══════════════════════════════════════

[INFO] System initialization...
[INFO] Database initialized successfully
[INFO] Auto-created database: stu_manage
[INFO] All tables created successfully
[INFO] Default users created

2FA Status: ❌ Not configured
  Telegram: Not configured
  Discord: Not configured

System ready! Login window will appear.
```

---

## 🔐 Step 4: Login

**The login window will pop up automatically.**

### Default Login Credentials

| Role | Username | Password |
|------|----------|----------|
| 👤 **Student** | `student1` | `student123` |
| 👨‍🏫 **Teacher** | `teacher1` | `teacher123` |
| ⚙️ **Admin** | `admin` | `admin123` |

**Try logging in as a student first to see the dashboard!**

---

## ✅ Step 5: Explore the Interface

### As a Student (student1 / student123):

**You'll see the Student Dashboard with:**
- 👋 Welcome panel with your name
- 📅 Today's schedule (initially empty)
- 📢 Recent announcements (initially empty)
- 📊 Quick stats (enrolled courses, GPA)

**Sidebar Navigation:**
- 📊 Dashboard (current view)
- 📚 My Courses
- 📅 Schedule
- 📊 Grades (coming soon)
- 👤 Profile

### As a Teacher (teacher1 / teacher123):

**You'll see:**
- Teacher-specific menu items
- Student management access
- Announcement posting capability
- Class management (coming soon)

### As Admin (admin / admin123):

**You'll see:**
- Full system access
- User management
- Course and schedule management
- System-wide announcements
- Settings access (coming soon)

---

## 🎨 What You'll See

### Modern UI Features:
✨ **Card-based design** - Clean, professional look
✨ **Sidebar navigation** - Easy access to all features
✨ **Color-coded elements** - Visual hierarchy
✨ **Role-based menus** - Only see what's relevant to you

### Key Colors:
- **Blue (#2980B9)** - Primary actions and headers
- **Light Blue (#3498DB)** - Secondary elements
- **Dark Gray (#34495E)** - Sidebar and navigation
- **White (#FFFFFF)** - Content cards

---

## 📊 Sample Data (Optional)

The system starts with minimal data. To add more:

### Add Sample Students (As Admin):
1. Login as `admin` / `admin123`
2. Click "Users" in sidebar (coming soon)
3. Add new students with the form

### Add Sample Schedules:
1. Click "Schedules" in sidebar
2. Create class schedules
3. Assign teachers and time slots

### Post Announcements:
1. Click "Announcements"
2. Create new announcement
3. Choose target role (STUDENT/TEACHER/ALL)

---

## 🔧 Optional: Enable Two-Factor Authentication

**Skip this for now if you just want to test the app!**

If you want to add 2FA security:

### Option 1: Telegram Bot
1. See [2FA_SETUP_GUIDE.md](2FA_SETUP_GUIDE.md) for detailed steps
2. Get bot token from BotFather
3. Get your chat ID
4. Edit `TwoFactorAuthService.java` (lines 58-68)

### Option 2: Discord Webhook
1. Create Discord webhook
2. Copy webhook URL
3. Edit `TwoFactorAuthService.java` (lines 70-74)

**Then recompile and run!**

---

## 🎯 Common First-Time Tasks

### 1. Change Your Password
```java
// Login as any user
// Click "Profile" in sidebar
// (Coming soon: Change password option)

// For now, change in database:
UPDATE users SET password_hash = '<new_hash>' WHERE username = 'student1';
```

### 2. Update Student Information
```java
// Login as admin
// Navigate to "Users" → "Students"
// Click on a student
// Edit their information
```

### 3. Create a Class Schedule
```java
// Login as admin
// Click "Schedules"
// Click "Add Schedule"
// Fill in course info, time, room
// Save
```

### 4. Post Your First Announcement
```java
// Login as teacher or admin
// Click "Announcements"
// Click "New Announcement"
// Title: "Welcome to the System!"
// Content: "Hello students, welcome!"
// Target: STUDENT
// Post
```

---

## 🐛 Troubleshooting

### "Database connection failed"
```
Problem: Can't connect to MySQL
Solution:
1. Check MySQL is running: net start mysql
2. Verify username/password in DatabaseConnection.java
3. Make sure MySQL is on port 3306
```

### "ClassNotFoundException: org.bouncycastle..."
```
Problem: BouncyCastle library not found
Solution:
1. Check lib/bcprov-jdk18on-1.77.jar exists
2. Make sure you're using -cp "lib/*" in compile command
```

### "No suitable driver found"
```
Problem: MySQL JDBC driver not found
Solution:
1. The driver should be in HikariCP jar
2. Check if HikariCP-5.1.0.jar is in lib/
3. Make sure -cp "bin;lib/*" is used when running
```

### Login window doesn't appear
```
Problem: GUI not showing
Solution:
1. Check if Java has GUI support: java -version
2. Make sure you're not running in headless mode
3. Try: java -Djava.awt.headless=false -cp "bin;lib/*" main.main
```

### "Default users not created"
```
Problem: Can't login with default credentials
Solution:
1. Check console for error messages
2. Database tables may not have been created
3. Try dropping the database and run again:
   DROP DATABASE stu_manage;
```

---

## 📈 Next Steps

### Customize Your System:

1. **Add Real Students**
   - Import from CSV (coming soon)
   - Add manually through admin panel

2. **Create Course Catalog**
   - Define all courses
   - Set prerequisites
   - Assign credit hours

3. **Build Schedules**
   - Create class timetables
   - Assign teachers
   - Set room locations

4. **Configure Security**
   - Enable 2FA for admins
   - Set password policies
   - Review audit logs

5. **Customize UI**
   - Change color scheme (see CONFIGURATION_GUIDE.md)
   - Add school logo
   - Modify welcome messages

---

## 📚 Learn More

**Detailed Documentation:**
- [FEATURES_OVERVIEW.md](FEATURES_OVERVIEW.md) - All features explained
- [CONFIGURATION_GUIDE.md](CONFIGURATION_GUIDE.md) - Detailed settings
- [2FA_SETUP_GUIDE.md](2FA_SETUP_GUIDE.md) - Security setup
- [README.md](README.md) - Project overview

**Key Files to Understand:**
- `DatabaseConnection.java` - Database setup
- `EnhancedMainFrame.java` - Main UI
- `StudentDashboard.java` - Student view
- `AuthenticationService.java` - Login logic

---

## ✅ Quick Command Reference

### Compile:
```cmd
javac -encoding UTF-8 -cp "lib/*" -d bin -sourcepath src src/main/main.java src/com/itc/studentmgmt/security/*.java src/com/itc/studentmgmt/service/*.java src/com/itc/studentmgmt/ui/*.java src/com/itc/studentmgmt/model/*.java src/com/itc/studentmgmt/database/*.java src/com/itc/studentmgmt/dao/*.java
```

### Run:
```cmd
java -cp "bin;lib/*" main.main
```

### Clean Build:
```cmd
rmdir /s /q bin
mkdir bin
javac -encoding UTF-8 -cp "lib/*" -d bin -sourcepath src src/main/main.java src/com/itc/studentmgmt/security/*.java src/com/itc/studentmgmt/service/*.java src/com/itc/studentmgmt/ui/*.java src/com/itc/studentmgmt/model/*.java src/com/itc/studentmgmt/database/*.java src/com/itc/studentmgmt/dao/*.java
```

---

## 🎉 You're All Set!

The system is now running with:
- ✅ Modern UI with sidebar navigation
- ✅ Role-based dashboards (Student/Teacher/Admin)
- ✅ Secure password hashing
- ✅ Auto-created database
- ✅ Ready for 2FA (optional)
- ✅ Audit logging
- ✅ Multi-user support

**Enjoy your new Student Management System!** 🚀

---

**Need Help?** Check the documentation files or the console output for error messages.

**Found a Bug?** Note the error message and check TROUBLESHOOTING section above.

**Want to Customize?** See [CONFIGURATION_GUIDE.md](CONFIGURATION_GUIDE.md) for all settings.
