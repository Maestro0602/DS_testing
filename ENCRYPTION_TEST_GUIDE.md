# 🔐 ENCRYPTION VERIFICATION GUIDE

## ✅ Changes Completed

### 1. **StudentDAO.java** - Encrypted Fields
- ✅ Phone numbers encrypted with AES-256
- ✅ Addresses encrypted with AES-256  
- ✅ All fields now saved (student_id, name, email, major, phone, address, dob, gpa, status)
- ✅ Automatic encryption on INSERT/UPDATE
- ✅ Automatic decryption on SELECT

### 2. **MainFrame.java** - Enhanced Student Table
- ✅ Added columns: Phone, GPA, Status
- ✅ Enhanced Add Student dialog with all fields
- ✅ Enhanced Edit Student dialog with all fields
- ✅ Visual indicator 🔒 for encrypted fields

### 3. **TeacherPanel.java** - NEW Teacher GUI
- ✅ Manage class schedules
- ✅ Create announcements
- ✅ View enrolled students
- ✅ Tabbed interface for easy navigation

### 4. **Schedule.java Model** - Convenience Methods
- ✅ Added setStartTime(String) and setEndTime(String) for HH:MM format

---

## 🧪 HOW TO TEST ENCRYPTION

### Step 1: Run the Application
```powershell
cd d:\DataSecurity
java -cp "bin;lib/*" main.main
```

### Step 2: Login
- **Username:** `admin` or your teacher/student account
- **Password:** Your password
- **2FA Code:** Check your authenticator app

### Step 3: Add a Student with Sensitive Data
1. Click **➕ Add Student** button
2. Fill in the form:
   - **Student ID:** `TEST001`
   - **Name:** `Test Student`
   - **Email:** `test@itc.edu.kh`
   - **Major:** `Computer Science`
   - **Phone 🔒:** `+855 12 345 678` ← This will be encrypted
   - **Address 🔒:** `123 Main St, Phnom Penh` ← This will be encrypted
   - **GPA:** `3.85`
   - **Status:** `ACTIVE`
3. Click **Save Student**
4. You should see: "Student added successfully! (Sensitive data encrypted)"

### Step 4: Verify in the UI
- The student table will show the phone and address **decrypted** (readable)
- This proves the decrypt function works

### Step 5: Check Database (Verify Encryption)
```powershell
# Connect to MySQL
mysql -u root -p

# Use the database
USE stu_manage;

# Check the encrypted data in the database
SELECT student_id, name, phone, address FROM students WHERE student_id = 'TEST001';
```

**Expected Result:**
- `phone` should look like: `ENC$v1$abc123def456...` (encrypted)
- `address` should look like: `ENC$v1$xyz789ghi012...` (encrypted)
- If you see the actual phone number/address in plaintext, encryption failed!

---

## 🔍 SQL QUERIES TO VERIFY ENCRYPTION

### 1. Check if Phone is Encrypted
```sql
SELECT 
    student_id, 
    name, 
    phone,
    CASE 
        WHEN phone LIKE 'ENC$v1$%' THEN '✅ ENCRYPTED'
        ELSE '❌ PLAIN TEXT'
    END AS phone_status
FROM students
WHERE phone IS NOT NULL;
```

### 2. Check if Address is Encrypted
```sql
SELECT 
    student_id, 
    name, 
    address,
    CASE 
        WHEN address LIKE 'ENC$v1$%' THEN '✅ ENCRYPTED'
        ELSE '❌ PLAIN TEXT'
    END AS address_status
FROM students
WHERE address IS NOT NULL;
```

### 3. View All Students with Encryption Status
```sql
SELECT 
    student_id,
    name,
    email,
    major,
    CASE WHEN phone LIKE 'ENC$v1$%' THEN '🔒 ENCRYPTED' ELSE phone END AS phone_display,
    CASE WHEN address LIKE 'ENC$v1$%' THEN '🔒 ENCRYPTED' ELSE address END AS address_display,
    gpa,
    status
FROM students;
```

### 4. Count Encrypted vs Plain Text Records
```sql
SELECT 
    COUNT(*) AS total_students,
    SUM(CASE WHEN phone LIKE 'ENC$v1$%' THEN 1 ELSE 0 END) AS encrypted_phones,
    SUM(CASE WHEN address LIKE 'ENC$v1$%' THEN 1 ELSE 0 END) AS encrypted_addresses
FROM students
WHERE phone IS NOT NULL OR address IS NOT NULL;
```

---

## 📊 TEACHER PANEL TEST

### Step 1: Login as Teacher
- Use a teacher account

### Step 2: Access Teacher Features
- You should see the **TeacherPanel** tab in the main window
- Navigate through:
  - 📅 **My Schedules** - Add/view/delete class schedules
  - 📢 **Announcements** - Create announcements for students
  - 👥 **My Students** - View enrolled students

### Step 3: Add a Schedule
1. Go to "My Schedules" tab
2. Click **➕ Add Schedule**
3. Fill in:
   - Course Code: `CS101`
   - Course Name: `Introduction to Programming`
   - Day: `Monday`
   - Start Time: `09:00`
   - End Time: `10:30`
   - Room: `Room 201`
   - Semester: `2024-2025 Semester 1`
4. Click **Save**

### Step 4: Create an Announcement
1. Go to "Announcements" tab
2. Click **➕ New Announcement**
3. Fill in:
   - Title: `Midterm Exam Schedule`
   - Target Audience: `STUDENT`
   - Content: `The midterm exam will be held on...`
4. Click **📢 Post Announcement**

---

## ✅ VERIFICATION CHECKLIST

- [ ] Compilation successful (no errors)
- [ ] Application starts without errors
- [ ] Login works (with 2FA)
- [ ] Student table shows 7 columns (ID, Name, Email, Major, Phone, GPA, Status)
- [ ] Add Student dialog has all fields including 🔒 indicators
- [ ] Can add student with phone and address
- [ ] Phone shows as `ENC$v1$...` in database (encrypted)
- [ ] Address shows as `ENC$v1$...` in database (encrypted)
- [ ] Phone and address display correctly in UI (decrypted)
- [ ] Edit Student dialog shows decrypted phone/address
- [ ] Can update student information
- [ ] Teacher panel appears for teacher accounts
- [ ] Can add class schedules
- [ ] Can create announcements
- [ ] All security features still work (audit logs, 2FA, etc.)

---

## 🐛 TROUBLESHOOTING

### Issue: "Encryption failed" message
**Solution:** Check that `SensitiveDataProtector.java` is compiled and in the classpath.

### Issue: Phone/address show as `ENC$v1$...` in UI
**Solution:** Decryption failed. Check that the encryption key is consistent.

### Issue: Teacher panel not showing
**Solution:** Make sure you're logged in with a TEACHER or ADMIN account.

### Issue: Cannot connect to database
**Solution:** 
```sql
-- Check database status
mysql -u root -p
SHOW DATABASES;
USE stu_manage;
SHOW TABLES;
```

---

## 🎯 EXPECTED BEHAVIOR

### ✅ CORRECT: Encrypted in Database
```sql
mysql> SELECT phone FROM students WHERE student_id = 'TEST001';
+------------------------------------------------------------------+
| phone                                                            |
+------------------------------------------------------------------+
| ENC$v1$a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6... |
+------------------------------------------------------------------+
```

### ✅ CORRECT: Decrypted in UI
```
+------------+--------------+--------------------+-------------------+------------------+------+--------+
| Student ID | Name         | Email              | Major             | Phone            | GPA  | Status |
+------------+--------------+--------------------+-------------------+------------------+------+--------+
| TEST001    | Test Student | test@itc.edu.kh    | Computer Science  | +855 12 345 678  | 3.85 | ACTIVE |
+------------+--------------+--------------------+-------------------+------------------+------+--------+
```

---

## 📝 SUMMARY

**Encryption System:** 
- Algorithm: AES-256-GCM
- Key Derivation: Argon2id
- Prefix: `ENC$v1$`
- Fields: Phone, Address

**All changes compiled successfully!** ✅

**Security Status:** 🔐 ENHANCED
- Student sensitive data now encrypted at rest
- Phone and address fields protected
- Transparent encryption/decryption in application layer
- Database contains only encrypted values
