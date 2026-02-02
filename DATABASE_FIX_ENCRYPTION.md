# 🔧 DATABASE SCHEMA FIX FOR ENCRYPTION

## Problem
The encrypted phone and address fields are too long for the current VARCHAR columns.

## Solution
Increase the column size to accommodate encrypted data.

## SQL Commands to Fix

```sql
-- Connect to MySQL
mysql -u root -p

-- Use the database
USE stu_manage;

-- Check current column sizes
DESCRIBE students;

-- Increase phone and address column sizes to store encrypted data
-- Encrypted data with ENC$v1$ prefix + Base64 encoding requires ~200-300 characters
ALTER TABLE students MODIFY COLUMN phone VARCHAR(500);
ALTER TABLE students MODIFY COLUMN address VARCHAR(1000);

-- Verify the changes
DESCRIBE students;

-- Check if there are any existing records
SELECT COUNT(*) FROM students;

-- If you want to re-encrypt existing plain text data, you'll need to:
-- 1. Backup the database first
-- 2. Let the application re-save each student (it will encrypt on save)
```

## PowerShell Command (One-liner)

```powershell
# Run SQL fix directly from PowerShell
mysql -u root -p -e "USE stu_manage; ALTER TABLE students MODIFY COLUMN phone VARCHAR(500); ALTER TABLE students MODIFY COLUMN address VARCHAR(1000); DESCRIBE students;"
```

## After Fixing

Restart the application:
```powershell
cd d:\DataSecurity
java -cp "bin;lib/*" main.main
```

Then try adding a student again with phone and address data.
