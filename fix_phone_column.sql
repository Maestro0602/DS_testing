-- ═══════════════════════════════════════════════════════════════════════════════
-- FIX DATABASE SCHEMA FOR ENCRYPTED FIELDS
-- ═══════════════════════════════════════════════════════════════════════════════
-- This script fixes the database columns to support encrypted data.
-- Encrypted data (AES + Base64) is much longer than plaintext.
-- 
-- Run this if you get errors like:
--   "Data truncation: Data too long for column 'phone' at row 1"
-- ═══════════════════════════════════════════════════════════════════════════════

USE stu_manage;

-- Fix phone column - change from VARCHAR(20) to TEXT
ALTER TABLE students MODIFY COLUMN phone TEXT;

-- Verify the change
DESCRIBE students;

-- Show success message
SELECT 'Database schema fixed successfully! Phone column now supports encrypted data.' AS Status;
