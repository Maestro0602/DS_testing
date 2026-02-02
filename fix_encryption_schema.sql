-- Fix database schema for encrypted fields
USE stu_manage;

-- Increase column sizes for encrypted data
ALTER TABLE students MODIFY COLUMN phone VARCHAR(500);
ALTER TABLE students MODIFY COLUMN address VARCHAR(1000);

-- Show updated schema
DESCRIBE students;

-- Show success message
SELECT 'Database schema updated successfully! Phone and Address columns can now store encrypted data.' AS Status;
