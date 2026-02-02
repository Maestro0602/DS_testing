-- Fix Database Foreign Key Issue
-- Run this in MySQL command line or MySQL Workbench

USE stu_manage;

-- Disable foreign key checks temporarily
SET FOREIGN_KEY_CHECKS = 0;

-- Drop the problematic table
DROP TABLE IF EXISTS student_enrollments;

-- Re-enable foreign key checks
SET FOREIGN_KEY_CHECKS = 1;

-- Recreate the table with proper constraints
CREATE TABLE student_enrollments (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    student_id VARCHAR(20) NOT NULL,
    schedule_id BIGINT NOT NULL,
    grade VARCHAR(5),
    status VARCHAR(20) DEFAULT 'ENROLLED',
    enrolled_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (student_id) REFERENCES students(student_id) ON DELETE CASCADE,
    FOREIGN KEY (schedule_id) REFERENCES schedules(id) ON DELETE CASCADE,
    UNIQUE KEY unique_enrollment (student_id, schedule_id),
    INDEX idx_student (student_id),
    INDEX idx_schedule (schedule_id),
    INDEX idx_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

SELECT 'Database fixed successfully!' AS status;
