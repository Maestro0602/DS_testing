package com.itc.studentmgmt.model;

/**
 * Enum representing different user roles in the system
 * Used for access control and authorization
 */
public enum UserRole {
    STUDENT,    // Students can only view their own data
    TEACHER,    // Teachers can view and manage student records
    ADMIN       // Admins have full system access
}