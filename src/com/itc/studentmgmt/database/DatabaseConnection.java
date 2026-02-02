package com.itc.studentmgmt.database;

import com.itc.studentmgmt.security.PasswordSecurityUtil;
import java.sql.*;

/**
 * 🔐 SIMPLIFIED DATABASE CONNECTION
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * Auto-creates database and tables if they don't exist.
 * Simple configuration - just update the credentials below.
 * Uses plain JDBC for maximum compatibility.
 * 
 * ╔═══════════════════════════════════════════════════════════════════════════╗
 * ║  📝 CONFIGURATION INSTRUCTIONS:                                           ║
 * ║                                                                           ║
 * ║  1. Update DB_USERNAME and DB_PASSWORD below                              ║
 * ║  2. Make sure MySQL is running on localhost:3306                          ║
 * ║  3. The database and tables will be created automatically!                ║
 * ╚═══════════════════════════════════════════════════════════════════════════╝
 * 
 * @author Security Team
 * @version 2.0.0 - Simplified Edition
 */
public class DatabaseConnection {
    
    // ═══════════════════════════════════════════════════════════════════════════
    // 📝 CONFIGURE YOUR DATABASE CREDENTIALS HERE
    // ═══════════════════════════════════════════════════════════════════════════
    
    private static final String DB_HOST = "localhost";
    private static final String DB_PORT = "3306";
    private static final String DB_NAME = "stu_manage";
    
    // ⚠️ CHANGE THESE TO YOUR MySQL CREDENTIALS
    private static final String DB_USERNAME = "root";
    private static final String DB_PASSWORD = "MRHENGXD123";
    
    // ═══════════════════════════════════════════════════════════════════════════
    
    private static volatile DatabaseConnection instance;
    private String jdbcUrl;
    
    /**
     * Private constructor - establishes connection and creates database/tables
     */
    private DatabaseConnection() throws SQLException {
        try {
            // Load MySQL driver
            Class.forName("com.mysql.cj.jdbc.Driver");
            
            // First, create the database if it doesn't exist
            createDatabaseIfNotExists();
            
            // Set the JDBC URL for future connections
            this.jdbcUrl = String.format(
                "jdbc:mysql://%s:%s/%s?useSSL=false&allowPublicKeyRetrieval=true&useUnicode=true&characterEncoding=UTF-8",
                DB_HOST, DB_PORT, DB_NAME
            );
            
            // Create tables if they don't exist
            createTablesIfNotExist();
            
            // Create default admin user if no users exist
            createDefaultUsers();
            
            System.out.println("✅ Database connection established successfully!");
            
        } catch (ClassNotFoundException e) {
            throw new SQLException("MySQL JDBC Driver not found: " + e.getMessage(), e);
        } catch (Exception e) {
            throw new SQLException("Failed to establish database connection: " + e.getMessage(), e);
        }
    }
    
    /**
     * Create the database if it doesn't exist
     */
    private void createDatabaseIfNotExists() throws SQLException {
        String urlWithoutDb = String.format("jdbc:mysql://%s:%s?useSSL=false&allowPublicKeyRetrieval=true", 
            DB_HOST, DB_PORT);
        
        try (Connection conn = DriverManager.getConnection(urlWithoutDb, DB_USERNAME, DB_PASSWORD)) {
            Statement stmt = conn.createStatement();
            stmt.executeUpdate("CREATE DATABASE IF NOT EXISTS " + DB_NAME + 
                " CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
            System.out.println("✅ Database '" + DB_NAME + "' is ready");
        }
    }
    
    /**
     * Create all required tables
     */
    private void createTablesIfNotExist() throws SQLException {
        try (Connection conn = getConnection()) {
            Statement stmt = conn.createStatement();
            
            // Create users table
            String createUsersTable = 
                "CREATE TABLE IF NOT EXISTS users (" +
                "user_id BIGINT AUTO_INCREMENT PRIMARY KEY," +
                "username VARCHAR(50) UNIQUE NOT NULL," +
                "password_hash TEXT NOT NULL," +
                "role VARCHAR(20) NOT NULL DEFAULT 'STUDENT'," +
                "failed_login_attempts INT DEFAULT 0," +
                "account_locked BOOLEAN DEFAULT FALSE," +
                "lockout_until TIMESTAMP NULL," +
                "last_login TIMESTAMP NULL," +
                "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP," +
                "updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP," +
                "INDEX idx_username (username)" +
                ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci";
            stmt.executeUpdate(createUsersTable);
            System.out.println("✅ Users table ready");
            
            // Create students table
            // Note: phone and address use TEXT to accommodate encrypted data (AES + Base64 = long strings)
            String createStudentsTable = 
                "CREATE TABLE IF NOT EXISTS students (" +
                "id BIGINT AUTO_INCREMENT PRIMARY KEY," +
                "student_id VARCHAR(20) UNIQUE NOT NULL," +
                "name VARCHAR(100) NOT NULL," +
                "email VARCHAR(100) UNIQUE NOT NULL," +
                "major VARCHAR(50) NOT NULL," +
                "phone TEXT," +
                "address TEXT," +
                "date_of_birth DATE," +
                "enrollment_date DATE DEFAULT (CURRENT_DATE)," +
                "gpa DECIMAL(3,2) DEFAULT 0.00," +
                "status VARCHAR(20) DEFAULT 'ACTIVE'," +
                "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP," +
                "updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP," +
                "INDEX idx_student_id (student_id)," +
                "INDEX idx_email (email)," +
                "INDEX idx_major (major)" +
                ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci";
            stmt.executeUpdate(createStudentsTable);
            System.out.println("✅ Students table ready");
            
            // Alter phone column to TEXT if it exists as VARCHAR (for existing databases)
            try {
                stmt.executeUpdate("ALTER TABLE students MODIFY COLUMN phone TEXT");
                System.out.println("✅ Phone column updated to TEXT for encryption support");
            } catch (SQLException e) {
                // Column might already be TEXT or table just created - ignore
            }
            
            // Create audit_logs table for security logging
            String createAuditTable = 
                "CREATE TABLE IF NOT EXISTS audit_logs (" +
                "id BIGINT AUTO_INCREMENT PRIMARY KEY," +
                "event_type VARCHAR(50) NOT NULL," +
                "username VARCHAR(50)," +
                "ip_address VARCHAR(45)," +
                "action VARCHAR(100)," +
                "details TEXT," +
                "timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP," +
                "INDEX idx_event_type (event_type)," +
                "INDEX idx_username (username)," +
                "INDEX idx_timestamp (timestamp)" +
                ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci";
            stmt.executeUpdate(createAuditTable);
            System.out.println("✅ Audit logs table ready");
            
            // Create announcements table
            String createAnnouncementsTable = 
                "CREATE TABLE IF NOT EXISTS announcements (" +
                "id BIGINT AUTO_INCREMENT PRIMARY KEY," +
                "title VARCHAR(200) NOT NULL," +
                "content TEXT NOT NULL," +
                "created_by VARCHAR(50) NOT NULL," +
                "target_role VARCHAR(20) NOT NULL DEFAULT 'ALL'," +
                "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP," +
                "INDEX idx_created_at (created_at)," +
                "INDEX idx_target_role (target_role)" +
                ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci";
            stmt.executeUpdate(createAnnouncementsTable);
            System.out.println("✅ Announcements table ready");
            
            // Create schedules table
            String createSchedulesTable = 
                "CREATE TABLE IF NOT EXISTS schedules (" +
                "id BIGINT AUTO_INCREMENT PRIMARY KEY," +
                "course_code VARCHAR(20) NOT NULL," +
                "course_name VARCHAR(100) NOT NULL," +
                "teacher_username VARCHAR(50) NOT NULL," +
                "day_of_week VARCHAR(20) NOT NULL," +
                "start_time TIME NOT NULL," +
                "end_time TIME NOT NULL," +
                "room VARCHAR(50)," +
                "semester VARCHAR(20) NOT NULL," +
                "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP," +
                "INDEX idx_teacher (teacher_username)," +
                "INDEX idx_day (day_of_week)," +
                "INDEX idx_semester (semester)" +
                ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci";
            stmt.executeUpdate(createSchedulesTable);
            System.out.println("✅ Schedules table ready");
            
            // Create student_enrollments table with proper foreign key handling
            // First, check if table exists and drop it to recreate with correct constraints
            try {
                // Check if table exists
                DatabaseMetaData meta = conn.getMetaData();
                ResultSet rs = meta.getTables(null, null, "student_enrollments", new String[]{"TABLE"});
                if (rs.next()) {
                    // Table exists, drop it
                    stmt.executeUpdate("SET FOREIGN_KEY_CHECKS = 0");
                    stmt.executeUpdate("DROP TABLE IF EXISTS student_enrollments");
                    stmt.executeUpdate("SET FOREIGN_KEY_CHECKS = 1");
                    System.out.println("🔄 Dropped old student_enrollments table");
                }
            } catch (SQLException e) {
                System.out.println("⚠️ Warning while dropping table: " + e.getMessage());
            }
            
            String createEnrollmentsTable = 
                "CREATE TABLE student_enrollments (" +
                "id BIGINT AUTO_INCREMENT PRIMARY KEY," +
                "student_id VARCHAR(20) NOT NULL," +
                "schedule_id BIGINT NOT NULL," +
                "grade VARCHAR(5)," +
                "status VARCHAR(20) DEFAULT 'ENROLLED'," +
                "enrolled_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP," +
                "FOREIGN KEY (student_id) REFERENCES students(student_id) ON DELETE CASCADE," +
                "FOREIGN KEY (schedule_id) REFERENCES schedules(id) ON DELETE CASCADE," +
                "UNIQUE KEY unique_enrollment (student_id, schedule_id)," +
                "INDEX idx_student (student_id)," +
                "INDEX idx_schedule (schedule_id)," +
                "INDEX idx_status (status)" +
                ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci";
            stmt.executeUpdate(createEnrollmentsTable);
            System.out.println("✅ Student enrollments table ready");
        }
    }
    
    /**
     * Create default admin and teacher users if no users exist
     */
    private void createDefaultUsers() throws SQLException {
        try (Connection conn = DriverManager.getConnection(jdbcUrl, DB_USERNAME, DB_PASSWORD)) {
            // Check if users exist
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery("SELECT COUNT(*) FROM users");
            rs.next();
            int userCount = rs.getInt(1);
            
            if (userCount == 0) {
                System.out.println("📝 Creating default users...");
                
                // Hash passwords using imported utility
                String adminHash = PasswordSecurityUtil.hashPassword("admin123");
                String teacherHash = PasswordSecurityUtil.hashPassword("teacher123");
                String studentHash = PasswordSecurityUtil.hashPassword("student123");
                
                PreparedStatement pstmt = conn.prepareStatement(
                    "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)"
                );
                
                // Create admin
                pstmt.setString(1, "admin");
                pstmt.setString(2, adminHash);
                pstmt.setString(3, "ADMIN");
                pstmt.executeUpdate();
                
                // Create teacher
                pstmt.setString(1, "teacher1");
                pstmt.setString(2, teacherHash);
                pstmt.setString(3, "TEACHER");
                pstmt.executeUpdate();
                
                // Create student
                pstmt.setString(1, "student1");
                pstmt.setString(2, studentHash);
                pstmt.setString(3, "STUDENT");
                pstmt.executeUpdate();
                
                System.out.println("✅ Default users created:");
                System.out.println("   👑 Admin: admin / admin123");
                System.out.println("   👨‍🏫 Teacher: teacher1 / teacher123");
                System.out.println("   👨‍🎓 Student: student1 / student123");
                
                pstmt.close();
            }
        }
    }
    
    /**
     * Get singleton instance
     */
    public static DatabaseConnection getInstance() throws SQLException {
        if (instance == null) {
            synchronized (DatabaseConnection.class) {
                if (instance == null) {
                    instance = new DatabaseConnection();
                }
            }
        }
        return instance;
    }
    
    /**
     * Get a connection from the pool
     */
    public Connection getConnection() throws SQLException {
        return DriverManager.getConnection(jdbcUrl, DB_USERNAME, DB_PASSWORD);
    }
    
    /**
     * Close the connection pool
     */
    public void closeConnectionPool() throws SQLException {
        System.out.println("✅ Database connection closed");
    }
    
    /**
     * Get connection pool statistics
     */
    public String getPoolStats() {
        return "Using direct JDBC connections";
    }
    
    /**
     * Reset database (for testing)
     */
    public static void resetDatabase() throws SQLException {
        try (Connection conn = getInstance().getConnection()) {
            Statement stmt = conn.createStatement();
            stmt.executeUpdate("DROP TABLE IF EXISTS audit_logs");
            stmt.executeUpdate("DROP TABLE IF EXISTS students");
            stmt.executeUpdate("DROP TABLE IF EXISTS users");
            System.out.println("⚠️ Database tables dropped");
        }
        
        // Recreate tables
        instance = null;
        getInstance();
    }
}
