import java.sql.*;

/**
 * Quick fix for database foreign key issue
 * Run this to drop and recreate the student_enrollments table
 */
public class FixDatabase {
    public static void main(String[] args) {
        String url = "jdbc:mysql://localhost:3306/stu_manage?useSSL=false&allowPublicKeyRetrieval=true";
        String username = "root";
        String password = "MRHENGXD123";
        
        try (Connection conn = DriverManager.getConnection(url, username, password)) {
            Statement stmt = conn.createStatement();
            
            System.out.println("🔧 Fixing database foreign key issue...\n");
            
            // Disable foreign key checks
            stmt.executeUpdate("SET FOREIGN_KEY_CHECKS = 0");
            System.out.println("✓ Disabled foreign key checks");
            
            // Drop the problematic tables
            stmt.executeUpdate("DROP TABLE IF EXISTS student_enrollments");
            System.out.println("✓ Dropped student_enrollments table");
            
            stmt.executeUpdate("DROP TABLE IF EXISTS students");
            System.out.println("✓ Dropped students table");
            
            stmt.executeUpdate("DROP TABLE IF EXISTS users");
            System.out.println("✓ Dropped users table");
            
            // Re-enable foreign key checks
            stmt.executeUpdate("SET FOREIGN_KEY_CHECKS = 1");
            System.out.println("✓ Re-enabled foreign key checks");
            
            // Recreate users table with proper structure
            String createUsersTable = 
                "CREATE TABLE users (" +
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
            System.out.println("✓ Created users table with proper structure");
            
            // Recreate students table with proper structure (matching DatabaseConnection.java)
            // Using TEXT for phone to support encrypted data
            String createStudentsTable = 
                "CREATE TABLE students (" +
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
            System.out.println("✓ Created students table with TEXT phone column for encryption");
            
            // Check the students table structure
            System.out.println("\n📋 New students table structure:");
            ResultSet rs = stmt.executeQuery("SHOW CREATE TABLE students");
            if (rs.next()) {
                System.out.println(rs.getString(2));
            }
            System.out.println();
            
            // Recreate the table with proper constraints
            String createTable = 
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
            
            stmt.executeUpdate(createTable);
            System.out.println("✓ Created student_enrollments table with proper constraints");
            
            System.out.println("\n✅ Database fixed successfully!");
            System.out.println("You can now run the application.");
            
        } catch (SQLException e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
