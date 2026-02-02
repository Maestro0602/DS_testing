package com.itc.studentmgmt.dao;

import com.itc.studentmgmt.database.DatabaseConnection;
import com.itc.studentmgmt.model.Student;
import com.itc.studentmgmt.security.SensitiveDataProtector;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;

/**
 * 🔐 SECURE STUDENT DATA ACCESS OBJECT
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * Handles all student CRUD operations with:
 * - Encrypted sensitive fields (phone, address, email)
 * - SQL injection prevention via PreparedStatement
 * - Duplicate checking before insert
 * 
 * @author Security Team
 * @version 2.1.0 - With Encryption & Better Error Handling
 */
public class StudentDAO {
    
    // Error codes for specific failure reasons
    public static final int SUCCESS = 0;
    public static final int ERROR_DUPLICATE_ID = 1;
    public static final int ERROR_DUPLICATE_EMAIL = 2;
    public static final int ERROR_DATABASE = 3;
    public static final int ERROR_ENCRYPTION = 4;
    
    // Store last error for detailed feedback
    private int lastErrorCode = SUCCESS;
    private String lastErrorMessage = "";
    
    /**
     * Get the last error code from the most recent operation.
     */
    public int getLastErrorCode() {
        return lastErrorCode;
    }
    
    /**
     * Get the last error message from the most recent operation.
     */
    public String getLastErrorMessage() {
        return lastErrorMessage;
    }
    
    /**
     * Check if a student ID already exists in the database.
     */
    public boolean studentIdExists(String studentId) {
        String sql = "SELECT COUNT(*) FROM students WHERE student_id = ?";
        try (Connection conn = DatabaseConnection.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, studentId);
            ResultSet rs = pstmt.executeQuery();
            if (rs.next()) {
                return rs.getInt(1) > 0;
            }
        } catch (SQLException e) {
            System.err.println("❌ Error checking student ID: " + e.getMessage());
        }
        return false;
    }
    
    /**
     * Check if an email already exists in the database.
     */
    public boolean emailExists(String email) {
        String sql = "SELECT COUNT(*) FROM students WHERE email = ?";
        try (Connection conn = DatabaseConnection.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, email);
            ResultSet rs = pstmt.executeQuery();
            if (rs.next()) {
                return rs.getInt(1) > 0;
            }
        } catch (SQLException e) {
            System.err.println("❌ Error checking email: " + e.getMessage());
        }
        return false;
    }
    
    /**
     * Check if an email already exists for a different student (used during update).
     */
    public boolean emailExistsForOtherStudent(String email, String studentId) {
        String sql = "SELECT COUNT(*) FROM students WHERE email = ? AND student_id != ?";
        try (Connection conn = DatabaseConnection.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, email);
            pstmt.setString(2, studentId);
            ResultSet rs = pstmt.executeQuery();
            if (rs.next()) {
                return rs.getInt(1) > 0;
            }
        } catch (SQLException e) {
            System.err.println("❌ Error checking email: " + e.getMessage());
        }
        return false;
    }
    
    /**
     * Add a new student with encrypted sensitive data.
     * Checks for duplicates before inserting.
     */
    public boolean addStudent(Student student) {
        // Reset error state
        lastErrorCode = SUCCESS;
        lastErrorMessage = "";
        
        // Check for duplicate student ID
        if (studentIdExists(student.getStudentId())) {
            lastErrorCode = ERROR_DUPLICATE_ID;
            lastErrorMessage = "Student ID '" + student.getStudentId() + "' already exists!";
            System.err.println("❌ " + lastErrorMessage);
            return false;
        }
        
        // Check for duplicate email
        if (emailExists(student.getEmail())) {
            lastErrorCode = ERROR_DUPLICATE_EMAIL;
            lastErrorMessage = "Email '" + student.getEmail() + "' is already registered!";
            System.err.println("❌ " + lastErrorMessage);
            return false;
        }
        
        String sql = "INSERT INTO students (student_id, name, email, major, phone, address, date_of_birth, gpa, status) " +
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
        try (Connection conn = DatabaseConnection.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setString(1, student.getStudentId());
            pstmt.setString(2, student.getName());
            pstmt.setString(3, student.getEmail());
            pstmt.setString(4, student.getMajor());
            // Encrypt sensitive fields
            pstmt.setString(5, encryptIfNotNull(student.getPhone()));
            pstmt.setString(6, encryptIfNotNull(student.getAddress()));
            pstmt.setDate(7, student.getDateOfBirth());
            pstmt.setDouble(8, student.getGpa());
            pstmt.setString(9, student.getStatus() != null ? student.getStatus() : "ACTIVE");
            
            boolean result = pstmt.executeUpdate() > 0;
            if (result) {
                System.out.println("✅ Student added: " + student.getStudentId() + " (sensitive data encrypted)");
            }
            return result;
        } catch (SQLException e) {
            lastErrorCode = ERROR_DATABASE;
            // Check for specific MySQL error codes
            if (e.getErrorCode() == 1062) { // Duplicate entry
                if (e.getMessage().contains("student_id")) {
                    lastErrorCode = ERROR_DUPLICATE_ID;
                    lastErrorMessage = "Student ID already exists!";
                } else if (e.getMessage().contains("email")) {
                    lastErrorCode = ERROR_DUPLICATE_EMAIL;
                    lastErrorMessage = "Email address already registered!";
                } else {
                    lastErrorMessage = "Duplicate entry detected!";
                }
            } else {
                lastErrorMessage = "Database error: " + e.getMessage();
            }
            System.err.println("❌ Failed to add student: " + lastErrorMessage);
            return false;
        }
    }
    
    /**
     * Get a single student by ID (decrypts sensitive fields)
     */
    public Student getStudent(String studentId) {
        String sql = "SELECT * FROM students WHERE student_id = ?";
        try (Connection conn = DatabaseConnection.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setString(1, studentId);
            ResultSet rs = pstmt.executeQuery();
            
            if (rs.next()) {
                return mapResultSetToStudent(rs);
            }
        } catch (SQLException e) {
            System.err.println("❌ Failed to get student: " + e.getMessage());
        }
        return null;
    }
    
    /**
     * Get all students (decrypts sensitive fields)
     */
    public List<Student> getAllStudents() {
        List<Student> students = new ArrayList<>();
        String sql = "SELECT * FROM students ORDER BY student_id";
        
        try (Connection conn = DatabaseConnection.getInstance().getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {
            
            while (rs.next()) {
                students.add(mapResultSetToStudent(rs));
            }
        } catch (SQLException e) {
            System.err.println("❌ Failed to get all students: " + e.getMessage());
        }
        return students;
    }
    
    /**
     * Update student with encrypted sensitive data.
     * Checks for duplicate email before updating.
     */
    public boolean updateStudent(Student student) {
        // Reset error state
        lastErrorCode = SUCCESS;
        lastErrorMessage = "";
        
        // Check if email is being changed to one that already exists
        if (emailExistsForOtherStudent(student.getEmail(), student.getStudentId())) {
            lastErrorCode = ERROR_DUPLICATE_EMAIL;
            lastErrorMessage = "Email '" + student.getEmail() + "' is already registered to another student!";
            System.err.println("❌ " + lastErrorMessage);
            return false;
        }
        
        String sql = "UPDATE students SET name = ?, email = ?, major = ?, phone = ?, address = ?, " +
                    "date_of_birth = ?, gpa = ?, status = ? WHERE student_id = ?";
        try (Connection conn = DatabaseConnection.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setString(1, student.getName());
            pstmt.setString(2, student.getEmail());
            pstmt.setString(3, student.getMajor());
            pstmt.setString(4, encryptIfNotNull(student.getPhone()));
            pstmt.setString(5, encryptIfNotNull(student.getAddress()));
            pstmt.setDate(6, student.getDateOfBirth());
            pstmt.setDouble(7, student.getGpa());
            pstmt.setString(8, student.getStatus());
            pstmt.setString(9, student.getStudentId());
            
            boolean result = pstmt.executeUpdate() > 0;
            if (result) {
                System.out.println("✅ Student updated: " + student.getStudentId());
            }
            return result;
        } catch (SQLException e) {
            lastErrorCode = ERROR_DATABASE;
            if (e.getErrorCode() == 1062 && e.getMessage().contains("email")) {
                lastErrorCode = ERROR_DUPLICATE_EMAIL;
                lastErrorMessage = "Email address already registered to another student!";
            } else {
                lastErrorMessage = "Database error: " + e.getMessage();
            }
            System.err.println("❌ Failed to update student: " + lastErrorMessage);
            return false;
        }
    }
    
    public boolean deleteStudent(String studentId) {
        String sql = "DELETE FROM students WHERE student_id = ?";
        try (Connection conn = DatabaseConnection.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setString(1, studentId);
            return pstmt.executeUpdate() > 0;
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }
    
    public Student getStudentByUsername(String username) {
        return getStudent(username);
    }
    
    public List<Student> searchStudents(String keyword) {
        List<Student> students = new ArrayList<>();
        String sql = "SELECT * FROM students WHERE student_id LIKE ? OR name LIKE ? OR email LIKE ? OR major LIKE ?";
        
        try (Connection conn = DatabaseConnection.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            String search = "%" + keyword + "%";
            pstmt.setString(1, search);
            pstmt.setString(2, search);
            pstmt.setString(3, search);
            pstmt.setString(4, search);
            
            ResultSet rs = pstmt.executeQuery();
            while (rs.next()) {
                students.add(mapResultSetToStudent(rs));
            }
        } catch (SQLException e) {
            System.err.println("❌ Failed to search students: " + e.getMessage());
        }
        return students;
    }
    
    /**
     * Update student GPA
     */
    public boolean updateStudentGpa(String studentId, double gpa) {
        String sql = "UPDATE students SET gpa = ? WHERE student_id = ?";
        try (Connection conn = DatabaseConnection.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setDouble(1, gpa);
            pstmt.setString(2, studentId);
            return pstmt.executeUpdate() > 0;
        } catch (SQLException e) {
            System.err.println("❌ Failed to update GPA: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * Count total students
     */
    public int countStudents() {
        String sql = "SELECT COUNT(*) FROM students";
        try (Connection conn = DatabaseConnection.getInstance().getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {
            if (rs.next()) return rs.getInt(1);
        } catch (SQLException e) {
            System.err.println("❌ Failed to count students: " + e.getMessage());
        }
        return 0;
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // HELPER METHODS - ENCRYPTION/DECRYPTION
    // ═══════════════════════════════════════════════════════════════════════════
    
    private Student mapResultSetToStudent(ResultSet rs) throws SQLException {
        Student student = new Student(
            rs.getString("student_id"),
            rs.getString("name"),
            rs.getString("email"),
            rs.getString("major")
        );
        // Decrypt sensitive fields
        student.setPhone(decryptIfEncrypted(rs.getString("phone")));
        student.setAddress(decryptIfEncrypted(rs.getString("address")));
        student.setDateOfBirth(rs.getDate("date_of_birth"));
        student.setGpa(rs.getDouble("gpa"));
        student.setStatus(rs.getString("status"));
        return student;
    }
    
    private String encryptIfNotNull(String value) {
        if (value == null || value.isEmpty()) return value;
        try {
            return SensitiveDataProtector.encryptField(value);
        } catch (Exception e) {
            System.err.println("⚠️ Encryption failed: " + e.getMessage());
            return value;
        }
    }
    
    private String decryptIfEncrypted(String value) {
        if (value == null || value.isEmpty()) return value;
        try {
            return SensitiveDataProtector.decryptField(value);
        } catch (Exception e) {
            return value; // Return as-is if not encrypted
        }
    }
}