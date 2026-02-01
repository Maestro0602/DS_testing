package com.itc.studentmgmt.dao;

import com.itc.studentmgmt.database.DatabaseConnection;
import com.itc.studentmgmt.model.Student;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;

public class StudentDAO {
    
    public boolean addStudent(Student student) {
        String sql = "INSERT INTO students (student_id, name, email, major) VALUES (?, ?, ?, ?)";
        try (Connection conn = DatabaseConnection.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setString(1, student.getStudentId());
            pstmt.setString(2, student.getName());
            pstmt.setString(3, student.getEmail());
            pstmt.setString(4, student.getMajor());
            
            return pstmt.executeUpdate() > 0;
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }
    
    public Student getStudent(String studentId) {
        String sql = "SELECT * FROM students WHERE student_id = ?";
        try (Connection conn = DatabaseConnection.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setString(1, studentId);
            ResultSet rs = pstmt.executeQuery();
            
            if (rs.next()) {
                Student student = new Student(
                    rs.getString("student_id"),
                    rs.getString("name"),
                    rs.getString("email"),
                    rs.getString("major")
                );
                student.setPhone(rs.getString("phone"));
                student.setAddress(rs.getString("address"));
                student.setDateOfBirth(rs.getDate("date_of_birth"));
                student.setGpa(rs.getDouble("gpa"));
                student.setStatus(rs.getString("status"));
                return student;
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return null;
    }
    
    public List<Student> getAllStudents() {
        List<Student> students = new ArrayList<>();
        String sql = "SELECT * FROM students ORDER BY student_id";
        
        try (Connection conn = DatabaseConnection.getInstance().getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {
            
            while (rs.next()) {
                Student student = new Student(
                    rs.getString("student_id"),
                    rs.getString("name"),
                    rs.getString("email"),
                    rs.getString("major")
                );
                student.setPhone(rs.getString("phone"));
                student.setAddress(rs.getString("address"));
                student.setDateOfBirth(rs.getDate("date_of_birth"));
                student.setGpa(rs.getDouble("gpa"));
                student.setStatus(rs.getString("status"));
                students.add(student);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return students;
    }
    
    public boolean updateStudent(Student student) {
        String sql = "UPDATE students SET name = ?, email = ?, major = ? WHERE student_id = ?";
        try (Connection conn = DatabaseConnection.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setString(1, student.getName());
            pstmt.setString(2, student.getEmail());
            pstmt.setString(3, student.getMajor());
            pstmt.setString(4, student.getStudentId());
            
            return pstmt.executeUpdate() > 0;
        } catch (SQLException e) {
            e.printStackTrace();
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
        // First get the student_id from the username (assuming username = student_id)
        // Or we need to add username column to students table
        return getStudent(username);
    }
    
    public List<Student> searchStudents(String keyword) {
        List<Student> students = new ArrayList<>();
        String sql = "SELECT * FROM students WHERE student_id LIKE ? OR name LIKE ? OR email LIKE ?";
        
        try (Connection conn = DatabaseConnection.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            String search = "%" + keyword + "%";
            pstmt.setString(1, search);
            pstmt.setString(2, search);
            pstmt.setString(3, search);
            
            ResultSet rs = pstmt.executeQuery();
            while (rs.next()) {
                Student student = new Student(
                    rs.getString("student_id"),
                    rs.getString("name"),
                    rs.getString("email"),
                    rs.getString("major")
                );
                student.setPhone(rs.getString("phone"));
                student.setAddress(rs.getString("address"));
                student.setDateOfBirth(rs.getDate("date_of_birth"));
                student.setGpa(rs.getDouble("gpa"));
                student.setStatus(rs.getString("status"));
                students.add(student);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return students;
    }
}