package com.itc.studentmgmt.dao;

import com.itc.studentmgmt.model.StudentEnrollment;
import com.itc.studentmgmt.database.DatabaseConnection;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;

public class StudentEnrollmentDAO {
    
    public boolean enrollStudent(String studentId, int scheduleId) {
        String sql = "INSERT INTO student_enrollments (student_id, schedule_id, status) VALUES (?, ?, 'ENROLLED')";
        try (Connection conn = DatabaseConnection.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setString(1, studentId);
            pstmt.setInt(2, scheduleId);
            
            return pstmt.executeUpdate() > 0;
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }
    
    public List<StudentEnrollment> getEnrollmentsByStudent(String studentId) {
        List<StudentEnrollment> enrollments = new ArrayList<>();
        String sql = "SELECT * FROM student_enrollments WHERE student_id = ?";
        
        try (Connection conn = DatabaseConnection.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setString(1, studentId);
            ResultSet rs = pstmt.executeQuery();
            
            while (rs.next()) {
                enrollments.add(new StudentEnrollment(
                    rs.getInt("id"),
                    rs.getString("student_id"),
                    rs.getInt("schedule_id"),
                    rs.getString("grade"),
                    rs.getString("status")
                ));
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return enrollments;
    }
    
    public boolean updateGrade(int enrollmentId, String grade) {
        String sql = "UPDATE student_enrollments SET grade = ? WHERE id = ?";
        try (Connection conn = DatabaseConnection.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setString(1, grade);
            pstmt.setInt(2, enrollmentId);
            
            return pstmt.executeUpdate() > 0;
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }
    
    public boolean dropEnrollment(int enrollmentId) {
        String sql = "UPDATE student_enrollments SET status = 'DROPPED' WHERE id = ?";
        try (Connection conn = DatabaseConnection.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setInt(1, enrollmentId);
            return pstmt.executeUpdate() > 0;
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }
}
