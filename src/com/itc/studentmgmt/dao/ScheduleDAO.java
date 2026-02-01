package com.itc.studentmgmt.dao;

import com.itc.studentmgmt.model.Schedule;
import com.itc.studentmgmt.database.DatabaseConnection;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;

public class ScheduleDAO {
    
    public boolean addSchedule(Schedule schedule) {
        String sql = "INSERT INTO schedules (course_code, course_name, teacher_username, day_of_week, start_time, end_time, room, semester) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
        try (Connection conn = DatabaseConnection.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setString(1, schedule.getCourseCode());
            pstmt.setString(2, schedule.getCourseName());
            pstmt.setString(3, schedule.getTeacherUsername());
            pstmt.setString(4, schedule.getDayOfWeek());
            pstmt.setTime(5, schedule.getStartTime());
            pstmt.setTime(6, schedule.getEndTime());
            pstmt.setString(7, schedule.getRoom());
            pstmt.setString(8, schedule.getSemester());
            
            return pstmt.executeUpdate() > 0;
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }
    
    public List<Schedule> getAllSchedules() {
        List<Schedule> schedules = new ArrayList<>();
        String sql = "SELECT * FROM schedules ORDER BY day_of_week, start_time";
        
        try (Connection conn = DatabaseConnection.getInstance().getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {
            
            while (rs.next()) {
                schedules.add(new Schedule(
                    rs.getInt("id"),
                    rs.getString("course_code"),
                    rs.getString("course_name"),
                    rs.getString("teacher_username"),
                    rs.getString("day_of_week"),
                    rs.getTime("start_time"),
                    rs.getTime("end_time"),
                    rs.getString("room"),
                    rs.getString("semester")
                ));
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return schedules;
    }
    
    public List<Schedule> getSchedulesByTeacher(String teacherUsername) {
        List<Schedule> schedules = new ArrayList<>();
        String sql = "SELECT * FROM schedules WHERE teacher_username = ? ORDER BY day_of_week, start_time";
        
        try (Connection conn = DatabaseConnection.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setString(1, teacherUsername);
            ResultSet rs = pstmt.executeQuery();
            
            while (rs.next()) {
                schedules.add(new Schedule(
                    rs.getInt("id"),
                    rs.getString("course_code"),
                    rs.getString("course_name"),
                    rs.getString("teacher_username"),
                    rs.getString("day_of_week"),
                    rs.getTime("start_time"),
                    rs.getTime("end_time"),
                    rs.getString("room"),
                    rs.getString("semester")
                ));
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return schedules;
    }
    
    public List<Schedule> getSchedulesByStudent(String studentId) {
        List<Schedule> schedules = new ArrayList<>();
        String sql = "SELECT s.* FROM schedules s " +
                    "INNER JOIN student_enrollments se ON s.id = se.schedule_id " +
                    "WHERE se.student_id = ? AND se.status = 'ENROLLED' " +
                    "ORDER BY s.day_of_week, s.start_time";
        
        try (Connection conn = DatabaseConnection.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setString(1, studentId);
            ResultSet rs = pstmt.executeQuery();
            
            while (rs.next()) {
                schedules.add(new Schedule(
                    rs.getInt("id"),
                    rs.getString("course_code"),
                    rs.getString("course_name"),
                    rs.getString("teacher_username"),
                    rs.getString("day_of_week"),
                    rs.getTime("start_time"),
                    rs.getTime("end_time"),
                    rs.getString("room"),
                    rs.getString("semester")
                ));
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return schedules;
    }
    
    public boolean deleteSchedule(int id) {
        String sql = "DELETE FROM schedules WHERE id = ?";
        try (Connection conn = DatabaseConnection.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setInt(1, id);
            return pstmt.executeUpdate() > 0;
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }
}
