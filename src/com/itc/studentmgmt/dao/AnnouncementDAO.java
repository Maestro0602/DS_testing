package com.itc.studentmgmt.dao;

import com.itc.studentmgmt.model.Announcement;
import com.itc.studentmgmt.database.DatabaseConnection;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;

public class AnnouncementDAO {
    
    public boolean addAnnouncement(Announcement announcement) {
        String sql = "INSERT INTO announcements (title, content, created_by, target_role) VALUES (?, ?, ?, ?)";
        try (Connection conn = DatabaseConnection.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setString(1, announcement.getTitle());
            pstmt.setString(2, announcement.getContent());
            pstmt.setString(3, announcement.getCreatedBy());
            pstmt.setString(4, announcement.getTargetRole());
            
            return pstmt.executeUpdate() > 0;
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }
    
    public List<Announcement> getAnnouncementsForRole(String role) {
        List<Announcement> announcements = new ArrayList<>();
        String sql = "SELECT * FROM announcements WHERE target_role IN ('ALL', ?) ORDER BY created_at DESC LIMIT 20";
        
        try (Connection conn = DatabaseConnection.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setString(1, role.toUpperCase());
            ResultSet rs = pstmt.executeQuery();
            
            while (rs.next()) {
                announcements.add(new Announcement(
                    rs.getInt("id"),
                    rs.getString("title"),
                    rs.getString("content"),
                    rs.getString("created_by"),
                    rs.getTimestamp("created_at"),
                    rs.getString("target_role")
                ));
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return announcements;
    }
    
    public boolean deleteAnnouncement(int id) {
        String sql = "DELETE FROM announcements WHERE id = ?";
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
