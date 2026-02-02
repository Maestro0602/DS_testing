package com.itc.studentmgmt.dao;

import com.itc.studentmgmt.database.DatabaseConnection;
import com.itc.studentmgmt.model.User;
import com.itc.studentmgmt.model.UserRole;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;

/**
 * USER DATA ACCESS OBJECT
 * ====================================================================
 * 
 * Handles all user CRUD operations with:
 * - Duplicate username checking
 * - Secure password hash storage
 * - User role management
 * 
 * @author Security Team
 * @version 2.0.0
 */
public class UserDAO {
    
    // Error codes
    public static final int SUCCESS = 0;
    public static final int ERROR_DUPLICATE_USERNAME = 1;
    public static final int ERROR_DATABASE = 2;
    
    private int lastErrorCode = SUCCESS;
    private String lastErrorMessage = "";
    
    public int getLastErrorCode() {
        return lastErrorCode;
    }
    
    public String getLastErrorMessage() {
        return lastErrorMessage;
    }
    
    /**
     * Check if a username already exists.
     */
    public boolean usernameExists(String username) {
        String sql = "SELECT COUNT(*) FROM users WHERE username = ?";
        try (Connection conn = DatabaseConnection.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, username);
            ResultSet rs = pstmt.executeQuery();
            if (rs.next()) {
                return rs.getInt(1) > 0;
            }
        } catch (SQLException e) {
            System.err.println("Error checking username: " + e.getMessage());
        }
        return false;
    }
    
    /**
     * Add a new user with duplicate checking.
     */
    public boolean addUser(User user) {
        lastErrorCode = SUCCESS;
        lastErrorMessage = "";
        
        // Check for duplicate username
        if (usernameExists(user.getUsername())) {
            lastErrorCode = ERROR_DUPLICATE_USERNAME;
            lastErrorMessage = "Username '" + user.getUsername() + "' already exists!";
            System.err.println("[ERROR] " + lastErrorMessage);
            return false;
        }
        
        String sql = "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)";
        try (Connection conn = DatabaseConnection.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setString(1, user.getUsername());
            pstmt.setString(2, user.getPasswordHash());
            pstmt.setString(3, user.getRole().name());
            
            boolean result = pstmt.executeUpdate() > 0;
            if (result) {
                System.out.println("[OK] User created: " + user.getUsername() + " (" + user.getRole() + ")");
            }
            return result;
        } catch (SQLException e) {
            lastErrorCode = ERROR_DATABASE;
            if (e.getErrorCode() == 1062) { // Duplicate entry
                lastErrorCode = ERROR_DUPLICATE_USERNAME;
                lastErrorMessage = "Username already exists!";
            } else {
                lastErrorMessage = "Database error: " + e.getMessage();
            }
            System.err.println("[ERROR] Failed to add user: " + lastErrorMessage);
            return false;
        }
    }
    
    /**
     * Update an existing user's role and optionally password.
     */
    public boolean updateUser(User user) {
        lastErrorCode = SUCCESS;
        lastErrorMessage = "";
        
        String sql = "UPDATE users SET role = ?, password_hash = ? WHERE username = ?";
        try (Connection conn = DatabaseConnection.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setString(1, user.getRole().name());
            pstmt.setString(2, user.getPasswordHash());
            pstmt.setString(3, user.getUsername());
            
            boolean result = pstmt.executeUpdate() > 0;
            if (result) {
                System.out.println("[OK] User updated: " + user.getUsername());
            }
            return result;
        } catch (SQLException e) {
            lastErrorCode = ERROR_DATABASE;
            lastErrorMessage = "Database error: " + e.getMessage();
            System.err.println("[ERROR] Failed to update user: " + lastErrorMessage);
            return false;
        }
    }
    
    /**
     * Update only the user's role.
     */
    public boolean updateUserRole(String username, UserRole role) {
        String sql = "UPDATE users SET role = ? WHERE username = ?";
        try (Connection conn = DatabaseConnection.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setString(1, role.name());
            pstmt.setString(2, username);
            
            return pstmt.executeUpdate() > 0;
        } catch (SQLException e) {
            System.err.println("[ERROR] Failed to update user role: " + e.getMessage());
            return false;
        }
    }
    
    public User getUser(String username) {
        String sql = "SELECT * FROM users WHERE username = ?";
        try (Connection conn = DatabaseConnection.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setString(1, username);
            ResultSet rs = pstmt.executeQuery();
            
            if (rs.next()) {
                return new User(
                    rs.getString("username"),
                    rs.getString("password_hash"),
                    UserRole.valueOf(rs.getString("role"))
                );
            }
        } catch (SQLException e) {
            System.err.println("[ERROR] Failed to get user: " + e.getMessage());
        }
        return null;
    }
    
    public List<User> getAllUsers() {
        List<User> users = new ArrayList<>();
        String sql = "SELECT * FROM users ORDER BY username";
        
        try (Connection conn = DatabaseConnection.getInstance().getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {
            
            while (rs.next()) {
                users.add(new User(
                    rs.getString("username"),
                    rs.getString("password_hash"),
                    UserRole.valueOf(rs.getString("role"))
                ));
            }
        } catch (SQLException e) {
            System.err.println("[ERROR] Failed to get all users: " + e.getMessage());
        }
        return users;
    }
    
    /**
     * Get users filtered by role.
     */
    public List<User> getUsersByRole(UserRole role) {
        List<User> users = new ArrayList<>();
        String sql = "SELECT * FROM users WHERE role = ? ORDER BY username";
        
        try (Connection conn = DatabaseConnection.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setString(1, role.name());
            ResultSet rs = pstmt.executeQuery();
            
            while (rs.next()) {
                users.add(new User(
                    rs.getString("username"),
                    rs.getString("password_hash"),
                    UserRole.valueOf(rs.getString("role"))
                ));
            }
        } catch (SQLException e) {
            System.err.println("[ERROR] Failed to get users by role: " + e.getMessage());
        }
        return users;
    }
    
    /**
     * Count users by role.
     */
    public int countUsersByRole(UserRole role) {
        String sql = "SELECT COUNT(*) FROM users WHERE role = ?";
        try (Connection conn = DatabaseConnection.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setString(1, role.name());
            ResultSet rs = pstmt.executeQuery();
            if (rs.next()) {
                return rs.getInt(1);
            }
        } catch (SQLException e) {
            System.err.println("[ERROR] Failed to count users: " + e.getMessage());
        }
        return 0;
    }
    
    public boolean deleteUser(String username) {
        String sql = "DELETE FROM users WHERE username = ?";
        try (Connection conn = DatabaseConnection.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setString(1, username);
            boolean result = pstmt.executeUpdate() > 0;
            if (result) {
                System.out.println("[OK] User deleted: " + username);
            }
            return result;
        } catch (SQLException e) {
            System.err.println("[ERROR] Failed to delete user: " + e.getMessage());
            return false;
        }
    }
}


