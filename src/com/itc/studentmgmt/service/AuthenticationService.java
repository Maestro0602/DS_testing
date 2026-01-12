package com.itc.studentmgmt.service;

import com.itc.studentmgmt.database.DatabaseConnection;
import com.itc.studentmgmt.security.PasswordSecurityUtil;
import com.itc.studentmgmt.model.User;
import com.itc.studentmgmt.model.UserRole;
import java.sql.*;

/**
 * Secure authentication service using Argon2id password hashing
 * Handles user login, registration, and account management
 */
public class AuthenticationService {
    
    /**
     * Login user with username and password
     * Returns User object if successful, null otherwise
     */
    public User login(String username, String password) {
        String sql = "SELECT password_hash, role, failed_login_attempts, account_locked " +
                    "FROM users WHERE username = ?";
        
        try (Connection conn = DatabaseConnection.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setString(1, username);
            ResultSet rs = pstmt.executeQuery();
            
            if (rs.next()) {
                // Check if account is locked
                if (rs.getBoolean("account_locked")) {
                    System.out.println("🔒 Account is locked. Contact administrator.");
                    return null;
                }
                
                String storedHash = rs.getString("password_hash");
                String roleStr = rs.getString("role");
                int failedAttempts = rs.getInt("failed_login_attempts");
                
                // Verify password with timing-attack resistance
                boolean isValid = PasswordSecurityUtil.verifyPassword(password, storedHash);
                
                if (isValid) {
                    // Reset failed attempts on successful login
                    updateLoginSuccess(username);
                    System.out.println("✅ Login successful for: " + username);
                    
                    // Return User object
                    UserRole role = UserRole.valueOf(roleStr.toUpperCase());
                    return new User(username, storedHash, role);
                } else {
                    // Increment failed attempts
                    int newAttempts = failedAttempts + 1;
                    updateLoginFailure(username, newAttempts);
                    
                    if (newAttempts >= 5) {
                        System.out.println("🔒 Account locked after 5 failed attempts!");
                    } else {
                        System.out.println("❌ Invalid credentials. Attempts remaining: " + (5 - newAttempts));
                    }
                    return null;
                }
            }
            
            // User not found - don't leak this information
            System.out.println("❌ Invalid credentials.");
            return null;
            
        } catch (SQLException e) {
            System.err.println("❌ Authentication error: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }
    
    /**
     * Register a new user with secure password hashing
     */
    public boolean registerUser(String username, String password, UserRole role) {
        // Validate password strength
        if (!PasswordSecurityUtil.isPasswordStrong(password)) {
            System.out.println("\n❌ Password does not meet security requirements:");
            System.out.println("   • Minimum 12 characters");
            System.out.println("   • Must contain uppercase letter");
            System.out.println("   • Must contain lowercase letter");
            System.out.println("   • Must contain digit");
            System.out.println("   • Must contain special character\n");
            return false;
        }
        
        // Hash password using Argon2id
        String passwordHash = PasswordSecurityUtil.hashPassword(password);
        
        // Store in database
        String sql = "INSERT INTO users (username, password_hash, salt, role) VALUES (?, ?, ?, ?)";
        
        try (Connection conn = DatabaseConnection.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setString(1, username);
            pstmt.setString(2, passwordHash);
            pstmt.setString(3, ""); // Salt is embedded in hash
            pstmt.setString(4, role.toString());
            
            int rows = pstmt.executeUpdate();
            
            if (rows > 0) {
                System.out.println("✅ User registered successfully: " + username);
                return true;
            }
            
            return false;
            
        } catch (SQLException e) {
            if (e.getMessage().contains("Duplicate entry")) {
                System.err.println("❌ Username already exists!");
            } else {
                System.err.println("❌ Registration failed: " + e.getMessage());
            }
            return false;
        }
    }
    
    /**
     * Update user record on successful login
     */
    private void updateLoginSuccess(String username) throws SQLException {
        String sql = "UPDATE users SET failed_login_attempts = 0, " +
                    "last_login = CURRENT_TIMESTAMP WHERE username = ?";
        
        try (Connection conn = DatabaseConnection.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, username);
            pstmt.executeUpdate();
        }
    }
    
    /**
     * Update user record on failed login
     */
    private void updateLoginFailure(String username, int attempts) throws SQLException {
        String sql = "UPDATE users SET failed_login_attempts = ?, " +
                    "account_locked = ? WHERE username = ?";
        
        try (Connection conn = DatabaseConnection.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setInt(1, attempts);
            pstmt.setBoolean(2, attempts >= 5);
            pstmt.setString(3, username);
            pstmt.executeUpdate();
        }
    }
    
    /**
     * Check if username exists
     */
    public boolean userExists(String username) {
        String sql = "SELECT COUNT(*) FROM users WHERE username = ?";
        
        try (Connection conn = DatabaseConnection.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setString(1, username);
            ResultSet rs = pstmt.executeQuery();
            
            if (rs.next()) {
                return rs.getInt(1) > 0;
            }
            
        } catch (SQLException e) {
            System.err.println("Error checking user: " + e.getMessage());
        }
        
        return false;
    }
    
    /**
     * Unlock a locked account (Admin only)
     */
    public boolean unlockAccount(String username) {
        String sql = "UPDATE users SET account_locked = FALSE, failed_login_attempts = 0 " +
                    "WHERE username = ?";
        
        try (Connection conn = DatabaseConnection.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setString(1, username);
            int rows = pstmt.executeUpdate();
            
            if (rows > 0) {
                System.out.println("✅ Account unlocked: " + username);
                return true;
            }
            
        } catch (SQLException e) {
            System.err.println("Error unlocking account: " + e.getMessage());
        }
        
        return false;
    }
    
    /**
     * Change user password
     */
    public boolean changePassword(String username, String oldPassword, String newPassword) {
        // First verify old password
        String sql = "SELECT password_hash FROM users WHERE username = ?";
        
        try (Connection conn = DatabaseConnection.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setString(1, username);
            ResultSet rs = pstmt.executeQuery();
            
            if (rs.next()) {
                String storedHash = rs.getString("password_hash");
                
                // Verify old password
                if (!PasswordSecurityUtil.verifyPassword(oldPassword, storedHash)) {
                    System.out.println("❌ Current password is incorrect");
                    return false;
                }
                
                // Check new password strength
                if (!PasswordSecurityUtil.isPasswordStrong(newPassword)) {
                    System.out.println("❌ New password does not meet security requirements");
                    return false;
                }
                
                // Hash new password
                String newHash = PasswordSecurityUtil.hashPassword(newPassword);
                
                // Update password
                String updateSql = "UPDATE users SET password_hash = ? WHERE username = ?";
                try (PreparedStatement updateStmt = conn.prepareStatement(updateSql)) {
                    updateStmt.setString(1, newHash);
                    updateStmt.setString(2, username);
                    
                    int rows = updateStmt.executeUpdate();
                    if (rows > 0) {
                        System.out.println("✅ Password changed successfully");
                        return true;
                    }
                }
            }
            
        } catch (SQLException e) {
            System.err.println("Error changing password: " + e.getMessage());
        }
        
        return false;
    }
    
    /**
     * Check password strength and return score (0-100)
     */
    public int checkPasswordStrength(String password) {
        return PasswordSecurityUtil.calculatePasswordStrength(password);
    }
}