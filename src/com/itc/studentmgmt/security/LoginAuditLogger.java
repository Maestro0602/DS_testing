package com.itc.studentmgmt.security;

import com.itc.studentmgmt.database.DatabaseConnection;
import java.sql.*;
import java.time.LocalDateTime;

/**
 * 🔐 LOGIN AUDIT LOGGER
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * Tracks user login activities in the database audit_logs table.
 * Separate from SecurityAuditLogger which tracks attacks/security events in files.
 * 
 * Purpose:
 * - User authentication tracking
 * - Login success/failure monitoring
 * - Account lockout events
 * - Password change tracking
 * - Compliance and user activity auditing
 * 
 * @author Security Team
 * @version 1.0.0
 */
public class LoginAuditLogger {
    
    /**
     * Event types for login auditing
     */
    public enum LoginEventType {
        LOGIN_SUCCESS,
        LOGIN_FAILURE,
        LOGOUT,
        PASSWORD_CHANGE,
        ACCOUNT_LOCKED,
        ACCOUNT_UNLOCKED,
        TWO_FACTOR_SUCCESS,
        TWO_FACTOR_FAILURE,
        SESSION_CREATED,
        SESSION_EXPIRED
    }
    
    /**
     * Log a login event to the database
     * 
     * @param eventType Type of login event
     * @param username Username attempting action
     * @param ipAddress IP address of the user
     * @param action Action description
     * @param details Additional details
     */
    public static void logLoginEvent(LoginEventType eventType, String username, 
                                     String ipAddress, String action, String details) {
        String sql = "INSERT INTO audit_logs (event_type, username, ip_address, action, details, timestamp) " +
                    "VALUES (?, ?, ?, ?, ?, ?)";
        
        try (Connection conn = DatabaseConnection.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setString(1, eventType.name());
            pstmt.setString(2, username);
            pstmt.setString(3, ipAddress);
            pstmt.setString(4, action);
            pstmt.setString(5, details);
            pstmt.setTimestamp(6, Timestamp.valueOf(LocalDateTime.now()));
            
            pstmt.executeUpdate();
            
            // Log to console for immediate visibility
            if (eventType == LoginEventType.LOGIN_FAILURE || 
                eventType == LoginEventType.ACCOUNT_LOCKED ||
                eventType == LoginEventType.TWO_FACTOR_FAILURE) {
                System.out.println("🚨 LOGIN AUDIT: " + eventType + " - " + username + " from " + ipAddress);
            }
            
        } catch (SQLException e) {
            System.err.println("❌ Failed to log login event: " + e.getMessage());
            // Don't throw exception - logging failures shouldn't break the application
        }
    }
    
    /**
     * Convenience method for login success
     */
    public static void logLoginSuccess(String username, String ipAddress) {
        logLoginEvent(LoginEventType.LOGIN_SUCCESS, username, ipAddress, 
                     "LOGIN", "User logged in successfully");
    }
    
    /**
     * Convenience method for login failure
     */
    public static void logLoginFailure(String username, String ipAddress, String reason) {
        logLoginEvent(LoginEventType.LOGIN_FAILURE, username, ipAddress, 
                     "LOGIN", "Login failed: " + reason);
    }
    
    /**
     * Convenience method for logout
     */
    public static void logLogout(String username, String ipAddress) {
        logLoginEvent(LoginEventType.LOGOUT, username, ipAddress, 
                     "LOGOUT", "User logged out");
    }
    
    /**
     * Convenience method for password change
     */
    public static void logPasswordChange(String username, String ipAddress) {
        logLoginEvent(LoginEventType.PASSWORD_CHANGE, username, ipAddress, 
                     "PASSWORD_CHANGE", "User changed password");
    }
    
    /**
     * Convenience method for account locked
     */
    public static void logAccountLocked(String username, String ipAddress, String reason) {
        logLoginEvent(LoginEventType.ACCOUNT_LOCKED, username, ipAddress, 
                     "ACCOUNT_LOCKED", "Account locked: " + reason);
    }
    
    /**
     * Convenience method for account unlocked
     */
    public static void logAccountUnlocked(String username, String ipAddress) {
        logLoginEvent(LoginEventType.ACCOUNT_UNLOCKED, username, ipAddress, 
                     "ACCOUNT_UNLOCKED", "Account unlocked by administrator");
    }
    
    /**
     * Convenience method for 2FA success
     */
    public static void logTwoFactorSuccess(String username, String ipAddress) {
        logLoginEvent(LoginEventType.TWO_FACTOR_SUCCESS, username, ipAddress, 
                     "2FA", "Two-factor authentication successful");
    }
    
    /**
     * Convenience method for 2FA failure
     */
    public static void logTwoFactorFailure(String username, String ipAddress, String reason) {
        logLoginEvent(LoginEventType.TWO_FACTOR_FAILURE, username, ipAddress, 
                     "2FA", "Two-factor authentication failed: " + reason);
    }
    
    /**
     * Get recent login attempts for a user (last 24 hours)
     * 
     * @param username Username to check
     * @return Number of failed login attempts in last 24 hours
     */
    public static int getRecentFailedAttempts(String username) {
        String sql = "SELECT COUNT(*) FROM audit_logs " +
                    "WHERE username = ? AND event_type = 'LOGIN_FAILURE' " +
                    "AND timestamp > DATE_SUB(NOW(), INTERVAL 24 HOUR)";
        
        try (Connection conn = DatabaseConnection.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setString(1, username);
            ResultSet rs = pstmt.executeQuery();
            
            if (rs.next()) {
                return rs.getInt(1);
            }
            
        } catch (SQLException e) {
            System.err.println("❌ Failed to get recent failed attempts: " + e.getMessage());
        }
        
        return 0;
    }
    
    /**
     * Get all login events for a user (for admin viewing)
     * 
     * @param username Username to query
     * @param limit Maximum number of records to return
     */
    public static void printUserLoginHistory(String username, int limit) {
        String sql = "SELECT event_type, ip_address, action, details, timestamp " +
                    "FROM audit_logs " +
                    "WHERE username = ? " +
                    "ORDER BY timestamp DESC " +
                    "LIMIT ?";
        
        try (Connection conn = DatabaseConnection.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setString(1, username);
            pstmt.setInt(2, limit);
            ResultSet rs = pstmt.executeQuery();
            
            System.out.println("\n📊 Login History for: " + username);
            System.out.println("═══════════════════════════════════════════════════════════════");
            
            int count = 0;
            while (rs.next()) {
                count++;
                System.out.printf("%2d. [%s] %s from %s - %s%n",
                    count,
                    rs.getTimestamp("timestamp").toString(),
                    rs.getString("event_type"),
                    rs.getString("ip_address"),
                    rs.getString("details")
                );
            }
            
            if (count == 0) {
                System.out.println("No login history found.");
            }
            
            System.out.println("═══════════════════════════════════════════════════════════════\n");
            
        } catch (SQLException e) {
            System.err.println("❌ Failed to get login history: " + e.getMessage());
        }
    }
    
    /**
     * Clean old audit logs (older than specified days)
     * 
     * @param daysToKeep Number of days of logs to retain
     * @return Number of records deleted
     */
    public static int cleanOldLogs(int daysToKeep) {
        String sql = "DELETE FROM audit_logs " +
                    "WHERE timestamp < DATE_SUB(NOW(), INTERVAL ? DAY)";
        
        try (Connection conn = DatabaseConnection.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setInt(1, daysToKeep);
            int deleted = pstmt.executeUpdate();
            
            System.out.println("✅ Cleaned " + deleted + " old audit log records (older than " + daysToKeep + " days)");
            return deleted;
            
        } catch (SQLException e) {
            System.err.println("❌ Failed to clean old logs: " + e.getMessage());
            return 0;
        }
    }
}
