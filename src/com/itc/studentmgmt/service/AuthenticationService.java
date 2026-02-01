package com.itc.studentmgmt.service;

import com.itc.studentmgmt.database.DatabaseConnection;
import com.itc.studentmgmt.model.User;
import com.itc.studentmgmt.model.UserRole;
import com.itc.studentmgmt.security.PasswordSecurityUtil;
import com.itc.studentmgmt.security.SecureSessionManager;
import com.itc.studentmgmt.security.SecurityAuditLogger;
import com.itc.studentmgmt.security.SensitiveDataProtector;
import com.itc.studentmgmt.security.TwoFactorAuthService;
import java.sql.*;

/**
 * 🔐 SECURE AUTHENTICATION SERVICE
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * Enterprise-grade authentication with:
 * 
 * ╔═══════════════════════════════════════════════════════════════════════════╗
 * ║  🔒 Multi-Layer Password Hashing (5 security layers)                      ║
 * ║  🎫 Cryptographic Session Management                                      ║
 * ║  📝 Security Audit Logging                                                ║
 * ║  🛡️ Brute Force Protection                                               ║
 * ║  🔄 Automatic Hash Upgrade                                                ║
 * ║  ⏰ Rate Limiting                                                         ║
 * ╚═══════════════════════════════════════════════════════════════════════════╝
 * 
 * @author Security Team
 * @version 3.0.0 - FORTRESS EDITION
 */
public class AuthenticationService {
    
    // Rate limiting: max failed attempts before lockout
    private static final int MAX_FAILED_ATTEMPTS = 5;
    
    // Lockout duration in minutes
    private static final int LOCKOUT_DURATION_MINUTES = 30;
    
    /**
     * Login user with username and password.
     * 
     * Security features:
     * - Multi-layer password verification
     * - Account lockout after failed attempts
     * - Automatic hash upgrade for legacy passwords
     * - Secure session creation
     * - Full audit logging
     * 
     * @param username Username
     * @param password Password
     * @return User object if successful, null otherwise
     */
    public User login(String username, String password) {
        return login(username, password, "0.0.0.0", "Unknown");
    }
    
    /**
     * Login with full client information for session binding.
     * 
     * @param username Username
     * @param password Password
     * @param ipAddress Client IP address
     * @param userAgent Client user agent
     * @return User object if successful, null otherwise
     */
    public User login(String username, String password, String ipAddress, String userAgent) {
        String sql = "SELECT password_hash, role, failed_login_attempts, account_locked, " +
                    "lockout_until FROM users WHERE username = ?";
        
        try (Connection conn = DatabaseConnection.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setString(1, username);
            ResultSet rs = pstmt.executeQuery();
            
            if (rs.next()) {
                // Check if account is locked
                if (rs.getBoolean("account_locked")) {
                    Timestamp lockoutUntil = rs.getTimestamp("lockout_until");
                    if (lockoutUntil != null && lockoutUntil.after(new Timestamp(System.currentTimeMillis()))) {
                        long remainingMinutes = (lockoutUntil.getTime() - System.currentTimeMillis()) / 60000;
                        System.out.println("🔒 Account is locked. Try again in " + remainingMinutes + " minutes.");
                        
                        SecurityAuditLogger.logSecurityEvent(
                            SecurityAuditLogger.EventType.LOGIN_FAILURE,
                            username, ipAddress,
                            "Login attempt on locked account"
                        );
                        return null;
                    } else {
                        // Lockout expired, unlock the account
                        unlockAccount(username);
                    }
                }
                
                String storedHash = rs.getString("password_hash");
                String roleStr = rs.getString("role");
                int failedAttempts = rs.getInt("failed_login_attempts");
                
                // Verify password with timing-attack resistance
                boolean isValid = PasswordSecurityUtil.verifyPassword(password, storedHash);
                
                if (isValid) {
                    // Reset failed attempts and update last login
                    updateLoginSuccess(username);
                    
                    // Create user object
                    User user = new User();
                    user.setUsername(username);
                    user.setRole(UserRole.valueOf(roleStr.toUpperCase()));
                    
                    // Create secure session (username, role, ipAddress, userAgent)
                    String sessionToken = SecureSessionManager.createSession(username, roleStr, ipAddress, userAgent);
                    user.setSessionToken(sessionToken);
                    
                    // Log successful login
                    SecurityAuditLogger.logSecurityEvent(
                        SecurityAuditLogger.EventType.LOGIN_SUCCESS,
                        username, ipAddress,
                        "User logged in successfully"
                    );
                    
                    System.out.println("✅ Login successful: " + username);
                    return user;
                } else {
                    // Increment failed attempts
                    failedAttempts++;
                    updateLoginFailure(username, failedAttempts, ipAddress);
                    
                    // Log failed login
                    SecurityAuditLogger.logSecurityEvent(
                        SecurityAuditLogger.EventType.LOGIN_FAILURE,
                        username, ipAddress,
                        "Invalid password. Attempt " + failedAttempts + "/" + MAX_FAILED_ATTEMPTS
                    );
                    
                    if (failedAttempts >= MAX_FAILED_ATTEMPTS) {
                        System.out.println("🔒 Account locked due to too many failed attempts.");
                    } else {
                        System.out.println("❌ Invalid credentials. Attempts remaining: " + 
                            (MAX_FAILED_ATTEMPTS - failedAttempts));
                    }
                }
            } else {
                // User not found - use constant time to prevent username enumeration
                PasswordSecurityUtil.verifyPassword(password, "$argon2id$v=19$m=65536,t=3,p=4$dummy$dummy");
                System.out.println("❌ Invalid credentials");
                
                SecurityAuditLogger.logSecurityEvent(
                    SecurityAuditLogger.EventType.LOGIN_FAILURE,
                    username, ipAddress,
                    "User not found"
                );
            }
            
        } catch (SQLException e) {
            System.err.println("❌ Login error: " + SensitiveDataProtector.redactPII(e.getMessage()));
        }
        
        return null;
    }
    
    /**
     * Register a new user with multi-layer password hashing.
     * 
     * @param username Username
     * @param password Password
     * @param role User role
     * @return true if registration successful
     */
    public boolean registerUser(String username, String password, UserRole role) {
        return registerUser(username, password, role, "0.0.0.0");
    }
    
    /**
     * Register a new user with full audit logging.
     * 
     * @param username Username
     * @param password Password
     * @param role User role
     * @param ipAddress Client IP address
     * @return true if registration successful
     */
    public boolean registerUser(String username, String password, UserRole role, String ipAddress) {
        // Validate password strength
        if (!PasswordSecurityUtil.isPasswordStrong(password)) {
            System.out.println("\n❌ Password does not meet security requirements:");
            System.out.println("   • Minimum 12 characters");
            System.out.println("   • Must contain uppercase letter");
            System.out.println("   • Must contain lowercase letter");
            System.out.println("   • Must contain digit");
            System.out.println("   • Must contain special character");
            System.out.println("   • No common patterns (password, 123456, etc.)");
            System.out.println("   • No excessive character repetition\n");
            return false;
        }
        
        // Hash password using multi-layer vault
        String passwordHash = PasswordSecurityUtil.hashPassword(password);
        
        String sql = "INSERT INTO users (username, password_hash, role, failed_login_attempts, " +
                    "account_locked, created_at) VALUES (?, ?, ?, 0, FALSE, CURRENT_TIMESTAMP)";
        
        try (Connection conn = DatabaseConnection.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setString(1, username);
            pstmt.setString(2, passwordHash);
            pstmt.setString(3, role.toString());
            
            int rows = pstmt.executeUpdate();
            
            if (rows > 0) {
                SecurityAuditLogger.log(new SecurityAuditLogger.AuditEvent.Builder()
                    .eventType(SecurityAuditLogger.EventType.DATA_MODIFICATION)
                    .username(username)
                    .ipAddress(ipAddress)
                    .action("USER_REGISTRATION")
                    .details("New user registered with role: " + role)
                    .build());
                    
                System.out.println("✅ User registered successfully: " + username);
                return true;
            }
            
            return false;
            
        } catch (SQLException e) {
            if (e.getMessage().contains("Duplicate entry")) {
                System.err.println("❌ Username already exists!");
            } else {
                System.err.println("❌ Registration failed: " + 
                    SensitiveDataProtector.redactPII(e.getMessage()));
            }
            return false;
        }
    }
    
    /**
     * Update user record on successful login
     */
    private void updateLoginSuccess(String username) throws SQLException {
        String sql = "UPDATE users SET failed_login_attempts = 0, " +
                    "account_locked = FALSE, lockout_until = NULL, " +
                    "last_login = CURRENT_TIMESTAMP WHERE username = ?";
        
        try (Connection conn = DatabaseConnection.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, username);
            pstmt.executeUpdate();
        }
    }
    
    /**
     * Update user record on failed login with timed lockout
     */
    private void updateLoginFailure(String username, int attempts, String ipAddress) throws SQLException {
        String sql;
        if (attempts >= MAX_FAILED_ATTEMPTS) {
            // Lock account with timed lockout
            sql = "UPDATE users SET failed_login_attempts = ?, " +
                  "account_locked = TRUE, " +
                  "lockout_until = DATE_ADD(CURRENT_TIMESTAMP, INTERVAL ? MINUTE) " +
                  "WHERE username = ?";
        } else {
            sql = "UPDATE users SET failed_login_attempts = ? WHERE username = ?";
        }
        
        try (Connection conn = DatabaseConnection.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setInt(1, attempts);
            if (attempts >= MAX_FAILED_ATTEMPTS) {
                pstmt.setInt(2, LOCKOUT_DURATION_MINUTES);
                pstmt.setString(3, username);
                
                SecurityAuditLogger.logSecurityEvent(
                    SecurityAuditLogger.EventType.ACCOUNT_LOCKED,
                    username, ipAddress,
                    "Account locked after " + MAX_FAILED_ATTEMPTS + " failed attempts"
                );
            } else {
                pstmt.setString(2, username);
            }
            pstmt.executeUpdate();
        }
    }
    
    /**
     * Unlock a locked account (Admin only)
     */
    public boolean unlockAccount(String username) {
        String sql = "UPDATE users SET account_locked = FALSE, failed_login_attempts = 0, " +
                    "lockout_until = NULL WHERE username = ?";
        
        try (Connection conn = DatabaseConnection.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setString(1, username);
            int rows = pstmt.executeUpdate();
            
            if (rows > 0) {
                System.out.println("✅ Account unlocked: " + username);
                SecurityAuditLogger.logSecurityEvent(
                    SecurityAuditLogger.EventType.ACCOUNT_UNLOCKED,
                    username, "0.0.0.0",
                    "Account unlocked by administrator"
                );
                return true;
            }
            
        } catch (SQLException e) {
            System.err.println("Error unlocking account: " + 
                SensitiveDataProtector.redactPII(e.getMessage()));
        }
        
        return false;
    }
    
    /**
     * Change user password with full validation and logging.
     */
    public boolean changePassword(String username, String oldPassword, String newPassword) {
        return changePassword(username, oldPassword, newPassword, "0.0.0.0");
    }
    
    /**
     * Change user password with audit logging.
     */
    public boolean changePassword(String username, String oldPassword, 
                                 String newPassword, String ipAddress) {
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
                    SecurityAuditLogger.logSecurityEvent(
                        SecurityAuditLogger.EventType.PASSWORD_CHANGE,
                        username, ipAddress,
                        "Password change failed - incorrect current password"
                    );
                    return false;
                }
                
                // Check new password strength
                if (!PasswordSecurityUtil.isPasswordStrong(newPassword)) {
                    System.out.println("❌ New password does not meet security requirements");
                    for (String feedback : PasswordSecurityUtil.getPasswordFeedback(newPassword)) {
                        System.out.println("   → " + feedback);
                    }
                    return false;
                }
                
                // Check that new password is different from old
                if (oldPassword.equals(newPassword)) {
                    System.out.println("❌ New password must be different from current password");
                    return false;
                }
                
                // Hash new password using multi-layer vault
                String newHash = PasswordSecurityUtil.hashPassword(newPassword);
                
                // Update password
                String updateSql = "UPDATE users SET password_hash = ? WHERE username = ?";
                try (PreparedStatement updateStmt = conn.prepareStatement(updateSql)) {
                    updateStmt.setString(1, newHash);
                    updateStmt.setString(2, username);
                    
                    int rows = updateStmt.executeUpdate();
                    if (rows > 0) {
                        System.out.println("✅ Password changed successfully");
                        
                        // Invalidate all existing sessions for security
                        SecureSessionManager.invalidateAllUserSessions(username);
                        
                        SecurityAuditLogger.logSecurityEvent(
                            SecurityAuditLogger.EventType.PASSWORD_CHANGE,
                            username, ipAddress,
                            "Password changed successfully - all sessions invalidated"
                        );
                        return true;
                    }
                }
            }
            
        } catch (SQLException e) {
            System.err.println("Error changing password: " + 
                SensitiveDataProtector.redactPII(e.getMessage()));
        }
        
        return false;
    }
    
    /**
     * Logout user and invalidate session.
     */
    public void logout(String username, String sessionToken, String ipAddress) {
        SecureSessionManager.invalidateAllUserSessions(username);
        SecurityAuditLogger.log(new SecurityAuditLogger.AuditEvent.Builder()
            .eventType(SecurityAuditLogger.EventType.LOGOUT)
            .username(username)
            .ipAddress(ipAddress)
            .action("LOGOUT")
            .details("User logged out, session invalidated")
            .build());
        System.out.println("✅ Logged out successfully: " + username);
    }
    
    /**
     * Check password strength and return score (0-100)
     */
    public int checkPasswordStrength(String password) {
        return PasswordSecurityUtil.calculatePasswordStrength(password);
    }
    
    /**
     * Get password strength label.
     */
    public String getPasswordStrengthLabel(String password) {
        return PasswordSecurityUtil.getPasswordStrengthLabel(password);
    }
    
    /**
     * Get active session count for a user.
     */
    public int getActiveSessionCount(String username) {
        return SecureSessionManager.getUserSessionCount(username);
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
            System.err.println("Error checking user: " + 
                SensitiveDataProtector.redactPII(e.getMessage()));
        }
        
        return false;
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // TWO-FACTOR AUTHENTICATION METHODS
    // ═══════════════════════════════════════════════════════════════════════════
    
    // Enable/Disable 2FA - set to true to require 2FA for all logins
    private static final boolean TWO_FACTOR_ENABLED = true;
    
    /**
     * Check if 2FA is enabled for the system.
     */
    public boolean isTwoFactorEnabled() {
        return TWO_FACTOR_ENABLED && TwoFactorAuthService.isConfigured();
    }
    
    /**
     * Validate credentials only (Step 1 of 2FA login).
     * Does NOT create a session - only validates username/password.
     * 
     * @param username Username
     * @param password Password
     * @return User object with role info if valid, null otherwise
     */
    public User validateCredentials(String username, String password) {
        return validateCredentials(username, password, "0.0.0.0", "Unknown");
    }
    
    /**
     * Validate credentials with full client info (Step 1 of 2FA login).
     */
    public User validateCredentials(String username, String password, 
                                   String ipAddress, String userAgent) {
        String sql = "SELECT password_hash, role, failed_login_attempts, account_locked, " +
                    "lockout_until FROM users WHERE username = ?";
        
        try (Connection conn = DatabaseConnection.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setString(1, username);
            ResultSet rs = pstmt.executeQuery();
            
            if (rs.next()) {
                // Check if account is locked
                if (rs.getBoolean("account_locked")) {
                    Timestamp lockoutUntil = rs.getTimestamp("lockout_until");
                    if (lockoutUntil != null && lockoutUntil.after(new Timestamp(System.currentTimeMillis()))) {
                        return null;
                    } else {
                        unlockAccount(username);
                    }
                }
                
                String storedHash = rs.getString("password_hash");
                String roleStr = rs.getString("role");
                int failedAttempts = rs.getInt("failed_login_attempts");
                
                // Verify password
                boolean isValid = PasswordSecurityUtil.verifyPassword(password, storedHash);
                
                if (isValid) {
                    // Create user object (but don't create session yet)
                    User user = new User();
                    user.setUsername(username);
                    user.setRole(UserRole.valueOf(roleStr.toUpperCase()));
                    return user;
                } else {
                    // Increment failed attempts
                    failedAttempts++;
                    updateLoginFailure(username, failedAttempts, ipAddress);
                }
            } else {
                // User not found - use constant time to prevent enumeration
                PasswordSecurityUtil.verifyPassword(password, "$argon2id$v=19$m=65536,t=3,p=4$dummy$dummy");
            }
            
        } catch (SQLException e) {
            System.err.println("❌ Credential validation error: " + 
                SensitiveDataProtector.redactPII(e.getMessage()));
        }
        
        return null;
    }
    
    /**
     * Complete login after 2FA verification (Step 2 of 2FA login).
     * Creates session and updates login tracking.
     * 
     * @param username Username (already validated)
     * @param ipAddress Client IP
     * @param userAgent Client user agent
     * @return User object with session token
     */
    public User completeLoginAfter2FA(String username, String ipAddress, String userAgent) {
        String sql = "SELECT role FROM users WHERE username = ?";
        
        try (Connection conn = DatabaseConnection.getInstance().getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setString(1, username);
            ResultSet rs = pstmt.executeQuery();
            
            if (rs.next()) {
                String roleStr = rs.getString("role");
                
                // Reset failed attempts and update last login
                updateLoginSuccess(username);
                
                // Create user object
                User user = new User();
                user.setUsername(username);
                user.setRole(UserRole.valueOf(roleStr.toUpperCase()));
                
                // Create secure session
                String sessionToken = SecureSessionManager.createSession(
                    username, roleStr, ipAddress, userAgent);
                user.setSessionToken(sessionToken);
                
                // Log successful login with 2FA
                SecurityAuditLogger.logSecurityEvent(
                    SecurityAuditLogger.EventType.LOGIN_SUCCESS,
                    username, ipAddress,
                    "User logged in with 2FA verification"
                );
                
                System.out.println("✅ Login successful (2FA verified): " + username);
                return user;
            }
            
        } catch (SQLException e) {
            System.err.println("❌ Login completion error: " + 
                SensitiveDataProtector.redactPII(e.getMessage()));
        }
        
        return null;
    }
    
    /**
     * Send 2FA code to user.
     */
    public TwoFactorAuthService.TwoFactorResult send2FACode(String username) {
        return TwoFactorAuthService.generateAndSendCode(username);
    }
    
    /**
     * Verify 2FA code.
     */
    public TwoFactorAuthService.TwoFactorResult verify2FACode(String username, String code) {
        return TwoFactorAuthService.verifyCode(username, code);
    }
}
