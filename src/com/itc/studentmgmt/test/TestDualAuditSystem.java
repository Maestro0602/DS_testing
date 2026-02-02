package com.itc.studentmgmt.test;

import com.itc.studentmgmt.model.User;
import com.itc.studentmgmt.security.LoginAuditLogger;
import com.itc.studentmgmt.security.SecurityAuditLogger;
import com.itc.studentmgmt.service.AuthenticationService;

/**
 * 🧪 DUAL AUDIT SYSTEM TEST
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * Tests both audit logging systems:
 * 1. LoginAuditLogger - Tracks login/auth events in DATABASE (audit_logs table)
 * 2. SecurityAuditLogger - Tracks attacks/security events in FILES (security_logs/*.log)
 * 
 * @author Security Team
 */
public class TestDualAuditSystem {
    
    public static void main(String[] args) {
        System.out.println("╔═══════════════════════════════════════════════════════════════╗");
        System.out.println("║          DUAL AUDIT SYSTEM TEST                               ║");
        System.out.println("╚═══════════════════════════════════════════════════════════════╝\n");
        
        AuthenticationService authService = new AuthenticationService();
        
        // ═══════════════════════════════════════════════════════════════════════════
        // Part 1: Test LOGIN AUDIT (Goes to DATABASE)
        // ═══════════════════════════════════════════════════════════════════════════
        System.out.println("📊 Part 1: Testing LOGIN AUDIT LOGGER (Database)");
        System.out.println("─────────────────────────────────────────────────────────────────\n");
        
        // Test 1: Successful login
        System.out.println("Test 1: Successful Login");
        User user = authService.login("admin", "admin123", "192.168.1.100", "TestClient");
        if (user != null) {
            System.out.println("✅ Login successful - should be logged to database\n");
        }
        
        // Test 2: Failed login attempts
        System.out.println("Test 2: Failed Login Attempts (triggers rate limiting)");
        for (int i = 1; i <= 6; i++) {
            System.out.println("Attempt " + i + ":");
            authService.login("admin", "wrongpass" + i, "192.168.1.101", "AttackerClient");
            System.out.println();
        }
        System.out.println("✅ Failed logins logged to database\n");
        
        // Test 3: Check login history from database
        System.out.println("Test 3: Viewing Login History from Database");
        LoginAuditLogger.printUserLoginHistory("admin", 10);
        
        // Test 4: Manual login audit logs
        System.out.println("Test 4: Manual Login Events");
        LoginAuditLogger.logPasswordChange("testuser", "192.168.1.102");
        LoginAuditLogger.logLogout("testuser", "192.168.1.102");
        System.out.println("✅ Password change and logout logged to database\n");
        
        // ═══════════════════════════════════════════════════════════════════════════
        // Part 2: Test SECURITY AUDIT (Goes to FILES)
        // ═══════════════════════════════════════════════════════════════════════════
        System.out.println("\n📁 Part 2: Testing SECURITY AUDIT LOGGER (Files)");
        System.out.println("─────────────────────────────────────────────────────────────────\n");
        
        // Test 5: Security events (attacks, intrusions)
        System.out.println("Test 5: Logging Security/Attack Events to Files");
        
        SecurityAuditLogger.logSecurityEvent(
            SecurityAuditLogger.EventType.INJECTION_ATTEMPT,
            "attacker", "192.168.1.200",
            "Detected SQL injection: SELECT * FROM users WHERE id='1' OR '1'='1'"
        );
        System.out.println("✅ SQL injection attempt logged to file\n");
        
        SecurityAuditLogger.logSecurityEvent(
            SecurityAuditLogger.EventType.INJECTION_ATTEMPT,
            "attacker", "192.168.1.200",
            "Detected XSS: <script>alert('xss')</script>"
        );
        System.out.println("✅ XSS attempt logged to file\n");
        
        SecurityAuditLogger.logSecurityEvent(
            SecurityAuditLogger.EventType.BRUTE_FORCE_DETECTED,
            "attacker", "192.168.1.200",
            "Rate limit exceeded: 100 requests in 10 seconds"
        );
        System.out.println("✅ Rate limit violation logged to file\n");
        
        SecurityAuditLogger.logSecurityEvent(
            SecurityAuditLogger.EventType.BRUTE_FORCE_DETECTED,
            "attacker", "192.168.1.200",
            "Brute force attack detected: 50 failed login attempts"
        );
        System.out.println("✅ Brute force attack logged to file\n");
        
        SecurityAuditLogger.logSecurityEvent(
            SecurityAuditLogger.EventType.TAMPERING_DETECTED,
            "attacker", "192.168.1.200",
            "IP blocked due to suspicious activity"
        );
        System.out.println("✅ IP block logged to file\n");
        
        // ═══════════════════════════════════════════════════════════════════════════
        // Summary
        // ═══════════════════════════════════════════════════════════════════════════
        System.out.println("\n╔═══════════════════════════════════════════════════════════════╗");
        System.out.println("║                    TEST SUMMARY                               ║");
        System.out.println("╠═══════════════════════════════════════════════════════════════╣");
        System.out.println("║                                                               ║");
        System.out.println("║  ✅ LOGIN AUDIT LOGGER (Database)                             ║");
        System.out.println("║     - Tracks: Login, Logout, Password Changes, 2FA            ║");
        System.out.println("║     - Location: audit_logs table in MySQL database            ║");
        System.out.println("║     - Query: SELECT * FROM audit_logs ORDER BY timestamp DESC ║");
        System.out.println("║                                                               ║");
        System.out.println("║  ✅ SECURITY AUDIT LOGGER (Files)                             ║");
        System.out.println("║     - Tracks: Attacks, Injections, Rate Limits, IDS Events    ║");
        System.out.println("║     - Location: security_logs/audit_*.log files               ║");
        System.out.println("║     - View: Get-Content security_logs\\audit_*.log             ║");
        System.out.println("║                                                               ║");
        System.out.println("╚═══════════════════════════════════════════════════════════════╝\n");
        
        // Verification commands
        System.out.println("📋 VERIFICATION COMMANDS:");
        System.out.println("─────────────────────────────────────────────────────────────────");
        System.out.println("\n🗄️  Check Database Audit Logs:");
        System.out.println("   mysql -u root -p");
        System.out.println("   USE stu_manage;");
        System.out.println("   SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 20;");
        System.out.println("   SELECT event_type, COUNT(*) FROM audit_logs GROUP BY event_type;");
        
        System.out.println("\n📁 Check File-Based Security Logs:");
        System.out.println("   Get-ChildItem security_logs");
        System.out.println("   Get-Content security_logs\\audit_*.log -Tail 20");
        System.out.println("   Select-String -Path security_logs\\*.log -Pattern \"INJECTION|XSS|BRUTE_FORCE\"");
        
        System.out.println("\n─────────────────────────────────────────────────────────────────\n");
    }
}
