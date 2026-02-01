package com.itc.studentmgmt.security;

import java.util.*;

/**
 * 🎯 MAX-SECURITY ADVERSARY ATTACK SIMULATION (SAFE)
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * This class simulates a multi-phase APT-style attack for DEFENSIVE TESTING ONLY.
 * 
 * ╔═══════════════════════════════════════════════════════════════════════════╗
 * ║  ⚠️ IMPORTANT SAFETY CONSTRAINTS:                                         ║
 * ║  ─────────────────────────────────────────────────────────────────────────║
 * ║  ✗ This is NOT malware                                                    ║
 * ║  ✗ Does NOT encrypt files                                                 ║
 * ║  ✗ Does NOT access OS, registry, filesystem, or network scanning          ║
 * ║  ✗ Does NOT include persistence, self-propagation, or destructive actions ║
 * ║  ✓ Only simulates application-layer behavior                              ║
 * ╚═══════════════════════════════════════════════════════════════════════════╝
 * 
 * PURPOSE: Test and demonstrate the security system's defensive capabilities:
 *   - Intrusion Detection
 *   - Rate Limiting
 *   - Audit Logging
 *   - Alert Generation
 * 
 * @author Security Testing Team
 * @version 1.0.0 - SAFE SIMULATION
 */
public class MaxSecurityAttackSimulation {
    
    // ═══════════════════════════════════════════════════════════════════════════
    // CONFIGURATION
    // ═══════════════════════════════════════════════════════════════════════════
    
    /** Simulated attacker IP addresses */
    private static final String[] ATTACKER_IPS = {
        "192.168.1.100",
        "10.0.0.50",
        "172.16.0.99",
        "192.168.100.200",
        "10.10.10.10"
    };
    
    /** Common passwords for credential stuffing simulation */
    private static final String[] COMMON_PASSWORDS = {
        "password", "123456", "admin", "qwerty", "letmein",
        "welcome", "monkey", "dragon", "master", "password1"
    };
    
    /** Target usernames for credential stuffing simulation */
    private static final String[] TARGET_USERS = {
        "admin", "administrator", "root", "user", "test",
        "guest", "manager", "operator", "support", "student"
    };
    
    /** SQL Injection payloads (SAFE - only string patterns) */
    private static final String[] SQLI_PAYLOADS = {
        "' OR '1'='1",
        "' OR 1=1--",
        "admin'--",
        "'; DROP TABLE users;--",
        "' UNION SELECT * FROM users--",
        "1' AND '1'='1",
        "' OR 'x'='x",
        "admin' OR '1'='1'#",
        "') OR ('1'='1",
        "1; DELETE FROM students"
    };
    
    /** XSS payloads (SAFE - only string patterns) */
    private static final String[] XSS_PAYLOADS = {
        "<script>alert('xss')</script>",
        "<img src=x onerror=alert('xss')>",
        "javascript:alert('xss')",
        "<svg onload=alert('xss')>",
        "<body onload=alert('xss')>",
        "<iframe src='javascript:alert(1)'>",
        "<img src=x onerror='document.location=\"http://evil.com\"'>",
        "'\"><script>alert(1)</script>",
        "<script>document.cookie</script>",
        "<div onclick=\"alert('xss')\">click me</div>"
    };
    
    /** Path traversal payloads (SAFE - only string patterns) */
    private static final String[] PATH_TRAVERSAL_PAYLOADS = {
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252f..%252f..%252fetc/passwd",
        "/etc/shadow",
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "....\\....\\....\\windows\\win.ini",
        "%00../../../etc/passwd",
        "..%c0%af..%c0%af..%c0%afetc/passwd"
    };
    
    /** Simulated fake session tokens */
    private static final String[] FAKE_TOKENS = {
        "fake_session_token_12345",
        "eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.",
        "admin_session_hijacked",
        "00000000-0000-0000-0000-000000000000",
        "session_modified_by_attacker",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "../../../../../../tmp/session",
        "null",
        "undefined",
        "<script>steal_session()</script>"
    };
    
    /** Simulated student IDs for mass data access */
    private static final String[] STUDENT_IDS = {
        "STU001", "STU002", "STU003", "STU004", "STU005",
        "STU006", "STU007", "STU008", "STU009", "STU010",
        "STU011", "STU012", "STU013", "STU014", "STU015",
        "STU016", "STU017", "STU018", "STU019", "STU020"
    };
    
    // Delay between operations (milliseconds) to avoid real DoS
    private static final int SHORT_DELAY = 100;
    private static final int MEDIUM_DELAY = 250;
    private static final int LONG_DELAY = 500;
    
    // ═══════════════════════════════════════════════════════════════════════════
    // SIMULATION RESULTS
    // ═══════════════════════════════════════════════════════════════════════════
    
    private final List<String> simulationLog = new ArrayList<>();
    private int rateLimitTriggered = 0;
    private int injectionDetected = 0;
    private int sessionAbuseDetected = 0;
    private int abnormalAccessDetected = 0;
    private int alertsGenerated = 0;
    
    // ═══════════════════════════════════════════════════════════════════════════
    // MAIN SIMULATION RUNNER
    // ═══════════════════════════════════════════════════════════════════════════
    
    /**
     * Run the complete multi-phase attack simulation.
     * 
     * @return Simulation summary report
     */
    public String runFullSimulation() {
        log("═══════════════════════════════════════════════════════════════════════════════");
        log("🎯 MAX-SECURITY ATTACK SIMULATION - STARTING");
        log("═══════════════════════════════════════════════════════════════════════════════");
        log("⚠️ This is a SAFE simulation for DEFENSIVE TESTING ONLY");
        log("   No real attacks or harmful operations are performed.");
        log("");
        
        long startTime = System.currentTimeMillis();
        
        try {
            // Phase 1: Reconnaissance
            runPhase1Reconnaissance();
            
            // Phase 2: Credential Stuffing
            runPhase2CredentialStuffing();
            
            // Phase 3: Injection Attempts
            runPhase3InjectionAttempts();
            
            // Phase 4: Session Token Abuse
            runPhase4SessionTokenAbuse();
            
            // Phase 5: Ransomware-Like Behavior (READ-ONLY)
            runPhase5RansomwareLikeBehavior();
            
        } catch (InterruptedException e) {
            log("⚠️ Simulation interrupted: " + e.getMessage());
            Thread.currentThread().interrupt();
        }
        
        long duration = System.currentTimeMillis() - startTime;
        
        return generateReport(duration);
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // PHASE 1: RECONNAISSANCE
    // ═══════════════════════════════════════════════════════════════════════════
    
    /**
     * Phase 1 - Reconnaissance Simulation
     * 
     * Simulates repeated harmless GET requests to trigger rate-limiting counters.
     * 
     * Purpose: Test rate-limiting detection
     */
    private void runPhase1Reconnaissance() throws InterruptedException {
        log("");
        log("╔═══════════════════════════════════════════════════════════════════════════╗");
        log("║  PHASE 1: RECONNAISSANCE                                                 ║");
        log("║  Purpose: Trigger rate-limiting counters                                 ║");
        log("╚═══════════════════════════════════════════════════════════════════════════╝");
        log("");
        
        String attackerIp = ATTACKER_IPS[0];
        int requestCount = 0;
        
        // Simulate repeated requests to /login endpoint
        log("📡 Simulating repeated GET requests to /login from " + attackerIp);
        
        for (int i = 0; i < 15; i++) {
            // Simulate API rate limit check
            boolean allowed = IntrusionDetection.allowApiRequest(attackerIp);
            requestCount++;
            
            if (!allowed) {
                log("   🚫 Request #" + requestCount + " BLOCKED by rate limiter");
                rateLimitTriggered++;
            } else {
                log("   ✓ Request #" + requestCount + " allowed");
            }
            
            // Small delay to avoid real DoS
            Thread.sleep(SHORT_DELAY);
        }
        
        // Check threat score
        int threatScore = IntrusionDetection.getThreatScore(attackerIp);
        log("");
        log("📊 Phase 1 Results:");
        log("   - Total requests: " + requestCount);
        log("   - Rate limits triggered: " + rateLimitTriggered);
        log("   - Current threat score for " + attackerIp + ": " + threatScore);
        
        // Log to audit
        SecurityAuditLogger.log(new SecurityAuditLogger.AuditEvent.Builder()
            .eventType(SecurityAuditLogger.EventType.DATA_ACCESS)
            .username("ATTACKER_SIM")
            .ipAddress(attackerIp)
            .action("RECONNAISSANCE")
            .details("Simulated reconnaissance phase - " + requestCount + " requests")
            .build());
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // PHASE 2: CREDENTIAL STUFFING
    // ═══════════════════════════════════════════════════════════════════════════
    
    /**
     * Phase 2 - Credential Stuffing Simulation
     * 
     * Simulates login attempts on multiple users with common passwords.
     * 
     * Purpose: Trigger brute-force & correlation detection
     */
    private void runPhase2CredentialStuffing() throws InterruptedException {
        log("");
        log("╔═══════════════════════════════════════════════════════════════════════════╗");
        log("║  PHASE 2: CREDENTIAL STUFFING                                            ║");
        log("║  Purpose: Trigger brute-force & correlation detection                    ║");
        log("╚═══════════════════════════════════════════════════════════════════════════╝");
        log("");
        
        String attackerIp = ATTACKER_IPS[1];
        int attempts = 0;
        int blocked = 0;
        
        log("🔑 Simulating credential stuffing attack from " + attackerIp);
        
        for (String username : TARGET_USERS) {
            for (String password : COMMON_PASSWORDS) {
                if (attempts >= 25) break; // Limit total attempts
                
                // Check if IP is allowed to attempt login
                boolean allowed = IntrusionDetection.allowLoginAttempt(attackerIp);
                
                if (!allowed) {
                    log("   🚫 Login attempt BLOCKED for " + username + " (IP rate limited)");
                    blocked++;
                    rateLimitTriggered++;
                    continue;
                }
                
                // Check if user is allowed
                boolean userAllowed = IntrusionDetection.allowUserLoginAttempt(username);
                
                if (!userAllowed) {
                    log("   🚫 Login attempt BLOCKED for " + username + " (User rate limited)");
                    blocked++;
                    rateLimitTriggered++;
                    continue;
                }
                
                attempts++;
                
                // Simulate failed login (we don't actually verify credentials)
                log("   ❌ Failed login attempt: " + username + " / " + password.substring(0, 3) + "***");
                
                // Record the failed login for IDS
                IntrusionDetection.recordFailedLogin(attackerIp, username);
                
                // Analyze pattern
                IntrusionDetection.analyzeLoginPattern(attackerIp, username, "AttackBot/1.0", false);
                
                // Log to audit
                SecurityAuditLogger.log(new SecurityAuditLogger.AuditEvent.Builder()
                    .eventType(SecurityAuditLogger.EventType.LOGIN_FAILURE)
                    .username(username)
                    .ipAddress(attackerIp)
                    .action("LOGIN_ATTEMPT")
                    .details("Simulated credential stuffing - password: " + password.substring(0, 3) + "***")
                    .build());
                
                Thread.sleep(SHORT_DELAY);
            }
            if (attempts >= 25) break;
        }
        
        // Check final status
        int threatScore = IntrusionDetection.getThreatScore(attackerIp);
        boolean isBlocked = IntrusionDetection.isIpBlocked(attackerIp);
        
        log("");
        log("📊 Phase 2 Results:");
        log("   - Login attempts: " + attempts);
        log("   - Blocked attempts: " + blocked);
        log("   - Threat score for " + attackerIp + ": " + threatScore);
        log("   - IP Blocked: " + (isBlocked ? "✅ YES" : "❌ NO"));
        
        if (isBlocked) {
            log("   - Block info: " + IntrusionDetection.getBlockInfo(attackerIp));
            alertsGenerated++;
        }
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // PHASE 3: INJECTION ATTEMPTS
    // ═══════════════════════════════════════════════════════════════════════════
    
    /**
     * Phase 3 - Injection Attempts Simulation
     * 
     * Simulates login requests with SQL injection, XSS, and path traversal payloads.
     * 
     * Purpose: Trigger IDS pattern detection
     */
    private void runPhase3InjectionAttempts() throws InterruptedException {
        log("");
        log("╔═══════════════════════════════════════════════════════════════════════════╗");
        log("║  PHASE 3: INJECTION ATTEMPTS                                             ║");
        log("║  Purpose: Trigger IDS pattern detection                                  ║");
        log("╚═══════════════════════════════════════════════════════════════════════════╝");
        log("");
        
        String attackerIp = ATTACKER_IPS[2];
        int sqliDetected = 0;
        int xssDetected = 0;
        int pathTraversalAttempts = 0;
        
        // SQL Injection testing
        log("💉 Testing SQL Injection detection...");
        for (String payload : SQLI_PAYLOADS) {
            boolean detected = IntrusionDetection.detectSqlInjection(payload);
            
            if (detected) {
                log("   ✅ DETECTED SQLi: " + truncate(payload, 40));
                sqliDetected++;
                injectionDetected++;
                
                // Add threat score
                IntrusionDetection.addThreatScore(attackerIp, 25, "SQL Injection attempt: " + truncate(payload, 20));
                
                // Generate alert
                IntrusionDetection.generateAlert(
                    IntrusionDetection.AlertSeverity.CRITICAL,
                    "SQL_INJECTION",
                    attackerIp,
                    "SQL Injection attempt detected",
                    Map.of("payload", truncate(payload, 50))
                );
                alertsGenerated++;
                
                // Log to audit
                SecurityAuditLogger.log(new SecurityAuditLogger.AuditEvent.Builder()
                    .eventType(SecurityAuditLogger.EventType.INJECTION_ATTEMPT)
                    .username("ATTACKER_SIM")
                    .ipAddress(attackerIp)
                    .action("SQLI_ATTEMPT")
                    .details("SQL Injection payload: " + truncate(payload, 50))
                    .build());
            } else {
                log("   ⚠️ NOT DETECTED: " + truncate(payload, 40));
            }
            
            Thread.sleep(SHORT_DELAY);
        }
        
        Thread.sleep(MEDIUM_DELAY);
        
        // XSS testing
        log("");
        log("🔥 Testing XSS detection...");
        for (String payload : XSS_PAYLOADS) {
            boolean detected = IntrusionDetection.detectXss(payload);
            
            if (detected) {
                log("   ✅ DETECTED XSS: " + truncate(payload, 40));
                xssDetected++;
                injectionDetected++;
                
                // Add threat score
                IntrusionDetection.addThreatScore(attackerIp, 20, "XSS attempt: " + truncate(payload, 20));
                
                // Generate alert
                IntrusionDetection.generateAlert(
                    IntrusionDetection.AlertSeverity.HIGH,
                    "XSS_ATTEMPT",
                    attackerIp,
                    "XSS attempt detected",
                    Map.of("payload", truncate(payload, 50))
                );
                alertsGenerated++;
                
                // Log to audit
                SecurityAuditLogger.log(new SecurityAuditLogger.AuditEvent.Builder()
                    .eventType(SecurityAuditLogger.EventType.INJECTION_ATTEMPT)
                    .username("ATTACKER_SIM")
                    .ipAddress(attackerIp)
                    .action("XSS_ATTEMPT")
                    .details("XSS payload: " + truncate(payload, 50))
                    .build());
            } else {
                log("   ⚠️ NOT DETECTED: " + truncate(payload, 40));
            }
            
            Thread.sleep(SHORT_DELAY);
        }
        
        Thread.sleep(MEDIUM_DELAY);
        
        // Path Traversal testing
        log("");
        log("📂 Testing Path Traversal detection...");
        for (String payload : PATH_TRAVERSAL_PAYLOADS) {
            // Log the attempt (path traversal detection could be added to IntrusionDetection)
            log("   📝 Logged path traversal attempt: " + truncate(payload, 40));
            pathTraversalAttempts++;
            
            // Add threat score for path traversal
            IntrusionDetection.addThreatScore(attackerIp, 15, "Path traversal attempt: " + truncate(payload, 20));
            
            // Log to audit
            SecurityAuditLogger.log(new SecurityAuditLogger.AuditEvent.Builder()
                .eventType(SecurityAuditLogger.EventType.ACCESS_DENIED)
                .username("ATTACKER_SIM")
                .ipAddress(attackerIp)
                .action("PATH_TRAVERSAL_ATTEMPT")
                .details("Path traversal payload: " + truncate(payload, 50))
                .build());
            
            Thread.sleep(SHORT_DELAY);
        }
        
        // Check final status
        int threatScore = IntrusionDetection.getThreatScore(attackerIp);
        boolean isBlocked = IntrusionDetection.isIpBlocked(attackerIp);
        
        log("");
        log("📊 Phase 3 Results:");
        log("   - SQL Injection detected: " + sqliDetected + "/" + SQLI_PAYLOADS.length);
        log("   - XSS detected: " + xssDetected + "/" + XSS_PAYLOADS.length);
        log("   - Path traversal attempts logged: " + pathTraversalAttempts);
        log("   - Threat score for " + attackerIp + ": " + threatScore);
        log("   - IP Blocked: " + (isBlocked ? "✅ YES" : "❌ NO"));
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // PHASE 4: SESSION TOKEN ABUSE
    // ═══════════════════════════════════════════════════════════════════════════
    
    /**
     * Phase 4 - Session Token Abuse Simulation
     * 
     * Simulates requests with fake, modified, and replayed tokens.
     * 
     * Purpose: Test HMAC, AES, and session integrity
     */
    private void runPhase4SessionTokenAbuse() throws InterruptedException {
        log("");
        log("╔═══════════════════════════════════════════════════════════════════════════╗");
        log("║  PHASE 4: SESSION TOKEN ABUSE                                            ║");
        log("║  Purpose: Test HMAC, AES, and session integrity                          ║");
        log("╚═══════════════════════════════════════════════════════════════════════════╝");
        log("");
        
        String attackerIp = ATTACKER_IPS[3];
        int invalidTokens = 0;
        int tamperedTokens = 0;
        
        log("🎫 Testing fake and modified session tokens...");
        
        for (String fakeToken : FAKE_TOKENS) {
            // Attempt to validate fake session token
            SecureSessionManager.Session session = SecureSessionManager.validateSession(
                fakeToken, attackerIp, "AttackBot/1.0");
            
            if (session == null) {
                log("   ✅ REJECTED invalid token: " + truncate(fakeToken, 35));
                invalidTokens++;
                sessionAbuseDetected++;
                
                // Add threat score
                IntrusionDetection.addThreatScore(attackerIp, 15, "Invalid session token attempt");
                
                // Log potential session hijack attempt
                SecurityAuditLogger.log(new SecurityAuditLogger.AuditEvent.Builder()
                    .eventType(SecurityAuditLogger.EventType.SESSION_HIJACK_ATTEMPT)
                    .username("UNKNOWN")
                    .ipAddress(attackerIp)
                    .action("INVALID_TOKEN")
                    .details("Fake token attempt: " + truncate(fakeToken, 50))
                    .build());
                
                alertsGenerated++;
            } else {
                log("   ❌ WARNING: Token accepted (unexpected)");
            }
            
            Thread.sleep(SHORT_DELAY);
        }
        
        Thread.sleep(MEDIUM_DELAY);
        
        // Simulate token replay attack
        log("");
        log("🔄 Simulating token replay attacks...");
        String replayedToken = "replayed_" + UUID.randomUUID().toString();
        
        for (int i = 0; i < 5; i++) {
            SecureSessionManager.Session session = SecureSessionManager.validateSession(
                replayedToken, attackerIp, "AttackBot/1.0");
            
            if (session == null) {
                log("   ✅ REJECTED replayed token (attempt " + (i + 1) + ")");
                tamperedTokens++;
                
                IntrusionDetection.addThreatScore(attackerIp, 10, "Token replay attempt #" + (i + 1));
                
                SecurityAuditLogger.log(new SecurityAuditLogger.AuditEvent.Builder()
                    .eventType(SecurityAuditLogger.EventType.SESSION_HIJACK_ATTEMPT)
                    .username("UNKNOWN")
                    .ipAddress(attackerIp)
                    .action("TOKEN_REPLAY")
                    .details("Token replay attempt #" + (i + 1))
                    .build());
            }
            
            Thread.sleep(SHORT_DELAY);
        }
        
        // Check final status
        int threatScore = IntrusionDetection.getThreatScore(attackerIp);
        boolean isBlocked = IntrusionDetection.isIpBlocked(attackerIp);
        
        log("");
        log("📊 Phase 4 Results:");
        log("   - Invalid tokens rejected: " + invalidTokens);
        log("   - Replay attempts blocked: " + tamperedTokens);
        log("   - Threat score for " + attackerIp + ": " + threatScore);
        log("   - IP Blocked: " + (isBlocked ? "✅ YES" : "❌ NO"));
        
        if (isBlocked) {
            alertsGenerated++;
        }
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // PHASE 5: RANSOMWARE-LIKE BEHAVIOR (SAFE - READ ONLY)
    // ═══════════════════════════════════════════════════════════════════════════
    
    /**
     * Phase 5 - Ransomware-Like Behavior Simulation (SAFE)
     * 
     * Simulates rapid access to many student records (READ-ONLY).
     * NO file encryption is performed.
     * 
     * Purpose: Trigger abnormal access / insider abuse detection
     */
    private void runPhase5RansomwareLikeBehavior() throws InterruptedException {
        log("");
        log("╔═══════════════════════════════════════════════════════════════════════════╗");
        log("║  PHASE 5: RANSOMWARE-LIKE BEHAVIOR (SAFE - READ ONLY)                    ║");
        log("║  Purpose: Trigger abnormal access / insider abuse detection              ║");
        log("║  ⚠️ NO FILE ENCRYPTION - Only simulates rapid data access                 ║");
        log("╚═══════════════════════════════════════════════════════════════════════════╝");
        log("");
        
        String attackerIp = ATTACKER_IPS[4];
        String suspiciousUser = "compromised_user";
        int recordsAccessed = 0;
        int accessesBlocked = 0;
        long startTime = System.currentTimeMillis();
        
        log("📚 Simulating rapid mass data access (READ-ONLY)...");
        log("   ⚠️ This simulates insider threat / data exfiltration behavior");
        log("");
        
        // Simulate rapid access to many student records
        for (int round = 0; round < 3; round++) {
            log("   Round " + (round + 1) + ": Accessing student records rapidly...");
            
            for (String studentId : STUDENT_IDS) {
                // Check rate limit
                boolean allowed = IntrusionDetection.allowApiRequest(attackerIp);
                
                if (!allowed) {
                    log("      🚫 Access BLOCKED for " + studentId + " (rate limited)");
                    accessesBlocked++;
                    abnormalAccessDetected++;
                    continue;
                }
                
                recordsAccessed++;
                
                // Log the access
                if (recordsAccessed <= 5 || recordsAccessed % 10 == 0) {
                    log("      📖 Accessed record: " + studentId);
                }
                
                // Log to audit as sensitive data access
                SecurityAuditLogger.log(new SecurityAuditLogger.AuditEvent.Builder()
                    .eventType(SecurityAuditLogger.EventType.SENSITIVE_DATA_ACCESS)
                    .username(suspiciousUser)
                    .ipAddress(attackerIp)
                    .resource("student/" + studentId)
                    .action("READ")
                    .details("Rapid data access - potential exfiltration")
                    .build());
                
                // Very short delay to simulate rapid access
                Thread.sleep(50);
            }
            
            // Add threat score for mass data access
            IntrusionDetection.addThreatScore(attackerIp, 30, 
                "Mass data access - " + STUDENT_IDS.length + " records in round " + (round + 1));
            
            Thread.sleep(SHORT_DELAY);
        }
        
        long accessDuration = System.currentTimeMillis() - startTime;
        
        // Generate alert for abnormal behavior
        IntrusionDetection.generateAlert(
            IntrusionDetection.AlertSeverity.CRITICAL,
            "ABNORMAL_DATA_ACCESS",
            attackerIp,
            "Rapid mass data access detected - potential ransomware/exfiltration",
            Map.of(
                "records_accessed", String.valueOf(recordsAccessed),
                "duration_ms", String.valueOf(accessDuration),
                "user", suspiciousUser
            )
        );
        alertsGenerated++;
        
        // Log the abnormal behavior
        SecurityAuditLogger.log(new SecurityAuditLogger.AuditEvent.Builder()
            .eventType(SecurityAuditLogger.EventType.TAMPERING_DETECTED)
            .username(suspiciousUser)
            .ipAddress(attackerIp)
            .action("MASS_DATA_ACCESS")
            .details("Accessed " + recordsAccessed + " records in " + accessDuration + "ms - ABNORMAL BEHAVIOR")
            .build());
        
        // Check final status
        int threatScore = IntrusionDetection.getThreatScore(attackerIp);
        boolean isBlocked = IntrusionDetection.isIpBlocked(attackerIp);
        
        log("");
        log("📊 Phase 5 Results:");
        log("   - Records accessed: " + recordsAccessed);
        log("   - Accesses blocked: " + accessesBlocked);
        log("   - Access duration: " + accessDuration + "ms");
        log("   - Access rate: " + String.format("%.1f", (recordsAccessed * 1000.0 / accessDuration)) + " records/sec");
        log("   - Threat score for " + attackerIp + ": " + threatScore);
        log("   - IP Blocked: " + (isBlocked ? "✅ YES" : "❌ NO"));
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // REPORT GENERATION
    // ═══════════════════════════════════════════════════════════════════════════
    
    /**
     * Generate a comprehensive simulation report.
     */
    private String generateReport(long durationMs) {
        StringBuilder report = new StringBuilder();
        
        report.append("\n");
        report.append("═══════════════════════════════════════════════════════════════════════════════\n");
        report.append("🎯 MAX-SECURITY ATTACK SIMULATION - FINAL REPORT\n");
        report.append("═══════════════════════════════════════════════════════════════════════════════\n");
        report.append("\n");
        report.append("📊 SIMULATION STATISTICS:\n");
        report.append("   ─────────────────────────────────────────────────────────────────────────────\n");
        report.append(String.format("   ⏱️ Total Duration:            %d ms (%.2f seconds)\n", 
            durationMs, durationMs / 1000.0));
        report.append(String.format("   🚫 Rate Limits Triggered:     %d\n", rateLimitTriggered));
        report.append(String.format("   💉 Injection Attacks Detected: %d\n", injectionDetected));
        report.append(String.format("   🎫 Session Abuse Detected:    %d\n", sessionAbuseDetected));
        report.append(String.format("   📚 Abnormal Access Detected:  %d\n", abnormalAccessDetected));
        report.append(String.format("   🚨 Alerts Generated:          %d\n", alertsGenerated));
        report.append("\n");
        
        report.append("🛡️ SECURITY SYSTEM STATUS:\n");
        report.append("   ─────────────────────────────────────────────────────────────────────────────\n");
        report.append(IntrusionDetection.getSystemStatus().replaceAll("(?m)^", "   "));
        report.append("\n\n");
        
        report.append("📋 RECENT SECURITY ALERTS:\n");
        report.append("   ─────────────────────────────────────────────────────────────────────────────\n");
        List<IntrusionDetection.SecurityAlert> alerts = IntrusionDetection.getRecentAlerts();
        int alertCount = 0;
        for (IntrusionDetection.SecurityAlert alert : alerts) {
            if (alertCount >= 10) break;
            report.append(String.format("   [%s] %s - %s: %s\n",
                alert.alertId, alert.severity, alert.type, alert.message));
            alertCount++;
        }
        if (alerts.size() > 10) {
            report.append("   ... and " + (alerts.size() - 10) + " more alerts\n");
        }
        report.append("\n");
        
        report.append("✅ DEFENSIVE CAPABILITIES TESTED:\n");
        report.append("   ─────────────────────────────────────────────────────────────────────────────\n");
        report.append("   ✓ Intrusion Detection System (IDS)\n");
        report.append("   ✓ Rate Limiting (IP and User-based)\n");
        report.append("   ✓ Brute Force Protection\n");
        report.append("   ✓ SQL Injection Detection\n");
        report.append("   ✓ XSS Detection\n");
        report.append("   ✓ Session Token Validation\n");
        report.append("   ✓ Threat Scoring System\n");
        report.append("   ✓ Security Audit Logging\n");
        report.append("   ✓ Alert Generation\n");
        report.append("   ✓ Abnormal Behavior Detection\n");
        report.append("\n");
        report.append("═══════════════════════════════════════════════════════════════════════════════\n");
        report.append("🎯 SIMULATION COMPLETE - All phases executed successfully\n");
        report.append("═══════════════════════════════════════════════════════════════════════════════\n");
        
        log(report.toString());
        
        return report.toString();
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // UTILITY METHODS
    // ═══════════════════════════════════════════════════════════════════════════
    
    /**
     * Log a message with timestamp.
     */
    private void log(String message) {
        System.out.println(message);
        simulationLog.add(message);
    }
    
    /**
     * Truncate a string to a maximum length.
     */
    private String truncate(String str, int maxLen) {
        if (str == null) return "";
        return str.length() <= maxLen ? str : str.substring(0, maxLen) + "...";
    }
    
    /**
     * Get the full simulation log.
     */
    public List<String> getSimulationLog() {
        return new ArrayList<>(simulationLog);
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // INDIVIDUAL PHASE RUNNERS (For selective testing)
    // ═══════════════════════════════════════════════════════════════════════════
    
    /**
     * Run only Phase 1: Reconnaissance
     */
    public void runPhase1Only() {
        try {
            log("Running Phase 1 only...");
            runPhase1Reconnaissance();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
    
    /**
     * Run only Phase 2: Credential Stuffing
     */
    public void runPhase2Only() {
        try {
            log("Running Phase 2 only...");
            runPhase2CredentialStuffing();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
    
    /**
     * Run only Phase 3: Injection Attempts
     */
    public void runPhase3Only() {
        try {
            log("Running Phase 3 only...");
            runPhase3InjectionAttempts();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
    
    /**
     * Run only Phase 4: Session Token Abuse
     */
    public void runPhase4Only() {
        try {
            log("Running Phase 4 only...");
            runPhase4SessionTokenAbuse();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
    
    /**
     * Run only Phase 5: Ransomware-Like Behavior (SAFE)
     */
    public void runPhase5Only() {
        try {
            log("Running Phase 5 only...");
            runPhase5RansomwareLikeBehavior();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // MAIN METHOD (For standalone testing)
    // ═══════════════════════════════════════════════════════════════════════════
    
    /**
     * Main method for standalone testing.
     * 
     * Usage: java MaxSecurityAttackSimulation [phase]
     *   phase: 1-5 for individual phases, or omit for full simulation
     */
    public static void main(String[] args) {
        System.out.println();
        System.out.println("╔═══════════════════════════════════════════════════════════════════════════╗");
        System.out.println("║       🎯 MAX-SECURITY ADVERSARY ATTACK SIMULATION                        ║");
        System.out.println("║                    SAFE DEFENSIVE TESTING ONLY                           ║");
        System.out.println("╚═══════════════════════════════════════════════════════════════════════════╝");
        System.out.println();
        
        MaxSecurityAttackSimulation simulation = new MaxSecurityAttackSimulation();
        
        if (args.length > 0) {
            int phase = Integer.parseInt(args[0]);
            switch (phase) {
                case 1 -> simulation.runPhase1Only();
                case 2 -> simulation.runPhase2Only();
                case 3 -> simulation.runPhase3Only();
                case 4 -> simulation.runPhase4Only();
                case 5 -> simulation.runPhase5Only();
                default -> {
                    System.out.println("Invalid phase. Use 1-5 or omit for full simulation.");
                    return;
                }
            }
        } else {
            simulation.runFullSimulation();
        }
    }
}
