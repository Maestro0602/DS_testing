package com.itc.studentmgmt.security;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 🛡️ INTRUSION DETECTION & RATE LIMITING SYSTEM
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * Real-time threat detection and prevention:
 * 
 * ╔═══════════════════════════════════════════════════════════════════════════╗
 * ║  ⏱️ Sliding Window Rate Limiting                                          ║
 * ║  🚨 Brute Force Attack Detection                                          ║
 * ║  🌐 IP-based Blocking                                                     ║
 * ║  👤 User-based Rate Limiting                                              ║
 * ║  📊 Real-time Threat Scoring                                              ║
 * ║  🔔 Automatic Alert Generation                                            ║
 * ╚═══════════════════════════════════════════════════════════════════════════╝
 * 
 * @author Security Team
 * @version 2.0.0
 */
public class IntrusionDetection {
    
    // ═══════════════════════════════════════════════════════════════════════════
    // CONFIGURATION
    // ═══════════════════════════════════════════════════════════════════════════
    
    // Rate limiting windows
    private static final Duration LOGIN_WINDOW = Duration.ofMinutes(15);
    private static final Duration API_WINDOW = Duration.ofMinutes(1);
    private static final Duration BLOCK_DURATION = Duration.ofHours(1);
    
    // Thresholds
    private static final int MAX_LOGIN_ATTEMPTS_PER_IP = 10;
    private static final int MAX_LOGIN_ATTEMPTS_PER_USER = 5;
    private static final int MAX_API_REQUESTS_PER_MINUTE = 100;
    private static final int BRUTE_FORCE_THRESHOLD = 20;
    private static final int THREAT_SCORE_BLOCK_THRESHOLD = 100;
    
    // Data structures
    private static final Map<String, RateLimitBucket> IP_LOGIN_BUCKETS = new ConcurrentHashMap<>();
    private static final Map<String, RateLimitBucket> USER_LOGIN_BUCKETS = new ConcurrentHashMap<>();
    private static final Map<String, RateLimitBucket> API_RATE_BUCKETS = new ConcurrentHashMap<>();
    private static final Map<String, BlockedEntity> BLOCKED_IPS = new ConcurrentHashMap<>();
    private static final Map<String, ThreatScore> THREAT_SCORES = new ConcurrentHashMap<>();
    private static final List<SecurityAlert> RECENT_ALERTS = new CopyOnWriteArrayList<>();
    
    // Cleanup scheduler
    private static final ScheduledExecutorService CLEANUP_SCHEDULER = 
        Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "IDS-Cleanup");
            t.setDaemon(true);
            return t;
        });
    
    static {
        // Schedule periodic cleanup
        CLEANUP_SCHEDULER.scheduleAtFixedRate(
            IntrusionDetection::cleanup, 5, 5, TimeUnit.MINUTES);
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // RATE LIMIT BUCKET
    // ═══════════════════════════════════════════════════════════════════════════
    
    private static class RateLimitBucket {
        private final Queue<Instant> requests = new ConcurrentLinkedQueue<>();
        private final Duration window;
        private final int maxRequests;
        
        RateLimitBucket(Duration window, int maxRequests) {
            this.window = window;
            this.maxRequests = maxRequests;
        }
        
        synchronized boolean tryAcquire() {
            Instant now = Instant.now();
            Instant windowStart = now.minus(window);
            
            // Remove old entries
            while (!requests.isEmpty() && requests.peek().isBefore(windowStart)) {
                requests.poll();
            }
            
            if (requests.size() < maxRequests) {
                requests.add(now);
                return true;
            }
            return false;
        }
        
        int getCurrentCount() {
            Instant windowStart = Instant.now().minus(window);
            requests.removeIf(t -> t.isBefore(windowStart));
            return requests.size();
        }
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // BLOCKED ENTITY
    // ═══════════════════════════════════════════════════════════════════════════
    
    private static class BlockedEntity {
        final String identifier;
        final Instant blockedAt;
        final Instant blockedUntil;
        final String reason;
        
        BlockedEntity(String identifier, Duration blockDuration, String reason) {
            this.identifier = identifier;
            this.blockedAt = Instant.now();
            this.blockedUntil = blockedAt.plus(blockDuration);
            this.reason = reason;
        }
        
        boolean isExpired() {
            return Instant.now().isAfter(blockedUntil);
        }
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // THREAT SCORE
    // ═══════════════════════════════════════════════════════════════════════════
    
    private static class ThreatScore {
        final String identifier;
        private final AtomicInteger score = new AtomicInteger(0);
        private Instant lastUpdate = Instant.now();
        private final List<String> indicators = new CopyOnWriteArrayList<>();
        
        ThreatScore(String identifier) {
            this.identifier = identifier;
        }
        
        void addScore(int points, String indicator) {
            score.addAndGet(points);
            lastUpdate = Instant.now();
            indicators.add(String.format("[%s] %s (+%d)", Instant.now(), indicator, points));
            
            // Keep only last 20 indicators
            while (indicators.size() > 20) {
                indicators.remove(0);
            }
        }
        
        int getScore() {
            // Decay score over time (halve every hour)
            long hoursSinceUpdate = Duration.between(lastUpdate, Instant.now()).toHours();
            int currentScore = score.get();
            for (int i = 0; i < hoursSinceUpdate; i++) {
                currentScore /= 2;
            }
            return currentScore;
        }
        
        List<String> getIndicators() {
            return new ArrayList<>(indicators);
        }
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // SECURITY ALERT
    // ═══════════════════════════════════════════════════════════════════════════
    
    public enum AlertSeverity {
        LOW, MEDIUM, HIGH, CRITICAL
    }
    
    public static class SecurityAlert {
        public final String alertId;
        public final Instant timestamp;
        public final AlertSeverity severity;
        public final String type;
        public final String source;
        public final String message;
        public final Map<String, String> details;
        
        SecurityAlert(AlertSeverity severity, String type, String source, 
                     String message, Map<String, String> details) {
            this.alertId = UUID.randomUUID().toString().substring(0, 8);
            this.timestamp = Instant.now();
            this.severity = severity;
            this.type = type;
            this.source = source;
            this.message = message;
            this.details = Collections.unmodifiableMap(new HashMap<>(details));
        }
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // RATE LIMITING API
    // ═══════════════════════════════════════════════════════════════════════════
    
    /**
     * Check if login attempt is allowed for an IP.
     */
    public static boolean allowLoginAttempt(String ipAddress) {
        // Check if IP is blocked
        if (isIpBlocked(ipAddress)) {
            return false;
        }
        
        RateLimitBucket bucket = IP_LOGIN_BUCKETS.computeIfAbsent(
            ipAddress, k -> new RateLimitBucket(LOGIN_WINDOW, MAX_LOGIN_ATTEMPTS_PER_IP));
        
        if (!bucket.tryAcquire()) {
            // Rate limit exceeded - potential brute force
            addThreatScore(ipAddress, 20, "Login rate limit exceeded");
            generateAlert(AlertSeverity.HIGH, "RATE_LIMIT", ipAddress,
                "Login rate limit exceeded from IP", 
                Map.of("attempts", String.valueOf(bucket.getCurrentCount())));
            return false;
        }
        
        return true;
    }
    
    /**
     * Check if login attempt is allowed for a user.
     */
    public static boolean allowUserLoginAttempt(String username) {
        RateLimitBucket bucket = USER_LOGIN_BUCKETS.computeIfAbsent(
            username, k -> new RateLimitBucket(LOGIN_WINDOW, MAX_LOGIN_ATTEMPTS_PER_USER));
        
        return bucket.tryAcquire();
    }
    
    /**
     * Check if API request is allowed.
     */
    public static boolean allowApiRequest(String ipAddress) {
        if (isIpBlocked(ipAddress)) {
            return false;
        }
        
        RateLimitBucket bucket = API_RATE_BUCKETS.computeIfAbsent(
            ipAddress, k -> new RateLimitBucket(API_WINDOW, MAX_API_REQUESTS_PER_MINUTE));
        
        return bucket.tryAcquire();
    }
    
    /**
     * Record a failed login attempt.
     */
    public static void recordFailedLogin(String ipAddress, String username) {
        addThreatScore(ipAddress, 5, "Failed login for user: " + 
            (username.length() > 3 ? username.substring(0, 3) + "***" : "***"));
        
        // Check for brute force pattern
        ThreatScore threat = THREAT_SCORES.get(ipAddress);
        if (threat != null && threat.getScore() >= BRUTE_FORCE_THRESHOLD) {
            blockIp(ipAddress, "Brute force attack detected");
            
            SecurityAuditLogger.logSecurityEvent(
                SecurityAuditLogger.EventType.BRUTE_FORCE_DETECTED,
                username, ipAddress,
                "Brute force attack detected and blocked"
            );
            
            // Send Telegram alert for brute force
            TelegramAlertService.alertBruteForce(ipAddress, username, threat.getScore());
        }
    }
    
    /**
     * Record a successful login (reduces threat score).
     */
    public static void recordSuccessfulLogin(String ipAddress) {
        ThreatScore threat = THREAT_SCORES.get(ipAddress);
        if (threat != null) {
            threat.score.updateAndGet(s -> Math.max(0, s - 10));
        }
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // BLOCKING API
    // ═══════════════════════════════════════════════════════════════════════════
    
    /**
     * Check if an IP is currently blocked.
     */
    public static boolean isIpBlocked(String ipAddress) {
        BlockedEntity blocked = BLOCKED_IPS.get(ipAddress);
        if (blocked != null) {
            if (blocked.isExpired()) {
                BLOCKED_IPS.remove(ipAddress);
                return false;
            }
            return true;
        }
        return false;
    }
    
    /**
     * Block an IP address.
     */
    public static void blockIp(String ipAddress, String reason) {
        BLOCKED_IPS.put(ipAddress, new BlockedEntity(ipAddress, BLOCK_DURATION, reason));
        
        generateAlert(AlertSeverity.CRITICAL, "IP_BLOCKED", ipAddress,
            "IP address blocked: " + reason,
            Map.of("duration", BLOCK_DURATION.toString()));
        
        // Send Telegram alert for IP blocked
        TelegramAlertService.alertIpBlocked(ipAddress, reason);
        
        System.out.println("🚫 IP BLOCKED: " + ipAddress + " - " + reason);
    }
    
    /**
     * Manually unblock an IP address.
     */
    public static void unblockIp(String ipAddress) {
        BLOCKED_IPS.remove(ipAddress);
        System.out.println("✅ IP UNBLOCKED: " + ipAddress);
    }
    
    /**
     * Get block info for an IP.
     */
    public static String getBlockInfo(String ipAddress) {
        BlockedEntity blocked = BLOCKED_IPS.get(ipAddress);
        if (blocked != null && !blocked.isExpired()) {
            long remainingMinutes = Duration.between(Instant.now(), blocked.blockedUntil).toMinutes();
            return String.format("Blocked for %d more minutes. Reason: %s", 
                remainingMinutes, blocked.reason);
        }
        return "Not blocked";
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // THREAT SCORING API
    // ═══════════════════════════════════════════════════════════════════════════
    
    /**
     * Add threat score for an identifier.
     */
    public static void addThreatScore(String identifier, int points, String indicator) {
        ThreatScore threat = THREAT_SCORES.computeIfAbsent(
            identifier, ThreatScore::new);
        threat.addScore(points, indicator);
        
        // Check if should be blocked
        if (threat.getScore() >= THREAT_SCORE_BLOCK_THRESHOLD) {
            blockIp(identifier, "Threat score exceeded threshold");
        }
    }
    
    /**
     * Get current threat score for an identifier.
     */
    public static int getThreatScore(String identifier) {
        ThreatScore threat = THREAT_SCORES.get(identifier);
        return threat != null ? threat.getScore() : 0;
    }
    
    /**
     * Get threat indicators for an identifier.
     */
    public static List<String> getThreatIndicators(String identifier) {
        ThreatScore threat = THREAT_SCORES.get(identifier);
        return threat != null ? threat.getIndicators() : Collections.emptyList();
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // ALERT API
    // ═══════════════════════════════════════════════════════════════════════════
    
    /**
     * Generate a security alert.
     */
    public static void generateAlert(AlertSeverity severity, String type, 
                                     String source, String message,
                                     Map<String, String> details) {
        SecurityAlert alert = new SecurityAlert(severity, type, source, message, details);
        RECENT_ALERTS.add(alert);
        
        // Keep only last 100 alerts
        while (RECENT_ALERTS.size() > 100) {
            RECENT_ALERTS.remove(0);
        }
        
        // Log to audit
        SecurityAuditLogger.log(new SecurityAuditLogger.AuditEvent.Builder()
            .eventType(severity == AlertSeverity.CRITICAL ? 
                SecurityAuditLogger.EventType.TAMPERING_DETECTED :
                SecurityAuditLogger.EventType.ACCESS_DENIED)
            .ipAddress(source)
            .action(type)
            .details(message)
            .build());
        
        // Print critical alerts
        if (severity == AlertSeverity.CRITICAL || severity == AlertSeverity.HIGH) {
            System.out.println(String.format("🚨 [%s] %s ALERT: %s - %s",
                alert.alertId, severity, type, message));
        }
    }
    
    /**
     * Get recent security alerts.
     */
    public static List<SecurityAlert> getRecentAlerts() {
        return new ArrayList<>(RECENT_ALERTS);
    }
    
    /**
     * Get alerts filtered by severity.
     */
    public static List<SecurityAlert> getAlertsBySeverity(AlertSeverity minSeverity) {
        return RECENT_ALERTS.stream()
            .filter(a -> a.severity.ordinal() >= minSeverity.ordinal())
            .toList();
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // ANOMALY DETECTION
    // ═══════════════════════════════════════════════════════════════════════════
    
    /**
     * Detect suspicious patterns in login attempts.
     */
    public static void analyzeLoginPattern(String ipAddress, String username, 
                                          String userAgent, boolean success) {
        // Check for user agent anomalies
        if (userAgent != null) {
            if (userAgent.contains("curl") || userAgent.contains("wget") ||
                userAgent.contains("python") || userAgent.contains("bot")) {
                addThreatScore(ipAddress, 10, "Suspicious user agent: " + 
                    userAgent.substring(0, Math.min(30, userAgent.length())));
            }
        }
        
        // Check for time-based anomalies (e.g., rapid attempts)
        RateLimitBucket ipBucket = IP_LOGIN_BUCKETS.get(ipAddress);
        if (ipBucket != null && ipBucket.getCurrentCount() > 3) {
            // More than 3 attempts in short window - suspicious
            addThreatScore(ipAddress, 5, "Rapid login attempts");
        }
        
        // Record the attempt
        if (!success) {
            recordFailedLogin(ipAddress, username);
        } else {
            recordSuccessfulLogin(ipAddress);
        }
    }
    
    /**
     * Check for SQL injection patterns.
     * Returns true if SQL injection is detected.
     */
    public static boolean detectSqlInjection(String input) {
        return detectSqlInjection(input, "UNKNOWN");
    }
    
    /**
     * Check for SQL injection patterns with IP tracking.
     */
    public static boolean detectSqlInjection(String input, String ipAddress) {
        if (input == null) return false;
        
        String[] sqlPatterns = {
            "(?i).*('|\")?\\s*(or|and)\\s+('|\")?\\d+('|\")?\\s*=\\s*('|\")?\\d+.*",
            "(?i).*union\\s+(all\\s+)?select.*",
            "(?i).*insert\\s+into.*",
            "(?i).*delete\\s+from.*",
            "(?i).*drop\\s+(table|database).*",
            "(?i).*;\\s*(drop|delete|update|insert).*",
            "(?i).*'\\s*(or|and)\\s+'.*'\\s*=\\s*'.*",
            "(?i).*--.*"
        };
        
        for (String pattern : sqlPatterns) {
            if (input.matches(pattern)) {
                // Send Telegram alert for SQL injection
                TelegramAlertService.alertSqlInjection(ipAddress, input);
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Check for XSS patterns.
     * Returns true if XSS is detected.
     */
    public static boolean detectXss(String input) {
        return detectXss(input, "UNKNOWN");
    }
    
    /**
     * Check for XSS patterns with IP tracking.
     */
    public static boolean detectXss(String input, String ipAddress) {
        if (input == null) return false;
        
        String[] xssPatterns = {
            "(?i).*<script.*>.*</script>.*",
            "(?i).*javascript:.*",
            "(?i).*on(load|error|click|mouseover)\\s*=.*",
            "(?i).*<iframe.*>.*",
            "(?i).*<img.*onerror.*>.*"
        };
        
        for (String pattern : xssPatterns) {
            if (input.matches(pattern)) {
                // Send Telegram alert for XSS
                TelegramAlertService.alertXssAttempt(ipAddress, input);
                return true;
            }
        }
        
        return false;
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // CLEANUP
    // ═══════════════════════════════════════════════════════════════════════════
    
    /**
     * Clean up expired entries.
     */
    private static void cleanup() {
        // Remove expired blocks
        BLOCKED_IPS.entrySet().removeIf(e -> e.getValue().isExpired());
        
        // Remove old rate limit buckets (not accessed in 30 minutes)
        Instant threshold = Instant.now().minus(Duration.ofMinutes(30));
        IP_LOGIN_BUCKETS.entrySet().removeIf(e -> e.getValue().getCurrentCount() == 0);
        USER_LOGIN_BUCKETS.entrySet().removeIf(e -> e.getValue().getCurrentCount() == 0);
        API_RATE_BUCKETS.entrySet().removeIf(e -> e.getValue().getCurrentCount() == 0);
        
        // Remove old threat scores
        THREAT_SCORES.entrySet().removeIf(e -> e.getValue().getScore() == 0);
    }
    
    /**
     * Get system status for monitoring.
     */
    public static String getSystemStatus() {
        return String.format(
            "IDS Status:\n" +
            "  - Blocked IPs: %d\n" +
            "  - Active IP Rate Limits: %d\n" +
            "  - Active User Rate Limits: %d\n" +
            "  - Tracked Threats: %d\n" +
            "  - Recent Alerts: %d",
            BLOCKED_IPS.size(),
            IP_LOGIN_BUCKETS.size(),
            USER_LOGIN_BUCKETS.size(),
            THREAT_SCORES.size(),
            RECENT_ALERTS.size()
        );
    }
}
