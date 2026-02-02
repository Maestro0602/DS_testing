package com.itc.studentmgmt.security;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * 🚨 TELEGRAM SECURITY ALERT SERVICE
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * Sends real-time security alerts to Telegram when attacks are detected:
 * 
 * ╔═══════════════════════════════════════════════════════════════════════════╗
 * ║  🔴 CRITICAL: SQL Injection, Brute Force, Ransomware                      ║
 * ║  🟠 HIGH: XSS Attacks, Session Hijacking, Rate Limit Exceeded             ║
 * ║  🟡 MEDIUM: Multiple Failed Logins, Suspicious Patterns                   ║
 * ║  🟢 LOW: Rate Limiting, Blocked IPs                                       ║
 * ╚═══════════════════════════════════════════════════════════════════════════╝
 * 
 * Uses the same Telegram bot configuration as TwoFactorAuthService.
 * 
 * @author Security Team
 * @version 1.0.0
 */
public class TelegramAlertService {
    
    // Use the same configuration as TwoFactorAuthService
    private static final String TELEGRAM_BOT_TOKEN = getEnvOrDefault(
        "TELEGRAM_BOT_TOKEN", 
        "8339279272:AAHN7KQVt9DAanb-8EielTEGw65uk0IySoU"
    );
    
    private static final String TELEGRAM_CHAT_ID = getEnvOrDefault(
        "TELEGRAM_CHAT_ID", 
        "1006124574"
    );
    
    // Async executor for non-blocking alert sending
    private static final ExecutorService alertExecutor = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "TelegramAlertService");
        t.setDaemon(true);
        return t;
    });
    
    // Enable/disable alerts
    private static volatile boolean alertsEnabled = true;
    
    // Alert severity levels
    public enum AlertSeverity {
        CRITICAL("🔴 CRITICAL"),
        HIGH("🟠 HIGH"),
        MEDIUM("🟡 MEDIUM"),
        LOW("🟢 LOW"),
        INFO("ℹ️ INFO");
        
        private final String emoji;
        
        AlertSeverity(String emoji) {
            this.emoji = emoji;
        }
        
        public String getEmoji() {
            return emoji;
        }
    }
    
    /**
     * Send a security alert asynchronously (non-blocking).
     */
    public static void sendAlertAsync(AlertSeverity severity, String attackType, 
                                       String sourceIp, String message, Map<String, String> details) {
        if (!alertsEnabled || !isConfigured()) {
            return;
        }
        
        alertExecutor.submit(() -> sendAlert(severity, attackType, sourceIp, message, details));
    }
    
    /**
     * Send a security alert synchronously.
     */
    public static boolean sendAlert(AlertSeverity severity, String attackType, 
                                     String sourceIp, String message, Map<String, String> details) {
        if (!isConfigured()) {
            System.out.println("⚠️ Telegram not configured - alert not sent");
            return false;
        }
        
        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
        
        StringBuilder alertMessage = new StringBuilder();
        alertMessage.append("🚨 SECURITY ALERT 🚨\n\n");
        alertMessage.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
        alertMessage.append(severity.getEmoji()).append(" Severity: ").append(severity.name()).append("\n");
        alertMessage.append("🎯 Attack Type: ").append(attackType).append("\n");
        alertMessage.append("🌐 Source IP: ").append(sourceIp).append("\n");
        alertMessage.append("⏰ Time: ").append(timestamp).append("\n");
        alertMessage.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");
        alertMessage.append("📝 Details:\n").append(message).append("\n");
        
        if (details != null && !details.isEmpty()) {
            alertMessage.append("\n📊 Additional Info:\n");
            for (Map.Entry<String, String> entry : details.entrySet()) {
                alertMessage.append("  • ").append(entry.getKey()).append(": ").append(entry.getValue()).append("\n");
            }
        }
        
        alertMessage.append("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
        alertMessage.append("🛡️ Student Management System");
        
        return sendTelegramMessage(alertMessage.toString());
    }
    
    /**
     * Send alert for brute force attack.
     */
    public static void alertBruteForce(String ipAddress, String targetUser, int attempts) {
        sendAlertAsync(
            AlertSeverity.CRITICAL,
            "BRUTE FORCE ATTACK",
            ipAddress,
            "Multiple failed login attempts detected!\nTarget user: " + targetUser,
            Map.of(
                "Attempts", String.valueOf(attempts),
                "Action", "IP has been blocked"
            )
        );
    }
    
    /**
     * Send alert for SQL injection attempt.
     */
    public static void alertSqlInjection(String ipAddress, String payload) {
        String sanitizedPayload = payload.length() > 50 ? payload.substring(0, 50) + "..." : payload;
        sendAlertAsync(
            AlertSeverity.CRITICAL,
            "SQL INJECTION ATTEMPT",
            ipAddress,
            "SQL Injection payload detected and blocked!",
            Map.of(
                "Payload", sanitizedPayload,
                "Action", "Request blocked, IP flagged"
            )
        );
    }
    
    /**
     * Send alert for XSS attempt.
     */
    public static void alertXssAttempt(String ipAddress, String payload) {
        String sanitizedPayload = payload.length() > 50 ? payload.substring(0, 50) + "..." : payload;
        sendAlertAsync(
            AlertSeverity.HIGH,
            "XSS ATTACK ATTEMPT",
            ipAddress,
            "Cross-Site Scripting (XSS) payload detected!",
            Map.of(
                "Payload", sanitizedPayload,
                "Action", "Request sanitized and blocked"
            )
        );
    }
    
    /**
     * Send alert for session hijacking attempt.
     */
    public static void alertSessionHijack(String ipAddress, String tokenInfo) {
        sendAlertAsync(
            AlertSeverity.CRITICAL,
            "SESSION HIJACK ATTEMPT",
            ipAddress,
            "Invalid or tampered session token detected!",
            Map.of(
                "Token Info", tokenInfo.length() > 30 ? tokenInfo.substring(0, 30) + "..." : tokenInfo,
                "Action", "Session rejected"
            )
        );
    }
    
    /**
     * Send alert for IP being blocked.
     */
    public static void alertIpBlocked(String ipAddress, String reason) {
        sendAlertAsync(
            AlertSeverity.HIGH,
            "IP BLOCKED",
            ipAddress,
            "IP address has been blocked due to suspicious activity.",
            Map.of(
                "Reason", reason,
                "Duration", "1 hour"
            )
        );
    }
    
    /**
     * Send alert for abnormal data access pattern (potential ransomware/exfiltration).
     */
    public static void alertAbnormalAccess(String ipAddress, String username, int recordsAccessed, long durationMs) {
        sendAlertAsync(
            AlertSeverity.CRITICAL,
            "ABNORMAL DATA ACCESS",
            ipAddress,
            "Rapid mass data access detected - Potential data exfiltration or ransomware behavior!",
            Map.of(
                "User", username,
                "Records Accessed", String.valueOf(recordsAccessed),
                "Duration", durationMs + "ms",
                "Rate", String.format("%.1f records/sec", recordsAccessed * 1000.0 / durationMs)
            )
        );
    }
    
    /**
     * Send alert for rate limit exceeded.
     */
    public static void alertRateLimitExceeded(String ipAddress, String limitType) {
        sendAlertAsync(
            AlertSeverity.MEDIUM,
            "RATE LIMIT EXCEEDED",
            ipAddress,
            "Rate limit has been exceeded.",
            Map.of(
                "Limit Type", limitType,
                "Action", "Requests throttled"
            )
        );
    }
    
    /**
     * Send simulation start alert.
     */
    public static void alertSimulationStarted() {
        sendAlertAsync(
            AlertSeverity.INFO,
            "SIMULATION STARTED",
            "LOCAL",
            "🎯 Security attack simulation has been started.\n" +
            "This is a SAFE defensive test - no real attacks are performed.",
            Map.of(
                "Type", "MAX-SECURITY ADVERSARY SIMULATION",
                "Status", "Running..."
            )
        );
    }
    
    /**
     * Send simulation complete alert with summary.
     */
    public static void alertSimulationComplete(int rateLimits, int injections, 
                                                int sessionAbuse, int abnormalAccess, int alerts) {
        sendAlertAsync(
            AlertSeverity.INFO,
            "SIMULATION COMPLETE",
            "LOCAL",
            "🎯 Security attack simulation has completed.\n\n" +
            "📊 RESULTS:\n" +
            "• Rate Limits Triggered: " + rateLimits + "\n" +
            "• Injection Attacks Detected: " + injections + "\n" +
            "• Session Abuse Detected: " + sessionAbuse + "\n" +
            "• Abnormal Access Detected: " + abnormalAccess + "\n" +
            "• Total Alerts Generated: " + alerts,
            null
        );
    }
    
    /**
     * Send a raw message to Telegram.
     */
    private static boolean sendTelegramMessage(String message) {
        try {
            String urlString = String.format(
                "https://api.telegram.org/bot%s/sendMessage",
                TELEGRAM_BOT_TOKEN
            );
            
            URL url = new URL(urlString);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            conn.setDoOutput(true);
            conn.setConnectTimeout(10000);
            conn.setReadTimeout(10000);
            
            String params = String.format(
                "chat_id=%s&text=%s&parse_mode=HTML",
                URLEncoder.encode(TELEGRAM_CHAT_ID, StandardCharsets.UTF_8.toString()),
                URLEncoder.encode(message, StandardCharsets.UTF_8.toString())
            );
            
            try (OutputStream os = conn.getOutputStream()) {
                os.write(params.getBytes(StandardCharsets.UTF_8));
            }
            
            int responseCode = conn.getResponseCode();
            
            if (responseCode == 200) {
                System.out.println("✅ Telegram security alert sent successfully");
                return true;
            } else {
                try (BufferedReader br = new BufferedReader(
                        new InputStreamReader(conn.getErrorStream()))) {
                    StringBuilder response = new StringBuilder();
                    String line;
                    while ((line = br.readLine()) != null) {
                        response.append(line);
                    }
                    System.err.println("Telegram API error: " + response.toString());
                }
                return false;
            }
            
        } catch (Exception e) {
            System.err.println("Failed to send Telegram alert: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * Check if Telegram is configured.
     */
    public static boolean isConfigured() {
        return TELEGRAM_BOT_TOKEN != null && 
               !TELEGRAM_BOT_TOKEN.contains("YOUR_") && 
               !TELEGRAM_BOT_TOKEN.isEmpty() &&
               TELEGRAM_CHAT_ID != null && 
               !TELEGRAM_CHAT_ID.contains("YOUR_") && 
               !TELEGRAM_CHAT_ID.isEmpty();
    }
    
    /**
     * Enable or disable alerts.
     */
    public static void setAlertsEnabled(boolean enabled) {
        alertsEnabled = enabled;
        System.out.println("🔔 Telegram alerts " + (enabled ? "ENABLED" : "DISABLED"));
    }
    
    /**
     * Check if alerts are enabled.
     */
    public static boolean isAlertsEnabled() {
        return alertsEnabled && isConfigured();
    }
    
    /**
     * Get environment variable or default value.
     */
    private static String getEnvOrDefault(String key, String defaultValue) {
        String value = System.getenv(key);
        return (value != null && !value.isEmpty()) ? value : defaultValue;
    }
    
    /**
     * Test the Telegram connection.
     */
    public static boolean testConnection() {
        return sendTelegramMessage("🔔 Test Alert - Student Management System\n\nTelegram security alerts are working correctly!");
    }
}
