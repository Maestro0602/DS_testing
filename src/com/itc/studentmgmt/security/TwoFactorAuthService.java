package com.itc.studentmgmt.security;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 🔐 TWO-FACTOR AUTHENTICATION SERVICE
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * Provides 2FA functionality with multiple notification channels:
 * 
 * ╔═══════════════════════════════════════════════════════════════════════════╗
 * ║  📱 Telegram Bot Integration                                              ║
 * ║  💬 Discord Webhook Integration                                           ║
 * ║  🔢 Secure OTP Generation (6-digit codes)                                 ║
 * ║  ⏰ Time-based Code Expiration (5 minutes)                                ║
 * ║  🛡️ Rate Limiting & Brute Force Protection                               ║
 * ╚═══════════════════════════════════════════════════════════════════════════╝
 * 
 * SETUP INSTRUCTIONS:
 * 
 * 🔹 TELEGRAM SETUP:
 *    1. Open Telegram and search for @BotFather
 *    2. Send /newbot and follow the prompts to create a bot
 *    3. Copy the API token (looks like: 123456789:ABCdefGHIjklMNOpqrsTUVwxyz)
 *    4. Start a chat with your bot and send /start
 *    5. Get your Chat ID by visiting:
 *       https://api.telegram.org/bot<YOUR_TOKEN>/getUpdates
 *       Look for "chat":{"id":YOUR_CHAT_ID}
 *    6. Set environment variables or update the config below
 * 
 * 🔹 DISCORD SETUP:
 *    1. Go to your Discord server settings
 *    2. Navigate to Integrations -> Webhooks
 *    3. Click "New Webhook"
 *    4. Copy the Webhook URL
 *    5. Set environment variable or update the config below
 * 
 * @author Security Team
 * @version 1.0.0
 */
public class TwoFactorAuthService {
    
    // ═══════════════════════════════════════════════════════════════════════════
    // CONFIGURATION - Update these or use environment variables
    // ═══════════════════════════════════════════════════════════════════════════
    
    // Telegram Configuration
    // Get from @BotFather on Telegram
    private static final String TELEGRAM_BOT_TOKEN = getEnvOrDefault(
        "TELEGRAM_BOT_TOKEN", 
        "8339279272:AAHN7KQVt9DAanb-8EielTEGw65uk0IySoU"
    );
    
    // Get from https://api.telegram.org/bot<TOKEN>/getUpdates after messaging your bot
    private static final String TELEGRAM_CHAT_ID = getEnvOrDefault(
        "TELEGRAM_CHAT_ID", 
        "1006124574"
    );
    
    // Discord Configuration
    // Get from Server Settings -> Integrations -> Webhooks
    private static final String DISCORD_WEBHOOK_URL = getEnvOrDefault(
        "DISCORD_WEBHOOK_URL", 
        "YOUR_DISCORD_WEBHOOK_URL_HERE"
    );
    
    // OTP Settings
    private static final int OTP_LENGTH = 6;
    private static final long OTP_VALIDITY_MILLIS = 5 * 60 * 1000; // 5 minutes
    private static final int MAX_VERIFICATION_ATTEMPTS = 3;
    
    // Choose which channel to use: "telegram", "discord", or "both"
    private static final String NOTIFICATION_CHANNEL = getEnvOrDefault(
        "TFA_NOTIFICATION_CHANNEL", 
        "telegram"
    );
    
    // Storage for pending OTPs (in production, use database or Redis)
    private static final Map<String, OTPData> pendingOTPs = new ConcurrentHashMap<>();
    
    // Secure random for OTP generation
    private static final SecureRandom secureRandom = new SecureRandom();
    
    /**
     * OTP data structure
     */
    private static class OTPData {
        final String code;
        final long expiresAt;
        int attempts;
        
        OTPData(String code, long expiresAt) {
            this.code = code;
            this.expiresAt = expiresAt;
            this.attempts = 0;
        }
        
        boolean isExpired() {
            return System.currentTimeMillis() > expiresAt;
        }
        
        boolean hasExceededAttempts() {
            return attempts >= MAX_VERIFICATION_ATTEMPTS;
        }
    }
    
    /**
     * Result of 2FA operations
     */
    public enum TwoFactorResult {
        SUCCESS,
        INVALID_CODE,
        CODE_EXPIRED,
        TOO_MANY_ATTEMPTS,
        SEND_FAILED,
        NOT_CONFIGURED
    }
    
    /**
     * Generate and send a 2FA code to the user.
     * 
     * @param username The username requesting 2FA
     * @return TwoFactorResult indicating success or failure
     */
    public static TwoFactorResult generateAndSendCode(String username) {
        // Check if service is configured
        if (!isConfigured()) {
            System.out.println("⚠️  2FA not configured. Please set up Telegram or Discord.");
            return TwoFactorResult.NOT_CONFIGURED;
        }
        
        // Generate secure OTP
        String otp = generateOTP();
        long expiresAt = System.currentTimeMillis() + OTP_VALIDITY_MILLIS;
        
        // Store OTP
        pendingOTPs.put(username, new OTPData(otp, expiresAt));
        
        // Create message
        String message = String.format(
            "🔐 Login Verification Code\n\n" +
            "Username: %s\n" +
            "Code: %s\n\n" +
            "⏰ This code expires in 5 minutes.\n" +
            "⚠️ If you didn't request this, please secure your account!",
            username, otp
        );
        
        boolean sent = false;
        
        // Send via configured channel(s)
        switch (NOTIFICATION_CHANNEL.toLowerCase()) {
            case "telegram":
                sent = sendTelegramMessage(message);
                break;
            case "discord":
                sent = sendDiscordMessage(message);
                break;
            case "both":
                boolean telegramSent = sendTelegramMessage(message);
                boolean discordSent = sendDiscordMessage(message);
                sent = telegramSent || discordSent;
                break;
            default:
                sent = sendTelegramMessage(message);
        }
        
        if (sent) {
            System.out.println("✅ 2FA code sent via " + NOTIFICATION_CHANNEL);
            
            // Log the event to login audit
            LoginAuditLogger.logTwoFactorSuccess(username, "0.0.0.0");
                
            return TwoFactorResult.SUCCESS;
        } else {
            System.out.println("❌ Failed to send 2FA code");
            return TwoFactorResult.SEND_FAILED;
        }
    }
    
    /**
     * Verify the 2FA code entered by user.
     * 
     * @param username The username
     * @param enteredCode The code entered by user
     * @return TwoFactorResult indicating verification result
     */
    public static TwoFactorResult verifyCode(String username, String enteredCode) {
        OTPData otpData = pendingOTPs.get(username);
        
        if (otpData == null) {
            return TwoFactorResult.INVALID_CODE;
        }
        
        // Check if expired
        if (otpData.isExpired()) {
            pendingOTPs.remove(username);
            LoginAuditLogger.logTwoFactorFailure(username, "0.0.0.0", "Verification code expired");
            return TwoFactorResult.CODE_EXPIRED;
        }
        
        // Check attempts
        otpData.attempts++;
        if (otpData.hasExceededAttempts()) {
            pendingOTPs.remove(username);
            LoginAuditLogger.logTwoFactorFailure(username, "0.0.0.0", 
                "Too many failed verification attempts (" + otpData.attempts + "/" + MAX_VERIFICATION_ATTEMPTS + ")");
            return TwoFactorResult.TOO_MANY_ATTEMPTS;
        }
        
        // Timing-safe comparison
        if (constantTimeEquals(enteredCode, otpData.code)) {
            pendingOTPs.remove(username);
            LoginAuditLogger.logTwoFactorSuccess(username, "0.0.0.0");
            return TwoFactorResult.SUCCESS;
        }
        
        LoginAuditLogger.logTwoFactorFailure(username, "0.0.0.0", 
            "Invalid verification code. Attempt " + otpData.attempts + "/" + MAX_VERIFICATION_ATTEMPTS);
            
        return TwoFactorResult.INVALID_CODE;
    }
    
    /**
     * Check if 2FA service is properly configured.
     */
    public static boolean isConfigured() {
        switch (NOTIFICATION_CHANNEL.toLowerCase()) {
            case "telegram":
                return isTelegramConfigured();
            case "discord":
                return isDiscordConfigured();
            case "both":
                return isTelegramConfigured() || isDiscordConfigured();
            default:
                return isTelegramConfigured();
        }
    }
    
    /**
     * Check if Telegram is configured.
     */
    public static boolean isTelegramConfigured() {
        return TELEGRAM_BOT_TOKEN != null && 
               !TELEGRAM_BOT_TOKEN.contains("YOUR_") && 
               !TELEGRAM_BOT_TOKEN.isEmpty() &&
               TELEGRAM_CHAT_ID != null && 
               !TELEGRAM_CHAT_ID.contains("YOUR_") && 
               !TELEGRAM_CHAT_ID.isEmpty();
    }
    
    /**
     * Check if Discord is configured.
     */
    public static boolean isDiscordConfigured() {
        return DISCORD_WEBHOOK_URL != null && 
               !DISCORD_WEBHOOK_URL.contains("YOUR_") && 
               !DISCORD_WEBHOOK_URL.isEmpty() &&
               DISCORD_WEBHOOK_URL.startsWith("https://discord.com/api/webhooks/");
    }
    
    /**
     * Generate a secure random OTP.
     */
    private static String generateOTP() {
        StringBuilder otp = new StringBuilder();
        for (int i = 0; i < OTP_LENGTH; i++) {
            otp.append(secureRandom.nextInt(10));
        }
        return otp.toString();
    }
    
    /**
     * Send message via Telegram Bot API.
     */
    private static boolean sendTelegramMessage(String message) {
        if (!isTelegramConfigured()) {
            System.out.println("⚠️  Telegram not configured");
            return false;
        }
        
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
                return true;
            } else {
                // Read error response
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
            System.err.println("Failed to send Telegram message: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * Send message via Discord Webhook.
     */
    private static boolean sendDiscordMessage(String message) {
        if (!isDiscordConfigured()) {
            System.out.println("⚠️  Discord not configured");
            return false;
        }
        
        try {
            URL url = new URL(DISCORD_WEBHOOK_URL);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setDoOutput(true);
            conn.setConnectTimeout(10000);
            conn.setReadTimeout(10000);
            
            // Build Discord embed message
            String jsonPayload = String.format(
                "{\"embeds\":[{" +
                    "\"title\":\"🔐 Login Verification Code\"," +
                    "\"description\":\"%s\"," +
                    "\"color\":3447003," +
                    "\"footer\":{\"text\":\"Student Management System - 2FA\"}" +
                "}]}",
                message.replace("\"", "\\\"").replace("\n", "\\n")
            );
            
            try (OutputStream os = conn.getOutputStream()) {
                os.write(jsonPayload.getBytes(StandardCharsets.UTF_8));
            }
            
            int responseCode = conn.getResponseCode();
            return responseCode == 204 || responseCode == 200;
            
        } catch (Exception e) {
            System.err.println("Failed to send Discord message: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * Timing-safe string comparison to prevent timing attacks.
     */
    private static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) {
            return false;
        }
        
        byte[] aBytes = a.getBytes(StandardCharsets.UTF_8);
        byte[] bBytes = b.getBytes(StandardCharsets.UTF_8);
        
        if (aBytes.length != bBytes.length) {
            return false;
        }
        
        int result = 0;
        for (int i = 0; i < aBytes.length; i++) {
            result |= aBytes[i] ^ bBytes[i];
        }
        return result == 0;
    }
    
    /**
     * Get environment variable or default value.
     */
    private static String getEnvOrDefault(String key, String defaultValue) {
        String value = System.getenv(key);
        return (value != null && !value.isEmpty()) ? value : defaultValue;
    }
    
    /**
     * Clear expired OTPs (call periodically for cleanup).
     */
    public static void cleanupExpiredOTPs() {
        long now = System.currentTimeMillis();
        pendingOTPs.entrySet().removeIf(entry -> entry.getValue().expiresAt < now);
    }
    
    /**
     * Get configuration status for display.
     */
    public static String getConfigurationStatus() {
        StringBuilder status = new StringBuilder();
        status.append("\n═══════════════════════════════════════════════════════════════\n");
        status.append("                    2FA CONFIGURATION STATUS\n");
        status.append("═══════════════════════════════════════════════════════════════\n\n");
        
        status.append("📱 Telegram: ");
        if (isTelegramConfigured()) {
            status.append("✅ Configured\n");
            status.append("   Bot Token: ").append(TELEGRAM_BOT_TOKEN.substring(0, Math.min(10, TELEGRAM_BOT_TOKEN.length()))).append("...\n");
            status.append("   Chat ID: ").append(TELEGRAM_CHAT_ID).append("\n");
        } else {
            status.append("❌ Not configured\n");
            status.append("   Set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID environment variables\n");
        }
        
        status.append("\n💬 Discord: ");
        if (isDiscordConfigured()) {
            status.append("✅ Configured\n");
            status.append("   Webhook: ").append(DISCORD_WEBHOOK_URL.substring(0, Math.min(50, DISCORD_WEBHOOK_URL.length()))).append("...\n");
        } else {
            status.append("❌ Not configured\n");
            status.append("   Set DISCORD_WEBHOOK_URL environment variable\n");
        }
        
        status.append("\n🔔 Active Channel: ").append(NOTIFICATION_CHANNEL.toUpperCase()).append("\n");
        status.append("═══════════════════════════════════════════════════════════════\n");
        
        return status.toString();
    }
}
