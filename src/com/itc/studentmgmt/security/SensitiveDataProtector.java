package com.itc.studentmgmt.security;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;
import java.util.regex.Pattern;

/**
 * 🔐 SENSITIVE DATA PROTECTOR
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * Comprehensive protection for sensitive data at rest and in transit:
 * 
 * ╔═══════════════════════════════════════════════════════════════════════════╗
 * ║  📧 Email Encryption & Masking                                            ║
 * ║  🆔 ID Number Protection                                                  ║
 * ║  📱 Phone Number Encryption                                               ║
 * ║  💳 PII Field Encryption                                                  ║
 * ║  🔍 Searchable Encryption (Blind Index)                                   ║
 * ║  📋 Data Masking for Display                                              ║
 * ╚═══════════════════════════════════════════════════════════════════════════╝
 * 
 * @author Security Team
 * @version 2.0.0
 */
public class SensitiveDataProtector {
    
    // ═══════════════════════════════════════════════════════════════════════════
    // ENCRYPTION KEYS (In production, use proper key management!)
    // ═══════════════════════════════════════════════════════════════════════════
    
    private static final SecretKey DATA_ENCRYPTION_KEY;
    private static final SecretKey BLIND_INDEX_KEY;
    
    private static final SecureRandom SECURE_RANDOM;
    
    // Masking patterns
    private static final Pattern EMAIL_PATTERN = Pattern.compile("^(.{2})(.*)(@.*)$");
    private static final Pattern PHONE_PATTERN = Pattern.compile("^(.{3})(.*)(.{2})$");
    
    static {
        try {
            SECURE_RANDOM = SecureRandom.getInstanceStrong();
            DATA_ENCRYPTION_KEY = loadOrGenerateKey("DATA_ENCRYPTION_KEY");
            BLIND_INDEX_KEY = loadOrGenerateKey("BLIND_INDEX_KEY");
        } catch (Exception e) {
            throw new SecurityException("Failed to initialize data protector", e);
        }
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // FIELD-LEVEL ENCRYPTION
    // ═══════════════════════════════════════════════════════════════════════════
    
    /**
     * Encrypt a sensitive field for database storage.
     * Returns: ENC$[version]$[ciphertext]
     */
    public static String encryptField(String plaintext) {
        if (plaintext == null || plaintext.isEmpty()) {
            return plaintext;
        }
        
        try {
            String encrypted = CryptoCore.encryptToBase64(plaintext, DATA_ENCRYPTION_KEY);
            return "ENC$v1$" + encrypted;
        } catch (Exception e) {
            throw new SecurityException("Field encryption failed", e);
        }
    }
    
    /**
     * Decrypt a sensitive field from database.
     */
    public static String decryptField(String encryptedField) {
        if (encryptedField == null || !encryptedField.startsWith("ENC$")) {
            return encryptedField; // Not encrypted or null
        }
        
        try {
            String[] parts = encryptedField.split("\\$");
            if (parts.length != 3) {
                throw new SecurityException("Invalid encrypted field format");
            }
            
            String version = parts[1];
            String ciphertext = parts[2];
            
            return CryptoCore.decryptFromBase64(ciphertext, DATA_ENCRYPTION_KEY);
        } catch (Exception e) {
            throw new SecurityException("Field decryption failed", e);
        }
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // SEARCHABLE ENCRYPTION (Blind Index)
    // ═══════════════════════════════════════════════════════════════════════════
    
    /**
     * Create a blind index for searchable encrypted data.
     * Allows searching without decrypting all records.
     * 
     * WARNING: Blind index leaks search patterns. Use with caution.
     */
    public static String createBlindIndex(String plaintext) {
        if (plaintext == null) {
            return null;
        }
        
        try {
            // Normalize input (lowercase, trim)
            String normalized = plaintext.toLowerCase().trim();
            
            // HMAC-based blind index
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(BLIND_INDEX_KEY);
            byte[] hash = mac.doFinal(normalized.getBytes(StandardCharsets.UTF_8));
            
            // Truncate for shorter index (still secure)
            byte[] truncated = Arrays.copyOf(hash, 16);
            return Base64.getEncoder().withoutPadding().encodeToString(truncated);
            
        } catch (Exception e) {
            throw new SecurityException("Blind index creation failed", e);
        }
    }
    
    /**
     * Encrypt field with blind index for searchable encryption.
     * Returns object with encrypted value and search index.
     */
    public static EncryptedSearchableField encryptSearchable(String plaintext) {
        String encrypted = encryptField(plaintext);
        String blindIndex = createBlindIndex(plaintext);
        return new EncryptedSearchableField(encrypted, blindIndex);
    }
    
    public static class EncryptedSearchableField {
        public final String encryptedValue;
        public final String blindIndex;
        
        public EncryptedSearchableField(String encryptedValue, String blindIndex) {
            this.encryptedValue = encryptedValue;
            this.blindIndex = blindIndex;
        }
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // SPECIALIZED FIELD ENCRYPTION
    // ═══════════════════════════════════════════════════════════════════════════
    
    /**
     * Encrypt email address with searchable index.
     */
    public static EncryptedSearchableField encryptEmail(String email) {
        if (email == null || email.isEmpty()) {
            return new EncryptedSearchableField(null, null);
        }
        
        // Normalize email
        String normalizedEmail = email.toLowerCase().trim();
        
        return encryptSearchable(normalizedEmail);
    }
    
    /**
     * Encrypt phone number.
     */
    public static String encryptPhoneNumber(String phoneNumber) {
        if (phoneNumber == null) {
            return null;
        }
        
        // Normalize: remove non-digits
        String normalized = phoneNumber.replaceAll("[^0-9+]", "");
        return encryptField(normalized);
    }
    
    /**
     * Encrypt ID number (student ID, SSN, etc.).
     */
    public static EncryptedSearchableField encryptIdNumber(String idNumber) {
        if (idNumber == null || idNumber.isEmpty()) {
            return new EncryptedSearchableField(null, null);
        }
        
        // Normalize: uppercase, remove special chars
        String normalized = idNumber.toUpperCase().replaceAll("[^A-Z0-9]", "");
        
        return encryptSearchable(normalized);
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // DATA MASKING (For Display)
    // ═══════════════════════════════════════════════════════════════════════════
    
    /**
     * Mask email for display: jo***@example.com
     */
    public static String maskEmail(String email) {
        if (email == null || email.isEmpty()) {
            return email;
        }
        
        int atIndex = email.indexOf('@');
        if (atIndex < 0) {
            return maskGeneric(email);
        }
        
        String local = email.substring(0, atIndex);
        String domain = email.substring(atIndex);
        
        if (local.length() <= 2) {
            return local.charAt(0) + "***" + domain;
        }
        
        return local.substring(0, 2) + "***" + domain;
    }
    
    /**
     * Mask phone number: ***-***-1234
     */
    public static String maskPhoneNumber(String phone) {
        if (phone == null || phone.length() < 4) {
            return "***-***-****";
        }
        
        String digits = phone.replaceAll("[^0-9]", "");
        if (digits.length() < 4) {
            return "***-***-****";
        }
        
        return "***-***-" + digits.substring(digits.length() - 4);
    }
    
    /**
     * Mask ID number: ****-****-1234
     */
    public static String maskIdNumber(String idNumber) {
        if (idNumber == null || idNumber.length() < 4) {
            return "****-****-****";
        }
        
        int visibleChars = Math.min(4, idNumber.length());
        String visible = idNumber.substring(idNumber.length() - visibleChars);
        String masked = "*".repeat(idNumber.length() - visibleChars);
        
        return masked + visible;
    }
    
    /**
     * Mask name: John D***
     */
    public static String maskName(String name) {
        if (name == null || name.length() <= 3) {
            return name;
        }
        
        String[] parts = name.split("\\s+");
        if (parts.length == 1) {
            return name.charAt(0) + "***";
        }
        
        // First name + masked last name
        StringBuilder masked = new StringBuilder(parts[0]);
        for (int i = 1; i < parts.length; i++) {
            masked.append(" ").append(parts[i].charAt(0)).append("***");
        }
        
        return masked.toString();
    }
    
    /**
     * Generic masking: show first and last 2 chars.
     */
    public static String maskGeneric(String data) {
        if (data == null || data.length() <= 4) {
            return "****";
        }
        
        int maskLength = data.length() - 4;
        return data.substring(0, 2) + "*".repeat(maskLength) + data.substring(data.length() - 2);
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // PII DETECTION
    // ═══════════════════════════════════════════════════════════════════════════
    
    /**
     * Detect if a string might contain PII.
     */
    public static boolean mightContainPII(String data) {
        if (data == null || data.isEmpty()) {
            return false;
        }
        
        // Email pattern
        if (data.matches(".*[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}.*")) {
            return true;
        }
        
        // Phone pattern (various formats)
        if (data.matches(".*\\d{3}[-.]?\\d{3}[-.]?\\d{4}.*")) {
            return true;
        }
        
        // SSN pattern
        if (data.matches(".*\\d{3}-\\d{2}-\\d{4}.*")) {
            return true;
        }
        
        // Credit card pattern
        if (data.matches(".*\\d{4}[-\\s]?\\d{4}[-\\s]?\\d{4}[-\\s]?\\d{4}.*")) {
            return true;
        }
        
        return false;
    }
    
    /**
     * Redact PII from a string (for logging).
     */
    public static String redactPII(String data) {
        if (data == null) {
            return null;
        }
        
        String redacted = data;
        
        // Redact emails
        redacted = redacted.replaceAll(
            "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}",
            "[EMAIL REDACTED]"
        );
        
        // Redact phone numbers
        redacted = redacted.replaceAll(
            "\\d{3}[-.]?\\d{3}[-.]?\\d{4}",
            "[PHONE REDACTED]"
        );
        
        // Redact SSN
        redacted = redacted.replaceAll(
            "\\d{3}-\\d{2}-\\d{4}",
            "[SSN REDACTED]"
        );
        
        // Redact credit cards
        redacted = redacted.replaceAll(
            "\\d{4}[-\\s]?\\d{4}[-\\s]?\\d{4}[-\\s]?\\d{4}",
            "[CARD REDACTED]"
        );
        
        return redacted;
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // UTILITY METHODS
    // ═══════════════════════════════════════════════════════════════════════════
    
    /**
     * Load key from environment or generate deterministic key.
     */
    private static SecretKey loadOrGenerateKey(String keyName) throws GeneralSecurityException {
        String envKey = System.getenv(keyName);
        byte[] keyBytes;
        
        if (envKey != null && !envKey.isEmpty()) {
            keyBytes = Base64.getDecoder().decode(envKey);
        } else {
            // Generate deterministic key (NOT for production!)
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            String seed = keyName + "StudentMgmtDataProtector2024!@#$";
            keyBytes = md.digest(seed.getBytes(StandardCharsets.UTF_8));
        }
        
        return new SecretKeySpec(keyBytes, "AES");
    }
    
    /**
     * Generate new random key (for initial setup).
     */
    public static String generateNewKey() {
        byte[] key = new byte[32];
        SECURE_RANDOM.nextBytes(key);
        return Base64.getEncoder().encodeToString(key);
    }
}
