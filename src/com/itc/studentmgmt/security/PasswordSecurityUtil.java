package com.itc.studentmgmt.security;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import java.security.SecureRandom;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * 🔐 ENHANCED PASSWORD SECURITY UTILITY
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * Multi-layer password security with:
 * 
 * ╔═══════════════════════════════════════════════════════════════════════════╗
 * ║  🔒 Argon2id Hashing (PHC Winner)                                         ║
 * ║  🛡️ Multi-Layer Protection (via MultiLayerPasswordVault)                 ║
 * ║  ⏰ Timing-Attack Resistant Comparison                                    ║
 * ║  🎲 Cryptographic Random Salt Generation                                  ║
 * ║  📊 Password Strength Analysis                                            ║
 * ║  🔄 Automatic Hash Format Detection                                       ║
 * ╚═══════════════════════════════════════════════════════════════════════════╝
 * 
 * This class provides both legacy Argon2id hashing and the new multi-layer
 * password vault for maximum security. New passwords use the vault by default.
 * 
 * @author Security Team
 * @version 3.0.0 - FORTRESS EDITION
 */
public class PasswordSecurityUtil {
    
    // ═══════════════════════════════════════════════════════════════════════════
    // ARGON2ID PARAMETERS (OWASP 2024 RECOMMENDATIONS - ENHANCED)
    // ═══════════════════════════════════════════════════════════════════════════
    
    private static final int SALT_LENGTH = 32;     // 256 bits (upgraded from 128)
    private static final int HASH_LENGTH = 64;     // 512 bits (upgraded from 256)
    private static final int ITERATIONS = 4;       // Time cost (upgraded from 3)
    private static final int MEMORY_COST = 131072; // 128 MB (upgraded from 64 MB)
    private static final int PARALLELISM = 8;      // Parallel threads (upgraded from 4)
    
    // Use strongest available SecureRandom
    private static final SecureRandom SECURE_RANDOM;
    
    // Feature flag: use multi-layer vault for new hashes
    private static final boolean USE_MULTI_LAYER_VAULT = true;
    
    static {
        try {
            SECURE_RANDOM = SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException e) {
            throw new SecurityException("Strong SecureRandom not available", e);
        }
    }
    
    /**
     * Hash a password using the most secure available method.
     * 
     * If USE_MULTI_LAYER_VAULT is enabled (default), uses 5-layer protection:
     * 1. Pepper (secret server-side key)
     * 2. Argon2id (memory-hard hashing)
     * 3. AES-256-GCM (authenticated encryption)
     * 4. HMAC-SHA512 (integrity signature)
     * 5. PBKDF2-SHA512 (key derivation)
     * 
     * @param password Plain text password
     * @return Encoded hash string (either MLP or Argon2id format)
     */
    public static String hashPassword(String password) {
        // Log the hashing operation (without the password!)
        SecurityAuditLogger.log(new SecurityAuditLogger.AuditEvent.Builder()
            .eventType(SecurityAuditLogger.EventType.ENCRYPTION_OPERATION)
            .action("PASSWORD_HASH")
            .details("Password hashing initiated")
            .build());
        
        if (USE_MULTI_LAYER_VAULT) {
            // Use the new 5-layer multi-layer password vault
            return MultiLayerPasswordVault.hashPassword(password);
        }
        
        // Fallback to enhanced Argon2id
        return hashPasswordArgon2id(password);
    }
    
    /**
     * Hash password using enhanced Argon2id (legacy method, still very secure).
     * 
     * @param password Plain text password
     * @return Argon2id encoded hash
     */
    public static String hashPasswordArgon2id(String password) {
        // Generate random salt
        byte[] salt = generateSalt();
        
        // Configure Argon2id parameters (enhanced)
        Argon2Parameters.Builder builder = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withIterations(ITERATIONS)
                .withMemoryAsKB(MEMORY_COST)
                .withParallelism(PARALLELISM)
                .withSalt(salt);
        
        // Generate hash
        Argon2BytesGenerator generator = new Argon2BytesGenerator();
        generator.init(builder.build());
        
        byte[] hash = new byte[HASH_LENGTH];
        generator.generateBytes(password.toCharArray(), hash);
        
        // Encode result as: $argon2id$v=19$m=131072,t=4,p=8$<salt>$<hash>
        return encodeHash(salt, hash);
    }
    
    /**
     * Verify a password against a stored hash.
     * 
     * Automatically detects the hash format and uses the appropriate
     * verification method:
     * - MLP format: Multi-Layer Password Vault (5 layers)
     * - Argon2id format: Direct Argon2id verification
     * 
     * @param password Plain text password to verify
     * @param encodedHash Stored encoded hash (MLP or Argon2id format)
     * @return true if password matches, false otherwise
     */
    public static boolean verifyPassword(String password, String encodedHash) {
        try {
            // Detect hash format and route to appropriate verifier
            if (encodedHash.startsWith("$MLP$")) {
                // Multi-Layer Password Vault format
                boolean result = MultiLayerPasswordVault.verifyPassword(password, encodedHash);
                logVerificationAttempt(result);
                return result;
            } else if (encodedHash.startsWith("$argon2id$")) {
                // Legacy Argon2id format
                boolean result = verifyPasswordArgon2id(password, encodedHash);
                logVerificationAttempt(result);
                return result;
            }
            
            // Unknown format
            logVerificationAttempt(false);
            return false;
            
        } catch (Exception e) {
            // Don't leak information about why verification failed
            logVerificationAttempt(false);
            return false;
        }
    }
    
    /**
     * Log verification attempt for security audit.
     */
    private static void logVerificationAttempt(boolean success) {
        SecurityAuditLogger.log(new SecurityAuditLogger.AuditEvent.Builder()
            .eventType(success ? 
                SecurityAuditLogger.EventType.ENCRYPTION_OPERATION : 
                SecurityAuditLogger.EventType.LOGIN_FAILURE)
            .action("PASSWORD_VERIFY")
            .details(success ? "Password verification successful" : "Password verification failed")
            .build());
    }
    
    /**
     * Verify password using Argon2id (legacy method).
     * 
     * @param password Plain text password to verify
     * @param encodedHash Stored Argon2id hash
     * @return true if password matches
     */
    private static boolean verifyPasswordArgon2id(String password, String encodedHash) {
        try {
            // Parse the encoded hash
            String[] parts = encodedHash.split("\\$");
            
            if (parts.length != 6) {
                return false;
            }
            
            // Extract parameters
            String[] params = parts[3].split(",");
            int memory = Integer.parseInt(params[0].split("=")[1]);
            int iterations = Integer.parseInt(params[1].split("=")[1]);
            int parallelism = Integer.parseInt(params[2].split("=")[1]);
            
            // Extract salt and hash
            byte[] salt = Base64.getDecoder().decode(parts[4]);
            byte[] expectedHash = Base64.getDecoder().decode(parts[5]);
            
            // Configure Argon2id with extracted parameters
            Argon2Parameters.Builder builder = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                    .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                    .withIterations(iterations)
                    .withMemoryAsKB(memory)
                    .withParallelism(parallelism)
                    .withSalt(salt);
            
            // Generate hash with provided password
            Argon2BytesGenerator generator = new Argon2BytesGenerator();
            generator.init(builder.build());
            
            byte[] hash = new byte[expectedHash.length];
            generator.generateBytes(password.toCharArray(), hash);
            
            // Constant-time comparison to prevent timing attacks
            return constantTimeEquals(hash, expectedHash);
            
        } catch (Exception e) {
            // Don't leak information about why verification failed
            return false;
        }
    }
    
    /**
     * Check if a stored hash should be rehashed with stronger parameters.
     * Call this after successful login to upgrade legacy hashes.
     * 
     * @param encodedHash The stored hash
     * @return true if the hash should be upgraded
     */
    public static boolean needsRehash(String encodedHash) {
        // MLP format is the strongest - no need to rehash
        if (encodedHash.startsWith("$MLP$")) {
            return false;
        }
        
        // Argon2id should be upgraded to MLP
        if (encodedHash.startsWith("$argon2id$") && USE_MULTI_LAYER_VAULT) {
            return true;
        }
        
        // Check if Argon2id parameters are outdated
        if (encodedHash.startsWith("$argon2id$")) {
            try {
                String[] parts = encodedHash.split("\\$");
                String[] params = parts[3].split(",");
                int memory = Integer.parseInt(params[0].split("=")[1]);
                int iterations = Integer.parseInt(params[1].split("=")[1]);
                
                // Needs upgrade if using less than current parameters
                return memory < MEMORY_COST || iterations < ITERATIONS;
            } catch (Exception e) {
                return true; // Unknown format, rehash to be safe
            }
        }
        
        return true; // Unknown format, definitely needs rehash
    }
    
    /**
     * Generate a cryptographically secure random salt
     * @return Random salt bytes (256-bit)
     */
    private static byte[] generateSalt() {
        byte[] salt = new byte[SALT_LENGTH];
        SECURE_RANDOM.nextBytes(salt);
        return salt;
    }
    
    /**
     * Encode hash in PHC string format (enhanced parameters)
     * Format: $argon2id$v=19$m=131072,t=4,p=8$<salt>$<hash>
     * @param salt Salt bytes
     * @param hash Hash bytes
     * @return Encoded hash string
     */
    private static String encodeHash(byte[] salt, byte[] hash) {
        StringBuilder sb = new StringBuilder();
        sb.append("$argon2id");
        sb.append("$v=").append(Argon2Parameters.ARGON2_VERSION_13);
        sb.append("$m=").append(MEMORY_COST);
        sb.append(",t=").append(ITERATIONS);
        sb.append(",p=").append(PARALLELISM);
        sb.append("$").append(Base64.getEncoder().withoutPadding().encodeToString(salt));
        sb.append("$").append(Base64.getEncoder().withoutPadding().encodeToString(hash));
        return sb.toString();
    }
    
    /**
     * Constant-time byte array comparison to prevent timing attacks
     * @param a First byte array
     * @param b Second byte array
     * @return true if arrays are equal
     */
    private static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a.length != b.length) {
            return false;
        }
        
        int result = 0;
        for (int i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }
        
        return result == 0;
    }
    
    /**
     * Generate a secure random token for session management or password reset.
     * Uses the CryptoCore for maximum security.
     * 
     * @param length Length of token in bytes (will be Base64 encoded)
     * @return Base64 URL-safe encoded random token
     */
    public static String generateSecureToken(int length) {
        return CryptoCore.generateSecureToken(length);
    }
    
    /**
     * Generate a cryptographically secure OTP (One-Time Password).
     * 
     * @param digits Number of digits (typically 6 or 8)
     * @return Numeric OTP string
     */
    public static String generateOTP(int digits) {
        StringBuilder otp = new StringBuilder();
        for (int i = 0; i < digits; i++) {
            otp.append(SECURE_RANDOM.nextInt(10));
        }
        return otp.toString();
    }
    
    /**
     * Check if a password meets minimum security requirements.
     * 
     * Enhanced requirements:
     * - Minimum 12 characters
     * - At least one uppercase letter
     * - At least one lowercase letter
     * - At least one digit
     * - At least one special character
     * - No common patterns (123, abc, password, etc.)
     * - No excessive repetition
     * 
     * @param password Password to check
     * @return true if password meets requirements
     */
    public static boolean isPasswordStrong(String password) {
        if (password == null || password.length() < 12) {
            return false;
        }
        
        boolean hasUppercase = false;
        boolean hasLowercase = false;
        boolean hasDigit = false;
        boolean hasSpecial = false;
        
        for (char c : password.toCharArray()) {
            if (Character.isUpperCase(c)) hasUppercase = true;
            else if (Character.isLowerCase(c)) hasLowercase = true;
            else if (Character.isDigit(c)) hasDigit = true;
            else hasSpecial = true;
        }
        
        if (!hasUppercase || !hasLowercase || !hasDigit || !hasSpecial) {
            return false;
        }
        
        // Check for common weak passwords
        String lowerPassword = password.toLowerCase();
        String[] weakPatterns = {"password", "123456", "qwerty", "admin", "letmein", "welcome"};
        for (String pattern : weakPatterns) {
            if (lowerPassword.contains(pattern)) {
                return false;
            }
        }
        
        // Check for character repetition (e.g., "aaaa", "1111")
        int maxRepeat = 0;
        int currentRepeat = 1;
        for (int i = 1; i < password.length(); i++) {
            if (password.charAt(i) == password.charAt(i - 1)) {
                currentRepeat++;
                maxRepeat = Math.max(maxRepeat, currentRepeat);
            } else {
                currentRepeat = 1;
            }
        }
        if (maxRepeat >= 4) {
            return false;
        }
        
        // Check for sequential characters (e.g., "abcd", "1234")
        int sequential = 1;
        for (int i = 1; i < password.length(); i++) {
            if (password.charAt(i) == password.charAt(i - 1) + 1) {
                sequential++;
                if (sequential >= 4) {
                    return false;
                }
            } else {
                sequential = 1;
            }
        }
        
        return true;
    }
    
    /**
     * Calculate password strength score with enhanced analysis.
     * 
     * @param password Password to evaluate
     * @return Strength score (0-100)
     */
    public static int calculatePasswordStrength(String password) {
        if (password == null || password.isEmpty()) {
            return 0;
        }
        
        int score = 0;
        
        // Length score (up to 30 points)
        score += Math.min(password.length() * 2, 30);
        
        // Character variety (up to 40 points)
        if (password.chars().anyMatch(Character::isUpperCase)) score += 10;
        if (password.chars().anyMatch(Character::isLowerCase)) score += 10;
        if (password.chars().anyMatch(Character::isDigit)) score += 10;
        if (password.chars().anyMatch(c -> !Character.isLetterOrDigit(c))) score += 10;
        
        // Unique character ratio (up to 15 points)
        long uniqueChars = password.chars().distinct().count();
        double uniqueRatio = (double) uniqueChars / password.length();
        score += (int) (uniqueRatio * 15);
        
        // Special character count bonus (up to 10 points)
        long specialCount = password.chars().filter(c -> !Character.isLetterOrDigit(c)).count();
        score += Math.min((int) specialCount * 3, 10);
        
        // Penalty for common patterns
        String lowerPassword = password.toLowerCase();
        String[] weakPatterns = {"password", "123456", "qwerty", "admin"};
        for (String pattern : weakPatterns) {
            if (lowerPassword.contains(pattern)) {
                score -= 20;
            }
        }
        
        // Penalty for repetition
        int maxRepeat = 1;
        int currentRepeat = 1;
        for (int i = 1; i < password.length(); i++) {
            if (password.charAt(i) == password.charAt(i - 1)) {
                currentRepeat++;
                maxRepeat = Math.max(maxRepeat, currentRepeat);
            } else {
                currentRepeat = 1;
            }
        }
        if (maxRepeat >= 3) {
            score -= maxRepeat * 5;
        }
        
        return Math.max(0, Math.min(score, 100));
    }
    
    /**
     * Get password strength label.
     * 
     * @param password Password to evaluate
     * @return Strength label (VERY_WEAK, WEAK, FAIR, STRONG, VERY_STRONG)
     */
    public static String getPasswordStrengthLabel(String password) {
        int score = calculatePasswordStrength(password);
        
        if (score < 20) return "VERY_WEAK";
        if (score < 40) return "WEAK";
        if (score < 60) return "FAIR";
        if (score < 80) return "STRONG";
        return "VERY_STRONG";
    }
    
    /**
     * Get detailed password strength feedback.
     * 
     * @param password Password to analyze
     * @return List of improvement suggestions
     */
    public static java.util.List<String> getPasswordFeedback(String password) {
        java.util.List<String> feedback = new java.util.ArrayList<>();
        
        if (password == null || password.isEmpty()) {
            feedback.add("Password cannot be empty");
            return feedback;
        }
        
        if (password.length() < 12) {
            feedback.add("Password should be at least 12 characters long");
        }
        
        if (!password.chars().anyMatch(Character::isUpperCase)) {
            feedback.add("Add uppercase letters (A-Z)");
        }
        
        if (!password.chars().anyMatch(Character::isLowerCase)) {
            feedback.add("Add lowercase letters (a-z)");
        }
        
        if (!password.chars().anyMatch(Character::isDigit)) {
            feedback.add("Add numbers (0-9)");
        }
        
        if (!password.chars().anyMatch(c -> !Character.isLetterOrDigit(c))) {
            feedback.add("Add special characters (!@#$%^&*)");
        }
        
        // Check for common patterns
        String lowerPassword = password.toLowerCase();
        if (lowerPassword.contains("password") || lowerPassword.contains("123456")) {
            feedback.add("Avoid common patterns like 'password' or '123456'");
        }
        
        // Check for repetition
        for (int i = 1; i < password.length(); i++) {
            if (password.charAt(i) == password.charAt(i - 1) && 
                i + 1 < password.length() && 
                password.charAt(i + 1) == password.charAt(i)) {
                feedback.add("Avoid repeating the same character multiple times");
                break;
            }
        }
        
        if (feedback.isEmpty()) {
            feedback.add("Password meets all security requirements ✓");
        }
        
        return feedback;
    }
}