package com.itc.studentmgmt.security;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Utility class for secure password hashing using Argon2id
 * Argon2id is the winner of the Password Hashing Competition (PHC)
 * and is recommended by OWASP for password storage
 */
public class PasswordSecurityUtil {
    
    // Argon2id parameters (OWASP 2023 recommendations)
    private static final int SALT_LENGTH = 16; // 128 bits
    private static final int HASH_LENGTH = 32; // 256 bits
    private static final int ITERATIONS = 3; // Number of iterations
    private static final int MEMORY_COST = 65536; // 64 MB (in KiB)
    private static final int PARALLELISM = 4; // Number of parallel threads
    
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    
    /**
     * Hash a password using Argon2id algorithm
     * @param password Plain text password
     * @return Encoded hash string containing algorithm params, salt, and hash
     */
    public static String hashPassword(String password) {
        // Generate random salt
        byte[] salt = generateSalt();
        
        // Configure Argon2id parameters
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
        
        // Encode result as: $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
        return encodeHash(salt, hash);
    }
    
    /**
     * Verify a password against a stored hash
     * @param password Plain text password to verify
     * @param encodedHash Stored encoded hash
     * @return true if password matches, false otherwise
     */
    public static boolean verifyPassword(String password, String encodedHash) {
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
     * Generate a cryptographically secure random salt
     * @return Random salt bytes
     */
    private static byte[] generateSalt() {
        byte[] salt = new byte[SALT_LENGTH];
        SECURE_RANDOM.nextBytes(salt);
        return salt;
    }
    
    /**
     * Encode hash in PHC string format
     * Format: $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
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
     * Generate a secure random token for session management or password reset
     * @param length Length of token in bytes (will be Base64 encoded)
     * @return Base64 encoded random token
     */
    public static String generateSecureToken(int length) {
        byte[] token = new byte[length];
        SECURE_RANDOM.nextBytes(token);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(token);
    }
    
    /**
     * Check if a password meets minimum security requirements
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
        
        return hasUppercase && hasLowercase && hasDigit && hasSpecial;
    }
    
    /**
     * Calculate password strength score (0-100)
     * @param password Password to evaluate
     * @return Strength score
     */
    public static int calculatePasswordStrength(String password) {
        if (password == null || password.isEmpty()) {
            return 0;
        }
        
        int score = 0;
        
        // Length score (up to 40 points)
        score += Math.min(password.length() * 2, 40);
        
        // Character variety (up to 40 points)
        if (password.chars().anyMatch(Character::isUpperCase)) score += 10;
        if (password.chars().anyMatch(Character::isLowerCase)) score += 10;
        if (password.chars().anyMatch(Character::isDigit)) score += 10;
        if (password.chars().anyMatch(c -> !Character.isLetterOrDigit(c))) score += 10;
        
        // Complexity bonus (up to 20 points)
        long uniqueChars = password.chars().distinct().count();
        score += Math.min((int)(uniqueChars * 1.5), 20);
        
        return Math.min(score, 100);
    }
}