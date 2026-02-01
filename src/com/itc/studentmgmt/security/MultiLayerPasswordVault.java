package com.itc.studentmgmt.security;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;

/**
 * 🔐 MULTI-LAYER PASSWORD VAULT
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * ULTIMATE PASSWORD SECURITY - 5 LAYERS OF PROTECTION:
 * 
 * ╔═══════════════════════════════════════════════════════════════════════════╗
 * ║  Layer 1: PEPPER (Secret server-side key)                                 ║
 * ║  Layer 2: ARGON2ID (Memory-hard password hashing)                        ║
 * ║  Layer 3: AES-256-GCM (Authenticated encryption of hash)                  ║
 * ║  Layer 4: HMAC-SHA512 (Integrity signature)                              ║
 * ║  Layer 5: PBKDF2-SHA512 (Key stretching for encryption key)              ║
 * ╚═══════════════════════════════════════════════════════════════════════════╝
 * 
 * Storage Format:
 * $MLP$v1$[salt_b64]$[pepper_id]$[argon2_params]$[encrypted_hmac_hash_b64]
 * 
 * @author Security Team
 * @version 3.0.0 - FORTRESS EDITION
 */
public class MultiLayerPasswordVault {
    
    // ═══════════════════════════════════════════════════════════════════════════
    // SECURITY CONSTANTS - EXCEEDS OWASP 2024 RECOMMENDATIONS
    // ═══════════════════════════════════════════════════════════════════════════
    
    // Argon2id Parameters (HIGHER than OWASP recommendations)
    private static final int ARGON2_SALT_LENGTH = 32;     // 256-bit salt
    private static final int ARGON2_HASH_LENGTH = 64;     // 512-bit hash output
    private static final int ARGON2_ITERATIONS = 4;       // Time cost
    private static final int ARGON2_MEMORY_KB = 131072;   // 128 MB memory
    private static final int ARGON2_PARALLELISM = 8;      // 8 parallel threads
    
    // AES-256-GCM Parameters
    private static final int AES_KEY_SIZE = 256;
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;
    
    // PBKDF2 Parameters for key derivation
    private static final int PBKDF2_ITERATIONS = 600000;
    
    // Pepper - In production, store in HSM or secure vault!
    private static final byte[] SYSTEM_PEPPER = getSystemPepper();
    private static final String PEPPER_VERSION = "v1";
    
    private static final SecureRandom SECURE_RANDOM;
    
    static {
        try {
            SECURE_RANDOM = SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException e) {
            throw new SecurityException("Strong SecureRandom not available", e);
        }
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // MAIN INTERFACE - HASH & VERIFY
    // ═══════════════════════════════════════════════════════════════════════════
    
    /**
     * Create a multi-layer protected password hash.
     * 
     * Process:
     * 1. Apply pepper to password
     * 2. Hash with Argon2id
     * 3. Encrypt hash with AES-256-GCM
     * 4. Sign with HMAC-SHA512
     * 5. Encode in secure format
     * 
     * @param password Plain text password
     * @return Secure encoded hash string
     */
    public static String hashPassword(String password) {
        try {
            // Generate random salt
            byte[] salt = new byte[ARGON2_SALT_LENGTH];
            SECURE_RANDOM.nextBytes(salt);
            
            // Layer 1: Apply pepper
            byte[] pepperedPassword = applyPepper(password.getBytes(StandardCharsets.UTF_8));
            
            // Layer 2: Argon2id hashing
            byte[] argon2Hash = argon2idHash(pepperedPassword, salt);
            
            // Layer 3 & 5: Derive encryption key and encrypt
            SecretKey encryptionKey = deriveEncryptionKey(salt);
            byte[] encryptedHash = encryptAesGcm(argon2Hash, encryptionKey);
            
            // Layer 4: HMAC signature
            SecretKey hmacKey = deriveHmacKey(salt);
            byte[] hmacSignature = hmacSign(encryptedHash, hmacKey);
            
            // Combine: encrypted_hash + hmac
            byte[] combined = new byte[encryptedHash.length + hmacSignature.length];
            System.arraycopy(encryptedHash, 0, combined, 0, encryptedHash.length);
            System.arraycopy(hmacSignature, 0, combined, encryptedHash.length, hmacSignature.length);
            
            // Encode in secure format
            String argon2Params = String.format("m=%d,t=%d,p=%d", 
                ARGON2_MEMORY_KB, ARGON2_ITERATIONS, ARGON2_PARALLELISM);
            
            return String.format("$MLP$%s$%s$%s$%s$%s",
                "v1",
                Base64.getEncoder().withoutPadding().encodeToString(salt),
                PEPPER_VERSION,
                argon2Params,
                Base64.getEncoder().withoutPadding().encodeToString(combined));
                
        } catch (Exception e) {
            throw new SecurityException("Password hashing failed", e);
        }
    }
    
    /**
     * Verify a password against a stored multi-layer hash.
     * 
     * @param password Plain text password to verify
     * @param storedHash Stored multi-layer hash
     * @return true if password matches
     */
    public static boolean verifyPassword(String password, String storedHash) {
        try {
            // Handle legacy Argon2 format for backwards compatibility
            if (storedHash.startsWith("$argon2id$")) {
                return verifyLegacyArgon2(password, storedHash);
            }
            
            // Parse MLP format
            String[] parts = storedHash.split("\\$");
            if (parts.length != 7 || !parts[1].equals("MLP")) {
                return false;
            }
            
            // Extract components (version and pepperVersion reserved for future format validation)
            @SuppressWarnings("unused") String version = parts[2];
            byte[] salt = Base64.getDecoder().decode(parts[3]);
            @SuppressWarnings("unused") String pepperVersion = parts[4];
            String argon2Params = parts[5];
            byte[] combined = Base64.getDecoder().decode(parts[6]);
            
            // Parse Argon2 parameters
            int memory = Integer.parseInt(extractParam(argon2Params, "m"));
            int iterations = Integer.parseInt(extractParam(argon2Params, "t"));
            int parallelism = Integer.parseInt(extractParam(argon2Params, "p"));
            
            // Split combined into encrypted hash and HMAC
            int hmacLength = 64; // SHA-512 output
            byte[] encryptedHash = Arrays.copyOfRange(combined, 0, combined.length - hmacLength);
            byte[] storedHmac = Arrays.copyOfRange(combined, combined.length - hmacLength, combined.length);
            
            // Verify HMAC first (fail fast)
            SecretKey hmacKey = deriveHmacKey(salt);
            byte[] computedHmac = hmacSign(encryptedHash, hmacKey);
            
            if (!constantTimeEquals(computedHmac, storedHmac)) {
                return false; // Integrity check failed
            }
            
            // Decrypt the hash
            SecretKey encryptionKey = deriveEncryptionKey(salt);
            byte[] expectedHash = decryptAesGcm(encryptedHash, encryptionKey);
            
            // Recompute password hash
            byte[] pepperedPassword = applyPepper(password.getBytes(StandardCharsets.UTF_8));
            byte[] computedHash = argon2idHash(pepperedPassword, salt, memory, iterations, parallelism);
            
            // Constant-time comparison
            return constantTimeEquals(computedHash, expectedHash);
            
        } catch (Exception e) {
            // Don't leak information about why verification failed
            return false;
        }
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // LAYER 1: PEPPER APPLICATION
    // ═══════════════════════════════════════════════════════════════════════════
    
    /**
     * Apply secret pepper to password using XOR mixing.
     */
    private static byte[] applyPepper(byte[] password) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA512");
        mac.init(new SecretKeySpec(SYSTEM_PEPPER, "HmacSHA512"));
        return mac.doFinal(password);
    }
    
    /**
     * Get system pepper from secure source.
     * In production, this should come from HSM, AWS KMS, Azure Key Vault, etc.
     */
    private static byte[] getSystemPepper() {
        String pepperEnv = System.getenv("SYSTEM_PEPPER");
        if (pepperEnv != null && !pepperEnv.isEmpty()) {
            return Base64.getDecoder().decode(pepperEnv);
        }
        // FALLBACK - Generate deterministic pepper from machine identity
        // In production, NEVER use this fallback!
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            String machineId = System.getProperty("user.name") + 
                              System.getProperty("os.name") + 
                              "StudentMgmtSecretPepper2024!@#$";
            return md.digest(machineId.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new SecurityException("SHA-256 not available", e);
        }
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // LAYER 2: ARGON2ID HASHING
    // ═══════════════════════════════════════════════════════════════════════════
    
    /**
     * Hash data using Argon2id with default parameters.
     */
    private static byte[] argon2idHash(byte[] data, byte[] salt) {
        return argon2idHash(data, salt, ARGON2_MEMORY_KB, ARGON2_ITERATIONS, ARGON2_PARALLELISM);
    }
    
    /**
     * Hash data using Argon2id with custom parameters.
     */
    private static byte[] argon2idHash(byte[] data, byte[] salt, 
                                       int memoryKb, int iterations, int parallelism) {
        Argon2Parameters.Builder builder = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13)
            .withIterations(iterations)
            .withMemoryAsKB(memoryKb)
            .withParallelism(parallelism)
            .withSalt(salt);
        
        Argon2BytesGenerator generator = new Argon2BytesGenerator();
        generator.init(builder.build());
        
        byte[] hash = new byte[ARGON2_HASH_LENGTH];
        generator.generateBytes(data, hash);
        
        return hash;
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // LAYER 3: AES-256-GCM ENCRYPTION
    // ═══════════════════════════════════════════════════════════════════════════
    
    /**
     * Encrypt data using AES-256-GCM.
     */
    private static byte[] encryptAesGcm(byte[] plaintext, SecretKey key) 
            throws GeneralSecurityException {
        // Generate random IV
        byte[] iv = new byte[GCM_IV_LENGTH];
        SECURE_RANDOM.nextBytes(iv);
        
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
        
        byte[] ciphertext = cipher.doFinal(plaintext);
        
        // Prepend IV
        byte[] result = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(ciphertext, 0, result, iv.length, ciphertext.length);
        
        return result;
    }
    
    /**
     * Decrypt AES-256-GCM data.
     */
    private static byte[] decryptAesGcm(byte[] ciphertext, SecretKey key) 
            throws GeneralSecurityException {
        byte[] iv = Arrays.copyOfRange(ciphertext, 0, GCM_IV_LENGTH);
        byte[] encrypted = Arrays.copyOfRange(ciphertext, GCM_IV_LENGTH, ciphertext.length);
        
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);
        
        return cipher.doFinal(encrypted);
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // LAYER 4: HMAC-SHA512 SIGNATURE
    // ═══════════════════════════════════════════════════════════════════════════
    
    /**
     * Generate HMAC-SHA512 signature.
     */
    private static byte[] hmacSign(byte[] data, SecretKey key) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA512");
        mac.init(key);
        return mac.doFinal(data);
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // LAYER 5: KEY DERIVATION
    // ═══════════════════════════════════════════════════════════════════════════
    
    /**
     * Derive encryption key from salt using PBKDF2.
     */
    private static SecretKey deriveEncryptionKey(byte[] salt) throws GeneralSecurityException {
        return deriveKey(salt, "ENCRYPTION_KEY_DERIVATION");
    }
    
    /**
     * Derive HMAC key from salt using PBKDF2.
     */
    private static SecretKey deriveHmacKey(byte[] salt) throws GeneralSecurityException {
        return deriveKey(salt, "HMAC_KEY_DERIVATION");
    }
    
    /**
     * Generic key derivation with purpose separation.
     */
    private static SecretKey deriveKey(byte[] salt, String purpose) throws GeneralSecurityException {
        // Combine pepper with purpose for domain separation
        byte[] combinedSecret = new byte[SYSTEM_PEPPER.length + purpose.getBytes().length];
        System.arraycopy(SYSTEM_PEPPER, 0, combinedSecret, 0, SYSTEM_PEPPER.length);
        System.arraycopy(purpose.getBytes(), 0, combinedSecret, SYSTEM_PEPPER.length, purpose.getBytes().length);
        
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
        PBEKeySpec spec = new PBEKeySpec(
            new String(combinedSecret, StandardCharsets.ISO_8859_1).toCharArray(),
            salt, 
            PBKDF2_ITERATIONS, 
            AES_KEY_SIZE
        );
        SecretKey tmp = factory.generateSecret(spec);
        return new SecretKeySpec(tmp.getEncoded(), "AES");
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // LEGACY SUPPORT
    // ═══════════════════════════════════════════════════════════════════════════
    
    /**
     * Verify legacy Argon2id format for backwards compatibility.
     */
    private static boolean verifyLegacyArgon2(String password, String encodedHash) {
        try {
            String[] parts = encodedHash.split("\\$");
            if (parts.length != 6) return false;
            
            String[] params = parts[3].split(",");
            int memory = Integer.parseInt(params[0].split("=")[1]);
            int iterations = Integer.parseInt(params[1].split("=")[1]);
            int parallelism = Integer.parseInt(params[2].split("=")[1]);
            
            byte[] salt = Base64.getDecoder().decode(parts[4]);
            byte[] expectedHash = Base64.getDecoder().decode(parts[5]);
            
            Argon2Parameters.Builder builder = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withIterations(iterations)
                .withMemoryAsKB(memory)
                .withParallelism(parallelism)
                .withSalt(salt);
            
            Argon2BytesGenerator generator = new Argon2BytesGenerator();
            generator.init(builder.build());
            
            byte[] hash = new byte[expectedHash.length];
            generator.generateBytes(password.toCharArray(), hash);
            
            return constantTimeEquals(hash, expectedHash);
        } catch (Exception e) {
            return false;
        }
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // UTILITY METHODS
    // ═══════════════════════════════════════════════════════════════════════════
    
    /**
     * Constant-time byte array comparison.
     */
    private static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a.length != b.length) return false;
        int result = 0;
        for (int i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }
        return result == 0;
    }
    
    /**
     * Extract parameter value from Argon2 params string.
     */
    private static String extractParam(String params, String key) {
        for (String param : params.split(",")) {
            if (param.startsWith(key + "=")) {
                return param.substring(key.length() + 1);
            }
        }
        throw new IllegalArgumentException("Parameter not found: " + key);
    }
}
