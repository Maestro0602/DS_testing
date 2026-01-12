package com.itc.studentmgmt.util;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Scanner;

/**
 * Utility to encrypt your database password
 * Run this once to generate encrypted credentials
 */
public class PasswordEncryptor {
    
    private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int ITERATIONS = 310000;
    private static final int KEY_LENGTH = 256;
    
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        
        try {
            System.out.println("=== Database Password Encryptor ===\n");
            
            System.out.print("Enter your MySQL password (MRHENGXD123): ");
            String password = scanner.nextLine();
            
            System.out.print("Enter a master key (min 32 characters): ");
            String masterKey = scanner.nextLine();
            
            if (masterKey.length() < 32) {
                System.out.println("\n❌ Master key must be at least 32 characters!");
                return;
            }
            
            // Generate random salt
            byte[] salt = new byte[16];
            new java.security.SecureRandom().nextBytes(salt);
            String saltBase64 = Base64.getEncoder().encodeToString(salt);
            
            // Derive encryption key from master key
            SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM);
            KeySpec spec = new PBEKeySpec(masterKey.toCharArray(), salt, ITERATIONS, KEY_LENGTH);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");
            
            // Encrypt password
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, secret);
            byte[] encrypted = cipher.doFinal(password.getBytes());
            String encryptedBase64 = Base64.getEncoder().encodeToString(encrypted);
            
            // Display results
            System.out.println("\n" + "=".repeat(60));
            System.out.println("✅ ENCRYPTION SUCCESSFUL!");
            System.out.println("=".repeat(60));
            System.out.println("\n📋 COPY THESE VALUES:\n");
            System.out.println("DB_PASSWORD_ENCRYPTED=" + encryptedBase64);
            System.out.println("DB_SALT=" + saltBase64);
            System.out.println("DB_MASTER_KEY=" + masterKey);
            System.out.println("\n" + "=".repeat(60));
            System.out.println("⚠️  IMPORTANT SECURITY NOTES:");
            System.out.println("=".repeat(60));
            System.out.println("1. Store DB_MASTER_KEY in a SECURE location (not in code!)");
            System.out.println("2. Set these as environment variables");
            System.out.println("3. NEVER commit these values to Git");
            System.out.println("=".repeat(60) + "\n");
            
        } catch (Exception e) {
            System.err.println("\n❌ Encryption failed: " + e.getMessage());
            e.printStackTrace();
        } finally {
            scanner.close();
        }
    }
}