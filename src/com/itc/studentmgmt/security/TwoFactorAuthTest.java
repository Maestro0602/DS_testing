package com.itc.studentmgmt.security;

/**
 * Simple test for 2FA configuration
 * Run with: java -cp "bin;lib/*" com.itc.studentmgmt.security.TwoFactorAuthTest
 */
public class TwoFactorAuthTest {
    
    public static void main(String[] args) {
        System.out.println("\n===========================================");
        System.out.println("    TWO-FACTOR AUTHENTICATION TEST");
        System.out.println("===========================================\n");
        
        // Print configuration status
        System.out.println(TwoFactorAuthService.getConfigurationStatus());
        
        // Check if configured
        if (!TwoFactorAuthService.isConfigured()) {
            System.out.println("\n[!] 2FA is not configured yet.");
            System.out.println("\nTo configure 2FA, set these environment variables:");
            System.out.println("\nFor Telegram:");
            System.out.println("  TELEGRAM_BOT_TOKEN = your_bot_token");
            System.out.println("  TELEGRAM_CHAT_ID = your_chat_id");
            System.out.println("\nFor Discord:");
            System.out.println("  DISCORD_WEBHOOK_URL = your_webhook_url");
            System.out.println("\nChannel selection:");
            System.out.println("  TFA_NOTIFICATION_CHANNEL = telegram | discord | both");
            System.out.println("\nSee 2FA_SETUP_GUIDE.md for detailed instructions.");
            return;
        }
        
        // Test sending a code
        System.out.println("[*] Testing 2FA code generation and sending...\n");
        
        String testUsername = "test_user";
        TwoFactorAuthService.TwoFactorResult result = 
            TwoFactorAuthService.generateAndSendCode(testUsername);
        
        switch (result) {
            case SUCCESS:
                System.out.println("\n[+] SUCCESS! Check your Telegram/Discord for the test code.");
                System.out.println("    This confirms 2FA is working correctly!");
                break;
            case SEND_FAILED:
                System.out.println("\n[-] Failed to send the code.");
                System.out.println("    Check your configuration and network connection.");
                break;
            case NOT_CONFIGURED:
                System.out.println("\n[-] 2FA is not configured.");
                break;
            default:
                System.out.println("\n[?] Unexpected result: " + result);
        }
        
        System.out.println("\n===========================================");
        System.out.println("    TEST COMPLETE");
        System.out.println("===========================================\n");
    }
}
