package main;
import com.itc.studentmgmt.database.DatabaseConnection;
import com.itc.studentmgmt.security.TwoFactorAuthService;
import com.itc.studentmgmt.ui.LoginFrame;
import java.sql.SQLException;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;

/**
 * Main application entry point
 * Initializes the Student Management System
 */
public class main {
    
    public static void main(String[] args) {
        // Print startup banner
        printBanner();
        
        try {
            // Set system look and feel for better UI
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
            
            // Test database connection
            System.out.println("🔌 Testing database connection...");
            DatabaseConnection.getInstance();
            System.out.println("✅ Database connection successful!\n");
            
            // Display connection pool statistics
            System.out.println("📊 Connection Pool Status:");
            System.out.println("   " + DatabaseConnection.getInstance().getPoolStats());
            System.out.println();
            
            // Display 2FA configuration status
            System.out.println(TwoFactorAuthService.getConfigurationStatus());
            
            // Launch the login GUI
            System.out.println("🚀 Launching application...\n");
            SwingUtilities.invokeLater(() -> {
                LoginFrame loginFrame = new LoginFrame();  // ← THIS CREATES YOUR UI!
                loginFrame.setVisible(true);                // ← THIS SHOWS YOUR UI!
            });
            
            // Add shutdown hook to properly close connections
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                System.out.println("\n👋 Shutting down application...");
                try {
                    DatabaseConnection.getInstance().closeConnectionPool();
                    System.out.println("✅ Cleanup completed");
                } catch (SQLException e) {
                    System.err.println("⚠️  Error during cleanup: " + e.getMessage());
                }
            }));
            
        } catch (SQLException e) {
            System.err.println("\n❌ DATABASE CONNECTION FAILED!");
            System.err.println("=".repeat(60));
            System.err.println("Error: " + e.getMessage());
            System.err.println("=".repeat(60));
            System.err.println("\n🔍 Troubleshooting Steps:");
            System.err.println("1. Check if MySQL server is running");
            System.err.println("2. Verify database 'stu_manage' exists:");
            System.err.println("   CREATE DATABASE IF NOT EXISTS stu_manage;");
            System.err.println("3. Check database credentials in DatabaseConnection.java");
            System.err.println("4. If using encrypted password, verify environment variables:");
            System.err.println("   - DB_PASSWORD_ENCRYPTED");
            System.err.println("   - DB_MASTER_KEY");
            System.err.println("   - DB_SALT");
            System.err.println("5. Run DatabaseSetup.java to initialize tables");
            System.err.println("=".repeat(60));
            System.exit(1);
            
        } catch (Exception e) {
            System.err.println("\n❌ APPLICATION ERROR: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
    
    /**
     * Print application startup banner
     */
    private static void printBanner() {
        System.out.println();
        System.out.println("╔═══════════════════════════════════════════════════════════╗");
        System.out.println("║                                                           ║");
        System.out.println("║          STUDENT MANAGEMENT SYSTEM v2.0                   ║");
        System.out.println("║          Institute of Technology Cambodia                 ║");
        System.out.println("║                                                           ║");
        System.out.println("║          🔒 Secured with Argon2id Encryption             ║");
        System.out.println("║                                                           ║");
        System.out.println("╚═══════════════════════════════════════════════════════════╝");
        System.out.println();
    }
}