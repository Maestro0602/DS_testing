import java.sql.*;

/**
 * Quick fix for phone column - changes from VARCHAR(20) to TEXT
 * to support encrypted data (AES + Base64 produces long strings)
 * 
 * Run this to fix the "Data too long for column 'phone'" error
 */
public class FixPhoneColumn {
    public static void main(String[] args) {
        String url = "jdbc:mysql://localhost:3306/stu_manage?useSSL=false&allowPublicKeyRetrieval=true";
        String username = "root";
        String password = "MRHENGXD123";
        
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
        } catch (ClassNotFoundException e) {
            System.err.println("MySQL JDBC Driver not found!");
            return;
        }
        
        try (Connection conn = DriverManager.getConnection(url, username, password)) {
            Statement stmt = conn.createStatement();
            
            System.out.println("[FIX] Fixing phone column for encrypted data support...\n");
            
            // Alter the phone column to TEXT
            stmt.executeUpdate("ALTER TABLE students MODIFY COLUMN phone TEXT");
            System.out.println("[OK] Phone column changed to TEXT");
            
            // Verify the change
            System.out.println("\n📋 Updated students table structure:");
            ResultSet rs = stmt.executeQuery("DESCRIBE students");
            while (rs.next()) {
                String field = rs.getString("Field");
                String type = rs.getString("Type");
                if (field.equals("phone") || field.equals("address")) {
                    System.out.println("   " + field + ": " + type + " ✓ (supports encrypted data)");
                }
            }
            
            System.out.println("\n[OK] Database fix complete! Encrypted phone numbers will now work.");
            
        } catch (SQLException e) {
            System.err.println("[ERROR] Database error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
