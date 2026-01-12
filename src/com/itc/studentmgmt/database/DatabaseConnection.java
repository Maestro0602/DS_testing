package com.itc.studentmgmt.database;

import java.sql.*;
import java.util.Properties;
import java.io.InputStream;
import java.io.IOException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.spec.KeySpec;
import java.util.Base64;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;

/**
 * Singleton class for managing secure database connections
 * Implements connection pooling, encrypted credentials, and SQL injection prevention
 * Uses HikariCP for enterprise-grade connection management
 */
public class DatabaseConnection {
    // Encryption constants (in production, store these in a secure vault/HSM)
    private static final String ENCRYPTION_ALGORITHM = "AES";
    private static final String KEY_DERIVATION_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int ITERATION_COUNT = 310000; // OWASP 2023 recommendation
    private static final int KEY_LENGTH = 256;
    
    // Singleton instance
    private static volatile DatabaseConnection instance;
    private HikariDataSource dataSource;
    
    /**
     * Private constructor to prevent direct instantiation
     * Establishes secure connection pool to MySQL database
     * @throws SQLException if connection fails
     */
    private DatabaseConnection() throws SQLException {
        try {
            // Load configuration from external secure file
            Properties props = loadSecureConfig();
            
            // Configure HikariCP for optimal security and performance
            HikariConfig config = new HikariConfig();
            
            // Basic connection settings
            config.setJdbcUrl(props.getProperty("db.url"));
            config.setUsername(props.getProperty("db.username"));
            config.setPassword(decryptPassword(props.getProperty("db.password.encrypted")));
            
            // Security settings
            config.addDataSourceProperty("useSSL", "true");
            config.addDataSourceProperty("requireSSL", "true");
            config.addDataSourceProperty("verifyServerCertificate", "true");
            config.addDataSourceProperty("allowPublicKeyRetrieval", "false");
            config.addDataSourceProperty("useUnicode", "true");
            config.addDataSourceProperty("characterEncoding", "UTF-8");
            
            // Prevent SQL injection through connection properties
            config.addDataSourceProperty("allowMultiQueries", "false");
            config.addDataSourceProperty("allowLoadLocalInfile", "false");
            config.addDataSourceProperty("autoDeserialize", "false");
            
            // Connection pool settings for reliability
            config.setMaximumPoolSize(10);
            config.setMinimumIdle(2);
            config.setConnectionTimeout(30000); // 30 seconds
            config.setIdleTimeout(600000); // 10 minutes
            config.setMaxLifetime(1800000); // 30 minutes
            config.setLeakDetectionThreshold(60000); // 1 minute
            
            // Validation query to ensure connections are alive
            config.setConnectionTestQuery("SELECT 1");
            
            // Pool name for monitoring
            config.setPoolName("StudentMgmtPool");
            
            // Initialize the data source
            this.dataSource = new HikariDataSource(config);
            
            System.out.println("Secure database connection pool established successfully!");
            
        } catch (Exception e) {
            throw new SQLException("Failed to establish secure database connection: " + e.getMessage(), e);
        }
    }
    
    /**
     * Thread-safe singleton instance getter with double-checked locking
     * @return DatabaseConnection instance
     * @throws SQLException if connection cannot be established
     */
    public static DatabaseConnection getInstance() throws SQLException {
        if (instance == null) {
            synchronized (DatabaseConnection.class) {
                if (instance == null) {
                    instance = new DatabaseConnection();
                }
            }
        }
        return instance;
    }
    
    /**
     * Get a connection from the pool
     * @return Connection object
     * @throws SQLException if connection cannot be obtained
     */
    public Connection getConnection() throws SQLException {
        if (dataSource == null || dataSource.isClosed()) {
            throw new SQLException("Connection pool is closed");
        }
        return dataSource.getConnection();
    }
    
    /**
     * Load secure configuration from external file
     * In production, use environment variables or a secure vault service
     * @return Properties object with configuration
     * @throws IOException if config file cannot be read
     */
    private Properties loadSecureConfig() throws IOException {
        Properties props = new Properties();
        
        // Try to load from external config file first
        try (InputStream input = getClass().getClassLoader()
                .getResourceAsStream("db-config.properties")) {
            if (input != null) {
                props.load(input);
                return props;
            }
        } catch (IOException e) {
            System.err.println("Warning: Could not load external config, using environment variables");
        }
        
        // Fallback to environment variables (more secure for production)
        props.setProperty("db.url", getEnvOrDefault("DB_URL", 
            "jdbc:mysql://localhost:3306/stu_manage?useSSL=true&requireSSL=true"));
        props.setProperty("db.username", getEnvOrDefault("DB_USERNAME", "root"));
        props.setProperty("db.password.encrypted", getEnvOrDefault("DB_PASSWORD_ENCRYPTED", ""));
        
        return props;
    }
    
    /**
     * Get environment variable or default value
     * @param key Environment variable name
     * @param defaultValue Default value if not found
     * @return Environment variable value or default
     */
    private String getEnvOrDefault(String key, String defaultValue) {
        String value = System.getenv(key);
        return (value != null && !value.isEmpty()) ? value : defaultValue;
    }
    
    /**
     * Decrypt password using AES-256 with PBKDF2
     * @param encryptedPassword Base64 encoded encrypted password
     * @return Decrypted password
     * @throws Exception if decryption fails
     */
    private String decryptPassword(String encryptedPassword) throws Exception {
        // In production, retrieve master key from secure vault (AWS KMS, Azure Key Vault, etc.)
        String masterPassword = System.getenv("DB_MASTER_KEY");
        if (masterPassword == null || masterPassword.isEmpty()) {
            throw new SecurityException("Master key not found. Set DB_MASTER_KEY environment variable.");
        }
        
        // Derive key from master password using PBKDF2
        byte[] salt = getSalt(); // In production, store salt securely
        SecretKeyFactory factory = SecretKeyFactory.getInstance(KEY_DERIVATION_ALGORITHM);
        KeySpec spec = new PBEKeySpec(masterPassword.toCharArray(), salt, ITERATION_COUNT, KEY_LENGTH);
        SecretKey tmp = factory.generateSecret(spec);
        SecretKey secret = new SecretKeySpec(tmp.getEncoded(), ENCRYPTION_ALGORITHM);
        
        // Decrypt password
        Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secret);
        byte[] decodedPassword = Base64.getDecoder().decode(encryptedPassword);
        byte[] decryptedPassword = cipher.doFinal(decodedPassword);
        
        return new String(decryptedPassword);
    }
    
    /**
     * Get salt for key derivation
     * In production, store this securely and never hardcode
     * @return Salt bytes
     */
    private byte[] getSalt() {
        // WARNING: In production, store salt in secure configuration
        // This is just an example - DO NOT use hardcoded salt in production
        String saltEnv = System.getenv("DB_SALT");
        if (saltEnv != null && !saltEnv.isEmpty()) {
            return Base64.getDecoder().decode(saltEnv);
        }
        return new byte[]{-12, 45, 78, -90, 34, -67, 89, 123, -45, 67, -89, 12, 34, -56, 78, 90};
    }
    
    /**
     * Initialize the database schema with prepared statements
     * Prevents SQL injection attacks
     * @throws SQLException if table creation fails
     */
    public static void initializeDatabase() throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        
        try {
            conn = getInstance().getConnection();
            
            // Create users table with enhanced security
            String createUsersTable = 
                "CREATE TABLE IF NOT EXISTS users (" +
                "user_id BIGINT AUTO_INCREMENT PRIMARY KEY," +
                "username VARCHAR(50) UNIQUE NOT NULL," +
                "password_hash VARCHAR(255) NOT NULL," + // Use bcrypt/Argon2
                "salt VARCHAR(255) NOT NULL," +
                "role VARCHAR(20) NOT NULL," +
                "failed_login_attempts INT DEFAULT 0," +
                "account_locked BOOLEAN DEFAULT FALSE," +
                "last_login TIMESTAMP NULL," +
                "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP," +
                "updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP," +
                "INDEX idx_username (username)," +
                "INDEX idx_role (role)" +
                ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci";
            
            pstmt = conn.prepareStatement(createUsersTable);
            pstmt.execute();
            pstmt.close();
            
            System.out.println("Users table ready with enhanced security");
            
            // Create students table with proper indexing
            String createStudentsTable = 
                "CREATE TABLE IF NOT EXISTS students (" +
                "id BIGINT AUTO_INCREMENT PRIMARY KEY," +
                "student_id VARCHAR(20) UNIQUE NOT NULL," +
                "name VARCHAR(100) NOT NULL," +
                "email VARCHAR(100) UNIQUE NOT NULL," +
                "major VARCHAR(50) NOT NULL," +
                "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP," +
                "updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP," +
                "INDEX idx_student_id (student_id)," +
                "INDEX idx_email (email)," +
                "INDEX idx_major (major)" +
                ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci";
            
            pstmt = conn.prepareStatement(createStudentsTable);
            pstmt.execute();
            
            System.out.println("Students table ready with proper indexing");
            
        } finally {
            if (pstmt != null) pstmt.close();
            if (conn != null) conn.close();
        }
    }
    
    /**
     * Safely close the database connection pool
     * Should be called when application is shutting down
     */
    public void closeConnectionPool() {
        if (dataSource != null && !dataSource.isClosed()) {
            dataSource.close();
            System.out.println("Database connection pool closed securely");
        }
    }
    
    /**
     * Get connection pool statistics for monitoring
     * @return String with pool statistics
     */
    public String getPoolStats() {
        if (dataSource != null) {
            return String.format(
                "Pool Stats - Active: %d, Idle: %d, Total: %d, Waiting: %d",
                dataSource.getHikariPoolMXBean().getActiveConnections(),
                dataSource.getHikariPoolMXBean().getIdleConnections(),
                dataSource.getHikariPoolMXBean().getTotalConnections(),
                dataSource.getHikariPoolMXBean().getThreadsAwaitingConnection()
            );
        }
        return "Pool not initialized";
    }
}