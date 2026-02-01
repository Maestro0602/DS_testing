# 🔐 Student Management System - FORTRESS EDITION

## Security Architecture Overview

This application implements **military-grade security** with multiple layers of protection. Here's what makes it secure:

---

## 🛡️ Security Features

### 1. Multi-Layer Password Vault (5 Layers!)

```
╔═══════════════════════════════════════════════════════════════════════════╗
║  Layer 1: PEPPER (Secret server-side key mixed with HMAC)                 ║
║  Layer 2: ARGON2ID (128MB memory-hard password hashing)                   ║
║  Layer 3: AES-256-GCM (Authenticated encryption of hash)                  ║
║  Layer 4: HMAC-SHA512 (Integrity signature)                               ║
║  Layer 5: PBKDF2-SHA512 (600,000 iteration key derivation)                ║
╚═══════════════════════════════════════════════════════════════════════════╝
```

**Password Format:** `$MLP$v1$[salt]$[pepper_id]$[params]$[encrypted_hmac_hash]`

### 2. End-to-End Encryption (E2E)

- **ECDH Key Exchange** (P-384 Curve - 192-bit security)
- **AES-256-GCM** for symmetric encryption
- **Perfect Forward Secrecy** with ephemeral keys
- **AEAD** (Authenticated Encryption with Associated Data)

### 3. Secure Session Management

- Cryptographic session tokens (256-bit)
- HMAC-SHA256 token signatures
- Encrypted session storage
- Automatic token rotation (every 10 minutes)
- IP/User-Agent binding (session hijacking protection)
- Maximum 3 concurrent sessions per user

### 4. Intrusion Detection System (IDS)

- **Sliding window rate limiting**
- **Brute force attack detection**
- **Threat scoring system** (auto-blocking at threshold)
- **SQL injection detection**
- **XSS pattern detection**
- **Real-time security alerts**

### 5. Sensitive Data Protection

- Field-level encryption for PII
- **Searchable encryption** (blind index)
- Data masking for display
- PII detection and redaction
- Automatic data classification

### 6. Security Audit Logging

- **Tamper-evident logs** (blockchain-style hash chain)
- Event classification (AUTH, AUTHZ, DATA, SECURITY)
- Severity levels (INFO, WARN, ERROR, CRITICAL)
- Async non-blocking logging
- Log integrity verification

---

## 📁 Security Module Files

```
src/com/itc/studentmgmt/security/
├── CryptoCore.java              # Core cryptographic operations
├── MultiLayerPasswordVault.java # 5-layer password protection
├── E2EEncryption.java           # End-to-end encryption
├── SecureSessionManager.java    # Session management
├── SensitiveDataProtector.java  # PII encryption/masking
├── SecurityAuditLogger.java     # Audit logging system
├── IntrusionDetection.java      # IDS & rate limiting
└── PasswordSecurityUtil.java    # Password utilities (enhanced)
```

---

## 🚀 Quick Usage Examples

### Password Hashing (5 Layers)
```java
// Hash with multi-layer protection
String hash = PasswordSecurityUtil.hashPassword("MySecureP@ssw0rd!");

// Verify (auto-detects format)
boolean valid = PasswordSecurityUtil.verifyPassword("MySecureP@ssw0rd!", hash);
```

### E2E Encryption
```java
// Generate key pair
KeyPair keyPair = E2EEncryption.generateKeyPair();

// Encrypt for recipient
String encrypted = E2EEncryption.encryptForRecipient("Secret data", recipientPublicKey);

// Decrypt with private key
String decrypted = E2EEncryption.decryptWithPrivateKey(encrypted, privateKey);
```

### Session Management
```java
// Create session
String token = SecureSessionManager.createSession(username, role, ipAddress, userAgent);

// Validate session
Session session = SecureSessionManager.validateSession(token, ipAddress, userAgent);

// Logout
SecureSessionManager.invalidateAllUserSessions(username);
```

### PII Protection
```java
// Encrypt email with searchable index
EncryptedSearchableField result = SensitiveDataProtector.encryptEmail("user@example.com");
// result.encryptedValue - encrypted email
// result.blindIndex - for searching without decryption

// Mask for display
String masked = SensitiveDataProtector.maskEmail("user@example.com"); // us***@example.com
```

### Security Audit
```java
// Log security event
SecurityAuditLogger.logLoginSuccess(username, ipAddress);
SecurityAuditLogger.logLoginFailure(username, ipAddress, "Invalid password");

// Verify log integrity
boolean valid = SecurityAuditLogger.verifyLogIntegrity("security_logs/audit_2024-01-15.log");
```

### Intrusion Detection
```java
// Check if login allowed (rate limiting)
if (IntrusionDetection.allowLoginAttempt(ipAddress)) {
    // Process login
}

// Record failed attempt (threat scoring)
IntrusionDetection.recordFailedLogin(ipAddress, username);

// Check for SQL injection
if (IntrusionDetection.detectSqlInjection(userInput)) {
    // Block request!
}
```

---

## 🔧 Environment Variables

For production, set these environment variables:

```bash
# Pepper for password hashing (32-byte Base64)
SYSTEM_PEPPER=<base64-encoded-32-bytes>

# Data encryption keys
DATA_ENCRYPTION_KEY=<base64-encoded-32-bytes>
BLIND_INDEX_KEY=<base64-encoded-32-bytes>

# Session keys
SESSION_SIGNING_KEY=<base64-encoded-32-bytes>
SESSION_ENCRYPTION_KEY=<base64-encoded-32-bytes>

# Database encryption
DB_MASTER_KEY=<your-master-key>
DB_SALT=<base64-encoded-salt>
DB_PASSWORD_ENCRYPTED=<encrypted-password>
```

---

## 📊 Security Comparison

| Feature | Before | After (FORTRESS) |
|---------|--------|------------------|
| Password Hashing | Argon2id (64MB, 3 iter) | 5-Layer Vault (128MB, 4 iter + AES + HMAC) |
| Key Derivation | PBKDF2 (310K iter) | PBKDF2-SHA512 (600K iter) |
| Session Tokens | None | 256-bit encrypted + signed |
| Rate Limiting | None | Sliding window + threat scoring |
| Audit Logging | Basic | Hash-chain tamper-evident |
| Data Protection | None | Field-level encryption + masking |
| E2E Encryption | None | ECDH + AES-256-GCM |

---

## 📚 Dependencies

- **BouncyCastle** - Argon2id implementation
- **HikariCP** - Connection pooling
- **MySQL Connector** - Database driver

---

## Getting Started

### Folder Structure

- `src/` - Source code
- `lib/` - Dependencies  
- `bin/` - Compiled output
- `security_logs/` - Audit logs

### Running the Application

1. Set up MySQL database
2. Configure environment variables
3. Run `main.java`

---

## ⚠️ Security Notes

1. **NEVER commit secrets to Git** - Use environment variables
2. **Rotate keys regularly** - Especially after personnel changes
3. **Monitor audit logs** - Check for CRITICAL events
4. **Keep dependencies updated** - Security patches
5. **Use HTTPS in production** - TLS 1.3 recommended

---

## 📝 License

Educational use only. Implement proper security review before production deployment.
---

## 🧪 Testing the Application

### Local Testing (Windows)

1. **Compile the project:**
   ```cmd
   cd "d:\gay subject\DataSecurity"
   javac -encoding UTF-8 -cp "lib/*" -d bin -sourcepath src src/main/main.java
   ```

2. **Run the application:**
   ```cmd
   java -cp "bin;lib/*" main.main
   ```

3. **Test password hashing:**
   ```java
   // In your test code or main method:
   String password = "TestP@ssw0rd123!";
   String hash = PasswordSecurityUtil.hashPassword(password);
   System.out.println("Hash: " + hash);
   boolean valid = PasswordSecurityUtil.verifyPassword(password, hash);
   System.out.println("Valid: " + valid);
   ```

### Unit Testing Security Components

```java
// Test Multi-Layer Password Vault
public class SecurityTest {
    public static void main(String[] args) {
        // Test 1: Password hashing and verification
        String testPassword = "MyS3cur3P@ssw0rd!";
        String hash = MultiLayerPasswordVault.hashPassword(testPassword);
        assert MultiLayerPasswordVault.verifyPassword(testPassword, hash);
        assert !MultiLayerPasswordVault.verifyPassword("wrong", hash);
        System.out.println("✅ Password hashing test passed");
        
        // Test 2: Session management
        String token = SecureSessionManager.createSession("testuser", "ADMIN", "127.0.0.1", "TestAgent");
        assert token != null;
        System.out.println("✅ Session creation test passed");
        
        // Test 3: Intrusion detection
        for (int i = 0; i < 10; i++) {
            IntrusionDetection.recordFailedLogin("192.168.1.100", "attacker");
        }
        assert !IntrusionDetection.allowLoginAttempt("192.168.1.100");
        System.out.println("✅ Intrusion detection test passed");
    }
}
```

---

## 🐧 Deploying to Linux Server

### Prerequisites

- Ubuntu 20.04+ / CentOS 8+ / Debian 11+
- Java 11+ (OpenJDK recommended)
- MySQL 8.0+
- Minimum 2GB RAM (for Argon2id memory requirements)

### Step 1: Prepare the Server

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Java
sudo apt install openjdk-17-jdk -y

# Install MySQL
sudo apt install mysql-server -y
sudo mysql_secure_installation

# Create application directory
sudo mkdir -p /opt/studentmgmt
sudo chown $USER:$USER /opt/studentmgmt
```

### Step 2: Transfer Files to Server

```bash
# From your Windows machine (use SCP or WinSCP)
scp -r "d:\gay subject\DataSecurity\*" user@your-server:/opt/studentmgmt/

# Or using rsync (faster for updates)
rsync -avz --progress "d:\gay subject\DataSecurity/" user@your-server:/opt/studentmgmt/
```

### Step 3: Configure Database

```bash
# Login to MySQL
sudo mysql -u root -p

# Create database and user
CREATE DATABASE studentmgmt CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'studentapp'@'localhost' IDENTIFIED BY 'YourStr0ngP@ssw0rd!';
GRANT ALL PRIVILEGES ON studentmgmt.* TO 'studentapp'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

### Step 4: Set Environment Variables

```bash
# Create environment file
sudo nano /etc/studentmgmt/env.conf

# Add these lines (generate real random values!):
export SYSTEM_PEPPER=$(openssl rand -base64 32)
export DATA_ENCRYPTION_KEY=$(openssl rand -base64 32)
export BLIND_INDEX_KEY=$(openssl rand -base64 32)
export SESSION_SIGNING_KEY=$(openssl rand -base64 32)
export SESSION_ENCRYPTION_KEY=$(openssl rand -base64 32)
export DB_URL="jdbc:mysql://localhost:3306/studentmgmt?useSSL=true"
export DB_USER="studentapp"
export DB_PASSWORD="YourStr0ngP@ssw0rd!"

# Source the environment
source /etc/studentmgmt/env.conf
```

### Step 5: Compile and Run

```bash
cd /opt/studentmgmt

# Compile
javac -cp "lib/*:src" -d bin src/main/main.java src/com/itc/studentmgmt/**/*.java

# Run
java -cp "bin:lib/*" main.main
```

### Step 6: Create Systemd Service (Auto-start)

```bash
sudo nano /etc/systemd/system/studentmgmt.service
```

Add this content:
```ini
[Unit]
Description=Student Management System
After=network.target mysql.service

[Service]
Type=simple
User=studentapp
WorkingDirectory=/opt/studentmgmt
EnvironmentFile=/etc/studentmgmt/env.conf
ExecStart=/usr/bin/java -Xmx512m -cp "bin:lib/*" main.main
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable studentmgmt
sudo systemctl start studentmgmt
sudo systemctl status studentmgmt
```

### Step 7: Configure Firewall

```bash
# If using GUI over network (not recommended for production)
sudo ufw allow 3306/tcp  # MySQL (only if needed externally)
sudo ufw allow 22/tcp    # SSH
sudo ufw enable
```

---

## 🔒 How Security Information Flows

### Authentication Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        USER LOGIN SECURITY FLOW                              │
└─────────────────────────────────────────────────────────────────────────────┘

 User                    Client                     Server                   Database
  │                        │                          │                         │
  │ 1. Enter credentials   │                          │                         │
  │───────────────────────>│                          │                         │
  │                        │                          │                         │
  │                        │ 2. Hash password         │                         │
  │                        │    (client-side)         │                         │
  │                        │                          │                         │
  │                        │ 3. Send over HTTPS       │                         │
  │                        │──────────────────────────>                         │
  │                        │   (TLS 1.3 encrypted)    │                         │
  │                        │                          │                         │
  │                        │                          │ 4. Rate limit check     │
  │                        │                          │    IntrusionDetection   │
  │                        │                          │                         │
  │                        │                          │ 5. Fetch user hash     │
  │                        │                          │────────────────────────>│
  │                        │                          │<────────────────────────│
  │                        │                          │   (stored MLP hash)     │
  │                        │                          │                         │
  │                        │                          │ 6. Verify password      │
  │                        │                          │    ┌─────────────────┐  │
  │                        │                          │    │ 5-LAYER VERIFY  │  │
  │                        │                          │    │ ┌─────────────┐ │  │
  │                        │                          │    │ │ HMAC-SHA512 │ │  │
  │                        │                          │    │ │ (integrity) │ │  │
  │                        │                          │    │ └──────┬──────┘ │  │
  │                        │                          │    │ ┌──────▼──────┐ │  │
  │                        │                          │    │ │ AES-256-GCM │ │  │
  │                        │                          │    │ │ (decrypt)   │ │  │
  │                        │                          │    │ └──────┬──────┘ │  │
  │                        │                          │    │ ┌──────▼──────┐ │  │
  │                        │                          │    │ │ Argon2id    │ │  │
  │                        │                          │    │ │ 128MB/4iter │ │  │
  │                        │                          │    │ └──────┬──────┘ │  │
  │                        │                          │    │ ┌──────▼──────┐ │  │
  │                        │                          │    │ │ PBKDF2-512K │ │  │
  │                        │                          │    │ └──────┬──────┘ │  │
  │                        │                          │    │ ┌──────▼──────┐ │  │
  │                        │                          │    │ │ PEPPER+HMAC │ │  │
  │                        │                          │    │ └─────────────┘ │  │
  │                        │                          │    └─────────────────┘  │
  │                        │                          │                         │
  │                        │                          │ 7. If valid:            │
  │                        │                          │    Create session       │
  │                        │                          │    ┌─────────────────┐  │
  │                        │                          │    │ SecureSession   │  │
  │                        │                          │    │ - 256-bit token │  │
  │                        │                          │    │ - HMAC signed   │  │
  │                        │                          │    │ - IP bound      │  │
  │                        │                          │    │ - Time-limited  │  │
  │                        │                          │    └─────────────────┘  │
  │                        │                          │                         │
  │                        │ 8. Return session token  │                         │
  │                        │<─────────────────────────│                         │
  │                        │   (encrypted + signed)   │                         │
  │                        │                          │                         │
  │ 9. Store token        │                          │                         │
  │<───────────────────────│                          │                         │
  │   (secure cookie)      │                          │                         │
  │                        │                          │                         │
  │                        │                          │ 10. Log to audit        │
  │                        │                          │     SecurityAuditLogger │
  │                        │                          │     (hash-chain linked) │
  └────────────────────────┴──────────────────────────┴─────────────────────────┘
```

### Password Storage Format

```
$MLP$v1$[salt_b64]$[pepper_id]$[argon2_params]$[encrypted_hmac_hash_b64]
  │   │     │          │            │                    │
  │   │     │          │            │                    └── Encrypted + HMAC signed hash
  │   │     │          │            └── m=131072,t=4,p=8 (Argon2 params)
  │   │     │          └── Pepper version for key rotation
  │   │     └── 32-byte random salt (Base64)
  │   └── Format version
  └── Multi-Layer Password indicator
```

### Data Encryption Flow (PII Protection)

```
┌────────────────────────────────────────────────────────────────────────────┐
│                     SENSITIVE DATA PROTECTION FLOW                          │
└────────────────────────────────────────────────────────────────────────────┘

   Original Data          Encryption Process            Stored Data
        │                        │                           │
   "john@email.com"              │                           │
        │                        │                           │
        ├───────────────────────>│ 1. Generate random IV     │
        │                        │                           │
        │                        │ 2. AES-256-GCM encrypt    │
        │                        │    with DATA_KEY + IV     │
        │                        │                           │
        │                        │ 3. Create blind index     │
        │                        │    HMAC(email, INDEX_KEY) │
        │                        │                           │
        │                        │ 4. Store both:            │
        │                        ├──────────────────────────>│
        │                        │                           │
        │                        │   encrypted_email: "..."  │
        │                        │   email_index: "abc123"   │
        │                        │                           │
        │                        │                           │
   Search Query                  │                           │
   "john@email.com"              │                           │
        │                        │                           │
        ├───────────────────────>│ 5. Hash search term       │
        │                        │    HMAC(query, INDEX_KEY) │
        │                        │                           │
        │                        │ 6. Search by blind index  │
        │                        │────────────────────────>  │
        │                        │<────────────────────────  │
        │                        │   (matches without        │
        │                        │    decrypting all rows!)  │
        │                        │                           │
   Display (masked)              │ 7. Decrypt matched row    │
   "jo***@email.com"             │                           │
        │<───────────────────────│ 8. Mask for display       │
        │                        │                           │
└────────────────────────────────┴───────────────────────────┴───────────────┘
```

### Session Security Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         SESSION TOKEN STRUCTURE                              │
└─────────────────────────────────────────────────────────────────────────────┘

Token Format: BASE64( ENCRYPT( SESSION_ID + RAW_TOKEN + TIMESTAMP + SIGNATURE ) )

Components:
┌───────────────┬────────────────┬─────────────┬──────────────────────────────┐
│  SESSION_ID   │   RAW_TOKEN    │  TIMESTAMP  │       HMAC-SHA256 SIG        │
│  (32 bytes)   │   (32 bytes)   │  (8 bytes)  │        (32 bytes)            │
└───────────────┴────────────────┴─────────────┴──────────────────────────────┘
        │                │               │                    │
        │                │               │                    └── Signs all above
        │                │               └── Expiration check    with SESSION_SIGNING_KEY
        │                └── Matched against stored hash
        └── Lookup key in session store

Validation Steps:
1. Decrypt token with SESSION_ENCRYPTION_KEY
2. Verify HMAC signature
3. Check timestamp not expired
4. Verify IP address matches (anti-hijacking)
5. Verify User-Agent matches (anti-hijacking)
6. Check if token hash matches stored hash
7. Rotate token if > 10 minutes old
```

### Intrusion Detection Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       INTRUSION DETECTION SYSTEM                             │
└─────────────────────────────────────────────────────────────────────────────┘

Request ──────> Rate Limiter ──────> Pattern Detection ──────> Threat Scoring
                    │                       │                        │
                    │                       │                        │
                    ▼                       ▼                        ▼
           ┌───────────────┐      ┌─────────────────┐      ┌─────────────────┐
           │ Sliding Window│      │ SQL Injection?  │      │ Score > 100?    │
           │ 10 req/min?   │      │ XSS Pattern?    │      │ Block IP!       │
           │               │      │ Path Traversal? │      │                 │
           └───────────────┘      └─────────────────┘      └─────────────────┘
                    │                       │                        │
                    ▼                       ▼                        ▼
              ✓ Allow            ⚠️ Log + Score +5           ❌ 403 Blocked
                                                              IP Blacklisted
```

---

## 🔑 Generating Secure Keys

Use these commands to generate cryptographically secure keys:

```bash
# Generate 32-byte Base64 key
openssl rand -base64 32

# Generate hex key (for debugging)
openssl rand -hex 32

# Generate pepper specifically
echo "SYSTEM_PEPPER=$(openssl rand -base64 32)"
echo "DATA_ENCRYPTION_KEY=$(openssl rand -base64 32)"
echo "BLIND_INDEX_KEY=$(openssl rand -base64 32)"
echo "SESSION_SIGNING_KEY=$(openssl rand -base64 32)"
echo "SESSION_ENCRYPTION_KEY=$(openssl rand -base64 32)"
```

---

## 🐛 Troubleshooting

### BouncyCastle Library Not Found
```bash
# Ensure library is in classpath
java -cp "bin:lib/bcprov-jdk18on-1.77.jar:lib/*" main.main
```

### OutOfMemoryError with Argon2id
```bash
# Increase JVM heap size (Argon2id needs 128MB)
java -Xmx512m -cp "bin:lib/*" main.main
```

### Database Connection Issues
```bash
# Check MySQL is running
sudo systemctl status mysql

# Test connection
mysql -u studentapp -p -h localhost studentmgmt
```

---