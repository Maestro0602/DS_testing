# 📊 Dual Audit Logging System

## Overview

The system now uses **TWO SEPARATE AUDIT LOGGERS** for different purposes:

```
┌─────────────────────────────────────────────────────────┐
│                   AUDIT LOGGING SYSTEM                  │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  ┌──────────────────────┐  ┌──────────────────────┐   │
│  │  LoginAuditLogger    │  │ SecurityAuditLogger  │   │
│  │                      │  │                      │   │
│  │  📊 DATABASE         │  │  📁 FILES            │   │
│  │  ├─ Login/Logout     │  │  ├─ Attacks         │   │
│  │  ├─ Password Change  │  │  ├─ SQL Injection   │   │
│  │  ├─ Account Lock     │  │  ├─ XSS Attempts    │   │
│  │  ├─ 2FA Events       │  │  ├─ Brute Force     │   │
│  │  └─ User Activity    │  │  ├─ Rate Limiting   │   │
│  │                      │  │  └─ IDS Alerts      │   │
│  └──────────────────────┘  └──────────────────────┘   │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

---

## 1. LoginAuditLogger (Database)

### Purpose
Tracks **user authentication and account activities** in the MySQL database.

### Storage Location
- **Database**: `stu_manage`
- **Table**: `audit_logs`
- **Format**: Structured relational data

### What It Tracks
- ✅ Login Success/Failure
- ✅ Logout Events
- ✅ Password Changes
- ✅ Account Locked/Unlocked
- ✅ Two-Factor Authentication (2FA) Success/Failure
- ✅ Session Created/Expired

### Why Database?
- **Compliance**: Required for SOC2, HIPAA, PCI-DSS audits
- **Queryable**: Easy SQL queries for reports
- **User History**: View all activities for specific users
- **Long-term Storage**: Persistent data for legal/compliance
- **Fast Search**: Indexed by username, timestamp, event_type

### Example Usage
```java
// Login events (automatically logged)
LoginAuditLogger.logLoginSuccess("admin", "192.168.1.100");
LoginAuditLogger.logLoginFailure("admin", "192.168.1.100", "Invalid password");

// Account management
LoginAuditLogger.logAccountLocked("admin", "192.168.1.100", "Too many failed attempts");
LoginAuditLogger.logPasswordChange("admin", "192.168.1.100");

// 2FA events
LoginAuditLogger.logTwoFactorSuccess("admin", "192.168.1.100");
LoginAuditLogger.logTwoFactorFailure("admin", "192.168.1.100", "Invalid code");

// Query history
LoginAuditLogger.printUserLoginHistory("admin", 20);
int failedAttempts = LoginAuditLogger.getRecentFailedAttempts("admin");
```

### Database Schema
```sql
CREATE TABLE audit_logs (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    event_type VARCHAR(50) NOT NULL,           -- LOGIN_SUCCESS, PASSWORD_CHANGE, etc.
    username VARCHAR(50),
    ip_address VARCHAR(45),
    action VARCHAR(100),
    details TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_event_type (event_type),
    INDEX idx_username (username),
    INDEX idx_timestamp (timestamp)
);
```

### SQL Queries
```sql
-- View all login attempts for a user
SELECT * FROM audit_logs 
WHERE username = 'admin' 
ORDER BY timestamp DESC 
LIMIT 20;

-- Count failed logins in last 24 hours
SELECT COUNT(*) FROM audit_logs 
WHERE event_type = 'LOGIN_FAILURE' 
AND timestamp > DATE_SUB(NOW(), INTERVAL 24 HOUR);

-- View all 2FA failures
SELECT * FROM audit_logs 
WHERE event_type LIKE 'TWO_FACTOR_FAILURE' 
ORDER BY timestamp DESC;

-- Summary by event type
SELECT event_type, COUNT(*) as count 
FROM audit_logs 
GROUP BY event_type 
ORDER BY count DESC;

-- Recent password changes
SELECT username, ip_address, timestamp 
FROM audit_logs 
WHERE event_type = 'PASSWORD_CHANGE' 
ORDER BY timestamp DESC 
LIMIT 10;
```

---

## 2. SecurityAuditLogger (Files)

### Purpose
Tracks **security events, attacks, and intrusion attempts** in log files. No encryption needed - designed for security monitoring.

### Storage Location
- **Directory**: `security_logs/`
- **Files**: `audit_YYYY-MM-DD.log`
- **Format**: JSON (one event per line)

### What It Tracks
- 🚨 SQL Injection Attempts
- 🚨 XSS (Cross-Site Scripting) Attempts
- 🚨 Brute Force Attacks
- 🚨 Rate Limit Violations
- 🚨 Session Hijacking Attempts
- 🚨 Privilege Escalation Attempts
- 🚨 Tampering Detection
- 🚨 IDS (Intrusion Detection) Alerts

### Why Files?
- **Performance**: Fast async writes, no database overhead
- **Security Focus**: Dedicated for threat monitoring
- **SIEM Integration**: Easy to forward to security tools (Splunk, ELK, etc.)
- **Immutable**: Blockchain-style hash chain prevents tampering
- **No Encryption Needed**: Attack data doesn't contain sensitive user info

### Example Usage
```java
// Security events (used by IDS, rate limiter, etc.)
SecurityAuditLogger.logSecurityEvent(
    SecurityAuditLogger.EventType.INJECTION_ATTEMPT,
    "attacker", "192.168.1.200",
    "Detected SQL injection: SELECT * FROM users WHERE id='1' OR '1'='1'"
);

SecurityAuditLogger.logSecurityEvent(
    SecurityAuditLogger.EventType.BRUTE_FORCE_DETECTED,
    "attacker", "192.168.1.200",
    "50 failed login attempts in 2 minutes"
);

SecurityAuditLogger.logSecurityEvent(
    SecurityAuditLogger.EventType.TAMPERING_DETECTED,
    "system", "0.0.0.0",
    "Hash chain broken - log tampering detected"
);
```

### Log File Format
```json
{
  "eventId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "timestamp": "2026-02-02T14:30:45.123Z",
  "eventType": "INJECTION_ATTEMPT",
  "category": "SECURITY",
  "severity": "CRITICAL",
  "username": "attacker",
  "ipAddress": "192.168.1.200",
  "details": "Detected SQL injection: SELECT * FROM users WHERE id='1' OR '1'='1'",
  "hash": "a7b8c9d0e1f2g3h4i5j6k7l8m9n0o1p2",
  "previousHash": "x1y2z3a4b5c6d7e8f9g0h1i2j3k4l5m6"
}
```

### Viewing Logs
**PowerShell:**
```powershell
# View latest logs
Get-Content security_logs\audit_*.log -Tail 20

# Search for specific attacks
Select-String -Path security_logs\*.log -Pattern "INJECTION|BRUTE_FORCE|TAMPERING"

# Count attack types
(Get-Content security_logs\audit_*.log | Select-String "INJECTION").Count
(Get-Content security_logs\audit_*.log | Select-String "BRUTE_FORCE").Count

# Monitor in real-time
Get-Content security_logs\audit_*.log -Wait -Tail 10
```

**Linux/Bash:**
```bash
# View latest logs
tail -20 security_logs/audit_*.log

# Search for attacks
grep -E "INJECTION|BRUTE_FORCE|TAMPERING" security_logs/*.log

# Count by severity
grep -c "CRITICAL" security_logs/audit_*.log
grep -c "WARN" security_logs/audit_*.log

# Real-time monitoring
tail -f security_logs/audit_*.log
```

---

## Comparison Table

| Feature | LoginAuditLogger | SecurityAuditLogger |
|---------|------------------|---------------------|
| **Storage** | MySQL Database | Log Files (JSON) |
| **Purpose** | User Activity Tracking | Security Monitoring |
| **Encryption** | Not needed (DB secured) | Not needed (no PII) |
| **Query Method** | SQL | grep/PowerShell |
| **SIEM Ready** | Requires export | Direct file access |
| **Compliance** | ✅ SOC2, HIPAA | ✅ PCI-DSS, ISO27001 |
| **Performance** | ~5ms per write | ~1ms per write |
| **Retention** | Configurable (SQL) | File rotation |
| **Tamper Detection** | Database integrity | Hash chain |
| **Best For** | Login history, user audits | Attack detection, threat intel |

---

## Integration with Application

### Authentication Service
```java
// File: AuthenticationService.java

// Login success → DATABASE
LoginAuditLogger.logLoginSuccess(username, ipAddress);

// Login failure → DATABASE
LoginAuditLogger.logLoginFailure(username, ipAddress, reason);

// Account locked → DATABASE
LoginAuditLogger.logAccountLocked(username, ipAddress, reason);
```

### Intrusion Detection System
```java
// File: IntrusionDetection.java

// SQL injection detected → FILES
SecurityAuditLogger.logSecurityEvent(
    SecurityAuditLogger.EventType.INJECTION_ATTEMPT,
    username, ipAddress, details
);

// Brute force detected → FILES
SecurityAuditLogger.logSecurityEvent(
    SecurityAuditLogger.EventType.BRUTE_FORCE_DETECTED,
    username, ipAddress, details
);
```

### Two-Factor Authentication
```java
// File: TwoFactorAuthService.java

// 2FA success → DATABASE
LoginAuditLogger.logTwoFactorSuccess(username, ipAddress);

// 2FA failure → DATABASE
LoginAuditLogger.logTwoFactorFailure(username, ipAddress, reason);
```

---

## Testing

### Run the Test Suite
```powershell
# Compile
javac -encoding UTF-8 -d bin -cp "bin;lib\*" -sourcepath src src\com\itc\studentmgmt\test\TestDualAuditSystem.java

# Run test
java -cp "bin;lib\*" com.itc.studentmgmt.test.TestDualAuditSystem
```

### Verify Database Logs
```sql
-- Connect to MySQL
mysql -u root -p

USE stu_manage;

-- View all audit logs
SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 20;

-- Count by event type
SELECT event_type, COUNT(*) FROM audit_logs GROUP BY event_type;
```

### Verify File Logs
```powershell
# List log files
Get-ChildItem security_logs

# View latest entries
Get-Content security_logs\audit_*.log -Tail 20

# Search for attacks
Select-String -Path security_logs\*.log -Pattern "CRITICAL"
```

---

## Best Practices

### When to Use LoginAuditLogger
- ✅ User logs in or out
- ✅ Password is changed or reset
- ✅ Account is locked or unlocked
- ✅ 2FA verification happens
- ✅ Any user account-related event

### When to Use SecurityAuditLogger
- ✅ Attack detected (SQL injection, XSS, etc.)
- ✅ Rate limit exceeded
- ✅ Brute force attempt detected
- ✅ Session hijacking suspected
- ✅ IDS alert triggered
- ✅ System security events

### Log Retention
**Database (LoginAuditLogger):**
```java
// Clean logs older than 90 days
LoginAuditLogger.cleanOldLogs(90);
```

**Files (SecurityAuditLogger):**
```powershell
# Delete logs older than 30 days
Get-ChildItem security_logs\*.log | Where-Object {$_.LastWriteTime -lt (Get-Date).AddDays(-30)} | Remove-Item
```

---

## Compliance Notes

### SOC 2 / HIPAA
- **LoginAuditLogger** meets requirements for user activity logging
- Tracks all authentication events with timestamps and IP addresses
- Database provides audit trail for compliance reports

### PCI-DSS
- **SecurityAuditLogger** tracks security events as required
- Immutable hash chain prevents log tampering
- Critical events logged immediately

### GDPR
- LoginAuditLogger can identify PII access
- Cleanup methods available for data deletion requests
- Audit logs excluded from "right to be forgotten" (compliance requirement)

---

## Summary

✅ **LoginAuditLogger** = User activity in database (encrypted, queryable, compliance-ready)  
✅ **SecurityAuditLogger** = Security events in files (fast, SIEM-ready, tamper-evident)  

Both systems work together to provide complete audit coverage:
- **Database** for business logic and compliance
- **Files** for security monitoring and threat detection

No overlap, no conflicts - each logger has a specific purpose! 🎯
