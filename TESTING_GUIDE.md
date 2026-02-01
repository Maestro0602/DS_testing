# 🧪 Security System Testing Guide

## Complete Testing Instructions for Windows, Linux, and Cross-Platform Scenarios

This guide provides comprehensive instructions for testing the Student Management System's security features on Windows, Linux, and in combined cross-platform scenarios.

---

## � Quick Start (Windows Users)

If you just want to test the security simulation right away:

```powershell
# 1. Navigate to project directory
cd D:\DataSecurity

# 2. Create bin directory
New-Item -ItemType Directory -Force -Path bin

# 3. Compile all Java files (with UTF-8 encoding)
Get-ChildItem -Path src -Recurse -Filter "*.java" | Select-Object -ExpandProperty FullName | ForEach-Object { javac -encoding UTF-8 -d bin -sourcepath src $_ }

# 4. Run the full security simulation
java -cp bin com.itc.studentmgmt.security.SecuritySimulationRunner full

# 5. View the results
Get-ChildItem security_logs
Get-Content security_logs\audit_*.json -Tail 20
```

**That's it!** The simulation will run all 5 attack phases and generate security logs.

---

## �📋 Table of Contents

1. [Prerequisites](#prerequisites)
2. [Project Structure](#project-structure)
3. [Windows Testing](#windows-testing)
4. [Linux Testing](#linux-testing)
5. [Cross-Platform Testing](#cross-platform-testing)
6. [User-Server Interaction Testing](#user-server-interaction-testing)
7. [Verifying Security Features](#verifying-security-features)
8. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Required Software

#### For Windows:
- **Java JDK 11+** - Download from [Oracle](https://www.oracle.com/java/technologies/downloads/) or [OpenJDK](https://adoptium.net/)
- **Git for Windows** - Download from [git-scm.com](https://git-scm.com/)
- **SQLite** or your preferred database
- **Text Editor/IDE** - VS Code, IntelliJ IDEA, or Eclipse

#### For Linux:
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install openjdk-11-jdk git sqlite3 -y

# Fedora/RHEL
sudo dnf install java-11-openjdk-devel git sqlite -y

# Arch Linux
sudo pacman -S jdk-openjdk git sqlite
```

### Verify Installations

**Windows (PowerShell):**
```powershell
java -version
javac -version
git --version
```

**Linux (Terminal):**
```bash
java -version
javac -version
git --version
```

---

## Project Structure

```
DataSecurity/
├── src/
│   └── com/itc/studentmgmt/
│       ├── dao/
│       ├── database/
│       ├── model/
│       ├── security/
│       │   ├── MaxSecurityAttackSimulation.java
│       │   ├── SecuritySimulationRunner.java
│       │   ├── IntrusionDetection.java
│       │   ├── SecureSessionManager.java
│       │   ├── SecurityAuditLogger.java
│       │   └── (other security classes)
│       ├── service/
│       └── ui/
├── bin/          # Compiled classes
├── lib/          # External libraries
└── security_logs/ # Generated audit logs
```

---

## Windows Testing

### 1. Setup on Windows

#### Step 1: Clone/Navigate to Project
```powershell
# If not already in project directory
cd D:\DataSecurity
```

#### Step 2: Compile the Project
```powershell
# Create bin directory if it doesn't exist
New-Item -ItemType Directory -Force -Path bin

# Compile all Java files (using UTF-8 encoding to handle special characters)
Get-ChildItem -Path src -Recurse -Filter "*.java" | Select-Object -ExpandProperty FullName | ForEach-Object { javac -encoding UTF-8 -d bin -sourcepath src $_ }

# Verify compilation
Get-ChildItem -Path bin -Recurse -Filter *.class | Measure-Object
```

**Expected Output:** Multiple `.class` files compiled successfully

#### Step 3: Run Security Simulation

**Option A: Run Full Simulation**
```powershell
# Run from project root
java -cp bin com.itc.studentmgmt.security.SecuritySimulationRunner full
```

**Option B: Run Individual Phases**
```powershell
# Phase 1: Reconnaissance
java -cp bin com.itc.studentmgmt.security.SecuritySimulationRunner 1

# Phase 2: Credential Stuffing
java -cp bin com.itc.studentmgmt.security.SecuritySimulationRunner 2

# Phase 3: Injection Attempts
java -cp bin com.itc.studentmgmt.security.SecuritySimulationRunner 3

# Phase 4: Session Token Abuse
java -cp bin com.itc.studentmgmt.security.SecuritySimulationRunner 4

# Phase 5: Ransomware-Like Behavior (SAFE)
java -cp bin com.itc.studentmgmt.security.SecuritySimulationRunner 5
```

**Option C: Run Direct Simulation**
```powershell
java -cp bin com.itc.studentmgmt.security.MaxSecurityAttackSimulation
```

#### Step 4: Verify Security Logs
```powershell
# Check if logs were created
Get-ChildItem security_logs -Filter "audit_*.json"

# View latest log (last 50 lines)
Get-Content security_logs/audit_*.json -Tail 50

# Count total log entries
(Get-Content security_logs/audit_*.json | Measure-Object -Line).Lines
```

---

## Linux Testing

### 1. Setup on Linux

#### Step 1: Navigate to Project
```bash
cd ~/DataSecurity  # or your project path
```

#### Step 2: Compile the Project
```bash
# Create bin directory
mkdir -p bin

# Compile all Java files
find src -name "*.java" -print | xargs javac -d bin -sourcepath src

# Alternative: Compile specific packages
javac -d bin -sourcepath src $(find src -name "*.java")

# Verify compilation
find bin -name "*.class" | wc -l
```

**Expected Output:** Number of compiled `.class` files

#### Step 3: Run Security Simulation

**Option A: Run Full Simulation**
```bash
java -cp bin com.itc.studentmgmt.security.SecuritySimulationRunner full
```

**Option B: Run Individual Phases**
```bash
# Phase 1: Reconnaissance
java -cp bin com.itc.studentmgmt.security.SecuritySimulationRunner recon

# Phase 2: Credential Stuffing
java -cp bin com.itc.studentmgmt.security.SecuritySimulationRunner cred

# Phase 3: Injection Attempts
java -cp bin com.itc.studentmgmt.security.SecuritySimulationRunner inject

# Phase 4: Session Token Abuse
java -cp bin com.itc.studentmgmt.security.SecuritySimulationRunner session

# Phase 5: Ransomware-Like Behavior
java -cp bin com.itc.studentmgmt.security.SecuritySimulationRunner ransom
```

**Option C: Run with Different Options**
```bash
# Run with verbose output
java -cp bin com.itc.studentmgmt.security.SecuritySimulationRunner full 2>&1 | tee simulation_output.log

# Run in background and capture output
nohup java -cp bin com.itc.studentmgmt.security.SecuritySimulationRunner full > simulation.log 2>&1 &

# Monitor running process
tail -f simulation.log
```

#### Step 4: Verify Security Logs
```bash
# Check logs directory
ls -lah security_logs/

# View latest audit log
tail -n 50 security_logs/audit_*.json

# Pretty print JSON logs (if jq is installed)
sudo apt install jq -y  # Ubuntu/Debian
cat security_logs/audit_*.json | jq '.'

# Search for specific events
grep "INJECTION_ATTEMPT" security_logs/audit_*.json

# Count specific alert types
grep -c "CRITICAL" security_logs/audit_*.json
```

---

## Cross-Platform Testing

### Scenario 1: Server on Linux, Client Simulation on Windows

#### On Linux (Server):
```bash
# Step 1: Compile and prepare server
cd ~/DataSecurity
mkdir -p bin
javac -d bin -sourcepath src $(find src -name "*.java")

# Step 2: Get server IP address
ip addr show | grep "inet " | grep -v "127.0.0.1"
# Note the IP address (e.g., 192.168.1.100)

# Step 3: Start the application (if you have a main server class)
java -cp bin com.itc.studentmgmt.Main &

# Step 4: Monitor logs in real-time
tail -f security_logs/audit_*.json
```

#### On Windows (Client):
```powershell
# Step 1: Navigate to project
cd D:\DataSecurity

# Step 2: Compile if needed
Get-ChildItem -Path src -Recurse -Filter "*.java" | Select-Object -ExpandProperty FullName | ForEach-Object { javac -encoding UTF-8 -d bin -sourcepath src $_ }

# Step 3: Run attack simulation targeting Linux server
# (If the simulation supports remote IP configuration)
java -cp bin com.itc.studentmgmt.security.SecuritySimulationRunner full

# Step 4: Check local results
Get-Content security_logs/audit_*.json -Tail 30
```

### Scenario 2: Server on Windows, Client Simulation on Linux

#### On Windows (Server):
```powershell
# Step 1: Get Windows IP
ipconfig | Select-String "IPv4"
# Note the IP address (e.g., 192.168.1.150)

# Step 2: Compile and run
Get-ChildItem -Path src -Recurse -Filter "*.java" | Select-Object -ExpandProperty FullName | ForEach-Object { javac -encoding UTF-8 -d bin -sourcepath src $_ }
java -cp bin com.itc.studentmgmt.Main

# Step 3: Monitor logs
Get-Content security_logs/audit_*.json -Wait -Tail 20
```

#### On Linux (Client):
```bash
# Run simulation
java -cp bin com.itc.studentmgmt.security.SecuritySimulationRunner full

# Monitor results
watch -n 2 'tail -n 10 security_logs/audit_*.json'
```

### Scenario 3: Simultaneous Multi-Platform Attack Simulation

#### Terminal 1 (Linux):
```bash
# Start Phase 1 and 2
java -cp bin com.itc.studentmgmt.security.SecuritySimulationRunner 1
sleep 5
java -cp bin com.itc.studentmgmt.security.SecuritySimulationRunner 2
```

#### Terminal 2 (Windows):
```powershell
# Start Phase 3 and 4 simultaneously
Start-Job { java -cp bin com.itc.studentmgmt.security.SecuritySimulationRunner 3 }
Start-Sleep -Seconds 2
Start-Job { java -cp bin com.itc.studentmgmt.security.SecuritySimulationRunner 4 }

# Check running jobs
Get-Job
```

#### Terminal 3 (Monitor - Any OS):
```bash
# Real-time monitoring
watch -n 1 'cat security_logs/audit_*.json | tail -n 15'
```

---

## User-Server Interaction Testing

### Scenario 1: Testing Login with GUI

#### Step 1: Start the Main Application
**Windows:**
```powershell
java -cp bin com.itc.studentmgmt.ui.LoginFrame
```

**Linux:**
```bash
java -cp bin com.itc.studentmgmt.ui.LoginFrame
```

#### Step 2: Test Normal Login
1. Enter valid credentials:
   - Username: `admin`
   - Password: `admin123`
2. Click "Login"
3. Observe: ✅ Successful login

#### Step 3: Test Failed Login (Trigger Rate Limiting)
1. Enter invalid credentials 6 times rapidly:
   - Username: `admin`
   - Password: `wrong1`, `wrong2`, `wrong3`, etc.
2. Observe: 🚫 Account locked after 5 attempts

#### Step 4: Check Security Logs
```bash
# View failed login attempts
grep "LOGIN_FAILURE" security_logs/audit_*.json

# Check if IP was blocked
grep "IP_BLOCKED" security_logs/audit_*.json
```

### Scenario 2: Testing with Command-Line Authentication

#### Create Test Script (test_auth.sh - Linux)
```bash
#!/bin/bash
echo "Testing Authentication Service..."

# Compile if needed
javac -d bin -sourcepath src $(find src -name "*.java")

# Test 1: Valid login
echo "Test 1: Valid Login"
java -cp bin com.itc.studentmgmt.service.AuthenticationService "admin" "admin123"

# Test 2: Invalid login (5 times)
echo "Test 2: Triggering Rate Limit"
for i in {1..6}; do
    echo "Attempt $i"
    java -cp bin com.itc.studentmgmt.service.AuthenticationService "admin" "wrong$i"
    sleep 1
done

# Test 3: Check if blocked
echo "Test 3: Verify Block"
java -cp bin com.itc.studentmgmt.service.AuthenticationService "admin" "admin123"

echo "Check security_logs/audit_*.json for details"
```

Make executable and run:
```bash
chmod +x test_auth.sh
./test_auth.sh
```

#### Create Test Script (test_auth.ps1 - Windows)
```powershell
Write-Host "Testing Authentication Service..."

# Test 1: Valid login
Write-Host "Test 1: Valid Login"
java -cp bin com.itc.studentmgmt.service.AuthenticationService "admin" "admin123"

# Test 2: Invalid login (6 times)
Write-Host "Test 2: Triggering Rate Limit"
1..6 | ForEach-Object {
    Write-Host "Attempt $_"
    java -cp bin com.itc.studentmgmt.service.AuthenticationService "admin" "wrong$_"
    Start-Sleep -Seconds 1
}

# Test 3: Check if blocked
Write-Host "Test 3: Verify Block"
java -cp bin com.itc.studentmgmt.service.AuthenticationService "admin" "admin123"

Write-Host "Check security_logs for details"
```

Run:
```powershell
.\test_auth.ps1
```

### Scenario 3: Multi-User Concurrent Testing

#### Script: concurrent_test.sh (Linux)
```bash
#!/bin/bash

echo "Starting concurrent user simulations..."

# Simulate 5 different users attacking simultaneously
for user in user1 user2 user3 user4 user5; do
    (
        for i in {1..10}; do
            echo "[$user] Attempt $i"
            java -cp bin com.itc.studentmgmt.service.AuthenticationService "$user" "password$i"
            sleep 0.5
        done
    ) &
done

# Wait for all background jobs
wait

echo "Concurrent testing complete. Check logs:"
grep -c "LOGIN_FAILURE" security_logs/audit_*.json
```

#### Script: concurrent_test.ps1 (Windows)
```powershell
Write-Host "Starting concurrent user simulations..."

# Simulate 5 different users attacking simultaneously
$users = @("user1", "user2", "user3", "user4", "user5")

$jobs = $users | ForEach-Object {
    $user = $_
    Start-Job -ScriptBlock {
        param($u)
        1..10 | ForEach-Object {
            Write-Host "[$u] Attempt $_"
            java -cp bin com.itc.studentmgmt.service.AuthenticationService $u "password$_"
            Start-Sleep -Milliseconds 500
        }
    } -ArgumentList $user
}

# Wait for all jobs
$jobs | Wait-Job | Receive-Job

Write-Host "Concurrent testing complete"
(Get-Content security_logs/audit_*.json | Select-String "LOGIN_FAILURE").Count
```

### Scenario 4: Testing SQL Injection Detection

#### Interactive Test (Both Platforms)
```bash
# Run the simulation with injection phase only
java -cp bin com.itc.studentmgmt.security.SecuritySimulationRunner inject

# Check results
grep "INJECTION_ATTEMPT" security_logs/audit_*.json | wc -l
```

#### Manual SQL Injection Test
Create a simple test program to try manual injections:

**TestInjection.java:**
```java
package com.itc.studentmgmt.test;

import com.itc.studentmgmt.security.IntrusionDetection;

public class TestInjection {
    public static void main(String[] args) {
        String[] testInputs = {
            "admin",
            "admin' OR '1'='1",
            "'; DROP TABLE users;--",
            "normal_username",
            "<script>alert('xss')</script>"
        };
        
        for (String input : testInputs) {
            boolean isSqli = IntrusionDetection.detectSqlInjection(input);
            boolean isXss = IntrusionDetection.detectXss(input);
            
            System.out.printf("Input: %-40s | SQLi: %-5s | XSS: %-5s%n", 
                input, isSqli ? "✓" : "✗", isXss ? "✓" : "✗");
        }
    }
}
```

Compile and run:
```bash
# Linux/Mac
javac -d bin -cp bin -sourcepath src src/com/itc/studentmgmt/test/TestInjection.java
java -cp bin com.itc.studentmgmt.test.TestInjection

# Windows
javac -d bin -cp bin -sourcepath src src\com\itc\studentmgmt\test\TestInjection.java
java -cp bin com.itc.studentmgmt.test.TestInjection
```

---

## Verifying Security Features

### 1. Rate Limiting Verification

**Test Command (Linux):**
```bash
# Generate rapid requests
for i in {1..20}; do
    echo "Request $i"
    java -cp bin com.itc.studentmgmt.security.SecuritySimulationRunner 1
done

# Check how many were blocked
grep "BLOCKED" security_logs/audit_*.json | wc -l
```

**Test Command (Windows):**
```powershell
# Generate rapid requests
1..20 | ForEach-Object {
    Write-Host "Request $_"
    java -cp bin com.itc.studentmgmt.security.SecuritySimulationRunner 1
}

# Check how many were blocked
(Select-String -Path "security_logs\audit_*.json" -Pattern "BLOCKED").Count
```

**Expected Result:** After 10-15 requests, rate limiting should block subsequent attempts.

### 2. Intrusion Detection Verification

```bash
# Run full simulation
java -cp bin com.itc.studentmgmt.security.SecuritySimulationRunner full

# Verify IDS detected threats
grep "threat" security_logs/audit_*.json -i
```

**Expected Result:** Multiple threat detection entries with increasing threat scores.

### 3. Audit Logging Verification

**Check Log Integrity:**
```bash
# Linux
ls -lh security_logs/
cat security_logs/audit_*.json | jq '.hash' | head -n 5

# Windows
Get-ChildItem security_logs
Get-Content security_logs\audit_*.json | Select-String "hash" | Select-Object -First 5
```

**Verify Hash Chain:**
```bash
# Verify that each log entry references the previous hash
cat security_logs/audit_*.json | jq '.previousHash' | head -n 10
```

**Expected Result:** Each entry should have a unique hash and reference the previous entry's hash (blockchain-style).

### 4. Session Management Verification

```bash
# Run session abuse test
java -cp bin com.itc.studentmgmt.security.SecuritySimulationRunner 4

# Check session validations
grep "SESSION" security_logs/audit_*.json
```

**Expected Result:** All fake/invalid session tokens should be rejected.

### 5. Alert Generation Verification

```bash
# Check for CRITICAL alerts
grep "CRITICAL" security_logs/audit_*.json

# Count alerts by severity
echo "CRITICAL:" $(grep -c "CRITICAL" security_logs/audit_*.json)
echo "HIGH:" $(grep -c "HIGH" security_logs/audit_*.json)
echo "WARN:" $(grep -c "WARN" security_logs/audit_*.json)
```

**Expected Result:** Multiple CRITICAL and HIGH severity alerts from injection attempts and brute force detection.

---

## Troubleshooting

### Issue 1: "Class not found" Error

**Symptom:**
```
Error: Could not find or load main class com.itc.studentmgmt.security.SecuritySimulationRunner
```

**Solution:**
```bash
# Verify classpath
# Linux
java -cp bin -verbose com.itc.studentmgmt.security.SecuritySimulationRunner

# Windows
java -cp bin -verbose com.itc.studentmgmt.security.SecuritySimulationRunner

# Recompile with verbose output
javac -verbose -d bin -sourcepath src $(find src -name "*.java")
```

### Issue 2: Permission Denied on Linux

**Symptom:**
```
security_logs: Permission denied
```

**Solution:**
```bash
# Fix permissions
chmod -R 755 .
mkdir -p security_logs
chmod 777 security_logs
```

### Issue 3: Windows Path Issues

**Symptom:**
```
Error: Could not find or load main class
```

**Solution:**
```powershell
# Use semicolon separator on Windows
java -cp "bin;lib/*" com.itc.studentmgmt.security.SecuritySimulationRunner

# Check Java classpath separator
java -XshowSettings:properties -version 2>&1 | Select-String "path.separator"
```

### Issue 4: No Logs Generated

**Symptom:**
No files in `security_logs/` directory

**Solution:**
```bash
# Check if logs are being created in current directory
ls -la | grep audit

# Manually create logs directory
mkdir -p security_logs

# Run with explicit working directory
cd /path/to/DataSecurity
java -cp bin com.itc.studentmgmt.security.SecuritySimulationRunner full
```

### Issue 5: Out of Memory Error

**Symptom:**
```
java.lang.OutOfMemoryError: Java heap space
```

**Solution:**
```bash
# Increase heap size
java -Xmx1024m -cp bin com.itc.studentmgmt.security.SecuritySimulationRunner full

# For very large simulations
java -Xmx2048m -Xms512m -cp bin com.itc.studentmgmt.security.SecuritySimulationRunner full
```

---

## Advanced Testing Scenarios

### Load Testing

**Linux Script (load_test.sh):**
```bash
#!/bin/bash
echo "Starting load test..."
for i in {1..100}; do
    java -cp bin com.itc.studentmgmt.security.SecuritySimulationRunner full &
    if [ $((i % 10)) -eq 0 ]; then
        echo "Started $i simulations"
        sleep 2
    fi
done
wait
echo "Load test complete"
```

**Windows Script (load_test.ps1):**
```powershell
Write-Host "Starting load test..."
1..100 | ForEach-Object {
    Start-Job -ScriptBlock { 
        java -cp bin com.itc.studentmgmt.security.SecuritySimulationRunner full 
    }
    if ($_ % 10 -eq 0) {
        Write-Host "Started $_ simulations"
        Start-Sleep -Seconds 2
    }
}
Get-Job | Wait-Job
Write-Host "Load test complete"
```

### Automated Testing Suite

**Create comprehensive test runner:**

**run_all_tests.sh (Linux):**
```bash
#!/bin/bash
set -e

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║         COMPREHENSIVE SECURITY TESTING SUITE                  ║"
echo "╚═══════════════════════════════════════════════════════════════╝"

# Clean previous logs
rm -rf security_logs/*
mkdir -p security_logs

# Test 1: Compilation
echo "[1/7] Compiling project..."
javac -d bin -sourcepath src $(find src -name "*.java")
echo "✓ Compilation successful"

# Test 2: Phase 1
echo "[2/7] Running Phase 1: Reconnaissance..."
java -cp bin com.itc.studentmgmt.security.SecuritySimulationRunner 1
echo "✓ Phase 1 complete"

# Test 3: Phase 2
echo "[3/7] Running Phase 2: Credential Stuffing..."
java -cp bin com.itc.studentmgmt.security.SecuritySimulationRunner 2
echo "✓ Phase 2 complete"

# Test 4: Phase 3
echo "[4/7] Running Phase 3: Injection Attempts..."
java -cp bin com.itc.studentmgmt.security.SecuritySimulationRunner 3
echo "✓ Phase 3 complete"

# Test 5: Phase 4
echo "[5/7] Running Phase 4: Session Token Abuse..."
java -cp bin com.itc.studentmgmt.security.SecuritySimulationRunner 4
echo "✓ Phase 4 complete"

# Test 6: Phase 5
echo "[6/7] Running Phase 5: Ransomware-Like Behavior..."
java -cp bin com.itc.studentmgmt.security.SecuritySimulationRunner 5
echo "✓ Phase 5 complete"

# Test 7: Verify logs
echo "[7/7] Verifying security logs..."
LOG_COUNT=$(ls security_logs/audit_*.json 2>/dev/null | wc -l)
if [ $LOG_COUNT -gt 0 ]; then
    echo "✓ Security logs generated ($LOG_COUNT files)"
    echo "✓ Total log entries: $(cat security_logs/audit_*.json | wc -l)"
else
    echo "✗ No security logs found!"
    exit 1
fi

echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║              ALL TESTS COMPLETED SUCCESSFULLY                  ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
```

**run_all_tests.ps1 (Windows):**
```powershell
Write-Host "╔═══════════════════════════════════════════════════════════════╗"
Write-Host "║         COMPREHENSIVE SECURITY TESTING SUITE                  ║"
Write-Host "╚═══════════════════════════════════════════════════════════════╝"

# Clean previous logs
if (Test-Path security_logs) {
    Remove-Item security_logs\* -Force
}
New-Item -ItemType Directory -Force -Path security_logs | Out-Null

# Test 1: Compilation
Write-Host "[1/7] Compiling project..."
Get-ChildItem -Path src -Recurse -Filter "*.java" | Select-Object -ExpandProperty FullName | ForEach-Object { javac -encoding UTF-8 -d bin -sourcepath src $_ }
Write-Host "✓ Compilation successful"

# Test 2-6: Run all phases
$phases = @(
    @{Num=1; Name="Reconnaissance"},
    @{Num=2; Name="Credential Stuffing"},
    @{Num=3; Name="Injection Attempts"},
    @{Num=4; Name="Session Token Abuse"},
    @{Num=5; Name="Ransomware-Like Behavior"}
)

$testNum = 2
foreach ($phase in $phases) {
    Write-Host "[$testNum/7] Running Phase $($phase.Num): $($phase.Name)..."
    java -cp bin com.itc.studentmgmt.security.SecuritySimulationRunner $phase.Num
    Write-Host "✓ Phase $($phase.Num) complete"
    $testNum++
}

# Test 7: Verify logs
Write-Host "[7/7] Verifying security logs..."
$logCount = (Get-ChildItem security_logs\audit_*.json -ErrorAction SilentlyContinue).Count
if ($logCount -gt 0) {
    $entryCount = (Get-Content security_logs\audit_*.json | Measure-Object -Line).Lines
    Write-Host "✓ Security logs generated ($logCount files)"
    Write-Host "✓ Total log entries: $entryCount"
} else {
    Write-Host "✗ No security logs found!"
    exit 1
}

Write-Host ""
Write-Host "╔═══════════════════════════════════════════════════════════════╗"
Write-Host "║              ALL TESTS COMPLETED SUCCESSFULLY                  ║"
Write-Host "╚═══════════════════════════════════════════════════════════════╝"
```

Make executable:
```bash
chmod +x run_all_tests.sh
./run_all_tests.sh
```

---

## Summary Checklist

### ✅ Windows Testing
- [ ] Java JDK installed and verified
- [ ] Project compiled successfully
- [ ] All 5 phases run without errors
- [ ] Security logs generated in `security_logs/`
- [ ] Audit logs contain hash chains
- [ ] Alerts generated for critical events

### ✅ Linux Testing
- [ ] Java JDK installed and verified
- [ ] Project compiled successfully
- [ ] All 5 phases run without errors
- [ ] Security logs generated with correct permissions
- [ ] Log files are readable and parseable
- [ ] Alerts generated for critical events

### ✅ Cross-Platform Testing
- [ ] Server runs on one platform, client on another
- [ ] Logs generated on both systems
- [ ] No compatibility issues between platforms
- [ ] Concurrent testing successful

### ✅ User-Server Interaction
- [ ] GUI login tested
- [ ] Rate limiting triggers after 5 failed attempts
- [ ] Account lockout works correctly
- [ ] Concurrent user tests successful
- [ ] Injection detection works in real scenarios

### ✅ Verification
- [ ] Rate limiting verified
- [ ] Intrusion detection verified
- [ ] Audit logging verified
- [ ] Session management verified
- [ ] Alert generation verified

---

## Additional Resources

### Useful Commands Reference

**Monitor logs in real-time (Linux):**
```bash
tail -f security_logs/audit_*.json
watch -n 1 'tail -n 20 security_logs/audit_*.json'
```

**Monitor logs in real-time (Windows):**
```powershell
Get-Content security_logs\audit_*.json -Wait -Tail 20
```

**Search logs (Linux):**
```bash
grep -i "critical\|high" security_logs/audit_*.json
jq 'select(.severity == "CRITICAL")' security_logs/audit_*.json
```

**Search logs (Windows):**
```powershell
Select-String -Path security_logs\audit_*.json -Pattern "CRITICAL|HIGH"
Get-Content security_logs\audit_*.json | ConvertFrom-Json | Where-Object {$_.severity -eq "CRITICAL"}
```

**Generate test report:**
```bash
# Linux
echo "Security Test Report - $(date)" > test_report.txt
echo "========================" >> test_report.txt
echo "Total alerts: $(grep -c "alert" security_logs/audit_*.json)" >> test_report.txt
echo "Critical: $(grep -c "CRITICAL" security_logs/audit_*.json)" >> test_report.txt
echo "High: $(grep -c "HIGH" security_logs/audit_*.json)" >> test_report.txt
cat test_report.txt
```

---

## Contact & Support

For issues or questions about testing:
1. Check the [Troubleshooting](#troubleshooting) section
2. Review security logs for detailed error messages
3. Verify Java version compatibility (JDK 11+)
4. Ensure all dependencies are properly compiled

**Happy Testing! 🧪🔐**
