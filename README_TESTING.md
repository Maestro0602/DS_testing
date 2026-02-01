# 🔐 Security System Testing - Quick Reference

## ✅ TESTED AND WORKING ON WINDOWS!

### 🚀 Fastest Way to Test (Windows):

**Just double-click one of these files:**
- `run_test_windows.ps1` (PowerShell - Recommended)
- `run_test_windows.bat` (Command Prompt)

That's it! The script will guide you through everything.

---

## 📁 Important Files

| File | Purpose |
|------|---------|
| `run_test_windows.ps1` | **Automated testing script for Windows (PowerShell)** |
| `run_test_windows.bat` | **Automated testing script for Windows (Batch)** |
| `TESTING_GUIDE.md` | **Complete testing guide for Windows, Linux, and cross-platform** |
| `WINDOWS_TEST_SUMMARY.md` | **Summary of Windows testing with working commands** |
| `MaxSecurityAttackSimulation.java` | Main simulation class (5 attack phases) |
| `SecuritySimulationRunner.java` | Test runner with command-line interface |

---

## 🎯 What Gets Tested

### Phase 1: Reconnaissance
- Repeated GET requests to trigger rate limiting
- **Tests**: Rate limiting counters, API request tracking

### Phase 2: Credential Stuffing  
- Login attempts with common passwords
- **Tests**: Brute-force detection, account lockout, IP blocking

### Phase 3: Injection Attempts
- SQL injection, XSS, path traversal payloads
- **Tests**: Pattern detection, IDS alerts, threat scoring

### Phase 4: Session Token Abuse
- Fake, modified, and replayed tokens
- **Tests**: HMAC validation, session integrity, token binding

### Phase 5: Ransomware-Like Behavior (SAFE)
- Rapid mass data access (read-only, no actual encryption)
- **Tests**: Abnormal behavior detection, insider threat detection

---

## 📊 Expected Results

When the simulation runs successfully, you should see:

✅ **98+ rate limits triggered**  
✅ **19+ injection attacks detected**  
✅ **10+ session abuse attempts blocked**  
✅ **3+ IPs blocked**  
✅ **30+ security alerts generated**  
✅ **Security logs created** in `security_logs/` folder

---

## 🆘 Troubleshooting

### "Class not found" error?
**Solution**: Make sure you're in the `D:\DataSecurity` directory
```powershell
cd D:\DataSecurity
```

### Compilation errors?
**Solution**: Use UTF-8 encoding (already included in scripts)
```powershell
javac -encoding UTF-8 ...
```

### No logs generated?
**Solution**: Check if `security_logs` folder exists
```powershell
New-Item -ItemType Directory -Force -Path security_logs
```

---

## 📖 Full Documentation

For detailed instructions, cross-platform testing, and advanced scenarios:
- See **[TESTING_GUIDE.md](TESTING_GUIDE.md)** (comprehensive guide)
- See **[WINDOWS_TEST_SUMMARY.md](WINDOWS_TEST_SUMMARY.md)** (Windows-specific summary)

---

## ⚡ Quick Manual Test (Windows)

If you prefer manual commands:

```powershell
# 1. Compile
New-Item -ItemType Directory -Force -Path bin
Get-ChildItem -Path src -Recurse -Filter "*.java" | Select-Object -ExpandProperty FullName | ForEach-Object { javac -encoding UTF-8 -d bin -sourcepath src $_ }

# 2. Run
java -cp bin com.itc.studentmgmt.security.SecuritySimulationRunner full

# 3. Check logs
Get-Content security_logs\audit_*.json -Tail 20
```

---

## 🎉 System Status: FULLY OPERATIONAL ✅

All security features have been tested and are working correctly:
- ✅ Intrusion Detection System (IDS)
- ✅ Rate Limiting (IP and User-based)
- ✅ Brute Force Protection
- ✅ SQL Injection Detection
- ✅ XSS Detection
- ✅ Session Token Validation
- ✅ Threat Scoring System
- ✅ Security Audit Logging
- ✅ Alert Generation
- ✅ Abnormal Behavior Detection

**Happy Testing! 🔐**
