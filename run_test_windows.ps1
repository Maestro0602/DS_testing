# ============================================================================
# Windows PowerShell Script for Security Testing
# ============================================================================

Write-Host ""
Write-Host "╔═══════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║         SECURITY SYSTEM - WINDOWS QUICK TEST                      ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Check if Java is installed
try {
    $javaVersion = java -version 2>&1 | Select-Object -First 1
    Write-Host "✓ Java detected: $javaVersion" -ForegroundColor Green
} catch {
    Write-Host "❌ ERROR: Java is not installed or not in PATH" -ForegroundColor Red
    Write-Host ""
    Write-Host "Please install Java JDK 11+ from:" -ForegroundColor Yellow
    Write-Host "https://adoptium.net/" -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host ""

# Create bin directory
if (!(Test-Path "bin")) {
    Write-Host "Creating bin directory..." -ForegroundColor Yellow
    New-Item -ItemType Directory -Path bin | Out-Null
}

# Compile Java files
Write-Host ""
Write-Host "[1/3] Compiling Java files..." -ForegroundColor Cyan
Write-Host "───────────────────────────────────────────────────────────────────"

try {
    Get-ChildItem -Path src -Recurse -Filter "*.java" | Select-Object -ExpandProperty FullName | ForEach-Object {
        javac -encoding UTF-8 -d bin -sourcepath src $_
        if ($LASTEXITCODE -ne 0) {
            throw "Compilation failed for $_"
        }
    }
    Write-Host "✓ Compilation successful" -ForegroundColor Green
} catch {
    Write-Host ""
    Write-Host "❌ Compilation failed! Check error messages above." -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host ""

# Count compiled classes
Write-Host "Checking compiled classes..."
$classCount = (Get-ChildItem -Path bin -Recurse -Filter "*.class" | Measure-Object).Count
Write-Host "✓ $classCount class files compiled" -ForegroundColor Green
Write-Host ""

# Ask user which test to run
Write-Host ""
Write-Host "Select test to run:" -ForegroundColor Yellow
Write-Host "═══════════════════════════════════════════════════════════════════"
Write-Host ""
Write-Host "  1 - Run FULL Security Simulation (All 5 phases)" -ForegroundColor White
Write-Host "  2 - Run Phase 1 only (Reconnaissance)" -ForegroundColor White
Write-Host "  3 - Run Phase 2 only (Credential Stuffing)" -ForegroundColor White
Write-Host "  4 - Run Phase 3 only (Injection Attempts)" -ForegroundColor White
Write-Host "  5 - Run Phase 4 only (Session Token Abuse)" -ForegroundColor White
Write-Host "  6 - Run Phase 5 only (Ransomware-Like Behavior)" -ForegroundColor White
Write-Host "  0 - Exit" -ForegroundColor Gray
Write-Host ""

$choice = Read-Host "Enter your choice (0-6)"

switch ($choice) {
    "0" { exit 0 }
    "1" { $testArg = "full" }
    "2" { $testArg = "1" }
    "3" { $testArg = "2" }
    "4" { $testArg = "3" }
    "5" { $testArg = "4" }
    "6" { $testArg = "5" }
    default {
        Write-Host "Invalid choice!" -ForegroundColor Red
        Read-Host "Press Enter to exit"
        exit 1
    }
}

# Run the security simulation
Write-Host ""
Write-Host "[2/3] Running security simulation..." -ForegroundColor Cyan
Write-Host "───────────────────────────────────────────────────────────────────"
Write-Host ""

java -cp bin com.itc.studentmgmt.security.SecuritySimulationRunner $testArg

Write-Host ""
Write-Host ""
Write-Host "[3/3] Checking results..." -ForegroundColor Cyan
Write-Host "───────────────────────────────────────────────────────────────────"
Write-Host ""

# Check if logs were created
if (Test-Path "security_logs\audit_*.json") {
    Write-Host "✓ Security logs generated successfully!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Log files:" -ForegroundColor Yellow
    Get-ChildItem security_logs\audit_*.json | Select-Object Name
    Write-Host ""
    Write-Host "✓ View logs in: security_logs folder" -ForegroundColor Green
} else {
    Write-Host "⚠ No security logs found" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "              TEST COMPLETED SUCCESSFULLY!" -ForegroundColor Green
Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

Read-Host "Press Enter to exit"
