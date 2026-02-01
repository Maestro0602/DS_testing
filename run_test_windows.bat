@echo off
REM ============================================================================
REM Windows Batch Script for Security Testing
REM ============================================================================

echo.
echo ╔═══════════════════════════════════════════════════════════════════╗
echo ║         SECURITY SYSTEM - WINDOWS QUICK TEST                      ║
echo ╚═══════════════════════════════════════════════════════════════════╝
echo.

REM Check if Java is installed
java -version >nul 2>&1
if errorlevel 1 (
    echo ❌ ERROR: Java is not installed or not in PATH
    echo.
    echo Please install Java JDK 11+ from:
    echo https://adoptium.net/
    pause
    exit /b 1
)

echo ✓ Java detected
echo.

REM Create bin directory
if not exist "bin" (
    echo Creating bin directory...
    mkdir bin
)

REM Compile Java files
echo.
echo [1/3] Compiling Java files...
echo ─────────────────────────────────────────────────────────────────── 

powershell -Command "Get-ChildItem -Path src -Recurse -Filter '*.java' | Select-Object -ExpandProperty FullName | ForEach-Object { javac -encoding UTF-8 -d bin -sourcepath src $_ }"

if errorlevel 1 (
    echo.
    echo ❌ Compilation failed! Check error messages above.
    pause
    exit /b 1
)

echo ✓ Compilation successful
echo.

REM Count compiled classes
echo Checking compiled classes...
powershell -Command "(Get-ChildItem -Path bin -Recurse -Filter '*.class' | Measure-Object).Count" > temp_count.txt
set /p CLASS_COUNT=<temp_count.txt
del temp_count.txt
echo ✓ %CLASS_COUNT% class files compiled
echo.

REM Ask user which test to run
echo.
echo Select test to run:
echo ═══════════════════════════════════════════════════════════════════
echo.
echo   1 - Run FULL Security Simulation (All 5 phases)
echo   2 - Run Phase 1 only (Reconnaissance)
echo   3 - Run Phase 2 only (Credential Stuffing)
echo   4 - Run Phase 3 only (Injection Attempts)
echo   5 - Run Phase 4 only (Session Token Abuse)
echo   6 - Run Phase 5 only (Ransomware-Like Behavior)
echo   0 - Exit
echo.
set /p CHOICE="Enter your choice (0-6): "

if "%CHOICE%"=="0" goto :end
if "%CHOICE%"=="1" set TEST_ARG=full
if "%CHOICE%"=="2" set TEST_ARG=1
if "%CHOICE%"=="3" set TEST_ARG=2
if "%CHOICE%"=="4" set TEST_ARG=3
if "%CHOICE%"=="5" set TEST_ARG=4
if "%CHOICE%"=="6" set TEST_ARG=5

if not defined TEST_ARG (
    echo Invalid choice!
    pause
    exit /b 1
)

REM Run the security simulation
echo.
echo [2/3] Running security simulation...
echo ───────────────────────────────────────────────────────────────────
echo.

java -cp bin com.itc.studentmgmt.security.SecuritySimulationRunner %TEST_ARG%

echo.
echo.
echo [3/3] Checking results...
echo ───────────────────────────────────────────────────────────────────
echo.

REM Check if logs were created
if exist "security_logs\audit_*.json" (
    echo ✓ Security logs generated successfully!
    echo.
    echo Log files:
    dir /b security_logs\audit_*.json
    echo.
    echo ✓ View logs in: security_logs folder
) else (
    echo ⚠ No security logs found
)

echo.
echo ═══════════════════════════════════════════════════════════════════
echo               TEST COMPLETED SUCCESSFULLY!
echo ═══════════════════════════════════════════════════════════════════
echo.

:end
pause
