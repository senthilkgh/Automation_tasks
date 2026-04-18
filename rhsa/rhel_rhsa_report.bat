@echo off
REM rhsa_collector.bat
REM Batch file wrapper for RHSA PowerShell script

setlocal enabledelayedexpansion

echo ========================================
echo   RHSA Data Collection Tool
echo   Windows Batch Launcher
echo ========================================
echo.

REM Check if PowerShell is available
powershell -Command "Write-Host 'PowerShell is available'" >nul 2>&1
if errorlevel 1 (
    echo ERROR: PowerShell is not available on this system
    echo Please ensure PowerShell 5.1 or higher is installed
    pause
    exit /b 1
)

REM Get script directory
set "SCRIPT_DIR=%~dp0"
set "PS_SCRIPT=%SCRIPT_DIR%rhsa_collector.ps1"

REM Check if PowerShell script exists
if not exist "%PS_SCRIPT%" (
    echo ERROR: PowerShell script not found: %PS_SCRIPT%
    pause
    exit /b 1
)

REM Display menu
:MENU
cls
echo ========================================
echo   RHSA Data Collection Menu
echo ========================================
echo.
echo 1. Fetch RHSAs from last 7 days
echo 2. Fetch RHSAs from last 30 days
echo 3. Fetch RHSAs from last 90 days
echo 4. Process RHSAs from file (rhsa_list.txt)
echo 5. Enter specific RHSA IDs manually
echo 6. Exit
echo.
set /p choice="Select option (1-6): "

if "%choice%"=="1" goto DAYS7
if "%choice%"=="2" goto DAYS30
if "%choice%"=="3" goto DAYS90
if "%choice%"=="4" goto FROMFILE
if "%choice%"=="5" goto MANUAL
if "%choice%"=="6" goto END

echo Invalid choice. Please try again.
timeout /t 2 >nul
goto MENU

:DAYS7
echo.
echo Fetching RHSAs from last 7 days...
powershell -ExecutionPolicy Bypass -File "%PS_SCRIPT%" -Days 7 -Format both
goto COMPLETE

:DAYS30
echo.
echo Fetching RHSAs from last 30 days...
powershell -ExecutionPolicy Bypass -File "%PS_SCRIPT%" -Days 30 -Format both
goto COMPLETE

:DAYS90
echo.
echo Fetching RHSAs from last 90 days...
powershell -ExecutionPolicy Bypass -File "%PS_SCRIPT%" -Days 90 -Format both
goto COMPLETE

:FROMFILE
echo.
set /p inputfile="Enter path to RHSA list file (default: rhsa_list.txt): "
if "%inputfile%"=="" set "inputfile=rhsa_list.txt"

if not exist "%inputfile%" (
    echo ERROR: File not found: %inputfile%
    pause
    goto MENU
)

echo Processing RHSAs from file: %inputfile%
powershell -ExecutionPolicy Bypass -File "%PS_SCRIPT%" -InputFile "%inputfile%" -Format both
goto COMPLETE

:MANUAL
echo.
echo Enter RHSA IDs separated by commas (e.g., RHSA-2024:0001,RHSA-2024:0002)
set /p rhsaids="RHSA IDs: "

if "%rhsaids%"=="" (
    echo ERROR: No RHSA IDs provided
    pause
    goto MENU
)

echo Processing specified RHSA IDs...
powershell -ExecutionPolicy Bypass -File "%PS_SCRIPT%" -RhsaIds %rhsaids% -Format both
goto COMPLETE

:COMPLETE
echo.
echo ========================================
echo   Process Complete!
echo ========================================
echo.
set /p again="Run again? (Y/N): "
if /i "%again%"=="Y" goto MENU
goto

END

:END
echo.
echo Thank you for using RHSA Data Collection Tool
echo.
pause
exit /b 0