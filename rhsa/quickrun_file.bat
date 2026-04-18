@echo off
REM quick_run_from_file.bat
REM Quick run from rhsa_list.txt

echo ========================================
echo   RHSA Quick Run - From File
echo ========================================
echo.

if not exist "%~dp0rhsa_list.txt" (
    echo ERROR: rhsa_list.txt not found!
    echo Please create rhsa_list.txt with RHSA IDs (one per line)
    pause
    exit /b 1
)

powershell -ExecutionPolicy Bypass -File "%~dp0rhsa_collector.ps1" -InputFile "%~dp0rhsa_list.txt" -Format both

echo.
echo Process complete! Check the 'reports' folder for output files.
pause