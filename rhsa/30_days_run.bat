@echo off
REM quick_run_30days.bat
REM Quick run for last 30 days

echo ========================================
echo   RHSA Quick Run - Last 30 Days
echo ========================================
echo.

powershell -ExecutionPolicy Bypass -File "%~dp0rhsa_collector.ps1" -Days 30 -Format both

echo.
echo Process complete! Check the 'reports' folder for output files.
pause