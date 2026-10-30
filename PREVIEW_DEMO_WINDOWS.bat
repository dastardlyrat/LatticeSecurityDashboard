@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>&1
if not errorlevel 1 (py -3 launch.py --demo) else (python launch.py --demo)
pause
