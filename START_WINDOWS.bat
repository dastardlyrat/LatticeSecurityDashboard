@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>&1
if not errorlevel 1 (
  py -3 launch.py
) else (
  where python >nul 2>&1
  if not errorlevel 1 (python launch.py) else (echo Python 3.10 or newer is required. & pause & exit /b 1)
)
if errorlevel 1 pause
