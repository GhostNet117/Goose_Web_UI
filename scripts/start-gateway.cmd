@echo off
rem Runs the goose-web gateway in the foreground as the current (non-elevated) user.
rem Optional: set GOOSE_WEB_CONFIG, or pass --config <file>; default is C:\Goose_Web_Profiles\_system\config.yaml.
setlocal
set "ROOT=%~dp0.."
if not exist "%ROOT%\.venv\Scripts\python.exe" (
  echo .venv not found - run scripts\install.ps1 first.
  exit /b 1
)
cd /d "%ROOT%"
"%ROOT%\.venv\Scripts\python.exe" -m goose_web %* serve
