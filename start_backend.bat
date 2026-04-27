@echo off
echo Stopping any process on port 9100...
for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":9100 "') do (
    taskkill /PID %%a /F >nul 2>&1
)
echo Starting SBOM backend on port 9100...
cd /d "%~dp0backend"
REM --no-proxy-headers: SEC-003 — don't trust client-supplied X-Forwarded-For.
REM Read X-Real-IP from headers in code (set by nginx from $remote_addr in prod).
python -m uvicorn app.main:app --port 9100 --reload --no-proxy-headers
