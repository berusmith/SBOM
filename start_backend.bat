@echo off
echo Stopping any process on port 9100...
for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":9100 "') do (
    taskkill /PID %%a /F >nul 2>&1
)
echo Starting SBOM backend on port 9100...
cd /d "%~dp0backend"
python -m uvicorn app.main:app --port 9100 --reload
