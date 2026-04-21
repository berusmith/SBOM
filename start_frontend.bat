@echo off
echo Starting SBOM frontend on port 3000...
cd /d "%~dp0frontend"
npm run dev
