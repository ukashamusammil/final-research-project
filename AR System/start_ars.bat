@echo off
echo ===================================================
echo       ARS COMMAND CENTER - REAL AI CORE MODE
echo ===================================================

echo 1. Starting Backend Server...
start "ARS Backend API" cmd /k "python scripts/dashboard_server.py"

echo 2. Starting REAL AI ENGINE (Mode 3: Training Data Replay)...
echo    (Look for the "ARS AI Brain" window and follow prompts if needed)
REM We use a temporary script to auto-select Mode 3 for the user
echo 3 | python src/core/main.py > logs/ars_audit.log 2>&1
start "ARS AI BRAIN" cmd /k "python src/core/main.py"

echo 3. Starting Frontend Interface...
cd frontend
start "ARS Web Dashboard" cmd /k "npm run dev"

echo ===================================================
echo    SYSTEM LINKED! 🧠 -> 🖥️
echo    Real AI decisions are now flowing to the dashboard.
echo    Open browser: http://localhost:5173
echo ===================================================
pause
