@echo off
TITLE ARS SYSTEM LAUNCHER
CLS

ECHO ==================================================
ECHO    AUTOMATED RESPONSE SYSTEM (ARS) - LAUNCHING
ECHO ==================================================
ECHO.
ECHO  [1] Starting Scheduler Service (Compliance/Reporting)...
start "ARS SCHEDULER" cmd /k "python src\core\scheduler.py"

ECHO.
ECHO  [2] Starting Defense Core (AI Detection/Response)...
start "ARS DEFENSE CORE" cmd /k "python src\core\main.py"

ECHO.
ECHO ==================================================
ECHO    SYSTEM ONLINE. MONITORING ACTIVE.
ECHO ==================================================
ECHO.
ECHO  Please keep the popped-up windows open.
ECHO.
PAUSE
