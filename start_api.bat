@echo off
echo ============================================================
echo   Starting DeepShield API
echo ============================================================
echo.

REM Activate virtual environment
call venv\Scripts\activate

REM Start the API server
python src/api_new.py

pause
