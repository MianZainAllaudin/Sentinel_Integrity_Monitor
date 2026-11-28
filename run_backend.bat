@echo off
rem Sentinel backend (FastAPI) on http://127.0.0.1:8000
cd /d "%~dp0"

if not exist ".venv\Scripts\activate.bat" (
    echo [ERROR] .venv not found. Create it first:
    echo     py -3.11 -m venv .venv
    echo     .venv\Scripts\activate.bat
    echo     pip install -r requirements.txt
    echo     pip install -e .
    pause
    exit /b 1
)
call ".venv\Scripts\activate.bat"

if not defined SENTINEL_HMAC_KEY (
    echo [ERROR] SENTINEL_HMAC_KEY is not set.
    echo Set it once, then open a NEW window:
    echo     setx SENTINEL_HMAC_KEY "your-base64-key-at-least-16-bytes"
    pause
    exit /b 1
)

if defined SENTINEL_STATE_DIR (
    echo State folder: %SENTINEL_STATE_DIR%
) else (
    echo State folder: default ^(%USERPROFILE%\.sentinel^)
)
echo Starting backend on http://127.0.0.1:8000  ^(Ctrl+C to stop^)
python -m uvicorn sentinel.api.main:app --host 127.0.0.1 --port 8000
pause
