@echo off
rem Sentinel dashboard (Vue + Vite) on http://localhost:5173
cd /d "%~dp0frontend"

where npm >nul 2>nul
if errorlevel 1 (
    echo [ERROR] npm not found. Install Node.js 18 or newer from https://nodejs.org
    pause
    exit /b 1
)

if not exist "node_modules" (
    echo Installing frontend dependencies ^(first run only^)...
    call npm install
    if errorlevel 1 (
        echo [ERROR] npm install failed.
        pause
        exit /b 1
    )
)

echo Starting dashboard on http://localhost:5173  ^(Ctrl+C to stop^)
echo Make sure run_backend.bat is running in another window.
call npm run dev
pause
