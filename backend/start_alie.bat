@echo off
setlocal

set "ROOT=%~dp0"
set "FRONTEND=%ROOT%..\backend_alie-feature-alie-frontend"

echo ========================================
echo   ALIE - Starting All Services
echo ========================================
echo.

echo [1/6] Starting Redis via Docker...
cd /d "%ROOT%"
docker stop alie-kong-gateway > nul 2>&1
docker start alie-redis-buffer
echo Waiting for Redis to initialize...
timeout /t 3 /nobreak > nul
echo.

echo [2/6] Starting Backend API...
start "ALIE Backend API" cmd /k "color 0A & title ALIE Backend API & cd /d "%ROOT%" & python app\main.py"
echo Waiting for Backend API to initialize...
timeout /t 3 /nobreak > nul
echo.

echo [3/6] Starting Gateway...
start "ALIE Gateway" cmd /k "color 0B & title ALIE Gateway & cd /d "%ROOT%api_gateway" & python scripts\main.py"
echo Waiting for Gateway to bind to port 8000...
timeout /t 4 /nobreak > nul
echo.

echo [4/6] Starting Brain Worker...
start "ALIE Brain Worker" cmd /k "color 0D & title ALIE Brain Worker & cd /d "%ROOT%api_gateway" & python scripts\brain_worker.py"
echo Waiting for Brain Worker to connect...
timeout /t 2 /nobreak > nul
echo.

echo [5/6] Starting Traffic Simulator...
start "ALIE Traffic Simulator" cmd /k "color 0C & title ALIE Traffic Simulator & cd /d "%ROOT%" & python traffic_sim.py"
echo Simulator is running.
timeout /t 2 /nobreak > nul
echo.

echo [*] Opening TrapNet Terminal UI in browser...
if exist "%ROOT%trapnet\terminal.html" (
    start "" "%ROOT%trapnet\terminal.html"
    echo TrapNet terminal opened.
) else (
    echo [WARN] trapnet\terminal.html not found, skipping.
)
echo.

echo [6/6] Starting Frontend...
start "ALIE Frontend" cmd /k "color 09 & title ALIE Frontend & cd /d "%FRONTEND%" & npm run dev"

echo.
echo ========================================
echo   All services launched successfully!
echo   Frontend will be available at: http://localhost:3000
echo ========================================
pause
endlocal