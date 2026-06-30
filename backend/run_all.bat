@echo off
setlocal

rem Launch the backend stack from the repository root.
set "ROOT=%~dp0"

echo Starting Redis via Docker Compose...
docker-compose up -d redis

if not exist "%ROOT%app\main.py" (
    echo Could not find backend entrypoint: %ROOT%app\main.py
    exit /b 1
)

if not exist "%ROOT%api_gateway\scripts\main.py" (
    echo Could not find gateway entrypoint: %ROOT%api_gateway\scripts\main.py
    exit /b 1
)

if not exist "%ROOT%api_gateway\scripts\brain_worker.py" (
    echo Could not find brain worker entrypoint: %ROOT%api_gateway\scripts\brain_worker.py
    exit /b 1
)

if not exist "%ROOT%traffic_sim.py" (
    echo Could not find traffic simulator: %ROOT%traffic_sim.py
    exit /b 1
)

echo Starting backend API...
start "Backend API" cmd /k python "%ROOT%app\main.py"

echo Starting gateway...
start "Gateway" cmd /k python "%ROOT%api_gateway\scripts\main.py"

echo Starting brain worker...
start "Brain Worker" cmd /k python "%ROOT%api_gateway\scripts\brain_worker.py"

echo Starting traffic simulator...
start "Traffic Simulator" cmd /k python "%ROOT%traffic_sim.py"

echo Starting frontend...
if exist "%ROOT%backend_alie-feature-alie-frontend" (
    start "ALIE Frontend" cmd /k "cd "%ROOT%backend_alie-feature-alie-frontend" && if not exist node_modules (npm install) && npm run dev"
) else (
    echo Could not find frontend directory: %ROOT%backend_alie-feature-alie-frontend
)

echo.
echo Started all scripts in separate windows.
echo Redis is running via Docker.
endlocal