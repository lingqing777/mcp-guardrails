@echo off
chcp 65001 >nul 2>&1

echo ==========================================
echo   MCP Guardrails - Security Gateway
echo ==========================================

REM Check Docker
docker --version >nul 2>&1
if errorlevel 1 (
    echo.
    echo [ERROR] Docker Desktop is not installed or not running.
    goto :fail
)

REM Check Node.js
node --version >nul 2>&1
if errorlevel 1 (
    echo.
    echo [ERROR] Node.js is not installed. Please install Node.js ^(^>=18^).
    goto :fail
)

REM Switch to script directory
cd /d "%~dp0"

REM Create .env if not exists
if not exist .env (
    copy .env.example .env >nul 2>&1
)

REM Step 1: Start WAF2 Docker service
echo.
echo [1/3] Starting WAF2 service (Docker)...

docker-compose up -d
if errorlevel 1 (
    echo [INFO] Image not found, trying to build...
    docker-compose up -d --build
)

REM Step 2: Install MCP Hub dependencies
echo.
echo [2/3] Installing MCP Hub dependencies...
cd mcp-hub
if not exist node_modules (
    call npm install
    if errorlevel 1 (
        echo.
        echo [ERROR] npm install failed.
        cd /d "%~dp0"
        goto :fail
    )
)

REM Step 3: Start MCP Hub
echo.
echo [3/3] Starting MCP Hub...
echo.
echo ==========================================
echo   Ready!
echo ==========================================
echo.
echo   Dashboard:  http://localhost:4000
echo   Login:      admin / guardrails
echo   MCP:        http://localhost:4000/mcp
echo.
echo ==========================================
echo.

REM Run MCP Hub (foreground)
node ./src/utils/cli.js --port 4000 --config ../config/mcp-servers.json

echo.
echo [!] MCP Hub has stopped.
echo.

:fail
echo.
echo Press any key to close...
pause >nul
exit /b 1
