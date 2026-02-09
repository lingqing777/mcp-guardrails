@echo off
chcp 65001 >nul 2>&1
REM MCP Guardrails 一键启动脚本 (Windows)

echo ==========================================
echo   MCP Guardrails - 安全网关启动脚本
echo ==========================================

REM 检查 Docker
docker --version >nul 2>&1
if errorlevel 1 (
    echo 错误: 请先安装 Docker Desktop
    pause
    exit /b 1
)

REM 检查 Node.js
node --version >nul 2>&1
if errorlevel 1 (
    echo 错误: 请先安装 Node.js ^(^>=18^)
    pause
    exit /b 1
)

REM 获取脚本所在目录
cd /d "%~dp0"

REM 创建 .env 文件 (可选，Dashboard 中也可配置)
if not exist .env (
    copy .env.example .env >nul 2>&1
)

REM 步骤 1: 启动 Docker 服务 (WAF2)
echo.
echo [1/3] 启动 WAF2 服务...
docker-compose up -d --build

REM 步骤 2: 安装 MCP Hub 依赖
echo.
echo [2/3] 安装 MCP Hub 依赖...
cd mcp-hub
if not exist node_modules (
    call npm install
)

REM 步骤 3: 启动 MCP Hub
echo.
echo [3/3] 启动 MCP Hub...
echo.
echo ==========================================
echo   启动完成！
echo ==========================================
echo.
echo   Dashboard:    http://localhost:4000
echo   登录账号:     admin / guardrails
echo.
echo   在 Dashboard 中完成所有配置:
echo   - 配置页面: 设置目标URL和API Key
echo   - MCP Servers页面: 添加你的MCP Server
echo.
echo   Agent 连接地址: http://localhost:4000/mcp
echo.
echo ==========================================
echo.

REM 启动 MCP Hub (前台运行)
node ./src/utils/cli.js --port 4000 --config ../config/mcp-servers.json
