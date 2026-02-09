#!/bin/bash
# MCP Guardrails 一键启动脚本

set -e

echo "=========================================="
echo "  MCP Guardrails - 安全网关启动脚本"
echo "=========================================="

# 颜色定义
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# 检查 Docker
if ! command -v docker &> /dev/null; then
    echo "错误: 请先安装 Docker"
    exit 1
fi

# 检查 Node.js
if ! command -v node &> /dev/null; then
    echo "错误: 请先安装 Node.js (>=18)"
    exit 1
fi

# 获取脚本所在目录
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# 创建 .env 文件 (可选，Dashboard 中也可配置)
if [ ! -f .env ]; then
    cp .env.example .env 2>/dev/null || true
fi

# 步骤 1: 启动 Docker 服务 (WAF2)
echo ""
echo -e "${GREEN}[1/3] 启动 WAF2 服务...${NC}"
docker-compose up -d --build

# 步骤 2: 安装 MCP Hub 依赖
echo ""
echo -e "${GREEN}[2/3] 安装 MCP Hub 依赖...${NC}"
cd mcp-hub
if [ ! -d node_modules ]; then
    npm install
fi

# 步骤 3: 启动 MCP Hub
echo ""
echo -e "${GREEN}[3/3] 启动 MCP Hub...${NC}"
echo ""
echo "=========================================="
echo "  启动完成！"
echo "=========================================="
echo ""
echo "  Dashboard:    http://localhost:4000"
echo "  登录账号:     admin / guardrails"
echo ""
echo "  在 Dashboard 中完成所有配置:"
echo "  - 配置页面: 设置目标URL和API Key"
echo "  - MCP Servers页面: 添加你的MCP Server"
echo ""
echo "  Agent 连接地址: http://localhost:4000/mcp"
echo ""
echo "=========================================="
echo ""

# 启动 MCP Hub (前台运行)
node ./src/utils/cli.js --port 4000 --config ../config/mcp-servers.json
