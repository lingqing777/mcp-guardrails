FROM node:20-slim

WORKDIR /app

# 复制 package.json
COPY package.json .

# 安装依赖
RUN npm install

# 复制源码
COPY . .

EXPOSE 4000

# 启动 MCP Hub，使用环境变量 MCP_SERVERS_CONFIG 或默认配置
# docker-compose 中会通过 volumes 挂载 config 目录
CMD ["sh", "-c", "node ./src/utils/cli.js --port 4000 --config ${MCP_SERVERS_CONFIG:-/app/mcp-servers.json}"]