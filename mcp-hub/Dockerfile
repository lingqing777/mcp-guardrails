FROM node:20-slim

WORKDIR /app

# 复制 package.json
COPY package.json .

# 安装依赖
RUN npm install

# 复制源码
COPY . .

# 复制配置文件
COPY mcp-servers.json /app/mcp-servers.json

EXPOSE 4000

# 启动 MCP Hub，指定配置文件
CMD ["node", "./src/utils/cli.js", "--port", "4000", "--config", "/app/mcp-servers.json"]
