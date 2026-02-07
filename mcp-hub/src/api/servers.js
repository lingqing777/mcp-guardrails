/**
 * MCP 服务器管理 API
 * 处理 MCP 服务器的启动、停止、刷新、工具调用等
 */

import {
  registerRoute,
} from "../utils/router.js";
import {
  ValidationError,
  wrapError,
} from "../utils/errors.js";
import { SubscriptionTypes } from "../utils/sse-manager.js";

/**
 * 注册 MCP 服务器管理路由
 */
export function registerServerRoutes(getServiceManager) {
  // 服务器列表
  registerRoute(
    "GET",
    "/servers",
    "List all MCP servers and their status",
    (req, res) => {
      const serviceManager = getServiceManager();
      const servers = serviceManager.mcpHub.getAllServerStatuses();
      res.json({
        servers,
        timestamp: new Date().toISOString(),
      });
    }
  );

  // 服务器详情
  registerRoute(
    "POST",
    "/servers/info",
    "Get status of a specific server",
    (req, res) => {
      const { server_name } = req.body;
      const serviceManager = getServiceManager();
      try {
        if (!server_name) {
          throw new ValidationError("Missing server name", { field: "server_name" });
        }
        const status = serviceManager.mcpHub.getServerStatus(server_name);
        res.json({
          server: status,
          timestamp: new Date().toISOString(),
        });
      } catch (error) {
        throw wrapError(error, "SERVER_NOT_FOUND", {
          server: server_name
        });
      }
    }
  );

  // 启动服务器
  registerRoute(
    "POST",
    "/servers/start",
    "Start a server",
    async (req, res) => {
      const { server_name } = req.body;
      const serviceManager = getServiceManager();
      try {
        if (!server_name) {
          throw new ValidationError("Missing server name", { field: "server_name" });
        }
        const status = await serviceManager.mcpHub.startServer(server_name);
        res.json({
          status: "ok",
          server: status,
          timestamp: new Date().toISOString(),
        });
      } catch (error) {
        throw wrapError(error, "SERVER_START_ERROR", { server: server_name });
      } finally {
        serviceManager.broadcastSubscriptionEvent(SubscriptionTypes.SERVERS_UPDATED, {
          changes: {
            modified: [server_name],
          }
        });
      }
    }
  );

  // 停止服务器
  registerRoute(
    "POST",
    "/servers/stop",
    "Stop a server",
    async (req, res) => {
      const { server_name } = req.body;
      const serviceManager = getServiceManager();
      try {
        if (!server_name) {
          throw new ValidationError("Missing server name", { field: "server_name" });
        }
        const { disable } = req.query;
        const status = await serviceManager.mcpHub.stopServer(
          server_name,
          disable === "true"
        );
        res.json({
          status: "ok",
          server: status,
          timestamp: new Date().toISOString(),
        });
      } catch (error) {
        throw wrapError(error, "SERVER_STOP_ERROR", { server: server_name });
      } finally {
        serviceManager.broadcastSubscriptionEvent(SubscriptionTypes.SERVERS_UPDATED, {
          changes: {
            modified: [server_name],
          }
        });
      }
    }
  );

  // 刷新服务器
  registerRoute(
    "POST",
    "/servers/refresh",
    "Refresh a server's capabilities",
    async (req, res) => {
      const { server_name } = req.body;
      const serviceManager = getServiceManager();
      try {
        if (!server_name) {
          throw new ValidationError("Missing server name", { field: "server_name" });
        }
        const info = await serviceManager.mcpHub.refreshServer(server_name);
        res.json({
          status: "ok",
          server: info,
          timestamp: new Date().toISOString(),
        });
      } catch (error) {
        throw wrapError(error, "SERVER_REFRESH_ERROR", { server: server_name });
      }
    }
  );

  // 刷新所有服务器
  registerRoute(
    "GET",
    "/refresh",
    "Refresh all servers' capabilities",
    async (req, res) => {
      const serviceManager = getServiceManager();
      try {
        const results = await serviceManager.mcpHub.refreshAllServers();
        res.json({
          status: "ok",
          servers: results,
          timestamp: new Date().toISOString(),
        });
      } catch (error) {
        throw wrapError(error, "SERVERS_REFRESH_ERROR");
      }
    }
  );

  // 执行工具
  registerRoute(
    "POST",
    "/servers/tools",
    "Execute a tool on a specific server",
    async (req, res) => {
      const { server_name, tool, arguments: args, request_options } = req.body;
      const serviceManager = getServiceManager();
      try {
        if (!server_name) {
          throw new ValidationError("Missing server name", { field: "server_name" });
        }
        if (!tool) {
          throw new ValidationError("Missing tool name", { field: "tool" });
        }
        const result = await serviceManager.mcpHub.callTool(
          server_name,
          tool,
          args || {},
          request_options
        );
        res.json({
          result,
          timestamp: new Date().toISOString(),
        });
      } catch (error) {
        throw wrapError(error, error.code || "TOOL_EXECUTION_ERROR", {
          server: server_name,
          tool,
          ...(error.data || {}),
        });
      }
    }
  );

  // 获取 Prompt
  registerRoute(
    "POST",
    "/servers/prompts",
    "Get a prompt from a specific server",
    async (req, res) => {
      const { server_name, prompt, arguments: args, request_options } = req.body;
      const serviceManager = getServiceManager();
      try {
        if (!server_name) {
          throw new ValidationError("Missing server name", { field: "server_name" });
        }
        if (!prompt) {
          throw new ValidationError("Missing prompt name", { field: "prompt" });
        }
        const result = await serviceManager.mcpHub.getPrompt(
          server_name,
          prompt,
          args || {},
          request_options
        );
        res.json({
          result,
          timestamp: new Date().toISOString(),
        });
      } catch (error) {
        throw wrapError(error, error.code || "PROMPT_EXECUTION_ERROR", {
          server: server_name,
          prompt,
          ...(error.data || {}),
        });
      }
    }
  );

  // 访问资源
  registerRoute(
    "POST",
    "/servers/resources",
    "Access a resource on a specific server",
    async (req, res) => {
      const { server_name, uri, request_options } = req.body;
      const serviceManager = getServiceManager();
      try {
        if (!server_name) {
          throw new ValidationError("Missing server name", { field: "server_name" });
        }
        if (!uri) {
          throw new ValidationError("Missing resource URI", { field: "uri" });
        }
        const result = await serviceManager.mcpHub.readResource(server_name, uri, request_options);
        res.json({
          result,
          timestamp: new Date().toISOString(),
        });
      } catch (error) {
        throw wrapError(error, error.code || "RESOURCE_READ_ERROR", {
          server: server_name,
          uri,
          ...(error.data || {}),
        });
      }
    }
  );

  // 授权
  registerRoute(
    "POST",
    "/servers/authorize",
    "Handles opening different kinds of uris",
    async (req, res) => {
      const { server_name } = req.body;
      const serviceManager = getServiceManager();
      try {
        if (!server_name) {
          throw new ValidationError("Missing server name", { field: "server_name" });
        }
        const connection = serviceManager.mcpHub.getConnection(server_name);
        const result = await connection.authorize();
        res.json(result);
      } catch (error) {
        throw wrapError(error, "OPEN_REQUEST_ERROR", error.data || {});
      }
    }
  );
}

/**
 * 注册简单工具调用 API (供 Dashboard 测试使用)
 */
export function registerToolsCallRoute(app, getServiceManager) {
  app.post("/api/tools/call", async (req, res) => {
    const { server_name, tool, arguments: args } = req.body;
    const serviceManager = getServiceManager();

    try {
      if (!serviceManager || !serviceManager.mcpHub) {
        return res.status(503).json({ error: "MCP Hub 未就绪" });
      }

      const connection = serviceManager.mcpHub.connections?.get(server_name);

      if (!connection) {
        return res.status(404).json({ error: `Server '${server_name}' 不存在` });
      }

      if (connection.status !== 'connected') {
        return res.status(503).json({ error: `Server '${server_name}' 未连接 (status: ${connection.status})` });
      }

      const result = await connection.client.callTool({
        name: tool,
        arguments: args || {}
      });

      res.json({ success: true, result });
    } catch (error) {
      console.error('[API] Tool call error:', error);
      res.status(500).json({ error: error.message });
    }
  });
}
