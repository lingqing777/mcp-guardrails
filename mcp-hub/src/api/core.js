/**
 * 核心 API 路由
 * 包含健康检查、SSE、MCP 端点、市场、工作区等
 */

import {
  registerRoute,
} from "../utils/router.js";
import {
  ValidationError,
  ServerError,
  wrapError,
} from "../utils/errors.js";
import { EventTypes, HubState } from "../utils/sse-manager.js";
import logger from "../utils/logger.js";

/**
 * 注册健康检查路由
 */
export function registerHealthRoute(getServiceManager) {
  registerRoute("GET", "/health", "Check server health", async (req, res) => {
    const serviceManager = getServiceManager();
    const healthData = {
      status: "ok",
      state: serviceManager?.state || HubState.STARTING,
      server_id: "mcp-hub",
      version: process.env.VERSION,
      activeClients: serviceManager?.sseManager?.connections.size || 0,
      timestamp: new Date().toISOString(),
      servers: serviceManager?.mcpHub?.getAllServerStatuses() || [],
      connections: serviceManager?.sseManager?.getStats() || { totalConnections: 0, connections: [] }
    };

    // Add MCP endpoint stats if available
    if (serviceManager?.mcpServerEndpoint) {
      healthData.mcpEndpoint = serviceManager.mcpServerEndpoint.getStats();
    }

    // Add workspace information if available
    if (serviceManager?.workspaceCache) {
      try {
        healthData.workspaces = {
          current: serviceManager.workspaceCache.getWorkspaceKey(),
          allActive: await serviceManager.workspaceCache.getActiveWorkspaces()
        };
      } catch (error) {
        logger.debug(`Failed to get workspace info for health check: ${error.message}`);
      }
    }

    res.json(healthData);
  });
}

/**
 * 注册 SSE 事件路由
 */
export function registerSSERoute(getServiceManager) {
  registerRoute("GET", "/events", "Subscribe to server events", async (req, res) => {
    const serviceManager = getServiceManager();
    try {
      if (!serviceManager?.sseManager) {
        throw new ServerError("SSE manager not initialized");
      }
      const connection = await serviceManager.sseManager.addConnection(req, res);
      connection.send(EventTypes.HUB_STATE, serviceManager.getState());
    } catch (error) {
      logger.error('SSE_SETUP_ERROR', 'Failed to setup SSE connection', {
        error: error.message,
        stack: error.stack
      });

      if (!res.writableEnded) {
        res.status(500).end();
      }
    }
  });
}

/**
 * 注册 MCP 端点路由
 */
export function registerMCPEndpointRoutes(app, getServiceManager) {
  // MCP SSE 端点
  app.get("/mcp", async (req, res) => {
    const serviceManager = getServiceManager();
    try {
      if (!serviceManager?.mcpServerEndpoint) {
        throw new ServerError("MCP server endpoint not initialized");
      }
      await serviceManager.mcpServerEndpoint.handleSSEConnection(req, res);
    } catch (error) {
      logger.warn(`Failed to setup MCP SSE connection: ${error.message}`);
      if (!res.headersSent) {
        res.status(500).send('Error establishing MCP connection');
      }
    }
  });

  // MCP 消息端点
  app.post("/messages", async (req, res) => {
    const serviceManager = getServiceManager();
    try {
      if (!serviceManager?.mcpServerEndpoint) {
        throw new ServerError("MCP server endpoint not initialized");
      }
      await serviceManager.mcpServerEndpoint.handleMCPMessage(req, res);
    } catch (error) {
      logger.warn('Failed to handle MCP message');
      if (!res.headersSent) {
        res.status(500).send('Error handling MCP message');
      }
    }
  });
}

/**
 * 注册市场路由
 */
export function registerMarketplaceRoutes(getServiceManager) {
  registerRoute(
    "GET",
    "/marketplace",
    "Get marketplace catalog with filtering and sorting",
    async (req, res) => {
      const { search, category, tags, sort } = req.query;
      const serviceManager = getServiceManager();
      try {
        if (!serviceManager?.marketplace) {
          return res.status(503).json({ error: "Marketplace 未就绪" });
        }
        const servers = await serviceManager.marketplace.getCatalog({
          search,
          category,
          tags: tags ? tags.split(",") : undefined,
          sort,
        });
        res.json({
          servers,
          timestamp: new Date().toISOString(),
        });
      } catch (error) {
        throw wrapError(error, "MARKETPLACE_ERROR", {
          query: req.query,
        });
      }
    }
  );

  registerRoute(
    "POST",
    "/marketplace/details",
    "Get detailed server information",
    async (req, res) => {
      const { mcpId } = req.body;
      const serviceManager = getServiceManager();
      try {
        if (!serviceManager?.marketplace) {
          return res.status(503).json({ error: "Marketplace 未就绪" });
        }
        if (!mcpId) {
          throw new ValidationError("Missing mcpId in request body");
        }

        const details = await serviceManager.marketplace.getServerDetails(mcpId);
        if (!details) {
          throw new ValidationError("Server not found", { mcpId });
        }

        res.json({
          server: details,
          timestamp: new Date().toISOString(),
        });
      } catch (error) {
        throw wrapError(error, "MARKETPLACE_ERROR", {
          mcpId: req.body.mcpId,
        });
      }
    }
  );
}

/**
 * 注册工作区路由
 */
export function registerWorkspacesRoute(getServiceManager) {
  registerRoute(
    "GET",
    "/workspaces",
    "Get all active workspaces",
    async (req, res) => {
      const serviceManager = getServiceManager();
      try {
        if (!serviceManager?.workspaceCache) {
          return res.status(503).json({ error: "Workspace Cache 未就绪" });
        }
        const workspaces = await serviceManager.workspaceCache.getActiveWorkspaces();
        res.json({
          workspaces,
          timestamp: new Date().toISOString(),
        });
      } catch (error) {
        throw wrapError(error, "WORKSPACE_ERROR", {
          operation: "list_workspaces",
        });
      }
    }
  );
}

/**
 * 注册 Hub 重启路由
 */
export function registerRestartRoutes(getServiceManager) {
  // 软重启
  registerRoute("POST", "/restart", "Restart MCP Hub", async (req, res) => {
    const serviceManager = getServiceManager();
    try {
      if (!serviceManager?.mcpHub) {
        return res.status(503).json({ error: "MCP Hub 未就绪" });
      }
      await serviceManager.restartHub();
      res.json({
        status: "ok",
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      throw wrapError(error, "HUB_RESTART_ERROR");
    }
  });

  // 硬重启
  registerRoute("POST", "/hard-restart", "Hard Restart MCP Hub", async (req, res) => {
    const serviceManager = getServiceManager();
    try {
      if (serviceManager?.mcpHub) {
        serviceManager.setState(HubState.RESTARTING);
        process.emit('SIGTERM');
      }
      res.json({
        status: "ok",
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      throw wrapError(error, "HUB_HARD_RESTART_ERROR");
    }
  });
}
