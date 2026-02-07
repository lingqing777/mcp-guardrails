/**
 * ServiceManager - MCP Hub 服务管理器
 * 负责 HTTP 服务器、MCP Hub、SSE 连接的生命周期管理
 */

import logger from "../utils/logger.js";
import { MCPHub } from "../MCPHub.js";
import { SSEManager, EventTypes, HubState, SubscriptionTypes } from "../utils/sse-manager.js";
import { WorkspaceCacheManager } from "../utils/workspace-cache.js";
import { wrapError } from "../utils/errors.js";
import { getMarketplace } from "../marketplace.js";

const SERVER_ID = "mcp-hub";

/**
 * 服务管理器类
 */
export class ServiceManager {
  constructor(options = {}) {
    this.config = options.config;
    this.port = options.port;
    this.autoShutdown = options.autoShutdown;
    this.shutdownDelay = options.shutdownDelay;
    this.watch = options.watch;
    this.mcpHub = null;
    this.server = null;
    this.marketplace = null;
    this.mcpServerEndpoint = null;
    this.workspaceCache = new WorkspaceCacheManager(options);
    this.sseManager = new SSEManager({
      ...options,
      workspaceCache: this.workspaceCache,
      port: this.port
    });
    this.state = 'starting';
    // Connect logger to SSE manager
    logger.setSseManager(this.sseManager);
  }

  isReady() {
    return this.state === HubState.READY;
  }

  getState(extraData = {}) {
    return {
      state: this.state,
      server_id: SERVER_ID,
      pid: process.pid,
      port: this.port,
      timestamp: new Date().toISOString(),
      ...extraData
    };
  }

  setState(newState, extraData) {
    this.state = newState;
    this.broadcastHubState(extraData);

    // Emit state change event via MCPHub for MCP endpoint to sync tools
    if (this.mcpHub) {
      this.mcpHub.emit('hubStateChanged', { state: newState, extraData });
    }
  }

  /**
   * Broadcasts current hub state to all clients
   * @private
   */
  broadcastHubState(extraData = {}) {
    this.sseManager.broadcast(EventTypes.HUB_STATE, this.getState(extraData));
  }

  broadcastSubscriptionEvent(eventType, data = {}) {
    this.sseManager.broadcast(EventTypes.SUBSCRIPTION_EVENT, {
      type: eventType,
      ...data
    });
  }

  async initializeMCPHub(MCPServerEndpoint) {
    // Initialize workspace cache first
    logger.info("Initializing workspace cache");
    await this.workspaceCache.initialize();
    await this.workspaceCache.register(this.port, this.config);
    await this.workspaceCache.startWatching();

    // Setup workspace cache event handlers
    this.workspaceCache.on('workspacesUpdated', (workspaces) => {
      this.broadcastSubscriptionEvent(SubscriptionTypes.WORKSPACES_UPDATED, { workspaces });
    });

    // Initialize marketplace second
    logger.info("Initializing marketplace catalog");
    this.marketplace = getMarketplace();
    await this.marketplace.initialize();
    logger.info(`Marketplace initialized with ${this.marketplace.cache.registry?.servers?.length || 0}`);

    // Then initialize MCP Hub
    logger.info("Initializing MCP Hub");
    this.mcpHub = new MCPHub(this.config, {
      watch: this.watch,
      port: this.port,
      marketplace: this.marketplace,
    });

    // Setup event handlers
    this.mcpHub.on("configChangeDetected", (data) => {
      this.broadcastSubscriptionEvent(SubscriptionTypes.CONFIG_CHANGED, data);
    });

    this.mcpHub.on("importantConfigChanged", (changes) => {
      this.broadcastSubscriptionEvent(SubscriptionTypes.SERVERS_UPDATING, { changes });
    });
    this.mcpHub.on("importantConfigChangeHandled", (changes) => {
      this.broadcastSubscriptionEvent(SubscriptionTypes.SERVERS_UPDATED, { changes });
    });

    // Server-specific events
    this.mcpHub.on("toolsChanged", (data) => {
      this.broadcastSubscriptionEvent(SubscriptionTypes.TOOL_LIST_CHANGED, data);
    });

    this.mcpHub.on("resourcesChanged", (data) => {
      this.broadcastSubscriptionEvent(SubscriptionTypes.RESOURCE_LIST_CHANGED, data);
    });

    this.mcpHub.on("promptsChanged", (data) => {
      this.broadcastSubscriptionEvent(SubscriptionTypes.PROMPT_LIST_CHANGED, data);
    });

    // Dev mode event handlers
    this.mcpHub.on("devServerRestarting", (data) => {
      this.broadcastSubscriptionEvent(SubscriptionTypes.SERVERS_UPDATING, data);
    });
    this.mcpHub.on("devServerRestarted", (data) => {
      this.broadcastSubscriptionEvent(SubscriptionTypes.SERVERS_UPDATED, data);
    });

    // Initialize MCP server endpoint
    if (MCPServerEndpoint) {
      try {
        this.mcpServerEndpoint = new MCPServerEndpoint(this.mcpHub);
        logger.info(`Hub endpoint ready: Use \`${this.mcpServerEndpoint.getEndpointUrl()}\` endpoint with any other MCP clients`);
      } catch (error) {
        logger.error("MCP_ENDPOINT_INIT_ERROR", "Failed to initialize MCP server endpoint", {
          error: error.message
        }, false);
      }
    }

    await this.mcpHub.initialize();
    this.setState(HubState.READY);
  }

  async restartHub() {
    if (this.mcpHub) {
      this.setState(HubState.RESTARTING);
      logger.info("Restarting MCP Hub");
      await this.mcpHub.initialize(true);
      logger.info("MCP Hub restarted successfully");
      this.setState(HubState.RESTARTED, { has_restarted: true });
    }
  }

  async startServer(app) {
    return new Promise((resolve, reject) => {
      logger.info(`Starting HTTP server on port ${this.port}`, {
        port: this.port,
      });

      this.server = app.listen(this.port, () => {
        logger.info("HTTP_SERVER_STARTED");
        resolve();
      });

      this.server.on("error", (error) => {
        this.setState(HubState.ERROR, { message: error.message, code: error.code });
        logger.info(`HTTP_SERVER_START_ERROR: ${error.code}: ${error.message}`);
        reject(
          wrapError(error, "HTTP_SERVER_ERROR", {
            port: this.port,
          })
        );
      });
    });
  }

  async stopServer() {
    return new Promise((resolve, reject) => {
      if (!this.server) {
        logger.warn("HTTP server is already stopped and cannot be stopped again");
        resolve();
        return;
      }

      logger.info("Stopping HTTP server and closing all connections");
      this.server.close((error) => {
        if (error) {
          logger.error(
            "SERVER_STOP_ERROR",
            "Failed to stop HTTP server",
            {
              error: error.message,
              stack: error.stack,
            },
            false
          );
          reject(wrapError(error, "SERVER_STOP_ERROR"));
          return;
        }

        logger.info("HTTP server has been successfully stopped");
        this.server = null;
        resolve();
      });
    });
  }

  async stopMCPHub() {
    if (!this.mcpHub) {
      logger.warn("MCP Hub is already stopped and cannot be stopped again");
      return;
    }

    logger.info("Stopping MCP Hub and cleaning up resources");
    try {
      await this.mcpHub.cleanup();
      logger.info("MCP Hub has been successfully stopped and cleaned up");
      this.mcpHub = null;
    } catch (error) {
      logger.error(
        "HUB_STOP_ERROR",
        "Failed to stop MCP Hub",
        {
          error: error.message,
          stack: error.stack,
        },
        false
      );
    }
  }

  setupSignalHandlers() {
    const shutdown = (signal) => async () => {
      logger.info(`Received ${signal} signal - initiating graceful shutdown`, {
        signal,
      });
      try {
        await this.shutdown();
        logger.info("Graceful shutdown completed successfully");
        process.exit(0);
      } catch (error) {
        logger.error(
          "SHUTDOWN_ERROR",
          "Shutdown failed",
          {
            error: error.message,
            stack: error.stack,
          },
          true,
          1
        );
      }
    };

    process.on("SIGTERM", shutdown("SIGTERM"));
    process.on("SIGINT", shutdown("SIGINT"));
  }

  async shutdown() {
    this.setState(HubState.STOPPING);
    logger.info("Starting graceful shutdown process");

    // Close MCP server endpoint
    if (this.mcpServerEndpoint) {
      try {
        await this.mcpServerEndpoint.close();
        this.mcpServerEndpoint = null;
      } catch (error) {
        logger.debug(`Error closing MCP server endpoint: ${error.message}`);
      }
    }

    this.stopServer().catch((error) => {
      logger.debug(`Error stopping HTTP server: ${error.message}`);
    });

    await Promise.allSettled([
      this.stopMCPHub(),
      this.sseManager.shutdown(),
      this.workspaceCache.shutdown()
    ]);
    this.setState(HubState.STOPPED);
  }
}

export { SERVER_ID, HubState };
