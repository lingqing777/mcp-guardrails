/**
 * MCP Hub Server Endpoint - Unified MCP Server Interface
 * 
 * This module creates a single MCP server endpoint that exposes ALL capabilities
 * from multiple managed MCP servers through one unified interface.
 * 
 * HOW IT WORKS:
 * 1. MCP Hub manages multiple individual MCP servers (like filesystem, github, etc.)
 * 2. This endpoint collects all tools/resources/prompts from those servers
 * 3. It creates a single MCP server that any MCP client can connect to
 * 4. When a client calls a tool, it routes the request to the correct underlying server
 * 
 * BENEFITS:
 * - Users manage all MCP servers in one place through MCP Hub's TUI
 * - MCP clients (like Claude Desktop, Cline, etc.) only need to connect to one endpoint
 * - No need to configure each MCP client with dozens of individual server connections
 * - Automatic capability updates when servers are added/removed/restarted
 * 
 * EXAMPLE:
 * Just configure clients with with:
 * {
 *  "Hub": {
 *    "url": "http://localhost:${port}/mcp"
 *  }
 * }
 * The hub automatically namespaces capabilities to avoid conflicts:
 * - "search" tool from filesystem server becomes "filesystem__search"
 * - "search" tool from github server becomes "github__search"
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { randomUUID } from "node:crypto";
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
  GetPromptResultSchema,
  CallToolResultSchema,
  ReadResourceResultSchema,
  ListResourcesRequestSchema,
  ReadResourceRequestSchema,
  ListResourceTemplatesRequestSchema,
  ListPromptsRequestSchema,
  GetPromptRequestSchema,
  McpError,
  ErrorCode,
} from "@modelcontextprotocol/sdk/types.js";
import { HubState } from "../utils/sse-manager.js";
import logger from "../utils/logger.js";

// Unique server name to identify our internal MCP endpoint
const HUB_INTERNAL_SERVER_NAME = "mcp-hub-internal-endpoint";

// Delimiter for namespacing
const DELIMITER = '__';
const MCP_REQUEST_TIMEOUT = 5 * 60 * 1000 //Default to 5 minutes

// Comprehensive capability configuration
const CAPABILITY_TYPES = {
  TOOLS: {
    id: 'tools',
    uidField: 'name',
    syncWithEvents: {
      events: ['toolsChanged'],
      capabilityIds: ['tools'],
      notificationMethod: 'sendToolListChanged'
    },
    listSchema: ListToolsRequestSchema,
    handler: {
      method: "tools/call",
      callSchema: CallToolRequestSchema,
      resultSchema: CallToolResultSchema,
      form_error(error) {
        return {
          content: [
            {
              type: "text",
              text: error instanceof Error ? error.message : String(error),
            },
          ],
          isError: true,
        }
      },
      form_params(cap, request) {
        return {
          name: cap.originalName,
          arguments: request.params.arguments || {},
        }
      }
    }
  },
  RESOURCES: {
    id: 'resources',
    uidField: 'uri',
    syncWithEvents: {
      events: ['resourcesChanged'],
      capabilityIds: ['resources', 'resourceTemplates'],
      notificationMethod: 'sendResourceListChanged'
    },
    listSchema: ListResourcesRequestSchema,
    handler: {
      method: "resources/read",
      form_error(error) {
        throw new McpError(ErrorCode.InvalidParams, `Failed to read resource: ${error.message}`);
      },
      form_params(cap, request) {
        return {
          uri: cap.originalName,
        }
      },
      callSchema: ReadResourceRequestSchema,
      resultSchema: ReadResourceResultSchema,
    }
  },
  RESOURCE_TEMPLATES: {
    id: 'resourceTemplates',
    uidField: 'uriTemplate',
    // No syncWithEvents - handled by resources event
    listSchema: ListResourceTemplatesRequestSchema,
    // No callSchema - templates are listed only
    syncWithEvents: {
      events: [],
      capabilityIds: [],
      notificationMethod: 'sendResourceListChanged'
    },
  },
  PROMPTS: {
    id: 'prompts',
    uidField: 'name',
    syncWithEvents: {
      events: ['promptsChanged'],
      capabilityIds: ['prompts'],
      notificationMethod: 'sendPromptListChanged'
    },
    listSchema: ListPromptsRequestSchema,
    handler: {
      method: "prompts/get",
      callSchema: GetPromptRequestSchema,
      resultSchema: GetPromptResultSchema,
      form_params(cap, request) {
        return {
          name: cap.originalName,
          arguments: request.params.arguments || {},
        }
      },
      form_error(error) {
        throw new McpError(ErrorCode.InvalidParams, `Failed to read resource: ${error.message}`);
      }
    }
  },
};

/**
 * MCP Server endpoint that exposes all managed server capabilities
 * This allows standard MCP clients to connect to mcp-hub via MCP protocol
 *
 * Supports both:
 * - SSE Transport: GET /mcp for SSE stream, POST /messages?sessionId=xxx for messages
 * - Streamable HTTP Transport: POST /mcp with Mcp-Session-Id header
 */
export class MCPServerEndpoint {
  constructor(mcpHub) {
    this.mcpHub = mcpHub;
    this.clients = new Map(); // sessionId -> { transport, server }
    this.serversMap = new Map(); // sessionId -> server instance

    // Streamable HTTP transports (keyed by session ID)
    this.streamableClients = new Map(); // sessionId -> { transport, server }

    // Store registered capabilities by type
    this.registeredCapabilities = {};
    Object.values(CAPABILITY_TYPES).forEach(capType => {
      this.registeredCapabilities[capType.id] = new Map(); // namespacedName -> { serverName, originalName, definition }
    });

    // Setup capability synchronization once
    this.setupCapabilitySync();

    // Initial capability registration
    this.syncCapabilities();
  }

  getEndpointUrl() {
    return `${this.mcpHub.hubServerUrl}/mcp`;
  }

  /**
   * Create a new MCP server instance for each connection
   */
  createServer() {
    // Create low-level MCP server instance with unique name
    const server = new Server(
      {
        name: HUB_INTERNAL_SERVER_NAME,
        version: "1.0.0",
      },
      {
        capabilities: {
          tools: {
            listChanged: true
          },
          resources: {
            listChanged: true,
          },
          prompts: {
            listChanged: true,
          },
        },
      }
    );
    server.onerror = function(err) {
      logger.warn(`Hub Endpoint onerror: ${err.message}`);
    }
    // Setup request handlers for this server instance
    this.setupRequestHandlers(server);

    return server;
  }

  /**
   * Creates a safe server name for namespacing (replace special chars with underscores)
   */
  createSafeServerName(serverName) {
    return serverName.replace(/[^a-zA-Z0-9]/g, '_');
  }


  /**
   * Setup MCP request handlers for a server instance
   */
  setupRequestHandlers(server) {
    // Setup handlers for each capability type
    Object.values(CAPABILITY_TYPES).forEach(capType => {
      const capId = capType.id;

      // Setup list handler if schema exists
      if (capType.listSchema) {
        server.setRequestHandler(capType.listSchema, () => {
          const capabilityMap = this.registeredCapabilities[capId];
          const capabilities = Array.from(capabilityMap.values()).map(item => item.definition);
          return { [capId]: capabilities };
        });
      }

      // Setup call/action handler if schema exists
      if (capType.handler?.callSchema) {
        server.setRequestHandler(capType.handler.callSchema, async (request, extra) => {

          const registeredCap = this.getRegisteredCapability(request, capType.id, capType.uidField);
          if (!registeredCap) {
            throw new McpError(
              ErrorCode.InvalidParams,
              `${capId} capability not found: ${key}`
            );
          }
          const { serverName, originalName } = registeredCap;
          const request_options = {
            timeout: MCP_REQUEST_TIMEOUT
          }
          try {
            const result = await this.mcpHub.rawRequest(serverName, {
              method: capType.handler.method,
              params: capType.handler.form_params(registeredCap, request)
            }, capType.handler.resultSchema, request_options)
            return result;
          } catch (error) {
            logger.debug(`Error executing ${capId} '${originalName}': ${error.message}`);
            return capType.handler.form_error(error)
          }
        });
      }
    });
  }

  getRegisteredCapability(request, capId, uidField) {
    const capabilityMap = this.registeredCapabilities[capId];
    let key = request.params[uidField]
    const registeredCap = capabilityMap.get(key);
    // key might be a resource Template
    if (!registeredCap && capId === CAPABILITY_TYPES.RESOURCES.id) {
      let [serverName, ...uri] = key.split(DELIMITER);
      if (!serverName || !uri) {
        return null; // Invalid format
      }
      serverName = this.serversMap.get(serverName)?.name
      return {
        serverName,
        originalName: uri.join(DELIMITER),
      }
    }
    return registeredCap
  }

  /**
   * Setup listeners for capability changes from managed servers
   */
  setupCapabilitySync() {
    // For each capability type with syncWithEvents
    Object.values(CAPABILITY_TYPES).forEach(capType => {
      if (capType.syncWithEvents) {
        const { events, capabilityIds } = capType.syncWithEvents;

        events.forEach(event => {
          this.mcpHub.on(event, (data) => {
            this.syncCapabilities(capabilityIds);
          });
        });
      }
    });

    // Global events that sync ALL capabilities
    const globalSyncEvents = ['importantConfigChangeHandled'];
    globalSyncEvents.forEach(event => {
      this.mcpHub.on(event, (data) => {
        this.syncCapabilities(); // Sync all capabilities
      });
    });

    // Listen for hub state changes to re-sync all capabilities when servers are ready
    this.mcpHub.on('hubStateChanged', (data) => {
      const { state } = data;
      const criticalStates = [HubState.READY, HubState.RESTARTED, HubState.STOPPED, HubState.ERROR];

      if (criticalStates.includes(state)) {
        this.syncCapabilities(); // Sync all capabilities
      }
    });
  }

  /**
   * Synchronize capabilities from connected servers
   * @param {string[]} capabilityIds - Specific capability IDs to sync, defaults to all
   */
  syncCapabilities(capabilityIds = null) {
    // Default to all capability IDs if none specified
    const idsToSync = capabilityIds || Object.values(CAPABILITY_TYPES).map(capType => capType.id);

    // Update the servers map with current connection states
    this.syncServersMap()

    // Sync each requested capability type and notify clients of changes
    idsToSync.forEach(capabilityId => {
      const changed = this.syncCapabilityType(capabilityId);
      if (changed) {
        // Send notification for this specific capability type if we have active connections
        if (this.hasActiveConnections()) {
          const capType = Object.values(CAPABILITY_TYPES).find(cap => cap.id === capabilityId);
          if (capType?.syncWithEvents?.notificationMethod) {
            this.notifyCapabilityChanges(capType.syncWithEvents.notificationMethod);
          }
        }
      }
    });
  }

  /**
   * Synchronize the servers map with current connection states
   * Creates safe server IDs for namespacing capabilities
   */
  syncServersMap() {
    this.serversMap.clear();

    // Register all connected servers with unique safe IDs
    for (const connection of this.mcpHub.connections.values()) {
      if (connection.status === "connected" && !connection.disabled) {
        const name = connection.name;
        let id = this.createSafeServerName(name);

        // Ensure unique ID by appending counter if needed
        if (this.serversMap.has(id)) {
          let counter = 1;
          while (this.serversMap.has(`${id}_${counter}`)) {
            counter++;
          }
          id = `${id}_${counter}`;
        }
        this.serversMap.set(id, connection);
      }
    }
  }

  /**
   * Synchronize a specific capability type and detect changes
   */
  syncCapabilityType(capabilityId) {
    const capabilityMap = this.registeredCapabilities[capabilityId];
    const previousKeys = new Set(capabilityMap.keys());

    // Clear and rebuild capabilities from connected servers
    capabilityMap.clear();
    for (const [serverId, connection] of this.serversMap) {
      if (connection.status === "connected" && !connection.disabled) {
        this.registerServerCapabilities(connection, { capabilityId, serverId });
      }
    }

    // Check if capability keys changed
    const newKeys = new Set(capabilityMap.keys());
    return previousKeys.size !== newKeys.size ||
      [...newKeys].some(key => !previousKeys.has(key));
  }


  /**
   * Send capability change notifications to all connected clients
   */
  notifyCapabilityChanges(notificationMethod) {
    for (const { server } of this.clients.values()) {
      try {
        server[notificationMethod]();
      } catch (error) {
        logger.warn(`Error sending ${notificationMethod} notification: ${error.message}`);
      }
    }
  }

  /**
   * Register capabilities from a server connection for a specific capability type
   * Creates namespaced capability names to avoid conflicts between servers
   */
  registerServerCapabilities(connection, { capabilityId, serverId }) {
    const serverName = connection.name;

    // Skip self-reference to prevent infinite recursion
    if (this.isSelfReference(connection)) {
      return;
    }

    // Find the capability type configuration and get server's capabilities
    const capType = Object.values(CAPABILITY_TYPES).find(cap => cap.id === capabilityId);
    const capabilities = connection[capabilityId];
    if (!capabilities || !Array.isArray(capabilities)) {
      return; // No capabilities of this type
    }

    const capabilityMap = this.registeredCapabilities[capabilityId];

    // Register each capability with namespaced name
    for (const cap of capabilities) {
      const originalValue = cap[capType.uidField];
      const uniqueName = serverId + DELIMITER + originalValue;

      // Create capability with namespaced unique identifier
      const formattedCap = {
        ...cap,
        [capType.uidField]: uniqueName
      };

      // Store capability with metadata for routing back to original server
      capabilityMap.set(uniqueName, {
        serverName,
        originalName: originalValue,
        definition: formattedCap,
      });
    }
  }


  /**
   * Check if a connection is a self-reference (connecting to our own MCP endpoint)
   */
  isSelfReference(connection) {
    // Primary check: Compare server's reported name with our internal server name
    if (connection.serverInfo && connection.serverInfo.name === HUB_INTERNAL_SERVER_NAME) {
      return true;
    }
    return false;
  }

  /**
   * Check if there are any active MCP client connections
   */
  hasActiveConnections() {
    return this.clients.size > 0 || this.streamableClients.size > 0;
  }




  /**
   * Handle SSE transport creation (GET /mcp)
   */
  async handleSSEConnection(req, res) {

    // Create SSE transport
    const transport = new SSEServerTransport('/messages', res);
    const sessionId = transport.sessionId;

    // Create a new server instance for this connection
    const server = this.createServer();

    // Store transport and server together
    this.clients.set(sessionId, { transport, server });

    let clientInfo


    // Setup cleanup on close - use a flag to prevent recursive calls
    let isClosing = false;
    const cleanup = async () => {
      if (isClosing) return;
      isClosing = true;

      this.clients.delete(sessionId);
      try {
        await server.close();
      } catch (error) {
        logger.warn(`Error closing server connected to ${clientInfo?.name ?? "Unknown"}: ${error.message}`);
      } finally {
        logger.info(`'${clientInfo?.name ?? "Unknown"}' client disconnected from MCP HUB`);
      }
    };

    res.on("close", cleanup);
    transport.onclose = cleanup;

    // Connect MCP server to transport
    await server.connect(transport);
    server.oninitialized = () => {
      clientInfo = server.getClientVersion()
      if (clientInfo) {
        logger.info(`'${clientInfo.name}' client connected to MCP HUB`)
      }
    }
  }

  /**
   * Handle Streamable HTTP transport (POST /mcp)
   * This supports the newer MCP Streamable HTTP transport specification
   */
  async handleStreamableHTTP(req, res) {
    const sessionId = req.headers['mcp-session-id'];

    // If we have a session ID, try to find existing transport
    if (sessionId && this.streamableClients.has(sessionId)) {
      const { transport } = this.streamableClients.get(sessionId);
      await transport.handleRequest(req, res, req.body);
      return;
    }

    // Create new Streamable HTTP transport for new sessions
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
      enableJsonResponse: true,
    });

    // Create a new server instance for this connection
    const server = this.createServer();

    let clientInfo;

    // Setup session initialization callback
    transport._onsessioninitialized = (newSessionId) => {
      this.streamableClients.set(newSessionId, { transport, server });
      logger.info(`Streamable HTTP session initialized: ${newSessionId}`);
    };

    // Setup cleanup on close - use a flag to prevent recursive calls
    let isClosing = false;
    transport.onclose = async () => {
      if (isClosing) return;
      isClosing = true;

      const sid = transport._sessionId;
      if (sid) {
        this.streamableClients.delete(sid);
      }
      try {
        await server.close();
      } catch (error) {
        logger.warn(`Error closing Streamable HTTP server: ${error.message}`);
      }
      logger.info(`'${clientInfo?.name ?? "Unknown"}' Streamable HTTP client disconnected from MCP HUB`);
    };

    // Connect MCP server to transport
    await server.connect(transport);
    server.oninitialized = () => {
      clientInfo = server.getClientVersion();
      if (clientInfo) {
        logger.info(`'${clientInfo.name}' Streamable HTTP client connected to MCP HUB`);
      }
    };

    // Handle the initial request
    await transport.handleRequest(req, res, req.body);
  }

  /**
   * Handle MCP messages (POST /messages)
   * 支持两种情况:
   * 1. 带 sessionId 参数 - SSE Transport 的消息
   * 2. 不带 sessionId 但带 Mcp-Session-Id header - Streamable HTTP Transport
   * 3. 都不带 - 创建新的 Streamable HTTP 会话
   */
  async handleMCPMessage(req, res) {
    const sessionId = req.query.sessionId;
    const mcpSessionId = req.headers['mcp-session-id'];

    function sendErrorResponse(code, error) {
      res.status(code).json({
        jsonrpc: "2.0",
        error: {
          code: -32000,
          message: error.message || 'Invalid request',
        },
        id: null,
      });
    }

    // 1. 尝试 SSE Transport (带 query sessionId)
    if (sessionId) {
      const transportInfo = this.clients.get(sessionId);
      if (transportInfo) {
        await transportInfo.transport.handlePostMessage(req, res, req.body);
        return;
      }
      logger.debug(`MCP message for unknown SSE session: ${sessionId}`);
      return sendErrorResponse(404, new Error(`Session not found: ${sessionId}`));
    }

    // 2. 尝试 Streamable HTTP Transport (带 Mcp-Session-Id header)
    if (mcpSessionId && this.streamableClients.has(mcpSessionId)) {
      const { transport } = this.streamableClients.get(mcpSessionId);
      await transport.handleRequest(req, res, req.body);
      return;
    }

    // 3. 没有 session - 创建新的 Streamable HTTP 会话
    // 这种情况通常是客户端第一次发送 initialize 请求（正常行为）
    await this.handleStreamableHTTP(req, res);
  }

  /**
   * Get statistics about the MCP endpoint
   */
  getStats() {
    const capabilityCounts = Object.entries(this.registeredCapabilities)
      .reduce((acc, [type, map]) => {
        acc[type] = map.size;
        return acc;
      }, {});

    return {
      activeClients: this.clients.size + this.streamableClients.size,
      sseClients: this.clients.size,
      streamableClients: this.streamableClients.size,
      registeredCapabilities: capabilityCounts,
      totalCapabilities: Object.values(capabilityCounts).reduce((sum, count) => sum + count, 0),
    };
  }

  /**
   * Close all transports and cleanup
   */
  async close() {
    // Close all SSE servers (which will close their transports)
    for (const [sessionId, { server }] of this.clients) {
      try {
        await server.close();
      } catch (error) {
        logger.debug(`Error closing SSE server ${sessionId}: ${error.message}`);
      }
    }

    // Close all Streamable HTTP servers
    for (const [sessionId, { server }] of this.streamableClients) {
      try {
        await server.close();
      } catch (error) {
        logger.debug(`Error closing Streamable HTTP server ${sessionId}: ${error.message}`);
      }
    }

    this.clients.clear();
    this.streamableClients.clear();

    // Clear all registered capabilities
    Object.values(this.registeredCapabilities).forEach(map => map.clear());

    logger.info('MCP server endpoint closed');
  }
}

