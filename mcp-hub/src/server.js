/**
 * MCP Hub Server - 主入口
 * MCP Guardrails 项目的核心服务器
 */

import express from "express";
import cors from "cors";
import path from "path";
import { fileURLToPath } from "url";
import logger from "./utils/logger.js";
import {
  router,
  generateStartupMessage,
} from "./utils/router.js";
import {
  ValidationError,
  ServerError,
  isMCPHubError,
  wrapError,
} from "./utils/errors.js";
import { MCPServerEndpoint } from "./mcp/server.js";
import { HubState } from "./utils/sse-manager.js";

// Services
import { ServiceManager } from "./services/service-manager.js";

// API Routes
import {
  registerConfigRoutes,
  loadGuardrailsConfig,
  saveGuardrailsConfig,
  registerWaf1Routes,
  registerServerRoutes,
  registerToolsCallRoute,
  registerOAuthRoutes,
  registerHealthRoute,
  registerSSERoute,
  registerMCPEndpointRoutes,
  registerMarketplaceRoutes,
  registerWorkspacesRoute,
  registerRestartRoutes,
} from "./api/index.js";

// WAF1 中间件
import {
  waf1Middleware,
  setWaf1Enabled,
  isWaf1Enabled,
  updateWaf1Config
} from "./waf1/index.js";

// ==================== 全局状态 ====================

let serviceManager = null;
let guardrailsConfig = loadGuardrailsConfig();

// ==================== 配置辅助函数 ====================

function getConfig() {
  return guardrailsConfig;
}

function setConfig(config) {
  guardrailsConfig = config;
}

function applyWaf1Config() {
  const shouldEnable = guardrailsConfig.mode === 'full' && guardrailsConfig.waf1.enabled;
  setWaf1Enabled(shouldEnable);
  console.log(`[Config] WAF1 ${shouldEnable ? '已启用' : '已禁用'} (模式: ${guardrailsConfig.mode})`);
}

function getServiceManager() {
  return serviceManager;
}

// 初始化时应用配置
applyWaf1Config();

// ==================== Express App ====================

// 获取当前文件目录 (ES Module 兼容)
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(cors());
app.use(express.json());

// Dashboard 静态文件服务 (支持 Docker 和本地开发)
// Docker: /app/src/dashboard/
// Local: ./dashboard/
const dockerDashboardPath = '/app/src/dashboard';
const localDashboardPath = path.join(__dirname, 'dashboard');

// 静态文件中间件 (CSS, JS)
app.use('/dashboard', express.static(dockerDashboardPath, { fallthrough: true }));
app.use('/dashboard', express.static(localDashboardPath));

// Dashboard 主页
app.get('/', (req, res) => {
  // 优先尝试新的模块化 dashboard
  const dockerIndexPath = path.join(dockerDashboardPath, 'index.html');
  const localIndexPath = path.join(localDashboardPath, 'index.html');
  // 兼容旧的单文件 dashboard
  const dockerLegacyPath = '/app/src/dashboard.html';
  const localLegacyPath = path.join(__dirname, 'dashboard.html');

  res.sendFile(dockerIndexPath, (err) => {
    if (err) {
      res.sendFile(localIndexPath, (err2) => {
        if (err2) {
          // 回退到旧版单文件 dashboard
          res.sendFile(dockerLegacyPath, (err3) => {
            if (err3) {
              res.sendFile(localLegacyPath);
            }
          });
        }
      });
    }
  });
});

// ==================== 注册 API 路由 ====================

// 配置管理 API
registerConfigRoutes(app, getConfig, setConfig, applyWaf1Config, updateWaf1Config, isWaf1Enabled);

// WAF1 仪表盘 API (在 waf1Middleware 之前，避免被拦截)
registerWaf1Routes(app, getConfig, setConfig, saveGuardrailsConfig, applyWaf1Config);

// WAF1 中间件 (在 WAF1 API 之后，其他路由之前)
app.use("/api", waf1Middleware);

// Dashboard 工具测试 API
registerToolsCallRoute(app, getServiceManager);

// 挂载路由器
app.use("/api", router);

// ==================== 注册 Router 路由 ====================

// 核心路由
registerHealthRoute(getServiceManager);
registerSSERoute(getServiceManager);
registerMCPEndpointRoutes(app, getServiceManager);
registerMarketplaceRoutes(getServiceManager);
registerWorkspacesRoute(getServiceManager);
registerRestartRoutes(getServiceManager);

// MCP 服务器管理路由
registerServerRoutes(getServiceManager);

// OAuth 路由
registerOAuthRoutes(getServiceManager);

// ==================== 错误处理 ====================

function getStatusCode(error) {
  if (error instanceof ValidationError) return 400;
  if (error instanceof ServerError) return 500;
  if (error.code === "SERVER_NOT_FOUND") return 404;
  if (error.code === "SERVER_NOT_CONNECTED") return 503;
  if (error.code === "TOOL_NOT_FOUND" || error.code === "RESOURCE_NOT_FOUND") return 404;
  return 500;
}

router.use((err, req, res, next) => {
  const error = isMCPHubError(err)
    ? err
    : wrapError(err, "REQUEST_ERROR", {
      path: req.path,
      method: req.method,
    });

  if (!res.headersSent) {
    res.status(getStatusCode(error)).json({
      error: error.message,
      code: error.code,
      data: error.data,
      timestamp: new Date().toISOString(),
    });
  }
});

// ==================== 服务器启动 ====================

export async function startServer(options = {}) {
  serviceManager = new ServiceManager(options);

  try {
    serviceManager.setupSignalHandlers();

    // Start HTTP server first to fail fast on port conflicts
    await serviceManager.startServer(app);

    // Then initialize MCP Hub
    await serviceManager.initializeMCPHub(MCPServerEndpoint);
  } catch (error) {
    const wrappedError = wrapError(error, error.code || "SERVER_START_ERROR");
    try {
      serviceManager.setState(HubState.ERROR, {
        message: wrappedError.message,
        code: wrappedError.code,
        data: wrappedError.data,
      });
      await serviceManager.shutdown();
    } catch (e) {
      // Ignore shutdown errors
    } finally {
      logger.error(
        wrappedError.code,
        wrappedError.message,
        wrappedError.data,
        true,
        1
      );
    }
  }
}

export default app;
