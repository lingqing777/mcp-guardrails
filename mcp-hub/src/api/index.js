/**
 * API 路由导出
 */

export { registerConfigRoutes, loadGuardrailsConfig, saveGuardrailsConfig, syncToWaf2 } from './config.js';
export { registerWaf1Routes } from './waf1-routes.js';
export { registerServerRoutes, registerToolsCallRoute } from './servers.js';
export { registerOAuthRoutes } from './oauth.js';
export {
  registerHealthRoute,
  registerSSERoute,
  registerMCPEndpointRoutes,
  registerMarketplaceRoutes,
  registerWorkspacesRoute,
  registerRestartRoutes
} from './core.js';
export { registerMcpConfigRoutes } from './mcp-config.js';
export { registerDemoRoutes } from './demo.js';
