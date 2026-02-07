/**
 * OAuth 回调 API
 * 处理 MCP 服务器的 OAuth 授权回调
 */

import {
  registerRoute,
} from "../utils/router.js";
import {
  ValidationError,
  wrapError,
} from "../utils/errors.js";
import { SubscriptionTypes } from "../utils/sse-manager.js";
import logger from "../utils/logger.js";

/**
 * 注册 OAuth 路由
 */
export function registerOAuthRoutes(getServiceManager) {
  // 手动 OAuth 回调 (用于远程系统)
  registerRoute(
    "POST",
    "/oauth/manual_callback",
    "Handle OAuth callback for manual authorization",
    async (req, res) => {
      let code, server_name;
      const serviceManager = getServiceManager();
      try {
        const { url } = req.body || {};
        if (!url) {
          throw new ValidationError("Missing URL parameter", { field: "url" });
        }
        const url_with_code = new URL(url);
        if (url_with_code.searchParams.has('code')) {
          code = url_with_code.searchParams.get('code');
        }
        if (url_with_code.searchParams.has('server_name')) {
          server_name = url_with_code.searchParams.get('server_name');
        }
        if (!code || !server_name) {
          throw new ValidationError("Missing code or server_name parameter");
        }

        const connection = serviceManager.mcpHub.getConnection(server_name);
        await connection.handleAuthCallback(code);

        serviceManager.broadcastSubscriptionEvent(SubscriptionTypes.SERVERS_UPDATED, {
          changes: {
            modified: [server_name],
          }
        });

        return res.json({
          status: "ok",
          message: `Authorization successful for server '${server_name}'`,
          server_name,
          timestamp: new Date().toISOString(),
        });
      } catch (error) {
        throw wrapError(error, "MANUAL_OAUTH_CALLBACK_ERROR", {
          url: req.body?.url || null,
        });
      }
    }
  );

  // OAuth 回调
  registerRoute(
    "GET",
    "/oauth/callback",
    "Handle OAuth callback",
    async (req, res) => {
      const { code, server_name } = req.query;
      const serviceManager = getServiceManager();

      try {
        if (!code || !server_name) {
          throw new ValidationError("Missing code or server_name parameter");
        }

        // Send initial processing page
        res.write(`
          <html>
            <head>
              <title>MCP HUB</title>
              <style>
                body { font-family: Arial, sans-serif; text-align: center; margin-top: 50px; }
                .loader { border: 5px solid #f3f3f3; border-top: 5px solid #3498db; border-radius: 50%; width: 50px; height: 50px; animation: spin 1s linear infinite; margin: 20px auto; }
                @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
                .hidden { display: none; }
                .message { margin: 20px 0; font-size: 18px; }
              </style>
              <script>
                function updateStatus(status, message) {
                  document.getElementById('processing').style.display = status === 'processing' ? 'block' : 'none';
                  document.getElementById('success').style.display = status === 'success' ? 'block' : 'none';
                  document.getElementById('error').style.display = status === 'error' ? 'block' : 'none';
                  if (message) {
                    document.getElementById('errorMessage').textContent = message;
                  }
                }
              </script>
            </head>
            <body>
              <div id="processing">
                <h1>MCP HUB</h1>
                <h2><code>${server_name}<code> Authorization Processing</h2>
                <div class="loader"></div>
                <p class="message">Please wait while mcp-hub completes the authorization...</p>
              </div>
              <div id="success" class="hidden">
                <h1>MCP HUB</h1>
                <h2><code>${server_name}<code> Authorization Successful</h2>
                <p class="message">Your server has been authorized successfully!</p>
                <p>You can close this window and return to the application.</p>
              </div>
              <div id="error" class="hidden">
                <h1>MCP HUB</h1>
                <h2><code>${server_name}<code> Authorization Failed</h2>
                <p class="message">An error occurred during authorization:</p>
                <p id="errorMessage" style="color: red;"></p>
                <p class="message">For errors like 'fetch failed' (serverless hosting might take time to startup), stopping and starting the MCP Server should help. </p>
              </div>
            </body>
          </html>
        `);

        const connection = serviceManager.mcpHub.getConnection(server_name);
        await connection.handleAuthCallback(code);
        res.write('<script>updateStatus("success");</script>');

      } catch (error) {
        logger.error('OAUTH_CALLBACK_ERROR', `Error during OAuth callback: ${error.message}`, {}, false);
        res.write(`<script>updateStatus("error", "${error.message.replace(/"/g, '\\"')}");</script>`);
      } finally {
        serviceManager.broadcastSubscriptionEvent(SubscriptionTypes.SERVERS_UPDATED, {
          changes: {
            modified: [server_name],
          }
        });
        res.end();
      }
    }
  );
}
