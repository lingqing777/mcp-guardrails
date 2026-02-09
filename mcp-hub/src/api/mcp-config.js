/**
 * MCP Server 配置管理 API
 * 用于在 Dashboard 中添加、编辑、删除 MCP Server
 */

import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// MCP Server 配置文件路径
const MCP_CONFIG_PATH = process.env.MCP_CONFIG_PATH ||
  path.resolve(__dirname, "../../../config/mcp-servers.json");

/**
 * 加载 MCP Server 配置
 */
function loadMcpConfig() {
  try {
    if (fs.existsSync(MCP_CONFIG_PATH)) {
      const content = fs.readFileSync(MCP_CONFIG_PATH, "utf-8");
      return JSON.parse(content);
    }
    return { mcpServers: {} };
  } catch (e) {
    console.error("[MCP Config] 加载配置失败:", e.message);
    return { mcpServers: {} };
  }
}

/**
 * 保存 MCP Server 配置
 */
function saveMcpConfig(config) {
  try {
    // 确保目录存在
    const dir = path.dirname(MCP_CONFIG_PATH);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(MCP_CONFIG_PATH, JSON.stringify(config, null, 2));
    console.log("[MCP Config] 配置已保存到:", MCP_CONFIG_PATH);
    return true;
  } catch (e) {
    console.error("[MCP Config] 保存配置失败:", e.message);
    return false;
  }
}

/**
 * 验证 MCP Server 配置
 */
function validateServerConfig(serverConfig) {
  const errors = [];

  // 检查是 stdio 还是 sse 类型
  const hasCommand = !!serverConfig.command;
  const hasUrl = !!serverConfig.url;

  if (!hasCommand && !hasUrl) {
    errors.push("必须提供 command (stdio) 或 url (sse)");
  }

  if (hasCommand && hasUrl) {
    errors.push("不能同时提供 command 和 url");
  }

  // stdio 类型验证
  if (hasCommand) {
    if (typeof serverConfig.command !== "string") {
      errors.push("command 必须是字符串");
    }
    if (serverConfig.args && !Array.isArray(serverConfig.args)) {
      errors.push("args 必须是数组");
    }
    if (serverConfig.env && typeof serverConfig.env !== "object") {
      errors.push("env 必须是对象");
    }
  }

  // sse 类型验证
  if (hasUrl) {
    try {
      new URL(serverConfig.url);
    } catch (e) {
      errors.push("url 格式无效");
    }
    if (serverConfig.headers && typeof serverConfig.headers !== "object") {
      errors.push("headers 必须是对象");
    }
  }

  return errors;
}

/**
 * 注册 MCP Server 配置管理 API
 */
export function registerMcpConfigRoutes(app) {
  // 获取所有 MCP Server 配置
  app.get("/api/mcp-config/servers", (req, res) => {
    const config = loadMcpConfig();
    const servers = Object.entries(config.mcpServers || {}).map(([name, cfg]) => ({
      name,
      ...cfg,
      type: cfg.command ? "stdio" : "sse"
    }));
    res.json({
      success: true,
      servers,
      configPath: MCP_CONFIG_PATH
    });
  });

  // 获取单个 MCP Server 配置
  app.get("/api/mcp-config/servers/:name", (req, res) => {
    const { name } = req.params;
    const config = loadMcpConfig();
    const serverConfig = config.mcpServers?.[name];

    if (!serverConfig) {
      return res.status(404).json({
        success: false,
        error: `Server '${name}' 不存在`
      });
    }

    res.json({
      success: true,
      server: {
        name,
        ...serverConfig,
        type: serverConfig.command ? "stdio" : "sse"
      }
    });
  });

  // 添加新的 MCP Server
  app.post("/api/mcp-config/servers", (req, res) => {
    const { name, ...serverConfig } = req.body;

    if (!name) {
      return res.status(400).json({
        success: false,
        error: "缺少 server name"
      });
    }

    // 验证配置
    const errors = validateServerConfig(serverConfig);
    if (errors.length > 0) {
      return res.status(400).json({
        success: false,
        error: "配置验证失败",
        details: errors
      });
    }

    const config = loadMcpConfig();

    // 检查是否已存在
    if (config.mcpServers?.[name]) {
      return res.status(409).json({
        success: false,
        error: `Server '${name}' 已存在`
      });
    }

    // 添加新服务器
    if (!config.mcpServers) {
      config.mcpServers = {};
    }
    config.mcpServers[name] = serverConfig;

    // 保存配置
    if (!saveMcpConfig(config)) {
      return res.status(500).json({
        success: false,
        error: "保存配置失败"
      });
    }

    res.json({
      success: true,
      message: `Server '${name}' 已添加`,
      server: { name, ...serverConfig }
    });
  });

  // 更新 MCP Server 配置
  app.put("/api/mcp-config/servers/:name", (req, res) => {
    const { name } = req.params;
    const serverConfig = req.body;

    // 验证配置
    const errors = validateServerConfig(serverConfig);
    if (errors.length > 0) {
      return res.status(400).json({
        success: false,
        error: "配置验证失败",
        details: errors
      });
    }

    const config = loadMcpConfig();

    // 检查是否存在
    if (!config.mcpServers?.[name]) {
      return res.status(404).json({
        success: false,
        error: `Server '${name}' 不存在`
      });
    }

    // 更新配置
    config.mcpServers[name] = serverConfig;

    // 保存配置
    if (!saveMcpConfig(config)) {
      return res.status(500).json({
        success: false,
        error: "保存配置失败"
      });
    }

    res.json({
      success: true,
      message: `Server '${name}' 已更新`,
      server: { name, ...serverConfig }
    });
  });

  // 删除 MCP Server
  app.delete("/api/mcp-config/servers/:name", (req, res) => {
    const { name } = req.params;
    const config = loadMcpConfig();

    // 检查是否存在
    if (!config.mcpServers?.[name]) {
      return res.status(404).json({
        success: false,
        error: `Server '${name}' 不存在`
      });
    }

    // 删除服务器
    delete config.mcpServers[name];

    // 保存配置
    if (!saveMcpConfig(config)) {
      return res.status(500).json({
        success: false,
        error: "保存配置失败"
      });
    }

    res.json({
      success: true,
      message: `Server '${name}' 已删除`
    });
  });

  // 批量导入 MCP Server 配置
  app.post("/api/mcp-config/import", (req, res) => {
    const { servers, merge = true } = req.body;

    if (!servers || typeof servers !== "object") {
      return res.status(400).json({
        success: false,
        error: "无效的配置格式"
      });
    }

    // 验证所有服务器配置
    const validationErrors = {};
    for (const [name, cfg] of Object.entries(servers)) {
      const errors = validateServerConfig(cfg);
      if (errors.length > 0) {
        validationErrors[name] = errors;
      }
    }

    if (Object.keys(validationErrors).length > 0) {
      return res.status(400).json({
        success: false,
        error: "部分配置验证失败",
        details: validationErrors
      });
    }

    const config = loadMcpConfig();

    if (merge) {
      // 合并模式：保留现有配置
      config.mcpServers = { ...config.mcpServers, ...servers };
    } else {
      // 覆盖模式：替换所有配置
      config.mcpServers = servers;
    }

    // 保存配置
    if (!saveMcpConfig(config)) {
      return res.status(500).json({
        success: false,
        error: "保存配置失败"
      });
    }

    res.json({
      success: true,
      message: `已导入 ${Object.keys(servers).length} 个 Server`,
      count: Object.keys(servers).length
    });
  });

  // 导出 MCP Server 配置
  app.get("/api/mcp-config/export", (req, res) => {
    const config = loadMcpConfig();
    res.json(config);
  });

  console.log("[MCP Config] API 路由已注册");
  console.log("[MCP Config] 配置文件路径:", MCP_CONFIG_PATH);
}

export { loadMcpConfig, saveMcpConfig, validateServerConfig, MCP_CONFIG_PATH };
