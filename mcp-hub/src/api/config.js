/**
 * 配置管理 API
 * 处理 WAF1/WAF2/系统配置的读写
 */

import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

// ==================== 配置管理 ====================

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// 配置文件路径: 优先环境变量，否则使用相对于项目根目录的路径
const CONFIG_FILE = process.env.GUARDRAILS_CONFIG ||
  path.resolve(__dirname, "../../../config/guardrails-config.json");

// .env 文件路径 (项目根目录)
const ENV_FILE = path.resolve(__dirname, "../../../.env");

// WAF2 URL: Docker 环境用 waf2，本地用 localhost:8081
const WAF2_URL = process.env.WAF2_URL || 'http://localhost:8081';

/**
 * 从 .env 文件加载环境变量 (不引入 dotenv 依赖)
 * 支持 KEY=VALUE, KEY="VALUE", KEY='VALUE' 格式
 * 忽略注释行和空行, 支持行内注释 (# 开头)
 */
function loadDotEnv() {
  try {
    if (!fs.existsSync(ENV_FILE)) {
      console.error("[dotenv] .env file not found at:", ENV_FILE);
      return;
    }
    const data = fs.readFileSync(ENV_FILE, 'utf-8');
    let count = 0;
    for (const line of data.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;
      const m = trimmed.match(/^(\w+)\s*=\s*(.*)$/);
      if (!m) continue;
      const key = m[1];
      let value = m[2].trim();
      if (value.startsWith('"')) {
        const end = value.indexOf('"', 1);
        value = end !== -1 ? value.slice(1, end) : value.slice(1);
      } else if (value.startsWith("'")) {
        const end = value.indexOf("'", 1);
        value = end !== -1 ? value.slice(1, end) : value.slice(1);
      } else {
        const hashIdx = value.indexOf('#');
        if (hashIdx !== -1 && value[hashIdx - 1] === ' ') {
          value = value.slice(0, hashIdx).trim();
        }
      }
      if (!(key in process.env)) {
        process.env[key] = value;
        count++;
      }
    }
    console.error(`[dotenv] Loaded ${count} variables from .env`);
  } catch (e) {
    console.error('[dotenv] Failed to load .env:', e.message);
  }
}

// 默认配置
const defaultConfig = {
  mode: 'full',  // 'full' | 'lite'
  waf1: {
    enabled: true,
    rules: {
      sqlInjection: true,
      commandInjection: true,
      xss: true,
      pathTraversal: true,
      sensitiveFiles: true
    }
  },
  waf2: {
    enabled: true,
    upstream: 'http://localhost:3000',
    llm: {
      provider: 'qwen',
      model: 'qwen-turbo',
      baseUrl: 'https://[YOUR WORKPLACE ID].cn-beijing.maas.aliyuncs.com/compatible-mode/v1',
      apiKey: '',
      timeout: 30000
    },
    features: {
      requestAnalysis: true,
      responseAnalysis: true,
      cache: true
    }
  },
  mcpHub: {
    port: 4000,
    url: 'http://localhost:4000'
  }
};

// 深度合并对象
function deepMerge(target, source) {
  const result = { ...target };
  for (const key of Object.keys(source)) {
    if (source[key] && typeof source[key] === 'object' && !Array.isArray(source[key])) {
      result[key] = deepMerge(result[key] || {}, source[key]);
    } else {
      result[key] = source[key];
    }
  }
  return result;
}

// 加载配置 (优先级: .env 文件 > 环境变量 > 配置文件 > 默认值)
export function loadGuardrailsConfig() {
  // 0. 先从 .env 文件加载环境变量到 process.env
  loadDotEnv();

  let config = { ...defaultConfig };

  // 1. 先从配置文件加载
  try {
    if (fs.existsSync(CONFIG_FILE)) {
      const data = fs.readFileSync(CONFIG_FILE, 'utf-8');
      const fileConfig = JSON.parse(data);
      config = deepMerge(config, fileConfig);
    }
  } catch (e) {
    console.error('[Config] 加载配置文件失败:', e.message);
  }

  // 2. 环境变量覆盖 (最高优先级)
  if (process.env.TARGET_URL) {
    config.waf2.upstream = process.env.TARGET_URL;
  }
  if (process.env.QWEN_API_KEY) {
    config.waf2.llm.apiKey = process.env.QWEN_API_KEY;
    if (!config.demo) config.demo = {};
    if (!config.demo.llmApiKey) config.demo.llmApiKey = process.env.QWEN_API_KEY;
  }
  if (process.env.LLM_MODEL) {
    config.waf2.llm.model = process.env.LLM_MODEL;
    if (config.demo && !config.demo.agentModel) config.demo.agentModel = process.env.LLM_MODEL;
  }
  if (process.env.LLM_BASE_URL) {
    config.waf2.llm.baseUrl = process.env.LLM_BASE_URL;
    if (!config.demo) config.demo = {};
    config.demo.llmBaseUrl = process.env.LLM_BASE_URL;
  }

  // Startup diagnostics (console.error = always visible)
  const key = config.waf2?.llm?.apiKey || "";
  console.error("===== GUARDRAILS_CONFIG =====");
  console.error("  waf2.upstream:", config.waf2?.upstream);
  console.error("  waf2.llm.model:", config.waf2?.llm?.model);
  console.error("  waf2.llm.baseUrl:", config.waf2?.llm?.baseUrl);
  console.error("  waf2.llm.apiKey:", key ? key.slice(0, 7) + "..." : "EMPTY");
  console.error("  demo.llmApiKey:", config.demo?.llmApiKey ? config.demo.llmApiKey.slice(0, 7) + "..." : "EMPTY");
  console.error("  demo.llmBaseUrl:", config.demo?.llmBaseUrl || "(from waf2)");
  console.error("  process.env.QWEN_API_KEY:", process.env.QWEN_API_KEY ? "SET" : "UNSET");
  console.error("================================");

  return config;
}

// 保存配置
export function saveGuardrailsConfig(config) {
  try {
    fs.writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2));
    return true;
  } catch (e) {
    console.error('[Config] 保存配置失败:', e.message);
    return false;
  }
}

// 同步配置到 WAF2 (带重试)
export async function syncToWaf2(waf2Config, retries = 2) {
  const payload = {
    enabled: waf2Config.enabled,
    upstream: waf2Config.upstream,
    api_key: waf2Config.llm?.apiKey,
    model: waf2Config.llm?.model,
    base_url: waf2Config.llm?.baseUrl,
    request_analysis: waf2Config.features?.requestAnalysis,
    response_analysis: waf2Config.features?.responseAnalysis,
    cache_enabled: waf2Config.features?.cache
  };

  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const response = await fetch(`${WAF2_URL}/waf2/config`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      if (response.ok) {
        const result = await response.json();
        console.log('[Config] WAF2 配置已同步:', result.message || 'success');
        return { success: true, message: result.message };
      } else {
        const errorText = await response.text();
        console.error(`[Config] WAF2 同步失败 (${response.status}):`, errorText);
        if (attempt === retries) {
          return { success: false, error: `HTTP ${response.status}: ${errorText}` };
        }
      }
    } catch (e) {
      console.error(`[Config] WAF2 同步错误 (尝试 ${attempt + 1}/${retries + 1}):`, e.message);
      if (attempt === retries) {
        return { success: false, error: e.message };
      }
      // 等待后重试
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
  }
  return { success: false, error: '同步超时' };
}

/**
 * 注册配置管理 API 路由
 */
export function registerConfigRoutes(app, getConfig, setConfig, applyWaf1Config, updateWaf1Config, isWaf1Enabled) {
  // 获取当前配置
  app.get("/api/config", (req, res) => {
    const config = getConfig();
    // 隐藏敏感信息
    const safeConfig = {
      ...config,
      waf2: {
        ...config.waf2,
        llm: {
          ...config.waf2.llm,
          apiKey: config.waf2.llm.apiKey ? '***已配置***' : ''
        }
      }
    };
    res.json(safeConfig);
  });

  // 获取配置状态
  app.get("/api/config/status", (req, res) => {
    const config = getConfig();
    res.json({
      mode: config.mode,
      waf1Enabled: config.mode === 'full' && config.waf1.enabled,
      waf2Enabled: config.waf2.enabled,
      waf1Running: isWaf1Enabled(),
      hasApiKey: !!config.waf2.llm.apiKey
    });
  });

  // 切换防护模式
  app.post("/api/config/mode", (req, res) => {
    const { mode } = req.body;
    if (!['full', 'lite'].includes(mode)) {
      return res.status(400).json({ error: '无效的模式，可选: full, lite' });
    }

    const config = getConfig();
    config.mode = mode;
    setConfig(config);
    saveGuardrailsConfig(config);
    applyWaf1Config();

    res.json({
      success: true,
      mode: config.mode,
      waf1Enabled: isWaf1Enabled(),
      message: `已切换到${mode === 'full' ? '完整防护' : '轻量防护'}模式`
    });
  });

  // 更新 WAF1 配置
  app.post("/api/config/waf1", (req, res) => {
    const { enabled, rules, callChainEnabled, dynamicPolicyEnabled, rbacArgsEnabled } = req.body;
    const config = getConfig();

    if (typeof enabled === 'boolean') {
      config.waf1.enabled = enabled;
    }
    if (rules && typeof rules === 'object') {
      config.waf1.rules = { ...config.waf1.rules, ...rules };
    }
    if (callChainEnabled !== undefined) {
      config.waf1.callChainEnabled = !!callChainEnabled;
    }
    if (dynamicPolicyEnabled !== undefined) {
      config.waf1.dynamicPolicyEnabled = !!dynamicPolicyEnabled;
    }
    if (rbacArgsEnabled !== undefined) {
      config.waf1.rbacArgsEnabled = !!rbacArgsEnabled;
    }

    setConfig(config);
    saveGuardrailsConfig(config);
    applyWaf1Config();

    // 同步规则到 WAF1 运行时
    updateWaf1Config(config);

    res.json({
      success: true,
      waf1: config.waf1,
      waf1Running: isWaf1Enabled()
    });
  });

  // 更新 WAF2 配置
  app.post("/api/config/waf2", async (req, res) => {
    const { enabled, upstream, llm, features } = req.body;
    const config = getConfig();

    if (typeof enabled === 'boolean') {
      config.waf2.enabled = enabled;
    }
    if (upstream) {
      config.waf2.upstream = upstream;
    }
    if (llm && typeof llm === 'object') {
      if (llm.provider) config.waf2.llm.provider = llm.provider;
      if (llm.model) config.waf2.llm.model = llm.model;
      if (llm.apiKey) config.waf2.llm.apiKey = llm.apiKey;
      if (llm.timeout) config.waf2.llm.timeout = llm.timeout;
    }
    if (features && typeof features === 'object') {
      config.waf2.features = { ...config.waf2.features, ...features };
    }

    setConfig(config);
    saveGuardrailsConfig(config);

    // 同步到 WAF2 容器
    const syncResult = await syncToWaf2(config.waf2);

    res.json({
      success: true,
      synced: syncResult.success,
      syncError: syncResult.error,
      waf2: {
        ...config.waf2,
        llm: {
          ...config.waf2.llm,
          apiKey: config.waf2.llm.apiKey ? '***已配置***' : ''
        }
      }
    });
  });

  // 完整配置更新
  app.post("/api/config", async (req, res) => {
    const { mode, waf1, waf2 } = req.body;
    const config = getConfig();

    if (mode && ['full', 'lite'].includes(mode)) {
      config.mode = mode;
    }
    if (waf1 && typeof waf1 === 'object') {
      config.waf1 = { ...config.waf1, ...waf1 };
    }
    if (waf2 && typeof waf2 === 'object') {
      if (waf2.enabled !== undefined) config.waf2.enabled = waf2.enabled;
      if (waf2.upstream) config.waf2.upstream = waf2.upstream;
      if (waf2.llm) {
        config.waf2.llm = { ...config.waf2.llm, ...waf2.llm };
      }
      if (waf2.features) {
        config.waf2.features = { ...config.waf2.features, ...waf2.features };
      }
    }

    setConfig(config);
    saveGuardrailsConfig(config);
    applyWaf1Config();

    // 同步到 WAF2 容器
    const syncResult = await syncToWaf2(config.waf2);

    res.json({
      success: true,
      synced: syncResult.success,
      syncError: syncResult.error,
      config: {
        ...config,
        waf2: {
          ...config.waf2,
          llm: {
            ...config.waf2.llm,
            apiKey: config.waf2.llm.apiKey ? '***已配置***' : ''
          }
        }
      }
    });
  });
}

export { defaultConfig, CONFIG_FILE, WAF2_URL };
