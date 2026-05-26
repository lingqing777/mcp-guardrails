/**
 * WAF1 - MCP Guardrails
 * MCP 协议层静态检测
 *
 * 参考:
 *   - MCP-Guard 论文 (arxiv:2508.10991)
 *   - Invariant Guardrails (https://github.com/invariantlabs-ai/invariant)
 *
 * 模块:
 *   - detectors/secrets.js  - 凭证泄露检测
 *   - detectors/pii.js      - PII 检测
 *   - detectors/unicode.js  - Unicode 异常检测
 *   - detectors/fuzzy.js    - 模糊匹配检测
 *   - rules.js              - 正则规则引擎
 *   - call-chain.js         - 调用链追踪
 *   - rate-limit.js         - 速率限制
 *   - rbac.js               - RBAC 访问控制
 *   - stats.js              - 统计与仪表盘
 */

import logger from '../utils/logger.js';
import { detectSecrets, detectPII, detectUnicodeAnomalies, detectFuzzyAttacks } from './detectors/index.js';
import { checkRules, checkWhitelist, RULES, DEFAULT_RULES_ENABLED } from './rules.js';
import { CallChainTracker } from './call-chain.js';
import { checkDynamicPolicy } from './dynamic-policy.js';
import { RateLimiter } from './rate-limit.js';
import { RBACController, detectArgsRoleClaimTampering } from './rbac.js';
import { StatsCollector } from './stats.js';
import { extractArgValues } from './utils.js';

// ==================== 缓存 ====================

class DetectorCache {
  constructor(maxSize = 1000, ttlMs = 60000) {
    this.cache = new Map();
    this.maxSize = maxSize;
    this.ttlMs = ttlMs;
  }

  get(key) {
    const entry = this.cache.get(key);
    if (!entry) return undefined;
    if (Date.now() - entry.ts > this.ttlMs) {
      this.cache.delete(key);
      return undefined;
    }
    return entry.value;
  }

  set(key, value) {
    if (this.cache.size >= this.maxSize) {
      const firstKey = this.cache.keys().next().value;
      this.cache.delete(firstKey);
    }
    this.cache.set(key, { value, ts: Date.now() });
  }
}

// ==================== 全局实例 ====================

const cache = new DetectorCache();
const stats = new StatsCollector();
const callChainTracker = new CallChainTracker();
const rateLimiter = new RateLimiter();
const rbacController = new RBACController();

// WAF1 开关
let waf1Enabled = true;

// 配置
let config = {
  enabled: true,
  whitelist: ["*"],
  rules: RULES,
  rulesEnabled: { ...DEFAULT_RULES_ENABLED },
  callChainEnabled: true,
  dynamicPolicyEnabled: true,
  rbacArgsEnabled: true,
};

// ==================== 导出 API ====================

export function setWaf1Enabled(enabled) {
  waf1Enabled = enabled;
  logger.info(`[WAF1] 状态切换: ${enabled ? '启用' : '禁用'}`);
}

export function isWaf1Enabled() {
  return waf1Enabled;
}

export function updateWaf1Config(newConfig) {
  if (newConfig && newConfig.waf1) {
    // 处理规则开关映射
    if (newConfig.waf1.rules) {
      const ruleMapping = {
        sqlInjection: 'sqlInjection',
        commandInjection: 'shellInjection',
        xss: 'xss',
        pathTraversal: 'pathTraversal',
        sensitiveFiles: 'sensitiveFiles'
      };

      for (const [dashboardRule, internalRule] of Object.entries(ruleMapping)) {
        if (newConfig.waf1.rules[dashboardRule] !== undefined) {
          config.rulesEnabled[internalRule] = newConfig.waf1.rules[dashboardRule];
        }
      }
    }

    if (newConfig.waf1.enabled !== undefined) {
      config.enabled = newConfig.waf1.enabled;
    }

    if (newConfig.waf1.callChainEnabled !== undefined) {
      config.callChainEnabled = !!newConfig.waf1.callChainEnabled;
    }
    if (newConfig.waf1.dynamicPolicyEnabled !== undefined) {
      config.dynamicPolicyEnabled = !!newConfig.waf1.dynamicPolicyEnabled;
    }
    if (newConfig.waf1.rbacArgsEnabled !== undefined) {
      config.rbacArgsEnabled = !!newConfig.waf1.rbacArgsEnabled;
    }

    logger.info("[WAF1] 配置已更新, rulesEnabled:", config.rulesEnabled);
  }
}

export function updateRBACConfig(newConfig) {
  if (newConfig && newConfig.rbac) {
    rbacController.updateConfig(newConfig.rbac);
  }
}

export function updateRateLimitConfig(newConfig) {
  if (newConfig && newConfig.rateLimit) {
    rateLimiter.updateConfig(newConfig.rateLimit);
  }
}

export function getWaf1Stats() {
  return {
    ...stats.getStats(),
    cacheSize: cache.cache.size,
  };
}

export function getDashboardData() {
  return stats.getDashboardData(rateLimiter, cache.cache.size);
}

export function getTimeSeriesData(intervalMs, periods) {
  return stats.getTimeSeriesData(intervalMs, periods);
}

export function getCallHistory() {
  return callChainTracker.getHistory(20);
}

export function resetStats() {
  stats.reset();
}

export function resetWaf1State() {
  stats.reset();
  cache.cache.clear();
  callChainTracker.clear();
  rateLimiter.store.clear();
}

// ==================== 检测管线 ====================

/**
 * PII 检测器在合法收件人/客户邮箱字段上的工具感知白名单。
 * 这些工具的命名字段本身就是邮箱(发邮件、注册客户等),不该当 PII 泄露拦截。
 * 字段名是 args 顶层 key;嵌套字段当前不支持(M-Bench-Core 工具都是平 schema)。
 */
const PII_FIELD_WHITELIST = {
  'mail__send':                    ['to', 'from', 'cc', 'bcc', 'reply_to'],
  'mail__forward':                 ['to', 'from', 'cc', 'bcc'],
  'notification__send':            ['to', 'recipient', 'recipients'],
  'woocommerce__create_customer':  ['email'],
  'woocommerce__update_customer':  ['email'],
};

function applyPIIWhitelist(tool, args) {
  if (!args || typeof args !== 'object' || Array.isArray(args)) return args;
  const skip = PII_FIELD_WHITELIST[tool];
  if (!skip || skip.length === 0) return args;
  const clone = { ...args };
  for (const f of skip) delete clone[f];
  return clone;
}

function runDetectors(tool, args, chainResult = { detected: false }) {
  // 输入剥离:fuzzy / secrets / unicode 仅扫描 args 的值,不扫描 JSON 字段名。
  // 这避免了 `<script>` (threshold=2) 误匹配 `description` 等英文 key
  // (`escripti` 与 `<script>` Levenshtein 距离恰好 = 2)。
  // PII 走单独的工具感知白名单路径(见下文)。
  const argsValuesStr = extractArgValues(args);
  const results = [];

  // 1. Secrets 检测
  const secretMatches = detectSecrets(argsValuesStr, cache);
  if (secretMatches.length > 0) {
    stats.recordBlock('detector', 'secrets');
    results.push({
      detector: 'secrets',
      category: 'secrets',
      allowed: false,
      reason: `检测到凭证泄露: ${secretMatches.map(m => m.type).join(', ')}`,
      matches: secretMatches,
    });
  }

  // 2. PII 检测(工具感知白名单 — D3 in design.md)
  const piiText = extractArgValues(applyPIIWhitelist(tool, args));
  const piiMatches = detectPII(piiText, cache);
  if (piiMatches.length > 0) {
    stats.recordBlock('detector', 'pii');
    results.push({
      detector: 'pii',
      category: 'pii',
      allowed: false,
      reason: `检测到 PII 泄露: ${piiMatches.map(m => m.type).join(', ')}`,
      matches: piiMatches,
    });
  }

  // 3. Unicode 异常检测
  const unicodeAnomalies = detectUnicodeAnomalies(argsValuesStr, cache);
  if (unicodeAnomalies.length > 2) {
    stats.recordBlock('detector', 'unicode');
    results.push({
      detector: 'unicode',
      category: 'unicode',
      allowed: false,
      reason: `检测到 Unicode 异常字符 (${unicodeAnomalies.length}个): 可能的 Prompt Injection 绕过`,
      matches: unicodeAnomalies,
    });
  }

  // 4. 模糊匹配检测
  const fuzzyMatches = detectFuzzyAttacks(argsValuesStr, cache);
  if (fuzzyMatches.length > 0) {
    stats.recordBlock('detector', 'fuzzy');
    // category 优先取 fuzzy pattern 自身的 category(如 xss),便于下游分类
    const primaryCat = (fuzzyMatches[0] && fuzzyMatches[0].category) || 'fuzzy';
    results.push({
      detector: 'fuzzy',
      category: primaryCat,
      allowed: false,
      reason: `检测到混淆攻击: ${fuzzyMatches.map(m => `${m.pattern}(距离=${m.distance})`).join(', ')}`,
      matches: fuzzyMatches,
    });
  }

  // 5. 调用链检测
  if (chainResult.detected) {
    const category = chainResult.category || 'callChain';
    stats.recordBlock('detector', category);
    results.push({
      detector: category,
      category,
      allowed: false,
      reason: `检测到危险调用链 [${chainResult.chain}]: ${chainResult.desc}`,
      chain: chainResult,
    });
  }

  return results;
}

// ==================== 协议无关检测函数 ====================

/**
 * 纯函数：对工具调用执行完整 WAF1 检测管线
 * 不依赖 Express req/res，可在 HTTP API 和 MCP 协议中共用
 *
 * @param {string} tool - 工具名 / prompt / uri
 * @param {object} args - 工具参数
 * @param {object} context - { clientId, userId }
 * @returns {{ allowed: true } | { allowed: false, status: number, error: object }}
 */
export function validateToolCall(tool, args, context = {}) {
  if (!waf1Enabled) return { allowed: true };
  if (!tool && !args) return { allowed: true };

  stats.recordRequest();
  const startTime = Date.now();
  const source = context.source || 'unknown';

  logger.info(`[WAF1] ── 检测请求: ${source} (${tool || 'unknown'}) ──`);
  const chainResult = config.callChainEnabled
    ? callChainTracker.check(tool, args || {}, context)
    : { detected: false };

  // Stage -1: 速率限制
  const clientId = context.clientId || 'unknown';
  const rateLimitResult = rateLimiter.check(clientId);
  if (!rateLimitResult.allowed) {
    stats.recordBlock('rateLimit');
    logger.warn(`[WAF1] ❌ 速率限制: ${rateLimitResult.reason}`);
    return { allowed: false, status: 429, error: { error: "WAF1 拦截", ...rateLimitResult } };
  }

  // Stage 0: RBAC
  const userId = context.userId || 'anonymous';
  const rbacResult = rbacController.check(userId, tool);
  if (!rbacResult.allowed) {
    stats.recordBlock('detector', 'rbac');
    logger.warn(`[WAF1] ❌ RBAC 拒绝: ${rbacResult.reason}`);
    return { allowed: false, status: 403, error: { error: "WAF1 拦截", ...rbacResult } };
  }

  // Stage 0.5: args role-claim tampering (always-on, independent of RBAC config)
  if (config.rbacArgsEnabled) {
    const rbacArgsResult = detectArgsRoleClaimTampering(args || {});
    if (rbacArgsResult.tampered) {
      stats.recordBlock('detector', 'rbac');
      stats.addDetection({
        tool,
        stage: 'rbac-args',
        category: 'rbac',
        detector: 'rbac',
        reason: rbacArgsResult.reason,
      });
      logger.warn(`[WAF1] ❌ RBAC args 篡改: ${rbacArgsResult.reason}`);
      return {
        allowed: false, status: 403, error: {
          error: "WAF1 拦截",
          reason: rbacArgsResult.reason,
          type: "RBAC_ARGS_TAMPER",
          category: 'rbac',
          detector: 'rbac',
          fields: rbacArgsResult.fields,
        }
      };
    }
  }

  // Stage 1: 白名单
  const whitelistResult = checkWhitelist(tool, config.whitelist);
  if (!whitelistResult.allowed) {
    stats.recordBlock('tool');
    logger.warn(`[WAF1] ❌ 白名单拦截: ${whitelistResult.reason}`);
    return { allowed: false, status: 403, error: { error: "WAF1 拦截", ...whitelistResult } };
  }

  // Stage 2: 正则规则
  const ruleResult = checkRules(args || {}, config.rules, config.rulesEnabled, { tool });
  if (!ruleResult.allowed) {
    stats.recordBlock('rule', ruleResult.category);
    stats.addDetection({ tool, stage: 'rules', ...ruleResult });
    logger.warn(`[WAF1] ❌ 规则拦截: ${ruleResult.reason}`);
    return { allowed: false, status: 403, error: { error: "WAF1 拦截", ...ruleResult } };
  }

  // Stage 3: 调用链
  if (chainResult.detected) {
    const category = chainResult.category || 'callChain';
    stats.recordBlock('detector', category);
    stats.addDetection({
      tool,
      stage: 'detector',
      category,
      detector: category,
      reason: `检测到危险调用链 [${chainResult.chain}]: ${chainResult.desc}`,
      severity: 'critical',
    });
    logger.warn(`[WAF1] ❌ 调用链拦截 [${chainResult.chain}]: ${chainResult.desc}`);
    return {
      allowed: false,
      status: 403,
      error: {
        error: "WAF1 拦截",
        reason: `检测到危险调用链 [${chainResult.chain}]: ${chainResult.desc}`,
        type: 'DETECTOR_BLOCKED',
        category,
        detector: category,
      }
    };
  }

  // Stage 4: 动态策略
  if (config.dynamicPolicyEnabled) {
    const dynamicPolicyResult = checkDynamicPolicy(tool, args || {});
    if (!dynamicPolicyResult.allowed) {
      stats.recordBlock('detector', dynamicPolicyResult.category || 'dynamicPolicy');
      stats.addDetection({
        tool,
        stage: 'dynamic-policy',
        category: dynamicPolicyResult.category || 'dynamicPolicy',
        detector: 'dynamicPolicy',
        reason: dynamicPolicyResult.reason,
        profile: dynamicPolicyResult.profile,
        statementType: dynamicPolicyResult.statementType,
        severity: dynamicPolicyResult.severity,
        direction: dynamicPolicyResult.direction,
      });
      logger.warn(
        `[WAF1] ❌ 动态策略拦截 [${dynamicPolicyResult.profile || 'dynamic-policy'}]: ${dynamicPolicyResult.reason}`
      );
      return {
        allowed: false,
        status: 403,
        error: {
          error: "WAF1 拦截",
          reason: dynamicPolicyResult.reason,
          type: dynamicPolicyResult.type || 'DYNAMIC_POLICY_BLOCKED',
          category: dynamicPolicyResult.category || 'dynamicPolicy',
          profile: dynamicPolicyResult.profile,
          direction: dynamicPolicyResult.direction,
          statementType: dynamicPolicyResult.statementType,
        }
      };
    }
  }

  // Stage 5: 检测器
  const detectorResults = runDetectors(tool, args || {}, chainResult);
  const blocked = detectorResults.filter(r => !r.allowed);

  if (blocked.length > 0) {
    const primary = blocked[0];
    stats.addDetection({
      tool,
      stage: 'detector',
      category: primary.category || primary.detector,
      detector: primary.detector,
      reason: primary.reason,
      direction: primary.direction,
      allDetections: blocked.map(b => ({ detector: b.detector, reason: b.reason })),
    });

    logger.warn(`[WAF1] ❌ 检测器拦截 [${primary.detector}]: ${primary.reason}`);
    blocked.slice(1).forEach(b => logger.warn(`[WAF1]    + [${b.detector}]: ${b.reason}`));

    return {
      allowed: false, status: 403, error: {
        error: "WAF1 拦截",
        reason: primary.reason,
        type: "DETECTOR_BLOCKED",
        category: primary.category || primary.detector,
        detector: primary.detector,
        allDetections: blocked.map(b => ({ detector: b.detector, reason: b.reason })),
      }
    };
  }

  const elapsed = Date.now() - startTime;
  stats.recordPass();
  logger.info(`[WAF1] ✅ 放行: ${tool} (${elapsed}ms)`);
  return { allowed: true };
}

// ==================== Express 中间件 ====================

export function waf1Middleware(req, res, next) {
  if (!waf1Enabled) return next();

  // 保护的路由
  const protectedRoutes = [
    { path: "/servers/tools", method: "POST" },
    { path: "/servers/prompts", method: "POST" },
    { path: "/servers/resources", method: "POST" },
    { path: "/tools/call", method: "POST" },
  ];

  const isProtectedRoute = protectedRoutes.some(
    route => req.path === route.path && req.method === route.method
  );

  if (!isProtectedRoute) return next();

  const { tool, arguments: args, prompt, uri } = req.body;
  const checkTarget = tool || prompt || uri;
  if (!checkTarget && !args) return next();

  const clientId = req.headers['x-user-id'] || req.ip || 'unknown';
  const userId = req.headers['x-user-id'] || req.body.user_id || 'anonymous';

  const result = validateToolCall(checkTarget, args, {
    clientId,
    userId,
    source: req.path,
  });

  if (!result.allowed) {
    return res.status(result.status).json(result.error);
  }

  next();
}

export default waf1Middleware;
