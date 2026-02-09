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
import { RateLimiter } from './rate-limit.js';
import { RBACController } from './rbac.js';
import { StatsCollector } from './stats.js';

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

// ==================== 检测管线 ====================

function runDetectors(tool, args) {
  const argsStr = JSON.stringify(args);
  const results = [];

  // 1. Secrets 检测
  const secretMatches = detectSecrets(argsStr, cache);
  if (secretMatches.length > 0) {
    stats.recordBlock('detector', 'secrets');
    results.push({
      detector: 'secrets',
      allowed: false,
      reason: `检测到凭证泄露: ${secretMatches.map(m => m.type).join(', ')}`,
      matches: secretMatches,
    });
  }

  // 2. PII 检测
  const piiMatches = detectPII(argsStr, cache);
  if (piiMatches.length > 0) {
    stats.recordBlock('detector', 'pii');
    results.push({
      detector: 'pii',
      allowed: false,
      reason: `检测到 PII 泄露: ${piiMatches.map(m => m.type).join(', ')}`,
      matches: piiMatches,
    });
  }

  // 3. Unicode 异常检测
  const unicodeAnomalies = detectUnicodeAnomalies(argsStr, cache);
  if (unicodeAnomalies.length > 2) {
    stats.recordBlock('detector', 'unicode');
    results.push({
      detector: 'unicode',
      allowed: false,
      reason: `检测到 Unicode 异常字符 (${unicodeAnomalies.length}个): 可能的 Prompt Injection 绕过`,
      matches: unicodeAnomalies,
    });
  }

  // 4. 模糊匹配检测
  const fuzzyMatches = detectFuzzyAttacks(argsStr, cache);
  if (fuzzyMatches.length > 0) {
    stats.recordBlock('detector', 'fuzzy');
    results.push({
      detector: 'fuzzy',
      allowed: false,
      reason: `检测到混淆攻击: ${fuzzyMatches.map(m => `${m.pattern}(距离=${m.distance})`).join(', ')}`,
      matches: fuzzyMatches,
    });
  }

  // 5. 调用链检测
  const chainResult = callChainTracker.check(tool, args);
  if (chainResult.detected) {
    stats.recordBlock('detector', 'callChain');
    results.push({
      detector: 'callChain',
      allowed: false,
      reason: `检测到危险调用链 [${chainResult.chain}]: ${chainResult.desc}`,
      chain: chainResult,
    });
  }

  return results;
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

  stats.recordRequest();
  const startTime = Date.now();

  logger.info(`[WAF1] ── 检测请求: ${req.path} (${checkTarget || 'unknown'}) ──`);

  // Stage -1: 速率限制
  const clientId = req.headers['x-user-id'] || req.ip || 'unknown';
  const rateLimitResult = rateLimiter.check(clientId);
  if (!rateLimitResult.allowed) {
    stats.recordBlock('rateLimit');
    logger.warn(`[WAF1] ❌ 速率限制: ${rateLimitResult.reason}`);
    return res.status(429).json({
      error: "WAF1 拦截",
      ...rateLimitResult,
    });
  }

  // Stage 0: RBAC
  const userId = req.headers['x-user-id'] || req.body.user_id || 'anonymous';
  const rbacResult = rbacController.check(userId, checkTarget);
  if (!rbacResult.allowed) {
    stats.recordBlock('detector', 'rbac');
    logger.warn(`[WAF1] ❌ RBAC 拒绝: ${rbacResult.reason}`);
    return res.status(403).json({
      error: "WAF1 拦截",
      ...rbacResult,
    });
  }

  // Stage 1: 白名单
  const whitelistResult = checkWhitelist(checkTarget, config.whitelist);
  if (!whitelistResult.allowed) {
    stats.recordBlock('tool');
    logger.warn(`[WAF1] ❌ 白名单拦截: ${whitelistResult.reason}`);
    return res.status(403).json({
      error: "WAF1 拦截",
      ...whitelistResult,
    });
  }

  // Stage 2: 正则规则
  const ruleResult = checkRules(args || {}, config.rules, config.rulesEnabled);
  if (!ruleResult.allowed) {
    stats.recordBlock('rule', ruleResult.category);
    stats.addDetection({ tool: checkTarget, stage: 'rules', ...ruleResult });
    logger.warn(`[WAF1] ❌ 规则拦截: ${ruleResult.reason}`);
    return res.status(403).json({
      error: "WAF1 拦截",
      ...ruleResult,
    });
  }

  // Stage 3: 检测器
  const detectorResults = runDetectors(checkTarget, args || {});
  const blocked = detectorResults.filter(r => !r.allowed);

  if (blocked.length > 0) {
    const primary = blocked[0];
    stats.addDetection({
      tool: checkTarget,
      stage: 'detector',
      detector: primary.detector,
      reason: primary.reason,
      allDetections: blocked.map(b => ({ detector: b.detector, reason: b.reason })),
    });

    logger.warn(`[WAF1] ❌ 检测器拦截 [${primary.detector}]: ${primary.reason}`);
    blocked.slice(1).forEach(b => logger.warn(`[WAF1]    + [${b.detector}]: ${b.reason}`));

    return res.status(403).json({
      error: "WAF1 拦截",
      reason: primary.reason,
      type: "DETECTOR_BLOCKED",
      detector: primary.detector,
      allDetections: blocked.map(b => ({ detector: b.detector, reason: b.reason })),
    });
  }

  const elapsed = Date.now() - startTime;
  stats.recordPass();
  logger.info(`[WAF1] ✅ 放行: ${checkTarget} (${elapsed}ms)`);
  next();
}

export default waf1Middleware;
