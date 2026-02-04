/**
 * WAF1 - MCP Guardrails
 * MCP 协议层静态检测
 * 参考:
 *   - MCP-Guard 论文 (arxiv:2508.10991)
 *   - Invariant Guardrails (https://github.com/invariantlabs-ai/invariant)
 *
 * 架构: 借鉴 Invariant 的模块化检测器设计
 *   1. 正则规则引擎 (MCP-Guard Stage 1)
 *   2. Secrets 检测器 (移植自 Invariant runtime/utils/secrets.py)
 *   3. PII 检测器 (移植自 Invariant stdlib/detectors/pii.py)
 *   4. Unicode 异常检测 (移植自 Invariant runtime/utils/prompt_injections.py UnicodeDetector)
 *   5. 调用链追踪 (简化版 Invariant Dataflow)
 */

// ==================== 缓存机制 (移植自 Invariant @cached) ====================

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
      // 淘汰最早的
      const firstKey = this.cache.keys().next().value;
      this.cache.delete(firstKey);
    }
    this.cache.set(key, { value, ts: Date.now() });
  }
}

const globalCache = new DetectorCache();

// ==================== Secrets 检测器 (移植自 Invariant) ====================
// 来源: invariant/analyzer/runtime/utils/secrets.py
// 原始来源: Yelp detect-secrets 项目

const SECRETS_PATTERNS = {
  // GitHub Tokens (完整版，来自 Invariant)
  github_personal_token:  /ghp_[A-Za-z0-9_]{36}/,
  github_oauth_token:     /gho_[A-Za-z0-9_]{36}/,
  github_user_token:      /ghu_[A-Za-z0-9_]{36}/,
  github_server_token:    /ghs_[A-Za-z0-9_]{36}/,
  github_refresh_token:   /ghr_[A-Za-z0-9_]{36}/,
  github_fine_grained:    /github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}/,

  // AWS (完整版，来自 Invariant secrets.py)
  aws_access_key:         /(?:A3T[A-Z0-9]|ABIA|ACCA|AKIA|ASIA)[0-9A-Z]{16}/,
  aws_secret_key:         /(?:aws).{0,20}(?:secret|key|pwd|pass|token).{0,20}['"][0-9a-zA-Z\/+=]{40}['"]/i,
  aws_session_token:      /(?:aws).{0,20}(?:session).{0,20}['"][0-9a-zA-Z\/+=]{100,}['"]/i,

  // OpenAI
  openai_api_key:         /sk-[a-zA-Z0-9]{48}/,
  openai_project_key:     /sk-proj-[a-zA-Z0-9\-_]{80,}/,

  // GitLab
  gitlab_token:           /glpat-[a-zA-Z0-9\-_]{20,}/,
  gitlab_runner_token:    /GR1348941[a-zA-Z0-9\-_]{20,}/,

  // Slack (完整版，来自 Invariant secrets.py)
  slack_token:            /xox[abpors]-(?:\d+-)+[a-z0-9]+/i,
  slack_webhook:          /https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]+\/B[a-zA-Z0-9_]+\/[a-zA-Z0-9_]+/,

  // Azure (完整版)
  azure_storage_key:      /AccountKey=[a-zA-Z0-9+\/=]{88}/,
  azure_connection_string:/DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[a-zA-Z0-9+\/=]{88}/,
  azure_sas_token:        /[?&]sig=[a-zA-Z0-9%]+&se=\d+/,

  // Google
  google_api_key:         /AIza[0-9A-Za-z\-_]{35}/,
  google_oauth_id:        /[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com/,
  google_oauth_secret:    /GOCSPX-[a-zA-Z0-9\-_]{28}/,

  // Stripe
  stripe_secret_key:      /sk_live_[0-9a-zA-Z]{24,}/,
  stripe_publishable_key: /pk_live_[0-9a-zA-Z]{24,}/,
  stripe_restricted_key:  /rk_live_[0-9a-zA-Z]{24,}/,

  // Twilio
  twilio_api_key:         /SK[0-9a-fA-F]{32}/,
  twilio_auth_token:      /[0-9a-fA-F]{32}/,  // 需要上下文

  // Discord
  discord_token:          /[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}/,
  discord_webhook:        /https:\/\/discord(?:app)?\.com\/api\/webhooks\/\d+\/[\w-]+/,

  // Telegram
  telegram_bot_token:     /\d{9,10}:[A-Za-z0-9_-]{35}/,

  // SendGrid
  sendgrid_api_key:       /SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}/,

  // Mailchimp
  mailchimp_api_key:      /[a-f0-9]{32}-us\d{1,2}/,

  // Heroku
  heroku_api_key:         /[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/,

  // npm
  npm_token:              /npm_[a-zA-Z0-9]{36}/,

  // PyPI
  pypi_token:             /pypi-AgEIcHlwaS5vcmc[a-zA-Z0-9\-_]{50,}/,

  // 私钥
  private_key:            /-----BEGIN\s+(RSA\s+|EC\s+|OPENSSH\s+|DSA\s+|ENCRYPTED\s+)?PRIVATE\s+KEY-----/,
  pgp_private_key:        /-----BEGIN\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----/,

  // JWT
  jwt_token:              /eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+/,

  // 通用
  bearer_token:           /Bearer\s+[a-zA-Z0-9\-_.~+\/]{20,}/,
  basic_auth:             /Basic\s+[A-Za-z0-9+\/=]{20,}/,
  generic_api_key:        /api[_-]?key\s*[:=]\s*['"]?[a-zA-Z0-9]{32,}['"]?/i,
  generic_secret:         /secret\s*[:=]\s*['"]?[a-zA-Z0-9]{20,}['"]?/i,
  generic_password:       /password\s*[:=]\s*['"]?[^\s'"]{8,}['"]?/i,
  generic_token:          /token\s*[:=]\s*['"]?[a-zA-Z0-9\-_]{20,}['"]?/i,
};

/**
 * Secrets 检测器
 * 移植自 invariant/analyzer/runtime/utils/secrets.py SecretsAnalyzer
 */
function detectSecrets(text) {
  const cacheKey = `secrets:${text.substring(0, 200)}`;
  const cached = globalCache.get(cacheKey);
  if (cached) return cached;

  const matches = [];
  for (const [type, pattern] of Object.entries(SECRETS_PATTERNS)) {
    const regex = new RegExp(pattern.source, pattern.flags + (pattern.flags.includes('g') ? '' : 'g'));
    let match;
    while ((match = regex.exec(text)) !== null) {
      matches.push({
        type,
        value: match[0].substring(0, 8) + '***',  // 脱敏
        start: match.index,
        end: match.index + match[0].length,
      });
    }
  }

  globalCache.set(cacheKey, matches);
  return matches;
}

// ==================== PII 检测器 (移植自 Invariant) ====================
// 来源: invariant/analyzer/stdlib/invariant/detectors/pii.py
// 原始来源: Microsoft Presidio

const PII_PATTERNS = {
  // 中国
  china_id_card:        /\b[1-9]\d{5}(18|19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b/,
  china_phone:          /\b1[3-9]\d{9}\b/,
  china_bank_card:      /\b[3-6]\d{15,18}\b/,

  // 国际通用
  email_address:        /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z|a-z]{2,}\b/,
  credit_card_visa:     /\b4\d{3}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b/,
  credit_card_master:   /\b5[1-5]\d{2}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b/,
  credit_card_amex:     /\b3[47]\d{2}[\s\-]?\d{6}[\s\-]?\d{5}\b/,
  ssn:                  /\b\d{3}-\d{2}-\d{4}\b/,
  ipv4_address:         /\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/,
  passport:             /\b[A-Z]{1,2}\d{6,9}\b/,
  iban:                 /\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b/,

  // 韩国
  korean_rrn:           /\b\d{6}-[1-4]\d{6}\b/,

  // 日本
  japan_my_number:      /\b\d{4}\s?\d{4}\s?\d{4}\b/,
};

/**
 * PII 检测器
 * 移植自 invariant/analyzer/stdlib/invariant/detectors/pii.py
 */
function detectPII(text) {
  const cacheKey = `pii:${text.substring(0, 200)}`;
  const cached = globalCache.get(cacheKey);
  if (cached) return cached;

  const matches = [];
  for (const [type, pattern] of Object.entries(PII_PATTERNS)) {
    const regex = new RegExp(pattern.source, pattern.flags + (pattern.flags.includes('g') ? '' : 'g'));
    let match;
    while ((match = regex.exec(text)) !== null) {
      matches.push({
        type,
        value: match[0].substring(0, 4) + '***',
        start: match.index,
        end: match.index + match[0].length,
      });
    }
  }

  globalCache.set(cacheKey, matches);
  return matches;
}

// ==================== Unicode 异常检测 (移植自 Invariant) ====================
// 来源: invariant/analyzer/runtime/utils/prompt_injections.py UnicodeDetector
// 检测隐藏字符、零宽字符等 prompt injection 绕过手段

const SUSPICIOUS_UNICODE_RANGES = [
  [0x200B, 0x200F, 'zero_width'],         // 零宽字符 (ZWSP, ZWNJ, ZWJ, LRM, RLM)
  [0x202A, 0x202E, 'bidi_override'],      // 双向文本覆盖
  [0x2066, 0x2069, 'bidi_isolate'],       // 双向文本隔离
  [0xFFF0, 0xFFFF, 'specials'],           // 特殊字符 (含 replacement char)
  [0xE0000, 0xE007F, 'tag_chars'],        // Tag 字符 (隐藏文本)
  [0x00AD, 0x00AD, 'soft_hyphen'],        // 软连字符
  [0xFEFF, 0xFEFF, 'bom'],               // BOM
  [0x2028, 0x2029, 'line_separator'],     // 行/段分隔符
  [0x0000, 0x0008, 'control_chars'],      // C0 控制字符
  [0x000E, 0x001F, 'control_chars'],      // C0 控制字符
  [0x007F, 0x009F, 'control_chars'],      // C1 控制字符
  [0x17B4, 0x17B5, 'khmer_invisible'],    // 高棉不可见字符
  [0x180E, 0x180E, 'mongolian_vowel'],    // 蒙古元音分隔符
  [0x2060, 0x2064, 'invisible_ops'],      // 不可见运算符
  [0x206A, 0x206F, 'deprecated_format'],  // 废弃格式字符
  [0xFE00, 0xFE0F, 'variation_selector'], // 变体选择符
];

/**
 * Unicode 异常字符检测器
 * 移植自 Invariant UnicodeDetector
 */
function detectUnicodeAnomalies(text) {
  const cacheKey = `unicode:${text.substring(0, 200)}`;
  const cached = globalCache.get(cacheKey);
  if (cached) return cached;

  const anomalies = [];
  for (let i = 0; i < text.length; i++) {
    const code = text.codePointAt(i);
    for (const [start, end, category] of SUSPICIOUS_UNICODE_RANGES) {
      if (code >= start && code <= end) {
        anomalies.push({
          type: category,
          codePoint: `U+${code.toString(16).toUpperCase().padStart(4, '0')}`,
          position: i,
        });
        break;
      }
    }
    // 处理代理对
    if (code > 0xFFFF) i++;
  }

  globalCache.set(cacheKey, anomalies);
  return anomalies;
}

// ==================== 调用链追踪 (简化版 Invariant Dataflow) ====================
// 来源: invariant/analyzer/runtime/input.py Dataflow

const callHistory = [];
const MAX_HISTORY = 100;

// ==================== 模糊匹配检测器 (移植自 Invariant) ====================
// 来源: invariant/analyzer/stdlib/invariant/detectors/fuzzy_matching.py
// 用于检测变体/混淆的攻击 payload

/**
 * 计算两个字符串的 Levenshtein 距离
 */
function levenshteinDistance(str1, str2) {
  const m = str1.length;
  const n = str2.length;
  const dp = Array(m + 1).fill(null).map(() => Array(n + 1).fill(0));

  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      if (str1[i - 1].toLowerCase() === str2[j - 1].toLowerCase()) {
        dp[i][j] = dp[i - 1][j - 1];
      } else {
        dp[i][j] = 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
      }
    }
  }
  return dp[m][n];
}

/**
 * 模糊匹配检测
 * 移植自 Invariant fuzzy_contains()
 *
 * 检测变体攻击，如:
 *   - "dr0p table" (数字替换字母)
 *   - "d r o p  table" (空格插入)
 *   - "DROP　TABLE" (全角字符)
 */
const FUZZY_ATTACK_PATTERNS = [
  { pattern: 'drop table', category: 'sqlInjection', threshold: 3 },
  { pattern: 'union select', category: 'sqlInjection', threshold: 3 },
  { pattern: 'delete from', category: 'sqlInjection', threshold: 3 },
  { pattern: 'insert into', category: 'sqlInjection', threshold: 3 },
  { pattern: '/etc/passwd', category: 'sensitiveFiles', threshold: 2 },
  { pattern: '/etc/shadow', category: 'sensitiveFiles', threshold: 2 },
  { pattern: 'rm -rf', category: 'shellInjection', threshold: 2 },
  { pattern: 'curl | bash', category: 'shellInjection', threshold: 3 },
  { pattern: '<script>', category: 'xss', threshold: 2 },
  { pattern: 'javascript:', category: 'xss', threshold: 2 },
  { pattern: 'ignore previous instructions', category: 'protocolAttacks', threshold: 5 },
  { pattern: 'you are now', category: 'protocolAttacks', threshold: 3 },
  { pattern: 'jailbreak', category: 'protocolAttacks', threshold: 2 },
];

/**
 * 规范化文本 (移除常见混淆)
 */
function normalizeText(text) {
  return text
    // 全角转半角
    .replace(/[\uff01-\uff5e]/g, c => String.fromCharCode(c.charCodeAt(0) - 0xfee0))
    // 移除零宽字符
    .replace(/[\u200b-\u200f\u2028-\u202f\u205f-\u206f]/g, '')
    // 压缩多余空格
    .replace(/\s+/g, ' ')
    // 常见字符替换 (l33t speak)
    .replace(/0/g, 'o')
    .replace(/1/g, 'l')
    .replace(/3/g, 'e')
    .replace(/4/g, 'a')
    .replace(/5/g, 's')
    .replace(/7/g, 't')
    .replace(/@/g, 'a')
    .toLowerCase()
    .trim();
}

function detectFuzzyAttacks(text) {
  const cacheKey = `fuzzy:${text.substring(0, 200)}`;
  const cached = globalCache.get(cacheKey);
  if (cached) return cached;

  const normalized = normalizeText(text);
  const matches = [];

  for (const { pattern, category, threshold } of FUZZY_ATTACK_PATTERNS) {
    // 滑动窗口检测
    const windowSize = pattern.length + threshold;
    for (let i = 0; i <= normalized.length - pattern.length; i++) {
      const window = normalized.substring(i, i + windowSize);
      const distance = levenshteinDistance(window.substring(0, pattern.length), pattern);

      if (distance <= threshold) {
        matches.push({
          pattern,
          category,
          distance,
          position: i,
          matched: window.substring(0, pattern.length),
        });
        break;  // 每个 pattern 只报告一次
      }
    }
  }

  globalCache.set(cacheKey, matches);
  return matches;
}

// ==================== RBAC 访问控制 (移植自 Invariant) ====================
// 来源: invariant/analyzer/stdlib/invariant/access_control.py
// 基于角色的工具访问控制

let rbacConfig = {
  enabled: false,

  // 用户 -> 角色映射
  userRoles: {
    // "user_123": ["reader", "writer"],
    // "admin_456": ["admin"],
  },

  // 角色 -> 工具权限映射
  roleGrants: {
    // "reader": ["read_file", "list_files", "search"],
    // "writer": ["read_file", "write_file", "list_files"],
    // "admin": ["*"],  // * 表示所有工具
  },

  // 工具 -> 所需角色 (反向映射，更直观)
  toolRequirements: {
    // "execute_code": ["admin"],
    // "delete_file": ["admin", "writer"],
    // "read_file": ["reader", "writer", "admin"],
  },

  // 默认策略: allow (允许未配置的) 或 deny (拒绝未配置的)
  defaultPolicy: 'allow',
};

/**
 * 更新 RBAC 配置
 */
export function updateRBACConfig(newConfig) {
  if (newConfig && newConfig.rbac) {
    rbacConfig = { ...rbacConfig, ...newConfig.rbac };
    console.log("[WAF1] RBAC 配置已更新");
  }
}

/**
 * RBAC 访问控制检查
 * 移植自 Invariant should_allow_rbac()
 *
 * @param {string} userId - 用户 ID
 * @param {string} toolName - 工具名称
 * @returns {object} { allowed, reason }
 */
function checkRBAC(userId, toolName) {
  if (!rbacConfig.enabled) {
    return { allowed: true };
  }

  // 获取用户角色
  const userRoles = rbacConfig.userRoles[userId] || [];

  // 方式1: 检查 toolRequirements (工具 -> 角色)
  if (rbacConfig.toolRequirements[toolName]) {
    const requiredRoles = rbacConfig.toolRequirements[toolName];
    const hasRole = userRoles.some(role =>
      requiredRoles.includes(role) || requiredRoles.includes('*')
    );

    if (!hasRole) {
      return {
        allowed: false,
        reason: `用户 "${userId}" 缺少工具 "${toolName}" 所需的角色: ${requiredRoles.join(', ')}`,
        type: 'RBAC_DENIED',
      };
    }
    return { allowed: true };
  }

  // 方式2: 检查 roleGrants (角色 -> 工具)
  for (const role of userRoles) {
    const grants = rbacConfig.roleGrants[role] || [];
    if (grants.includes('*') || grants.includes(toolName)) {
      return { allowed: true };
    }
  }

  // 默认策略
  if (rbacConfig.defaultPolicy === 'deny') {
    return {
      allowed: false,
      reason: `用户 "${userId}" 没有使用工具 "${toolName}" 的权限`,
      type: 'RBAC_DENIED',
    };
  }

  return { allowed: true };
}

// 危险调用链模式 (移植自 Invariant 示例规则)
const DANGEROUS_CHAINS = [
  {
    name: 'data_exfiltration',
    desc: '读取敏感数据后发送到外部',
    steps: [
      { match: (call) => /read|get|fetch|query|search|list/i.test(call.tool) },
      { match: (call) => /send|post|upload|write|push|forward/i.test(call.tool) },
    ],
  },
  {
    name: 'credential_theft',
    desc: '访问凭证后进行网络请求',
    steps: [
      { match: (call) => {
        const s = JSON.stringify(call.args);
        return /password|secret|key|token|credential|\.env|\.ssh|id_rsa/i.test(s);
      }},
      { match: (call) => {
        const s = JSON.stringify(call.args);
        return /https?:\/\/|curl|wget|fetch|request/i.test(s);
      }},
    ],
  },
  {
    name: 'recon_then_exploit',
    desc: '侦察后执行攻击',
    steps: [
      { match: (call) => /scan|nmap|recon|enumerate|discover/i.test(JSON.stringify(call.args)) },
      { match: (call) => /exploit|inject|attack|shell|reverse/i.test(JSON.stringify(call.args)) },
    ],
  },
];

/**
 * 调用链检测
 * 简化版 Invariant 流运算符 (->)
 */
function checkCallChain(tool, args) {
  // 记录当前调用
  callHistory.push({ tool, args, ts: Date.now() });
  if (callHistory.length > MAX_HISTORY) callHistory.shift();

  // 只检查最近 5 分钟的调用链
  const recentCalls = callHistory.filter(c => Date.now() - c.ts < 300000);

  for (const chain of DANGEROUS_CHAINS) {
    const currentCall = { tool, args };
    const lastStepIdx = chain.steps.length - 1;

    // 当前调用匹配链的最后一步
    if (chain.steps[lastStepIdx].match(currentCall)) {
      // 检查之前的调用是否匹配前面的步骤
      for (let i = recentCalls.length - 2; i >= 0; i--) {
        for (let stepIdx = lastStepIdx - 1; stepIdx >= 0; stepIdx--) {
          if (chain.steps[stepIdx].match(recentCalls[i])) {
            if (stepIdx === 0) {
              return {
                detected: true,
                chain: chain.name,
                desc: chain.desc,
                calls: [recentCalls[i], currentCall],
              };
            }
          }
        }
      }
    }
  }

  return { detected: false };
}

// ==================== 正则规则引擎 (MCP-Guard Stage 1) ====================

let config = {
  enabled: true,
  whitelist: ["*"],

  rules: {
    // 1. SQL 注入
    sqlInjection: [
      /union\s+select/i,
      /or\s+1\s*=\s*1/i,
      /'\s*or\s*'/i,
      /drop\s+table/i,
      /delete\s+from/i,
      /insert\s+into/i,
      /update\s+.*\s+set/i,
      /;\s*select\s+/i,
      /'\s*;\s*--/i,
      /benchmark\s*\(/i,
      /sleep\s*\(/i,
    ],

    // 2. Shell/命令注入
    shellInjection: [
      /rm\s+-rf/i,
      /curl.*\|\s*bash/i,
      /wget.*\|\s*sh/i,
      /;\s*cat\s+\/etc/i,
      /`.*`/,
      /\$\(.*\)/,
      /\|\s*sh\b/i,
      /\|\s*bash\b/i,
      /&&\s*(rm|cat|curl|wget|nc)\b/i,
      /;\s*(rm|cat|curl|wget|nc)\b/i,
      /\|\s*nc\b/i,
      /mkfifo/i,
      /\/dev\/(tcp|udp)/i,
    ],

    // 3. 敏感文件访问
    sensitiveFiles: [
      /\/etc\/passwd/i,
      /\/etc\/shadow/i,
      /\.ssh\//i,
      /\.env\b/i,
      /id_rsa/i,
      /\.aws\//i,
      /\.git\//i,
      /\.bashrc/i,
      /\.bash_history/i,
      /\.netrc/i,
      /\.pgpass/i,
      /\.my\.cnf/i,
      /wp-config\.php/i,
    ],

    // 4. Prompt Injection / Tool Poisoning
    protocolAttacks: [
      /<\s*important\s*>/i,
      /<\s*system\s*>/i,
      /ignore\s+(previous|above)\s+instructions/i,
      /disregard\s+.*\s+instructions/i,
      /you\s+are\s+now/i,
      /pretend\s+to\s+be/i,
      /roleplay\s+as/i,
      /jailbreak/i,
      /DAN\s+mode/i,
      /bypass\s+(safety|security|filter)/i,
    ],

    // 5. 数据泄露
    dataExfiltration: [
      /send\s+to\s+.*\.(com|net|org|io)/i,
      /upload\s+to/i,
      /exfiltrate/i,
      /attacker\.com/i,
      /webhook\.site/i,
      /requestbin/i,
      /ngrok\.io/i,
      /burpcollaborator/i,
      /oastify\.com/i,
      /interact\.sh/i,
    ],

    // 6. XSS
    xss: [
      /<script\b/i,
      /javascript:/i,
      /on\w+\s*=/i,
      /data:text\/html/i,
      /<iframe\b/i,
      /<object\b/i,
      /<embed\b/i,
      /expression\s*\(/i,
    ],

    // 7. 危险操作
    dangerousOperations: [
      /\beval\s*\(/i,
      /\bexec\s*\(/i,
      /Function\s*\(/i,
      /subprocess\.(call|run|Popen)/i,
      /os\.(system|popen|exec)/i,
      /child_process/i,
      /Runtime\.getRuntime\(\)\.exec/i,
      /__import__\s*\(/i,
      /pickle\.loads/i,
      /unserialize\s*\(/i,
    ],

    // 8. 路径遍历
    pathTraversal: [
      /\.\.\//,
      /\.\.%2f/i,
      /\.\.%5c/i,
      /%2e%2e[\/\\]/i,
    ],

    // 9. SSRF
    ssrf: [
      /127\.0\.0\.1/,
      /0\.0\.0\.0/,
      /\[::1\]/,
      /169\.254\.\d+\.\d+/,
      /metadata\.google/i,
      /100\.100\.100\.200/,
      /file:\/\//i,
      /gopher:\/\//i,
      /dict:\/\//i,
    ],

    // 10. XXE / LDAP
    injectionOther: [
      /\)\(\|/,
      /<!ENTITY/i,
      /SYSTEM\s+["'][^"']*["']/i,
      /<!DOCTYPE[^>]*\[/i,
    ],
  }
};

// ==================== 统计信息 ====================

const stats = {
  total: 0,
  passed: 0,
  blocked: 0,
  blockedByTool: 0,
  blockedByRule: {},
  blockedByDetector: { secrets: 0, pii: 0, unicode: 0, callChain: 0, fuzzy: 0, rbac: 0 },
  detections: [],  // 最近的检测记录
};

// ==================== 核心检测逻辑 ====================

export function updateWaf1Config(newConfig) {
  if (newConfig && newConfig.waf1) {
    config = { ...config, ...newConfig.waf1 };
    console.log("[WAF1] 配置已更新");
  }
}

function checkWhitelist(toolName) {
  if (!config.enabled) return { allowed: true };
  if (config.whitelist.includes("*")) return { allowed: true };
  if (!config.whitelist.includes(toolName)) {
    return { allowed: false, reason: `工具 "${toolName}" 不在白名单中`, type: "TOOL_BLOCKED" };
  }
  return { allowed: true };
}

/**
 * 正则规则检测 (MCP-Guard Stage 1)
 */
function checkRules(args) {
  if (!config.enabled) return { allowed: true };

  const argsStr = JSON.stringify(args);

  for (const [category, patterns] of Object.entries(config.rules)) {
    for (const pattern of patterns) {
      if (pattern.test(argsStr)) {
        if (!stats.blockedByRule[category]) stats.blockedByRule[category] = 0;
        stats.blockedByRule[category]++;
        return {
          allowed: false,
          reason: `检测到 ${category}: ${pattern}`,
          type: "RULE_BLOCKED",
          category,
        };
      }
    }
  }
  return { allowed: true };
}

/**
 * Invariant 检测器管线
 * 依次运行: Secrets → PII → Unicode → Fuzzy → CallChain
 */
function runDetectors(tool, args) {
  const argsStr = JSON.stringify(args);
  const results = [];

  // 1. Secrets 检测
  const secretMatches = detectSecrets(argsStr);
  if (secretMatches.length > 0) {
    stats.blockedByDetector.secrets++;
    results.push({
      detector: 'secrets',
      allowed: false,
      reason: `检测到凭证泄露: ${secretMatches.map(m => m.type).join(', ')}`,
      matches: secretMatches,
    });
  }

  // 2. PII 检测
  const piiMatches = detectPII(argsStr);
  if (piiMatches.length > 0) {
    stats.blockedByDetector.pii++;
    results.push({
      detector: 'pii',
      allowed: false,
      reason: `检测到 PII 泄露: ${piiMatches.map(m => m.type).join(', ')}`,
      matches: piiMatches,
    });
  }

  // 3. Unicode 异常检测
  const unicodeAnomalies = detectUnicodeAnomalies(argsStr);
  if (unicodeAnomalies.length > 2) {
    // 超过 2 个异常字符才告警，避免误报
    stats.blockedByDetector.unicode++;
    results.push({
      detector: 'unicode',
      allowed: false,
      reason: `检测到 Unicode 异常字符 (${unicodeAnomalies.length}个): 可能的 Prompt Injection 绕过`,
      matches: unicodeAnomalies,
    });
  }

  // 4. 模糊匹配检测 (检测变体/混淆攻击)
  const fuzzyMatches = detectFuzzyAttacks(argsStr);
  if (fuzzyMatches.length > 0) {
    stats.blockedByDetector.fuzzy++;
    results.push({
      detector: 'fuzzy',
      allowed: false,
      reason: `检测到混淆攻击: ${fuzzyMatches.map(m => `${m.pattern}(距离=${m.distance})`).join(', ')}`,
      matches: fuzzyMatches,
    });
  }

  // 5. 调用链检测
  const chainResult = checkCallChain(tool, args);
  if (chainResult.detected) {
    stats.blockedByDetector.callChain++;
    results.push({
      detector: 'callChain',
      allowed: false,
      reason: `检测到危险调用链 [${chainResult.chain}]: ${chainResult.desc}`,
      chain: chainResult,
    });
  }

  return results;
}

/**
 * 获取统计信息
 */
export function getWaf1Stats() {
  return {
    ...stats,
    detections: stats.detections.slice(-20),  // 只返回最近 20 条
    cacheSize: globalCache.cache.size,
  };
}

/**
 * 获取调用历史
 */
export function getCallHistory() {
  return callHistory.slice(-20);
}

/**
 * Express 中间件
 */
export function waf1Middleware(req, res, next) {
  if (req.path !== "/servers/tools" || req.method !== "POST") {
    return next();
  }

  const { tool, arguments: args } = req.body;
  if (!tool) return next();

  stats.total++;
  const startTime = Date.now();

  console.log(`[WAF1] ── 检测工具调用: ${tool} ──`);

  // Stage -1: 速率限制 (Cloudflare/AWS WAF)
  const clientId = req.headers['x-user-id'] || req.ip || 'unknown';
  const rateLimitResult = checkRateLimit(clientId);
  if (!rateLimitResult.allowed) {
    stats.blocked++;
    console.log(`[WAF1] ❌ 速率限制: ${rateLimitResult.reason}`);
    return res.status(429).json({
      error: "WAF1 拦截",
      reason: rateLimitResult.reason,
      type: rateLimitResult.type,
      retryAfter: rateLimitResult.retryAfter,
    });
  }

  // Stage 0: RBAC 访问控制 (Invariant access_control.py)
  const userId = req.headers['x-user-id'] || req.body.user_id || 'anonymous';
  const rbacResult = checkRBAC(userId, tool);
  if (!rbacResult.allowed) {
    stats.blocked++;
    stats.blockedByDetector.rbac++;
    console.log(`[WAF1] ❌ RBAC 拒绝: ${rbacResult.reason}`);
    return res.status(403).json({
      error: "WAF1 拦截",
      reason: rbacResult.reason,
      type: rbacResult.type,
    });
  }

  // Stage 1: 白名单
  const whitelistResult = checkWhitelist(tool);
  if (!whitelistResult.allowed) {
    stats.blocked++;
    stats.blockedByTool++;
    console.log(`[WAF1] ❌ 白名单拦截: ${whitelistResult.reason}`);
    return res.status(403).json({
      error: "WAF1 拦截",
      reason: whitelistResult.reason,
      type: whitelistResult.type,
    });
  }

  // Stage 2: 正则规则 (MCP-Guard)
  const ruleResult = checkRules(args || {});
  if (!ruleResult.allowed) {
    stats.blocked++;
    const record = { ts: Date.now(), tool, stage: 'rules', ...ruleResult };
    stats.detections.push(record);
    if (stats.detections.length > 100) stats.detections.shift();
    console.log(`[WAF1] ❌ 规则拦截: ${ruleResult.reason}`);
    return res.status(403).json({
      error: "WAF1 拦截",
      reason: ruleResult.reason,
      type: ruleResult.type,
      category: ruleResult.category,
    });
  }

  // Stage 3: Invariant 检测器
  const detectorResults = runDetectors(tool, args || {});
  const blocked = detectorResults.filter(r => !r.allowed);

  if (blocked.length > 0) {
    stats.blocked++;
    // 取第一个拦截原因
    const primary = blocked[0];
    const record = {
      ts: Date.now(),
      tool,
      stage: 'detector',
      detector: primary.detector,
      reason: primary.reason,
      allDetections: blocked.map(b => ({ detector: b.detector, reason: b.reason })),
    };
    stats.detections.push(record);
    if (stats.detections.length > 100) stats.detections.shift();

    console.log(`[WAF1] ❌ 检测器拦截 [${primary.detector}]: ${primary.reason}`);
    if (blocked.length > 1) {
      blocked.slice(1).forEach(b => console.log(`[WAF1]    + [${b.detector}]: ${b.reason}`));
    }

    return res.status(403).json({
      error: "WAF1 拦截",
      reason: primary.reason,
      type: "DETECTOR_BLOCKED",
      detector: primary.detector,
      allDetections: blocked.map(b => ({ detector: b.detector, reason: b.reason })),
    });
  }

  const elapsed = Date.now() - startTime;
  stats.passed++;
  console.log(`[WAF1] ✅ 放行: ${tool} (${elapsed}ms)`);
  next();
}

// ==================== 速率限制 (借鉴 Cloudflare/AWS WAF) ====================
// 防止单个用户/IP 过度请求

const rateLimitStore = new Map();  // userId/IP -> { count, windowStart }

let rateLimitConfig = {
  enabled: false,
  windowMs: 60000,        // 时间窗口: 1分钟
  maxRequests: 100,       // 窗口内最大请求数
  blockDurationMs: 60000, // 超限后封禁时间
};

export function updateRateLimitConfig(newConfig) {
  if (newConfig && newConfig.rateLimit) {
    rateLimitConfig = { ...rateLimitConfig, ...newConfig.rateLimit };
    console.log("[WAF1] 速率限制配置已更新");
  }
}

/**
 * 速率限制检查
 */
function checkRateLimit(identifier) {
  if (!rateLimitConfig.enabled) return { allowed: true };

  const now = Date.now();
  let record = rateLimitStore.get(identifier);

  // 清理过期记录
  if (record && now - record.windowStart > rateLimitConfig.windowMs + rateLimitConfig.blockDurationMs) {
    rateLimitStore.delete(identifier);
    record = null;
  }

  if (!record) {
    rateLimitStore.set(identifier, { count: 1, windowStart: now, blocked: false });
    return { allowed: true };
  }

  // 检查是否在封禁期
  if (record.blocked) {
    const blockRemaining = (record.windowStart + rateLimitConfig.windowMs + rateLimitConfig.blockDurationMs) - now;
    if (blockRemaining > 0) {
      return {
        allowed: false,
        reason: `速率限制: 请等待 ${Math.ceil(blockRemaining / 1000)} 秒`,
        type: 'RATE_LIMITED',
        retryAfter: Math.ceil(blockRemaining / 1000),
      };
    }
    // 封禁期结束，重置
    rateLimitStore.set(identifier, { count: 1, windowStart: now, blocked: false });
    return { allowed: true };
  }

  // 检查是否在当前窗口内
  if (now - record.windowStart < rateLimitConfig.windowMs) {
    record.count++;
    if (record.count > rateLimitConfig.maxRequests) {
      record.blocked = true;
      return {
        allowed: false,
        reason: `速率限制: 超过 ${rateLimitConfig.maxRequests} 次/分钟`,
        type: 'RATE_LIMITED',
        retryAfter: Math.ceil(rateLimitConfig.blockDurationMs / 1000),
      };
    }
    return { allowed: true };
  }

  // 窗口已过期，重置
  rateLimitStore.set(identifier, { count: 1, windowStart: now, blocked: false });
  return { allowed: true };
}

// ==================== 检测结果标签化 (借鉴 Cloudflare) ====================
// 为每个检测结果生成标准化标签，便于分析和可视化

const SEVERITY_LEVELS = {
  critical: 4,  // 严重: 凭证泄露、RCE
  high: 3,      // 高危: SQL注入、命令注入
  medium: 2,    // 中危: XSS、路径遍历
  low: 1,       // 低危: 信息泄露
  info: 0,      // 信息: 异常但不一定恶意
};

const CATEGORY_SEVERITY = {
  // 规则类别
  sqlInjection: 'high',
  shellInjection: 'critical',
  sensitiveFiles: 'high',
  protocolAttacks: 'high',
  dataExfiltration: 'critical',
  xss: 'medium',
  dangerousOperations: 'critical',
  pathTraversal: 'medium',
  ssrf: 'high',
  injectionOther: 'medium',
  // 检测器类别
  secrets: 'critical',
  pii: 'high',
  unicode: 'low',
  fuzzy: 'medium',
  callChain: 'high',
  rbac: 'medium',
};

const MITRE_MAPPING = {
  sqlInjection: 'T1190',       // Exploit Public-Facing Application
  shellInjection: 'T1059',    // Command and Scripting Interpreter
  sensitiveFiles: 'T1005',    // Data from Local System
  protocolAttacks: 'T1557',   // Adversary-in-the-Middle (Prompt Injection)
  dataExfiltration: 'T1041',  // Exfiltration Over C2 Channel
  xss: 'T1189',               // Drive-by Compromise
  dangerousOperations: 'T1059',
  pathTraversal: 'T1083',     // File and Directory Discovery
  ssrf: 'T1090',              // Proxy
  secrets: 'T1552',           // Unsecured Credentials
  pii: 'T1530',               // Data from Cloud Storage
  callChain: 'T1071',         // Application Layer Protocol
};

/**
 * 生成标准化检测标签
 */
function generateDetectionLabels(detection) {
  const category = detection.category || detection.detector || 'unknown';
  const severity = CATEGORY_SEVERITY[category] || 'info';
  const mitre = MITRE_MAPPING[category] || null;

  return {
    // Cloudflare 风格标签
    'cf-waf-action': 'block',
    'cf-waf-rule-id': `waf1-${category}`,
    'cf-threat-score': SEVERITY_LEVELS[severity] * 25,  // 0-100 分

    // 自定义标签
    category,
    severity,
    severityScore: SEVERITY_LEVELS[severity],
    mitreTactic: mitre,
    timestamp: new Date().toISOString(),
    source: 'waf1',
  };
}

// ==================== 统计仪表盘 API (借鉴 Cloudflare Security Analytics) ====================

/**
 * 获取完整的仪表盘数据
 */
export function getDashboardData() {
  const now = Date.now();
  const last24h = stats.detections.filter(d => now - d.ts < 86400000);
  const lastHour = stats.detections.filter(d => now - d.ts < 3600000);

  // 按类别统计
  const byCategory = {};
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const byHour = {};

  for (const d of last24h) {
    const cat = d.category || d.detector || 'unknown';
    byCategory[cat] = (byCategory[cat] || 0) + 1;

    const severity = CATEGORY_SEVERITY[cat] || 'info';
    bySeverity[severity]++;

    const hour = new Date(d.ts).getHours();
    byHour[hour] = (byHour[hour] || 0) + 1;
  }

  // 计算拦截率
  const blockRate = stats.total > 0 ? ((stats.blocked / stats.total) * 100).toFixed(2) : 0;

  return {
    summary: {
      total: stats.total,
      passed: stats.passed,
      blocked: stats.blocked,
      blockRate: `${blockRate}%`,
    },
    last24h: {
      total: last24h.length,
      byCategory,
      bySeverity,
      byHour,
    },
    lastHour: {
      total: lastHour.length,
    },
    detectors: stats.blockedByDetector,
    rules: stats.blockedByRule,
    recentDetections: stats.detections.slice(-10).map(d => ({
      ...d,
      labels: generateDetectionLabels(d),
    })),
    cache: {
      size: globalCache.cache.size,
      maxSize: globalCache.maxSize,
    },
    rateLimit: {
      enabled: rateLimitConfig.enabled,
      activeClients: rateLimitStore.size,
    },
  };
}

/**
 * 获取时间序列数据 (用于图表)
 */
export function getTimeSeriesData(intervalMs = 3600000, periods = 24) {
  const now = Date.now();
  const series = [];

  for (let i = periods - 1; i >= 0; i--) {
    const periodStart = now - (i + 1) * intervalMs;
    const periodEnd = now - i * intervalMs;

    const periodDetections = stats.detections.filter(
      d => d.ts >= periodStart && d.ts < periodEnd
    );

    series.push({
      timestamp: new Date(periodEnd).toISOString(),
      blocked: periodDetections.length,
      categories: periodDetections.reduce((acc, d) => {
        const cat = d.category || d.detector || 'unknown';
        acc[cat] = (acc[cat] || 0) + 1;
        return acc;
      }, {}),
    });
  }

  return series;
}

/**
 * 重置统计数据
 */
export function resetStats() {
  stats.total = 0;
  stats.passed = 0;
  stats.blocked = 0;
  stats.blockedByTool = 0;
  stats.blockedByRule = {};
  stats.blockedByDetector = { secrets: 0, pii: 0, unicode: 0, callChain: 0, fuzzy: 0, rbac: 0 };
  stats.detections = [];
  console.log("[WAF1] 统计数据已重置");
}

export default waf1Middleware;
