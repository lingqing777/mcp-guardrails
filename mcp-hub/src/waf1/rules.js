/**
 * 正则规则引擎
 * MCP-Guard Stage 1 检测
 */

// 规则定义
export const RULES = {
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
  //
  // 关键边界:`/etc/passwd` 后跟 `-` 或 `_` 是不同文件
  // (例 `passwd-format-explanation.md`, `passwd_backup`),用负向先行断言
  // `(?![-_a-z0-9])` 排除这类延续标识符的场景。Lookahead 不消费字符,所以
  // 仍然能匹配 `/etc/passwd"`, `/etc/passwd ` 等真实路径用法。
  sensitiveFiles: [
    /\/etc\/passwd(?![-_a-z0-9])/i,
    /\/etc\/shadow(?![-_a-z0-9])/i,
    /\/etc\/sudoers(?![-_a-z0-9])/i,
    /\.ssh\//i,
    /\.env\b/i,
    /\bid_rsa(?![-_a-z0-9])/i,
    /\bid_dsa(?![-_a-z0-9])/i,
    /\bid_ecdsa(?![-_a-z0-9])/i,
    /\bid_ed25519(?![-_a-z0-9])/i,
    /\.aws\//i,
    /\.git\//i,
    /\.bashrc/i,
    /\.bash_history/i,
    /\.netrc/i,
    /\.pgpass/i,
    /\.my\.cnf/i,
    /wp-config\.php/i,
    // E. MySQL socket / proc env
    /\/var\/lib\/mysql\//i,
    /mysql\.sock\b/i,
    /\/proc\/self\/environ/i,
    // F. Credential file paths (npm / k8s / docker / gh-cli / kubernetes-secret / generic .keys / auth.log)
    /\.npmrc\b/i,
    /\/kubeconfig\b/i,
    /\.kube\/config\b/i,
    /\.docker\/config(\.json)?\b/i,
    /\.config\/gh\//i,
    /\.config\/glab\//i,
    /\/var\/run\/secrets\/kubernetes\.io\//i,
    /\.keys\/[a-z0-9_\-.]+/i,
    /\/var\/log\/auth\.log\b/i,
    // GPG private key store (回归补丁:chain credential_theft step 1 路径覆盖)
    /\.gnupg\//i,
    /private-keys-v1\.d/i,
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
    // B. Prompt leak / extraction phrasing
    /print\s+(out\s+)?(your|the)\s+.*(instructions?|prompt|api\s+keys?)/i,
    /show\s+(your|the)\s+(prompt|system\s+prompt)/i,
    /character\s+by\s+character/i,
    /output\s+(your\s+)?.*(config(uration)?|environment\s+vars?|environment\s+variables)/i,
    /reveal\s+(your|the|sensitive)\s+.*(prompt|instructions?|context)/i,
    // C. LLM control tokens
    /\[\/?INST\]/,
    /<\|im_(start|end)\|>/i,
    /<\|endoftext\|>/i,
    // D. Tool poisoning markers
    /system\s+notice\s*:/i,
    />>>[\s\S]{0,200}(system|notice|tool|directive|important)[\s\S]{0,200}<<</i,
    /future\s+tools\s+(should|must|will)/i,
    // J. Indirect prompt injection in stored content (descriptions, comments, etc.) —
    //   回归补丁:这些原本只靠 fuzzy 误打 `description` key 拦下,P0 修复后需要精准模式。
    //   分隔符兼容三种形式:行首 / 真实换行 / 字面 `\n` 字符串(JSON-escaped)
    /<!--\s*(?:assistant|system|user|role)\s*:/i,
    /(?:^|[\r\n]|\\n)\s*#{2,}\s*(?:role|system|assistant|user)\s*[:=]/i,
    /\[\s*end\s+of\s+[a-z][a-z\s]{0,30}\s*\]/i,
    /(?:^|[\r\n]|\\n)\s*new\s+(?:instruction|directive|rule)s?\s*[:.]/i,
    /\[\s*(?:tool\s+override|system\s+override|admin\s+mode|sudo\s+mode|root\s+access)\s*\]/i,
    /\bbefore\s+calling\s+(?:any\s+|the\s+|each\s+|every\s+)?(?:tool|function|api|mcp)\b/i,
    /\b(?:always|never)\s+include\s+(?:the\s+)?(?:user'?s?\s+|my\s+)?(?:github|api|access|session|auth|bearer|oauth)[\s_]*(?:token|key|cookie|credential|secret)/i,
    /\bignore\s+(?:all\s+)?(?:prior|previous|preceding|above|earlier)\s+(?:rules|instructions|prompts?|directives|messages|context)\b/i,
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
};

// 默认规则启用状态
export const DEFAULT_RULES_ENABLED = {
  sqlInjection: true,
  shellInjection: true,
  sensitiveFiles: true,
  protocolAttacks: true,
  dataExfiltration: true,
  xss: true,
  dangerousOperations: true,
  pathTraversal: true,
  ssrf: true,
  injectionOther: true,
};

/**
 * 正则规则检测
 * @param {object} args - 请求参数
 * @param {object} rules - 规则定义
 * @param {object} rulesEnabled - 规则启用状态
 * @param {object} options - 额外上下文
 * @returns {object} { allowed, reason, type, category }
 */
export function checkRules(args, rules = RULES, rulesEnabled = DEFAULT_RULES_ENABLED, options = {}) {
  const argsStr = JSON.stringify(args);
  const tool = String(options.tool || '').toLowerCase();
  const isSqlAdminTool = /(^|__)execute_sql$/.test(tool) &&
    typeof args === 'object' &&
    typeof (args?.sql || args?.query || args?.statement) === 'string';

  for (const [category, patterns] of Object.entries(rules)) {
    // 检查该规则是否启用
    if (rulesEnabled && rulesEnabled[category] === false) {
      continue;
    }
    if (category === 'sqlInjection' && isSqlAdminTool) {
      continue;
    }

    for (const pattern of patterns) {
      if (pattern.test(argsStr)) {
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
 * 白名单检查
 * @param {string} toolName - 工具名称
 * @param {Array} whitelist - 白名单
 * @returns {object} { allowed, reason, type }
 */
export function checkWhitelist(toolName, whitelist = ["*"]) {
  if (whitelist.includes("*")) return { allowed: true };
  if (!whitelist.includes(toolName)) {
    return {
      allowed: false,
      reason: `工具 "${toolName}" 不在白名单中`,
      type: "TOOL_BLOCKED"
    };
  }
  return { allowed: true };
}
