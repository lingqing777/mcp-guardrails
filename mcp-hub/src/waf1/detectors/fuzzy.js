/**
 * 模糊匹配检测器
 * 移植自 Invariant stdlib/detectors/fuzzy_matching.py
 * 用于检测变体/混淆的攻击 payload
 */

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

// 模糊攻击模式
//
// 注:`/etc/passwd` / `/etc/shadow` 等路径类模式已从 fuzzy 移除 — 这些应由
// `rules.sensitiveFiles` 的边界锚定正则负责。fuzzy 不做单词边界检查,会把
// `/etc/passwd-format-explanation.md` 这种合法子串也命中,造成 FP。
// 真实 l33t 变体(`/3tc/p4sswd`)会先经 normalizeText 还原成 `/etc/passwd`,
// 再被精确正则匹配,无需在 fuzzy 中重复。
const FUZZY_ATTACK_PATTERNS = [
  { pattern: 'drop table', category: 'sqlInjection', threshold: 3 },
  { pattern: 'union select', category: 'sqlInjection', threshold: 3 },
  { pattern: 'delete from', category: 'sqlInjection', threshold: 3 },
  { pattern: 'insert into', category: 'sqlInjection', threshold: 3 },
  { pattern: 'rm -rf', category: 'shellInjection', threshold: 2 },
  { pattern: 'curl | bash', category: 'shellInjection', threshold: 3 },
  { pattern: '<script>', category: 'xss', threshold: 2 },
  { pattern: 'javascript:', category: 'xss', threshold: 2 },
  { pattern: 'ignore previous instructions', category: 'protocolAttacks', threshold: 5 },
  { pattern: 'you are now', category: 'protocolAttacks', threshold: 3 },
  { pattern: 'jailbreak', category: 'protocolAttacks', threshold: 2 },
];

/**
 * 模糊匹配检测
 * 检测变体攻击，如:
 *   - "dr0p table" (数字替换字母)
 *   - "d r o p  table" (空格插入)
 *   - "DROP　TABLE" (全角字符)
 *
 * @param {string} text - 待检测文本
 * @param {object} cache - 缓存对象
 * @returns {Array} 匹配结果
 */
export function detectFuzzyAttacks(text, cache) {
  const cacheKey = `fuzzy:${text.substring(0, 200)}`;
  if (cache) {
    const cached = cache.get(cacheKey);
    if (cached) return cached;
  }

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

  if (cache) cache.set(cacheKey, matches);
  return matches;
}

export { FUZZY_ATTACK_PATTERNS, normalizeText, levenshteinDistance };
