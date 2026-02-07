/**
 * PII 检测器
 * 移植自 Invariant stdlib/detectors/pii.py
 * 原始来源: Microsoft Presidio
 */

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
 * 检测文本中的 PII (个人身份信息)
 * @param {string} text - 待检测文本
 * @param {object} cache - 缓存对象
 * @returns {Array} 匹配结果
 */
export function detectPII(text, cache) {
  const cacheKey = `pii:${text.substring(0, 200)}`;
  if (cache) {
    const cached = cache.get(cacheKey);
    if (cached) return cached;
  }

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

  if (cache) cache.set(cacheKey, matches);
  return matches;
}

export { PII_PATTERNS };
