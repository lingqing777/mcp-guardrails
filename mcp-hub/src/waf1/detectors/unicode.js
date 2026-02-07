/**
 * Unicode 异常检测器
 * 移植自 Invariant runtime/utils/prompt_injections.py UnicodeDetector
 * 检测隐藏字符、零宽字符等 prompt injection 绕过手段
 */

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
 * 检测文本中的异常 Unicode 字符
 * @param {string} text - 待检测文本
 * @param {object} cache - 缓存对象
 * @returns {Array} 异常字符列表
 */
export function detectUnicodeAnomalies(text, cache) {
  const cacheKey = `unicode:${text.substring(0, 200)}`;
  if (cache) {
    const cached = cache.get(cacheKey);
    if (cached) return cached;
  }

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

  if (cache) cache.set(cacheKey, anomalies);
  return anomalies;
}

export { SUSPICIOUS_UNICODE_RANGES };
