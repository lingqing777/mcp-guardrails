/**
 * WAF1 通用工具
 *
 * `extractArgValues`:把任意 args 对象/数组递归拍平成纯文本(仅值,不含 key)。
 * Stage 5 detectors(fuzzy / secrets / unicode)用此函数获取扫描输入,
 * 避免 JSON 字段名(如 `"description"`)被错误地匹配为攻击模式
 * (例:`<script>` threshold=2 + `description` 的 8-gram `escripti` 距离正好 2)。
 *
 * 值之间用空格连接 — 防止跨值 8-gram 误命中:
 *   {a:"<scr", b:"ipt>"} → "<scr ipt>"(含空格),不会误匹配 <script>。
 */

export function extractArgValues(value) {
  if (value === null || value === undefined) return '';
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  if (Array.isArray(value)) {
    return value.map(extractArgValues).filter(s => s).join(' ');
  }
  if (typeof value === 'object') {
    return Object.values(value).map(extractArgValues).filter(s => s).join(' ');
  }
  return '';
}
