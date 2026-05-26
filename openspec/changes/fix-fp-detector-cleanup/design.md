# Design — fix-fp-detector-cleanup

## D1 · 输入剥离 vs whitelist:为什么 fuzzy / PII 选了不同路径

Fuzzy 的 FP 全部来自 **JSON 字段名**(`description` 这个 key),与值无关 →
最干净的修法是**让 fuzzy 永远看不到 key**,即从输入剥离 JSON 语法。
这一变更对其他检测器(secrets / unicode)同样无害(它们的 pattern 都是
值层面的,字段名出现不应触发)。

PII 的 FP 完全相反 — 输入是**真邮箱**(`bob@example.org`),只是在合法字段
(`to`)出现。剥离 JSON key 没用。所以 PII 需要**工具+字段白名单**:
`mail__send.to` 合法 / `wordpress__create_post.body` 不合法。

两种修法都不引入新的语义,只是让现有检测器更"了解上下文":
- fuzzy/secrets/unicode 拿"args 全部值的纯文本"
- PII 拿"args 全部值 minus 工具白名单字段"

## D2 · `extractArgValues` 实现 — 递归 + Unicode-safe

```js
// mcp-hub/src/waf1/utils.js (新建,或追加到 index.js)
export function extractArgValues(value) {
  if (value === null || value === undefined) return '';
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  if (Array.isArray(value)) return value.map(extractArgValues).join(' ');
  if (typeof value === 'object') {
    return Object.values(value).map(extractArgValues).join(' ');
  }
  return '';
}
```

**为什么 join 用空格而不是空串**:防止值连接造成跨值 fuzzy 误命中。例:
`{a: "<scr", b: "ipt>"}` 用空串拼接成 `<script>` 就误命中了。空格能保证
8-gram 滑动窗口在值边界处不会"穿越"。

**测试需覆盖**:嵌套对象、数组、null、空字符串。

## D3 · `PII_FIELD_WHITELIST` 结构与匹配

```js
const PII_FIELD_WHITELIST = {
  // mail.* 类工具收/发邮箱字段不视为 PII 泄露
  'mail__send':         ['to', 'from', 'cc', 'bcc', 'reply_to'],
  'mail__forward':      ['to', 'from', 'cc', 'bcc'],
  'notification__send': ['to', 'recipient', 'recipients'],
  // wordpress / woocommerce 也有合法邮箱场景
  'woocommerce__create_customer': ['email'],
  'woocommerce__update_customer': ['email'],
};
```

**匹配语义**:PII 检测器接收 `{tool, args}`,先用 `extractArgValues(args)` 拿
全部值,然后在 PII 命中时反查该命中文本来自哪个 args 字段。如果命中字段
∈ `PII_FIELD_WHITELIST[tool]`,则丢弃该命中。

更简单的实现:**先剥离白名单字段**,再用 extractArgValues:
```js
function applyPIIWhitelist(tool, args) {
  const skip = PII_FIELD_WHITELIST[tool] || [];
  if (skip.length === 0) return args;
  const clone = { ...args };
  for (const f of skip) delete clone[f];
  return clone;
}
const piiText = extractArgValues(applyPIIWhitelist(tool, args));
```

这种实现更便宜(不用反查命中位置),但缺点是**只能在顶层字段做**。
对于 `mail__send.attachments[0].metadata.cc` 这种嵌套场景做不到。
考虑到当前 M-Bench-Core 的所有 mail 工具 schema 都是平的(`to/from/...` 顶层),
**采用顶层白名单方案**,等遇到嵌套需求再扩展。

## D4 · sensitiveFiles 正则边界

原:`/\/etc\/passwd/i`(子串匹配)
新:`/(?:^|[\s'"\\\/])(?:\/etc\/passwd|\/etc\/shadow|\/etc\/sudoers)(?:$|[\s'"\\\/\?\#])/i`

边界字符集:
- 前:行首 | 空白 | 引号 | 反斜杠 | **不**含 `/`,因为 `/etc/passwd-format` 的前 `/` 是边界,后面接 `-` 也不应放行
- 后:行末 | 空白 | 引号 | 反斜杠 | URL 段(`?` `#`)

**注意误打仍要修 `passwd-format-explanation.md`**:前缀 `/etc/passwd` 后跟 `-` →
新正则不命中(`-` 不在后边界字符集),正确。`/etc/passwd"` → 命中(`"` 在边界),
正确。

类似处理:`id_rsa`、`/root/.ssh/`、`/.aws/credentials`、`.kube/config` 等。

## D5 · protocolAttacks 上下文谓词

| 原始模式 | FP 案例 | 新模式 |
|---|---|---|
| `/jailbreak/i` | "How developers test for jailbreak vulnerabilities" | `/(?:^|[^a-z])(?:do|try|teach|enter|enable|let'?s\s+do|attempt)\s+(?:a\s+)?jailbreak|jailbreak\s+(?:mode|prompt|attack|technique|payload)/i` |
| `/print\s+(out\s+)?(your|the)\s+.*(instructions?|prompt|api\s+keys?)/i` | "please print your initial onboarding instructions" | `/(?:reveal|show|display|leak|tell\s+me|repeat|output|dump|expose)\s+(?:your|the)\s+(?:system\s+|hidden\s+|internal\s+)?(instructions?|prompt|api\s+keys?|system\s+prompt)/i` |

去掉 `print` 因为合法培训/客服场景频繁出现"please print"。如果未来发现真攻击
确实用 `print your prompt`,可单独加一条 `print\s+your\s+(?:system\s+)?prompt`
(`prompt` 比 `instructions` 攻击信号强很多)。

## D6 · pathTraversal 净位移逻辑

原:任何 `../` 出现 → 拦截。
新:用栈模拟解析,统计上行 / 下行段数:

```js
function isContainedRelativePath(p) {
  const segs = p.split('/').filter(s => s && s !== '.');
  let depth = 0;
  let minDepth = 0;
  for (const s of segs) {
    if (s === '..') depth--;
    else depth++;
    minDepth = Math.min(minDepth, depth);
  }
  return minDepth >= 0;  // 任意时刻不越过容器根
}
```

`templates/../static/images/banner.jpg` → segs=[`templates`,`..`,`static`,`images`,`banner.jpg`] →
depth: 1, 0, 1, 2, 3, minDepth=0 → contained。
`../../../etc/passwd` → segs=[`..`,`..`,`..`,`etc`,`passwd`] →
depth: -1, -2, -3, -2, -1, minDepth=-3 → 越界。

**仍要拦截的场景**:`/etc/passwd`(绝对路径)、`%2e%2e%2f`(URL 编码)— 这些
不走 `..` 路径,由 sensitiveFiles 和编码规则继续覆盖。

## D7 · `error.category` 补全 — 顺手修一个调试盲点

`mcp-hub/src/waf1/index.js:406` 的 Stage 5 拦截分支:
```js
return { allowed: false, status: 403, error: {
  error: "WAF1 拦截",
  reason: primary.reason,
  type: "DETECTOR_BLOCKED",
  detector: primary.detector,
  // ← 缺 category 字段
  allDetections: ...,
}};
```

补上:
```js
  category: primary.category || primary.detector,
```

这样下游 `classifyFullResult` 和 merged JSONL 就能直接看到 `pii`/`fuzzy`/`secrets`
而非 `unknown`,后续 FP 分析省一大步。这次的根因调试本来要从 reason 文本反推,
有了 category 直接 group_by 就行。

## D8 · 不做的事

- **不动 WAF2 LLM prompt** — 17 个 LLM 误判另立 change(`tune-waf2-prompt-anti-fp`),
  涉及 system prompt 工程+回归集,工作量与本次不可比。
- **不改 fuzzy threshold** — `<script>` threshold=2 在攻击侧仍有用(`<scr1pt>`、
  `<script `,变形拦截),只是不应被字段名误打。剥离 key 是更精准的修复。
- **不加 mail.body PII 白名单** — `body` 里的邮箱可能是真泄露(把客户邮箱
  通过 webhook 转发出去就是攻击),只放行 `to/from/cc/bcc`。
- **不引入新检测器**。
