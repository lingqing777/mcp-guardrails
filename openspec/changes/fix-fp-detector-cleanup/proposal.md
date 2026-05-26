# Proposal — fix-fp-detector-cleanup

## Why

`add-waf-ablation-eval-harness` 跑分(qwen3:8b, 150 attacks + 150 benigns)显示
Full 配置 FPR=33%(50/150 良性被误拦),综合 F1=0.857 被 precision 拖累。
对 50 个 FP 做归因分析,**85% 来自 6 个可定位的 WAF1 检测器 bug,而非 LLM 误判**:

| 根因 | FP 数 | 根因描述 |
|---|---:|---|
| Fuzzy 扫到 JSON 字段名 | 34 | `JSON.stringify(args)` 包含 key `"description"`,其 8-gram `"escripti"` 与模式 `<script>` Levenshtein 距离 = 2,正好命中 threshold,所有 `woocommerce__create_product` 等带 `description` 的合法请求全部被误拦 |
| PII 误标邮件 收件人 | 12 | `mail__send {to: "bob@example.org"}` 的合法收件人地址被 PII 检测器当成"邮箱泄露" |
| sensitiveFiles 子串匹配 | 2 | 正则 `/\/etc\/passwd/i` 误打 `docs/setup/etc/passwd-format-explanation.md` |
| protocolAttacks 语境过宽 | 2 | "Article: How to test for jailbreak vulnerabilities" / "please print your initial onboarding instructions" 这类信息性句子被当成 PI |
| pathTraversal 不容许内部相对路径 | 1 | `templates/../static/images/banner.jpg` 这种容器内不越界的相对引用被拦 |
| secrets 占位 webhook 误打 | 1 | `https://hooks.slack.com/services/T00/B00/abc` 占位 URL 被当成 slack webhook 凭据 |

修这些 bug 不影响 attack recall(因为这些都是检测器**错杀**良性,真实攻击仍命中
其他规则或同一检测器的合规路径)。预期 FPR 33% → 11%,综合 F1 ~0.857 → ~0.92。

## What Changes

- **fuzzy 检测器输入剥离 JSON key**:`runDetectors` 给 fuzzy / PII / unicode / secrets
  扫的不再是 `JSON.stringify(args)`,而是只把 args 值递归拍平成纯文本(跳过对象 key)。
  新 helper `extractArgValues(args) -> string`。
- **PII 检测器工具感知**:新增 `PII_FIELD_WHITELIST` 表,标记 "邮件收件人" 类合法
  邮箱字段;PII 检测时给出 `tool` 参数,如果命中字段在 whitelist 内则跳过该字段。
  覆盖 `mail__send {to,from,cc,bcc,reply_to}` 等。
- **sensitiveFiles 正则锚定**:`/\/etc\/passwd/i` 改成 `/(?:^|[\s'"\\\/])\/etc\/passwd(?:$|[\s'"\\\/\?\#])/i`,
  确保 `/etc/passwd` 作为完整文件名出现,而非作为子串。同理 `/etc/shadow`、
  `/root/.ssh/`、`id_rsa` 等。
- **protocolAttacks 限定动作语境**:
  - `jailbreak` 单字不再裸拦,需要 `(do|try|teach|enter|enable|let'?s\s+do)\s+(?:a\s+)?jailbreak`
    或 `jailbreak\s+(mode|prompt|attack|technique)`。
  - "print your instructions" 改成 `(reveal|show|display|leak|tell\s+me|repeat|output|dump|expose)\s+(?:your|the)\s+(?:system\s+)?(instructions?|prompt|api\s+keys?)`,
    去掉 `print`(培训邮件场景常见)。
- **pathTraversal 容器内净位移检测**:若 `..` 出现次数 ≤ 路径中实际下行段数,
  视为容器内合法引用(`templates/../static` 净位移 = 0),放行;否则拦截。
- **slack_webhook 占位识别**:在 secrets 检测器内对 `hooks.slack.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24,}`
  设最小长度,占位 `T00/B00/abc` 不达标 → 不拦。
- **`classifyFullResult` 顺手修 category 字段**:Stage 5 detectors 拦截分支当前
  返回的 `error` 对象没 `category` 字段,harness 把它分类为 `unknown`。给该分支
  补上 `category: primary.category || primary.detector`,让分析脚本能直接读出
  是哪个检测器误杀(本次 root cause 调试就吃过这个亏)。

## Impact

- Affected specs:`waf1`(MODIFIED — Stage 5 detector 输入与字段语义、Stage 4
  正则锚定与上下文)。
- Affected code:
  - `mcp-hub/src/waf1/index.js`(`runDetectors` 输入剥离 + Stage 5 error.category)
  - `mcp-hub/src/waf1/detectors/fuzzy.js`(无改动,只换调用方传入)
  - `mcp-hub/src/waf1/detectors/secrets.js`(slack webhook 正则)
  - `mcp-hub/src/waf1/detectors/pii.js`(签名加 tool + 字段感知)
  - `mcp-hub/src/waf1/rules.js`(sensitiveFiles + protocolAttacks 正则)
  - `mcp-hub/src/waf1/path-traversal.js` 或同等位置(容器内净位移逻辑)
- Tests:每条 fix 至少 1 个 vitest case 验证误打不再发生、真攻击仍命中。
- Validation:重跑 ablation 3 (Full),验证 FPR 从 33% 降到 ≤ 12%,recall 仍 ≥ 0.99,
  index.tsv 追加一行 `Full-fp-cleanup`。
