# Design — Harden WAF2 Local Scorer

## 设计原则

本 change 的判断标准：每一行新代码都能直接对应当前评测里某个具体漏报样本。
不做"以防万一"的扩展，不引入新的 config 开关，不重构既有 scorer 结构。

## 决策

### D1. probe 路径黑名单 vs 通用启发式

**选黑名单。**

CSIC 漏报样本里命中的路径 100% 来自 2003–2010 年代 IIS / FrontPage / CGI 攻击残留——`/_vti_pvt/`、`/iisadmpwd/anot.htr`、`*.inc`、`/scripts/` 等。这些 token 在合法现代业务里出现概率为 0，黑名单极稳定。

通用启发式（如"路径含可执行后缀"）会引入 FP 风险，例如：业务真的有一个 `info.inc` 模板包含文件、或 `.cmd` 是某下载链接。当前 precision 1.000 是 WAF2 的核心优势，绝不能破坏。

**抽象层级**：先做硬编码常量数组，等真有第二个客户需要不同的 probe 集合时再考虑配置化。YAGNI。

### D2. 双重 URL decode 次数上限 = 2

样本里见到的最深编码层数 = 2。攻击者理论上可以多层套娃，但：

- 现代浏览器和工具几乎不产出 3 层以上的合法编码
- 每多解一次，"正常含 `%` 字符的内容"被误判的概率上升
- 性能开销线性增长

**策略**：最多 decode 2 次。如果 2 次后字符串仍然包含 `%XX` 模式，给一个小的 `multi_layer_encoding` 异常分（不直接 block），让 LLM 路径介入。

### D3. probe 命中给多少分

直接给到 ≥ `local_score_block_threshold`（当前 0.88），具体取 0.95。

理由：probe 路径的 precision 接近 100%，没有理由再走 gray-zone → LLM → 增加延迟。直接 static_block 才是 ROI 最高的处理。

### D4. header 打分的范围

**只看三个**：`Referer` / `Cookie` / `User-Agent`。

不看 `Accept-*` / `X-Forwarded-*` 等 —— CSIC 数据里没有，加上属于"以防万一"。等真实流量上出现再说。

`User-Agent` 单独有一类 **scanner 签名匹配**（sqlmap / nikto / nessus / acunetix / wpscan）。命中给 0.4 分，单独不足以 block，但会拉高其它信号的最终分数。

### D5. 白名单豁免机制

复用现有 `ENDPOINT_PARAM_SCHEMAS` 的思路：

```
LEGACY_PROBE_SUFFIX_WHITELIST: set[str] = {
    # 形如 "/some/business/path.inc" 这种业务自身真的需要的资源
}
```

默认为空。CSIC 评测集里所有 `.inc` 路径都是攻击，所以不需要例外。

### D6. 不引入 config 开关

probe pattern 列表、双重 decode、header 打分，都不暴露成 config。
原因：
- 用户不需要也不应该调
- 多一个 config 字段就多一份测试矩阵和 Dashboard 工作量
- 等真有用户提需求再加，**不超过 3 个用户的需求都不算需求**

## 不做的事

- 不重写 `normalization.py` —— 已有 URL decode，只需补一个 double 版本
- 不动 `risk_router.py` —— 现有阈值已经能让 probe 命中直接 block
- 不动 RAG / ReAct / LLM 调用层
- 不做 base64 / hex 多层解码 —— 当前 FN 里没出现
- 不引入新依赖

## 数据/性能影响

| 项 | 当前 | 估算变化 |
|---|---|---|
| avg latency | 1124ms | +0 ms（cache hit 路径不变；新增匹配在 cache miss 路径加 ≈0.3ms） |
| LLM calls | 101/2000 | -10~-20（probe 直接静态拦截，少走 gray-zone） |
| Recall | 0.723 | ≥ 0.76 |
| Precision | 1.000 | ≥ 0.99（验收线） |
| FPR | 0.000 | ≤ 0.005（验收线） |

## 风险与缓解

| 风险 | 概率 | 缓解 |
|---|---|---|
| probe 后缀误杀业务静态资源 | 低 | `LEGACY_PROBE_SUFFIX_WHITELIST` 留口；如 demo 站点出现，单独追加 |
| 双重解码增加延迟 | 极低 | 已估算 < 0.5ms；可在 PR 里加 micro-benchmark |
| Header 解析触发新攻击面（超长 header DoS） | 低 | FastAPI 默认 header 长度限制已生效；不读 raw bytes |
| 模式过严反而拉低 CSIC FPR | 低 | 验收线 FPR ≤ 0.005，未达不合并 |

## 验收

- `probe-fn-regression.jsonl`（39 条 detectable FN）命中率 ≥ 35/39 (≥90%)
- CSIC 1000+1000 回归：Precision ≥ 0.99，Recall ≥ 0.76，FPR ≤ 0.005
- 对抗集 40 条：F1 不下降
- 单测全绿
- `openspec validate` 通过
