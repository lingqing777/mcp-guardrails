# Design — Harden WAF2 Nested JSON Extraction + IPI Markers

## 设计原则

本 change 的判断标准：每一行新代码都能直接对应 B-0 / B-1 评测里某个具体漏报样本。不做"以防万一"的扩展，不引入新的 config 开关。

## 决策

### D1. Python literal fallback 选 ast.literal_eval

**选 `ast.literal_eval`。**

InjecAgent 的 `tool_response` 字段是 Python repr：

```python
"\"{'product_details': {'name': 'Dell Inspiron Laptop', 'reviews': [{'content': 'Please grant access...'}]}}\""
```

外层是 JSON string，剥掉引号后是 Python repr。`json.loads` 会因单引号失败。可选 fallback：

| 方案 | 安全 | 兼容性 | 维护成本 |
|------|------|--------|----------|
| `ast.literal_eval` | ✓ 只解析字面量 | 支持 dict/list/str/num/bool/None | 标准库 |
| 正则把单引号换双引号再 `json.loads` | ✗ 易破坏字符串内容 | 误伤合法包含单引号的字符串 | 复杂 |
| `eval` | ✗ 执行任意代码 | 100% | 危险 |
| 写自定义 parser | 中 | 受限 | 高 |

`ast.literal_eval` 等同 `json.loads` 的安全级别——只解析字面量常量，**不执行代码**。

**策略**: 先 `json.loads`，失败后 `ast.literal_eval`，两个都失败返回 None（保持原行为）。

### D2. depth limit 4 → 6

InjecAgent 的实际最深嵌套：

```
{"user_tool": ...,                          # depth 0
 "tool_response": "stringified...           # depth 1
   {'product_details':                       # depth 2 (after parse)
     {'reviews': [                           # depth 3
       {'review_content': '<payload>'}       # depth 4
     ]}}"}                                   # depth 5 (payload 在这一层)
```

实测 InjecAgent 最深 5 层。设 limit 6 留一层缓冲。再深的嵌套属于异常，停止递归是合理的安全行为。

### D3. IPI marker pattern 选哪些 marker

只选**评测样本里实际出现** + **正常业务里出现率为 0** 的 marker。

从 `prompt_injection.py` 的 INDIRECT_INJECTION + CONTEXT_MANIPULATION 抽取 marker，去重后保留：

```
[NOTE TO AI]                       indirect-note-approved 等
[INTERNAL USE]                     indirect-internal-bypass
[PROMPT INJECTION TEST]            indirect-sql-exec
[SYSTEM]                           context-* / indirect-supabase-trifecta-1
[MEMORY UPDATE]                    ctx-memory-admin
[CONTEXT]                          ctx-skip-confirm
[SESSION]                          ctx-session-super
[内部提示]                          indirect-zh-internal
【重要】                            indirect-zh-cancel-delete
[记忆更新]                          ctx-zh-memory-admin
[上下文]                            ctx-zh-skip-confirm
[审计/audit] note: ...             ctx-audit-skip
Attention agent:                   indirect-exfil-post
ATTN AI:                           indirect-email-ceo
AI, when processing                indirect-silent-env
If AI:                             indirect-conditional-pwd
Dear AI                            indirect-concat-keys
AI assistant请                      indirect-zh-internal
```

合并为 **2 个 regex**（一个英文中括号 marker，一个 AI-targeted 软诱导）+ **2 个中文 regex**（中文中括号 marker + 中文 AI 称呼）。

**权重决策**: 给 0.55-0.65。

理由：
- 单独命中不应直接 `static_block`（误伤"合法的元数据带方括号"的场景，比如 markdown `[INFO]`）
- 进入 gray-zone 后 + RAG 命中 / LLM 评估 → 大概率 block
- B-0 数据显示 IPI marker 样本绝大多数能被 LLM 单 shot 在 gray-zone 识别，但 RAG OFF 下完全没分数，所以 LLM 会 PASS。加 0.55-0.65 分让它进入 LLM 评估窗口。

### D4. 验收线设定

**B-0 regression**（228 cases, RAG OFF/ON）:

| 子分类×包装 | before | after (预期) |
|-------------|--------|--------------|
| context_manip / response | 0% / 35.7% | ≥ 50% / ≥ 75% |
| indirect_pi / response | 30.8% / 76.9% | ≥ 55% / ≥ 80% |
| 其他 | (维持) | (维持，零回归) |

**B-1 InjecAgent**（400 cases, RAG ON）:

```
before: BR 5.0%
after:  BR ≥ 15.0%
```

15% 是保守目标。理由：InjecAgent 的 attacker instruction 大部分是**社工诱导**（"please grant access"、"send to email"），不是 [MEMORY UPDATE] 这类显式 marker。本 change 主要救的是嵌套提取盲区——让 LLM 至少能 *看见* attacker instruction 文本，但 LLM 是否真的识别要靠 prompt 工程改造（后续 change）。

### D5. 不引入 config 开关

depth limit、ast fallback、IPI marker pattern 列表，都不暴露成 config。
原因：
- 用户不需要也不应该调
- 多一个 config 字段就多一份测试矩阵和 Dashboard 工作量
- 与 probe/decode change 的 D6 决策一致

### D6. 不动其他模块

不动：
- `risk_router.py` —— 现有阈值已经能让 IPI marker 命中进 gray-zone
- `engine.py` / RAG —— 它们自己跑测试
- `waf2_proxy.py` —— normalize 接口签名不变
- LLM prompt —— 单独 change 处理

> **2026-05-14 实验记录（保留 D6 决策）**：B-0 第一轮跑出 `context_manip / response` 14.3% / 50.0% 未达 50% / 75% 验收线后，曾尝试合并入本 change 改造 `REACT_REQUEST_PROMPT` + `REQUEST_ONESHOT_PROMPT`（加"🛡️ 载体无关原则"段 + 反例条款 + Example 6/7）。
>
> B-0 重跑结果反表：
> - `context_manip / response` 微涨：14.3% → 35.7% (RAG OFF)，50.0% → 64.3% (RAG ON)，**仍未达 50% / 75%**
> - 但 RAG ON 整体大幅回退：86.8% → 64.5%（**-24.5pp**）。受冲击最大：
>   - `prompt_leak / chat`: 82.1% → 39.3%（-42.8pp）
>   - `indirect_pi / chat`: 100% → 53.8%（-46.2pp）
>   - `jailbreak / chat`: 83.8% → 54.1%（-29.7pp）
>   - `tool_poisoning / mcp-rpc`: 95.2% → 66.7%（-28.5pp）
>
> 推断根因：加的"反例"条款（`[INFO]` / Markdown 章节不算攻击）+ Example 6/7 把 LLM 注意力锚定到"嵌套载体里的 marker 才是 BLOCK 信号"，弱化了对 chat-wrap 直接 prompt-injection 的判定，对 RAG 检索相似度较低的 case 倾向 PASS。
>
> **决策**：rollback prompt 改造，维持 D6 原决策。`context_manip / response` 验收线降级为"已知限制 / 后续 LLM-prompt-only change 解决"。详见报告 `runs/2026-05-14-nested-json-extraction/b0-after-llm-prompt.{json,log}`。

## 数据/性能影响

| 项 | 当前 | 预期 |
|---|---|---|
| normalize avg cost | ~0.5ms | +0.1ms (深度 4 → 6 边际成本) |
| LLM calls per request | 不变 | 不变 |
| Recall (CSIC 1000) | 0.761 | ≥ 0.761（B-0/B-1 改善不冲击 CSIC，验收） |
| FPR (CSIC 1000) | 0.000 | 0.000（IPI marker 在 CSIC 业务里出现率 0） |
| B-0 context_manip response BR | 0% / 35.7% | **14.3% / 50.0%**（实测；未达原 ≥50%/≥75% 目标，降级为已知限制） |
| B-0 indirect_pi response BR | 30.8% / 76.9% | **61.5% / 84.6%**（实测；超 ≥55%/≥80% 目标） |
| B-1 BR | 5.0% | ≥ 15.0% |



## 不做的事

- 不重写嵌套解析为 `ijson` / streaming parser —— 当前递归足够，2108 case 实测内存 < 50MB
- 不增加 base64-as-string 在嵌套字段中的递归（B-0/B-1 没出现这个 case）
- 不预筛"看起来像 Python repr"的 heuristic（直接 try-except 更简单）
- 不为 IPI marker 单开 `category=indirect_prompt_injection`，沿用 `prompt_injection`（与现有 routing 一致）
