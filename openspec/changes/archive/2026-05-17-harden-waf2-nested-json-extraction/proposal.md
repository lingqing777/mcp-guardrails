# Harden WAF2 Nested JSON Extraction + IPI Markers

## Why

方向 2 路径 B-0 / B-1 评测（`waf2/rag/eval/runs/2026-05-13-prompt-injection/`、`runs/2026-05-13-injecagent/`）显示 WAF2 在 LLM 时代攻击模型下两个具体盲区：

- **B-0 response wrap** — `{"issue": {"body": "<payload>"}}` 嵌套 JSON 中的 prompt-injection payload
  - context_manipulation: 0% (RAG OFF) / 35.7% (RAG ON)
  - indirect_pi: 30.8% (OFF) / 76.9% (ON)
- **B-1 InjecAgent 1054 cases** — `tool_response` 字段是 Python repr 字符串（单引号 dict）嵌套 attacker instruction
  - 总 BR = 5.0%, ASR = 95.0% (4 splits × 100 cases)
  - 所有 5% block 都被误识别为 `command_injection`（attacker instruction 里偶然含 SQL/shell 关键字），没一个被正确识别为 `prompt_injection`

两个 root cause：

1. **Python repr 嵌套不解析** — `_try_parse_json` 只支持合法 JSON。InjecAgent 的 `tool_response` 是 Python repr `"{'product_details': {...}}"` 单引号，`json.loads` 失败，嵌套字段不进 `analysis_text`。
2. **IPI marker patterns 缺失** — `local_attack_score` 的 `prompt_injection` 已覆盖 `ignore previous` / `DAN` / `jailbreak` / 中文变体，但 `[MEMORY UPDATE]` / `[CONTEXT]` / `[SESSION]` / `[NOTE TO AI]` / `[INTERNAL]` / `[SYSTEM]` / `attention agent` 这类 IPI marker 完全无 pattern → context_manipulation 在 RAG OFF 下 0%。

修这两个 root cause 预计：

- B-0 context_manip response wrap: 0% (OFF) → ≥ 50%；35.7% (ON) → ≥ 75%
- B-0 indirect_pi response wrap: 30.8% (OFF) → ≥ 55%
- B-1 InjecAgent BR: 5% → ≥ 15%（含 IPI marker 的样本，社工类纯诱导仍需 ReAct/session 改造，不在本 change 范围）
- 零 FP 风险 — pattern 都是高 precision marker，正常业务里出现概率为 0

## What Changes

1. 在 `waf2/normalization.py` 让 `_try_parse_json` 增加 `ast.literal_eval` 作为 fallback：合法 JSON 优先，失败后尝试解析 Python literal（typically dict/list with single quotes）。
2. 在 `waf2/normalization.py` 把 `_collect_json_strings` 的 depth limit 从 4 提到 6，覆盖 InjecAgent 4 层 + 安全余量。
3. 在 `waf2/local_attack_score.py` 的 `prompt_injection` 类别新增 IPI marker patterns（中括号系统消息伪装 + AI-targeted 软诱导词）。
4. 在 `waf2/tests/test_local_pipeline.py` 增加：
   - 嵌套 JSON depth 5/6 提取测试
   - Python repr 字符串解析测试
   - 复合：JSON 包 JSON-as-Python-repr 包嵌套 dict
   - IPI marker 单测（中括号系统消息伪装、AI 软诱导词、正常业务无误报）
5. 不动 RAG / ReAct / LLM prompt — 它们是独立的后续 change（已在 B-1 报告里列为 P0/P1）。

## Capabilities

### Modified Capabilities

- `waf2-local-attack-scoring`: 增加 nested JSON-as-string extraction（含 Python literal fallback）、IPI marker scoring 两类 Requirements

## Impact

- **Affected WAF2 code:**
  - `waf2/normalization.py`: `_try_parse_json` 增加 fallback、depth limit 提升
  - `waf2/local_attack_score.py`: 新增 IPI marker patterns（≈ 6 条 regex）
  - `waf2/tests/test_local_pipeline.py`: 新增 ≈ 8 条单测
- **评测**:
  - 复用 `waf2/rag/eval/prompt-injection-eval.jsonl`（228 cases，B-0）作为回归集
  - 复用 `waf2/rag/external/InjecAgent/data/`（400 cases，B-1）作为外部 baseline
  - 新增 `waf2/rag/eval/runs/<dated>-nested-json-extraction/` before/after 报告
- **配置**: 不新增 config 字段。Depth limit 是常量（6），ast fallback 默认开启。
- **风险**:
  - Python literal eval 安全性：`ast.literal_eval` 只解析常量字面量（dict / list / tuple / str / number / bool / None），不执行代码。等同 `json.loads` 的安全级别。
  - depth limit 提升的性能影响：单次请求成本由 normalize 阶段决定，递归 6 层在最坏 case 增加 < 1ms。
  - IPI marker 假阳性：中括号系统消息（`[MEMORY UPDATE]` 等）在合法业务里几乎不出现；如有特例可走现有 endpoint whitelist 机制。
- **不在范围内**:
  - ReAct prompt 改造（独立 change）
  - KB 扩充以覆盖 InjecAgent 风格的"埋在合法内容里"样本（独立 change）
  - LLM 单 shot 提示工程
  - Session/dataflow 状态追踪
