## Context

WAF2 当前主线已经包含：

- 静态规则层：明显 SQLi/XSS/Path Traversal/SSRF/Command Injection 等直接拦截
- 关键词/敏感模式层：轻量检测与缓存
- RAG 层：3354 条攻击知识库，`all-MiniLM-L6-v2` ONNX embedding + ChromaDB
- ReAct/COT 层：`decode_base64`、`url_decode`、`decode_hex`、`decode_unicode`、`rag_search` 工具
- 当前默认参数：`RAG_THRESHOLD=0.60`，`RAG_CONFIDENCE_THRESHOLD=0.50`，`RAG_TOP_K=5`

初步快测显示 RAG + ReAct 相比 ReAct-only 可以提升 Recall/F1，但 ReAct 也明显增加延迟。后续不能直接大规模测模型，因为当前链路中规则、RAG、ReAct、工具调用和模型能力交织在一起，必须先定义可解释的数据分类和调试闭环。

## Goals / Non-Goals

### Goals

- 定义 WAF2 RAG + ReAct 的测试数据 taxonomy
- 区分 dev set 与 holdout set，避免用评估集调参导致结果虚高
- 定义每类数据的预期检测路径：static / rag_llm / rag_react / react_tool / fast_pass
- 定义 failure analysis 分类，让每次误报/漏报都能定位到具体原因
- 定义 ReAct 进入量控制目标，减少普通请求进入深度推理
- 定义多模型测试矩阵，固定架构后再比较模型

### Non-Goals

- 不在本 change 中实现 ReAct entry gate
- 不在本 change 中扩充知识库
- 不在本 change 中替换 embedding 模型或引入 reranker
- 不在本 change 中归档现有 RAG 打包 change

## Testing Taxonomy

测试数据分 8 类，每类有不同目的和预期路径。

```
┌────────────────────────────────────────────────────────────┐
│                    WAF2 测试数据分类                       │
├────────────────────────────────────────────────────────────┤
│  1. Classic Web Attacks                                    │
│  2. Obfuscated / Encoded Attacks                           │
│  3. Prompt Injection / Jailbreak                           │
│  4. MCP / Tool Poisoning                                   │
│  5. Data Exfiltration / Lethal Trifecta                    │
│  6. Sensitive Response Leakage                             │
│  7. Benign Hard Negatives                                  │
│  8. Normal Business Traffic                                │
└────────────────────────────────────────────────────────────┘
```

### 1. Classic Web Attacks

Examples: SQLi, XSS, Command Injection, Path Traversal, SSRF, XXE.

Expected path:

```
Classic Web Attack → Static Rules / Keywords → BLOCK
```

Purpose:

- Confirm fast-path coverage
- Ensure obvious attacks do not waste ReAct iterations
- Measure static-rule precision/recall baseline

### 2. Obfuscated / Encoded Attacks

Examples: Base64 command, URL double encoding, Unicode escape, hex encoding, overlong UTF-8, zero-width/homoglyph variants.

Expected path:

```
Encoded Payload → cheap encoding signal → ReAct tool call → BLOCK/PASS
```

Purpose:

- Validate `decode_base64` / `url_decode` / `decode_unicode` tools
- Tune ReAct entry gate
- Detect loops where Agent repeatedly calls tools without reaching final_answer

### 3. Prompt Injection / Jailbreak

Examples: direct prompt injection, indirect injection, jailbreak, system prompt leak, translation disguise, academic disguise.

Expected path:

```
Prompt Injection → RAG evidence → Evidence Review → BLOCK prompt_injection
```

Purpose:

- Validate RAG evidence usefulness
- Ensure LLM references retrieved evidence instead of ignoring it
- Cover English and Chinese prompts

### 4. MCP / Tool Poisoning

Examples: malicious tool description, tool squatting, tool argument injection, resource poisoning, prompt poisoning, sampling abuse.

Expected path:

```
MCP Tool Payload → RAG tool_poisoning evidence → ReAct reasoning → BLOCK
```

Purpose:

- Demonstrate MCP/Agent-specific value beyond traditional WAF
- Validate tool description as an attack surface
- Detect whether ReAct understands JSON-RPC / MCP semantics

### 5. Data Exfiltration / Lethal Trifecta

Examples: read sensitive data, write to public table, send outputs to attacker endpoint, Supabase lethal trifecta patterns.

Expected path:

```
Seemingly legitimate tool/data operation → RAG data_exfiltration evidence → ReAct reconstructs intent → BLOCK
```

Purpose:

- Validate attack-chain intent recognition
- Measure whether RAG helps when no classic SQLi/XSS signature exists

### 6. Sensitive Response Leakage

Examples: API keys, JWTs, private keys, `.env`, database URLs, password hashes, internal IPs, stack traces.

Expected path:

```
Response leakage → deterministic detector / sensitive regex → BLOCK
Encoded leakage → ReAct decode tool → BLOCK
```

Purpose:

- Keep response-side detection mostly deterministic
- Only use ReAct for encoded or ambiguous leakage

### 7. Benign Hard Negatives

Examples: SQL tutorial text, XSS classroom discussion, normal `password_hash` field, "ignored previous draft" text, security report quoting payloads.

Expected path:

```
Looks attack-like but benign → evidence conflict review → PASS / INCONCLUSIVE
```

Purpose:

- Measure false positive pressure
- Detect over-aggressive static rules and over-trusting RAG
- Tune context-aware exceptions

### 8. Normal Business Traffic

Examples: login, order query, cart update, comments, product search, normal MCP tool call.

Expected path:

```
Normal traffic → fast pass / cheap checks → no ReAct
```

Purpose:

- Measure ReAct entry rate on normal traffic
- Measure latency/cost baseline

## Dataset Structure

Each JSONL sample SHOULD include:

```json
{
  "id": "pi-indirect-supabase-001",
  "label": "attack",
  "category": "prompt_injection",
  "subcategory": "indirect_prompt_injection",
  "method": "POST",
  "path": "/api/notes",
  "body": "...",
  "expected_decision": "BLOCK",
  "expected_category": "prompt_injection",
  "expected_path": "rag_react",
  "needs_rag": true,
  "needs_react": false,
  "needs_tool": false,
  "hard_negative": false,
  "source": "manual",
  "rationale": "Indirect instruction tries to alter agent behavior"
}
```

Important fields:

- `expected_path`: `static`, `fast_pass`, `rag_llm`, `rag_react`, `react_tool`, `detector`
- `needs_rag`: whether retrieval evidence is expected to matter
- `needs_react`: whether multi-step reasoning is expected
- `needs_tool`: whether a decode/tool call is expected
- `hard_negative`: whether this is benign but attack-shaped

## Dev Set / Holdout Set Split

```
Dev Set
  用于调 prompt、阈值、ReAct entry gate、工具调用策略、KB 补充方向
  可以反复看失败样本

Holdout Set
  用于最终证明效果
  不允许把样本写入 KB
  不允许根据具体失败样本继续调参
```

Initial recommended size:

| Set | Size | Purpose |
| --- | ---: | --- |
| Dev v1 | 150-200 | Tune routing and failure analysis |
| Holdout v1 | 80-120 | Validate final architecture |
| Smoke | 10-20 | Fast sanity checks after code changes |
| CSIC sample | 100/200/500 | Real web-traffic baseline |

## Failure Analysis

Each false positive / false negative MUST be classified:

```
┌────────────────────────────────────┐
│  Failure Cause                      │
├────────────────────────────────────┤
│  A. Did not enter RAG               │
│  B. RAG retrieved wrong evidence    │
│  C. RAG evidence was ignored        │
│  D. Did not enter ReAct             │
│  E. Entered ReAct but tool not used │
│  F. Tool used but observation ignored│
│  G. Static rule false positive      │
│  H. LLM output / parse failure      │
└────────────────────────────────────┘
```

Mapping to tuning action:

| Cause | Likely Action |
| --- | --- |
| A | Tune `rag_input`, `RAG_THRESHOLD`, `RAG_CONFIDENCE_THRESHOLD` |
| B | Improve KB, metadata, category filtering, or future reranker |
| C | Strengthen Evidence Review prompt / require evidence_ids |
| D | Tune ReAct entry gate |
| E | Add stronger tool-use instruction for encoded samples |
| F | Require final_answer to cite Observation |
| G | Add context exception or route hard negative to LLM review |
| H | Improve JSON parser / retry / strict prompt |

## ReAct Entry Targets

The goal is not to maximize ReAct usage. The goal is to use ReAct where it adds value.

Target rates:

| Data Class | Desired ReAct Entry |
| --- | ---: |
| Normal Business Traffic | < 5% |
| Classic Web Attacks | < 10% |
| Encoded / Obfuscated | > 70% |
| MCP / Tool Poisoning | > 50% |
| Prompt Injection / Jailbreak | 20-40% |
| Sensitive Response Leakage | mostly detector-only; ReAct only for encoded/ambiguous |

## Proposed WAF2 Routing Model

```
┌──────────────────────────────────────────────────────────────┐
│                        WAF2 Pipeline                          │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  0. Static Rules                                              │
│     明确攻击直接 BLOCK                                        │
│                                                              │
│  1. Cheap Signal Extraction                                   │
│     path/body/tool字段/编码迹象/RAG top_score                 │
│                                                              │
│  2. Risk Router                                               │
│                                                              │
│       ┌───────────────┬───────────────────┬────────────────┐ │
│       ▼               ▼                   ▼                │ │
│   Low Risk        Medium Risk          High Risk            │ │
│   PASS / Cache    RAG + LLM            RAG + ReAct          │ │
│                   one-shot             tools + COT          │ │
│                                                              │
│  3. Decision                                                  │
│     PASS / BLOCK / INCONCLUSIVE                              │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

This model is a design target for a future implementation change. Current change defines how to evaluate whether the routing is correct.

## Metrics

### Detection Metrics

- Precision
- Recall
- F1
- FPR
- TP / FP / TN / FN

### Path Metrics

- `static_blocks`
- `rag_queries`
- `rag_augmented`
- `rag_gated`
- `react_entered`
- `tool_called`
- `tool_iterations`
- `inconclusive_count`

### Performance Metrics

- Average latency
- p95 latency
- max latency
- LLM calls per request
- Agent iterations average

### Quality Metrics

- `evidence_used_correctly`
- `wrong_category`
- `format_error`
- `llm_error`
- `parse_failed`

## Model Evaluation Strategy

Do not start with a full matrix. First stabilize the architecture.

### Round 1: Architecture Validation

- Model: `glm-4-flash`
- Modes:
  - LLM only
  - RAG + LLM
  - ReAct only
  - RAG + ReAct
- Datasets:
  - Classic/Prompt/MCP focused dev set
  - Adversarial set

### Round 2: Model Comparison

- Models:
  - `glm-4-flash`
  - `Qwen/Qwen2.5-7B-Instruct`
  - GPT mini-class model
  - Claude Haiku-class model
  - DeepSeek Chat-class model
- Mode: fixed architecture after routing design
- Datasets:
  - CSIC sample
  - MCP custom holdout
  - Benign hard negatives

### Round 3: Cost / Latency Analysis

For each model:

- Precision / Recall / F1 / FPR
- Average and p95 latency
- LLM calls per request
- Estimated token cost
- ReAct iteration distribution

## Risks

- If dev and holdout data are mixed, reported RAG gain will be inflated.
- If ReAct entry is not controlled, latency and cost can dominate the evaluation.
- If static rules block too early, RAG/ReAct contribution may be hidden.
- If hard negatives are underrepresented, FPR will look artificially low.
- If model comparison starts before architecture is fixed, results will be hard to interpret.

