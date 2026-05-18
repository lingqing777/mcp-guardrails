# Harden WAF2 ReAct Fallback with RAG Rescue

## Why

`add-waf2-eval-failure-analysis-loop` 给 B-0 RAG-ON 的 69 个失败做了结构化归因。其中一个最干净、最可独立解决的 bucket 是 **R9 `react_fallback_pass`**：

```
B-0 RAG-ON 失败 69 拆解 (228 case, BR 80.7%):
  R7 miscat        25   ← static_block 抢拦但归错类 (不动 BR)
  R2 local_score_low 17 ← local_llm_one_shot 路径 PASS
  R9 react_fallback  16  ← ReAct 跑完 4 步无 verdict → fallback 默认 PASS
  R3 rag_miss      10   ← KB 命中分 < 0.55 (这 change 不解)
  R4 rag_wrong     1
```

**R9 的本质**：ReAct LLM 进了深推理（说明 router 认为这是"高 RAG 命中 + 高风险类别"），但输出格式没产出 `final_answer`（典型：思路写一堆但漏 `verdict: blocked` 行）。`run_react_agent` 返回 `None`，调用方走 fallback → 默认 PASS。

**关键观察**：16 个 R9 case 全部 `rag_used=True`，14 个 (87.5%) RAG `cat=prompt_injection ∩ score≥0.55`。这意味着 RAG 检索本身命中了原样 KB 样本、类别也是对的，**只是这个证据没被 LLM 用上**。fallback 默认 PASS 等于**忽略了 KB 已有的强信号**。

**为什么先解 R9 不解 R2 / R5**：
- R9 在 ReAct fallback 这个独立小路径上，影响面**只在一个 `if final is None` 分支**，不动 LLM 主流。
- 不绕过任何 LLM gating —— 因为这条路径里 LLM 已经"放弃"了。RAG 救回的判决取代的是 fallback 默认值，不是 LLM 的明示判决。
- 风险面最小，可作为后续更激进改动（变体 B `RAG-as-score-boost` / 变体 A `RAG-direct-block`）的前置验证。

**预期 ROI**：R9 16 → 0~2，B-0 RAG-ON BR 80.7% → 87% (228 case 中救回 14)。CSIC 100 RAG-ON FPR 应保持 0（fallback rescue 只在 LLM 已经认输时触发，对 normal traffic 影响接近零）。

## What Changes

1. **`run_react_agent` 失败后增加 RAG rescue 分支** — 当 `run_react_agent` 返回 `None`（达到 max_iters 未 final_answer，或单步 parse 失败）且 RAG 已命中（`rag_used=True ∧ rag_top_score ≥ K ∧ rag_top_category ∈ rescue_categories`），fallback 决策从 `PASS` 改为 `BLOCK with category=rag_top_category`。
2. **配置开关 + 阈值常量**：
   - `rag_decisive_fallback_enabled` (default `True`)：总开关，false 时完全 no-op，行为与现状一致。
   - `rag_decisive_fallback_min_score` (default `0.55`)：触发救援的 `rag_top_score` 下限。低于此值不救。
   - `rag_decisive_fallback_categories` (default `{"prompt_injection"}`)：允许救援的 RAG top category 白名单。其他类别（command_injection / sql_injection 等）默认不救，避免子串误匹配引起的 FP。
3. **诊断信号** — `X-Waf2-Route` 在救援触发时新增枚举值 `react_fallback_rag_rescue`，`X-Waf2-Reasons` 含 `rag_decisive_fallback`。eval 脚本和 `label_failures.py` 据此区分新路由路径。
4. **`label_failures.py` 加 R10 规则** — 当 `outcome=blocked ∧ route=react_fallback_rag_rescue` 时，标 `layer=react_rescued, fix_hint=(none, monitored)`。这条规则用来识别"被本 change 救回的 case"。
5. **ReAct fallback 路径在 response analysis (`agent_analyze_response`) 同样应用** — RAG-augmented response 检测也走 fallback，对称。

## Capabilities

### Added Capabilities

- `waf2-rag-enforcement` — 一个新的、专门描述 "RAG 信号如何被采纳成决策" 的能力。本次 change 是它的第一个 requirement set：ReAct fallback rescue。后续变体 B / 变体 A 都会向这个 capability 增量。

## Impact

- **Affected production code**:
  - `waf2/waf2_proxy.py`: 修改 `run_react_agent` 调用方（`agent_analyze_request` / `agent_analyze_response`），把 None fallback 改成"尝试 RAG rescue → 仍 None 才 PASS"。新增 helper `_rag_decisive_rescue(rag_meta, direction)` 返回 `Optional[detection_result]`。
  - `waf2/waf2_proxy.py`: `Config` 增 3 个字段（默认开），`/waf2/config` 接受 update。
- **Affected eval code**:
  - `waf2/rag/scripts/label_failures.py`: 新增 R10 `react_rescued` 规则，priority 在 R7 之后 R1 之前。
  - `waf2/rag/scripts/build_failure_report.py`: `FIX_TO_CHANGE` 表加 `(monitored): harden-waf2-react-fallback-rag-rescue (this)` 条目。
- **不动**:
  - Router 决策逻辑（routes 之间的分配规则不变；只动 fallback 后的兜底）
  - LLM prompt 模板
  - RAG retrieval / KB 内容
  - local_attack_score
  - 任何生产侧默认行为之外的路径（rag_decisive_fallback_enabled=false 时完全等价于不部署本 change）
- **风险**:
  - **FP 风险**：fallback rescue 把"LLM 放弃判决"的 case 改成 BLOCK。若 normal traffic 的某条恰好 RAG 命中 cat=PI ≥0.55 且 ReAct parse 失败，将变成 FP。CSIC 1000 历史数据显示 23 RagHit + 0 FP，但那是 LLM gating 后的数字；本 change 在 LLM gating **失败**时介入，理论上 FP 上限是 "normal RAG cat=PI ≥0.55 且 LLM parse fail" 的合集——目前未量化。验收线：CSIC 100 RAG-ON FPR ≤ 0.005（即 100 normal 上 ≤ 0 FP，CSIC 100 阈值粒度只允许 0）。
  - **category 白名单收紧带来的 ROI 损失**：B-0 16 R9 里有 2 个 `rag_top_category` 不是 prompt_injection（按 design 数据：14 PI / 16 总）。本 change 默认不救这 2 个，保守换稳。
  - **route 枚举扩展**：`X-Waf2-Route` 新增 `react_fallback_rag_rescue`。下游消费者（eval 脚本、dashboard、label_failures）需要识别这个新值。
- **不在范围内**:
  - 变体 B (RAG-as-score-boost) / 变体 A (RAG-direct-block) — 留待后续 change
  - 改 R2 / R3 / R7 — 各有其他 fix_hint 桶对应
  - 跑 CSIC 1000 验收（验收线只跑 CSIC 100；CSIC 1000 留给后续聚合实验）
  - 跑 B-1 RAG-ON（B-1 还没建立 RAG-ON baseline）
