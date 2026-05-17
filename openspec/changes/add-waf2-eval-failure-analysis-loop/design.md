# Design — Add WAF2 Eval Failure Analysis Loop

## 设计原则

- **每条规则、每个 schema 字段都能映射到一个具体诊断问题**。不做"以防万一"的扩展。
- **数据流单向、零状态**：WAF2 通过 response header 透出 eval 信号 → eval 脚本写 JSONL → 派生脚本只读 JSONL。中间不存数据库、不开 endpoint。
- **派生与原始分离**：`cases-*.jsonl` (immutable raw) vs `labels-*.jsonl` (从 cases 派生，改规则可重跑)。
- **不动生产**：所有 WAF2 改动都在 `eval_mode=true` 分支内。

## 决策

### D1. 信号传输 — X-Waf2-* response header（不是新 endpoint）

**选 response header**。理由：

| 方案 | 状态 | 改动 | 时序 |
|---|---|---|---|
| ✅ X-Waf2-* response header | 单向、零状态 | ~10 行 waf2_proxy.py | 同步、无丢失 |
| `/waf2/dashboard/eval-trace` endpoint | 需要内存 buffer | ~50 行 + 并发处理 | 异步、可能丢条 |
| 直接读 stderr 日志 | 零侵入 | 解析复杂、case 关联难 | 高耦合到 log 格式 |

Header 长度上限：单 header ≤ 256 bytes（保守 HTTP 兼容），多字段拆多 header。`local_score_breakdown` 只取 top-3 非零类别；`rag_top_text` 不传（要全文看 stderr）。

完整 header 集（eval_mode=true 时附加）：

```
X-Waf2-Eval-Mode: true
X-Waf2-Outcome: blocked|passed
X-Waf2-Detected-Category: prompt_injection|<empty>
X-Waf2-Local-Score-Total: 0.250
X-Waf2-Local-Score-Top: prompt_injection:0.250,json_fragments:0.0
X-Waf2-Rag-Used: true|false
X-Waf2-Rag-Top-Score: 0.452
X-Waf2-Rag-Top-Category: jailbreak
X-Waf2-Route: local_llm_one_shot|fast_pass|static_block|react_deep_inspection
X-Waf2-Reasons: local_score=0.250|json_fragments
X-Waf2-Normalize-Meta: depth=5,frags=20,decoded=ast,b64=0
X-Waf2-Latency-Ms: 1240
```

### D2. case 记录范围 — FN + FP + ambiguous

不记 TN/TP 全量，理由：

- **诊断价值**：我们要"为什么失败"，TN/TP 是"成功"，对 layer/cause 标签无贡献。
- **存储成本**：CSIC 1000 全记 ≈ 500KB/run × 多 round；只记 FN+FP+ambig 约 30% 大小。
- **未来需要 score 分布**：单独跑一次"全记 mode"即可，不污染常规 loop。

**ambiguous 严格定义**：

```
case 进 cases-*.jsonl ⟺
  (outcome != expected)                               # FN 或 FP
  OR (outcome == passed AND (
      local_score_total >= 0.40                       # 接近 gray_threshold 0.35 之上
      OR rag_top_score >= 0.55                        # 接近 RAG block 阈值 0.60 之下
      OR llm_parse_failed == true                     # pipeline 异常单标
  ))
```

`0.40` / `0.55` 这俩阈值是当前 `risk_router` 的 gray_threshold/rag_threshold 的"靠近但未触发"档，可用 eval-only config 调整，不暴露成 production config。

### D3. auto-推导规则 R1~R8

每条规则形如 `(条件) → (layer, cause-hint, fix-hint, confidence)`。规则顺序即优先级，第一个匹配即停。

```
R1  normalize_miss
    IF normalize_meta.fragments_extracted == 0
       AND body 含嵌套字符 (任一 of { " : in body)
    THEN layer=normalize_miss
         cause-hint = deep_nesting | novel_encoding (按 normalize_meta.depth_max 判)
         fix-hint  = depth_limit_bump | new_decoder
         conf = high

R2  local_score_low
    IF local_score_total < 0.35
       AND no IPI/encode/sql marker in reasons
       AND outcome == passed
    THEN layer = local_score_low
         cause-hint = social_eng_no_marker (probable, 需 text 确认)
         fix-hint  = fath_judge_wrap + field_path_boost
         conf = medium

R3  rag_miss
    IF rag_used == true AND rag_top_score < 0.55
    THEN layer = rag_miss
         cause-hint = kb_coverage_gap
         fix-hint  = kb_inject_socialeng
         conf = high if score<0.45, medium if 0.45-0.55

R4  rag_wrong
    IF rag_top_score >= 0.60
       AND rag_top_category != expected_category
       AND outcome == passed
    THEN layer = rag_wrong
         cause-hint = kb_label_noise
         fix-hint  = kb_clean
         conf = high

R5  llm_overrode  (★ FATH judge wrap 的精确指纹)
    IF local_score_total >= 0.55 AND outcome == passed
       AND route IN (local_llm_one_shot, react_deep_inspection)
    THEN layer = llm_overrode
         cause-hint = carrier_unaware (probable)
         fix-hint  = fath_judge_wrap
         conf = high

R6  router_too_loose
    IF route == fast_pass AND local_score_total >= 0.35
    THEN layer = router_too_loose
         cause-hint = threshold_misfit
         fix-hint  = route_threshold_tune
         conf = high

R7  miscategorized
    IF outcome == blocked AND detected_category != expected_category
    THEN layer = miscategorized
         cause-hint = ambiguous_pattern
         fix-hint  = category_rule_refine
         conf = high
    (B-1 那 5% command_injection 误归类走这条)

R8  fallback unknown
    ELSE
    THEN layer = unknown, cause = needs_manual
         conf = low → 进抽样队列

R9  react_fallback_pass  (★ Phase E 实跑发现, 占 17.7% R8 → 加入正式规则)
    IF route == fallback AND outcome == passed
       AND local_score_total >= 0.35
    THEN layer = react_fallback_pass
         cause-hint = react_parse_failure
         fix-hint  = fath_judge_wrap + react_prompt_robustness
         conf = medium
    (ReAct 进了但解不出 verdict; fallback 默认放行)
```

`fix-hint` 在 `build_failure_report.py` 里聚合成 bucket → ROI 表。映射到已 queued / 未立 change：

```
fath_judge_wrap         →  harden-waf2-llm-judge-field-isolation (queued)
kb_inject_socialeng     →  (新 change) inject-socialeng-kb-samples
field_path_boost        →  (新 change) add-field-path-aware-scoring
depth_limit_bump        →  已 ship (nested-json-extraction depth 6)
new_decoder             →  按 encoding 类型立新 change
kb_clean                →  KB 数据治理子任务
route_threshold_tune    →  evaluate-waf2-rag-react-routing-and-models
category_rule_refine    →  local_attack_score 规则细化
unfixable_in_waf2       →  需要 session/dataflow 状态（业务上游）
```

### D4. 抽样策略 — B-1 抽 30 验证 single-bucket

```
B-0 25 FN:    全部 auto + 全部人工标 (量小)
CSIC FN/FP:   全部 auto + 全部人工标 (量小)
B-1 380 FN:   全部 auto + 抽 30 人工验证假设

  假设: ≥ 90% 的 B-1 FN 归到 R2 (local_score_low) + cause=social_eng_no_marker
  
  抽样判定:
    抽 30 个 (random.seed 固定, 可复现)
    人工标 cause 字段
    IF (非 social_eng_no_marker 的条数 >= 3):
        → 假设破裂, 扩抽样到 100, 再决定要不要全标
    ELSE:
        → 假设成立, 380 全集只用 auto-推导
```

抽样种子写死 `random.seed("waf2-eval-fal-2026-05-17")`，下次 reproduce 不漂移。

### D5. 文件布局

```
runs/<date>-<change>/
├── cases-csic-rag-off.jsonl                ← raw, immutable
├── cases-csic-rag-on.jsonl
├── cases-b0-rag-off.jsonl
├── cases-b0-rag-on.jsonl
├── cases-b1-dh-base.jsonl
├── cases-b1-ds-base.jsonl
├── cases-b1-dh-enhanced.jsonl
├── cases-b1-ds-enhanced.jsonl
├── labels-csic-rag-off.jsonl               ← 派生, label_failures.py 输出
├── labels-*.jsonl
├── b1-sample-30.md                         ← 人工补 cause 的 markdown checklist
├── failure-analysis.md                     ← bucket → ROI 报告
└── failures.jsonl                          ← legacy, 保留向后兼容
```

### D6. 不引入 config 开关 (除 eval-only)

- `ambiguous_score_threshold` (0.40) / `ambiguous_rag_threshold` (0.55) 是常量，写在 `eval_rag.py` 顶部
- `eval_mode` 已有，不新增 flag
- 抽样种子写死字符串，不暴露 CLI
- header 字段名常量，不可配

> 与 `harden-waf2-nested-json-extraction` D5 决策一致：不暴露不必要 config 字段。

### D7. 派生脚本可以独立重跑

`labels-*.jsonl` 完全从 `cases-*.jsonl` 派生。当规则 R1~R8 调整时：

```
python label_failures.py runs/2026-05-17-eval-fal/cases-*.jsonl
   → 重写 labels-*.jsonl, 不重跑 eval
python build_failure_report.py runs/2026-05-17-eval-fal/
   → 重写 failure-analysis.md
```

这是"快速实验失败归因规则"的入口。

## 数据/性能影响

| 项 | 当前 | 预期 |
|---|---|---|
| WAF2 生产模式延迟 | (现状) | 不变（eval_mode=false 不附加 header） |
| WAF2 eval 模式延迟 | (现状) | +0.1ms (header 序列化) |
| eval_rag.py CSIC 1000 单 run | ~10 min | +5s (per-case JSONL 写入) |
| eval_prompt_injection.py 228 单 run | ~50 min | +1s |
| eval_injecagent.py 400 单 run | ~25 min | +2s |
| labels-*.jsonl 生成 | n/a | < 5s (auto 推导纯本地计算) |
| failure-analysis.md 生成 | n/a | < 1s |

## 不做的事

- **不引入 OpenTelemetry / metrics pipeline** — JSONL 文件 + grep 已足够 eval 用
- **不写 Dashboard 集成** — eval 数据只在 CI/分析流水线消费，不进生产 UI
- **不引入 LLM-assisted labeling** — R1~R8 + 人工 30 抽样已覆盖，R8 unknown 用 LLM 标会引入二阶噪音
- **不改任何拦截规则** — 这是 loop 的下游，本 change 严格只生产数据
- **不改 KB / prompt / 路由阈值** — 同上

## Open questions（不阻塞 ship，但记录）

- **OQ1**: ambiguous 阈值 0.40 / 0.55 在不同 model（qwen3:8b vs 14B vs API）下是否需要分别校准？暂用 8B 作基线，未来切模型时单独评估。
- **OQ2**: `field_path` 信号 (case 来自 user_query / tool_response / response body) 当前没在 normalize_meta 里。R5 carrier_unaware 标签的 confidence 受此影响。本 change 不补这个字段，但留意 — 若后续证明 R5 准确率 < 70%，再立 change 扩 normalize_meta。
- **OQ3**: 跨 run 的"FN 是否仍是同一 case"对比，靠 `case_id` 稳定？B-0/B-1 用 jsonl 行号，CSIC 用 hash(method+path+body)。可能受 dataset 排序影响。本 change 用行号 + body-hash 双 key 互为校验。
