# Eval Run: Probe & Double-Decode Harden — CSIC 100+100 + 1000+1000 2026-05-13

OpenSpec change: `harden-waf2-local-scorer-probe-and-decode`

## 环境

- Commit: `fcae26d` (working tree 含 change 改动，未提交)
- Model: `qwen3:8b` (Ollama local via `host.docker.internal:11434`)
- Provider: local / ollama
- RAG: 3364 entries, threshold=0.60
- 数据集: CSIC 2010, sample={100, 1000} (seed=42)
- 评测: `eval_mode=true`, `eval_fail_closed=false`

## TL;DR

| 验收项 | 结果 |
|--------|------|
| 6.1 Probe regression 35 条 → 100% direct_block | ✅ 35/35 |
| 6.4 对抗集 F1 不下降 (vs baseline F1=1.000) | ✅ F1=1.000 (维持满分) |
| 6.2 CSIC 100 RAG OFF, FPR ≤ 0.005 | ✅ FPR=0.000 |
| 6.3 CSIC 100 RAG ON 未引入 FP | ✅ OFF/ON 完全一致 |
| 6.6 CSIC 1000 Recall ≥ 0.76 | ✅ Recall=0.761 (+3.8 pp vs baseline 0.723) |
| 6.6 CSIC 1000 FPR ≤ 0.005 | ✅ FPR=0.000 |
| 6.6 CSIC 1000 RAG ON 未引入 FP | ✅ FPR=0.000 (RAG 反而 +1 TP) |

## 6.1 Probe FN 回归集 (35 条)

```
Probe-FN regression: 35/35 blocked (100.0%)
Detected categories:
   27  unknown          ← legacy_web_probe / legacy_web_probe_suffix
    8  sql_injection    ← double-decoded boolean tautology
```

全部由 local scorer 直接拦截，**未触发 LLM 调用**。

## 6.4 对抗集 (30 攻击 + 10 良性，OFF/ON 对照)

| 指标 | OFF | ON | Δ |
|------|-----|-----|---|
| Precision | 1.000 | 1.000 | 0.000 |
| Recall | 1.000 | 1.000 | 0.000 |
| F1 | 1.000 | 1.000 | 0.000 |
| FPR | 0.000 | 0.000 | 0.000 |
| CategoryAcc | 0.833 | 0.833 | 0.000 |

- 攻击拦截: 30/30
- 误拦良性: 0/10
- RAG fire 攻击: 0/30 (全部由前置层拦下)
- RAG fire 良性: 0/10

类别归因偏差 5 条（命中其他 pattern，仍 BLOCK，不影响主指标）：
- cmd-bash-IFS-bypass: expected=command_injection actual=path_traversal
- cmd-bash-substring-pivot: 同上
- pi-bracket-redirect: expected=prompt_injection actual=path_traversal
- xxe-classic-but-rare: expected=xxe actual=path_traversal
- cmd-newline-inject: expected=command_injection actual=path_traversal

## 6.2 + 6.3 CSIC 100+100

### 主指标

| 指标 | baseline 1000 (RAG OFF) | new 100 (RAG OFF) | new 100 (RAG ON) | baseline 100 ref |
|------|--------------------------|---------------------|--------------------|--------------------|
| Precision | 1.000 | **1.000** | **1.000** | 1.000 |
| Recall | 0.723 | **0.850** | **0.850** | 0.850 |
| F1 | 0.839 | **0.919** | **0.919** | 0.919 |
| FPR | 0.000 | **0.000** | **0.000** | 0.000 |

> **小样本说明**：baseline 在 100 样本上的 Recall 也是 0.850（见 `runs/2026-05-10-big/README.md` 中 "样本量 vs Recall 趋势" 表）。
> 100 样本里随机命中 probe path 的概率太低，**不能用来证明 Recall 提升**。
> 当前结果证明的是：新代码在 100 样本上保持了相同的 Recall 上限，没有任何回归；要量化 +Recall 需要跑 1000+ 样本。

### 路由分布 (RAG OFF)

| 路由 | 数量 | 说明 |
|------|------|------|
| Static Block | 79 | 本地 scorer direct_block |
| Fast Pass | 58 | 低风险业务上下文 |
| Local LLM | 5 | 灰区进入 LLM 单 shot |
| ReAct | 0 | 没进入 ReAct（小样本里灰区少）|
| Local Block | 78 | scorer 给出的拦截信号（≈ static_block 一致）|

### RAG 信号 (RAG ON)

| 字段 | 值 |
|------|-----|
| RagQuery | 5 |
| RagHit | 3 |
| RagEmpty | 2 |
| RagGated | 3 |
| RagPositive | 3 |
| RagBenign | 0 |

> **RAG 在该批次 0 决策影响**：3 次命中全部被 gated（已在 KB 评估后被打回原决策）。
> 这和 baseline 1000 样本上"24 hits / all gated / 0 decision changes"的现象一致。

### 性能

| 指标 | 值 |
|------|-----|
| avg latency | 524 ms |
| cache hit rate | 92.1% |
| llm calls | 5 |
| llm errors | 0 |

## 15 个 FN 样本特征 (定性)

逐条 inspect 后归类：

- **CSIC 已知 label noise (10/15)**: 普通登录/注册请求 (`/tienda1/publico/autenticar.jsp` 含合法用户名密码)、静态资源 (`/tienda1/asf-logo-wide.gif`)、错误页 (`errorMsg=Credenciales+incorrectas`)
- **西班牙语字符 URL 编码 (3/15)**: `Jam%F3n` (Jamón), `pic%F3n` (Picón) — 合法用户名/产品名
- **数字资源 ID (1/15)**: `/tienda1/4861362529278789730`
- **空 path (1/15)**: `GET /`

无一条属于本 change 应该修复的 probe-path 或 double-encoded 类别。

## 6.6 CSIC 1000+1000 大样本验证

### 主指标

| 指标 | baseline 1000 (RAG OFF) | new 1000 (RAG OFF) | new 1000 (RAG ON) | Δ vs baseline |
|------|--------------------------|---------------------|--------------------|----------------|
| Precision | 1.000 | **1.000** | **1.000** | 0.000 |
| Recall | 0.723 | **0.761** | **0.762** | **+3.8 / +3.9 pp** |
| F1 | 0.839 | **0.864** | **0.865** | **+2.5 / +2.6 pp** |
| FPR | 0.000 | **0.000** | **0.000** | 0.000 |
| LLM Errors | 0 | 0 | 0 | 0 |
| Parse Fail | — | 3 | 6 | (qwen3:8b 解析噪声) |

> ✅ 达到 design.md 验收线 (Recall ≥ 0.76, FPR ≤ 0.005)。

### 路由分布对比 (RAG OFF, 1000)

| 路由 | baseline | new | Δ | 解读 |
|------|----------|-----|---|------|
| Static Block | 640 | **668** | **+28** | probe path 黑名单 + 双重 decode 直接拦下原 gray-zone 样本 |
| Fast Pass | 506 | 474 | -32 | 之前被 fast_pass 误放的边缘样本被 static 拦下 |
| Local LLM | 93 | 93 | 0 | LLM 调用次数维持，无额外延迟 |
| ReAct | 8 | **0** | **-8** | 进入 ReAct 的样本被前置层提早拦下，节省深度推理 |
| Local Block | 616 | 648 | +32 | scorer 给出的总拦截信号 |

> ReAct 调用 8 → 0 是个意外收益：所有原本依赖深度推理的样本被新 pattern 直接拦下了。

### RAG 信号对比 (RAG ON, 1000)

| 字段 | baseline | new | 解读 |
|------|----------|-----|------|
| RagQuery | 101 | **93** | 灰区样本减少（前置层拦走更多） |
| RagHit | 24 | **23** | 命中知识库的次数 |
| RagGated | 24 | 23 | 全部被 gating 评估 |
| RagPositive | 24 | **23** | 提供肯定证据 |
| RagBenign | 0 | 0 | 无良性证据 |
| RAG **决策影响** | 0 | **+1 TP** | 新代码下 RAG 实际改了 1 个判决 (762 vs 761)|

> RAG 在新代码下从"完全无影响"变成"+1 TP 微影响"。仍未达到改架构必要性，但**不再是纯摆设**。

### 与 baseline 的关键差异

```
                baseline 1000           new 1000             解读
─────────────────────────────────────────────────────────────────────────
TP             723                     761  (+38)           多识别 38 条攻击
FN             277                     239  (-38)           漏报减少 38 条
Static block   640 (64.0%)             668 (66.8%)          probe + double-decode 直接拦
ReAct calls    8                       0                    深度推理被前置层取代
RAG impact     0 decisions             +1 TP                微正向
LLM calls      93                      93                   总 LLM 开销不变
```

## 结论

✅ **强烈建议合并 PR**：

1. **零 FP 维持**: Precision/FPR 在 100/1000 样本上完全保持
2. **probe regression 100% 修复**: 在线 35/35 = 100% direct_block
3. **Recall 实质提升 +3.8 pp**: 0.723 → 0.761 (达到 design.md 验收线 0.76)
4. **F1 提升 +2.5 pp**: 0.839 → 0.864
5. **对抗集无回归**: F1=1.000 保持满分
6. **架构副作用为正**: ReAct 调用从 8 降到 0，节省深度推理；RAG 由 0 影响变 +1 TP

⚠️ **未量化项**:

- 单次 latency 变化（新加的 pattern 匹配 < 0.3ms，理论上可忽略，未实测）
- 若需 latency 实测，可对比 `waf2-stats.json` 中 `avg_latency_ms`（当前 524ms / baseline ~1124ms — 但样本量差异大，不可直接比）

## 与 baseline (2026-05-10-big) 的差异

| 维度 | baseline 1000 (RAG OFF) | new 1000 (RAG OFF) |
|------|--------------------------|---------------------|
| Recall | 0.723 | **0.761 (+3.8 pp)** |
| F1 | 0.839 | **0.864 (+2.5 pp)** |
| Static Block 比例 | 640/1000 = 64.0% | 668/1000 = 66.8% (+2.8 pp) |
| 离线 25k anomalous 测算 | — | 72.6% direct_block (与在线 66.8% 之差源于 25k 包含更多 probe path) |

## 文件

- `results-csic-100.md` — CSIC 100 + 100 评测报告
- `results-csic-1000.md` — CSIC 1000 + 1000 评测报告
- `failures-csic-100.jsonl` — CSIC 100 失败样本
- `failures-csic-1000.jsonl` — CSIC 1000 失败样本 (477 条 = ~239 FN × 2 round)
- `waf2-config.json` — 评测时 WAF2 完整配置
- `waf2-stats.json` — 100 样本评测后 stats
- `waf2-stats-1000.json` — 1000 样本评测后 stats

## 复现命令

```bash
# 1. probe regression (1 min)
PYTHONPATH=. python3 -m waf2.rag.scripts.eval_probe_regression --waf2 http://localhost:8081

# 2. 对抗集 (~3 min, OFF/ON 自带)
PYTHONPATH=. python3 -m waf2.rag.scripts.eval_adversarial --waf2 http://localhost:8081

# 3. CSIC 100+100 (~10 min, OFF/ON 自带)
PYTHONPATH=. python3 -m waf2.rag.scripts.eval_rag \
  --waf2 http://localhost:8081 --sample 100 --dataset csic \
  --eval-fail-closed false
```
