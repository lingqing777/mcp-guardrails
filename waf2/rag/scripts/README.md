# waf2/rag/scripts — Evaluation Scripts

本目录收录 M-Bench-Core 评测的端到端脚本。其中 `run_ablation.sh` 是 7 组 WAF
消融评测的总入口,详见下文。

---

## `run_ablation.sh` — WAF 消融评测总入口

一键跑完 7 组 WAF 消融配置,把每组的 P/R/F1 + AvgTime 追加到一张 `index.tsv`,
便于跨配置 / 跨模型对比。

### 7 组消融配置

| # | 标签 (label) | 改动 | 说明 |
|---|---|---|---|
| 1 | `WAF1-only` | 关 WAF2 | 仅 WAF1(三开关全开) |
| 2 | `WAF2-only` | 关 WAF1 | 仅 WAF2(rag + react 全开) |
| 3 | `Full` | 全开 | WAF1 + WAF2 双层(基线) |
| 4 | `Full no-chain` | `callChainEnabled=false` | 关 WAF1 调用链 detector |
| 5 | `Full no-dynSQL` | `dynamicPolicyEnabled=false` | 关 WAF1 动态 SQL 策略 |
| 6 | `Full no-RAG` | WAF2 `rag_enabled=false` | 关 WAF2 RAG |
| 7 | `Full no-ReAct` | WAF2 `react_routing_enabled=false` | 关 WAF2 ReAct 决策路由 |

配置 4/5 只改 WAF1,WAF2 输出直接 `cp` 复用配置 3 的产物;
配置 6/7 只改 WAF2,WAF1 输出 `cp` 复用配置 3。因此 **运行顺序敏感**:
跑 `--ablation 4|5|6|7` 之前必须先有 `3-full/` 目录。
`--ablation all` 会按 1→7 顺序自动满足这一依赖。

### 数据集与样本量

- 攻击样本:**全部** `attacks.jsonl`(默认 150 条,可 `--attacks` 覆盖)
- 良性样本:默认采样,**等量于攻击数**(`--benign-sample equal`)
  - `equal`(默认)→ 与 attacks 行数对齐,目前 150 条
  - `<N>` → 显式抽 N 条
  - `all` → 不采样,跑全量 1000 条
- 采样确定性:`--sample-seed 42`(默认 42),把 1000 条 `random.sample(seed=42)` 截到目标数,
  写入 `<root>/_benign_sample.jsonl`,各 ablation 共用同一采样池(可重现且跨 ablation 对齐)

### 前置条件

启动两个服务后再跑脚本:

```bash
# WAF1 (mcp-hub) — 端口 4000
cd mcp-hub && npm start

# WAF2 — 端口 8081(另开终端)
cd waf2 && uvicorn rag.app.main:app --port 8081
```

Ollama 拉好评测模型(默认 `qwen3:8b`):

```bash
ollama pull qwen3:8b
```

### CLI

```bash
bash waf2/rag/scripts/run_ablation.sh \
  --ablation {1|2|3|4|5|6|7|all} \
  [--date YYYY-MM-DD]              # 默认 today,作为输出目录日期 tag
  [--model NAME]                   # 用作输出目录后缀(并不影响实际模型)
  [--attacks PATH]                 # 默认 waf2/rag/eval/m-bench-core/attacks.jsonl
  [--benigns PATH]                 # 默认 waf2/rag/eval/m-bench-core/benign.jsonl
  [--benign-sample {equal|N|all}]  # 默认 equal,即与 attacks 等量
  [--sample-seed N]                # 默认 42
  [--root DIR]                     # 默认 waf2/rag/eval/runs/<date>-ablation-7way[-<model>]
  [--mcp-hub URL]                  # 默认 http://localhost:4000
  [--waf2 URL]                     # 默认 http://localhost:8081
```

### 典型用法

```bash
# 单 ablation,默认 150 + 150
bash waf2/rag/scripts/run_ablation.sh --ablation 3

# 跑全部 7 组,标记模型名(便于多模型对比)
bash waf2/rag/scripts/run_ablation.sh --ablation all --model qwen3-8b

# 跑全量 1000 benigns(慢,~5h 含 LLM)
bash waf2/rag/scripts/run_ablation.sh --ablation all --benign-sample all

# 抽 100 条 benigns,自定义随机种子
bash waf2/rag/scripts/run_ablation.sh --ablation all --benign-sample 100 --sample-seed 7

# 多模型并发:不同终端跑不同模型 (改 --waf2 端口与 --model)
bash waf2/rag/scripts/run_ablation.sh --ablation all --model llama3-8b --waf2 http://localhost:8082
```

### Windows 协作者(无 WSL/Git Bash)

用同目录下的 `run_ablation.bat`(纯 cmd,功能与 `run_ablation.sh --ablation all --benign-sample equal` 等价):

```cmd
REM 从仓库根运行,可选传入 model tag(默认 qwen3-1_5b)
waf2\rag\scripts\run_ablation.bat qwen3-1_5b
```

依赖:Node.js 18+ / Python 3.10+ / `curl.exe`(Win10+ 内置)/ PowerShell。
脚本会自动登录 mcp-hub、采样等量 benigns、按 1→7 顺序跑、最后 `type` 出 index.tsv。

### 输出结构

```
waf2/rag/eval/runs/<date>-ablation-7way[-<model>]/
├── _benign_sample.jsonl            # 采样产物(7 个 ablation 共用)
├── index.tsv                       # ★ 8 字段 × 7 行汇总
├── 1-waf1-only/
│   ├── _dataset/{attacks,benign}.jsonl
│   ├── cases-mbench-attacks-waf1-strict.jsonl
│   ├── cases-mbench-attacks-waf1-full.jsonl
│   ├── cases-mbench-benign-waf1-strict.jsonl
│   ├── cases-mbench-benign-waf1-full.jsonl
│   ├── cases-mbench-merged.jsonl
│   ├── dual-layer-mbench-report.md
│   └── summary.tsv                  # 单 ablation 1 行
├── 2-waf2-only/
├── 3-full/
├── 4-full-no-chain/
├── 5-full-no-dynsql/
├── 6-full-no-rag/
└── 7-full-no-react/
```

### `index.tsv` 字段(8 列)

| 列 | 含义 |
|---|---|
| `ablation_label` | 配置标签(WAF1-only / Full / Full no-chain ...) |
| `char_F1` | 字符注入族 F1 |
| `pi_F1` | 提示注入族 F1 |
| `chain_F1` | 调用链攻击族 F1 |
| `recall` | 综合召回率 |
| `F1` | 综合 F1 |
| `avg_time_attacks_ms` | 攻击样本端到端平均延迟(仅活跃层) |
| `avg_time_benigns_ms` | 良性样本端到端平均延迟(仅活跃层) |

查看汇总:

```bash
cat waf2/rag/eval/runs/<date>-ablation-7way[-<model>]/index.tsv
```

### 故障与调试

- **`error: ablation 3 dir not found`** — 跑 `--ablation 4|5|6|7` 前必须先跑 `--ablation 3`。
  推荐 `--ablation all` 让脚本按序跑。
- **`curl: (7) Failed to connect`** — mcp-hub(4000)或 WAF2(8081)未启动。
- **WAF2 LLM 卡住** — 检查 Ollama 在跑且模型已 `ollama pull`。
- **`row_index` 数量不一致** — 检查 attacks/benign jsonl 是不是已被外部脚本修改;
  采样确定性靠 `--sample-seed`。

### 与其他脚本的关系

`run_ablation.sh` 内部按序调用本目录及 `mcp-hub/scripts/` 的零件:

| 步骤 | 脚本 |
|---|---|
| WAF1 跑分 | `mcp-hub/scripts/run_waf1_on_mbench.mjs` |
| WAF2 跑分 | `waf2/rag/scripts/run_waf2_on_mbench.py` |
| 4 层合并 | `waf2/rag/scripts/merge_mbench_layers.py` |
| 报告 + TSV | `waf2/rag/scripts/report_mbench.py` |

如需手动驱动单个零件,参见各脚本顶部的 docstring。
