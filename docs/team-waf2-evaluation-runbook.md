# WAF2 Local-First Evaluation Runbook

本文给两个队友跑数用。目标是拿到可复现的数据，而不是边跑边随手改代码。

## 当前结论

当前项目路线是:

```text
WAF1: MCP 协议层防护
WAF2: local-first intelligent WAF
  normalize/decode -> static rules -> local attack score -> RAG evidence
  -> local LLM one-shot -> ReAct deep inspection only when needed
```

这轮测试要回答 4 个问题:

```text
1. 普通笔记本本地小模型能不能跑得动？
2. RAG ON/OFF 对结果有没有稳定影响？
3. ReAct 实际进入率是多少，值不值得保留在灰区路径？
4. 大样本下 Precision / Recall / F1 / FPR 是否稳定？
```

## 分工

### 队友 A: 普通用户硬件路线

优先跑本地 Ollama 小模型:

```text
qwen2.5:1.5b-instruct
qwen3:4b
```

代表普通笔记本用户。重点看:

```text
FPR 是否接近 0
Recall 是否稳定
LLM / ReAct 调用率是否低
延迟是否能接受
```

### 队友 B: 上限路线

优先跑更强模型:

```text
本地 7B / 14B 模型，如果机器能跑
或在线 OpenAI-compatible API baseline，例如硅基流动
```

代表高硬件或在线 API 上限。重点看:

```text
强模型是否真的提升 Recall
提升是否值得额外成本和隐私代价
ReAct 是否只对强模型有效
```

## 是否需要队友改代码

默认不需要。

队友这轮只做 4 件事:

```text
1. pull 最新代码
2. 按本文固定命令跑数据
3. 保存输出、results.md、模型名、硬件信息
4. 把失败样本和异常情况发回来
```

不要在同一轮评测里自行改:

```text
local_attack_score.py
risk_router.py
normalization.py
waf2_proxy.py
RAG KB 数据
prompt
threshold
```

原因: 如果每个人边跑边改，最后数据不可比。

调代码由我们根据失败样本集中处理。可以调的地方按优先级是:

```text
FN 多: normalization / local_attack_score / KB / ReAct 入口
FP 多: hard negatives / business fast-pass / benign RAG evidence
LLM 调用多: risk_router
ReAct 调用多: ReAct 灰区入口
延迟高: 先减少模型进入率，再考虑换模型
```

## 拉代码和启动

从仓库根目录执行:

```bash
git pull origin master
git rev-parse --short HEAD
docker-compose up -d --build waf2
curl -s http://localhost:8081/waf2/config
```

记录 `git rev-parse --short HEAD` 的输出。所有结果必须带 commit hash。

## CSIC 数据集准备

CSIC 2010 CSV 不入仓库。把文件放到:

```text
waf2/rag/eval/csic2010/csic_database.csv
```

跑 CSIC 前确认:

```bash
ls -lh waf2/rag/eval/csic2010/csic_database.csv
```

如果脚本输出:

```text
[eval] ⚠️ 未找到 CSIC, 使用 smoke
```

这轮结果无效，说明 CSV 路径不对。

## 配置本地 Ollama

如果 Ollama 在 Windows 宿主机上，Docker 里应该使用:

```text
http://host.docker.internal:11434/v1
```

确认容器能访问 Ollama:

```bash
docker exec waf2 python -c "import urllib.request; print(urllib.request.urlopen('http://host.docker.internal:11434/api/tags', timeout=3).read().decode())"
```

配置 qwen2.5 1.5B:

```bash
curl -s -X POST http://localhost:8081/waf2/config \
  -H 'Content-Type: application/json' \
  -d '{"model":"qwen2.5:1.5b-instruct","base_url":"http://host.docker.internal:11434/v1","format":"openai","api_key":"","provider_locality":"local","privacy_mode":"local_only","local_provider_name":"ollama","local_first_enabled":true,"eval_mode":false,"eval_fail_closed":false,"fail_policy":"fail_open","agent_max_iters_request":2,"agent_max_iters_response":2,"llm_max_tokens":160,"llm_timeout_seconds":45,"rag_enabled":true,"rag_threshold":0.60,"rag_confidence_threshold":0.50}'
```

配置 qwen3 4B:

```bash
curl -s -X POST http://localhost:8081/waf2/config \
  -H 'Content-Type: application/json' \
  -d '{"model":"qwen3:4b","base_url":"http://host.docker.internal:11434/v1","format":"openai","api_key":"","provider_locality":"local","privacy_mode":"local_only","local_provider_name":"ollama","local_first_enabled":true,"eval_mode":false,"eval_fail_closed":false,"fail_policy":"fail_open","agent_max_iters_request":2,"agent_max_iters_response":2,"llm_max_tokens":220,"llm_timeout_seconds":90,"rag_enabled":true,"rag_threshold":0.60,"rag_confidence_threshold":0.50}'
```

## 配置在线 API baseline

不要把 API key 写进代码或提交到 git。

示例:

```bash
export LLM_API_KEY='填自己的 key'
export MODEL_NAME='从服务商控制台复制模型名'

curl -s -X POST http://localhost:8081/waf2/config \
  -H 'Content-Type: application/json' \
  -d "{\"model\":\"${MODEL_NAME}\",\"base_url\":\"https://api.siliconflow.cn/v1\",\"format\":\"openai\",\"api_key\":\"${LLM_API_KEY}\",\"provider_locality\":\"online\",\"privacy_mode\":\"online_provider\",\"local_provider_name\":\"siliconflow\",\"local_first_enabled\":true,\"eval_mode\":false,\"eval_fail_closed\":false,\"fail_policy\":\"fail_open\",\"agent_max_iters_request\":2,\"agent_max_iters_response\":2,\"llm_max_tokens\":220,\"llm_timeout_seconds\":90,\"rag_enabled\":true,\"rag_threshold\":0.60,\"rag_confidence_threshold\":0.50}"
```

在线 API 只作为上限 baseline，不是项目默认路线。

## 必跑顺序

每个模型按这个顺序跑。

### 1. 对抗集 40

用于确认核心检测没有回退。

```bash
python3 -m waf2.rag.scripts.eval_adversarial --waf2 http://localhost:8081
```

当前期望趋势:

```text
Precision 接近 1.000
Recall 接近 1.000
FPR 接近 0.000
LLM/ReAct 调用应很低或为 0
```

如果这组明显掉分，先不要继续跑大样本，直接把完整输出发回来。

### 2. CSIC 100

```bash
python3 -m waf2.rag.scripts.eval_rag \
  --waf2 http://localhost:8081 \
  --dataset csic \
  --sample 100 \
  --seed 42 \
  --eval-fail-closed false
```

### 3. CSIC 250

```bash
python3 -m waf2.rag.scripts.eval_rag \
  --waf2 http://localhost:8081 \
  --dataset csic \
  --sample 250 \
  --seed 42 \
  --eval-fail-closed false
```

### 4. CSIC 500

如果 100 和 250 没有异常，再跑 500:

```bash
python3 -m waf2.rag.scripts.eval_rag \
  --waf2 http://localhost:8081 \
  --dataset csic \
  --sample 500 \
  --seed 42 \
  --eval-fail-closed false
```

### 5. 可选: CSIC full

如果机器和时间允许:

```bash
python3 -m waf2.rag.scripts.eval_rag \
  --waf2 http://localhost:8081 \
  --dataset csic \
  --sample 0 \
  --seed 42 \
  --eval-fail-closed false
```

full 可能很慢，优先级低于 100 / 250 / 500。

## 每轮需要保存什么

每跑完一个模型和一个样本规模，保存:

```text
1. 终端完整输出
2. waf2/rag/eval/results.md
3. git commit hash
4. 模型名
5. 本地/在线
6. CPU / 内存 / 是否有 GPU
7. 大致耗时
8. 是否出现 LLM Errors / Parse Failed
```

额外保存当前配置和统计:

```bash
curl -s http://localhost:8081/waf2/config > /tmp/waf2-config.json
curl -s http://localhost:8081/waf2/stats > /tmp/waf2-stats.json
```

把 `/tmp/waf2-config.json`、`/tmp/waf2-stats.json` 和 `results.md` 一起发回来。

## 判断结果是否有效

有效结果必须满足:

```text
1. commit hash 一致
2. CSIC 没有 fallback 到 smoke
3. LLM Errors = 0，或者明确标注该轮不可比
4. eval_fail_closed=false
5. 每组同时有 RAG OFF 和 RAG ON
6. 没有手动改代码或改 threshold
```

如果 `LLM Errors > 0`，这轮不能拿来比较 RAG/ReAct 效果，只能作为稳定性问题记录。

## 看哪些指标

核心指标:

```text
Precision
Recall
F1
FPR
TP / FP / TN / FN
```

架构指标:

```text
RAG Queries
RAG Hits
RAG Empty Results
RAG Gated
RAG Positive Evidence
RAG Benign Evidence
Route Static Block
Route Fast Pass
Route Local LLM
Route ReAct
Local Score Direct Blocks
LLM Errors
Parse Failed
```

解释方式:

```text
Recall 高: 攻击拦得住
FPR 低: 不乱拦正常业务
Route Fast Pass 高: 普通请求没进模型，性能好
Route ReAct 低但有效: ReAct 位置合理
RAG Hits 高但指标不变: KB 有命中，但路由/Prompt 可能没用好
RAG Empty 高: KB 覆盖不足
LLM Errors 高: 模型或接口不稳定，该轮不可比
```

## 结果发回格式

建议直接按这个格式发:

```text
队友:
commit:
机器:
模型:
本地/在线:
数据集:
sample:
耗时:

RAG OFF:
TP/FP/TN/FN:
Precision/Recall/F1/FPR:
LLM Errors:
Route Static/Fast/LLM/ReAct:

RAG ON:
TP/FP/TN/FN:
Precision/Recall/F1/FPR:
RAG Queries/Hits/Empty/Gated:
RAG Pos/Benign:
LLM Errors:
Route Static/Fast/LLM/ReAct:

异常:
```

## 我们收到数据后怎么改

队友提供数据，我们集中改代码。

改动规则:

```text
1. 先分类失败样本，而不是直接硬编码单条 payload
2. 只用 dev / 小样本调参
3. 调完后再让队友重跑 100 / 250 / 500
4. 最终报告只写固定 commit 的 holdout 结果
```

下一轮最可能改的地方:

```text
normalization.py: 编码、混淆、嵌套 payload 还原
local_attack_score.py: 补召回，尤其 CSIC-style 和 MCP/Agent 类
risk_router.py: 减少 LLM/ReAct 进入量
RAG KB: 增加 benign hard negatives 和缺失攻击族
waf2_proxy.py: ReAct 入口、失败恢复、解析稳定性
dashboard: 展示新指标，不影响检测逻辑
```

## 会议里的一句话

可以这样解释分工:

```text
队友跑固定 commit 的多模型、多样本评估，不改代码，保证数据可比。
我们根据失败样本统一调整本地 score、RAG 证据和 ReAct 路由，再让队友重跑。
这样能避免为了某一轮数据过拟合，也能证明架构本身是否有效。
```
