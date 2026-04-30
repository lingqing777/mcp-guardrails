## Why

WAF2 当前已经具备静态规则、RAG、ReAct/COT 和多模型 API 调用能力，但实验结果显示主要瓶颈是召回率不足，而不是误报过高。继续把系统专精为“RAG + ReAct WAF”会让主线偏向模型技巧；更适合本项目的方向是面向 MCP 网关的本地优先智能检测管线：用户流量、MCP tool 参数、Cookie、Token 和日志默认不离开本机，在线能力只用于规则、知识库和模型资产更新。

本 change 将 WAF2 从“外部 LLM 判定器”调整为“本地检测管线 + 本地知识证据 + 灰区深度分析”的架构，使项目同时具备传统 Web WAF 的高召回能力和 MCP/Agent 场景的差异化防护能力。

## What Changes

- 将 WAF2 的主叙事调整为 Local-First Intelligent WAF，默认优先使用本地 OpenAI-compatible 模型服务，在线 API 只作为评估基线或用户显式配置选项。
- 引入 Normalization / Decode 阶段，在规则、RAG、LLM、ReAct 之前统一处理 URL 编码、Unicode escape、HTML entity、嵌套 JSON、可疑 base64、路径归一化和混淆字符。
- 引入 Local Attack Score 阶段，为 SQLi、XSS、RCE、path traversal、SSRF、prompt injection、data exfiltration、credential leakage、MCP tool abuse 等风险计算本地分数。
- 将现有 RAG 定位调整为 Local Knowledge Evidence Layer，用于提供本地攻击/良性 hard-negative 证据，而不是作为唯一检测核心。
- 将 ReAct/COT 定位调整为 Deep Inspection Path，只处理灰区、编码混淆、多步工具链、证据冲突和 MCP/Agent 特有复杂样本。
- 引入 Risk Router，根据静态规则、decode 结果、attack score、RAG 证据和模型置信度选择 PASS、BLOCK、local LLM one-shot 或 ReAct deep inspection。
- 定义本地化数据平面隐私要求：HTTP request/response body、MCP tool args、认证凭据、检测日志、RAG 查询和 LLM 推理不得默认上传到云端。
- 定义本地模型评估矩阵和指标：Precision、Recall、F1、FPR、avg/p95 latency、LLM call rate、ReAct entry rate、RAG hit/gated/empty、offline availability、local RAM/VRAM footprint。
- 调整 Dashboard 可视化目标：展示本地/在线 provider 状态、隐私模式、route 分布、attack score、RAG evidence、ReAct deep path 进入率和本地模型延迟。

## Capabilities

### New Capabilities

- `waf2-local-first-pipeline`: 定义 WAF2 本地优先检测管线、数据平面隐私边界、本地 provider 优先级、Risk Router、RAG 证据层和 ReAct 深度路径。
- `waf2-local-attack-scoring`: 定义 normalize/decode 后的本地攻击评分能力、分类型风险分、路由阈值输入和可解释评分输出。
- `waf2-local-model-evaluation`: 定义本地模型与在线 API 基线的评估矩阵、离线可用性要求、性能指标和按类别效果报告。

### Modified Capabilities

- `waf2`: WAF2 的检测流程从“请求分析 → 转发 → 响应分析”扩展为“normalize/decode → deterministic guard → local attack score → knowledge evidence → risk router → local LLM / ReAct deep inspection → 转发/拦截”，并要求本地 provider 可作为默认运行方式。
- `dashboard`: Dashboard 需要展示 WAF2 的本地化状态、隐私模式、route/score/evidence/deep-path 指标，而不仅是 LLM 调用数和拦截统计。

## Impact

- Affected WAF2 code:
  - `waf2/waf2_proxy.py`: 检测管线、配置字段、路由策略、统计字段、检测记录结构。
  - `waf2/rag/engine.py`: RAG 作为本地证据层使用，后续可能增加正负样本混合检索和类别过滤。
  - `waf2/rag/scripts/eval_*.py`: 增加本地/在线模型、route、attack score、RAG、ReAct、延迟和离线指标。
  - `waf2/requirements.txt`: 后续可能增加本地模型客户端、decode/normalization 辅助库或轻量分类器依赖。
- Affected MCP Hub / Dashboard code:
  - `mcp-hub/src/dashboard/app.js`
  - `mcp-hub/src/dashboard/styles.css`
  - `mcp-hub/src/dashboard/services/api.js`
  - `config/guardrails-config.json`
- Docker impact:
  - 可能需要在 `docker-compose.yml` 中新增可选本地 LLM provider 配置示例，例如 Ollama/vLLM/llama.cpp/LocalAI 的 OpenAI-compatible endpoint。
  - 不强制把本地模型服务塞进现有 WAF2 容器；优先让 WAF2 连接宿主机或独立容器上的本地 provider，避免 WAF2 镜像过重。
- API impact:
  - `GET /waf2/config`、`POST /waf2/config`、`GET /waf2/stats`、`GET /waf2/dashboard`、`GET /waf2/detections` 需要暴露本地 provider、privacy mode、route、attack score、RAG evidence 和 ReAct path 指标。
- Route registration:
  - 本 change 不新增 MCP Hub server.js 路由。若后续需要新增 Dashboard API，应放在现有 `/api` 认证边界之后，遵守当前 server.js 路由注册顺序。
- Dashboard refresh:
  - 继续兼容现有 5 秒刷新机制。新增指标必须可在缺失字段时安全降级，避免旧 WAF2 运行时导致前端报错。
