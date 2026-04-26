## Why

WAF2 已经从“静态规则 + LLM”演进到“静态规则 + RAG + ReAct/COT 工具化推理”。当前问题不再是能否接入 RAG，而是需要用可解释、可复现的测试体系判断：

- 哪些请求应该进入 ReAct 深度推理
- 哪些请求应停留在静态规则或轻量 LLM 路径
- RAG 在不同数据类型与不同模型上的真实收益
- 如何避免 ReAct 对所有请求都进行深度思考导致延迟和成本失控

因此需要先定义测试数据分类、评估指标和路由调试闭环，再进行多模型大规模测试。

## What Changes

- 新增 WAF2 RAG + ReAct 评估计划，明确 dev set / holdout set 的数据分类
- 定义测试数据 taxonomy：Classic Web、Encoded/Obfuscated、Prompt Injection、MCP Tool Poisoning、Data Exfiltration、Sensitive Response Leakage、Benign Hard Negatives、Normal Business Traffic
- 定义按类别调试 ReAct + RAG 的 failure analysis 闭环
- 定义 ReAct 进入量控制目标：减少普通请求进入深度推理，将 ReAct 用于高风险、混淆、编码、MCP/Agent 特有攻击
- 定义多模型测试矩阵：先固定架构，再比较模型，不把模型能力差异和架构差异混在一起
- 输出评估结果格式要求：不仅看 Precision/Recall/F1/FPR，还要记录路径指标、性能指标和质量指标

## Capabilities

### New Capabilities

- `waf2-rag-react-evaluation`: 定义 WAF2 RAG + ReAct 的测试分类、评估指标、调试闭环和模型评估矩阵

### Modified Capabilities

- `waf2`: 明确 WAF2 后续应区分 Fast Path / Middle Path / Deep Path，并基于评估结果控制 ReAct 进入量

## Impact

- `openspec/changes/evaluate-waf2-rag-react-routing-and-models/design.md`: 记录测试分类、调试闭环、路由目标和模型矩阵
- `openspec/changes/evaluate-waf2-rag-react-routing-and-models/specs/waf2-rag-react-evaluation/spec.md`: 新增评估能力规格
- `openspec/changes/evaluate-waf2-rag-react-routing-and-models/specs/waf2/spec.md`: 记录 WAF2 路由设计要求
- 后续可能影响：
  - `waf2/rag/eval/*.jsonl`: 新增结构化 dev/holdout 测试集
  - `waf2/rag/scripts/eval_*.py`: 扩展评估脚本以记录路径与性能指标
  - `waf2/waf2_proxy.py`: 后续 change 中可能引入 ReAct entry gate；本 change 先定义测试与路由目标，不直接实现

