## Decision

采用“镜像预置 RAG 资产”作为默认交付路径。

截至当前主线，WAF2 交付形态已从“代理 + RAG 资产”进一步演进为“代理 + RAG 资产 + ReAct/COT 工具化推理”。本 change 的核心仍是交付可复现性：队友从 git 拉取后，通过 `start.sh` / `start.bat` 构建镜像即可得到可用 RAG 环境，而不依赖个人本地残留文件。

## Rationale

在当前架构中（MCP Hub 宿主机 + WAF2 Docker），只有镜像预置可以同时满足：

1. 一键启动可用
2. 团队复现一致
3. 不要求每位队友额外执行初始化脚本

相较方案：

- 提交整个本地产物目录到 Git：仓库膨胀且难维护
- 容器启动时动态构建 KB：首次启动慢、失败点多、体验不稳定

## Design Outline

1. WAF2 Docker 构建阶段将 RAG 运行目录纳入镜像
2. 保留必要依赖与模型/知识库可用性校验
3. 启动后以 `/waf2/rag/info` 作为健康验证入口
4. 通过 `.dockerignore` 控制构建上下文，避免无关文件进入镜像
5. WAF2 主代理使用 ReAct/COT 管线时，RAG 检索结果作为 `retrieved_context` 注入 Agent prompt
6. 默认 `RAG_CONFIDENCE_THRESHOLD=0.50`，使中等相似度证据能进入 ReAct 证据审查，而不是被过早门控

## Trade-offs

- 镜像体积会增加（可接受，换可复现）
- 构建时间略增（可接受，换一键体验）
- ReAct/COT 管线比一次性 LLM 判断更慢。该问题不属于本 change 的交付打包范围，后续通过独立评估与路由设计控制深度推理进入量

## Rollout

1. 先在当前主线验证 `start.sh` 冷启动可用
2. 再补充 README 验证指令与故障排查

## Current Validation Snapshot

- `docker-compose up -d --build waf2` 可构建包含 RAG 资产的镜像
- `/waf2/rag/info` 返回 `enabled=true` 且 `total_entries=3354`
- WAF2 启动日志显示 `STATIC_RULES → KEYWORDS → RAG → ReAct Agent`
- ReAct 工具列表包含 `decode_base64`、`url_decode`、`decode_hex`、`decode_unicode`、`rag_search`
- 快测中，RAG ON + ReAct 相比 RAG OFF + ReAct 的 Recall/F1 有提升，且未增加误报率

## Follow-up

本 change 只解决“RAG + ReAct 能被一键启动复现”。下一步需要单独设计评估与路由：

- 定义 WAF2 测试数据分类与 dev/holdout 切分
- 基于分类结果调试 RAG、ReAct、工具调用和静态规则边界
- 设计 ReAct 进入条件，减少深度思考进入量
- 在架构稳定后做多模型矩阵评估
