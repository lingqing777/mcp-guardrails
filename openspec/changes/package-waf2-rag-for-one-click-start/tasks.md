## 1. Artifacts

- [x] 1.1 完成 proposal
- [x] 1.2 完成 spec delta (`waf2`)
- [x] 1.3 完成 design

## 2. Implementation

- [x] 2.1 调整 `waf2/Dockerfile`，确保镜像包含 RAG 运行目录
- [x] 2.2 调整 `waf2/.dockerignore`，避免误排除 RAG 必需资产
- [x] 2.3 校验 `waf2/requirements.txt` 与 RAG 运行依赖一致
- [x] 2.4 更新 README 一键启动后 RAG 验证步骤
- [x] 2.5 合入 ReAct/COT 版 WAF2 主代理，并确认 RAG evidence 注入 ReAct prompt
- [x] 2.6 将 RAG 置信门控默认值调整为 `RAG_CONFIDENCE_THRESHOLD=0.50`

## 3. Validation

- [x] 3.1 执行 `docker-compose up -d --build` 完成全新构建
- [x] 3.2 验证 `GET /waf2/rag/info` 返回 enabled=true 且 knowledge base size > 0
- [x] 3.3 验证 ReAct + RAG 快测可运行，并观察到 RAG ON 相比 RAG OFF 提升 Recall/F1
- [x] 3.4 验证运行态 `eval_mode=false`，避免测试模式影响正常演示
- [x] 3.5 执行 `openspec validate package-waf2-rag-for-one-click-start`
