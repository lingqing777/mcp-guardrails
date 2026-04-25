## 1. Artifacts

- [x] 1.1 完成 proposal
- [x] 1.2 完成 spec delta (`waf2`)
- [x] 1.3 完成 design

## 2. Implementation

- [ ] 2.1 调整 `waf2/Dockerfile`，确保镜像包含 RAG 运行目录
- [ ] 2.2 调整 `waf2/.dockerignore`，避免误排除 RAG 必需资产
- [ ] 2.3 校验 `waf2/requirements.txt` 与 RAG 运行依赖一致
- [ ] 2.4 更新 README 一键启动后 RAG 验证步骤

## 3. Validation

- [ ] 3.1 执行 `docker-compose up -d --build` 完成全新构建
- [ ] 3.2 验证 `GET /waf2/rag/info` 返回 enabled=true 且 knowledge base size > 0
- [ ] 3.3 验证 `semantic` 小样本评估可运行（至少 1 轮）
