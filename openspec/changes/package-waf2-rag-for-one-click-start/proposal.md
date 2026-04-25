## Why

当前项目目标是 `./start.sh` / `start.bat` 一键启动后即可完整演示双层防护（WAF1 + WAF2）。

现状中 WAF2 运行在 Docker 容器内，而 RAG 相关代码与数据在仓库 `waf2/rag/`。若镜像未完整打包这些资产，队友环境会出现：

- 服务可启动，但 RAG 不可用或行为不一致
- 本地可用、他人不可复现
- 评估结果与演示效果不稳定

因此需要将 RAG 作为 WAF2 镜像的标准交付资产，而不是依赖个人本地残留文件。

## What Changes

- 将 WAF2 镜像构建改为包含 RAG 运行代码与运行所需资产
- 保证 `docker-compose up -d --build` 后，WAF2 容器内具备可用 RAG 环境
- 在启动与文档中明确“一键启动默认具备 RAG 能力”
- 明确哪些内容属于镜像资产，哪些属于本地开发产物（避免仓库污染）

## Capability Scope

### Modified Capabilities

- `waf2`: 交付形态从“仅代理脚本”升级为“代理 + RAG 可运行资产”
- `docker`: WAF2 构建流程支持可复现 RAG 运行环境

## Impact

- `waf2/Dockerfile`: 调整 COPY 与构建步骤，确保容器内具备 RAG 目录/依赖
- `waf2/.dockerignore`: 调整忽略策略，避免误排除必要 RAG 资产
- `waf2/requirements.txt`: 保持与 RAG 运行依赖一致
- `README.md`: 更新一键启动后 RAG 可用的说明与验证命令
