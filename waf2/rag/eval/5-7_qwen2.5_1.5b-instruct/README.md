# WAF2 RAG 评估结果 - Qwen2.5 1.5B Instruct

## 概述

本目录包含使用 **Qwen2.5 1.5B Instruct** 模型进行 WAF2 (Web Application Firewall) RAG (Retrieval-Augmented Generation) 功能评估的结果数据。

## 目录结构

```
├── waf2-config.json    # WAF2 配置文件
├── waf2-stats.json     # 评估统计数据
├── results_100.md      # 100 条样本评估报告
├── results_250.md      # 250 条样本评估报告
├── results_500.md      # 500 条样本评估报告
├── failures_100.jsonl  # 100 条样本失败记录
├── failures_250.jsonl  # 250 条样本失败记录
└── failures_500.jsonl  # 500 条样本失败记录
```

## 配置信息

| 参数 | 值 |
|------|-----|
| 模型 | qwen2.5:1.5b-instruct |
| 提供者 | Ollama (本地) |
| 知识库大小 | 3364 条 |
| RAG Top-K | 5 |
| RAG 阈值 | 0.6 |
| 本地分数阻断阈值 | 0.88 |
| 快速通过阈值 | 0.12 |
| 评估模式 | 启用 |

## 评估结果摘要

基于 `waf2-stats.json` 的完整评估（1000 条样本）：

| 指标 | 数值 |
|------|------|
| 总样本数 | 1000 |
| 通过 | 698 |
| 阻断 | 302 |
| 缓存命中率 | 87.9% |
| 平均延迟 | 742ms |
| LLM 调用次数 | 52 |
| RAG 查询次数 | 52 |
| RAG 命中次数 | 12 |

## 文件说明

### waf2-config.json
WAF2 运行时配置，包含模型设置、RAG 参数、路由策略等。

### waf2-stats.json
完整评估统计，包含流量分布、缓存性能、RAG 效果等关键指标。

### results_{n}.md
不同样本量的详细评估报告，包含精确率、召回率、F1 分数、混淆矩阵等。

### failures_{n}.jsonl
失败样本记录，每行一条 JSON，包含请求详情和失败原因。

## 评估数据集

使用 **CSIC 2010** 数据集，包含攻击和正常请求样本。

## 使用方法

```bash
# 查看评估报告
cat results_100.md

# 分析失败样本
cat failures_100.jsonl | head -20
```