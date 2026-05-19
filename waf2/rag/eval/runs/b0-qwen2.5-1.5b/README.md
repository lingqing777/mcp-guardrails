# WAF2 RAG 评估报告

## 模型信息
- **模型**: Qwen2.5-1.5B
- **评估数据集**: prompt-injection-eval.jsonl
- **测试用例总数**: 228

---

## 评估结果汇总

| 指标 | RAG OFF | RAG ON | 变化 |
|------|---------|--------|------|
| Blocked | 73 | 107 | +34 |
| Passed | 155 | 121 | -34 |
| **整体拦截率** | **32.0%** | **46.9%** | **+14.9%** |

---

## 各子类别拦截率对比

| 子类别 | Wrap | 总数 | RAG OFF | RAG ON | 提升 |
|--------|------|------|---------|--------|------|
| context_manipulation | chat | 14 | 0.0% | 35.7% | +35.7% |
| context_manipulation | response | 14 | 0.0% | 35.7% | +35.7% |
| direct_prompt_injection | chat | 42 | 45.2% | 59.5% | +14.3% |
| encoded_injection | chat | 20 | 45.0% | 60.0% | +15.0% |
| indirect_prompt_injection | chat | 26 | 46.2% | 61.5% | +15.3% |
| indirect_prompt_injection | response | 26 | 42.3% | 61.5% | +19.2% |
| jailbreak | chat | 37 | 16.2% | 18.9% | +2.7% |
| prompt_leak | chat | 28 | 14.3% | 21.4% | +7.1% |
| tool_poisoning | mcp-rpc | 21 | 57.1% | 71.4% | +14.3% |

---

## 检测到的攻击类别分布

### RAG OFF
| 类别 | 数量 |
|------|------|
| prompt_injection | 41 |
| sql_injection | 11 |
| path_traversal | 8 |
| command_injection | 6 |
| sensitive_data_exposure | 4 |
| ssrf | 2 |
| authentication_bypass | 1 |

### RAG ON
| 类别 | 数量 |
|------|------|
| prompt_injection | 84 |
| sql_injection | 10 |
| path_traversal | 8 |
| command_injection | 3 |
| ssrf | 2 |

---

## 关键发现

1. **RAG开启后整体拦截率提升14.9%**（从32.0%提升至46.9%）

2. **context_manipulation类型提升最显著**：RAG OFF时完全无法检测（0%），RAG ON时达到35.7%

3. **indirect_prompt_injection检测效果最佳**：RAG ON时chat和response wrap均达到61.5%拦截率

4. **jailbreak和prompt_leak仍是薄弱环节**：即使开启RAG，拦截率仍低于22%

5. **prompt_injection检测数量大幅增加**：从41次增加到84次（翻倍+）

---

## 结论

启用RAG后，WAF2对提示注入攻击的防护能力显著提升，特别是在context_manipulation和indirect_prompt_injection方面。但jailbreak和prompt_leak类型的攻击仍需进一步加强防护。
