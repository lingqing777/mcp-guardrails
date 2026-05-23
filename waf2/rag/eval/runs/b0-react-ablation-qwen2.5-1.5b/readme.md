# RAG Prompt Injection Evaluation: React Ablation Study

## Overview

This directory contains the results of a prompt injection evaluation comparing two WAF2 RAG modes:
- **React ON**: With ReAct deep inspection enabled
- **React OFF**: Without ReAct deep inspection (one-shot mode only)

Model: Qwen2.5-1.5B

## Files

| File | Description |
|------|-------------|
| `b0-react-on-report.json` | Evaluation report for React ON mode |
| `b0-react-off-report.json` | Evaluation report for React OFF mode |
| `cases-b0-rag-on.jsonl` | Detailed case results |
| `output_react_on.txt` | Full output log for React ON run |
| `output_react_off.txt` | Full output log for React OFF run |

## Key Results

### Overall Performance

| Mode | Total Cases | Blocked | Passed | Block Rate |
|------|-------------|---------|--------|------------|
| React ON | 228 | 107 | 121 | **46.9%** |
| React OFF | 228 | 56 | 172 | **24.6%** |

### Block Rate by Subcategory

| Subcategory | React ON BR | React OFF BR | Improvement |
|-------------|-------------|--------------|-------------|
| context_manipulation | 35.7% | 0.0% | +35.7% |
| direct_prompt_injection | 59.5% | 42.9% | +16.6% |
| encoded_injection | 60.0% | 35.0% | +25.0% |
| indirect_prompt_injection | 61.5% | 26.9% | +34.6% |
| jailbreak | 18.9% | 5.4% | +13.5% |
| prompt_leak | 21.4% | 14.3% | +7.1% |
| tool_poisoning | 71.4% | 52.4% | +19.0% |

### Detected Categories

| Category | React ON | React OFF |
|----------|----------|-----------|
| prompt_injection | 84 | 33 |
| sql_injection | 10 | 10 |
| command_injection | 3 | 3 |
| path_traversal | 8 | 8 |
| ssrf | 2 | 2 |

### Performance Metrics

| Metric | React ON | React OFF |
|--------|----------|-----------|
| avg_latency_ms | 22417 | 61 |
| llm_calls | 172 | 172 |
| rag_queries | 172 | 172 |
| agent_invocations | 131 | 0 |

## Conclusions

1. **React deep inspection significantly improves security**: The overall block rate increased from 24.6% to 46.9% when ReAct was enabled.

2. **Most improvement in complex attacks**: The biggest gains were seen in:
   - `context_manipulation`: +35.7% (from 0% to 35.7%)
   - `indirect_prompt_injection`: +34.6% (from 26.9% to 61.5%)
   - `encoded_injection`: +25.0% (from 35.0% to 60.0%)

3. **Trade-off with latency**: React mode introduces significant latency (22417ms vs 61ms) due to additional agent invocations and deep inspection.

4. **Static rules unchanged**: SQL injection, command injection, path traversal, and SSRF detection remained identical, indicating these are handled by static rules rather than the ReAct engine.

## Evaluation Command

```bash
# React ON
python waf2/rag/scripts/eval_prompt_injection.py \
  --waf2 http://localhost:8081 \
  --dataset waf2/rag/eval/prompt-injection-eval.jsonl \
  --mode on \
  --report b0-react-on-report.json \
  --cases-out-dir .

# React OFF
python waf2/rag/scripts/eval_prompt_injection.py \
  --waf2 http://localhost:8081 \
  --dataset waf2/rag/eval/prompt-injection-eval.jsonl \
  --mode on \
  --report b0-react-off-report.json \
  --cases-out-dir .
```
