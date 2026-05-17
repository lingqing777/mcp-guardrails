# Tasks — WAF2 RAG + ReAct Evaluation and Routing Plan

## 1. Artifact Completion

- [x] 1.1 Create proposal for RAG + ReAct evaluation and routing plan
- [x] 1.2 Create design covering taxonomy, failure analysis, route targets, and model matrix
- [x] 1.3 Create specs for evaluation datasets and WAF2 route-aware evaluation

## 2. Dataset Taxonomy

- [ ] 2.1 Define canonical dataset classes:
  - classic_web_attack
  - encoded_obfuscated_attack
  - prompt_injection
  - mcp_tool_poisoning
  - data_exfiltration
  - sensitive_response_leakage
  - benign_hard_negative
  - normal_business_traffic
- [ ] 2.2 Define JSONL schema with expected path and needs_rag/needs_react/needs_tool flags
- [ ] 2.3 Convert existing adversarial samples to the structured schema
- [ ] 2.4 Create dev set v1 (target 150-200 samples)
- [ ] 2.5 Create holdout set v1 (target 80-120 samples)
- [ ] 2.6 Confirm holdout samples are not injected into the RAG KB

## 3. Evaluation Script Design

- [ ] 3.1 Extend or create evaluator to report observed path, not only BLOCK/PASS
- [ ] 3.2 Record path metrics: rag_queries, rag_augmented, rag_gated, react_entered, tool_called, tool_iterations
- [ ] 3.3 Record performance metrics: average latency, p95 latency, max latency, LLM calls per request
- [ ] 3.4 Record quality metrics: wrong_category, format_error, llm_error, parse_failed
- [ ] 3.5 Emit per-class metrics and failure list

## 4. Failure Analysis Loop

> **Scope moved to `add-waf2-eval-failure-analysis-loop`** (2026-05-17). The structured per-case schema, R1-R8 auto-derivation, B-1 sampling, and the fix-bucket ROI report were factored into that change. Items 4.1-4.3 are kept as a back-reference and will close out alongside its archive. `eval_*.py` per-case JSONL output (task 3.1-3.5 below) was also implemented there.

- [ ] 4.1 Run current WAF2 RAG + ReAct on dev set v1 with glm-4-flash
- [ ] 4.2 Label each FP/FN with failure cause:
  - did_not_enter_rag
  - rag_wrong_evidence
  - rag_ignored
  - did_not_enter_react
  - react_tool_not_used
  - react_observation_ignored
  - static_rule_false_positive
  - llm_output_or_parse_failure
- [ ] 4.3 Decide whether failures indicate prompt change, threshold change, ReAct entry change, static-rule exception, or KB expansion
- [ ] 4.4 Document tuning decisions before implementing them

## 5. ReAct Routing Strategy

- [ ] 5.1 Define cheap signals for ReAct entry:
  - encoding/obfuscation indicators
  - MCP/tool fields
  - RAG category/top_score
  - LLM inconclusive output
  - high-risk field names
- [ ] 5.2 Define target ReAct entry rates by data class
- [ ] 5.3 Decide Fast Path / Middle Path / Deep Path route boundaries
- [ ] 5.4 Decide fallback behavior when ReAct reaches max iterations
- [ ] 5.5 If route design is stable, start a separate implementation change for ReAct routing

## 6. Model Evaluation Plan

- [ ] 6.1 Round 1: architecture validation with glm-4-flash across LLM only / RAG+LLM / ReAct only / RAG+ReAct
- [ ] 6.2 Round 2: fixed architecture model comparison across glm-4-flash, Qwen2.5-7B, GPT mini-class, Claude Haiku-class, DeepSeek Chat-class
- [ ] 6.3 Round 3: cost and latency analysis
- [ ] 6.4 Produce model comparison report with accuracy, latency, cost, error rate, and route statistics

## 7. OpenSpec Validation

- [x] 7.1 Run `openspec validate evaluate-waf2-rag-react-routing-and-models`
- [ ] 7.2 Review whether `package-waf2-rag-for-one-click-start` can be verified/archived after cold-start demo rehearsal

## 8. Dashboard Visibility

- [x] 8.1 Surface WAF2 RAG, ReAct, and routing path metrics in the dashboard for demos
