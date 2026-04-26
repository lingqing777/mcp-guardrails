# WAF2 RAG + ReAct Evaluation

## Purpose

定义 WAF2 RAG + ReAct/COT 管线的测试分类、评估指标、调试闭环和模型评估矩阵，避免在未固定架构前盲目做大规模模型测试。

## ADDED Requirements

### Requirement: Evaluation dataset taxonomy

The evaluation plan MUST define explicit data classes for WAF2 RAG + ReAct testing.

#### Scenario: Dataset classes are declared

- **WHEN** evaluation data is prepared
- **THEN** each sample MUST belong to one of:
  - `classic_web_attack`
  - `encoded_obfuscated_attack`
  - `prompt_injection`
  - `mcp_tool_poisoning`
  - `data_exfiltration`
  - `sensitive_response_leakage`
  - `benign_hard_negative`
  - `normal_business_traffic`
- **AND** each class MUST have a documented purpose and expected pipeline path

### Requirement: Structured sample metadata

Evaluation samples MUST carry enough metadata to explain not only correctness but also path correctness.

#### Scenario: JSONL sample format

- **WHEN** a JSONL sample is added to a dev or holdout dataset
- **THEN** it MUST include:
  - `id`
  - `label`
  - `category`
  - `method`
  - `path`
  - `expected_decision`
  - `expected_path`
  - `needs_rag`
  - `needs_react`
  - `needs_tool`
  - `hard_negative`
  - `rationale`
- **AND** `expected_path` MUST be one of `static`, `fast_pass`, `rag_llm`, `rag_react`, `react_tool`, `detector`

### Requirement: Dev and holdout separation

The evaluation process MUST separate tuning data from final validation data.

#### Scenario: Dev set is used for tuning

- **WHEN** prompt, thresholds, route gates, or KB content are changed based on samples
- **THEN** those samples MUST be treated as dev set samples
- **AND** they MUST NOT be used as final holdout evidence

#### Scenario: Holdout set is used for validation

- **WHEN** final RAG/ReAct effectiveness is reported
- **THEN** holdout samples MUST NOT have been used to tune RAG thresholds, ReAct entry gates, prompts, or KB contents
- **AND** holdout samples MUST NOT be injected into the RAG knowledge base

### Requirement: Failure analysis categories

Every false positive and false negative in dev-set runs MUST be categorized by failure cause.

#### Scenario: Failure cause is assigned

- **WHEN** a dev-set sample fails
- **THEN** the failure MUST be assigned one of:
  - `did_not_enter_rag`
  - `rag_wrong_evidence`
  - `rag_ignored`
  - `did_not_enter_react`
  - `react_tool_not_used`
  - `react_observation_ignored`
  - `static_rule_false_positive`
  - `llm_output_or_parse_failure`
- **AND** the next tuning action SHOULD be selected based on that cause

### Requirement: Metrics beyond F1

Evaluation reports MUST include detection, path, performance, and quality metrics.

#### Scenario: Evaluation report is generated

- **WHEN** a WAF2 RAG + ReAct evaluation report is generated
- **THEN** it MUST include Precision, Recall, F1, FPR, TP, FP, TN, FN
- **AND** it MUST include path metrics such as `rag_queries`, `rag_augmented`, `rag_gated`, `react_entered`, `tool_called`
- **AND** it SHOULD include performance metrics such as average latency, p95 latency, max latency, LLM calls per request, and agent iterations
- **AND** it SHOULD include quality metrics such as wrong category, format error, LLM error, and parse failure counts

### Requirement: Model evaluation must follow architecture stabilization

Multi-model evaluation MUST be performed only after the WAF2 architecture and route gates are fixed for that round.

#### Scenario: Model matrix is executed

- **WHEN** comparing multiple models
- **THEN** the WAF2 detection mode, RAG thresholds, ReAct entry policy, datasets, and prompt version MUST be fixed
- **AND** the report MUST compare both detection quality and cost/latency

