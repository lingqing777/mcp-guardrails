## ADDED Requirements

### Requirement: Local model evaluation matrix
WAF2 evaluation SHALL compare local models and online API baselines with the same dataset split, route configuration, and thresholds unless a test explicitly declares otherwise.

#### Scenario: Compare local and online providers
- **WHEN** an evaluation run includes both local and online models
- **THEN** the report MUST identify provider locality, model name, base URL class, and whether request data leaves the host

#### Scenario: Fixed architecture model comparison
- **WHEN** comparing multiple models
- **THEN** the evaluator MUST keep RAG, ReAct, attack-score thresholds, and router configuration fixed for that comparison round

#### Scenario: Local provider with no API key
- **WHEN** a local OpenAI-compatible provider does not require an API key
- **THEN** WAF2 evaluation MUST support running without sending an Authorization header

### Requirement: Route-aware evaluation metrics
WAF2 evaluation SHALL report quality, route, performance, and privacy metrics for each dataset class and for the full run.

#### Scenario: Quality metrics are reported
- **WHEN** an evaluation run completes
- **THEN** the report MUST include Precision, Recall, F1, FPR, TP, FP, TN, FN, wrong category count, parse failures, and LLM errors

#### Scenario: Route metrics are reported
- **WHEN** an evaluation run completes
- **THEN** the report MUST include static block rate, fast pass rate, RAG query/hit/gated/empty counts, local LLM call rate, ReAct entry rate, tool call count, and fallback count

#### Scenario: Performance metrics are reported
- **WHEN** an evaluation run completes
- **THEN** the report MUST include average latency, p95 latency, max latency, and model/provider notes

#### Scenario: Privacy metrics are reported
- **WHEN** an evaluation run completes
- **THEN** the report MUST state whether the run was local-only, online, or mixed
- **AND** it MUST identify which parts of the detection path could send request data outside the host

### Requirement: Dataset classes for final evaluation
WAF2 evaluation SHALL use both traditional Web WAF data and MCP/Agent-specific data. Reports MUST show per-class results so improvements are not hidden inside aggregate F1.

#### Scenario: Traditional Web classes are evaluated
- **WHEN** running the Web WAF evaluation set
- **THEN** the evaluator MUST report separate metrics for classic web attacks, encoded/obfuscated attacks, benign hard negatives, and normal business traffic

#### Scenario: MCP Agent classes are evaluated
- **WHEN** running the MCP/Agent evaluation set
- **THEN** the evaluator MUST report separate metrics for prompt injection, MCP tool poisoning, data exfiltration, sensitive response leakage, and tool-chain abuse

#### Scenario: Holdout set is protected from KB leakage
- **WHEN** a holdout evaluation set is used
- **THEN** holdout samples MUST NOT be inserted into the RAG knowledge base before or during that evaluation

### Requirement: Recall-oriented tuning workflow
WAF2 evaluation SHALL support a tuning workflow that prioritizes recall improvement while monitoring false positive pressure.

#### Scenario: False negatives are categorized
- **WHEN** an attack sample is missed
- **THEN** the evaluator or failure-analysis report MUST classify the likely cause as decode failure, score threshold failure, RAG coverage gap, router miss, LLM judgment error, ReAct tool failure, or static-rule gap

#### Scenario: False positives are categorized
- **WHEN** a benign sample is blocked
- **THEN** the evaluator or failure-analysis report MUST classify whether the cause was static overmatch, attack score overmatch, RAG evidence overtrust, LLM judgment error, ReAct reasoning error, or missing hard-negative evidence

#### Scenario: Dev and holdout tuning separation
- **WHEN** thresholds, KB content, prompts, or route policies are tuned
- **THEN** tuning MUST be performed on dev data
- **AND** holdout data MUST be used only for final validation
