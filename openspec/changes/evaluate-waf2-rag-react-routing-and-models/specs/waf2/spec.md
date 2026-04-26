# WAF2 — RAG/ReAct Routing Evaluation Delta

## ADDED Requirements

### Requirement: WAF2 must support route-aware evaluation

WAF2 evaluation MUST distinguish whether a decision came from static rules, RAG-assisted LLM, ReAct tool reasoning, deterministic detectors, or fast-pass behavior.

#### Scenario: Evaluation captures decision path

- **WHEN** a WAF2 request is evaluated in a test run
- **THEN** the evaluation output SHOULD record the observed path:
  - `static`
  - `fast_pass`
  - `rag_llm`
  - `rag_react`
  - `react_tool`
  - `detector`
- **AND** the observed path SHOULD be compared with the sample's `expected_path`

### Requirement: ReAct should be treated as a deep path, not the default path

ReAct/COT analysis MUST be evaluated as a high-cost deep path whose entry rate must be controlled.

#### Scenario: Normal traffic is evaluated

- **WHEN** normal business traffic is evaluated
- **THEN** the target ReAct entry rate SHOULD be below 5%
- **AND** most normal samples SHOULD use fast-pass or lightweight analysis paths

#### Scenario: Encoded or obfuscated attacks are evaluated

- **WHEN** encoded or obfuscated attack samples are evaluated
- **THEN** the target ReAct entry rate SHOULD be above 70%
- **AND** tool calls SHOULD be observed for samples marked `needs_tool=true`

#### Scenario: MCP tool poisoning is evaluated

- **WHEN** MCP/tool-poisoning samples are evaluated
- **THEN** the target ReAct entry rate SHOULD be above 50%
- **AND** RAG evidence SHOULD be available for samples marked `needs_rag=true`

### Requirement: RAG evidence must be evaluated as decision support

RAG MUST be evaluated by whether it improves final decisions and whether evidence is used correctly, not merely by whether retrieval occurs.

#### Scenario: RAG retrieves evidence

- **WHEN** RAG returns evidence above threshold
- **THEN** the evaluation SHOULD record whether the final decision used that evidence appropriately
- **AND** benign hard negatives SHOULD verify that RAG evidence does not cause over-blocking when context contradicts the retrieved payload
