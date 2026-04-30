## ADDED Requirements

### Requirement: Request normalization and decode
WAF2 SHALL normalize and decode request method, path, query string, headers selected for security analysis, and body before local attack scoring. The normalization result MUST retain both original and decoded forms for evidence and logging.

#### Scenario: Double URL encoded SQLi is decoded
- **WHEN** a request contains `%2527%2520OR%25201%253D1--`
- **THEN** WAF2 MUST produce a decoded representation containing `' OR 1=1--`
- **AND** local scoring MUST evaluate the decoded representation

#### Scenario: Unicode escape payload is decoded
- **WHEN** a request body contains JSON text with `\\u003cscript\\u003e`
- **THEN** WAF2 MUST produce a decoded representation containing `<script>`
- **AND** XSS scoring MUST evaluate the decoded representation

#### Scenario: Original payload is preserved
- **WHEN** WAF2 decodes or normalizes any request component
- **THEN** detection records MUST preserve enough original payload context to explain the decision without losing the raw input shape

### Requirement: Local attack score categories
WAF2 SHALL compute local attack scores for web, agent, data leakage, and MCP/tool abuse risks. Scores MUST be normalized to a consistent numeric range and include evidence terms.

#### Scenario: SQL injection score
- **WHEN** a decoded request contains SQL injection indicators such as boolean tautology, UNION query, stacked statement, comment truncation, or schema enumeration
- **THEN** WAF2 MUST increase `sqli_score`
- **AND** score evidence MUST identify the matched indicators

#### Scenario: Prompt injection score
- **WHEN** a request contains direct or indirect instruction override patterns, jailbreak framing, role hijacking, or multilingual prompt manipulation
- **THEN** WAF2 MUST increase `prompt_injection_score`
- **AND** score evidence MUST identify the prompt manipulation indicators

#### Scenario: MCP tool abuse score
- **WHEN** a request or tool argument contains high-risk MCP/tool behavior such as tool poisoning, exfiltration target, dangerous tool chaining, or privilege-like operation intent
- **THEN** WAF2 MUST increase `mcp_tool_abuse_score`
- **AND** score evidence MUST identify the tool-related risk indicators

### Requirement: Score-based route inputs
The risk router SHALL consume local attack scores as first-class route inputs. The router MUST support configurable thresholds for direct block, gray-zone analysis, and fast pass.

#### Scenario: High score routes to block
- **WHEN** a category score exceeds its configured direct-block threshold with high-confidence evidence
- **THEN** WAF2 MUST block the request with HTTP 403
- **AND** the block response MUST include the matching attack category and reason

#### Scenario: Medium score routes to evidence or model path
- **WHEN** one or more category scores fall into the configured gray-zone range
- **THEN** WAF2 MUST route the request to local knowledge evidence retrieval, local LLM one-shot, or ReAct based on route policy

#### Scenario: Low score routes to fast pass
- **WHEN** all category scores are below the configured low-risk threshold and no deterministic rule matches
- **THEN** WAF2 MUST avoid unnecessary local LLM or ReAct calls for that request

### Requirement: Score reporting for tuning
WAF2 SHALL report local attack score summaries for evaluation and tuning without exposing unnecessary full sensitive payloads in aggregate stats.

#### Scenario: Detection record includes score summary
- **WHEN** WAF2 stores a detection record
- **THEN** the record MUST include top category scores, matched evidence terms, and route decision

#### Scenario: Dashboard stats include aggregate score distribution
- **WHEN** `GET /waf2/dashboard` returns aggregate WAF2 data
- **THEN** it MUST include route and score aggregates suitable for tuning thresholds

#### Scenario: Evaluation script can read score fields
- **WHEN** the evaluator collects WAF2 detection or route data
- **THEN** it MUST be able to associate each sample with observed top scores and route decisions
