## ADDED Requirements

### Requirement: Local-first data plane privacy
WAF2 SHALL treat HTTP request bodies, HTTP response bodies, cookies, tokens, MCP tool arguments, RAG queries, retrieved evidence, LLM prompts and detection logs as local data-plane material. WAF2 MUST NOT send data-plane material to an online provider unless the user explicitly configures an online provider and disables local-only privacy mode.

#### Scenario: Local provider keeps traffic local
- **WHEN** WAF2 is configured with `provider_locality: "local"` and an OpenAI-compatible local `base_url`
- **THEN** WAF2 MUST send LLM requests only to that local `base_url`
- **AND** WAF2 MUST report `privacy_mode: "local_only"` through config and dashboard APIs

#### Scenario: Online provider requires explicit opt-in
- **WHEN** the user configures an online `base_url`
- **THEN** WAF2 MUST mark `provider_locality: "online"`
- **AND** WAF2 MUST expose that request data may leave the host through config and dashboard APIs

#### Scenario: Control-plane updates are separate from data-plane traffic
- **WHEN** WAF2 updates rules, payload knowledge, CVE/CWE/CAPEC metadata, or model assets
- **THEN** the update process MUST NOT upload captured user request/response data or MCP tool arguments

### Requirement: Local-first detection pipeline order
WAF2 SHALL process requests through a layered local-first pipeline before forwarding to the target application. The request-side order MUST be normalize/decode, deterministic guard, local attack scoring, local knowledge evidence retrieval, risk routing, and only then local LLM one-shot or ReAct deep inspection when required.

#### Scenario: Request passes through local layers before LLM
- **WHEN** WAF2 receives an HTTP request and request analysis is enabled
- **THEN** WAF2 MUST normalize/decode the request before static rules, RAG retrieval, LLM calls, or ReAct tools
- **AND** WAF2 MUST compute local attack scores before deciding whether to call a model

#### Scenario: High-confidence deterministic attack blocks without model call
- **WHEN** deterministic guard or local attack score produces a high-confidence attack decision
- **THEN** WAF2 MUST return HTTP 403 using the existing WAF2 block response format
- **AND** WAF2 MUST NOT call the LLM or ReAct for that request

#### Scenario: Low-risk normal traffic avoids deep inspection
- **WHEN** a request has low deterministic risk, low attack scores, and no relevant knowledge evidence
- **THEN** WAF2 SHOULD route the request through fast pass
- **AND** WAF2 MUST record the route in detection or route statistics

### Requirement: Knowledge evidence layer
WAF2 SHALL treat RAG retrieval as a local knowledge evidence layer. Retrieved evidence MUST include enough metadata for auditability, including evidence ID, category, source, similarity score, and whether the evidence is positive attack evidence or benign hard-negative evidence.

#### Scenario: Attack evidence augments gray-zone decision
- **WHEN** a gray-zone request retrieves high-similarity attack evidence
- **THEN** WAF2 MUST include the evidence IDs and categories in the LLM or ReAct prompt context
- **AND** the final detection record MUST include the evidence IDs used

#### Scenario: Benign hard-negative evidence reduces false positives
- **WHEN** a request retrieves high-similarity benign hard-negative evidence
- **THEN** WAF2 MUST expose that evidence to the risk router or local LLM judge
- **AND** the detection record MUST show that benign evidence was considered

#### Scenario: Empty RAG result is explicit
- **WHEN** the knowledge evidence layer has no relevant result above threshold
- **THEN** WAF2 MUST record the retrieval outcome as empty or gated
- **AND** downstream routing MUST NOT pretend that external evidence exists

### Requirement: ReAct deep inspection path
WAF2 SHALL use ReAct/COT only as an optional deep inspection path for gray-zone requests. ReAct MUST NOT be the default route for normal business traffic or obvious deterministic attacks.

#### Scenario: Encoded gray-zone request enters deep inspection
- **WHEN** a request contains suspicious encoding and deterministic decode cannot reach a final high-confidence decision
- **THEN** the risk router MAY send the request to ReAct deep inspection
- **AND** the route record MUST include the reason for ReAct entry

#### Scenario: Normal request does not enter ReAct
- **WHEN** a request has low local attack scores and no high-risk evidence
- **THEN** WAF2 MUST NOT enter ReAct deep inspection

#### Scenario: ReAct fallback is explicit
- **WHEN** ReAct reaches max iterations or cannot produce a parseable final decision
- **THEN** WAF2 MUST record `route_agent_fallback`
- **AND** WAF2 MUST use the configured fail-open or fail-closed policy for final handling

### Requirement: Risk router observability
WAF2 SHALL expose route decisions and route reasons for each analyzed request and aggregate route statistics through WAF2 APIs.

#### Scenario: Route fields appear in detection records
- **WHEN** `GET /waf2/detections` returns a WAF2 detection record
- **THEN** the record MUST include route name, route reason, provider locality, local score summary, RAG outcome, and ReAct entry status when available

#### Scenario: Route stats appear in dashboard payload
- **WHEN** `GET /waf2/dashboard` returns WAF2 dashboard data
- **THEN** the payload MUST include route counters for static block, fast pass, knowledge evidence path, local LLM one-shot, ReAct deep inspection, and fallback
