## ADDED Requirements

### Requirement: WAF2 exposes local-first runtime configuration
WAF2 MUST expose local-first runtime configuration through `GET /waf2/config` and allow supported fields to be changed through `POST /waf2/config`.

#### Scenario: Config includes local-first fields
- **WHEN** `GET /waf2/config` is called
- **THEN** the response MUST include provider locality, privacy mode, local-first enabled state, router thresholds, RAG evidence settings, and ReAct deep-path settings when available

#### Scenario: Config update preserves existing provider compatibility
- **WHEN** `POST /waf2/config` updates local-first fields
- **THEN** WAF2 MUST preserve existing OpenAI-compatible, Anthropic, Gemini, and custom provider behavior unless the user explicitly changes provider fields

### Requirement: WAF2 detection records include route and evidence metadata
WAF2 MUST include route, local score, RAG evidence, and ReAct path metadata in detection records while keeping the existing WAF2 block response format compatible.

#### Scenario: Block response remains compatible
- **WHEN** WAF2 blocks a request after local scoring, RAG, LLM, or ReAct
- **THEN** WAF2 MUST return HTTP 403 with the existing fields `error`, `direction`, `category`, `severity`, `reason`, `owasp`, and `mitre`
- **AND** WAF2 MAY include additional route or evidence fields without removing existing fields

#### Scenario: Detection record includes metadata
- **WHEN** `GET /waf2/detections` returns recent detections
- **THEN** each relevant record MUST include route, route reason, top local scores, RAG outcome, evidence IDs, ReAct entry status, and provider locality when available

### Requirement: WAF2 local provider defaults are supported
WAF2 MUST support local OpenAI-compatible model endpoints as first-class providers and MUST allow local providers to run without API keys.

#### Scenario: Ollama-compatible local endpoint
- **WHEN** WAF2 is configured with `format: "openai"` and `base_url: "http://host.docker.internal:11434/v1"`
- **THEN** WAF2 MUST call `{base_url}/chat/completions`
- **AND** WAF2 MUST omit the Authorization header when API key is empty

#### Scenario: vLLM-compatible local endpoint
- **WHEN** WAF2 is configured with `format: "openai"` and a vLLM OpenAI-compatible base URL
- **THEN** WAF2 MUST call the endpoint using the same OpenAI-compatible request format as online OpenAI-compatible providers

### Requirement: WAF2 distinguishes fail-open, fail-closed, and local-only failures
WAF2 MUST distinguish model call failures, local provider unavailability, ReAct fallback, and parsing failures in stats and detection records.

#### Scenario: Local provider unavailable
- **WHEN** local-first mode is enabled and the configured local provider is unreachable
- **THEN** WAF2 MUST increment a local provider error counter
- **AND** WAF2 MUST use the configured fail-open or fail-closed policy

#### Scenario: Parse failure is counted separately
- **WHEN** a local or online model returns an unparseable decision
- **THEN** WAF2 MUST increment a parse failure counter separate from transport errors
