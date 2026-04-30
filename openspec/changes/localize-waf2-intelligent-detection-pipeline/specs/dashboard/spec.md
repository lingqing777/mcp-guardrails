## ADDED Requirements

### Requirement: Dashboard shows local-first WAF2 status
Dashboard SHALL show whether WAF2 is running in local-only, online, or mixed provider mode and whether request data can leave the host.

#### Scenario: Local-only mode visible
- **WHEN** Dashboard loads WAF2 config or dashboard data with `privacy_mode: "local_only"`
- **THEN** the WAF2 panel MUST show that detection is local-only
- **AND** it MUST show the configured local provider/model when available

#### Scenario: Online mode visible
- **WHEN** Dashboard loads WAF2 config or dashboard data with `provider_locality: "online"`
- **THEN** the WAF2 panel MUST visibly indicate that online provider mode is active
- **AND** it MUST avoid implying that request data stays local

### Requirement: Dashboard shows route, score, evidence, and deep-path metrics
Dashboard SHALL visualize WAF2 route distribution and per-detection route details without breaking the existing 5-second refresh flow.

#### Scenario: Aggregate route metrics render
- **WHEN** `GET /waf2/dashboard` includes route counters and score aggregates
- **THEN** Dashboard MUST render static block, fast pass, RAG/evidence path, local LLM one-shot, ReAct deep inspection, and fallback counts

#### Scenario: Detection details render new metadata
- **WHEN** a detection record includes route, local scores, RAG evidence IDs, and ReAct entry status
- **THEN** Dashboard MUST show those fields in the WAF2 or detections view
- **AND** missing fields MUST be handled with safe fallbacks for older WAF2 payloads

### Requirement: Dashboard preserves existing visual language
Dashboard changes for local-first WAF2 SHALL preserve the existing Grafana dark, Linear gradient, and Tabler-like layout language.

#### Scenario: New panels match existing style
- **WHEN** local-first WAF2 cards, badges, route chips, or score widgets are added
- **THEN** they MUST use the existing color tokens, spacing, typography, card radius, transition style, and dashboard layout conventions

#### Scenario: Refresh remains stable
- **WHEN** Dashboard refreshes every 5 seconds
- **THEN** new local-first metrics MUST update without layout jump, console errors, or blocking other dashboard panels
