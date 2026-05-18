# waf2-rag-enforcement delta

## ADDED Requirements

### Requirement: ReAct fallback rescue via RAG-decisive evidence

WAF2 SHALL rescue a request from the default ReAct fallback PASS outcome by emitting a BLOCK verdict when (a) the ReAct agent terminates without producing a `final_answer` (parse failure or `max_iters` exhausted), AND (b) the RAG retrieval result carries a sufficiently strong, category-aligned signal. The rescue logic MUST be confined to the `agent_analyze_request` and `agent_analyze_response` callers; the `run_react_agent` core function MUST remain RAG-agnostic.

The rescue MUST trigger only when ALL of:

- `config.rag_decisive_fallback_enabled` is `True`
- `rag_meta.rag_used == True`
- `rag_meta.rag_top_score >= config.rag_decisive_fallback_min_score` (default `0.55`)
- A category can be resolved via **dual-source category selection**:
  1. If `rag_meta.rag_top_category` ∈ `config.rag_decisive_fallback_categories` (default `{"prompt_injection"}`), use it.
  2. Otherwise, if `local_attack_score.top_category` ∈ the same whitelist AND `local_attack_score.top_score >= 0.35` (the gray-zone threshold), use the local category instead.
  3. If neither source resolves to a whitelisted category, rescue MUST NOT trigger.

The dual-source rule requires **two independent signals** (high RAG score + a whitelisted category from either RAG or local scorer) to fire, which is strictly more conservative than relaxing the whitelist to include additional categories.

When rescue triggers, WAF2 MUST return a detection result with:

- `blocked: True`
- `category: <rag_top_category>`
- `engine: "rag_decisive_fallback"`
- `route: "react_fallback_rag_rescue"`
- `route_reasons` containing `"rag_decisive_fallback"` and a `"rag_score=<score>"` token
- `reason` string explaining the rescue mechanism

When rescue does NOT trigger (any predicate fails), WAF2 MUST preserve the existing fallback behavior (return `None` to the analyze entry point, which leads to PASS).

The pre-existing `_SALVAGE_BLOCK_RE` mechanism inside `_parse_agent_action` MUST remain unchanged; it runs first as a per-step rescue, and the RAG-decisive fallback rescue introduced here runs only when SALVAGE itself failed.

#### Scenario: Rescue fires when RAG hits with sufficient evidence

- **WHEN** ReAct exhausts max_iters without producing a `final_answer`
- **AND** `rag_meta` indicates `rag_used=True`, `rag_top_score=0.62`, `rag_top_category="prompt_injection"`
- **AND** `rag_decisive_fallback_enabled=True` with default thresholds
- **THEN** the detection result MUST be `blocked=True` with `category="prompt_injection"`
- **AND** `route` MUST be `"react_fallback_rag_rescue"`
- **AND** `engine` MUST be `"rag_decisive_fallback"`

#### Scenario: Rescue skipped when RAG score below threshold

- **WHEN** ReAct fails to produce a verdict
- **AND** `rag_top_score=0.45` (below default 0.55)
- **THEN** rescue MUST be skipped
- **AND** the fallback MUST resolve to PASS (return None from analyze entry point)

#### Scenario: Rescue skipped when RAG category not in whitelist

- **WHEN** ReAct fails to produce a verdict
- **AND** `rag_top_score=0.70`, but `rag_top_category="sql_injection"` (not in default whitelist)
- **AND** `local_attack_score.top_category="sql_injection"` (also not in whitelist)
- **THEN** rescue MUST be skipped
- **AND** the fallback MUST resolve to PASS

#### Scenario: Rescue uses local category when RAG category is mis-matched

- **WHEN** ReAct fails to produce a verdict
- **AND** `rag_top_score=0.58`, `rag_top_category="sql_injection"` (not in whitelist)
- **AND** `local_attack_score.top_category="prompt_injection"` with `top_score=0.55` (≥ 0.35 gray threshold)
- **THEN** rescue MUST trigger via the dual-source fallback
- **AND** the resulting `category` MUST be `prompt_injection` (taken from local, not RAG)
- **AND** `route_reasons` MUST include a marker indicating local-cat was used (e.g. `local_cat`)

#### Scenario: Dual-source rescue rejects when local score is below gray threshold

- **WHEN** ReAct fails to produce a verdict
- **AND** `rag_top_score=0.58`, `rag_top_category="sql_injection"` (not in whitelist)
- **AND** `local_attack_score.top_category="prompt_injection"` with `top_score=0.20` (< 0.35)
- **THEN** rescue MUST be skipped (local signal too weak to act as second confirmation)
- **AND** the fallback MUST resolve to PASS

#### Scenario: Rescue skipped when feature disabled

- **WHEN** `config.rag_decisive_fallback_enabled=False`
- **AND** all other rescue conditions hold
- **THEN** rescue MUST NOT trigger
- **AND** behavior MUST be byte-identical to a deployment without this change

#### Scenario: Rescue does not affect successful ReAct verdicts

- **WHEN** ReAct returns a valid `final_answer` with `verdict: BLOCK`
- **OR** with `verdict: PASS`
- **THEN** rescue logic MUST NOT execute
- **AND** the detection result MUST come from the LLM's own `final_answer`, not from the rescue path

### Requirement: Eval-mode telemetry for rescue route

The `X-Waf2-Route` response header (defined by `waf2-evaluation` capability) SHALL recognize the new enum value `react_fallback_rag_rescue` so that per-case JSONL output and the `label_failures.py` derivation can identify cases rescued by this mechanism.

The `X-Waf2-Reasons` header SHALL contain the token `rag_decisive_fallback` (pipe-separated alongside any other reason tokens) when rescue triggered.

#### Scenario: Rescued case carries identifiable headers

- **WHEN** a rescue triggers and `eval_mode=true`
- **THEN** `X-Waf2-Outcome` MUST be `blocked`
- **AND** `X-Waf2-Route` MUST be `react_fallback_rag_rescue`
- **AND** `X-Waf2-Reasons` MUST contain `rag_decisive_fallback`
- **AND** `X-Waf2-Detected-Category` MUST equal the rescue's category (e.g. `prompt_injection`)

### Requirement: Failure labeler recognizes rescued cases as R10

`label_failures.py` SHALL include a new auto-derivation rule R10 that labels rescued cases distinctly from other blocked outcomes. R10's priority MUST be placed between R7 (miscategorized) and R1 (normalize_miss), so that genuine miscategorization is still surfaced first.

R10 MUST emit:

- `layer: react_rescued`
- `cause_hint: react_parse_failure`
- `fix_hint: (none, monitored)`
- `confidence: high`
- `rule_id: R10`

The `(none, monitored)` fix_hint indicates "no further fix required; tracked under this change for monitoring purposes."

#### Scenario: R10 fires on rescued case

- **WHEN** a case has `outcome=blocked` and `route=react_fallback_rag_rescue`
- **THEN** `label_failures.py` MUST emit `rule_id=R10`, `layer=react_rescued`, `fix_hint=(none, monitored)`
- **AND** the case MUST NOT be re-derived through R1-R9

#### Scenario: R10 does not eclipse R7 for miscategorized blocks

- **WHEN** a case has `record_kind=miscategorized` AND `route=react_fallback_rag_rescue`
- **THEN** R7 MUST fire first (priority order), labeling the case as miscategorized
- **AND** R10 MUST NOT fire on the same case
