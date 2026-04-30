# Tasks — Localize WAF2 Intelligent Detection Pipeline

## 1. OpenSpec Artifacts

- [x] 1.1 Create proposal for `localize-waf2-intelligent-detection-pipeline` in `openspec/changes/localize-waf2-intelligent-detection-pipeline/proposal.md`
- [x] 1.2 Create design for local-first WAF2 architecture in `openspec/changes/localize-waf2-intelligent-detection-pipeline/design.md`
- [x] 1.3 Create specs for local-first pipeline, attack scoring, model evaluation, WAF2 API changes, and Dashboard visibility under `openspec/changes/localize-waf2-intelligent-detection-pipeline/specs/`

## 2. Baseline and Safety Snapshot

- [x] 2.1 Record current WAF2 config, route stats, RAG stats, ReAct stats, and model provider in `waf2/rag/eval/results.md` or a dated report under `waf2/rag/eval/`
- [x] 2.2 Run the existing smoke/adversarial evaluator against current WAF2 in `waf2/rag/scripts/eval_adversarial.py` and save baseline Precision/Recall/F1/FPR
- [x] 2.3 Run a small CSIC baseline using `waf2/rag/scripts/eval_rag.py` and save Recall/F1 plus route stats before changing thresholds
- [x] 2.4 Confirm `docker-compose.yml` and `waf2/waf2_proxy.py` still support existing online API provider mode before local-first changes

## 3. Local Provider and Privacy Config

- [x] 3.1 Add local-first config fields in `waf2/waf2_proxy.py`: `local_first_enabled`, `provider_locality`, `privacy_mode`, `local_provider_name`, and fail-open/fail-closed policy fields
- [x] 3.2 Ensure `call_llm()` in `waf2/waf2_proxy.py` omits Authorization header for local OpenAI-compatible endpoints when API key is empty
- [x] 3.3 Add provider-locality and privacy-mode fields to `GET /waf2/config`, `POST /waf2/config`, `GET /waf2/stats`, and `GET /waf2/dashboard`
- [x] 3.4 Add optional local provider examples to `docker-compose.yml` comments or project docs without forcing Ollama/vLLM into the WAF2 container
- [x] 3.5 Update `config/guardrails-config.json` defaults to prefer local provider fields while preserving existing API provider compatibility

## 4. Normalize / Decode Stage

- [x] 4.1 Create a normalization helper module such as `waf2/normalization.py` for URL decode, double URL decode, Unicode escape decode, HTML entity decode, path normalization, and suspicious base64 attempts
- [x] 4.2 Add JSON body extraction and nested JSON string parsing in `waf2/normalization.py`
- [x] 4.3 Preserve original and decoded request representations in the analysis context passed through `waf2/waf2_proxy.py`
- [x] 4.4 Add normalization metadata to detection records in `waf2/waf2_proxy.py`, including decoded fields and decode methods used
- [x] 4.5 Add unit or smoke tests for double URL SQLi, Unicode XSS, nested JSON payloads, and non-attack normal traffic

## 5. Local Attack Score

- [x] 5.1 Create `waf2/local_attack_score.py` with score categories: SQLi, XSS, RCE, path traversal, SSRF, prompt injection, data exfiltration, credential leakage, and MCP tool abuse
- [x] 5.2 Implement score evidence terms in `waf2/local_attack_score.py` so each score can explain which indicators matched
- [x] 5.3 Integrate local attack scoring into `waf2/waf2_proxy.py` after normalization and before RAG/LLM/ReAct
- [x] 5.4 Add configurable thresholds in `waf2/waf2_proxy.py` for low-risk fast pass, gray-zone analysis, and direct block
- [x] 5.5 Include top score categories and evidence terms in WAF2 detection records and dashboard payloads
- [x] 5.6 Run current datasets to verify whether attack scoring raises CSIC/adversarial Recall without increasing FPR beyond the chosen threshold target

## 6. Risk Router

- [x] 6.1 Implement a route decision function in `waf2/waf2_proxy.py` or `waf2/risk_router.py` that consumes deterministic rules, normalization metadata, attack scores, RAG evidence, and model/ReAct settings
- [x] 6.2 Define route names: `static_block`, `fast_pass`, `knowledge_evidence`, `local_llm_one_shot`, `react_deep_inspection`, and `fallback`
- [x] 6.3 Ensure high-confidence deterministic attacks return HTTP 403 without model calls in `waf2/waf2_proxy.py`
- [x] 6.4 Ensure low-risk normal traffic avoids unnecessary RAG, LLM, and ReAct calls when policy allows
- [x] 6.5 Record route reason and route counters in WAF2 stats and detection records
- [x] 6.6 Preserve current WAF2 behavior behind config flags so router changes can be disabled during testing

## 7. Knowledge Evidence Layer

- [x] 7.1 Update `waf2/rag/engine.py` output to expose evidence ID, category, source, similarity score, and positive/benign evidence type
- [x] 7.2 Add support for benign hard-negative evidence in the local KB build pipeline under `waf2/rag/scripts/`
- [x] 7.3 Update RAG prompt context in `waf2/waf2_proxy.py` to distinguish attack evidence from benign hard-negative evidence
- [x] 7.4 Track RAG outcomes as hit, gated, empty, positive evidence, and benign evidence in stats and detection records
- [ ] 7.5 Add CSIC-style and MCP/Agent-specific missing categories to KB only from dev data, not holdout data

## 8. ReAct Deep Inspection Path

- [x] 8.1 Update ReAct routing conditions in `waf2/waf2_proxy.py` so ReAct runs only for gray-zone, encoded, evidence-conflict, or MCP/tool-chain complex samples
- [x] 8.2 Add explicit ReAct route reasons and max-iteration fallback records in WAF2 detection logs
- [x] 8.3 Measure ReAct entry rate on normal business traffic and tune the router toward less than 5 percent normal-entry target
- [ ] 8.4 Verify encoded/obfuscated and MCP/tool-poisoning samples still enter ReAct often enough to preserve deep inspection value

## 9. Dashboard and API Visibility

- [x] 9.1 Update `mcp-hub/src/dashboard/services/api.js` only if new authenticated MCP Hub API methods are required; otherwise continue consuming existing WAF2 proxy dashboard endpoints
- [x] 9.2 Update WAF2 panel rendering in `mcp-hub/src/dashboard/app.js` to show local-only, online, or mixed provider mode
- [x] 9.3 Add route distribution, attack score summary, RAG evidence status, and ReAct deep-path entry rate to `mcp-hub/src/dashboard/app.js`
- [x] 9.4 Add detection-detail rendering for route reason, top scores, evidence IDs, provider locality, and ReAct status in `mcp-hub/src/dashboard/app.js`
- [x] 9.5 Update `mcp-hub/src/dashboard/styles.css` using existing Grafana dark, Linear gradient, and Tabler-like layout patterns
- [ ] 9.6 Confirm Dashboard remains stable with old WAF2 payloads that do not include new fields and continues refreshing every 5 seconds

## 10. Evaluation Scripts and Datasets

- [ ] 10.1 Extend `waf2/rag/scripts/eval_rag.py` to record provider locality, privacy mode, route, top scores, RAG outcome, ReAct entry, tool calls, and p95 latency
- [ ] 10.2 Extend `waf2/rag/scripts/eval_adversarial.py` with per-class route-aware metrics
- [ ] 10.3 Convert or create dev-set JSONL samples with dataset classes: classic web, encoded/obfuscated, prompt injection, MCP tool poisoning, data exfiltration, sensitive response leakage, benign hard negative, and normal business traffic
- [ ] 10.4 Create holdout-set JSONL samples and document that they are not inserted into the RAG KB
- [ ] 10.5 Add failure classification output for decode failure, score threshold failure, RAG coverage gap, router miss, LLM judgment error, ReAct tool failure, and static-rule gap
- [ ] 10.6 Produce a model comparison report covering local 7B/14B models and online API baselines with fixed router/RAG/ReAct settings

## 11. Local Model Runs

- [x] 11.1 Verify WAF2 can call a local Ollama OpenAI-compatible endpoint from Docker using `host.docker.internal`
- [ ] 11.2 Verify WAF2 can call a local vLLM OpenAI-compatible endpoint when available
- [x] 11.3 Run Qwen2.5-7B local or equivalent small local model across smoke/adversarial/CSIC samples
- [ ] 11.4 Run Qwen2.5-14B local or equivalent mid-size local model when hardware is available
- [ ] 11.5 Compare local models against SiliconFlow/Zhipu/DeepSeek API baselines without changing thresholds inside the comparison round
- [x] 11.6 Record RAM/VRAM notes, latency, offline availability, and whether request data leaves host in the evaluation report

## 12. Validation and Documentation

- [x] 12.1 Run `openspec validate localize-waf2-intelligent-detection-pipeline`
- [x] 12.2 Run Python syntax checks for changed WAF2 modules with `python3 -m py_compile`
- [ ] 12.3 Run Dashboard smoke checks or manual browser verification after UI changes
- [x] 12.4 Update `waf2/rag/eval-report.md` or a new local-first report with before/after Recall/F1/FPR and route metrics
- [x] 12.5 Document the final architecture diagram: WAF1 MCP Protocol Guard plus WAF2 Local Intelligent WAF
- [x] 12.6 Prepare a short meeting explanation that RAG is now the knowledge evidence layer and ReAct is the deep inspection path, not the main architecture
