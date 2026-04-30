## Context

WAF2 当前已经从“静态规则 + LLM”演进到“静态规则 + RAG + ReAct/COT”。近期测试给出一个清晰结论：系统主要瓶颈是召回率，而不是误报率。

已观察到的关键现象：

- CSIC 真实流量样本中 Precision 可达到 1.000，但 Recall 只有 0.17-0.19，说明很多攻击没有被检测链路充分看见。
- RAG 在弱模型和知识库覆盖场景能提升 F1，但在 KB 盲区提升有限。
- ReAct 对复杂样本有价值，但不适合大量进入主路径，否则会拉高延迟和不确定性。
- 在线 API 模型适合快速实验，但与本项目“本地部署、保护用户隐私”的亮点冲突。

参考 open-appsec、SafeLine、OWASP CRS、Prompt Guard、LLM Guard 后，本项目最适合的专精方向不是复制某个产品，而是形成自己的双层 MCP 网关形态：

```text
WAF1: MCP Protocol Guard
  - RBAC / rate limit / tool whitelist
  - MCP call-chain tracing
  - secrets / PII / unicode / fuzzy detectors
  - dynamic policy for tool-specific risks

WAF2: Local Intelligent WAF
  - normalize / decode
  - deterministic guard
  - local attack score
  - local knowledge evidence
  - risk router
  - local LLM one-shot
  - optional ReAct deep inspection
```

## Goals / Non-Goals

**Goals:**

- Make WAF2 local-first by default for the request/response data plane.
- Improve recall by adding normalization/decode and local attack scoring before RAG/LLM/ReAct.
- Reposition RAG as a local evidence layer that supplies positive and benign hard-negative context.
- Reposition ReAct as a controlled deep inspection path for gray-zone samples only.
- Preserve compatibility with existing OpenAI-compatible online API configuration for evaluation baselines.
- Expose route, score, evidence, privacy and local model metrics through WAF2 APIs and Dashboard.
- Define an evaluation matrix that measures effectiveness, route behavior, latency and offline availability.

**Non-Goals:**

- Do not implement a full graph RAG or CVE question-answering system in the WAF hot path.
- Do not make ReAct the default detection path for all requests.
- Do not force a local model server into the WAF2 container image.
- Do not remove online API support; keep it as explicit opt-in and evaluation baseline.
- Do not replace WAF1. WAF1 remains the MCP protocol layer, while this change focuses on WAF2.

## Decisions

### Decision 1: Use local-first as the product architecture, not just a provider option

WAF2 will distinguish data plane and control plane:

```text
Data plane, local by default:
  - HTTP request/response body
  - MCP tool args
  - cookies, tokens, secrets
  - RAG queries and retrieved evidence
  - LLM inference payloads
  - detection logs

Control plane, may be online:
  - ruleset updates
  - payload/KB updates
  - CVE/CWE/CAPEC metadata updates
  - model weight download
```

Rationale:

- The project is a local competition/demo tool and a security gateway; sending user traffic to online APIs weakens the security story.
- Existing WAF2 already supports OpenAI-compatible `base_url`, so Ollama/vLLM/llama.cpp/LocalAI can be integrated without a rewrite.

Alternatives considered:

- Continue online API as default: easier for testing, but weaker privacy story and not differentiated.
- Bundle a local model inside WAF2: simpler startup story, but makes the image too heavy and hardware-dependent.

### Decision 2: Improve recall with normalize/decode before model reasoning

WAF2 will add a normalization stage before static rules, RAG, local LLM and ReAct.

Initial transformations:

- URL decode and double URL decode
- Unicode escape decode
- HTML entity decode
- JSON string extraction and nested JSON parsing
- suspicious base64 decode attempts
- path normalization
- SQL comment and whitespace normalization
- zero-width and suspicious unicode marker detection

Rationale:

- Many attacks are missed because the payload shape remains encoded or hidden.
- This layer is deterministic, fast and model-independent, so it is the most stable way to raise recall.

Alternatives considered:

- Let ReAct decode suspicious payloads: useful for gray-zone cases, but too expensive as a first-line mechanism.
- Let LLM infer encoded payload intent directly: inconsistent across small local models.

### Decision 3: Add Local Attack Score as the main recall lever

WAF2 will compute local risk scores after normalization:

```text
sqli_score
xss_score
rce_score
path_traversal_score
ssrf_score
prompt_injection_score
data_exfiltration_score
credential_leak_score
mcp_tool_abuse_score
```

Each score includes evidence terms and normalized/decoded payload snippets. The router consumes these scores to decide whether a request is high-risk, low-risk or gray-zone.

Rationale:

- open-appsec and OWASP CRS both demonstrate that local contextual scoring is a better hot-path backbone than asking a model about every request.
- Existing metrics show F1 will improve most if recall rises while preserving low FPR.

Alternatives considered:

- Keep pure binary rules: high precision but weaker coverage for obfuscated and contextual attacks.
- Train a classifier immediately: likely useful later, but deterministic scoring is faster to implement and easier to explain.

### Decision 4: Treat RAG as Local Knowledge Evidence Layer

RAG will be renamed conceptually to Knowledge Evidence Layer in docs/UI, while code may keep `rag_*` internal names during migration.

Expected retrieval sources:

- PayloadsAllTheThings and OWASP CRS-derived payloads
- prompt injection and agent attack examples
- MCP tool poisoning and data exfiltration examples
- benign hard negatives, such as security tutorials quoting payloads
- CSIC-style business traffic and attack shapes for evaluation-driven coverage

Rationale:

- RAG is useful when the KB covers the sample, but it is not a universal detector.
- Evidence is still valuable for explanation, category attribution and gray-zone decisions.

Alternatives considered:

- Remove RAG: loses explainability and weak-model gains already observed.
- Make GraphRAG the default: too heavy for the WAF hot path and not necessary for current datasets.

### Decision 5: ReAct becomes Deep Inspection Path

ReAct will only run when the router detects uncertainty or complexity:

- high attack score but weak direct block evidence
- encoded/obfuscated payload where deterministic decode is inconclusive
- RAG evidence conflicts with local score or request semantics
- MCP/tool-chain context requires multi-step reasoning
- suspected data exfiltration without classic attack signatures

Target route behavior:

- normal business traffic ReAct entry rate < 5%
- overall ReAct entry rate < 15% during normal demos
- encoded/obfuscated and MCP/tool poisoning classes may enter ReAct at higher rates

Rationale:

- ReAct is valuable but expensive. It should be a second-line inspection path, not the default.

Alternatives considered:

- Disable ReAct: simpler and faster, but loses a visible differentiator for MCP/Agent threats.
- Run ReAct for every suspicious request: better coverage for some samples, but high latency and unstable output.

### Decision 6: Evaluation must be route-aware and local-aware

Evaluation will report both detection quality and architecture behavior:

```text
Quality:
  - Precision / Recall / F1 / FPR
  - wrong category rate
  - parse failure / LLM error

Route:
  - static block rate
  - fast pass rate
  - RAG hit / gated / empty
  - local LLM call rate
  - ReAct entry rate
  - tool call count

Performance:
  - avg latency
  - p95 latency
  - max latency
  - local RAM/VRAM notes

Privacy:
  - local provider or online provider
  - whether request data leaves host
  - offline runnable or not
```

Rationale:

- A higher F1 that relies on sending all traffic to a large online API does not support the new project story.
- We need to know whether improvements come from better routing, better KB coverage, or only stronger models.

## Risks / Trade-offs

- Local model quality may be weaker than online API models -> keep online models as baselines, but tune pipeline around local 7B/14B models.
- More pipeline stages can make debugging harder -> every detection record must include route, scores, evidence IDs and reason.
- Aggressive attack score thresholds may increase false positives -> use dev/holdout split and benign hard negatives before changing default thresholds.
- Local provider setup varies by hardware -> support OpenAI-compatible endpoint first and document Ollama/vLLM/llama.cpp separately.
- RAG KB expansion can leak holdout knowledge into evaluation -> do not add holdout samples to KB; record KB source and build time.
- Dashboard may receive old WAF2 payloads without new fields -> frontend must use safe defaults and progressive rendering.

## Migration Plan

1. Keep current WAF2 behavior as compatibility baseline.
2. Add config fields for local-first mode, route thresholds and provider locality without changing defaults abruptly.
3. Implement normalization/decode and local attack score with stats-only mode first.
4. Enable router decisions gradually:
   - direct block only for very high-confidence deterministic cases
   - gray-zone samples go through existing RAG/LLM/ReAct path
5. Add Dashboard visibility for local provider, privacy mode, scores and routes.
6. Run smoke, adversarial, CSIC and MCP/Agent dev sets.
7. Tune thresholds on dev set only.
8. Validate final numbers on holdout set and online API baselines.

Rollback strategy:

- Disable local-first router through config and fall back to current static + RAG + LLM/ReAct flow.
- Keep online provider configuration compatible.
- Keep old stats fields while adding new fields to avoid Dashboard breakage.

## Open Questions

- Which local provider should be the default demo recommendation: Ollama for easiest setup, or vLLM for better performance?
- Should local attack score initially live in `waf2/waf2_proxy.py` or a separate module such as `waf2/local_score.py`?
- Which hard-negative sources should be added first: CSIC benign samples, security tutorial snippets, or MCP tool descriptions?
- What threshold target should be accepted for CSIC v1: Recall 0.45 with FPR <= 0.03, or a stricter FPR target?
- Should Prompt Guard-style local classifiers be integrated in this change, or left as a later optimization after deterministic scoring?
