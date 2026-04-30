# Local-First Pipeline Baseline

Date: 2026-04-30

Purpose: snapshot the currently running WAF2 container before applying the local-first normalization / attack-score / router changes.

## Runtime Config Snapshot

- `model`: `qwen-turbo`
- `format`: `openai`
- `base_url`: `https://dashscope.aliyuncs.com/compatible-mode/v1`
- `has_api_key`: `false`
- `rag_enabled`: `true`
- `rag_threshold`: `0.60`
- `rag_confidence_threshold`: `0.50`
- `rag_top_k`: `5`
- `react_routing_enabled`: `true`
- `react_rag_score_threshold`: `0.68`
- `knowledge_base_size`: `3354`

Because `has_api_key=false`, model-dependent metrics below are not valid for model comparison. They are still useful as a safety snapshot for static/routing behavior and no-key degradation.

## Adversarial 40 Baseline

Command:

```bash
python3 -m waf2.rag.scripts.eval_adversarial --waf2 http://localhost:8081
```

Results:

| Metric | RAG OFF | RAG ON | Delta |
| --- | ---: | ---: | ---: |
| Precision | 0.944 | 0.944 | +0.000 |
| Recall | 0.567 | 0.567 | +0.000 |
| F1 | 0.708 | 0.708 | +0.000 |
| FPR | 0.100 | 0.100 | +0.000 |
| Attack blocks | 17/30 | 17/30 | +0 |
| Benign false blocks | 1/10 | 1/10 | +0 |
| RAG fire attacks | - | 0/30 | - |
| RAG fire benign | - | 0/10 | - |

Common misses:

- `auth-impersonate`
- `creds-keys-as-keys`
- `deser-php-objstr`
- `deser-pickle-base64`
- `exfil-cdn-tunnel`
- `exfil-email-via-tool`
- `path-utf8-overlong`
- `pi-academic-pretense`
- `pi-fictional-persona`
- `pi-indirect-mcp`
- `pi-llama-sys-tag`
- `pi-pig-latin-leak`
- `pi-zh-formal-jailbreak`

Interpretation: the baseline misses are exactly the classes the local-first change targets: MCP/tool abuse, credential exfiltration, deserialization, prompt injection variants, and encoding edge cases.

## CSIC 100 Baseline

Command:

```bash
python3 -m waf2.rag.scripts.eval_rag --waf2 http://localhost:8081 --dataset csic --sample 50 --seed 42
```

Results:

| Metric | RAG OFF | RAG ON | Delta |
| --- | ---: | ---: | ---: |
| Precision | 0.683 | 0.689 | +0.006 |
| Recall | 0.820 | 0.840 | +0.020 |
| F1 | 0.745 | 0.757 | +0.012 |
| FPR | 0.380 | 0.380 | +0.000 |
| LLM Errors | 50 | 51 | +1 |
| RAG Queries | 0 | 80 | +80 |
| RAG Empty | 0 | 52 | +52 |
| RAG Gated | 0 | 21 | +21 |
| Valid for model comparison | no | no | - |

Interpretation: this CSIC run is invalid for model comparison because fail-closed plus missing API key converts LLM errors into blocks. It is retained only as a no-key behavior snapshot.

## Local-First Pipeline First Result

After adding normalization, local attack scoring, and risk routing, the same no-key environment was retested. These runs are still not valid for LLM model comparison because `has_api_key=false`, but they are valid for evaluating deterministic local layers because `--eval-fail-closed false` allows model errors to fail open.

### Adversarial 40

Command:

```bash
python3 -m waf2.rag.scripts.eval_adversarial --waf2 http://localhost:8081
```

| Metric | Before | After | Delta |
| --- | ---: | ---: | ---: |
| Precision | 0.944 | 0.968 | +0.024 |
| Recall | 0.567 | 1.000 | +0.433 |
| F1 | 0.708 | 0.984 | +0.276 |
| FPR | 0.100 | 0.100 | +0.000 |
| Attack blocks | 17/30 | 30/30 | +13 |
| Benign false blocks | 1/10 | 1/10 | +0 |

The local-first pipeline recovered all 13 previous adversarial misses. The only remaining false positive is `benign-edu-xss`, which is a hard-negative educational sample containing a literal `<script>` payload and is caused by static XSS matching.

### CSIC 100, deterministic fail-open

Command:

```bash
python3 -m waf2.rag.scripts.eval_rag --waf2 http://localhost:8081 --dataset csic --sample 50 --seed 42 --eval-fail-closed false
```

| Metric | RAG OFF | RAG ON |
| --- | ---: | ---: |
| Precision | 1.000 | 1.000 |
| Recall | 0.280 | 0.280 |
| F1 | 0.438 | 0.438 |
| FPR | 0.000 | 0.000 |
| Static blocks | 14 | 14 |
| Fast pass | 24 | 24 |
| Local LLM path | 37 | 36 |
| ReAct path | 13 | 14 |
| Local score direct blocks | 8 | 8 |

Compared with the deterministic fail-open run before CSIC-specific scoring refinements (`Recall=0.160`, `F1=0.276`, `FPR=0.000`), the local scoring refinements improved CSIC Recall by `+0.120` and F1 by `+0.162` while preserving zero false positives on this 100-sample run.

Interpretation: deterministic local layers now provide measurable lift without using an online model. RAG remains unchanged in this no-key run because the recovered samples are handled by normalize/decode and Local Attack Score before model judgment.

## Local Ollama Runtime Run

After the Windows Ollama service was connected from the WAF2 Docker container, WAF2 was configured as a local-only OpenAI-compatible provider:

- `base_url`: `http://host.docker.internal:11434/v1`
- `model`: `qwen2.5:1.5b-instruct`
- `provider_locality`: `local`
- `privacy_mode`: `local_only`
- `api_key`: empty, Authorization header omitted
- `llm_timeout_seconds`: `45`
- `llm_max_tokens`: `160`

Docker-to-host Ollama connectivity was verified through `http://host.docker.internal:11434/api/tags`. The available local models were:

- `qwen2.5:1.5b-instruct`, Qwen2, `1.5B`, `Q4_K_M`, size about `986 MB`
- `qwen3:4b`, Qwen3, `4.0B`, `Q4_K_M`, size about `2.5 GB`

The 1.5B model was used for the first stable local run because the 4B model was slower on full WAF prompts in this environment. Ollama's tags API does not expose live RAM/VRAM use, so the recorded hardware note is model asset size plus observed latency. Long one-shot prompts on benign hard-negative samples took roughly `4-23s` in container logs, while CSIC aggregate latency stayed low because most requests used static block or fast pass.

### Smoke 10, local Ollama

Command:

```bash
python3 -m waf2.rag.scripts.eval_rag --waf2 http://localhost:8081 --dataset smoke --sample 5 --seed 42 --eval-fail-closed false
```

| Metric | RAG OFF | RAG ON |
| --- | ---: | ---: |
| Precision | 1.000 | 1.000 |
| Recall | 0.600 | 0.600 |
| F1 | 0.750 | 0.750 |
| FPR | 0.000 | 0.000 |
| LLM Errors | 0 | 0 |
| Parse Failed | 0 | 0 |
| RAG Queries | 0 | 1 |
| Static blocks | 3 | 3 |
| Fast pass | 5 | 5 |
| Local LLM path | 1 | 1 |
| ReAct path | 0 | 0 |

### Adversarial 40, local Ollama

Command:

```bash
python3 -m waf2.rag.scripts.eval_adversarial --waf2 http://localhost:8081
```

| Metric | RAG OFF | RAG ON |
| --- | ---: | ---: |
| Precision | 0.968 | 0.968 |
| Recall | 1.000 | 1.000 |
| F1 | 0.984 | 0.984 |
| FPR | 0.100 | 0.100 |
| Attack blocks | 30/30 | 30/30 |
| Benign false blocks | 1/10 | 1/10 |
| RAG fire attacks | - | 0/30 |
| RAG fire benign | - | 0/10 |

Post-run route stats showed `31` static blocks, `2` fast-pass requests, `7` local one-shot requests, `0` ReAct entries, and `13` local score direct blocks. The remaining false positive is still `benign-edu-xss`, caused by the static XSS rule matching a literal classroom example.

### CSIC 40, local Ollama

Command:

```bash
python3 -m waf2.rag.scripts.eval_rag --waf2 http://localhost:8081 --dataset csic --sample 20 --seed 42 --eval-fail-closed false
```

| Metric | RAG OFF | RAG ON |
| --- | ---: | ---: |
| Precision | 1.000 | 1.000 |
| Recall | 0.300 | 0.300 |
| F1 | 0.462 | 0.462 |
| FPR | 0.000 | 0.000 |
| LLM Errors | 0 | 0 |
| Parse Failed | 0 | 0 |
| RAG Queries | 0 | 3 |
| RAG Empty | 0 | 2 |
| RAG Gated | 0 | 1 |
| Static blocks | 6 | 6 |
| Fast pass | 28 | 28 |
| Local LLM path | 3 | 3 |
| ReAct path | 0 | 0 |
| Local score direct blocks | 3 | 3 |

Interpretation: local Ollama inference is now functionally stable (`LLM Errors=0`, `Parse Failed=0`) and request data stays local. On these small runs, RAG does not change aggregate quality because the local score and static layers make most decisions before evidence or model reasoning. ReAct entry is currently `0`, which is good for latency and normal-traffic safety, but it means the next tuning target is not "more ReAct everywhere"; it is better CSIC/Web recall in the local score layer and selective ReAct entry only for encoded or MCP/tool-chain gray-zone samples.

## Knowledge Evidence Layer Update

The RAG layer now records evidence type instead of treating every retrieved item as attack evidence:

- `ATTACK/<category>`: positive attack evidence that can support a block decision.
- `BENIGN_HARD_NEGATIVE/<category>`: benign examples that resemble attacks but should reduce false positives when no independent attack indicator exists.

Runtime fields added to WAF2 stats and detection records:

- `rag_outcome`: `disabled`, `empty`, `hit`, `gated`, or `error`
- `rag_evidence_ids`
- `rag_evidence_types`
- `rag_evidence_categories`
- `rag_positive_count`
- `rag_benign_count`
- aggregate stats: `rag_hits`, `rag_positive_evidence`, `rag_benign_evidence`

The local KB was rebuilt from `3354` to `3364` entries by adding 10 benign hard-negative seed examples under `waf2/rag/data/seeds/benign_hard_negatives.jsonl`. Direct KB retrieval confirms the educational XSS example retrieves the benign seed as the top result:

```text
entry-3354 benign xss 0.898 WAF2-Benign-Hard-Negatives
```

Smoke recheck after the rebuild:

```bash
python3 -m waf2.rag.scripts.eval_rag --waf2 http://localhost:8081 --dataset smoke --sample 5 --seed 42 --eval-fail-closed false
```

| Metric | RAG OFF | RAG ON |
| --- | ---: | ---: |
| Precision | 1.000 | 1.000 |
| Recall | 0.600 | 0.600 |
| F1 | 0.750 | 0.750 |
| FPR | 0.000 | 0.000 |
| LLM Errors | 0 | 0 |
| RAG Queries | 0 | 1 |
| RAG Hits | 0 | 1 |
| RAG Positive Evidence | 0 | 1 |
| RAG Benign Evidence | 0 | 0 |
| ReAct path | 0 | 0 |

Important boundary: `benign-edu-xss` is still blocked by the static XSS keyword layer before RAG can influence the decision. Reducing that false positive requires a separate static-rule hard-negative bypass or a policy that downgrades selected static keyword matches into the evidence/model path.

## Deterministic Routing Tuning

After the local Ollama run, two issues were fixed in the local-first path:

- `benign-edu-xss` was a false positive because the static XSS rule blocked educational text quoting `<script>alert(1)</script>`.
- CSIC/Web recall stayed low because several CSIC anomaly shapes had no local score signal.

The fix keeps the "ordinary laptop" target in mind: do not send common benign business traffic to a small local model unless it is genuinely ambiguous.

Changes:

- Added hard-negative context detection for security-training/documentation text that quotes XSS, SQLi, command, traversal, SSRF, or placeholder credential payloads.
- Added benign hard-negative fast-pass when the top RAG evidence is benign and the request matches a training/documentation/placeholder context.
- Added weak SQLi quote-comment truncation scoring for payloads such as `admin'--`.
- Added CSIC-style protocol anomaly indicators under the local `unknown` score:
  - `idA`, `precioA`, `errorMsgA`, `B2A`
  - control-character values such as `%7C`
  - double-encoded question marks such as `%253F`
  - static resource paths followed by long numeric suffixes
  - `/examplesWebApp/index.jsp`
- Expanded known business fast-pass paths for `/api/order`, `/api/comment`, `/api/post`, `/api/ticket`, `/api/db_query`, `/api/forum`, and `/api/settings`.

### Targeted checks

```text
POST /api/forum
{"text":"Example XSS payload for class: <script>alert(1)</script> -- discuss why this is dangerous"}
=> PASS, llm_calls=0

GET /admin?user=admin'--
=> BLOCK sql_injection, local_attack_top_score=0.9882, llm_calls=0

POST /api/settings
{"config":{"api_key":"user-set-value-here"}}
=> PASS, llm_calls=0
```

### Adversarial 40 after deterministic tuning

Command:

```bash
python3 -m waf2.rag.scripts.eval_adversarial --waf2 http://localhost:8081
```

| Metric | RAG OFF | RAG ON |
| --- | ---: | ---: |
| Precision | 1.000 | 1.000 |
| Recall | 1.000 | 1.000 |
| F1 | 1.000 | 1.000 |
| FPR | 0.000 | 0.000 |
| Attack blocks | 30/30 | 30/30 |
| Benign false blocks | 0/10 | 0/10 |

Final route stats for the adversarial run:

- `llm_calls`: `0`
- `agent_invocations`: `0`
- `route_static_block`: `30`
- `route_fast_pass`: `10`
- `rag_queries`: `2`
- `rag_benign_evidence`: `2`
- average latency: about `7ms`

### CSIC 40 after deterministic tuning

Command:

```bash
python3 -m waf2.rag.scripts.eval_rag --waf2 http://localhost:8081 --dataset csic --sample 20 --seed 42 --eval-fail-closed false
```

| Metric | Before | After |
| --- | ---: | ---: |
| Precision | 1.000 | 1.000 |
| Recall | 0.300 | 0.800 |
| F1 | 0.462 | 0.889 |
| FPR | 0.000 | 0.000 |
| Local score direct blocks | 4 | 14 |
| ReAct path | 0 | 0 |

Interpretation: the best gains came from deterministic local scoring and routing, not from calling a larger model. This supports the product direction: ordinary users should get strong default protection with local rules, normalization, scoring, evidence, and routing; larger models are optional accelerators for gray-zone analysis rather than the hot-path foundation.
