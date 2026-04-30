# Local-First WAF2 Architecture

## Positioning

MCP Guardrails is now framed as a local-first dual WAF gateway for MCP and Web traffic.

The project is not just "RAG + ReAct WAF". The current architecture is:

```text
AI Agent / MCP Client
        |
        v
MCP Hub :4000
        |
        v
WAF1: MCP Protocol Guard
  - rate limit / RBAC / tool whitelist
  - MCP call-chain tracing
  - secrets / PII / unicode / fuzzy detectors
  - dynamic tool-specific policies
        |
        v
MCP Server / HTTP Client
        |
        v
WAF2: Local Intelligent WAF :8081
  - normalize / decode
  - deterministic rules
  - local attack score
  - local knowledge evidence
  - risk router
  - local LLM one-shot
  - optional ReAct deep inspection
        |
        v
Target Web App / API
```

## WAF2 Pipeline

```text
HTTP Request
    |
    v
Normalize / Decode
  - URL / double URL decode
  - Unicode escape decode
  - HTML entity decode
  - JSON and nested JSON extraction
  - suspicious base64 decode
  - path normalization
    |
    v
Deterministic Guard
  - existing static rules
  - decoded static rules
    |
    v
Local Attack Score
  - sql_injection
  - xss
  - command_injection
  - path_traversal
  - ssrf
  - prompt_injection
  - data_exfiltration
  - credential_leakage
  - mcp_tool_abuse
  - authentication_bypass
  - insecure_deserialization
    |
    v
Risk Router
    | high confidence
    +--> BLOCK
    |
    | low risk
    +--> PASS
    |
    | gray zone
    +--> Local Knowledge Evidence (RAG)
             |
             +--> local LLM one-shot
             |
             +--> ReAct deep inspection only when needed
```

## RAG and ReAct Roles

RAG is now the local knowledge evidence layer.

It answers:

```text
Does this payload resemble known attacks?
Does it resemble known benign hard negatives?
Which category, source, and evidence ID support the decision?
```

ReAct is now the deep inspection path.

It is reserved for:

```text
encoded or obfuscated gray-zone payloads
RAG evidence conflicts
MCP/tool-chain contextual attacks
data exfiltration without classic signatures
model uncertainty or parse failure recovery
```

ReAct is not the default route for normal requests.

## Privacy Boundary

Local data plane:

```text
HTTP bodies
cookies / tokens / API keys
MCP tool arguments
RAG retrieval queries
LLM prompts
detection logs
```

These should stay on the host when `provider_locality=local`.

Online control plane:

```text
ruleset updates
payload KB updates
CVE / CWE / CAPEC metadata updates
model weight download
```

Online API providers are preserved only as explicit baselines or user-selected mode.

## First Measured Effect

No-key deterministic run, local layers only:

| Dataset | Before | After | Main Change |
| --- | ---: | ---: | --- |
| Adversarial 40 Recall | 0.567 | 1.000 | Local score recovered 13 missed attacks |
| Adversarial 40 F1 | 0.708 | 0.984 | FPR unchanged at 0.100 |
| CSIC 100 Recall | 0.160 | 0.280 | Local score direct-blocked 8 attacks |
| CSIC 100 F1 | 0.276 | 0.438 | FPR stayed 0.000 |

These numbers are not local model benchmarks because no local model was running. They show that deterministic local layers already improve recall before RAG/LLM/ReAct are involved.

## Meeting Explanation

Short version:

```text
We changed the project direction from "RAG + ReAct WAF" to a local-first intelligent WAF for MCP gateways.

WAF1 protects MCP protocol and tool-call behavior. WAF2 protects HTTP traffic locally.
The new WAF2 first normalizes and decodes traffic, then computes local attack scores.
Only gray-zone samples enter RAG, local LLM, or ReAct.

RAG is no longer the whole architecture. It is the knowledge evidence layer.
ReAct is no longer the default path. It is a deep inspection path for difficult samples.

This makes the system faster, more private, and easier to evaluate.
```

Data version:

```text
Our earlier experiments showed that RAG helps only when the knowledge base covers the attack, and ReAct is too expensive to run everywhere.
The main bottleneck was recall.

So we added deterministic local recall layers before model reasoning:
normalize/decode + local attack score + risk router.

On the adversarial set, recall improved from 56.7% to 100% with no extra false positives.
On the CSIC sample, deterministic fail-open recall improved from 16% to 28%, and FPR stayed 0.

The next step is to run the same fixed pipeline with local 7B/14B models and compare it against online API baselines.
```
