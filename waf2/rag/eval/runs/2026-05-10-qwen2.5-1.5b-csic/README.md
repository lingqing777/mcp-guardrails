# qwen2.5:1.5b-instruct CSIC Evaluation

Date: 2026-05-10
Commit: 727c663
Provider: local Ollama
Model: qwen2.5:1.5b-instruct
Base URL: http://host.docker.internal:11434/v1
Privacy mode: local_only

## Notes

The first foreground CSIC 500 attempt was discarded because the running WAF2
container still had an older `/app/local_attack_score.py` and did not include
the 727c663 endpoint/probe scoring changes. The current source files were then
copied into the container and WAF2 was restarted before the valid runs below.

## Results

### CSIC 250, ReAct ON

| Metric | RAG OFF | RAG ON | Delta |
|---|---:|---:|---:|
| Precision | 1.000 | 1.000 | +0.000 |
| Recall | 0.788 | 0.788 | +0.000 |
| F1 | 0.881 | 0.881 | +0.000 |
| FPR | 0.000 | 0.000 | +0.000 |
| TP | 197 | 197 | +0 |
| FP | 0 | 0 | +0 |
| TN | 250 | 250 | +0 |
| FN | 53 | 53 | +0 |
| LLM Errors | 2 | 2 | +0 |
| RAG Queries | 0 | 26 | +26 |
| RAG Hits | 0 | 6 | +6 |
| RAG Gated | 0 | 6 | +6 |
| Route ReAct | 2 | 2 | +0 |
| Local Score Direct Blocks | 173 | 173 | +0 |

### CSIC 250, ReAct OFF

| Metric | RAG OFF | RAG ON | Delta |
|---|---:|---:|---:|
| Precision | 1.000 | 1.000 | +0.000 |
| Recall | 0.788 | 0.788 | +0.000 |
| F1 | 0.881 | 0.881 | +0.000 |
| FPR | 0.000 | 0.000 | +0.000 |
| TP | 197 | 197 | +0 |
| FP | 0 | 0 | +0 |
| TN | 250 | 250 | +0 |
| FN | 53 | 53 | +0 |
| LLM Errors | 0 | 0 | +0 |
| RAG Queries | 0 | 26 | +26 |
| RAG Hits | 0 | 6 | +6 |
| RAG Gated | 0 | 6 | +6 |
| Route ReAct | 0 | 0 | +0 |
| Local Score Direct Blocks | 173 | 173 | +0 |

### CSIC 500, ReAct ON

| Metric | RAG OFF | RAG ON | Delta |
|---|---:|---:|---:|
| Precision | 1.000 | 1.000 | +0.000 |
| Recall | 0.752 | 0.752 | +0.000 |
| F1 | 0.858 | 0.858 | +0.000 |
| FPR | 0.000 | 0.000 | +0.000 |
| TP | 376 | 376 | +0 |
| FP | 0 | 0 | +0 |
| TN | 500 | 500 | +0 |
| FN | 124 | 124 | +0 |
| LLM Errors | 4 | 4 | +0 |
| RAG Queries | 0 | 43 | +43 |
| RAG Hits | 0 | 8 | +8 |
| RAG Gated | 0 | 8 | +8 |
| Route ReAct | 4 | 4 | +0 |
| Local Score Direct Blocks | 321 | 321 | +0 |

### CSIC 500, ReAct OFF

| Metric | RAG OFF | RAG ON | Delta |
|---|---:|---:|---:|
| Precision | 1.000 | 1.000 | +0.000 |
| Recall | 0.752 | 0.752 | +0.000 |
| F1 | 0.858 | 0.858 | +0.000 |
| FPR | 0.000 | 0.000 | +0.000 |
| TP | 376 | 376 | +0 |
| FP | 0 | 0 | +0 |
| TN | 500 | 500 | +0 |
| FN | 124 | 124 | +0 |
| LLM Errors | 0 | 0 | +0 |
| RAG Queries | 0 | 43 | +43 |
| RAG Hits | 0 | 8 | +8 |
| RAG Gated | 0 | 8 | +8 |
| Route ReAct | 0 | 0 | +0 |
| Local Score Direct Blocks | 312 | 312 | +0 |

## Four-way comparison

For this CSIC run, the four combinations are now covered:

```text
ReAct ON  + RAG OFF
ReAct ON  + RAG ON
ReAct OFF + RAG OFF
ReAct OFF + RAG ON
```

RAG does not change TP/FP/TN/FN in any combination. ReAct does not improve
CSIC quality metrics for this 1.5B model, but it introduces LLM timeout risk in
the ReAct ON runs.

## Interpretation

RAG does not change final CSIC decisions for this model and commit. It retrieves
some positive evidence, but every hit is gated and TP/FP/TN/FN remain unchanged.

The local deterministic score layer is the main contributor. The 1.5B model can
support the current pipeline because most requests are handled by local scoring
or fast-pass routes. ReAct OFF produced valid comparable runs (`Valid=True`);
ReAct ON kept the same detection metrics but produced LLM timeouts
(`Valid=False`).

The CSIC 1000 run was intentionally not started after CSIC 500 because the 1.5B
model already showed repeated LLM timeouts while RAG had no decision impact.
