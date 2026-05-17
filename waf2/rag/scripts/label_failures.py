"""Auto-derive failure labels from cases-*.jsonl produced by the eval scripts.

Reads each `cases-<dataset>-<round>.jsonl` and writes a sibling
`labels-<dataset>-<round>.jsonl` where every input case gets a one-line label
record:

    {case_id, layer, cause_hint, fix_hint, confidence, rule_id, ...}

Rules R1-R8 are applied in priority order (first match wins). See
openspec/changes/add-waf2-eval-failure-analysis-loop/design.md (D3) for the
authoritative definitions.

Usage:
    python3 waf2/rag/scripts/label_failures.py <cases.jsonl> [<cases.jsonl> ...]
    python3 waf2/rag/scripts/label_failures.py <cases.jsonl> -o labels.jsonl
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


# ====== thresholds & taxonomy ======

LOCAL_SCORE_GRAY_THRESHOLD = 0.35
LOCAL_SCORE_LLM_OVERRODE_THRESHOLD = 0.55
RAG_MISS_THRESHOLD = 0.55
RAG_MISS_HIGH_CONF = 0.45
RAG_WRONG_THRESHOLD = 0.60
UNKNOWN_RATE_WARNING = 0.30

# Marker tokens that the local scorer would surface in `reasons` when it hits
# an IPI / encode / sql signature. Used by R2 to distinguish "no markers at
# all" (social_eng) from "markers but still low score" (something else).
MARKER_REASON_TOKENS = (
    "ipi_bracket_marker",
    "ai_targeted_soft_injection",
    "sql_keyword",
    "command_keyword",
    "xss_keyword",
    "prompt_injection_keyword",
    "base64",
    "url_encoded",
    "unicode_escape",
    "html_entity",
    "encoded_static",
    "static_keyword",
)


# ====== rule implementations ======


def _reasons_has_marker(case: dict) -> bool:
    reasons = case.get("reasons") or []
    text = " ".join(str(r) for r in reasons).lower()
    return any(token in text for token in MARKER_REASON_TOKENS)


def _body_has_nested_struct(case: dict) -> bool:
    body = case.get("body") or ""
    # Cheap heuristic for "contains JSON-ish nesting"
    return ('{' in body and '"' in body and ':' in body) or ('[' in body and ',' in body)


def _norm_frags(case: dict) -> int:
    nm = case.get("normalize_meta") or {}
    return int(nm.get("frags", 0) or 0)


def _has_any_encoding_signal(case: dict) -> bool:
    nm = case.get("normalize_meta") or {}
    return (
        int(nm.get("pct", 0) or 0) > 0
        or int(nm.get("uni", 0) or 0) > 0
        or int(nm.get("b64", 0) or 0) > 0
    )


def rule_R1_normalize_miss(case: dict) -> dict | None:
    """fragments=0 but body has nested structure → normalize didn't extract."""
    if _norm_frags(case) != 0:
        return None
    if not _body_has_nested_struct(case):
        return None
    # Cause hint: encoding-mark presence suggests novel encoding; otherwise depth.
    cause_hint = "novel_encoding" if _has_any_encoding_signal(case) else "deep_nesting"
    fix_hint = "new_decoder" if cause_hint == "novel_encoding" else "depth_limit_bump"
    return {
        "rule_id": "R1",
        "layer": "normalize_miss",
        "cause_hint": cause_hint,
        "fix_hint": fix_hint,
        "confidence": "high",
    }


def rule_R2_local_score_low(case: dict) -> dict | None:
    """Score under gray threshold AND no marker hits AND case passed."""
    if case.get("outcome") != "passed":
        return None
    if float(case.get("local_score_total", 0.0) or 0.0) >= LOCAL_SCORE_GRAY_THRESHOLD:
        return None
    if _reasons_has_marker(case):
        return None
    return {
        "rule_id": "R2",
        "layer": "local_score_low",
        "cause_hint": "social_eng_no_marker",
        "fix_hint": "fath_judge_wrap+field_path_boost",
        "confidence": "medium",
    }


def rule_R3_rag_miss(case: dict) -> dict | None:
    """RAG was queried but top score didn't clear the retrieval bar."""
    if not case.get("rag_used"):
        return None
    score = float(case.get("rag_top_score", 0.0) or 0.0)
    if score >= RAG_MISS_THRESHOLD:
        return None
    confidence = "high" if score < RAG_MISS_HIGH_CONF else "medium"
    return {
        "rule_id": "R3",
        "layer": "rag_miss",
        "cause_hint": "kb_coverage_gap",
        "fix_hint": "kb_inject_socialeng",
        "confidence": confidence,
    }


def rule_R4_rag_wrong(case: dict) -> dict | None:
    """High RAG score but wrong category — KB label noise."""
    if case.get("outcome") != "passed":
        return None
    if float(case.get("rag_top_score", 0.0) or 0.0) < RAG_WRONG_THRESHOLD:
        return None
    expected_cat = (case.get("expected_category") or "").strip().lower()
    top_cat = (case.get("rag_top_category") or "").strip().lower()
    if not expected_cat or not top_cat:
        return None
    if expected_cat == top_cat:
        return None
    return {
        "rule_id": "R4",
        "layer": "rag_wrong",
        "cause_hint": "kb_label_noise",
        "fix_hint": "kb_clean",
        "confidence": "high",
    }


def rule_R5_llm_overrode(case: dict) -> dict | None:
    """Score >= 0.55, route reached LLM/ReAct, yet case passed — carrier_unaware."""
    if case.get("outcome") != "passed":
        return None
    if float(case.get("local_score_total", 0.0) or 0.0) < LOCAL_SCORE_LLM_OVERRODE_THRESHOLD:
        return None
    if case.get("route") not in ("local_llm_one_shot", "react_deep_inspection"):
        return None
    return {
        "rule_id": "R5",
        "layer": "llm_overrode",
        "cause_hint": "carrier_unaware",
        "fix_hint": "fath_judge_wrap",
        "confidence": "high",
    }


def rule_R9_react_fallback_pass(case: dict) -> dict | None:
    """Score above gray threshold, ReAct/LLM was routed but agent returned
    `fallback` (parse failure or no verdict), outcome passed.

    Empirically dominant for response-wrap / mcp-rpc payloads where the LLM's
    structured output is brittle (Phase E real-run found 47/47 R8 unknowns
    fit this pattern). Fix overlaps with R5 (fath_judge_wrap) but adds a
    distinct robustness axis for prompt format.
    """
    if case.get("outcome") != "passed":
        return None
    if case.get("route") != "fallback":
        return None
    if float(case.get("local_score_total", 0.0) or 0.0) < LOCAL_SCORE_GRAY_THRESHOLD:
        return None
    return {
        "rule_id": "R9",
        "layer": "react_fallback_pass",
        "cause_hint": "react_parse_failure",
        "fix_hint": "fath_judge_wrap+react_prompt_robustness",
        "confidence": "medium",
    }


def rule_R6_router_too_loose(case: dict) -> dict | None:
    """Fast pass route taken despite a non-trivial score."""
    if case.get("route") != "fast_pass":
        return None
    if float(case.get("local_score_total", 0.0) or 0.0) < LOCAL_SCORE_GRAY_THRESHOLD:
        return None
    return {
        "rule_id": "R6",
        "layer": "router_too_loose",
        "cause_hint": "threshold_misfit",
        "fix_hint": "route_threshold_tune",
        "confidence": "high",
    }


def rule_R7_miscategorized(case: dict) -> dict | None:
    """Attack was blocked but with the wrong category label."""
    if case.get("record_kind") != "miscategorized":
        return None
    return {
        "rule_id": "R7",
        "layer": "miscategorized",
        "cause_hint": "ambiguous_pattern",
        "fix_hint": "category_rule_refine",
        "confidence": "high",
    }


def rule_R8_unknown(case: dict) -> dict:
    return {
        "rule_id": "R8",
        "layer": "unknown",
        "cause_hint": "needs_manual",
        "fix_hint": "manual_review_required",
        "confidence": "low",
    }


# Priority order (first match wins). Note R7 first — it short-circuits on the
# record_kind signal which is more reliable than score-based rules. R9 sits
# next to R5 since they share the "LLM should have decided but didn't" axis.
RULES = (
    rule_R7_miscategorized,
    rule_R1_normalize_miss,
    rule_R5_llm_overrode,
    rule_R9_react_fallback_pass,
    rule_R4_rag_wrong,
    rule_R6_router_too_loose,
    rule_R3_rag_miss,
    rule_R2_local_score_low,
)


def label_case(case: dict) -> dict:
    for rule in RULES:
        result = rule(case)
        if result:
            return _wrap_label(case, result)
    return _wrap_label(case, rule_R8_unknown(case))


def _wrap_label(case: dict, label: dict) -> dict:
    return {
        "case_id": case.get("case_id", ""),
        "dataset": case.get("dataset", ""),
        "round_or_split": case.get("round_or_split", ""),
        "record_kind": case.get("record_kind", ""),
        **label,
    }


# ====== I/O ======


def load_cases(path: Path) -> list[dict]:
    cases = []
    with path.open("r", encoding="utf-8") as fh:
        for ln, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                cases.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise SystemExit(f"{path}:{ln}: invalid JSON ({exc})")
    return cases


def derive_output_path(input_path: Path, override: str | None) -> Path:
    if override:
        return Path(override)
    name = input_path.name
    if name.startswith("cases-"):
        return input_path.with_name("labels-" + name[len("cases-") :])
    return input_path.with_name("labels-" + name)


def label_file(input_path: Path, output_path: Path) -> dict[str, int]:
    cases = load_cases(input_path)
    counts = {"total": len(cases), "unknown": 0}
    by_rule: dict[str, int] = {}
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as out:
        for case in cases:
            label = label_case(case)
            out.write(json.dumps(label, ensure_ascii=False) + "\n")
            rid = label["rule_id"]
            by_rule[rid] = by_rule.get(rid, 0) + 1
            if label["layer"] == "unknown":
                counts["unknown"] += 1
    counts["by_rule"] = by_rule
    return counts


def main() -> int:
    parser = argparse.ArgumentParser(description="Auto-derive failure labels from cases-*.jsonl")
    parser.add_argument(
        "inputs",
        nargs="+",
        help="One or more cases-*.jsonl files",
    )
    parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="When exactly one input is given, write labels here. "
        "Otherwise derived from each input filename.",
    )
    args = parser.parse_args()

    if args.output and len(args.inputs) > 1:
        print("--output may only be combined with a single input file", file=sys.stderr)
        return 2

    overall_total = 0
    overall_unknown = 0
    for inp in args.inputs:
        input_path = Path(inp)
        if not input_path.is_file():
            print(f"⚠️  not a file: {input_path}", file=sys.stderr)
            continue
        output_path = derive_output_path(input_path, args.output)
        counts = label_file(input_path, output_path)
        overall_total += counts["total"]
        overall_unknown += counts["unknown"]
        print(
            f"📄 {output_path.name}  total={counts['total']}  "
            f"unknown={counts['unknown']}  by_rule={counts['by_rule']}"
        )

    if overall_total > 0:
        rate = overall_unknown / overall_total
        print(f"overall unknown rate: {overall_unknown}/{overall_total} = {rate:.1%}")
        if rate > UNKNOWN_RATE_WARNING:
            print(
                f"⚠️  unknown rate exceeds {UNKNOWN_RATE_WARNING:.0%} — "
                "consider adding new rules or expanding manual sampling.",
                file=sys.stderr,
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
