"""Smoke tests for label_failures.py (Phase C: auto-derivation rules R1-R8).

Run with:
  python3 waf2/tests/test_label_failures.py
"""

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "rag" / "scripts"))

from label_failures import (
    derive_output_path,
    label_case,
    label_file,
    rule_R1_normalize_miss,
    rule_R2_local_score_low,
    rule_R3_rag_miss,
    rule_R4_rag_wrong,
    rule_R5_llm_overrode,
    rule_R6_router_too_loose,
    rule_R7_miscategorized,
    rule_R8_unknown,
    rule_R9_react_fallback_pass,
)


def _case(**overrides) -> dict:
    base = {
        "case_id": "test:0",
        "dataset": "b0",
        "round_or_split": "rag-off",
        "record_kind": "false_negative",
        "outcome": "passed",
        "method": "POST",
        "path": "/api/test",
        "body": '{"q":"test"}',
        "local_score_total": 0.0,
        "local_score_top": {},
        "rag_used": False,
        "rag_top_score": 0.0,
        "rag_top_category": "",
        "route": "",
        "reasons": [],
        "normalize_meta": {"frags": 1, "b64": 0, "pct": 0, "uni": 0, "changed": False},
        "expected_category": "",
    }
    base.update(overrides)
    return base


# ==================== R1 normalize_miss ====================


def test_R1_fires_when_nested_but_no_frags():
    case = _case(body='{"a":{"b":"payload"}}', normalize_meta={"frags": 0})
    result = rule_R1_normalize_miss(case)
    assert result is not None
    assert result["layer"] == "normalize_miss"
    assert result["confidence"] == "high"


def test_R1_skipped_when_frags_present():
    case = _case(body='{"a":"b"}', normalize_meta={"frags": 1})
    assert rule_R1_normalize_miss(case) is None


def test_R1_skipped_when_body_is_plain_text():
    case = _case(body="plain text no nesting here", normalize_meta={"frags": 0})
    assert rule_R1_normalize_miss(case) is None


def test_R1_novel_encoding_cause_when_pct_signal():
    case = _case(body='{"a":1}', normalize_meta={"frags": 0, "pct": 3})
    result = rule_R1_normalize_miss(case)
    assert result["cause_hint"] == "novel_encoding"
    assert result["fix_hint"] == "new_decoder"


def test_R1_deep_nesting_cause_when_no_encoding_signal():
    case = _case(body='{"a":1}', normalize_meta={"frags": 0})
    result = rule_R1_normalize_miss(case)
    assert result["cause_hint"] == "deep_nesting"
    assert result["fix_hint"] == "depth_limit_bump"


# ==================== R2 local_score_low ====================


def test_R2_fires_low_score_passed_no_markers():
    case = _case(local_score_total=0.20, reasons=["json_fragments"])
    result = rule_R2_local_score_low(case)
    assert result is not None
    assert result["layer"] == "local_score_low"
    assert result["fix_hint"] == "fath_judge_wrap+field_path_boost"


def test_R2_skipped_when_marker_in_reasons():
    case = _case(local_score_total=0.20, reasons=["ipi_bracket_marker_en", "json_fragments"])
    assert rule_R2_local_score_low(case) is None


def test_R2_skipped_when_score_above_threshold():
    case = _case(local_score_total=0.40, reasons=["json_fragments"])
    assert rule_R2_local_score_low(case) is None


def test_R2_skipped_when_blocked():
    case = _case(outcome="blocked", local_score_total=0.20)
    assert rule_R2_local_score_low(case) is None


# ==================== R3 rag_miss ====================


def test_R3_fires_rag_used_score_low():
    case = _case(rag_used=True, rag_top_score=0.30)
    result = rule_R3_rag_miss(case)
    assert result is not None
    assert result["layer"] == "rag_miss"
    assert result["confidence"] == "high"


def test_R3_medium_confidence_at_0_50():
    case = _case(rag_used=True, rag_top_score=0.50)
    result = rule_R3_rag_miss(case)
    assert result["confidence"] == "medium"


def test_R3_skipped_when_rag_not_used():
    case = _case(rag_used=False, rag_top_score=0.30)
    assert rule_R3_rag_miss(case) is None


def test_R3_skipped_when_score_above_threshold():
    case = _case(rag_used=True, rag_top_score=0.60)
    assert rule_R3_rag_miss(case) is None


# ==================== R4 rag_wrong ====================


def test_R4_fires_high_score_wrong_category():
    case = _case(
        outcome="passed",
        rag_used=True,
        rag_top_score=0.75,
        rag_top_category="sql_injection",
        expected_category="prompt_injection",
    )
    result = rule_R4_rag_wrong(case)
    assert result is not None
    assert result["layer"] == "rag_wrong"


def test_R4_skipped_when_category_matches():
    case = _case(
        outcome="passed",
        rag_used=True,
        rag_top_score=0.75,
        rag_top_category="prompt_injection",
        expected_category="prompt_injection",
    )
    assert rule_R4_rag_wrong(case) is None


def test_R4_skipped_when_no_expected_category():
    case = _case(
        outcome="passed",
        rag_used=True,
        rag_top_score=0.75,
        rag_top_category="sql_injection",
        expected_category="",
    )
    assert rule_R4_rag_wrong(case) is None


# ==================== R5 llm_overrode (FATH fingerprint) ====================


def test_R5_fires_high_score_passed_via_llm():
    case = _case(local_score_total=0.62, route="local_llm_one_shot", outcome="passed")
    result = rule_R5_llm_overrode(case)
    assert result is not None
    assert result["layer"] == "llm_overrode"
    assert result["cause_hint"] == "carrier_unaware"
    assert result["fix_hint"] == "fath_judge_wrap"


def test_R5_skipped_when_route_is_fast_pass():
    case = _case(local_score_total=0.62, route="fast_pass", outcome="passed")
    assert rule_R5_llm_overrode(case) is None


def test_R5_fires_for_react_route_too():
    case = _case(local_score_total=0.70, route="react_deep_inspection", outcome="passed")
    result = rule_R5_llm_overrode(case)
    assert result is not None


# ==================== R6 router_too_loose ====================


def test_R6_fires_fast_pass_with_meaningful_score():
    case = _case(route="fast_pass", local_score_total=0.40)
    result = rule_R6_router_too_loose(case)
    assert result is not None
    assert result["layer"] == "router_too_loose"


def test_R6_skipped_when_score_below_gray():
    case = _case(route="fast_pass", local_score_total=0.10)
    assert rule_R6_router_too_loose(case) is None


def test_R6_skipped_when_not_fast_pass():
    case = _case(route="local_llm_one_shot", local_score_total=0.40)
    assert rule_R6_router_too_loose(case) is None


# ==================== R7 miscategorized ====================


def test_R7_fires_when_record_kind_miscategorized():
    case = _case(record_kind="miscategorized", outcome="blocked")
    result = rule_R7_miscategorized(case)
    assert result is not None
    assert result["layer"] == "miscategorized"
    assert result["fix_hint"] == "category_rule_refine"


def test_R7_skipped_for_normal_record_kinds():
    for kind in ("false_negative", "false_positive", "ambiguous"):
        assert rule_R7_miscategorized(_case(record_kind=kind)) is None


# ==================== R9 react_fallback_pass ====================


def test_R9_fires_fallback_route_with_meaningful_score():
    case = _case(route="fallback", outcome="passed", local_score_total=0.60)
    result = rule_R9_react_fallback_pass(case)
    assert result is not None
    assert result["layer"] == "react_fallback_pass"
    assert result["cause_hint"] == "react_parse_failure"
    assert result["fix_hint"] == "fath_judge_wrap+react_prompt_robustness"


def test_R9_skipped_when_score_below_gray():
    case = _case(route="fallback", outcome="passed", local_score_total=0.10)
    assert rule_R9_react_fallback_pass(case) is None


def test_R9_skipped_when_route_is_not_fallback():
    case = _case(route="local_llm_one_shot", outcome="passed", local_score_total=0.60)
    assert rule_R9_react_fallback_pass(case) is None


def test_R9_skipped_when_blocked():
    case = _case(route="fallback", outcome="blocked", local_score_total=0.60)
    assert rule_R9_react_fallback_pass(case) is None


# ==================== R8 unknown ====================


def test_R8_always_returns_unknown():
    label = rule_R8_unknown(_case())
    assert label["rule_id"] == "R8"
    assert label["layer"] == "unknown"
    assert label["confidence"] == "low"


# ==================== priority order ====================


def test_priority_R5_beats_R3_when_both_apply():
    # high score that passed via LLM, also RAG used with low score
    case = _case(
        local_score_total=0.62,
        route="local_llm_one_shot",
        rag_used=True,
        rag_top_score=0.30,
        outcome="passed",
    )
    label = label_case(case)
    assert label["rule_id"] == "R5"  # llm_overrode is more diagnostic


def test_priority_R7_beats_everything():
    # miscategorized record should always go through R7, not get re-derived
    case = _case(
        record_kind="miscategorized",
        outcome="blocked",
        local_score_total=0.95,
        route="static_block",
    )
    label = label_case(case)
    assert label["rule_id"] == "R7"


def test_unmatched_case_goes_to_R8():
    # outcome=passed, low score, marker present (R2 skipped), rag not used (R3 skipped),
    # route is fast_pass but score is too low (R6 skipped) → R8
    case = _case(
        outcome="passed",
        local_score_total=0.10,
        rag_used=False,
        route="local_llm_one_shot",
        reasons=["ipi_bracket_marker_en"],  # has marker, R2 skipped
    )
    label = label_case(case)
    assert label["rule_id"] == "R8"


# ==================== file I/O ====================


def test_label_file_writes_one_label_per_input(tmp_path: Path):
    inp = tmp_path / "cases-b0-rag-off.jsonl"
    cases = [
        _case(case_id="c1", local_score_total=0.62, route="local_llm_one_shot"),  # R5
        _case(case_id="c2", record_kind="false_negative", outcome="passed",
              local_score_total=0.20, reasons=["json_fragments"]),                # R2
        _case(case_id="c3", rag_used=True, rag_top_score=0.40),                  # R3
    ]
    inp.write_text("\n".join(json.dumps(c) for c in cases) + "\n")
    out = tmp_path / "labels-b0-rag-off.jsonl"
    counts = label_file(inp, out)
    assert counts["total"] == 3
    assert counts["unknown"] == 0
    lines = out.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 3
    ids = [json.loads(l)["rule_id"] for l in lines]
    assert ids == ["R5", "R2", "R3"]


def test_derive_output_path_cases_prefix():
    p = derive_output_path(Path("/tmp/cases-csic-rag-off.jsonl"), None)
    assert p.name == "labels-csic-rag-off.jsonl"


def test_derive_output_path_no_cases_prefix():
    p = derive_output_path(Path("/tmp/random.jsonl"), None)
    assert p.name == "labels-random.jsonl"


def test_derive_output_path_with_override():
    p = derive_output_path(Path("/tmp/cases-csic-rag-off.jsonl"), "/out/foo.jsonl")
    assert str(p) == "/out/foo.jsonl"


# ==================== R10 react_rescued (harden-waf2-react-fallback-rag-rescue) ====================
# Appended in harden-waf2-react-fallback-rag-rescue. Do not modify tests above.


from label_failures import rule_R10_react_rescued  # noqa: E402


def test_R10_fires_for_rescued_block():
    case = _case(record_kind="false_negative", outcome="blocked",
                 route="react_fallback_rag_rescue")
    result = rule_R10_react_rescued(case)
    assert result is not None
    assert result["rule_id"] == "R10"
    assert result["layer"] == "react_rescued"
    assert result["cause_hint"] == "react_parse_failure"
    assert result["fix_hint"] == "(none, monitored)"
    assert result["confidence"] == "high"


def test_R10_skipped_when_outcome_passed():
    case = _case(outcome="passed", route="react_fallback_rag_rescue")
    assert rule_R10_react_rescued(case) is None


def test_R10_skipped_when_route_is_not_rescue():
    case = _case(outcome="blocked", route="static_block")
    assert rule_R10_react_rescued(case) is None
    case2 = _case(outcome="blocked", route="react_deep_inspection")
    assert rule_R10_react_rescued(case2) is None


def test_R10_priority_R7_miscat_takes_precedence_over_rescue():
    # A miscat case that happened via rescue path: R7 should fire first
    # (record_kind is the more reliable signal), R10 should NOT fire.
    case = _case(
        record_kind="miscategorized",
        outcome="blocked",
        route="react_fallback_rag_rescue",
    )
    label = label_case(case)
    assert label["rule_id"] == "R7"
    assert label["layer"] == "miscategorized"


def test_R10_fires_after_R7_when_record_kind_is_not_miscat():
    # rescued block that is NOT miscategorized → R10 wins over R1-R9
    case = _case(
        record_kind="false_negative",
        outcome="blocked",
        route="react_fallback_rag_rescue",
        local_score_total=0.55,
        rag_used=True,
        rag_top_score=0.62,
    )
    label = label_case(case)
    assert label["rule_id"] == "R10"


if __name__ == "__main__":
    tests = [
        test_R1_fires_when_nested_but_no_frags,
        test_R1_skipped_when_frags_present,
        test_R1_skipped_when_body_is_plain_text,
        test_R1_novel_encoding_cause_when_pct_signal,
        test_R1_deep_nesting_cause_when_no_encoding_signal,
        test_R2_fires_low_score_passed_no_markers,
        test_R2_skipped_when_marker_in_reasons,
        test_R2_skipped_when_score_above_threshold,
        test_R2_skipped_when_blocked,
        test_R3_fires_rag_used_score_low,
        test_R3_medium_confidence_at_0_50,
        test_R3_skipped_when_rag_not_used,
        test_R3_skipped_when_score_above_threshold,
        test_R4_fires_high_score_wrong_category,
        test_R4_skipped_when_category_matches,
        test_R4_skipped_when_no_expected_category,
        test_R5_fires_high_score_passed_via_llm,
        test_R5_skipped_when_route_is_fast_pass,
        test_R5_fires_for_react_route_too,
        test_R6_fires_fast_pass_with_meaningful_score,
        test_R6_skipped_when_score_below_gray,
        test_R6_skipped_when_not_fast_pass,
        test_R7_fires_when_record_kind_miscategorized,
        test_R7_skipped_for_normal_record_kinds,
        test_R9_fires_fallback_route_with_meaningful_score,
        test_R9_skipped_when_score_below_gray,
        test_R9_skipped_when_route_is_not_fallback,
        test_R9_skipped_when_blocked,
        test_R8_always_returns_unknown,
        test_priority_R5_beats_R3_when_both_apply,
        test_priority_R7_beats_everything,
        test_unmatched_case_goes_to_R8,
        test_derive_output_path_cases_prefix,
        test_derive_output_path_no_cases_prefix,
        test_derive_output_path_with_override,
        # R10 (harden-waf2-react-fallback-rag-rescue)
        test_R10_fires_for_rescued_block,
        test_R10_skipped_when_outcome_passed,
        test_R10_skipped_when_route_is_not_rescue,
        test_R10_priority_R7_miscat_takes_precedence_over_rescue,
        test_R10_fires_after_R7_when_record_kind_is_not_miscat,
    ]
    for test in tests:
        test()
    with tempfile.TemporaryDirectory() as td:
        test_label_file_writes_one_label_per_input(Path(td))
    print(f"label_failures rule tests passed ({len(tests) + 1} cases)")
