"""Smoke tests for Phase D scripts (sample_for_manual + build_failure_report).

Run with:
  python3 waf2/tests/test_phase_d_scripts.py
"""

import json
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "rag" / "scripts"))

from sample_for_manual import (
    SAMPLE_SEED,
    _infer_eval,
    build_checklist,
    select,
)
from build_failure_report import (
    B1_HYPOTHESIS_BREAK_THRESHOLD,
    B1_SINGLE_BUCKET_CAUSE,
    _aggregate,
    _b1_hypothesis_verdict,
    _compare,
    _discover_pairs,
    _format_report,
    _parse_b1_sample,
)


def _case(**overrides):
    base = {
        "case_id": "test:0",
        "body_hash": "abc",
        "dataset": "b0",
        "round_or_split": "rag-off",
        "expected": "blocked",
        "outcome": "passed",
        "record_kind": "false_negative",
        "method": "POST",
        "path": "/x",
        "body": '{"a":1}',
        "detected_category": "",
        "local_score_total": 0.0,
        "local_score_top": {},
        "rag_used": False,
        "rag_top_score": 0.0,
        "rag_top_category": "",
        "route": "",
        "reasons": [],
        "normalize_meta": {},
        "latency_ms": 0,
    }
    base.update(overrides)
    return base


def _label(**overrides):
    base = {
        "case_id": "test:0",
        "dataset": "b0",
        "round_or_split": "rag-off",
        "record_kind": "false_negative",
        "rule_id": "R5",
        "layer": "llm_overrode",
        "cause_hint": "carrier_unaware",
        "fix_hint": "fath_judge_wrap",
        "confidence": "high",
    }
    base.update(overrides)
    return base


def _write_jsonl(path, records):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")


# ==================== sample_for_manual ====================


def test_infer_eval_homogeneous_dataset():
    assert _infer_eval([_case(dataset="csic")]) == "csic"
    assert _infer_eval([_case(dataset="b0")]) == "b0"
    assert _infer_eval([_case(dataset="b1")]) == "b1"


def test_select_b1_sampling_is_deterministic():
    cases = [_case(case_id=f"b1:dh_base:{i}") for i in range(100)]
    s1 = select(cases, "b1", 30)
    s2 = select(cases, "b1", 30)
    assert [c["case_id"] for c in s1] == [c["case_id"] for c in s2]
    assert len(s1) == 30


def test_select_b0_returns_all():
    cases = [_case(case_id=f"b0:{i}") for i in range(50)]
    s = select(cases, "b0", 30)
    assert len(s) == 50  # no sampling for B-0


def test_select_csic_returns_all():
    cases = [_case(case_id=f"csic:{i}") for i in range(10)]
    s = select(cases, "csic", 30)
    assert len(s) == 10


def test_select_b1_below_threshold_returns_all():
    cases = [_case(case_id=f"b1:{i}") for i in range(20)]
    s = select(cases, "b1", 30)  # n > len(cases)
    assert len(s) == 20


def test_build_checklist_emits_blanks_per_case():
    cases = [_case(case_id="c1"), _case(case_id="c2")]
    md = build_checklist(cases, {}, "b1", full_size=100)
    assert "**case_id:** `c1`" in md
    assert "**case_id:** `c2`" in md
    assert "**cause:** `__________`" in md
    # Two checklist items
    assert md.count("- [ ]") == 2


def test_build_checklist_annotates_with_labels():
    cases = [_case(case_id="c1")]
    labels = {"c1": _label(rule_id="R5", layer="llm_overrode")}
    md = build_checklist(cases, labels, "b1", full_size=100)
    assert "R5/llm_overrode" in md


# ==================== build_failure_report ====================


def test_aggregate_groups_fix_hints(tmp_path):
    cases = [
        _case(case_id="c1"),
        _case(case_id="c2"),
        _case(case_id="c3"),
    ]
    labels = [
        _label(case_id="c1", fix_hint="fath_judge_wrap", confidence="high"),
        _label(case_id="c2", fix_hint="fath_judge_wrap", confidence="high"),
        _label(case_id="c3", fix_hint="kb_inject_socialeng", confidence="medium"),
    ]
    _write_jsonl(tmp_path / "cases-b0-rag-off.jsonl", cases)
    _write_jsonl(tmp_path / "labels-b0-rag-off.jsonl", labels)

    pairs = _discover_pairs(tmp_path)
    agg = _aggregate(pairs)
    assert agg["total_cases"] == 3
    assert agg["fix_counts"]["fath_judge_wrap"] == 2
    assert agg["fix_counts"]["kb_inject_socialeng"] == 1
    assert agg["fix_high_conf"]["fath_judge_wrap"] == 2


def test_aggregate_splits_composite_fix_hint(tmp_path):
    cases = [_case(case_id="c1")]
    labels = [_label(case_id="c1", fix_hint="fath_judge_wrap+field_path_boost")]
    _write_jsonl(tmp_path / "cases-b0-rag-off.jsonl", cases)
    _write_jsonl(tmp_path / "labels-b0-rag-off.jsonl", labels)

    pairs = _discover_pairs(tmp_path)
    agg = _aggregate(pairs)
    assert agg["fix_counts"]["fath_judge_wrap"] == 1
    assert agg["fix_counts"]["field_path_boost"] == 1


def test_aggregate_counts_unknown(tmp_path):
    cases = [
        _case(case_id="c1"),
        _case(case_id="c2"),
        _case(case_id="c3"),
    ]
    labels = [
        _label(case_id="c1", rule_id="R5", layer="llm_overrode"),
        _label(case_id="c2", rule_id="R8", layer="unknown"),
        _label(case_id="c3", rule_id="R8", layer="unknown"),
    ]
    _write_jsonl(tmp_path / "cases-b0-rag-off.jsonl", cases)
    _write_jsonl(tmp_path / "labels-b0-rag-off.jsonl", labels)

    agg = _aggregate(_discover_pairs(tmp_path))
    assert agg["total_unknown"] == 2
    assert agg["layer_counts"]["unknown"] == 2


def test_aggregate_handles_missing_labels_file(tmp_path):
    cases = [_case(case_id="c1")]
    _write_jsonl(tmp_path / "cases-csic-rag-off.jsonl", cases)
    # No labels-csic-rag-off.jsonl

    pairs = _discover_pairs(tmp_path)
    agg = _aggregate(pairs)
    assert "cases-csic-rag-off.jsonl" in agg["unlabeled_files"]
    assert agg["total_unknown"] == 0  # not counted since no labels


def test_b1_sample_parses_filled_and_blank():
    md = """
- [ ] **case_id:** `b1:dh_base:1` | **auto:** R2/local_score_low | **cause:** `social_eng_no_marker`
- [ ] **case_id:** `b1:dh_base:2` | **auto:** R2/local_score_low | **cause:** `__________`
- [ ] **case_id:** `b1:dh_base:3` | **auto:** R5/llm_overrode | **cause:** `carrier_unaware`
"""
    with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False) as fh:
        fh.write(md)
        path = Path(fh.name)
    try:
        out = _parse_b1_sample(path)
        assert out["filled"] == {
            "b1:dh_base:1": "social_eng_no_marker",
            "b1:dh_base:3": "carrier_unaware",
        }
        assert out["blanks"] == ["b1:dh_base:2"]
        assert out["total"] == 3
    finally:
        path.unlink()


def test_b1_verdict_intact_when_dominant():
    filled = {f"b1:{i}": B1_SINGLE_BUCKET_CAUSE for i in range(28)}
    filled["b1:99"] = "carrier_unaware"
    verdict, counts = _b1_hypothesis_verdict(filled)
    assert verdict == "intact"


def test_b1_verdict_broken_when_threshold_exceeded():
    filled = {f"b1:{i}": B1_SINGLE_BUCKET_CAUSE for i in range(25)}
    for i in range(B1_HYPOTHESIS_BREAK_THRESHOLD):
        filled[f"b1:other:{i}"] = "carrier_unaware"
    verdict, _ = _b1_hypothesis_verdict(filled)
    assert verdict == "broken"


def test_b1_verdict_no_data_when_empty():
    verdict, _ = _b1_hypothesis_verdict({})
    assert verdict == "no-data"


def test_compare_counts_new_fixed_persistent(tmp_path):
    prior = tmp_path / "prior"
    curr = tmp_path / "curr"
    _write_jsonl(
        prior / "cases-b0-rag-off.jsonl",
        [_case(case_id="c1"), _case(case_id="c2")],
    )
    _write_jsonl(
        curr / "cases-b0-rag-off.jsonl",
        [_case(case_id="c2"), _case(case_id="c3")],
    )
    pairs = _discover_pairs(curr)
    agg = _aggregate(pairs)
    diff = _compare(agg["case_ids_by_source"], prior)
    assert diff["new"] == 1     # c3 only in curr
    assert diff["fixed"] == 1   # c1 only in prior
    assert diff["same"] == 1    # c2 in both


def test_format_report_contains_key_sections(tmp_path):
    cases = [_case(case_id="c1")]
    labels = [_label(case_id="c1", fix_hint="fath_judge_wrap")]
    _write_jsonl(tmp_path / "cases-b0-rag-off.jsonl", cases)
    _write_jsonl(tmp_path / "labels-b0-rag-off.jsonl", labels)

    agg = _aggregate(_discover_pairs(tmp_path))
    md = _format_report(tmp_path, agg, None, None)
    assert "# Failure Analysis Report" in md
    assert "## Overview" in md
    assert "## Fix-bucket ROI" in md
    assert "## Layer distribution" in md
    assert "## Rule fire counts" in md
    assert "fath_judge_wrap" in md
    assert "harden-waf2-llm-judge-field-isolation" in md  # mapped change name


def test_format_report_warns_on_high_unknown_rate(tmp_path):
    cases = [_case(case_id=f"c{i}") for i in range(10)]
    labels = [_label(case_id=f"c{i}", rule_id="R8", layer="unknown") for i in range(4)]
    labels += [_label(case_id=f"c{i}", rule_id="R5", layer="llm_overrode") for i in range(4, 10)]
    _write_jsonl(tmp_path / "cases-b0-rag-off.jsonl", cases)
    _write_jsonl(tmp_path / "labels-b0-rag-off.jsonl", labels)

    agg = _aggregate(_discover_pairs(tmp_path))
    md = _format_report(tmp_path, agg, None, None)
    assert "⚠️" in md
    assert "unknown rate exceeds 30%" in md


if __name__ == "__main__":
    tests_no_tmp = [
        test_infer_eval_homogeneous_dataset,
        test_select_b1_sampling_is_deterministic,
        test_select_b0_returns_all,
        test_select_csic_returns_all,
        test_select_b1_below_threshold_returns_all,
        test_build_checklist_emits_blanks_per_case,
        test_build_checklist_annotates_with_labels,
        test_b1_sample_parses_filled_and_blank,
        test_b1_verdict_intact_when_dominant,
        test_b1_verdict_broken_when_threshold_exceeded,
        test_b1_verdict_no_data_when_empty,
    ]
    for t in tests_no_tmp:
        t()

    tests_with_tmp = [
        test_aggregate_groups_fix_hints,
        test_aggregate_splits_composite_fix_hint,
        test_aggregate_counts_unknown,
        test_aggregate_handles_missing_labels_file,
        test_compare_counts_new_fixed_persistent,
        test_format_report_contains_key_sections,
        test_format_report_warns_on_high_unknown_rate,
    ]
    for t in tests_with_tmp:
        with tempfile.TemporaryDirectory() as td:
            t(Path(td))

    print(f"phase D scripts tests passed ({len(tests_no_tmp) + len(tests_with_tmp)} cases)")
