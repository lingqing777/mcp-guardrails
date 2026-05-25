"""Tests for report_scenario_playbook.py merge and summary logic."""
import sys
from pathlib import Path

import pytest

SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "rag" / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

from report_scenario_playbook import (
    group_waf2_by_scenario,
    merge_scenario,
    generate_summary,
)


def _make_waf1(**overrides):
    base = {
        "scenario_case_id": "sp:wordpress:01",
        "platform": "wordpress",
        "scenario_description": "test",
        "subcategory": "data_exfiltration",
        "tag": "test-tag",
        "outcome": "blocked",
        "blocked_at_step": 1,
        "step_verdicts": [{"step": 1, "blocked": True, "category": "sqlInjection"}],
        "expected_block_step": 1,
        "expected_layer": "waf1",
    }
    base.update(overrides)
    return base


def _make_waf2_step(**overrides):
    base = {
        "scenario_case_id": "sp:wordpress:01",
        "step_num": 1,
        "outcome": "passed",
        "route": "fast_pass",
    }
    base.update(overrides)
    return base


# ---------- group_waf2_by_scenario ----------


def test_group_waf2_by_scenario():
    steps = [
        _make_waf2_step(step_num=1),
        _make_waf2_step(step_num=2),
        _make_waf2_step(scenario_case_id="sp:supabase:01", step_num=1),
    ]
    grouped = group_waf2_by_scenario(steps)
    assert len(grouped) == 2
    assert len(grouped["sp:wordpress:01"]) == 2
    assert len(grouped["sp:supabase:01"]) == 1


def test_group_waf2_empty():
    grouped = group_waf2_by_scenario([])
    assert len(grouped) == 0


# ---------- merge_scenario ----------


def test_merge_both_blocked():
    waf1 = _make_waf1(outcome="blocked", blocked_at_step=1)
    waf2 = [_make_waf2_step(step_num=1, outcome="blocked", route="static_block")]
    result = merge_scenario(waf1, waf2)
    assert result["overall_blocked"] is True
    assert result["actual_layer"] == "both"
    assert result["actual_block_step"] == 1


def test_merge_waf1_only():
    waf1 = _make_waf1(outcome="blocked", blocked_at_step=1)
    waf2 = [_make_waf2_step(step_num=1, outcome="passed")]
    result = merge_scenario(waf1, waf2)
    assert result["overall_blocked"] is True
    assert result["actual_layer"] == "waf1"


def test_merge_waf2_only():
    waf1 = _make_waf1(outcome="passed", blocked_at_step=None)
    waf2 = [_make_waf2_step(step_num=2, outcome="blocked", route="local_llm_one_shot")]
    result = merge_scenario(waf1, waf2)
    assert result["overall_blocked"] is True
    assert result["actual_layer"] == "waf2"
    assert result["actual_block_step"] == 2


def test_merge_neither_blocked():
    waf1 = _make_waf1(outcome="passed", blocked_at_step=None)
    waf2 = [_make_waf2_step(step_num=1, outcome="passed")]
    result = merge_scenario(waf1, waf2)
    assert result["overall_blocked"] is False
    assert result["actual_layer"] == "none"
    assert result["actual_block_step"] is None


def test_merge_gray_zone_react():
    waf1 = _make_waf1(outcome="passed", blocked_at_step=None)
    waf2 = [_make_waf2_step(step_num=1, outcome="passed", route="react_deep_inspection")]
    result = merge_scenario(waf1, waf2)
    assert result["needs_gray_zone"] is True


def test_merge_gray_zone_fallback():
    waf1 = _make_waf1(outcome="passed", blocked_at_step=None)
    waf2 = [_make_waf2_step(step_num=1, outcome="passed", route="fallback")]
    result = merge_scenario(waf1, waf2)
    assert result["needs_gray_zone"] is True


def test_merge_no_gray_zone_on_fast_pass():
    waf1 = _make_waf1(outcome="passed", blocked_at_step=None)
    waf2 = [_make_waf2_step(step_num=1, outcome="passed", route="fast_pass")]
    result = merge_scenario(waf1, waf2)
    assert result["needs_gray_zone"] is False


def test_merge_earliest_block_step():
    waf1 = _make_waf1(outcome="blocked", blocked_at_step=2)
    waf2 = [_make_waf2_step(step_num=1, outcome="blocked", route="static_block")]
    result = merge_scenario(waf1, waf2)
    assert result["actual_block_step"] == 1  # WAF2 step 1 is earlier


def test_merge_no_waf2_steps():
    waf1 = _make_waf1(outcome="blocked", blocked_at_step=1)
    result = merge_scenario(waf1, [])
    assert result["overall_blocked"] is True
    assert result["actual_layer"] == "waf1"
    assert result["waf2_blocked"] is False


# ---------- generate_summary ----------


def test_summary_contains_table():
    results = [
        {
            "case_id": "sp:wordpress:01", "platform": "wordpress",
            "scenario_description": "test", "subcategory": "data_exfiltration",
            "tag": "t", "num_steps": 2, "expected_block_step": 1,
            "expected_layer": "waf1", "overall_blocked": True,
            "actual_layer": "waf1", "actual_block_step": 1,
            "needs_gray_zone": False,
            "waf1_outcome": "blocked", "waf1_blocked_at_step": 1,
            "waf2_blocked": False, "waf2_blocked_at_step": None,
        },
    ]
    summary = generate_summary(results)
    assert "Table 5.2" in summary
    assert "WordPress" in summary
    assert "| WordPress |" in summary


def test_summary_all_platforms():
    results = [
        {"case_id": f"sp:{p}:01", "platform": p, "scenario_description": "t",
         "subcategory": "data_exfiltration", "tag": "t", "num_steps": 2,
         "expected_block_step": 1, "expected_layer": "waf1",
         "overall_blocked": True, "actual_layer": "waf1", "actual_block_step": 1,
         "needs_gray_zone": False, "waf1_outcome": "blocked",
         "waf1_blocked_at_step": 1, "waf2_blocked": False, "waf2_blocked_at_step": None}
        for p in ("wordpress", "woocommerce", "supabase")
    ]
    summary = generate_summary(results)
    assert "WordPress" in summary
    assert "WooCommerce" in summary
    assert "Supabase" in summary
    assert "综合" in summary


def test_summary_per_scenario_detail():
    results = [
        {
            "case_id": "sp:wordpress:01", "platform": "wordpress",
            "scenario_description": "test", "subcategory": "data_exfiltration",
            "tag": "wp-test", "num_steps": 2, "expected_block_step": 1,
            "expected_layer": "waf1", "overall_blocked": True,
            "actual_layer": "waf1", "actual_block_step": 1,
            "needs_gray_zone": False,
            "waf1_outcome": "blocked", "waf1_blocked_at_step": 1,
            "waf2_blocked": False, "waf2_blocked_at_step": None,
        },
    ]
    summary = generate_summary(results)
    assert "Per-Scenario Detail" in summary
    assert "wp-test" in summary
