"""Tests for Scenario-Playbook dataset integrity."""
import json
import re
from pathlib import Path

import pytest

DATASET_PATH = Path(__file__).resolve().parent.parent / "rag" / "eval" / "scenario-playbook" / "scenarios.jsonl"
SCHEMA_PATH = Path(__file__).resolve().parent.parent / "rag" / "eval" / "scenario-playbook" / "schema.json"

VALID_PLATFORMS = {"wordpress", "woocommerce", "supabase"}
VALID_SUBCATEGORIES = {
    "data_exfiltration", "credential_theft", "recon_then_exploit",
    "supabase_lethal_trifecta", "prompt_injection_to_exfil",
}
VALID_LAYERS = {"waf1", "waf2", "both"}
CASE_ID_RE = re.compile(r"^sp:(wordpress|woocommerce|supabase):\d{2}$")
TOOL_RE = re.compile(r"^[a-zA-Z0-9_-]+__[a-zA-Z0-9_]+$")


@pytest.fixture(scope="module")
def scenarios():
    lines = DATASET_PATH.read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines if line.strip()]


def test_total_count(scenarios):
    assert len(scenarios) == 30


def test_platform_distribution(scenarios):
    by_platform = {}
    for s in scenarios:
        by_platform.setdefault(s["platform"], 0)
        by_platform[s["platform"]] += 1
    assert by_platform == {"wordpress": 10, "woocommerce": 10, "supabase": 10}


def test_case_id_uniqueness(scenarios):
    ids = [s["case_id"] for s in scenarios]
    assert len(ids) == len(set(ids))


def test_case_id_format(scenarios):
    for s in scenarios:
        assert CASE_ID_RE.match(s["case_id"]), f"Bad case_id: {s['case_id']}"


def test_all_required_fields(scenarios):
    required = [
        "case_id", "label", "family", "subcategory", "platform",
        "scenario_description", "steps", "expected_chain", "expected_block_step",
        "expected_layer", "tag",
    ]
    for s in scenarios:
        for field in required:
            assert field in s, f"{s['case_id']}: missing field '{field}'"


def test_label_always_attack(scenarios):
    for s in scenarios:
        assert s["label"] == "attack"


def test_family_always_call_chain(scenarios):
    for s in scenarios:
        assert s["family"] == "call_chain"


def test_valid_platform(scenarios):
    for s in scenarios:
        assert s["platform"] in VALID_PLATFORMS


def test_valid_subcategory(scenarios):
    for s in scenarios:
        assert s["subcategory"] in VALID_SUBCATEGORIES


def test_valid_expected_layer(scenarios):
    for s in scenarios:
        assert s["expected_layer"] in VALID_LAYERS


def test_step_count_range(scenarios):
    for s in scenarios:
        n = len(s["steps"])
        assert 2 <= n <= 4, f"{s['case_id']}: {n} steps"


def test_step_tool_format(scenarios):
    for s in scenarios:
        for i, step in enumerate(s["steps"]):
            assert TOOL_RE.match(step["tool"]), (
                f"{s['case_id']} step {i+1}: bad tool format '{step['tool']}'"
            )


def test_step_has_args(scenarios):
    for s in scenarios:
        for i, step in enumerate(s["steps"]):
            assert "args" in step, f"{s['case_id']} step {i+1}: missing args"


def test_expected_block_step_range(scenarios):
    for s in scenarios:
        ebs = s["expected_block_step"]
        assert 1 <= ebs <= len(s["steps"]), (
            f"{s['case_id']}: expected_block_step={ebs} but {len(s['steps'])} steps"
        )


def test_expected_chain_matches_subcategory(scenarios):
    for s in scenarios:
        assert s["expected_chain"] == s["subcategory"], (
            f"{s['case_id']}: expected_chain={s['expected_chain']} != subcategory={s['subcategory']}"
        )


def test_scenario_description_min_length(scenarios):
    for s in scenarios:
        assert len(s["scenario_description"]) >= 10, (
            f"{s['case_id']}: scenario_description too short"
        )


def test_tag_nonempty(scenarios):
    for s in scenarios:
        assert len(s["tag"]) >= 1
