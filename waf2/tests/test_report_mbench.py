"""Tests for report_mbench.py.

Run: PYTHONPATH=waf2/rag/scripts python3 waf2/tests/test_report_mbench.py

Covers:
  - All 6 tables render and appear in the final markdown
  - F1 uses real precision (not equal to recall when precision < 1)
  - Hard-neg callout fires when gap >= 10 percentage points
  - Universe classification: real vs synthetic
  - Chain block-step grouping respects expected_block_step bounds
  - Per-subcategory matrix sorted by count desc
  - Confusion arithmetic matches manual calculation
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "rag" / "scripts"))

import report_mbench as R  # noqa: E402


# ---------- fixture builders ----------


def _classification(layer_to_class: dict[str, str]) -> dict:
    """Build a classification dict, defaulting other layers to TN."""
    base = {l: "TN" for l in R.LAYERS}
    base.update(layer_to_class)
    return base


def _attack_record(
    *,
    row_index: int,
    family: str = "char_injection",
    subcategory: str = "sql_injection",
    tool: str = "woocommerce__list_orders",
    is_multi_step: bool = False,
    expected_block_step: int | None = None,
    classification: dict[str, str] | None = None,
    steps: list | None = None,
) -> dict:
    classification = classification or {l: "TP" for l in R.LAYERS}
    rec = {
        "case_id_orig": f"mbc:attack:{str(row_index).zfill(3)}",
        "case_id": f"mbench:merged:{str(row_index).zfill(4)}",
        "row_index": row_index,
        "label": "attack",
        "family": family,
        "subcategory": subcategory,
        "tool": tool,
        "is_multi_step": is_multi_step,
        "expected_block_step": expected_block_step,
        "steps": steps,
        "classification": classification,
        "waf1_strict": {"blocked": classification.get("waf1_strict") == "TP",
                        "detected_namespace": ""},
        "waf1_full": {"blocked": classification.get("waf1_full") == "TP",
                      "detected_namespace": "", "blocked_at_step": None},
        "rag_on": {"blocked": classification.get("rag_on") == "TP",
                   "detected_namespace": ""},
        "rag_off": {"blocked": classification.get("rag_off") == "TP",
                    "detected_namespace": ""},
    }
    return rec


def _benign_record(
    *,
    row_index: int,
    source: str = "template",
    paired_with: str | None = None,
    tool: str = "woocommerce__list_orders",
    classification: dict[str, str] | None = None,
) -> dict:
    classification = classification or {l: "TN" for l in R.LAYERS}
    return {
        "case_id_orig": f"mbc:benign:{str(row_index).zfill(4)}",
        "case_id": f"mbench:merged:{str(row_index).zfill(4)}",
        "row_index": row_index,
        "label": "benign",
        "family": "",
        "subcategory": "",
        "tool": tool,
        "is_multi_step": False,
        "source": source,
        "paired_with": paired_with,
        "classification": classification,
        "waf1_strict": {"blocked": classification.get("waf1_strict") == "FP",
                        "detected_namespace": ""},
        "waf1_full": {"blocked": classification.get("waf1_full") == "FP",
                      "detected_namespace": "", "blocked_at_step": None},
        "rag_on": {"blocked": classification.get("rag_on") == "FP",
                   "detected_namespace": ""},
        "rag_off": {"blocked": classification.get("rag_off") == "FP",
                    "detected_namespace": ""},
    }


# ---------- tests ----------


def test_tool_universe_real_vs_synthetic():
    real = _attack_record(row_index=0, tool="woocommerce__list_orders")
    syn = _attack_record(row_index=1, tool="xml_processor__parse")
    assert R.tool_universe(real) == "real"
    assert R.tool_universe(syn) == "synthetic"
    # Multi-step: any synthetic step → synthetic
    multi = _attack_record(
        row_index=2,
        family="call_chain",
        is_multi_step=True,
        steps=[
            {"tool": "woocommerce__list_orders", "args": {}},
            {"tool": "xml_processor__parse", "args": {}},
        ],
    )
    assert R.tool_universe(multi) == "synthetic"
    print("test_tool_universe_real_vs_synthetic OK")


def test_confusion_arithmetic():
    """3 TP + 2 FN + 1 FP + 4 TN → precision = 3/4, recall = 3/5, F1 ≈ 0.667."""
    records = []
    for i in range(3):
        records.append(_attack_record(
            row_index=i,
            classification={l: "TP" for l in R.LAYERS},
        ))
    for i in range(3, 5):
        records.append(_attack_record(
            row_index=i,
            classification={l: "FN" for l in R.LAYERS},
        ))
    records.append(_benign_record(
        row_index=5,
        classification={l: "FP" for l in R.LAYERS},
    ))
    for i in range(6, 10):
        records.append(_benign_record(
            row_index=i,
            classification={l: "TN" for l in R.LAYERS},
        ))
    c = R.confusion(records, "dual")
    assert c["tp"] == 3
    assert c["fn"] == 2
    assert c["fp"] == 1
    assert c["tn"] == 4
    assert abs(c["precision"] - 0.75) < 1e-6
    assert abs(c["recall"] - 0.6) < 1e-6
    # F1 = 2 * 0.75 * 0.6 / (0.75 + 0.6) = 0.9 / 1.35 ≈ 0.6667
    assert abs(c["f1"] - (2 * 0.75 * 0.6 / 1.35)) < 1e-6
    # F1 should NOT equal recall (because precision < 1)
    assert abs(c["f1"] - c["recall"]) > 1e-3
    print("test_confusion_arithmetic OK")


def test_hardneg_callout_fires_when_gap_gte_10pp():
    """5 handcrafted, 4 FP → 80% FP rate. 10 template, 1 FP → 10% FP rate.
    Gap = 70 pp ≥ 10 pp → overblock_flag=True."""
    records = []
    # 4 attacks (need some attack samples for the dataset to be coherent)
    for i in range(4):
        records.append(_attack_record(row_index=i))
    # 5 handcrafted benigns, 4 are FP (on dual layer)
    for i in range(4, 8):
        records.append(_benign_record(
            row_index=i, source="handcrafted",
            paired_with=f"mbc:attack:{i:03d}",
            classification={l: "FP" for l in R.LAYERS},
        ))
    records.append(_benign_record(
        row_index=8, source="handcrafted",
        paired_with="mbc:attack:008",
        classification={l: "TN" for l in R.LAYERS},
    ))
    # 10 template benigns, 1 is FP
    for i in range(9, 18):
        records.append(_benign_record(
            row_index=i, source="template",
            classification={l: "TN" for l in R.LAYERS},
        ))
    records.append(_benign_record(
        row_index=19, source="template",
        classification={l: "FP" for l in R.LAYERS},
    ))

    t = R.build_table_hardneg_breakdown(records)
    cell = t["dual"]
    assert cell["handcrafted_total"] == 5
    assert cell["handcrafted_fp"] == 4
    assert cell["template_total"] == 10
    assert cell["template_fp"] == 1
    assert cell["gap_pp"] > 10.0
    assert cell["overblock_flag"] is True
    # Render to verify callout text is in markdown
    md = R.render_table_hardneg(t)
    assert "OVERBLOCK" in md
    assert "Callout" in md
    print("test_hardneg_callout_fires_when_gap_gte_10pp OK")


def test_hardneg_no_callout_when_balanced():
    records = []
    for i in range(4):
        records.append(_attack_record(row_index=i))
    # 5 handcrafted, 1 FP (20%); 10 template, 2 FP (20%) → gap=0
    for i in range(4, 8):
        records.append(_benign_record(
            row_index=i, source="handcrafted",
            paired_with=f"mbc:attack:{i:03d}",
            classification={l: "TN" for l in R.LAYERS},
        ))
    records.append(_benign_record(
        row_index=8, source="handcrafted",
        paired_with="mbc:attack:008",
        classification={l: "FP" for l in R.LAYERS},
    ))
    for i in range(9, 17):
        records.append(_benign_record(
            row_index=i, source="template",
            classification={l: "TN" for l in R.LAYERS},
        ))
    for i in range(17, 19):
        records.append(_benign_record(
            row_index=i, source="template",
            classification={l: "FP" for l in R.LAYERS},
        ))
    t = R.build_table_hardneg_breakdown(records)
    assert t["dual"]["overblock_flag"] is False
    md = R.render_table_hardneg(t)
    assert "OVERBLOCK" not in md
    print("test_hardneg_no_callout_when_balanced OK")


def test_chain_block_step_grouping():
    records = [
        _attack_record(row_index=0, family="call_chain", is_multi_step=True,
                       subcategory="data_exfiltration",
                       expected_block_step=1,
                       classification={l: "TP" for l in R.LAYERS}),
        _attack_record(row_index=1, family="call_chain", is_multi_step=True,
                       subcategory="credential_theft",
                       expected_block_step=2,
                       classification={l: "FN" for l in R.LAYERS}),
        _attack_record(row_index=2, family="call_chain", is_multi_step=True,
                       subcategory="credential_theft",
                       expected_block_step=2,
                       classification={l: "TP" for l in R.LAYERS}),
    ]
    t = R.build_table_chain_block_step(records)
    assert set(t.keys()) == {1, 2}
    assert t[1]["dual"]["recall"] == 1.0
    assert t[1]["dual"]["n"] == 1
    assert t[2]["dual"]["recall"] == 0.5  # 1 of 2 TPs
    assert t[2]["dual"]["n"] == 2
    print("test_chain_block_step_grouping OK")


def test_per_subcategory_sorted_by_count_desc():
    records = [
        _attack_record(row_index=0, subcategory="sql_injection",
                       classification={l: "TP" for l in R.LAYERS}),
        _attack_record(row_index=1, subcategory="sql_injection",
                       classification={l: "FN" for l in R.LAYERS}),
        _attack_record(row_index=2, subcategory="sql_injection",
                       classification={l: "TP" for l in R.LAYERS}),
        _attack_record(row_index=3, subcategory="xss",
                       classification={l: "TP" for l in R.LAYERS}),
    ]
    t = R.build_table_per_subcategory(records)
    keys = list(t.keys())
    assert keys[0] == "sql_injection"  # 3 samples
    assert keys[1] == "xss"  # 1 sample
    assert t["sql_injection"]["dual"]["recall"] == 2 / 3
    assert t["xss"]["dual"]["recall"] == 1.0
    print("test_per_subcategory_sorted_by_count_desc OK")


def test_render_report_has_all_six_tables():
    records = [
        _attack_record(row_index=0, family="char_injection",
                       subcategory="sql_injection",
                       classification={l: "TP" for l in R.LAYERS}),
        _attack_record(row_index=1, family="prompt_injection_and_priv_esc",
                       subcategory="direct_pi",
                       classification={l: "FN" for l in R.LAYERS}),
        _attack_record(row_index=2, family="call_chain",
                       subcategory="credential_theft",
                       is_multi_step=True, expected_block_step=2,
                       steps=[
                           {"tool": "file_read_MCP__read", "args": {}},
                           {"tool": "http-client__http_request", "args": {}},
                       ],
                       classification={"waf1_union": "TP", "rag_on": "FN", "dual": "TP",
                                       "waf1_strict": "FN", "waf1_full": "TP",
                                       "rag_off": "FN"}),
        _benign_record(row_index=3, source="handcrafted",
                       paired_with="mbc:attack:000",
                       classification={l: "TN" for l in R.LAYERS}),
        _benign_record(row_index=4, source="template",
                       classification={l: "TN" for l in R.LAYERS}),
        _benign_record(row_index=5, source="template",
                       classification={l: "FP" for l in R.LAYERS}),
        # Synthetic tool sample
        _attack_record(row_index=6, family="char_injection",
                       subcategory="xxe", tool="xml_processor__parse",
                       classification={l: "TP" for l in R.LAYERS}),
    ]
    with tempfile.NamedTemporaryFile(suffix=".jsonl", mode="w", delete=False) as f:
        merged_path = Path(f.name)
    md = R.render_report(records, merged_path)
    # 6 table headers must appear
    assert "## Table 1 — Overall Confusion" in md
    assert "## Table 2 — Per-Family Confusion" in md
    assert "## Table 3 — Per-Tool-Universe" in md
    assert "## Table 4 — Hard-neg vs Template FP" in md
    assert "## Table 5 — Chain Block-Step Distribution" in md
    assert "## Table 6 — Per-Subcategory Recall" in md
    assert "Fairness Disclosures" in md
    assert "Reproduction" in md
    assert "WAF1 (strict ∪ full)" in md
    merged_path.unlink(missing_ok=True)
    print("test_render_report_has_all_six_tables OK")


def test_real_precision_in_overall_table():
    """F1 should be computed from real precision, not assume precision=1."""
    records = [
        _attack_record(row_index=0,
                       classification={l: "TP" for l in R.LAYERS}),
        _attack_record(row_index=1,
                       classification={l: "TP" for l in R.LAYERS}),
        _attack_record(row_index=2,
                       classification={l: "FN" for l in R.LAYERS}),
        # 2 FP benigns → precision = 2/4 = 0.5
        _benign_record(row_index=3, source="template",
                       classification={l: "FP" for l in R.LAYERS}),
        _benign_record(row_index=4, source="template",
                       classification={l: "FP" for l in R.LAYERS}),
        _benign_record(row_index=5, source="template",
                       classification={l: "TN" for l in R.LAYERS}),
    ]
    t = R.build_table_overall(records)
    c = t["dual"]
    assert c["tp"] == 2
    assert c["fn"] == 1
    assert c["fp"] == 2
    assert abs(c["precision"] - 0.5) < 1e-6
    assert abs(c["recall"] - 2 / 3) < 1e-6
    # F1 = 2 * 0.5 * 0.667 / (0.5 + 0.667) ≈ 0.571
    f1_expected = 2 * 0.5 * (2 / 3) / (0.5 + 2 / 3)
    assert abs(c["f1"] - f1_expected) < 1e-6
    # F1 ≠ recall (because precision < 1)
    assert abs(c["f1"] - c["recall"]) > 1e-3
    print("test_real_precision_in_overall_table OK")


def main():
    test_tool_universe_real_vs_synthetic()
    test_confusion_arithmetic()
    test_hardneg_callout_fires_when_gap_gte_10pp()
    test_hardneg_no_callout_when_balanced()
    test_chain_block_step_grouping()
    test_per_subcategory_sorted_by_count_desc()
    test_render_report_has_all_six_tables()
    test_real_precision_in_overall_table()
    print("\nALL TESTS PASSED")


if __name__ == "__main__":
    main()
