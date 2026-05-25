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


# ---------- TSV summary / AvgTime / --append-to ----------


def _add_latency(rec: dict, *, strict: float = 2.0, full: float = 3.0,
                 rag_on: float = 15000.0, rag_off: float = 14000.0) -> dict:
    """Stamp latency_ms into the 4 layer slots."""
    rec["waf1_strict"]["latency_ms"] = strict
    rec["waf1_full"]["latency_ms"] = full
    rec["rag_on"]["latency_ms"] = rag_on
    rec["rag_off"]["latency_ms"] = rag_off
    return rec


def test_active_layers_full_mode_includes_all_four():
    rec = _attack_record(row_index=0)
    _add_latency(rec)
    rec["skipped_layers"] = []
    layers = R.active_layers(rec)
    assert "waf1_strict" in layers
    assert "waf1_full" in layers
    assert "rag_on" in layers
    assert "rag_off" in layers  # rag_off has real latency, not stub
    print("test_active_layers_full_mode_includes_all_four OK")


def test_active_layers_waf2_skipped_excludes_rag_slots():
    rec = _attack_record(row_index=0)
    _add_latency(rec)
    rec["skipped_layers"] = ["waf2"]
    rec["rag_on"]["_skipped"] = True
    rec["rag_off"]["_skipped"] = True
    layers = R.active_layers(rec)
    assert layers == ["waf1_strict", "waf1_full"]
    print("test_active_layers_waf2_skipped_excludes_rag_slots OK")


def test_active_layers_waf1_skipped_only_rag_on():
    rec = _attack_record(row_index=0)
    _add_latency(rec)
    rec["skipped_layers"] = ["waf1"]
    rec["waf1_strict"]["_skipped"] = True
    rec["waf1_full"]["_skipped"] = True
    # Configuration 2 (WAF2-only) doesn't write rag_off — make it a stub
    rec["rag_off"]["_stub"] = True
    layers = R.active_layers(rec)
    assert layers == ["rag_on"]
    print("test_active_layers_waf1_skipped_only_rag_on OK")


def test_compute_avg_time_attacks_only_full_mode():
    """AvgTime sums all 4 active layers per attack case, then averages."""
    records = []
    for i in range(3):
        rec = _attack_record(row_index=i)
        # Latencies: strict=2, full=3, rag_on=15000, rag_off=14000 → total 29005
        _add_latency(rec)
        rec["skipped_layers"] = []
        records.append(rec)
    # Benigns with different latencies — should NOT pollute attack average
    for i in range(2):
        rec = _benign_record(row_index=100 + i)
        _add_latency(rec, strict=99, full=99, rag_on=99, rag_off=99)
        rec["skipped_layers"] = []
        records.append(rec)
    attacks_avg = R.compute_avg_time_ms(records, "attack")
    benigns_avg = R.compute_avg_time_ms(records, "benign")
    assert abs(attacks_avg - 29005.0) < 1e-3, f"attacks: {attacks_avg}"
    assert abs(benigns_avg - 396.0) < 1e-3, f"benigns: {benigns_avg}"
    print("test_compute_avg_time_attacks_only_full_mode OK")


def test_compute_avg_time_waf1_only_excludes_waf2_latency():
    """In WAF1-only ablation, rag_on/rag_off latency MUST NOT count."""
    records = []
    for i in range(2):
        rec = _attack_record(row_index=i)
        _add_latency(rec)  # rag_on=15000 should be ignored
        rec["skipped_layers"] = ["waf2"]
        rec["rag_on"]["_skipped"] = True
        rec["rag_off"]["_skipped"] = True
        records.append(rec)
    # Only waf1_strict (2) + waf1_full (3) = 5 ms per case
    avg = R.compute_avg_time_ms(records, "attack")
    assert abs(avg - 5.0) < 1e-3, f"got {avg}"
    print("test_compute_avg_time_waf1_only_excludes_waf2_latency OK")


def test_format_summary_tsv_row_eight_fields():
    metrics = {
        "char_F1": 0.98,
        "pi_F1": 0.78,
        "chain_F1": 0.74,
        "recall": 0.833,
        "F1": 0.702,
        "avg_time_attacks_ms": 15005.5,
        "avg_time_benigns_ms": 20480.0,
    }
    row = R.format_summary_tsv_row("Full no-chain", metrics)
    fields = row.split("\t")
    assert len(fields) == 8
    assert fields[0] == "Full no-chain"
    assert fields[1] == "0.980"
    assert fields[2] == "0.780"
    assert fields[3] == "0.740"
    assert fields[4] == "0.833"
    assert fields[5] == "0.702"
    assert fields[6] == "15005.5"
    assert fields[7] == "20480.0"
    # No trailing newline in formatter — write_summary_tsv adds it
    assert not row.endswith("\n")
    print("test_format_summary_tsv_row_eight_fields OK")


def test_format_summary_tsv_label_sanitization():
    """Tabs / newlines in label MUST be replaced (would break TSV columns)."""
    metrics = {k: 0.0 for k in ["char_F1", "pi_F1", "chain_F1", "recall",
                                "F1", "avg_time_attacks_ms", "avg_time_benigns_ms"]}
    row = R.format_summary_tsv_row("bad\tlabel\nhere", metrics)
    fields = row.split("\t")
    assert len(fields) == 8
    assert fields[0] == "bad label here"
    print("test_format_summary_tsv_label_sanitization OK")


def test_write_summary_tsv_file_has_one_line_eight_fields():
    with tempfile.TemporaryDirectory() as td:
        out_dir = Path(td)
        metrics = {k: 0.5 for k in ["char_F1", "pi_F1", "chain_F1", "recall",
                                    "F1", "avg_time_attacks_ms", "avg_time_benigns_ms"]}
        path = R.write_summary_tsv(out_dir, "Full", metrics)
        assert path.exists()
        content = path.read_text(encoding="utf-8")
        assert content.endswith("\n")
        lines = [ln for ln in content.split("\n") if ln]
        assert len(lines) == 1
        assert len(lines[0].split("\t")) == 8
        assert lines[0].split("\t")[0] == "Full"
    print("test_write_summary_tsv_file_has_one_line_eight_fields OK")


def test_append_to_index_accumulates_lines():
    with tempfile.TemporaryDirectory() as td:
        index_path = Path(td) / "subdir" / "index.tsv"
        metrics_a = {k: 0.5 for k in ["char_F1", "pi_F1", "chain_F1", "recall",
                                      "F1", "avg_time_attacks_ms", "avg_time_benigns_ms"]}
        metrics_b = {**metrics_a, "recall": 0.7}
        R.append_to_index(index_path, "WAF1-only", metrics_a)
        R.append_to_index(index_path, "Full", metrics_b)
        R.append_to_index(index_path, "Full no-chain", metrics_a)
        assert index_path.exists()
        lines = [ln for ln in index_path.read_text("utf-8").split("\n") if ln]
        assert len(lines) == 3
        assert lines[0].split("\t")[0] == "WAF1-only"
        assert lines[1].split("\t")[0] == "Full"
        assert lines[2].split("\t")[0] == "Full no-chain"
        # second line carries the differing recall (0.700)
        assert lines[1].split("\t")[4] == "0.700"
    print("test_append_to_index_accumulates_lines OK")


def test_summary_metrics_with_real_records():
    """Smoke test: compute_summary_metrics returns all 7 fields with sane values."""
    records = []
    # 5 char_injection TP, 3 pi FN, 4 chain TP
    for i in range(5):
        rec = _attack_record(row_index=i, family="char_injection",
                             classification=_classification({"dual": "TP"}))
        _add_latency(rec)
        records.append(rec)
    for i in range(3):
        rec = _attack_record(row_index=10 + i,
                             family="prompt_injection_and_priv_esc",
                             classification=_classification({"dual": "FN"}))
        _add_latency(rec)
        records.append(rec)
    for i in range(4):
        rec = _attack_record(row_index=20 + i, family="call_chain",
                             classification=_classification({"dual": "TP"}))
        _add_latency(rec)
        records.append(rec)
    # Some benigns (all TN by default) so FPR has a denominator
    for i in range(10):
        rec = _benign_record(row_index=100 + i,
                             classification=_classification({"dual": "TN"}))
        _add_latency(rec, rag_on=10000, rag_off=9000)
        records.append(rec)
    metrics = R.compute_summary_metrics(records)
    assert set(metrics.keys()) == {
        "char_F1", "pi_F1", "chain_F1", "recall", "F1",
        "avg_time_attacks_ms", "avg_time_benigns_ms",
    }
    # char: 5 TP, 0 FN, 0 FP, 10 TN → F1=1.0
    assert abs(metrics["char_F1"] - 1.0) < 1e-6
    # pi: 0 TP, 3 FN, 0 FP, 10 TN → F1=0
    assert abs(metrics["pi_F1"] - 0.0) < 1e-6
    # chain: 4 TP, 0 FN, 0 FP, 10 TN → F1=1.0
    assert abs(metrics["chain_F1"] - 1.0) < 1e-6
    # overall recall: 9/12
    assert abs(metrics["recall"] - 9 / 12) < 1e-6
    # AvgTime attacks = 2 + 3 + 15000 + 14000 = 29005
    assert abs(metrics["avg_time_attacks_ms"] - 29005.0) < 1e-3
    # AvgTime benigns = 2 + 3 + 10000 + 9000 = 19005
    assert abs(metrics["avg_time_benigns_ms"] - 19005.0) < 1e-3
    print("test_summary_metrics_with_real_records OK")


def main():
    test_tool_universe_real_vs_synthetic()
    test_confusion_arithmetic()
    test_hardneg_callout_fires_when_gap_gte_10pp()
    test_hardneg_no_callout_when_balanced()
    test_chain_block_step_grouping()
    test_per_subcategory_sorted_by_count_desc()
    test_render_report_has_all_six_tables()
    test_real_precision_in_overall_table()
    test_active_layers_full_mode_includes_all_four()
    test_active_layers_waf2_skipped_excludes_rag_slots()
    test_active_layers_waf1_skipped_only_rag_on()
    test_compute_avg_time_attacks_only_full_mode()
    test_compute_avg_time_waf1_only_excludes_waf2_latency()
    test_format_summary_tsv_row_eight_fields()
    test_format_summary_tsv_label_sanitization()
    test_write_summary_tsv_file_has_one_line_eight_fields()
    test_append_to_index_accumulates_lines()
    test_summary_metrics_with_real_records()
    print("\nALL TESTS PASSED")


if __name__ == "__main__":
    main()
