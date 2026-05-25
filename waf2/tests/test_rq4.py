"""Tests for RQ4 evaluation scripts (run_rq4.py and report_rq4.py).

Run: PYTHONPATH=waf2/rag/scripts python3 waf2/tests/test_rq4.py

Covers:
  - run_rq4: sample_benign, is_gray_area, build_mcp_envelope,
             envelope_for_record, RAG_CONFIGS
  - report_rq4: compute_metrics, compute_gray_area_metrics,
                render_table_overall, render_table_per_subcategory
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "waf2" / "rag" / "scripts"))

from run_rq4 import (
    RAG_CONFIGS,
    build_mcp_envelope,
    envelope_for_record,
    is_gray_area,
    sample_benign,
)
from report_rq4 import (
    compute_gray_area_metrics,
    compute_metrics,
    render_table_overall,
    render_table_per_subcategory,
)


# =====================================================================
#  sample_benign
# =====================================================================


class TestSampleBenign:
    """Tests for run_rq4.sample_benign."""

    def test_handcrafted_ge_n_returns_n_handcrafted(self):
        """500 handcrafted + 500 template, sample 150 => 150, all handcrafted."""
        handcrafted = [{"source": "handcrafted", "id": i} for i in range(500)]
        template = [{"source": "template", "id": 500 + i} for i in range(500)]
        benigns = handcrafted + template

        result = sample_benign(benigns, n=150, seed=42)

        assert len(result) == 150
        assert all(b["source"] == "handcrafted" for b in result)

    def test_handcrafted_lt_n_fills_with_template(self):
        """100 handcrafted + 500 template, sample 150 => 150 (100+50)."""
        handcrafted = [{"source": "handcrafted", "id": i} for i in range(100)]
        template = [{"source": "template", "id": 100 + i} for i in range(500)]
        benigns = handcrafted + template

        result = sample_benign(benigns, n=150, seed=42)

        assert len(result) == 150
        n_hc = sum(1 for b in result if b["source"] == "handcrafted")
        n_tpl = sum(1 for b in result if b["source"] == "template")
        assert n_hc == 100
        assert n_tpl == 50

    def test_same_seed_reproducible(self):
        handcrafted = [{"source": "handcrafted", "id": i} for i in range(100)]
        template = [{"source": "template", "id": 100 + i} for i in range(500)]
        benigns = handcrafted + template

        r1 = sample_benign(benigns, n=150, seed=99)
        r2 = sample_benign(benigns, n=150, seed=99)

        assert [b["id"] for b in r1] == [b["id"] for b in r2]

    def test_different_seed_different_result(self):
        handcrafted = [{"source": "handcrafted", "id": i} for i in range(100)]
        template = [{"source": "template", "id": 100 + i} for i in range(500)]
        benigns = handcrafted + template

        r1 = sample_benign(benigns, n=150, seed=42)
        r2 = sample_benign(benigns, n=150, seed=99)

        # Template portion should differ (extremely unlikely to be identical)
        ids1 = [b["id"] for b in r1 if b["source"] == "template"]
        ids2 = [b["id"] for b in r2 if b["source"] == "template"]
        assert ids1 != ids2


# =====================================================================
#  is_gray_area
# =====================================================================


class TestIsGrayArea:
    """Tests for run_rq4.is_gray_area."""

    # -- M-Bench attacks --

    def test_mbench_attack_indirect_pi(self):
        rec = {"label": "attack", "subcategory": "indirect_pi"}
        assert is_gray_area(rec, "mbench") is True

    def test_mbench_attack_sql_injection(self):
        rec = {"label": "attack", "subcategory": "sql_injection"}
        assert is_gray_area(rec, "mbench") is False

    # -- M-Bench benigns --

    def test_mbench_benign_handcrafted(self):
        rec = {"label": "benign", "source": "handcrafted"}
        assert is_gray_area(rec, "mbench") is True

    def test_mbench_benign_template(self):
        rec = {"label": "benign", "source": "template"}
        assert is_gray_area(rec, "mbench") is False

    # -- PI-Eval --

    def test_pieval_indirect_prompt_injection(self):
        rec = {"subcategory": "indirect_prompt_injection"}
        assert is_gray_area(rec, "pi-eval") is True

    def test_pieval_context_manipulation(self):
        rec = {"subcategory": "context_manipulation"}
        assert is_gray_area(rec, "pi-eval") is True

    def test_pieval_encoded_injection(self):
        rec = {"subcategory": "encoded_injection"}
        assert is_gray_area(rec, "pi-eval") is True

    def test_pieval_direct_prompt_injection(self):
        rec = {"subcategory": "direct_prompt_injection"}
        assert is_gray_area(rec, "pi-eval") is False

    # -- Adversarial --

    def test_adversarial_pi_indirect_mcp(self):
        rec = {"tag": "pi-indirect-mcp"}
        assert is_gray_area(rec, "adversarial") is True

    def test_adversarial_benign_edu_xss(self):
        rec = {"tag": "benign-edu-xss"}
        assert is_gray_area(rec, "adversarial") is True

    def test_adversarial_sqli_unicode_escape(self):
        rec = {"tag": "sqli-unicode-escape"}
        assert is_gray_area(rec, "adversarial") is False

    # -- Unknown dataset --

    def test_unknown_dataset(self):
        rec = {"subcategory": "indirect_pi"}
        assert is_gray_area(rec, "unknown_ds") is False


# =====================================================================
#  build_mcp_envelope
# =====================================================================


class TestBuildMcpEnvelope:
    """Tests for run_rq4.build_mcp_envelope."""

    def test_valid_jsonrpc_structure(self):
        result = build_mcp_envelope("search_docs", {"query": "test"})
        parsed = json.loads(result)

        assert parsed["jsonrpc"] == "2.0"
        assert parsed["id"] == 1
        assert parsed["method"] == "tools/call"
        assert parsed["params"]["name"] == "search_docs"
        assert parsed["params"]["arguments"] == {"query": "test"}

    def test_empty_args(self):
        result = build_mcp_envelope("some_tool", {})
        parsed = json.loads(result)
        assert parsed["params"]["arguments"] == {}

    def test_none_args_becomes_empty_dict(self):
        result = build_mcp_envelope("some_tool", None)  # type: ignore[arg-type]
        parsed = json.loads(result)
        assert parsed["params"]["arguments"] == {}


# =====================================================================
#  envelope_for_record
# =====================================================================


class TestEnvelopeForRecord:
    """Tests for run_rq4.envelope_for_record."""

    def test_single_step_record(self):
        rec = {"tool": "search", "args": {"q": "hello"}}
        path, body, step = envelope_for_record(rec)

        assert path == "/mcp"
        assert step is None
        parsed = json.loads(body)
        assert parsed["params"]["name"] == "search"
        assert parsed["params"]["arguments"] == {"q": "hello"}

    def test_call_chain_record(self):
        rec = {
            "family": "call_chain",
            "steps": [
                {"tool": "step1", "args": {"a": 1}},
                {"tool": "step2", "args": {"b": 2}},
                {"tool": "step3", "args": {"c": 3}},
            ],
        }
        path, body, step = envelope_for_record(rec)

        assert path == "/mcp"
        assert step == 3
        parsed = json.loads(body)
        # Uses the LAST step
        assert parsed["params"]["name"] == "step3"
        assert parsed["params"]["arguments"] == {"c": 3}

    def test_call_chain_empty_steps_raises(self):
        rec = {"family": "call_chain", "case_id": "test-001", "steps": []}

        with pytest.raises(ValueError, match="empty steps"):
            envelope_for_record(rec)


# =====================================================================
#  RAG_CONFIGS
# =====================================================================


class TestRagConfigs:
    """Tests for run_rq4.RAG_CONFIGS constant."""

    def test_exactly_three_configs(self):
        assert len(RAG_CONFIGS) == 3

    def test_config_slugs(self):
        slugs = [slug for slug, _ in RAG_CONFIGS]
        assert slugs == ["rag-off", "rag-generic", "rag-mcp"]

    def test_rag_off_disables_rag(self):
        slug, payload = RAG_CONFIGS[0]
        assert slug == "rag-off"
        assert payload["rag_enabled"] is False

    def test_rag_generic_domain(self):
        slug, payload = RAG_CONFIGS[1]
        assert slug == "rag-generic"
        assert payload["rag_enabled"] is True
        assert payload["rag_domain"] == "generic"

    def test_rag_mcp_domain(self):
        slug, payload = RAG_CONFIGS[2]
        assert slug == "rag-mcp"
        assert payload["rag_enabled"] is True
        assert payload["rag_domain"] == "mcp"


# =====================================================================
#  compute_metrics
# =====================================================================


class TestComputeMetrics:
    """Tests for report_rq4.compute_metrics."""

    def test_all_attacks_blocked(self):
        records = [
            {"label": "attack", "outcome": "blocked"},
            {"label": "attack", "outcome": "blocked"},
            {"label": "attack", "outcome": "blocked"},
        ]
        m = compute_metrics(records)
        assert m["tp"] == 3
        assert m["fn"] == 0
        assert m["recall"] == 1.0

    def test_all_attacks_passed(self):
        records = [
            {"label": "attack", "outcome": "passed"},
            {"label": "attack", "outcome": "passed"},
        ]
        m = compute_metrics(records)
        assert m["tp"] == 0
        assert m["fn"] == 2
        assert m["recall"] == 0.0

    def test_mixed_outcomes(self):
        """8 blocked attacks + 2 passed attacks + 1 FP benign + 9 TN benign."""
        records = []
        for _ in range(8):
            records.append({"label": "attack", "outcome": "blocked"})
        for _ in range(2):
            records.append({"label": "attack", "outcome": "passed"})
        records.append({"label": "benign", "outcome": "blocked"})  # FP
        for _ in range(9):
            records.append({"label": "benign", "outcome": "passed"})  # TN

        m = compute_metrics(records)
        assert m["tp"] == 8
        assert m["fn"] == 2
        assert m["fp"] == 1
        assert m["tn"] == 9
        assert m["recall"] == pytest.approx(0.8)
        assert m["precision"] == pytest.approx(8 / 9)
        assert m["fpr"] == pytest.approx(1 / 10)

    def test_empty_records(self):
        m = compute_metrics([])
        assert m["tp"] == 0
        assert m["fn"] == 0
        assert m["fp"] == 0
        assert m["tn"] == 0
        assert m["recall"] == 0.0
        assert m["precision"] == 0.0
        assert m["f1"] == 0.0
        assert m["fpr"] == 0.0

    def test_rag_hit_rate(self):
        """3 out of 10 records with rag_used=True => 30.0%."""
        records = []
        for i in range(3):
            records.append({"label": "attack", "outcome": "blocked", "rag_used": True})
        for i in range(7):
            records.append({"label": "attack", "outcome": "blocked", "rag_used": False})

        m = compute_metrics(records)
        assert m["rag_hit_rate"] == pytest.approx(30.0)


# =====================================================================
#  compute_gray_area_metrics
# =====================================================================


class TestComputeGrayAreaMetrics:
    """Tests for report_rq4.compute_gray_area_metrics."""

    def test_gray_area_attacks(self):
        records = [
            {"label": "attack", "outcome": "blocked", "is_gray_area": True},
            {"label": "attack", "outcome": "blocked", "is_gray_area": True},
            {"label": "attack", "outcome": "passed", "is_gray_area": True},
            {"label": "attack", "outcome": "blocked", "is_gray_area": False},  # not gray
        ]
        ga = compute_gray_area_metrics(records, "mbench")

        assert ga["attacks"]["n"] == 3
        assert ga["attacks"]["tp"] == 2
        assert ga["attacks"]["fn"] == 1
        assert ga["attacks"]["recall"] == pytest.approx(2 / 3)
        assert ga["benigns"]["n"] == 0

    def test_gray_area_benigns(self):
        records = [
            {"label": "benign", "outcome": "blocked", "is_gray_area": True},  # FP
            {"label": "benign", "outcome": "passed", "is_gray_area": True},   # TN
            {"label": "benign", "outcome": "passed", "is_gray_area": True},   # TN
        ]
        ga = compute_gray_area_metrics(records, "mbench")

        assert ga["benigns"]["n"] == 3
        assert ga["benigns"]["fp"] == 1
        assert ga["benigns"]["tn"] == 2
        assert ga["benigns"]["fpr"] == pytest.approx(1 / 3)
        assert ga["attacks"]["n"] == 0

    def test_no_gray_area_records(self):
        records = [
            {"label": "attack", "outcome": "blocked", "is_gray_area": False},
            {"label": "benign", "outcome": "passed", "is_gray_area": False},
        ]
        ga = compute_gray_area_metrics(records, "mbench")

        assert ga["attacks"]["n"] == 0
        assert ga["benigns"]["n"] == 0


# =====================================================================
#  render_table_overall
# =====================================================================


class TestRenderTableOverall:
    """Tests for report_rq4.render_table_overall."""

    @staticmethod
    def _make_records(label: str, outcome: str, n: int) -> list[dict]:
        return [{"label": label, "outcome": outcome, "latency_ms": 100}] * n

    def test_contains_mbench_rows(self):
        all_data = {
            "mbench": {
                "rag-off": self._make_records("attack", "blocked", 5),
            },
        }
        table = render_table_overall(all_data)
        assert "| M-Bench |" in table

    def test_contains_pieval_rows(self):
        all_data = {
            "pi-eval": {
                "rag-off": self._make_records("attack", "blocked", 3),
            },
        }
        table = render_table_overall(all_data)
        assert "| PI-Eval |" in table

    def test_pieval_no_benigns_shows_dashes(self):
        """PI-Eval has no benigns so FP/TN/FPR should be '---'."""
        all_data = {
            "pi-eval": {
                "rag-off": self._make_records("attack", "blocked", 3),
            },
        }
        table = render_table_overall(all_data)
        # Find the PI-Eval row
        lines = table.split("\n")
        pieval_lines = [l for l in lines if "| PI-Eval |" in l]
        assert len(pieval_lines) >= 1
        row = pieval_lines[0]
        # FP, TN, FPR columns should be ---
        # Format: | PI-Eval | rag-off | N_atk | N_ben | TP | FN | FP | TN | Recall | Precision | F1 | FPR | ...
        cells = [c.strip() for c in row.split("|")]
        # cells[0] is empty, cells[1]=Dataset, cells[2]=Config, ...
        # FP is cells[7], TN is cells[8], FPR is cells[11]
        assert cells[7] == "---"
        assert cells[8] == "---"
        assert cells[11] == "---"


# =====================================================================
#  render_table_per_subcategory
# =====================================================================


class TestRenderTablePerSubcategory:
    """Tests for report_rq4.render_table_per_subcategory."""

    def test_contains_subcategory_names(self):
        mbench_data = {
            "rag-off": [
                {"subcategory": "sql_injection", "outcome": "blocked"},
                {"subcategory": "sql_injection", "outcome": "blocked"},
                {"subcategory": "xss", "outcome": "passed"},
            ],
        }
        table = render_table_per_subcategory(mbench_data)
        assert "sql_injection" in table
        assert "xss" in table

    def test_empty_data(self):
        table = render_table_per_subcategory({})
        # Should still have header
        assert "Table 3" in table
