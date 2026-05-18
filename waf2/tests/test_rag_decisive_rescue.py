"""Tests for ReAct fallback RAG-decisive rescue (harden-waf2-react-fallback-rag-rescue).

Covers `_rescue_category` (dual-source selection D2) and `_rag_decisive_rescue`
(full predicate chain) in waf2/waf2_proxy.py.

Run with:
  PYTHONPATH=waf2 python3 waf2/tests/test_rag_decisive_rescue.py
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import waf2_proxy as p  # noqa: E402


def _restore_config():
    """Reset config to defaults between tests (in case a prior test toggled)."""
    p.config.rag_decisive_fallback_enabled = True
    p.config.rag_decisive_fallback_min_score = 0.55
    p.config.rag_decisive_fallback_categories = {"prompt_injection"}
    p.config.local_score_gray_threshold = 0.35


# ==================== _rescue_category (dual-source D2) ====================


def test_rescue_category_uses_rag_when_in_whitelist():
    _restore_config()
    rag_meta = {"rag_top_category": "prompt_injection"}
    local_meta = {"top_category": "unknown", "top_score": 0.0}
    cat, source = p._rescue_category(rag_meta, local_meta, 0.35)
    assert cat == "prompt_injection"
    assert source == "rag_cat"


def test_rescue_category_falls_back_to_local_when_rag_wrong():
    _restore_config()
    rag_meta = {"rag_top_category": "sql_injection"}  # not in whitelist
    local_meta = {"top_category": "prompt_injection", "top_score": 0.55}
    cat, source = p._rescue_category(rag_meta, local_meta, 0.35)
    assert cat == "prompt_injection"
    assert source == "local_cat"


def test_rescue_category_rejects_when_local_score_below_gray():
    _restore_config()
    rag_meta = {"rag_top_category": "sql_injection"}
    local_meta = {"top_category": "prompt_injection", "top_score": 0.20}  # < 0.35
    cat, source = p._rescue_category(rag_meta, local_meta, 0.35)
    assert cat is None
    assert source is None


def test_rescue_category_rejects_when_both_sources_not_in_whitelist():
    _restore_config()
    rag_meta = {"rag_top_category": "sql_injection"}
    local_meta = {"top_category": "command_injection", "top_score": 0.80}
    cat, source = p._rescue_category(rag_meta, local_meta, 0.35)
    assert cat is None


def test_rescue_category_handles_missing_metadata():
    _restore_config()
    assert p._rescue_category(None, None, 0.35) == (None, None)
    assert p._rescue_category({}, {}, 0.35) == (None, None)


def test_rescue_category_case_insensitive_lookup():
    _restore_config()
    rag_meta = {"rag_top_category": "PROMPT_Injection"}  # mixed case
    cat, source = p._rescue_category(rag_meta, {}, 0.35)
    assert cat == "prompt_injection"
    assert source == "rag_cat"


# ==================== _rag_decisive_rescue (full predicate chain) ====================


def test_rescue_triggers_via_rag_cat():
    _restore_config()
    r = p._rag_decisive_rescue(
        rag_meta={"rag_top_category": "prompt_injection"},
        local_meta={"top_category": "unknown", "top_score": 0.0},
        direction="request",
        top_score=0.60,
        rag_used=True,
    )
    assert r is not None
    assert r["blocked"] is True
    assert r["category"] == "prompt_injection"
    assert r["route"] == "react_fallback_rag_rescue"
    assert r["engine"] == "rag_decisive_fallback"
    assert r["rescued_via"] == "rag_cat"
    assert "rag_decisive_fallback" in r["route_reasons"]
    assert "rag_cat" in r["route_reasons"]
    assert r["direction"] == "request"


def test_rescue_triggers_via_local_cat_for_b0_83_85_style_case():
    """B-0 case 83/85: rag_cat=sql_injection (KB mis-match) but local
    correctly identifies prompt_injection. Dual-source D2 should rescue.
    """
    _restore_config()
    r = p._rag_decisive_rescue(
        rag_meta={"rag_top_category": "sql_injection"},
        local_meta={"top_category": "prompt_injection", "top_score": 0.55},
        direction="request",
        top_score=0.58,
        rag_used=True,
    )
    assert r is not None
    assert r["category"] == "prompt_injection"  # came from local, not rag
    assert r["rescued_via"] == "local_cat"
    assert "local_cat" in r["route_reasons"]


def test_rescue_skipped_when_rag_score_below_min():
    _restore_config()
    r = p._rag_decisive_rescue(
        rag_meta={"rag_top_category": "prompt_injection"},
        local_meta={"top_category": "prompt_injection", "top_score": 0.50},
        direction="request",
        top_score=0.40,  # < 0.55
        rag_used=True,
    )
    assert r is None


def test_rescue_skipped_when_rag_used_is_false():
    _restore_config()
    r = p._rag_decisive_rescue(
        rag_meta={"rag_top_category": "prompt_injection"},
        local_meta={"top_category": "prompt_injection", "top_score": 0.50},
        direction="request",
        top_score=0.80,
        rag_used=False,
    )
    assert r is None


def test_rescue_skipped_when_disabled():
    _restore_config()
    p.config.rag_decisive_fallback_enabled = False
    try:
        r = p._rag_decisive_rescue(
            rag_meta={"rag_top_category": "prompt_injection"},
            local_meta={"top_category": "prompt_injection", "top_score": 0.55},
            direction="request",
            top_score=0.80,
            rag_used=True,
        )
        assert r is None
    finally:
        _restore_config()


def test_rescue_skipped_when_dual_source_resolves_nothing():
    _restore_config()
    # both rag and local are in non-whitelisted categories
    r = p._rag_decisive_rescue(
        rag_meta={"rag_top_category": "command_injection"},
        local_meta={"top_category": "sql_injection", "top_score": 0.80},
        direction="request",
        top_score=0.70,
        rag_used=True,
    )
    assert r is None


def test_rescue_response_direction_works_without_local_meta():
    """Response path passes local_meta=None (no local_attack_score available)."""
    _restore_config()
    r = p._rag_decisive_rescue(
        rag_meta={"rag_top_category": "prompt_injection"},
        local_meta=None,
        direction="response",
        top_score=0.70,
        rag_used=True,
    )
    assert r is not None
    assert r["direction"] == "response"
    assert r["rescued_via"] == "rag_cat"


def test_rescue_tolerates_non_numeric_top_score():
    _restore_config()
    # invalid top_score should not crash; behave as 0.0
    r = p._rag_decisive_rescue(
        rag_meta={"rag_top_category": "prompt_injection"},
        local_meta={},
        direction="request",
        top_score="not-a-number",  # type: ignore[arg-type]
        rag_used=True,
    )
    assert r is None  # 0.0 < 0.55


def test_rescue_at_exact_threshold():
    _restore_config()
    r = p._rag_decisive_rescue(
        rag_meta={"rag_top_category": "prompt_injection"},
        local_meta={},
        direction="request",
        top_score=0.55,  # exactly the threshold
        rag_used=True,
    )
    assert r is not None  # >= is inclusive


def test_rescue_reason_contains_score_and_source():
    _restore_config()
    r = p._rag_decisive_rescue(
        rag_meta={"rag_top_category": "prompt_injection"},
        local_meta={},
        direction="request",
        top_score=0.7234,
        rag_used=True,
    )
    assert r is not None
    # reason mentions rounded score and source
    assert "0.723" in r["reason"]
    assert "via=rag_cat" in r["reason"]


if __name__ == "__main__":
    tests = [
        test_rescue_category_uses_rag_when_in_whitelist,
        test_rescue_category_falls_back_to_local_when_rag_wrong,
        test_rescue_category_rejects_when_local_score_below_gray,
        test_rescue_category_rejects_when_both_sources_not_in_whitelist,
        test_rescue_category_handles_missing_metadata,
        test_rescue_category_case_insensitive_lookup,
        test_rescue_triggers_via_rag_cat,
        test_rescue_triggers_via_local_cat_for_b0_83_85_style_case,
        test_rescue_skipped_when_rag_score_below_min,
        test_rescue_skipped_when_rag_used_is_false,
        test_rescue_skipped_when_disabled,
        test_rescue_skipped_when_dual_source_resolves_nothing,
        test_rescue_response_direction_works_without_local_meta,
        test_rescue_tolerates_non_numeric_top_score,
        test_rescue_at_exact_threshold,
        test_rescue_reason_contains_score_and_source,
    ]
    for test in tests:
        test()
    print(f"rag-decisive-rescue tests passed ({len(tests)} cases)")
