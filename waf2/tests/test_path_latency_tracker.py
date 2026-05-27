"""Tests for PathLatencyTracker (improve-waf2-concurrency-for-rq5).

Covers spec scenarios for `/waf2/stats` `per_path_latency` field:
  - 各路径请求按窗口统计
  - 窗口溢出时丢弃最旧样本
  - 重置清空所有路径窗口

Run with:
  PYTHONPATH=waf2 python3 -m pytest waf2/tests/test_path_latency_tracker.py -v
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import waf2_proxy as p  # noqa: E402


def test_snapshot_empty_paths_have_zero_count():
    t = p.PathLatencyTracker(window=128)
    snap = t.snapshot()
    assert set(snap.keys()) == {"stage0", "local_only", "rag", "llm"}
    for path, stats in snap.items():
        assert stats["count"] == 0
        assert stats["p50"] is None
        assert stats["p95"] is None
        assert stats["p99"] is None


def test_records_route_counts():
    t = p.PathLatencyTracker(window=1024)
    for _ in range(100):
        t.record("stage0", 3.5)
    for _ in range(50):
        t.record("local_only", 12.0)
    for _ in range(20):
        t.record("rag", 45.0)
    for _ in range(5):
        t.record("llm", 600.0)

    snap = t.snapshot()
    assert snap["stage0"]["count"] == 100
    assert snap["local_only"]["count"] == 50
    assert snap["rag"]["count"] == 20
    assert snap["llm"]["count"] == 5
    # constant samples → percentiles equal that value
    assert abs(snap["stage0"]["p95"] - 3.5) < 0.01
    assert abs(snap["llm"]["p50"] - 600.0) < 0.01


def test_window_overflow_drops_oldest():
    t = p.PathLatencyTracker(window=100)
    # push 200 increasing values
    for i in range(200):
        t.record("stage0", float(i))
    snap = t.snapshot()
    assert snap["stage0"]["count"] == 100
    # Last 100 samples = 100..199. p50 ≈ 149-150
    assert 140 <= snap["stage0"]["p50"] <= 160
    # p99 reflects high tail near 199
    assert snap["stage0"]["p99"] >= 195


def test_reset_clears_all_paths():
    t = p.PathLatencyTracker(window=64)
    for path in ("stage0", "local_only", "rag", "llm"):
        for _ in range(10):
            t.record(path, 1.0)
    t.reset()
    snap = t.snapshot()
    for path in snap:
        assert snap[path]["count"] == 0


def test_unknown_path_is_ignored():
    t = p.PathLatencyTracker(window=64)
    t.record("nonexistent_path", 9.0)
    t.record("stage0", 1.0)
    snap = t.snapshot()
    assert snap["stage0"]["count"] == 1
    assert "nonexistent_path" not in snap


def test_global_tracker_exposed_via_module():
    """模块级 path_latency_tracker 是 PathLatencyTracker 实例,/waf2/stats 消费它"""
    assert isinstance(p.path_latency_tracker, p.PathLatencyTracker)
    snap = p.path_latency_tracker.snapshot()
    assert set(snap.keys()) == {"stage0", "local_only", "rag", "llm"}


if __name__ == "__main__":
    test_snapshot_empty_paths_have_zero_count()
    test_records_route_counts()
    test_window_overflow_drops_oldest()
    test_reset_clears_all_paths()
    test_unknown_path_is_ignored()
    test_global_tracker_exposed_via_module()
    print("OK - all path latency tracker tests passed")
