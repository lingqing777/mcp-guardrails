"""Tests for the RQ5 perf harness (add-waf2-rq5-perf-eval-harness).

Covers spec scenarios across driver / sampler / report / run_rq5.
Uses httpx.MockTransport to fake the WAF2 service so tests run offline.

Run with:
    PYTHONPATH=. python3 -m pytest waf2/tests/test_rq5_perf_harness.py -v
"""

from __future__ import annotations

import asyncio
import csv
import json
import os
import sys
import time
from pathlib import Path

import httpx
import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO_ROOT))

from waf2.rag.eval.perf import rq5_driver, rq5_report, rq5_sampler  # noqa: E402


# ---------------------------------------------------------------- shared helpers


def _mock_waf2_handler(stats_payload: dict | None = None):
    """Return an httpx.MockTransport handler that fakes WAF2 endpoints.

    - GET  /waf2/stats   → 200 with provided payload (or default minimal one)
    - any other path     → 200 OK (or 403 if body contains 'attack')
    """
    default_stats = stats_payload or {
        "cache_hits": 100,
        "llm_calls": 20,
        "route_static_block": 5,
        "route_fast_pass": 90,
        "route_one_shot": 10,
        "route_react": 5,
        "per_path_latency": {
            "stage0": {"p50": 3.5, "p95": 5.0, "p99": 6.0, "count": 100},
            "local_only": {"p50": 12.0, "p95": 15.0, "p99": 20.0, "count": 50},
            "rag": {"p50": 45.0, "p95": 60.0, "p99": 80.0, "count": 20},
            "llm": {"p50": 600.0, "p95": 900.0, "p99": 1200.0, "count": 5},
        },
    }
    monotonic_stats = {"call": 0}

    def handler(request):
        if request.url.path == "/waf2/stats":
            monotonic_stats["call"] += 1
            payload = dict(default_stats)
            # Make the time-series interesting: cache_hits/llm_calls drift up.
            payload["cache_hits"] = int(default_stats["cache_hits"]) + 10 * monotonic_stats["call"]
            payload["llm_calls"] = int(default_stats["llm_calls"]) + 1 * monotonic_stats["call"]
            return httpx.Response(200, json=payload)
        body = (request.content or b"").decode("utf-8", errors="replace")
        if "attack" in body.lower() or "../" in request.url.path:
            return httpx.Response(403, json={"error": "WAF2 拦截"})
        return httpx.Response(200, json={"ok": True})

    return handler


@pytest.fixture
def mock_waf2(monkeypatch):
    """Force httpx.AsyncClient + httpx.Client to use a shared MockTransport."""
    handler = _mock_waf2_handler()
    transport = httpx.MockTransport(handler)

    real_async_init = httpx.AsyncClient.__init__
    real_sync_init = httpx.Client.__init__

    def patched_async(self, *a, **kw):
        kw["transport"] = transport
        kw.pop("limits", None)
        kw.pop("verify", None)
        real_async_init(self, *a, **kw)

    def patched_sync(self, *a, **kw):
        kw["transport"] = transport
        kw.pop("verify", None)
        real_sync_init(self, *a, **kw)

    monkeypatch.setattr(httpx.AsyncClient, "__init__", patched_async)
    monkeypatch.setattr(httpx.Client, "__init__", patched_sync)
    return handler


# ---------------------------------------------------------------- driver tests


def test_driver_emits_csv_with_correct_columns(tmp_path, mock_waf2):
    """Spec scenario: 阶梯升压并产出可重放的 driver CSV"""
    out_dir = tmp_path / "run1"
    rc = rq5_driver.main([
        "--target-rps", "20",
        "--steady-seconds", "2",
        "--ladder-start", "20",
        "--ladder-step-seconds", "1",
        "--cooldown-seconds", "0",
        "--sample-size", "50",
        "--seed", "1",
        "--out-dir", str(out_dir),
        "--waf2-url", "http://mock.waf2.local",
    ])
    assert rc == 0
    csv_path = out_dir / "driver.csv"
    assert csv_path.exists()
    with csv_path.open() as fh:
        reader = csv.DictReader(fh)
        rows = list(reader)
    assert reader.fieldnames == ["ts_ms", "latency_ms", "status", "success", "phase", "label"]
    assert len(rows) > 0, "expected at least one request row"
    # all rows have known phases
    phases = {r["phase"] for r in rows}
    assert phases.issubset({"warmup", "steady", "cooldown"})

    # run.driver.json populated
    meta = json.loads((out_dir / "run.driver.json").read_text())
    assert meta["target_rps"] == 20.0
    assert meta["steady_start_ms"] >= 0
    assert meta["steady_end_ms"] >= meta["steady_start_ms"]


def test_driver_phase_order(tmp_path, mock_waf2):
    """Spec scenario: warmup 阶段标识正确 (warmup < steady < cooldown)"""
    out_dir = tmp_path / "run2"
    rq5_driver.main([
        "--target-rps", "40", "--steady-seconds", "1",
        "--ladder-start", "10", "--ladder-step-seconds", "1",
        "--cooldown-seconds", "1",
        "--sample-size", "50", "--seed", "1",
        "--out-dir", str(out_dir),
        "--waf2-url", "http://mock.waf2.local",
    ])
    rows = list(csv.DictReader((out_dir / "driver.csv").open()))
    # Sort by ts_ms and check phase transitions only go forward.
    rows.sort(key=lambda r: int(r["ts_ms"]))
    order = {"warmup": 0, "steady": 1, "cooldown": 2}
    last = -1
    for r in rows:
        cur = order[r["phase"]]
        assert cur >= last, f"phase regressed: {rows}"
        last = cur


def test_driver_blocked_response_is_success(tmp_path, mock_waf2):
    """Spec scenario: blocked 响应不算 failure (WAF2 successfully decided BLOCK)"""
    # Force only attack-like payloads so mock returns 403
    payload_file = tmp_path / "attacks.jsonl"
    payload_file.write_text("\n".join(
        json.dumps({"method": "POST", "path": "/tienda1/anadir.jsp", "body": "attack=1' OR 1=1", "label": "attack"})
        for _ in range(10)
    ), encoding="utf-8")
    out_dir = tmp_path / "run3"
    rq5_driver.main([
        "--target-rps", "10", "--steady-seconds", "1",
        "--ladder-start", "10", "--ladder-step-seconds", "0",
        "--cooldown-seconds", "0",
        "--payload-file", str(payload_file),
        "--out-dir", str(out_dir),
        "--waf2-url", "http://mock.waf2.local",
    ])
    rows = list(csv.DictReader((out_dir / "driver.csv").open()))
    assert rows, "expected requests to be sent"
    blocked = [r for r in rows if r["status"] == "403"]
    assert blocked, "mock should have returned 403 for attack payloads"
    # all 403 rows should still be marked success=true
    assert all(r["success"] == "true" for r in blocked)


# ---------------------------------------------------------------- sampler tests


def test_sampler_psutil_pid_mode(tmp_path, mock_waf2):
    """Spec scenario: 用 psutil 模式采集到完整时间序列"""
    pytest.importorskip("psutil")
    out_dir = tmp_path / "sampler1"
    pid = os.getpid()  # sample THIS test process so the path is exercised
    rc = rq5_sampler.main([
        "--mode", "psutil-pid",
        "--pid", str(pid),
        "--interval", "0.5",
        "--duration-seconds", "2.0",
        "--out-dir", str(out_dir),
        "--waf2-url", "http://mock.waf2.local",
    ])
    assert rc == 0
    rows = list(csv.DictReader((out_dir / "sampler.csv").open()))
    assert len(rows) >= 3, f"expected ≥3 samples in 2s, got {len(rows)}"
    assert set(rows[0].keys()) == {
        "ts_ms", "mode", "cpu_pct", "rss_mb",
        "cache_hits", "llm_calls",
        "route_static_block", "route_fast_pass", "route_one_shot", "route_react",
        "per_path_latency_json",
    }
    # mode field consistent
    assert all(r["mode"] == "psutil-pid" for r in rows)
    # Each row's per_path_latency_json is valid JSON with the four buckets
    for r in rows:
        if r["per_path_latency_json"]:
            ppl = json.loads(r["per_path_latency_json"])
            assert set(ppl.keys()) == {"stage0", "local_only", "rag", "llm"}


def test_sampler_writes_stats_final_json(tmp_path, mock_waf2):
    """Spec scenario: 收尾时写入 stats_final.json"""
    pytest.importorskip("psutil")
    out_dir = tmp_path / "sampler2"
    rq5_sampler.main([
        "--mode", "psutil-pid", "--pid", str(os.getpid()),
        "--interval", "0.5", "--duration-seconds", "1.5",
        "--out-dir", str(out_dir),
        "--waf2-url", "http://mock.waf2.local",
    ])
    stats_final = json.loads((out_dir / "stats_final.json").read_text())
    assert "per_path_latency" in stats_final
    assert set(stats_final["per_path_latency"].keys()) == {"stage0", "local_only", "rag", "llm"}


def test_sampler_docker_stats_forces_min_interval(tmp_path, mock_waf2, capfd):
    """Spec scenario: docker stats fallback 强制最小 2s 间隔"""
    out_dir = tmp_path / "sampler3"
    # `docker` binary likely absent in CI — but we only care that the warning fires
    # before the (likely-failing) docker-stats call happens.
    try:
        rq5_sampler.main([
            "--mode", "docker-stats",
            "--interval", "0.5",
            "--duration-seconds", "2.5",
            "--out-dir", str(out_dir),
            "--waf2-url", "http://mock.waf2.local",
            "--container-name", "definitely-not-running",
        ])
    except SystemExit:
        pass
    # Warning should appear on stderr
    captured = capfd.readouterr()
    assert "docker-stats mode forces interval" in captured.err
    # And run.sampler.json should record interval == 2.0
    meta = json.loads((out_dir / "run.sampler.json").read_text())
    assert meta["interval_s"] == 2.0
    assert meta["mode"] == "docker-stats"


# ---------------------------------------------------------------- report tests


def _build_report_fixtures(run_dir: Path, *, target_rps: float = 10.0, steady_s: float = 5.0,
                          want_steady_met: bool = True):
    """Create plausible driver/sampler/stats_final fixtures for report.py tests."""
    run_dir.mkdir(parents=True, exist_ok=True)
    steady_start_ms = 1000
    steady_end_ms = steady_start_ms + int(steady_s * 1000)

    # driver.csv — emit `target_rps * steady_s` rows in steady, plus a few warmup rows
    n_steady = int(target_rps * steady_s)
    if not want_steady_met:
        n_steady = int(n_steady * 0.5)  # half the expected RPS → steady NOT met
    rows = []
    # warmup rows
    for i in range(5):
        rows.append({
            "ts_ms": 200 + i * 100, "latency_ms": 10.0 + i,
            "status": 200, "success": "true", "phase": "warmup", "label": "normal",
        })
    # steady rows uniformly spaced
    interval_ms = int(steady_s * 1000 / max(n_steady, 1))
    for i in range(n_steady):
        rows.append({
            "ts_ms": steady_start_ms + i * interval_ms,
            "latency_ms": 5.0 + (i % 7),  # tight P95
            "status": 200, "success": "true", "phase": "steady", "label": "normal",
        })
    with (run_dir / "driver.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["ts_ms", "latency_ms", "status", "success", "phase", "label"])
        w.writeheader()
        w.writerows(rows)

    # sampler.csv — 6 rows across steady window
    sampler_rows = []
    for i in range(6):
        ts = steady_start_ms + i * int((steady_end_ms - steady_start_ms) / 5)
        sampler_rows.append({
            "ts_ms": ts, "mode": "psutil-pid",
            "cpu_pct": f"{30 + i:.3f}", "rss_mb": f"{120 + i * 0.5:.3f}",
            "cache_hits": 100 + i * 20,
            "llm_calls": 10 + i,
            "route_static_block": 5, "route_fast_pass": 200,
            "route_one_shot": 10, "route_react": 3,
            "per_path_latency_json": json.dumps({
                "stage0": {"p50": 3.0, "p95": 5.0, "p99": 6.0, "count": 100 + i},
                "local_only": {"p50": 10.0, "p95": 14.0, "p99": 18.0, "count": 30 + i},
                "rag": {"p50": 40.0, "p95": 55.0, "p99": 70.0, "count": 5 + i},
                "llm": {"p50": 500.0, "p95": 800.0, "p99": 1100.0, "count": 1 + i},
            }),
        })
    with (run_dir / "sampler.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(sampler_rows[0].keys()))
        w.writeheader()
        w.writerows(sampler_rows)

    # stats_final.json
    (run_dir / "stats_final.json").write_text(json.dumps({
        "cache_hits": 220, "llm_calls": 15,
        "route_static_block": 10, "route_fast_pass": 300, "route_one_shot": 12,
        "route_react": 5, "route_knowledge_evidence": 4,
        "route_local_llm_one_shot": 8, "route_react_deep_inspection": 5,
        "route_fallback": 1,
        "per_path_latency": {
            "stage0": {"p50": 3.0, "p95": 5.0, "p99": 6.0, "count": 300},
            "local_only": {"p50": 10.0, "p95": 14.0, "p99": 18.0, "count": 50},
            "rag": {"p50": 40.0, "p95": 55.0, "p99": 70.0, "count": 10},
            "llm": {"p50": 500.0, "p95": 800.0, "p99": 1100.0, "count": 3},
        },
    }), encoding="utf-8")

    # run.driver.json — steady window + target rps
    (run_dir / "run.driver.json").write_text(json.dumps({
        "target_rps": target_rps,
        "steady_start_ms": steady_start_ms,
        "steady_end_ms": steady_end_ms,
        "mode": "psutil-pid",
    }), encoding="utf-8")


def test_report_table_5_8_contains_all_paper_metric_names(tmp_path):
    """Spec scenario: 表 5.8 列名与论文一致"""
    run_dir = tmp_path / "report1"
    _build_report_fixtures(run_dir, target_rps=10.0, steady_s=5.0, want_steady_met=True)
    rq5_report.generate_report(run_dir, skip_plot=True)
    md = (run_dir / "report.md").read_text(encoding="utf-8")
    assert "表 5.8 WAF2 大规模数据面性能指标" in md
    for needed in (
        "稳态平均 QPS", "Avg 延迟 (ms)", "P50 延迟 (ms)", "P95 延迟 (ms)",
        "P99 延迟 (ms)", "CPU 占用 (%)", "内存占用 (MB)", "缓存命中率 (%)",
    ):
        assert needed in md, f"metric label missing: {needed}"


def test_report_cache_hit_rate_formula(tmp_path):
    """Spec scenario: 缓存命中率用稳态差值计算"""
    run_dir = tmp_path / "report2"
    _build_report_fixtures(run_dir, target_rps=10.0, steady_s=5.0)
    rq5_report.generate_report(run_dir, skip_plot=True)
    metrics = json.loads((run_dir / "run.report.json").read_text())["metrics"]
    # Fixture: cache_hits 100 → 200 (Δ=100), llm_calls 10 → 15 (Δ=5)
    # rate = 100 / (100+5) * 100 ≈ 95.24
    hit_rate = float(metrics["缓存命中率 (%)"])
    assert abs(hit_rate - 95.24) < 0.5


def test_report_marks_unsteady_with_warning(tmp_path):
    """Spec scenario: 稳态未达成时顶部标注"""
    run_dir = tmp_path / "report3"
    _build_report_fixtures(run_dir, target_rps=10.0, steady_s=5.0, want_steady_met=False)
    rq5_report.generate_report(run_dir, skip_plot=True)
    md = (run_dir / "report.md").read_text(encoding="utf-8")
    assert "⚠️ 稳态未达成" in md
    # Even when not met, table 5.8 still present
    assert "表 5.8" in md


def test_report_per_path_table_lists_all_four_paths(tmp_path):
    """Spec scenario: 分路径分桶附表覆盖四桶"""
    run_dir = tmp_path / "report4"
    _build_report_fixtures(run_dir, target_rps=10.0, steady_s=5.0)
    rq5_report.generate_report(run_dir, skip_plot=True)
    md = (run_dir / "report.md").read_text(encoding="utf-8")
    for p in ("stage0", "local_only", "rag", "llm"):
        assert f"| {p} |" in md, f"per-path row missing: {p}"


def test_report_with_empty_path_still_lists_row(tmp_path):
    """Per-path table must list all four paths even if some have zero count."""
    run_dir = tmp_path / "report5"
    _build_report_fixtures(run_dir, target_rps=10.0, steady_s=5.0)
    # Wipe llm bucket samples
    sf_path = run_dir / "stats_final.json"
    sf = json.loads(sf_path.read_text())
    sf["per_path_latency"]["llm"] = {"p50": None, "p95": None, "p99": None, "count": 0}
    sf_path.write_text(json.dumps(sf), encoding="utf-8")
    rq5_report.generate_report(run_dir, skip_plot=True)
    md = (run_dir / "report.md").read_text(encoding="utf-8")
    # llm row exists with count = 0 and dashes for percentiles
    assert "| llm | 0 | — | — | — |" in md


# ---------------------------------------------------------------- run_rq5 smoke


def test_run_rq5_orchestrator_produces_all_artifacts(tmp_path, mock_waf2, monkeypatch):
    """Spec scenario: 完整 run 产出 6 个标准产物 (5 mandatory + optional png)"""
    from waf2.rag.eval.perf import run_rq5

    # Force --pid to a known PID so sampler can attach (sampling self)
    monkeypatch.setenv("PYTHONPATH", str(_REPO_ROOT))
    out_dir = tmp_path / "smoke_run"
    rc = run_rq5.main([
        "--target-rps", "10", "--steady-seconds", "2",
        "--ladder-start", "10", "--ladder-step-seconds", "0",
        "--cooldown-seconds", "0",
        "--sample-size", "20", "--seed", "1",
        "--waf2-url", "http://mock.waf2.local",
        "--sampler-mode", "psutil-pid",
        "--waf2-pid", str(os.getpid()),
        "--sampler-interval", "0.5",
        "--sampler-extra-seconds", "1.0",
        "--skip-plot",
        "--out-dir", str(out_dir),
    ])
    # Note: subprocess'd driver/sampler won't have our monkeypatched httpx —
    # they will fail to connect to http://mock.waf2.local. That's fine, the
    # orchestrator should still produce all 5 mandatory artifacts (with some
    # rows being failures / no stats). What we assert:
    #   - The orchestrator returns 0 (report.md generated even with failures)
    #   - All five files exist
    assert rc == 0, "orchestrator should complete even when subprocess driver has errors"
    for required in ("driver.csv", "sampler.csv", "stats_final.json", "report.md", "run.json"):
        assert (out_dir / required).exists(), f"missing artifact: {required}"


def test_run_json_has_env_metadata(tmp_path, mock_waf2):
    """Spec scenario: run.json 含完整环境元数据"""
    from waf2.rag.eval.perf import run_rq5

    out_dir = tmp_path / "meta_run"
    run_rq5.main([
        "--target-rps", "5", "--steady-seconds", "1",
        "--ladder-start", "5", "--ladder-step-seconds", "0",
        "--cooldown-seconds", "0",
        "--sample-size", "10", "--seed", "1",
        "--waf2-url", "http://mock.waf2.local",
        "--sampler-mode", "psutil-pid",
        "--waf2-pid", str(os.getpid()),
        "--sampler-interval", "0.5",
        "--sampler-extra-seconds", "1.0",
        "--skip-plot",
        "--out-dir", str(out_dir),
    ])
    run_meta = json.loads((out_dir / "run.json").read_text())
    for k in ("timestamp", "hostname", "cpu_count"):
        assert k in run_meta and run_meta[k] is not None
    assert isinstance(run_meta["cpu_count"], int) and run_meta["cpu_count"] > 0
    # commit_hash may be None outside a git repo, but should be the right shape if present
    if run_meta.get("commit_hash"):
        assert len(run_meta["commit_hash"]) == 7
    assert run_meta["target_rps"] == 5.0


# ---------------------------------------------------------------- generic guards


def test_perf_module_has_no_production_diff():
    """Spec scenario: 生产代码零触碰 (sanity — perf files exist, prod files not modified)"""
    perf_dir = _REPO_ROOT / "waf2" / "rag" / "eval" / "perf"
    for name in ("__init__.py", "rq5_driver.py", "rq5_sampler.py", "rq5_report.py", "run_rq5.py",
                "requirements.txt"):
        assert (perf_dir / name).exists(), f"perf module missing: {name}"
    # The waf2 Dockerfile and requirements.txt must NOT have grown psutil/matplotlib
    docker_reqs = (_REPO_ROOT / "waf2" / "requirements.txt").read_text(encoding="utf-8")
    assert "psutil" not in docker_reqs.lower(), "psutil leaked into WAF2 docker image"
    assert "matplotlib" not in docker_reqs.lower(), "matplotlib leaked into WAF2 docker image"
