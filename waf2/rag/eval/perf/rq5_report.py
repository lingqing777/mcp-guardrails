"""RQ5 report generator — merges driver+sampler+stats_final into table 5.8.

Inputs (all under --run-dir):
  - driver.csv               per-request latency (cols: ts_ms, latency_ms, status, success, phase, label)
  - sampler.csv              CPU/RSS/stats time series
  - stats_final.json         last /waf2/stats snapshot
  - run.driver.json          driver phase metadata (steady_start_ms / steady_end_ms)
  - run.sampler.json         sampler metadata

Outputs (written into --run-dir):
  - report.md                table 5.8 + routing breakdown + per-path breakdown
  - timeseries.png           optional QPS/P95/CPU triple plot (skipped if no matplotlib)
  - run.report.json          steady-criterion verdict + computed metrics
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

try:
    import matplotlib  # type: ignore
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt  # type: ignore
    _HAS_MPL = True
except Exception:  # pragma: no cover - optional dep
    _HAS_MPL = False


_TABLE_5_8_ROWS = [
    "稳态平均 QPS",
    "Avg 延迟 (ms)",
    "P50 延迟 (ms)",
    "P95 延迟 (ms)",
    "P99 延迟 (ms)",
    "CPU 占用 (%)",
    "内存占用 (MB)",
    "缓存命中率 (%)",
]


# ----------------------------------------------------------------- statistics


def _percentile(arr: np.ndarray, p: float) -> float:
    if arr.size == 0:
        return float("nan")
    return float(np.percentile(arr, p))


def _safe_mean(series: pd.Series) -> float:
    arr = pd.to_numeric(series, errors="coerce").dropna().to_numpy()
    if arr.size == 0:
        return float("nan")
    return float(arr.mean())


def _fmt(x: float, ndigits: int = 2) -> str:
    if x is None or (isinstance(x, float) and (math.isnan(x) or math.isinf(x))):
        return "—"
    return f"{x:.{ndigits}f}"


def _steady_slice(df: pd.DataFrame, start_ms: int, end_ms: int) -> pd.DataFrame:
    if start_ms < 0 or end_ms < 0 or end_ms <= start_ms:
        return df.iloc[0:0]
    return df[(df["ts_ms"] >= start_ms) & (df["ts_ms"] <= end_ms)].copy()


def _check_steady(
    driver_steady: pd.DataFrame,
    target_rps: float,
    steady_start_ms: int,
    steady_end_ms: int,
) -> tuple[bool, float, float]:
    """Return (steady_met, actual_steady_rps, p95_jitter_pct)."""
    if driver_steady.empty or steady_end_ms <= steady_start_ms:
        return False, float("nan"), float("nan")
    duration_s = (steady_end_ms - steady_start_ms) / 1000.0
    n_success = int((driver_steady["success"].astype(str).str.lower() == "true").sum())
    actual_rps = n_success / duration_s if duration_s > 0 else float("nan")
    rps_diff = abs(actual_rps - target_rps) / target_rps if target_rps > 0 else float("inf")

    # 30s rolling P95 jitter (max - min) / median
    df = driver_steady.copy()
    df["sec"] = (df["ts_ms"] // 1000).astype(int)
    if df["sec"].nunique() < 5:
        p95_jitter = float("nan")
    else:
        rolling_p95: list[float] = []
        secs = sorted(df["sec"].unique())
        window_s = 30
        for s in secs:
            slab = df[(df["sec"] >= s) & (df["sec"] < s + window_s)]
            if len(slab) < 10:
                continue
            rolling_p95.append(_percentile(slab["latency_ms"].to_numpy(), 95))
        if len(rolling_p95) < 2:
            p95_jitter = float("nan")
        else:
            arr = np.asarray(rolling_p95)
            median = float(np.median(arr))
            p95_jitter = float((arr.max() - arr.min()) / median) if median > 0 else float("nan")
    p95_jitter_pct = p95_jitter * 100 if not math.isnan(p95_jitter) else float("nan")

    steady_met = (rps_diff <= 0.05) and (
        math.isnan(p95_jitter_pct) or p95_jitter_pct <= 10.0
    )
    return steady_met, actual_rps, p95_jitter_pct


def _cache_hit_rate(sampler_steady: pd.DataFrame) -> float:
    """(Δcache_hits) / max(Δcache_hits + Δllm_calls, 1) * 100 across steady window."""
    if sampler_steady.empty:
        return float("nan")
    s = sampler_steady.copy()
    for col in ("cache_hits", "llm_calls"):
        s[col] = pd.to_numeric(s[col], errors="coerce")
    first = s.dropna(subset=["cache_hits", "llm_calls"]).head(1)
    last = s.dropna(subset=["cache_hits", "llm_calls"]).tail(1)
    if first.empty or last.empty:
        return float("nan")
    d_hits = float(last["cache_hits"].iloc[0] - first["cache_hits"].iloc[0])
    d_calls = float(last["llm_calls"].iloc[0] - first["llm_calls"].iloc[0])
    denom = max(d_hits + d_calls, 1.0)
    return (d_hits / denom) * 100.0


# --------------------------------------------------------------- report build


def _build_table_5_8(values: dict[str, str]) -> str:
    rows = ["| 指标 | 数值 |", "| --- | --- |"]
    for name in _TABLE_5_8_ROWS:
        rows.append(f"| {name} | {values.get(name, '—')} |")
    return "\n".join(rows)


def _build_routing_table(stats_final: dict[str, Any]) -> str:
    routes = [
        ("static_block", "route_static_block"),
        ("fast_pass", "route_fast_pass"),
        ("knowledge_evidence", "route_knowledge_evidence"),
        ("local_llm_one_shot", "route_local_llm_one_shot"),
        ("react_deep_inspection", "route_react_deep_inspection"),
        ("fallback", "route_fallback"),
    ]
    total = sum(int(stats_final.get(k, 0) or 0) for _, k in routes)
    rows = ["| 路由 | 计数 | 占比 |", "| --- | ---: | ---: |"]
    for label, key in routes:
        v = int(stats_final.get(key, 0) or 0)
        pct = (v / total * 100) if total > 0 else 0.0
        rows.append(f"| {label} | {v} | {pct:.1f}% |")
    rows.append(f"| **合计** | **{total}** | **100.0%** |")
    return "\n".join(rows)


def _build_per_path_table(stats_final: dict[str, Any]) -> str:
    per_path = stats_final.get("per_path_latency") or {}
    rows = ["| 路径 | count | P50 (ms) | P95 (ms) | P99 (ms) |",
            "| --- | ---: | ---: | ---: | ---: |"]
    for p in ("stage0", "local_only", "rag", "llm"):
        entry = per_path.get(p) or {}
        count = entry.get("count", 0)
        p50 = entry.get("p50")
        p95 = entry.get("p95")
        p99 = entry.get("p99")
        def f(v):
            return "—" if v is None else f"{v:.3f}"
        rows.append(f"| {p} | {count} | {f(p50)} | {f(p95)} | {f(p99)} |")
    return "\n".join(rows)


def _maybe_plot(run_dir: Path, driver_steady: pd.DataFrame, sampler_steady: pd.DataFrame) -> Path | None:
    if not _HAS_MPL or driver_steady.empty:
        return None
    try:
        fig, axes = plt.subplots(3, 1, figsize=(10, 8), sharex=True)
        # QPS — per-second request count
        d = driver_steady.copy()
        d["sec"] = (d["ts_ms"] // 1000).astype(int)
        qps = d.groupby("sec").size()
        axes[0].plot(qps.index, qps.values, label="QPS", color="#3b82f6")
        axes[0].set_ylabel("QPS")
        axes[0].grid(True, alpha=0.3)
        # P95 latency rolling
        rolling_p95 = (
            d.groupby("sec")["latency_ms"]
             .apply(lambda x: float(np.percentile(x.to_numpy(), 95)) if len(x) else float("nan"))
        )
        axes[1].plot(rolling_p95.index, rolling_p95.values, label="P95 latency", color="#ef4444")
        axes[1].set_ylabel("P95 latency (ms)")
        axes[1].grid(True, alpha=0.3)
        # CPU
        if not sampler_steady.empty:
            s = sampler_steady.copy()
            s["sec"] = (s["ts_ms"] // 1000).astype(int)
            cpu = pd.to_numeric(s.set_index("sec")["cpu_pct"], errors="coerce")
            axes[2].plot(cpu.index, cpu.values, label="CPU%", color="#10b981")
        axes[2].set_ylabel("CPU (%)")
        axes[2].set_xlabel("Steady window seconds")
        axes[2].grid(True, alpha=0.3)
        out = run_dir / "timeseries.png"
        fig.tight_layout()
        fig.savefig(out, dpi=120)
        plt.close(fig)
        return out
    except Exception as exc:  # pragma: no cover - best effort
        print(f"[rq5_report] warn: timeseries.png skipped ({exc})", file=sys.stderr)
        return None


def _read_run_metadata(run_dir: Path) -> dict[str, Any]:
    meta: dict[str, Any] = {}
    # Combine all run.*.json files we find
    for stem in ("run.driver", "run.sampler", "run"):
        p = run_dir / f"{stem}.json"
        if p.exists():
            try:
                meta.update(json.loads(p.read_text(encoding="utf-8")))
            except json.JSONDecodeError:
                pass
    return meta


def _resolve_steady_window(meta: dict[str, Any]) -> tuple[int, int]:
    return (
        int(meta.get("steady_start_ms", -1)),
        int(meta.get("steady_end_ms", -1)),
    )


def generate_report(run_dir: Path, target_rps: float | None = None, skip_plot: bool = False) -> Path:
    driver_csv = run_dir / "driver.csv"
    sampler_csv = run_dir / "sampler.csv"
    stats_final_path = run_dir / "stats_final.json"
    if not driver_csv.exists():
        raise FileNotFoundError(f"missing {driver_csv}")
    if not sampler_csv.exists():
        raise FileNotFoundError(f"missing {sampler_csv}")
    if not stats_final_path.exists():
        raise FileNotFoundError(f"missing {stats_final_path}")

    meta = _read_run_metadata(run_dir)
    if target_rps is None:
        target_rps = float(meta.get("target_rps", 0.0))

    driver_df = pd.read_csv(driver_csv)
    sampler_df = pd.read_csv(sampler_csv)
    stats_final = json.loads(stats_final_path.read_text(encoding="utf-8"))

    steady_start_ms, steady_end_ms = _resolve_steady_window(meta)
    driver_steady = _steady_slice(driver_df, steady_start_ms, steady_end_ms)
    sampler_steady = _steady_slice(sampler_df, steady_start_ms, steady_end_ms)
    # Drop sampler prime row (psutil-pid mode emits 0% on first call).
    mode = meta.get("mode", "")
    if mode.startswith("psutil") and not sampler_steady.empty:
        sampler_steady = sampler_steady.iloc[1:] if len(sampler_steady) > 1 else sampler_steady

    success_mask = driver_steady["success"].astype(str).str.lower() == "true"
    lat = pd.to_numeric(driver_steady.loc[success_mask, "latency_ms"], errors="coerce").dropna().to_numpy()
    duration_s = max((steady_end_ms - steady_start_ms) / 1000.0, 0.0)
    qps = (len(lat) / duration_s) if duration_s > 0 else float("nan")
    avg = float(lat.mean()) if lat.size else float("nan")
    p50 = _percentile(lat, 50)
    p95 = _percentile(lat, 95)
    p99 = _percentile(lat, 99)
    cpu = _safe_mean(sampler_steady["cpu_pct"])
    rss = _safe_mean(sampler_steady["rss_mb"])
    hit_rate = _cache_hit_rate(sampler_steady)

    steady_met, actual_steady_rps, p95_jitter_pct = _check_steady(
        driver_steady, target_rps, steady_start_ms, steady_end_ms,
    )

    values = {
        "稳态平均 QPS": _fmt(qps, 2),
        "Avg 延迟 (ms)": _fmt(avg, 2),
        "P50 延迟 (ms)": _fmt(p50, 2),
        "P95 延迟 (ms)": _fmt(p95, 2),
        "P99 延迟 (ms)": _fmt(p99, 2),
        "CPU 占用 (%)": _fmt(cpu, 2),
        "内存占用 (MB)": _fmt(rss, 2),
        "缓存命中率 (%)": _fmt(hit_rate, 2),
    }

    sections: list[str] = []
    sections.append("# WAF2 RQ5 性能评测报告\n")
    if not steady_met:
        sections.append(
            "> ⚠️ 稳态未达成 — 实际稳态 RPS 偏差 > 5% 或 P95 抖动 > 10%,以下数据仅供参考。\n"
            f"> 实际稳态 RPS: {_fmt(actual_steady_rps, 2)} (target={_fmt(target_rps, 2)})\n"
            f"> P95 抖动: {_fmt(p95_jitter_pct, 2)}%\n"
        )
    else:
        sections.append(
            f"> ✅ 稳态达成 — 实际稳态 RPS {_fmt(actual_steady_rps, 2)} "
            f"(target={_fmt(target_rps, 2)}), P95 抖动 {_fmt(p95_jitter_pct, 2)}%\n"
        )
    sections.append("## 表 5.8 WAF2 大规模数据面性能指标\n")
    sections.append(_build_table_5_8(values))
    sections.append("\n")
    sections.append("## 路由比例\n")
    sections.append(_build_routing_table(stats_final))
    sections.append("\n")
    sections.append("## 分路径分桶延迟\n")
    sections.append(_build_per_path_table(stats_final))
    sections.append("\n")
    sections.append("## Run metadata\n")
    sections.append(
        f"- target_rps: {target_rps}\n"
        f"- steady window: [{steady_start_ms}..{steady_end_ms}] ms "
        f"({duration_s:.1f}s)\n"
        f"- driver samples (success in steady): {len(lat)}\n"
        f"- sampler mode: {mode}\n"
        f"- sampler rows (steady): {len(sampler_steady)}\n"
    )

    if not skip_plot:
        plot_path = _maybe_plot(run_dir, driver_steady, sampler_steady)
        if plot_path:
            sections.append(f"\n![timeseries](./{plot_path.name})\n")

    report_md = "\n".join(sections)
    report_path = run_dir / "report.md"
    report_path.write_text(report_md, encoding="utf-8")

    # Persist the report-side metrics for downstream tooling (run_rq5 merges)
    (run_dir / "run.report.json").write_text(json.dumps({
        "target_rps": target_rps,
        "actual_steady_rps": actual_steady_rps,
        "p95_jitter_pct": p95_jitter_pct,
        "steady_met": steady_met,
        "metrics": values,
        "steady_seconds": duration_s,
        "driver_steady_count": len(lat),
        "sampler_steady_rows": len(sampler_steady),
    }, indent=2, default=str), encoding="utf-8")
    return report_path


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="WAF2 RQ5 report generator")
    p.add_argument("--run-dir", type=Path, required=True)
    p.add_argument("--target-rps", type=float, default=None,
                   help="Override target RPS used for steady criterion (default: from run.driver.json)")
    p.add_argument("--skip-plot", action="store_true")
    args = p.parse_args(argv)
    out = generate_report(args.run_dir, target_rps=args.target_rps, skip_plot=args.skip_plot)
    print(f"[rq5_report] wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
