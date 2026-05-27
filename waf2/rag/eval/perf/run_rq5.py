"""RQ5 orchestrator — spawns driver + sampler in parallel, then runs report.

Archives the full run to
    waf2/rag/eval/runs/2026-05-27-rq5-csic-full/<YYYYMMDD-HHMMSS>/
together with a top-level run.json containing commit hash / hostname / cpu_count
/ total_mem_mb / steady verdict / actual_steady_rps / p95_jitter_pct.

Usage:
    python -m waf2.rag.eval.perf.run_rq5 \
        --target-rps 50 --steady-seconds 300

For a quick smoke run that exercises the pipeline against a mocked WAF2:
    python -m waf2.rag.eval.perf.run_rq5 \
        --target-rps 5 --steady-seconds 10 --ladder-step-seconds 2 \
        --skip-plot
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import platform
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

# We import siblings as module-level callables instead of via subprocess so the
# orchestrator stays self-contained (no PYTHONPATH gymnastics for tests).
from . import rq5_driver as driver_mod
from . import rq5_report as report_mod
from . import rq5_sampler as sampler_mod

try:
    import psutil  # type: ignore
    _HAS_PSUTIL = True
except Exception:
    psutil = None  # type: ignore
    _HAS_PSUTIL = False


_DEFAULT_RUNS_PARENT = Path(__file__).resolve().parents[1] / "runs" / "2026-05-27-rq5-csic-full"


def _git_commit_short() -> str | None:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--short=7", "HEAD"],
            capture_output=True, text=True, timeout=5,
            cwd=str(Path(__file__).resolve().parents[4]),
        )
        if out.returncode == 0:
            return out.stdout.strip() or None
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return None


def _env_metadata() -> dict[str, Any]:
    meta: dict[str, Any] = {
        "commit_hash": _git_commit_short(),
        "timestamp": _dt.datetime.now().isoformat(timespec="seconds"),
        "hostname": platform.node(),
        "os_release": platform.platform(),
        "python_version": platform.python_version(),
        "cpu_count": os.cpu_count(),
    }
    if _HAS_PSUTIL:
        try:
            meta["total_mem_mb"] = int(psutil.virtual_memory().total // (1024 * 1024))
        except Exception:
            meta["total_mem_mb"] = None
    else:
        meta["total_mem_mb"] = None
    return meta


def _estimate_driver_duration(args: argparse.Namespace) -> float:
    """Estimate total driver wall time given current CLI flags. Used to size
    sampler --duration-seconds."""
    target = float(args.target_rps)
    start = float(args.ladder_start)
    step = float(args.ladder_step_seconds)
    ladder_count = 0
    cur = start
    while cur < target:
        ladder_count += 1
        nxt = min(target, cur * 2)
        if nxt == cur:
            break
        cur = nxt
    ladder_total = ladder_count * step
    return ladder_total + float(args.steady_seconds) + float(args.cooldown_seconds)


def _orchestrate(args: argparse.Namespace) -> int:
    # ---------------- create archive dir ----------------
    ts = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    if args.out_dir:
        out_dir = Path(args.out_dir)
    else:
        out_dir = _DEFAULT_RUNS_PARENT / ts
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"[run_rq5] archive dir: {out_dir}")

    # ---------------- shared t0 ----------------
    t0_unix = time.time()
    driver_duration = _estimate_driver_duration(args)
    sampler_duration = driver_duration + float(args.sampler_extra_seconds)

    # ---------------- launch driver + sampler concurrently ----------------
    # Use subprocess so each tool has its own event loop / signal handlers.
    py = sys.executable
    repo_root = str(Path(__file__).resolve().parents[4])

    driver_cmd = [
        py, "-m", "waf2.rag.eval.perf.rq5_driver",
        "--target-rps", str(args.target_rps),
        "--steady-seconds", str(args.steady_seconds),
        "--ladder-start", str(args.ladder_start),
        "--ladder-step-seconds", str(args.ladder_step_seconds),
        "--cooldown-seconds", str(args.cooldown_seconds),
        "--sample-size", str(args.sample_size),
        "--seed", str(args.seed),
        "--out-dir", str(out_dir),
        "--waf2-url", args.waf2_url,
        "--start-at-unix-ts", str(t0_unix),
        "--request-timeout", str(args.request_timeout),
    ]
    if args.full:
        driver_cmd.append("--full")
    if args.payload_file:
        driver_cmd += ["--payload-file", str(args.payload_file)]

    sampler_cmd = [
        py, "-m", "waf2.rag.eval.perf.rq5_sampler",
        "--mode", args.sampler_mode,
        "--interval", str(args.sampler_interval),
        "--duration-seconds", str(sampler_duration),
        "--out-dir", str(out_dir),
        "--waf2-url", args.waf2_url,
        "--start-at-unix-ts", str(t0_unix),
        "--container-name", args.container_name,
    ]
    if args.waf2_pid:
        sampler_cmd += ["--pid", str(args.waf2_pid)]

    env = os.environ.copy()
    env["PYTHONPATH"] = repo_root + os.pathsep + env.get("PYTHONPATH", "")

    print(f"[run_rq5] driver:  {' '.join(driver_cmd)}")
    print(f"[run_rq5] sampler: {' '.join(sampler_cmd)}")
    sampler_proc = subprocess.Popen(sampler_cmd, env=env, cwd=repo_root)
    # Brief stagger so sampler is ready before driver starts hammering
    time.sleep(0.2)
    driver_proc = subprocess.Popen(driver_cmd, env=env, cwd=repo_root)

    driver_rc = driver_proc.wait()
    # Give the sampler a chance to finish naturally (it has its own duration timer)
    try:
        sampler_rc = sampler_proc.wait(timeout=sampler_duration + 30.0)
    except subprocess.TimeoutExpired:
        sampler_proc.terminate()
        try:
            sampler_rc = sampler_proc.wait(timeout=10.0)
        except subprocess.TimeoutExpired:
            sampler_proc.kill()
            sampler_rc = sampler_proc.wait()

    if driver_rc != 0:
        print(f"[run_rq5] driver exited rc={driver_rc}", file=sys.stderr)
    if sampler_rc != 0:
        print(f"[run_rq5] sampler exited rc={sampler_rc}", file=sys.stderr)

    # ---------------- report ----------------
    try:
        report_mod.generate_report(out_dir, target_rps=args.target_rps, skip_plot=args.skip_plot)
    except Exception as exc:
        print(f"[run_rq5] report generation failed: {exc}", file=sys.stderr)
        return 2

    # ---------------- top-level run.json ----------------
    env_meta = _env_metadata()
    report_meta_path = out_dir / "run.report.json"
    report_meta = json.loads(report_meta_path.read_text(encoding="utf-8")) if report_meta_path.exists() else {}
    driver_meta_path = out_dir / "run.driver.json"
    driver_meta = json.loads(driver_meta_path.read_text(encoding="utf-8")) if driver_meta_path.exists() else {}
    sampler_meta_path = out_dir / "run.sampler.json"
    sampler_meta = json.loads(sampler_meta_path.read_text(encoding="utf-8")) if sampler_meta_path.exists() else {}
    top_meta = {
        **env_meta,
        "out_dir": str(out_dir),
        "t0_unix_ts": t0_unix,
        "driver_args": driver_meta.get("driver_args"),
        "sampler_args": sampler_meta.get("sampler_args"),
        "steady_met": report_meta.get("steady_met"),
        "actual_steady_rps": report_meta.get("actual_steady_rps"),
        "p95_jitter_pct": report_meta.get("p95_jitter_pct"),
        "target_rps": args.target_rps,
    }
    (out_dir / "run.json").write_text(json.dumps(top_meta, indent=2, default=str), encoding="utf-8")
    print(f"[run_rq5] done. report.md → {out_dir / 'report.md'}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="WAF2 RQ5 one-click orchestrator")
    p.add_argument("--target-rps", type=float, required=True)
    p.add_argument("--steady-seconds", type=float, default=300.0)
    p.add_argument("--ladder-start", type=float, default=50.0)
    p.add_argument("--ladder-step-seconds", type=float, default=30.0)
    p.add_argument("--cooldown-seconds", type=float, default=10.0)
    p.add_argument("--sample-size", type=int, default=5000)
    p.add_argument("--full", action="store_true")
    p.add_argument("--seed", type=int, default=20260527)
    p.add_argument("--payload-file", type=Path, default=None)
    p.add_argument("--out-dir", type=Path, default=None,
                   help="Override archive dir (default: waf2/rag/eval/runs/2026-05-27-rq5-csic-full/<ts>)")
    p.add_argument("--waf2-url", default="http://localhost:8081")
    p.add_argument("--waf2-pid", type=int, default=None,
                   help="Explicit WAF2 PID for sampler psutil-pid mode")
    p.add_argument("--container-name", default="waf2")
    p.add_argument("--sampler-mode", default="auto",
                   choices=["auto", "psutil-pid", "psutil-name", "docker-stats"])
    p.add_argument("--sampler-interval", type=float, default=1.0)
    p.add_argument("--sampler-extra-seconds", type=float, default=5.0,
                   help="Extra time sampler keeps running after driver finishes")
    p.add_argument("--request-timeout", type=float, default=30.0)
    p.add_argument("--skip-plot", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return _orchestrate(args)


if __name__ == "__main__":
    sys.exit(main())
