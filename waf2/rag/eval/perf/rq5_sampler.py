"""RQ5 resource + WAF2 stats sampler (add-waf2-rq5-perf-eval-harness).

Three-tier fallback for CPU/RSS sampling:
  1. psutil + explicit --pid
  2. psutil + docker inspect (PID resolved from container name)
  3. docker stats --no-stream (no psutil dependency; forced ≥ 2s interval)

Concurrently polls /waf2/stats every interval and serializes per_path_latency
plus a handful of route counters. Writes streaming CSV; on signal or duration
expiry, dumps the last full /waf2/stats response to stats_final.json.

Usage:
    python -m waf2.rag.eval.perf.rq5_sampler \
        --interval 1.0 --duration-seconds 360 \
        --out-dir runs/2026-05-27-rq5-csic-full/<ts>
"""

from __future__ import annotations

import argparse
import csv
import json
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import httpx

try:
    import psutil  # type: ignore
    _HAS_PSUTIL = True
except Exception:  # pragma: no cover - optional dep
    psutil = None  # type: ignore
    _HAS_PSUTIL = False


# ------------------------------------------------------------- mode selection


def _resolve_pid_from_container(name: str) -> int | None:
    try:
        result = subprocess.run(
            ["docker", "inspect", "--format", "{{.State.Pid}}", name],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode != 0:
            return None
        pid = int(result.stdout.strip())
        return pid if pid > 0 else None
    except (FileNotFoundError, subprocess.TimeoutExpired, ValueError):
        return None


def _pick_mode(args: argparse.Namespace) -> tuple[str, int | None]:
    """Return (mode, pid) where mode ∈ {psutil-pid, psutil-name, docker-stats}.

    Honors --mode override. Auto-resolves the best available.
    """
    explicit = (args.mode or "auto").lower()
    if explicit == "psutil-pid":
        if not _HAS_PSUTIL:
            raise RuntimeError("psutil not installed; cannot use psutil-pid mode")
        if not args.pid:
            raise RuntimeError("--mode psutil-pid requires --pid")
        return "psutil-pid", int(args.pid)
    if explicit == "psutil-name":
        if not _HAS_PSUTIL:
            raise RuntimeError("psutil not installed; cannot use psutil-name mode")
        pid = _resolve_pid_from_container(args.container_name)
        if pid is None:
            raise RuntimeError(f"docker inspect could not resolve PID for {args.container_name}")
        return "psutil-name", pid
    if explicit == "docker-stats":
        return "docker-stats", None
    # auto
    if _HAS_PSUTIL and args.pid:
        return "psutil-pid", int(args.pid)
    if _HAS_PSUTIL:
        pid = _resolve_pid_from_container(args.container_name)
        if pid is not None:
            return "psutil-name", pid
    return "docker-stats", None


# ------------------------------------------------------------- CPU/RSS readers


def _read_psutil(proc) -> tuple[float, float]:
    """Return (cpu_pct, rss_mb) using psutil. Note: cpu_percent(interval=None)
    returns 0.0 on first call — caller MUST prime once and discard."""
    try:
        cpu = float(proc.cpu_percent(interval=None))
        rss = float(proc.memory_info().rss) / (1024 * 1024)
        return cpu, rss
    except Exception:
        return float("nan"), float("nan")


_DOCKER_STATS_LINE = "{{.CPUPerc}}|{{.MemUsage}}"


def _read_docker_stats(container: str) -> tuple[float, float]:
    try:
        out = subprocess.run(
            ["docker", "stats", "--no-stream", "--format", _DOCKER_STATS_LINE, container],
            capture_output=True, text=True, timeout=10,
        )
        if out.returncode != 0 or "|" not in out.stdout:
            return float("nan"), float("nan")
        cpu_s, mem_s = out.stdout.strip().split("|", 1)
        cpu = float(cpu_s.rstrip("%").strip())
        # MemUsage looks like "123.4MiB / 1.234GiB"
        rss_s = mem_s.split("/")[0].strip()
        rss_mb = _parse_mem_to_mb(rss_s)
        return cpu, rss_mb
    except Exception:
        return float("nan"), float("nan")


def _parse_mem_to_mb(s: str) -> float:
    s = s.strip().upper().replace(" ", "")
    if s.endswith("GIB"):
        return float(s[:-3]) * 1024.0
    if s.endswith("MIB"):
        return float(s[:-3])
    if s.endswith("KIB"):
        return float(s[:-3]) / 1024.0
    if s.endswith("GB"):
        return float(s[:-2]) * 1024.0
    if s.endswith("MB"):
        return float(s[:-2])
    if s.endswith("KB"):
        return float(s[:-2]) / 1024.0
    try:
        return float(s) / (1024 * 1024)  # assume bytes
    except ValueError:
        return float("nan")


# ------------------------------------------------------------------ main loop


_FIELDS = [
    "ts_ms", "mode", "cpu_pct", "rss_mb",
    "cache_hits", "llm_calls",
    "route_static_block", "route_fast_pass", "route_one_shot", "route_react",
    "per_path_latency_json",
]


def _poll_stats(client: httpx.Client, waf2_url: str) -> dict[str, Any] | None:
    try:
        r = client.get(waf2_url.rstrip("/") + "/waf2/stats", timeout=2.0)
        if r.status_code != 200:
            return None
        return r.json()
    except (httpx.HTTPError, ValueError):
        return None


def _extract_row(stats: dict[str, Any] | None, ts_ms: int, mode: str,
                 cpu: float, rss: float) -> dict[str, Any]:
    row = {
        "ts_ms": ts_ms,
        "mode": mode,
        "cpu_pct": _fmt_num(cpu),
        "rss_mb": _fmt_num(rss),
        "cache_hits": None,
        "llm_calls": None,
        "route_static_block": None,
        "route_fast_pass": None,
        "route_one_shot": None,
        "route_react": None,
        "per_path_latency_json": None,
    }
    if not stats:
        return row
    row["cache_hits"] = stats.get("cache_hits")
    row["llm_calls"] = stats.get("llm_calls")
    row["route_static_block"] = stats.get("route_static_block")
    row["route_fast_pass"] = stats.get("route_fast_pass")
    row["route_one_shot"] = stats.get("route_one_shot")
    row["route_react"] = stats.get("route_react")
    ppl = stats.get("per_path_latency")
    if ppl is not None:
        row["per_path_latency_json"] = json.dumps(ppl, separators=(",", ":"))
    return row


def _fmt_num(x: float) -> str:
    if x != x:  # NaN
        return ""
    return f"{x:.3f}"


def _run(args: argparse.Namespace) -> int:
    args.out_dir.mkdir(parents=True, exist_ok=True)
    mode, pid = _pick_mode(args)
    interval = float(args.interval)
    if mode == "docker-stats" and interval < 2.0:
        print(f"[rq5_sampler] warn: docker-stats mode forces interval ≥ 2.0s "
              f"(was {interval}s)", file=sys.stderr)
        interval = 2.0

    print(f"[rq5_sampler] mode={mode} pid={pid} interval={interval}s "
          f"duration={args.duration_seconds}s", file=sys.stderr)

    proc = None
    if mode.startswith("psutil") and pid is not None:
        try:
            proc = psutil.Process(pid)
            # prime cpu_percent so subsequent reads have a baseline
            proc.cpu_percent(interval=None)
        except (psutil.NoSuchProcess, psutil.AccessDenied) as exc:
            # WSL2 + Docker Desktop: docker inspect PID is in VM namespace,
            # invisible to host psutil. Degrade to docker-stats fallback.
            print(f"[rq5_sampler] warn: psutil cannot attach to pid={pid} ({exc}); "
                  f"falling back to docker-stats mode", file=sys.stderr)
            mode = "docker-stats"
            proc = None
            if interval < 2.0:
                interval = 2.0

    sampler_csv_path = args.out_dir / "sampler.csv"
    fh = sampler_csv_path.open("w", newline="", encoding="utf-8")
    writer = csv.DictWriter(fh, fieldnames=_FIELDS)
    writer.writeheader()

    t0 = float(args.start_at_unix_ts) if args.start_at_unix_ts else time.time()
    deadline = t0 + float(args.duration_seconds)

    stop_flag = {"stop": False}
    def _stop(*_):
        stop_flag["stop"] = True
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    last_stats: dict[str, Any] | None = None
    sample_count = 0
    try:
        with httpx.Client() as http:
            while not stop_flag["stop"] and time.time() < deadline:
                ts_ms = int((time.time() - t0) * 1000)
                if proc is not None:
                    cpu, rss = _read_psutil(proc)
                else:
                    cpu, rss = _read_docker_stats(args.container_name)
                stats = _poll_stats(http, args.waf2_url)
                if stats is not None:
                    last_stats = stats
                writer.writerow(_extract_row(stats, ts_ms, mode, cpu, rss))
                sample_count += 1
                # Cooperative sleep
                next_tick = time.time() + interval
                while not stop_flag["stop"] and time.time() < min(next_tick, deadline):
                    time.sleep(min(0.1, max(0.0, next_tick - time.time())))
    finally:
        fh.flush()
        fh.close()
        # Write the last good /waf2/stats snapshot as the final source of truth
        if last_stats is not None:
            (args.out_dir / "stats_final.json").write_text(
                json.dumps(last_stats, indent=2, default=str), encoding="utf-8"
            )
        else:
            # Ensure file exists even when WAF2 was unreachable (downstream tools
            # rely on it). Mark explicitly that no snapshot succeeded.
            (args.out_dir / "stats_final.json").write_text(
                json.dumps({"_warning": "no /waf2/stats snapshot succeeded during sampler run"},
                           indent=2), encoding="utf-8"
            )

    # Persist sampler portion of run.json (orchestrator merges into top-level run.json)
    (args.out_dir / "run.sampler.json").write_text(json.dumps({
        "t0_unix_ts": t0,
        "mode": mode,
        "pid": pid,
        "interval_s": interval,
        "duration_seconds": args.duration_seconds,
        "container_name": args.container_name,
        "sample_count": sample_count,
        "sampler_csv": str(sampler_csv_path),
        "sampler_args": vars(args),
    }, indent=2, default=str), encoding="utf-8")
    print(f"[rq5_sampler] wrote {sample_count} samples", file=sys.stderr)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="WAF2 RQ5 resource sampler")
    p.add_argument("--mode", default="auto",
                   choices=["auto", "psutil-pid", "psutil-name", "docker-stats"])
    p.add_argument("--pid", type=int, default=None,
                   help="Explicit WAF2 process PID (for psutil-pid mode)")
    p.add_argument("--container-name", default="waf2",
                   help="Docker container name (for psutil-name or docker-stats mode)")
    p.add_argument("--interval", type=float, default=1.0)
    p.add_argument("--duration-seconds", type=float, required=True)
    p.add_argument("--out-dir", type=Path, required=True)
    p.add_argument("--waf2-url", default="http://localhost:8081")
    p.add_argument("--start-at-unix-ts", type=float, default=None,
                   help="Shared t0 with driver (seconds since epoch)")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return _run(args)


if __name__ == "__main__":
    sys.exit(main())
