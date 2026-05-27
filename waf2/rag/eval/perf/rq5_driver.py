"""RQ5 async load driver for WAF2 (add-waf2-rq5-perf-eval-harness).

Loads CSIC-HTTP payloads, replays them against WAF2 :8081 using httpx asyncio
concurrency with a token-bucket RPS controller. Implements warmup-ladder →
steady → cooldown protocol and emits per-request CSV plus a run.json segment.

Usage:
    python -m waf2.rag.eval.perf.rq5_driver \
        --target-rps 50 --steady-seconds 300 \
        --out-dir runs/2026-05-27-rq5-csic-full/<ts>

CSIC payload schema (csv columns we read): Method, URL, content, classification.
We rewrite the host in URL (CSIC's localhost:8080) to whatever --waf2-url is.
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import json
import os
import random
import sys
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse

import httpx


# ---------------------------------------------------------------- CSIC loader

_REPO_ROOT = Path(__file__).resolve().parents[4]
_CSIC_CSV = _REPO_ROOT / "waf2" / "rag" / "eval" / "csic2010" / "csic_database.csv"


@dataclass
class Sample:
    method: str
    path: str
    body: str
    label: str  # "attack" | "normal"


def _load_csic_samples(csv_path: Path) -> list[Sample]:
    """Minimal CSIC loader; mirrors rag/scripts/eval_rag.py shape but kept local
    so the perf harness has no cross-module dependency."""
    if not csv_path.exists():
        raise FileNotFoundError(f"CSIC dataset not found at {csv_path}")
    samples: list[Sample] = []
    with csv_path.open(newline="", encoding="utf-8", errors="replace") as fh:
        reader = csv.reader(fh)
        header = next(reader, None)
        if header is None:
            return []

        def idx_of(name: str) -> int:
            try:
                return header.index(name)
            except ValueError:
                return -1

        m_i, u_i, c_i = idx_of("Method"), idx_of("URL"), idx_of("content")
        for row in reader:
            if not row or len(row) <= max(m_i, u_i, c_i):
                continue
            label_raw = (row[0] or "").strip().lower()
            if not label_raw:
                continue
            label = "attack" if label_raw.startswith("anom") else "normal"
            method = (row[m_i] or "GET").strip() if m_i >= 0 else "GET"
            url_raw = (row[u_i] or "").strip() if u_i >= 0 else ""
            body = (row[c_i] or "").strip() if c_i >= 0 else ""
            url_clean = url_raw.split(" HTTP/")[0].strip()
            try:
                parsed = urlparse(url_clean)
                path = parsed.path or "/"
                if parsed.query:
                    path = f"{path}?{parsed.query}"
            except Exception:
                path = url_clean
            if not path:
                continue
            samples.append(Sample(method=method, path=path, body=body, label=label))
    return samples


def _resolve_samples(args: argparse.Namespace) -> list[Sample]:
    if args.payload_file:
        # JSONL alt source (one sample per line)
        path = Path(args.payload_file)
        items: list[Sample] = []
        for ln in path.read_text(encoding="utf-8").splitlines():
            ln = ln.strip()
            if not ln:
                continue
            obj = json.loads(ln)
            items.append(Sample(
                method=str(obj.get("method", "POST")).upper(),
                path=str(obj.get("path", "/")),
                body=str(obj.get("body", "")),
                label=str(obj.get("label", "normal")),
            ))
        return items

    samples = _load_csic_samples(Path(args.csic_path or _CSIC_CSV))
    if not samples:
        raise RuntimeError("CSIC dataset loaded zero samples — check dataset file")

    if args.full:
        return samples
    rng = random.Random(args.seed)
    sample_size = min(args.sample_size, len(samples))
    return rng.sample(samples, sample_size)


# ---------------------------------------------------------------- Driver core


@dataclass
class LadderEntry:
    rps: int
    start_ms: int
    end_ms: int


@dataclass
class PhaseSpec:
    """A single (rps, duration_s, phase_label) tuple to emit."""
    rps: float
    duration_s: float
    phase: str  # "warmup" | "steady" | "cooldown"


def _build_phases(args: argparse.Namespace) -> list[PhaseSpec]:
    target = float(args.target_rps)
    start = float(args.ladder_start)
    step = float(args.ladder_step_seconds)
    ladder_rps: list[float] = []
    cur = start
    while cur < target:
        ladder_rps.append(cur)
        cur = min(target, cur * 2)  # double each step (50→100→200→...)
        if cur == ladder_rps[-1]:
            break
    # Ensure target itself is reached at end of warmup if it wasn't last entry
    if not ladder_rps or ladder_rps[-1] < target:
        # If target is below start, just skip the ladder and go straight to steady
        if start >= target:
            ladder_rps = []

    phases: list[PhaseSpec] = []
    for rps in ladder_rps:
        phases.append(PhaseSpec(rps=rps, duration_s=step, phase="warmup"))
    phases.append(PhaseSpec(rps=target, duration_s=float(args.steady_seconds), phase="steady"))
    # cooldown: emit at near-zero RPS for cooldown_seconds, mainly to let in-flight drain.
    if args.cooldown_seconds > 0:
        phases.append(PhaseSpec(rps=0.0, duration_s=float(args.cooldown_seconds), phase="cooldown"))
    return phases


async def _one_request(
    client: httpx.AsyncClient,
    waf2_url: str,
    sample: Sample,
    t0_unix: float,
    phase: str,
    writer: csv.DictWriter,
    write_lock: asyncio.Lock,
    counters: dict[str, int],
) -> None:
    target = waf2_url.rstrip("/") + (sample.path if sample.path.startswith("/") else "/" + sample.path)
    ts_ms = int((time.time() - t0_unix) * 1000)
    start = time.perf_counter()
    status = 0
    success = False
    try:
        if sample.body and sample.method.upper() in ("POST", "PUT", "PATCH"):
            resp = await client.request(
                sample.method, target,
                content=sample.body.encode("utf-8", errors="replace"),
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
        else:
            resp = await client.request(sample.method, target)
        status = resp.status_code
        # 2xx = passed; 4xx = WAF2 successfully decided BLOCK (still counts as success)
        # 5xx / network failures = failure
        success = status < 500
    except (httpx.TimeoutException, httpx.RequestError):
        status = -1
        success = False
    latency_ms = (time.perf_counter() - start) * 1000.0

    async with write_lock:
        writer.writerow({
            "ts_ms": ts_ms,
            "latency_ms": round(latency_ms, 3),
            "status": status,
            "success": "true" if success else "false",
            "phase": phase,
            "label": sample.label,
        })
    counters["sent"] += 1
    if success:
        counters["success"] += 1
    if status == 403:
        counters["blocked"] += 1


async def _emit_phase(
    client: httpx.AsyncClient,
    waf2_url: str,
    samples: list[Sample],
    phase_spec: PhaseSpec,
    t0_unix: float,
    writer: csv.DictWriter,
    write_lock: asyncio.Lock,
    counters: dict[str, int],
    inflight: set[asyncio.Task],
) -> None:
    """Run a single phase using token-bucket pacing.

    Token bucket pace: emit one request every 1/rps seconds. Each emit creates
    a new asyncio Task so we never block on slow responses.
    """
    if phase_spec.rps <= 0.0 or not samples:
        # cooldown or no payload — just sleep, do not emit new tasks
        await asyncio.sleep(phase_spec.duration_s)
        return

    interval = 1.0 / phase_spec.rps
    deadline = time.perf_counter() + phase_spec.duration_s
    rng_idx = 0
    while time.perf_counter() < deadline:
        sample = samples[rng_idx % len(samples)]
        rng_idx += 1
        task = asyncio.create_task(
            _one_request(client, waf2_url, sample, t0_unix, phase_spec.phase, writer, write_lock, counters)
        )
        inflight.add(task)
        task.add_done_callback(inflight.discard)
        await asyncio.sleep(interval)


async def _run_async(args: argparse.Namespace, out_dir: Path, t0_unix: float) -> dict[str, Any]:
    samples = _resolve_samples(args)
    phases = _build_phases(args)

    driver_csv_path = out_dir / "driver.csv"
    fh = driver_csv_path.open("w", newline="", encoding="utf-8")
    writer = csv.DictWriter(fh, fieldnames=["ts_ms", "latency_ms", "status", "success", "phase", "label"])
    writer.writeheader()
    write_lock = asyncio.Lock()
    counters: dict[str, int] = {"sent": 0, "success": 0, "blocked": 0}
    inflight: set[asyncio.Task] = set()

    limits = httpx.Limits(max_connections=args.max_connections, max_keepalive_connections=args.max_connections)
    timeout = httpx.Timeout(args.request_timeout, connect=5.0)
    ladder_entries: list[LadderEntry] = []
    steady_start_ms = -1
    steady_end_ms = -1
    try:
        async with httpx.AsyncClient(limits=limits, timeout=timeout, verify=False) as client:
            for spec in phases:
                phase_start_ms = int((time.time() - t0_unix) * 1000)
                if spec.phase == "warmup":
                    ladder_entries.append(LadderEntry(
                        rps=int(spec.rps), start_ms=phase_start_ms, end_ms=-1
                    ))
                elif spec.phase == "steady":
                    steady_start_ms = phase_start_ms
                await _emit_phase(client, args.waf2_url, samples, spec, t0_unix, writer, write_lock, counters, inflight)
                phase_end_ms = int((time.time() - t0_unix) * 1000)
                if spec.phase == "warmup" and ladder_entries:
                    ladder_entries[-1].end_ms = phase_end_ms
                elif spec.phase == "steady":
                    steady_end_ms = phase_end_ms
            # Drain any remaining in-flight tasks (with a hard cap)
            if inflight:
                try:
                    await asyncio.wait_for(asyncio.gather(*inflight, return_exceptions=True), timeout=30.0)
                except asyncio.TimeoutError:
                    print("[rq5_driver] warn: in-flight drain timed out", file=sys.stderr)
    finally:
        fh.flush()
        fh.close()

    return {
        "t0_unix_ts": t0_unix,
        "target_rps": args.target_rps,
        "steady_seconds": args.steady_seconds,
        "ladder_step_seconds": args.ladder_step_seconds,
        "cooldown_seconds": args.cooldown_seconds,
        "ladder": [asdict(e) for e in ladder_entries],
        "steady_start_ms": steady_start_ms,
        "steady_end_ms": steady_end_ms,
        "sample_size": args.sample_size if not args.full else "full",
        "seed": args.seed,
        "csic_path": str(args.csic_path or _CSIC_CSV),
        "waf2_url": args.waf2_url,
        "driver_csv": str(driver_csv_path),
        "counters": counters,
        "driver_args": vars(args),
    }


# ------------------------------------------------------------------------- CLI


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="WAF2 RQ5 async load driver")
    p.add_argument("--target-rps", type=float, required=True,
                   help="Steady-state target requests per second")
    p.add_argument("--steady-seconds", type=float, default=300.0)
    p.add_argument("--ladder-start", type=float, default=50.0,
                   help="Initial RPS of warmup ladder; ladder doubles until reaching target")
    p.add_argument("--ladder-step-seconds", type=float, default=30.0)
    p.add_argument("--cooldown-seconds", type=float, default=10.0)
    p.add_argument("--sample-size", type=int, default=5000,
                   help="How many CSIC payloads to sample (ignored when --full)")
    p.add_argument("--full", action="store_true",
                   help="Use the entire CSIC dataset instead of sampling")
    p.add_argument("--seed", type=int, default=20260527,
                   help="Random seed for CSIC sampling")
    p.add_argument("--csic-path", type=Path, default=None,
                   help="Override CSIC csv path (default: waf2/rag/eval/csic2010/csic_database.csv)")
    p.add_argument("--payload-file", type=Path, default=None,
                   help="Optional JSONL payload override (overrides CSIC loader)")
    p.add_argument("--out-dir", type=Path, required=True,
                   help="Directory to write driver.csv and run.driver.json")
    p.add_argument("--waf2-url", type=str, default="http://localhost:8081")
    p.add_argument("--start-at-unix-ts", type=float, default=None,
                   help="Shared t0 (seconds since epoch). Defaults to time.time() at start.")
    p.add_argument("--request-timeout", type=float, default=30.0)
    p.add_argument("--max-connections", type=int, default=128)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    t0 = float(args.start_at_unix_ts) if args.start_at_unix_ts else time.time()
    run_segment = asyncio.run(_run_async(args, args.out_dir, t0))
    # Persist driver portion of run.json. Orchestrator merges this into top-level run.json.
    (args.out_dir / "run.driver.json").write_text(
        json.dumps(run_segment, indent=2, default=str), encoding="utf-8"
    )
    print(f"[rq5_driver] sent={run_segment['counters']['sent']} "
          f"success={run_segment['counters']['success']} "
          f"steady=[{run_segment['steady_start_ms']}..{run_segment['steady_end_ms']}]ms")
    return 0


if __name__ == "__main__":
    sys.exit(main())
