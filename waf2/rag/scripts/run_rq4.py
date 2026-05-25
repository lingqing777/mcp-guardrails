"""RQ4: Unified evaluation driver for three RAG configurations.

Runs 3 datasets x 3 RAG configs (rag-off, rag-generic, rag-mcp) = 9 evaluations.
Produces cases-rq4-{dataset}-{config}.jsonl files for report_rq4.py.

Datasets:
  1. M-Bench-Core  (MCP format, 150 sampled benigns + 150 attacks)
  2. PI-Eval       (HTTP format, 228 attacks only)
  3. Adversarial   (HTTP format, 30 attacks + 10 benigns)

Usage:
    PYTHONPATH=. python3 -m waf2.rag.scripts.run_rq4 \\
        --waf2 http://localhost:8081 \\
        --out-dir waf2/rag/eval/runs/2026-05-25-rq4/

Optional flags:
    --datasets mbench,pi-eval,adversarial  (default: all three)
    --seed 42  (for benign sampling reproducibility)
"""
from __future__ import annotations

import argparse
import json
import random
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve()
PROJECT_ROOT = HERE.parents[3]

sys.path.insert(0, str(HERE.parent))
from _eval_cases import parse_waf2_headers, stable_case_id, write_cases_jsonl  # noqa: E402

# ---------- inline helpers (self-contained, no sibling imports at runtime) ----------


def _post_config(waf2_url: str, payload: dict) -> None:
    """POST a config payload to /waf2/config."""
    url = waf2_url.rstrip("/") + "/waf2/config"
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=data, method="POST", headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp.read()
    except Exception as e:
        print(f"  [warn] config update failed: {e}", file=sys.stderr)


def send_one(
    waf2_url: str, method: str, path: str, body: str
) -> tuple[str, str, dict]:
    """Send one request and return (outcome, detected_category, headers).

    outcome in {"blocked", "passed", "upstream_error", "other"}
    """
    url = waf2_url.rstrip("/") + path
    data = body.encode() if body else None
    headers = {"Content-Type": "application/json"} if body else {}
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=200) as resp:
            resp.read()
            return "passed", "", dict(resp.headers.items())
    except urllib.error.HTTPError as he:
        resp_headers = dict(he.headers.items()) if he.headers else {}
        if he.code == 403:
            try:
                body_text = he.read().decode("utf-8", errors="replace")
                parsed = json.loads(body_text)
                if parsed.get("error") and "WAF2" in str(parsed.get("error", "")):
                    return "blocked", parsed.get("category", ""), resp_headers
            except Exception:
                pass
            return "upstream_error", "", resp_headers
        if 500 <= he.code < 600:
            return "upstream_error", "", resp_headers
        return "other", "", resp_headers
    except urllib.error.URLError:
        return "upstream_error", "", {}
    except Exception:
        return "other", "", {}


def load_jsonl(path: Path) -> list[dict]:
    """Load a JSONL file into a list of dicts."""
    out: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        out.append(json.loads(line))
    return out


def build_mcp_envelope(tool: str, args: dict) -> str:
    """Wrap {tool, args} as a JSON-RPC tools/call body for POST /mcp."""
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": tool, "arguments": args or {}},
    }
    return json.dumps(payload, ensure_ascii=False)


def envelope_for_record(rec: dict) -> tuple[str, str, int | None]:
    """Return (path, body, waf2_evaluated_step) for an M-Bench record.

    waf2_evaluated_step is None for single-step, len(steps) for multi-step.
    """
    family = rec.get("family", "")
    if family == "call_chain":
        steps = rec.get("steps") or []
        if not steps:
            raise ValueError(
                f"call_chain record {rec.get('case_id')} has empty steps"
            )
        last = steps[-1]
        body = build_mcp_envelope(last.get("tool", ""), last.get("args") or {})
        return "/mcp", body, len(steps)
    body = build_mcp_envelope(rec.get("tool", ""), rec.get("args") or {})
    return "/mcp", body, None


# ---------- gray-area definitions ----------

GRAY_AREA_SUBCATEGORIES = {
    "indirect_prompt_injection",  # PI-Eval naming
    "indirect_pi",                # M-Bench-Core naming
    "context_manipulation",
    "encoded_injection",
}

GRAY_AREA_TAGS = {
    # adversarial attack gray-area tags
    "pi-indirect-mcp",
    "pi-academic-pretense",
    "pi-translate-cover",
    "pi-bracket-redirect",
    "pi-llama-sys-tag",
    "pi-pig-latin-leak",
    "pi-fictional-persona",
    # adversarial benign gray-area tags
    "benign-discuss-sqli",
    "benign-ignore-context",
    "benign-edu-xss",
    "benign-discuss-IFS",
    "benign-user-config",
}


def is_gray_area(record: dict, dataset: str) -> bool:
    """Determine if a record is a gray-area sample based on dataset-specific rules.

    Gray-area rules:
    - M-Bench: subcategory == "indirect_pi" (attacks)
               or source == "handcrafted" (benigns)
    - PI-Eval: subcategory in GRAY_AREA_SUBCATEGORIES
    - Adversarial: tag in GRAY_AREA_TAGS
    """
    if dataset == "mbench":
        subcat = record.get("subcategory", "")
        source = record.get("source", "")
        label = record.get("label", "")
        if label == "attack" and subcat == "indirect_pi":
            return True
        if label == "benign" and source == "handcrafted":
            return True
        return False
    if dataset == "pi-eval":
        return record.get("subcategory", "") in GRAY_AREA_SUBCATEGORIES
    if dataset == "adversarial":
        return record.get("tag", "") in GRAY_AREA_TAGS
    return False


# ---------- RAG configs ----------

RAG_CONFIGS: list[tuple[str, dict]] = [
    (
        "rag-off",
        {"rag_enabled": False, "eval_mode": True, "eval_fail_closed": False},
    ),
    (
        "rag-generic",
        {
            "rag_enabled": True,
            "rag_domain": "generic",
            "eval_mode": True,
            "eval_fail_closed": False,
        },
    ),
    (
        "rag-mcp",
        {
            "rag_enabled": True,
            "rag_domain": "mcp",
            "eval_mode": True,
            "eval_fail_closed": False,
        },
    ),
]


# ---------- telemetry extraction ----------


def _extract_telemetry(
    outcome: str, detected_cat: str, headers: dict
) -> dict[str, Any]:
    """Parse WAF2 headers and merge detected_category from response body."""
    telemetry = parse_waf2_headers(headers)
    if outcome == "blocked" and not telemetry.get("detected_category"):
        telemetry["detected_category"] = detected_cat or ""
    return telemetry


def _build_output_record(
    *,
    case_id: str,
    dataset: str,
    config_slug: str,
    row_index: int,
    label: str,
    category: str,
    subcategory: str,
    tag: str,
    outcome: str,
    detected_category: str,
    telemetry: dict[str, Any],
    is_gray: bool,
) -> dict[str, Any]:
    """Build the standardized output record for RQ4."""
    return {
        "case_id": case_id,
        "dataset": dataset,
        "round": config_slug,
        "row_index": row_index,
        "label": label,
        "category": category,
        "subcategory": subcategory,
        "tag": tag,
        "outcome": outcome,
        "detected_category": detected_category or telemetry.get("detected_category", ""),
        "latency_ms": telemetry.get("latency_ms", 0),
        "rag_used": telemetry.get("rag_used", False),
        "rag_top_score": telemetry.get("rag_top_score", 0.0),
        "rag_top_category": telemetry.get("rag_top_category", ""),
        "route": telemetry.get("route", ""),
        "reasons": telemetry.get("reasons") or [],
        "is_gray_area": is_gray,
    }


# ---------- M-Bench-Core runner ----------

MBENCH_ATTACKS_PATH = PROJECT_ROOT / "waf2" / "rag" / "eval" / "m-bench-core" / "attacks.jsonl"
MBENCH_BENIGN_PATH = PROJECT_ROOT / "waf2" / "rag" / "eval" / "m-bench-core" / "benign.jsonl"


def sample_benign(
    benigns: list[dict], n: int = 150, seed: int = 42
) -> list[dict]:
    """Stratified benign sampling: keep ALL handcrafted, sample template to fill n.

    If handcrafted count >= n, return all handcrafted (no sampling needed).
    Otherwise, keep all handcrafted and sample template benigns to fill
    remaining slots.
    """
    rng = random.Random(seed)
    handcrafted = [b for b in benigns if b.get("source") == "handcrafted"]
    template = [b for b in benigns if b.get("source") == "template"]

    if len(handcrafted) >= n:
        rng.shuffle(handcrafted)
        return handcrafted[:n]

    n_template = n - len(handcrafted)
    if n_template > len(template):
        n_template = len(template)
    sampled_template = rng.sample(template, n_template)
    return handcrafted + sampled_template


def run_mbench(
    waf2_url: str,
    attacks: list[dict],
    benign_sample: list[dict],
    config_slug: str,
    config_payload: dict,
    out_dir: Path,
) -> None:
    """Run M-Bench-Core evaluation under one RAG config."""
    _post_config(waf2_url, config_payload)

    rows = attacks + benign_sample
    records: list[dict] = []
    width = max(4, len(str(len(rows) - 1)))

    for i, rec in enumerate(rows):
        path, body, eval_step = envelope_for_record(rec)
        outcome, cat, resp_headers = send_one(waf2_url, "POST", path, body)
        telemetry = _extract_telemetry(outcome, cat, resp_headers)

        label = rec.get("label", "")
        subcategory = rec.get("subcategory", "")
        tag = rec.get("tag", "")
        is_gray = is_gray_area(rec, "mbench")

        case_id = stable_case_id("rq4", "mbench", config_slug, str(i).zfill(width))
        out_rec = _build_output_record(
            case_id=case_id,
            dataset="mbench",
            config_slug=config_slug,
            row_index=i,
            label=label,
            category=subcategory,  # M-Bench uses subcategory as category
            subcategory=subcategory,
            tag=tag,
            outcome=outcome,
            detected_category=cat,
            telemetry=telemetry,
            is_gray=is_gray,
        )
        records.append(out_rec)

        if (i + 1) % 50 == 0:
            blocked = sum(1 for r in records if r["outcome"] == "blocked")
            passed = sum(1 for r in records if r["outcome"] == "passed")
            print(
                f"  [mbench/{config_slug}] {i + 1}/{len(rows)} "
                f"blocked={blocked} passed={passed}",
                file=sys.stderr,
            )

    out_path = out_dir / f"cases-rq4-mbench-{config_slug}.jsonl"
    n = write_cases_jsonl(out_path, records)
    blocked = sum(1 for r in records if r["outcome"] == "blocked")
    passed = sum(1 for r in records if r["outcome"] == "passed")
    err = sum(1 for r in records if r["outcome"] == "upstream_error")
    print(
        f"[mbench/{config_slug}] DONE  blocked={blocked} passed={passed} "
        f"err={err}  -> {out_path} ({n} rows)",
        file=sys.stderr,
    )


# ---------- PI-Eval runner ----------

PI_EVAL_PATH = PROJECT_ROOT / "waf2" / "rag" / "eval" / "prompt-injection-eval.jsonl"


def run_pi_eval(
    waf2_url: str,
    dataset: list[dict],
    config_slug: str,
    config_payload: dict,
    out_dir: Path,
) -> None:
    """Run Prompt-Injection-Eval under one RAG config."""
    _post_config(waf2_url, config_payload)

    records: list[dict] = []
    width = max(4, len(str(len(dataset) - 1)))

    for i, sample in enumerate(dataset):
        outcome, cat, resp_headers = send_one(
            waf2_url, sample["method"], sample["path"], sample["body"]
        )
        telemetry = _extract_telemetry(outcome, cat, resp_headers)

        label = sample.get("label", "")
        category = sample.get("category", "")
        subcategory = sample.get("subcategory", "")
        tag = sample.get("tag", "")
        is_gray = is_gray_area(sample, "pi-eval")

        case_id = stable_case_id("rq4", "pi-eval", config_slug, str(i).zfill(width))
        out_rec = _build_output_record(
            case_id=case_id,
            dataset="pi-eval",
            config_slug=config_slug,
            row_index=i,
            label=label,
            category=category,
            subcategory=subcategory,
            tag=tag,
            outcome=outcome,
            detected_category=cat,
            telemetry=telemetry,
            is_gray=is_gray,
        )
        records.append(out_rec)

        if (i + 1) % 50 == 0:
            blocked = sum(1 for r in records if r["outcome"] == "blocked")
            passed = sum(1 for r in records if r["outcome"] == "passed")
            print(
                f"  [pi-eval/{config_slug}] {i + 1}/{len(dataset)} "
                f"blocked={blocked} passed={passed}",
                file=sys.stderr,
            )

    out_path = out_dir / f"cases-rq4-pi-eval-{config_slug}.jsonl"
    n = write_cases_jsonl(out_path, records)
    blocked = sum(1 for r in records if r["outcome"] == "blocked")
    passed = sum(1 for r in records if r["outcome"] == "passed")
    err = sum(1 for r in records if r["outcome"] == "upstream_error")
    print(
        f"[pi-eval/{config_slug}] DONE  blocked={blocked} passed={passed} "
        f"err={err}  -> {out_path} ({n} rows)",
        file=sys.stderr,
    )


# ---------- Adversarial runner ----------

ADVERSARIAL_PATH = PROJECT_ROOT / "waf2" / "rag" / "eval" / "adversarial.jsonl"


def run_adversarial(
    waf2_url: str,
    dataset: list[dict],
    config_slug: str,
    config_payload: dict,
    out_dir: Path,
) -> None:
    """Run Adversarial dataset under one RAG config."""
    _post_config(waf2_url, config_payload)

    records: list[dict] = []
    width = max(4, len(str(len(dataset) - 1)))

    for i, sample in enumerate(dataset):
        outcome, cat, resp_headers = send_one(
            waf2_url, sample["method"], sample["path"], sample["body"]
        )
        telemetry = _extract_telemetry(outcome, cat, resp_headers)

        label = sample.get("label", "")
        category = sample.get("category", "")
        subcategory = sample.get("subcategory", "")
        tag = sample.get("tag", "")
        is_gray = is_gray_area(sample, "adversarial")

        case_id = stable_case_id("rq4", "adversarial", config_slug, str(i).zfill(width))
        out_rec = _build_output_record(
            case_id=case_id,
            dataset="adversarial",
            config_slug=config_slug,
            row_index=i,
            label=label,
            category=category,
            subcategory=subcategory,
            tag=tag,
            outcome=outcome,
            detected_category=cat,
            telemetry=telemetry,
            is_gray=is_gray,
        )
        records.append(out_rec)

    out_path = out_dir / f"cases-rq4-adversarial-{config_slug}.jsonl"
    n = write_cases_jsonl(out_path, records)
    blocked = sum(1 for r in records if r["outcome"] == "blocked")
    passed = sum(1 for r in records if r["outcome"] == "passed")
    err = sum(1 for r in records if r["outcome"] == "upstream_error")
    print(
        f"[adversarial/{config_slug}] DONE  blocked={blocked} passed={passed} "
        f"err={err}  -> {out_path} ({n} rows)",
        file=sys.stderr,
    )


# ---------- main ----------

DATASET_CHOICES = ["mbench", "pi-eval", "adversarial"]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="RQ4: Unified evaluation across 3 RAG configs x 3 datasets."
    )
    ap.add_argument("--waf2", default="http://localhost:8081", help="WAF2 base URL")
    ap.add_argument("--out-dir", required=True, help="output directory for cases JSONL")
    ap.add_argument(
        "--datasets",
        default=",".join(DATASET_CHOICES),
        help=f"comma-separated datasets to run (default: {','.join(DATASET_CHOICES)})",
    )
    ap.add_argument(
        "--seed", type=int, default=42, help="random seed for benign sampling (default: 42)"
    )
    args = ap.parse_args(argv)

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    datasets_to_run = [d.strip() for d in args.datasets.split(",")]
    for d in datasets_to_run:
        if d not in DATASET_CHOICES:
            print(f"Unknown dataset: {d!r} (valid: {DATASET_CHOICES})", file=sys.stderr)
            return 2

    # ---------- load datasets ----------
    mbench_attacks: list[dict] | None = None
    mbench_benign_sample: list[dict] | None = None
    pi_eval_data: list[dict] | None = None
    adversarial_data: list[dict] | None = None

    if "mbench" in datasets_to_run:
        if not MBENCH_ATTACKS_PATH.exists():
            print(f"M-Bench attacks not found: {MBENCH_ATTACKS_PATH}", file=sys.stderr)
            return 2
        if not MBENCH_BENIGN_PATH.exists():
            print(f"M-Bench benigns not found: {MBENCH_BENIGN_PATH}", file=sys.stderr)
            return 2
        mbench_attacks = load_jsonl(MBENCH_ATTACKS_PATH)
        all_benigns = load_jsonl(MBENCH_BENIGN_PATH)
        mbench_benign_sample = sample_benign(all_benigns, n=150, seed=args.seed)
        print(
            f"[mbench] loaded {len(mbench_attacks)} attacks, "
            f"sampled {len(mbench_benign_sample)} benigns "
            f"(handcrafted={sum(1 for b in mbench_benign_sample if b.get('source') == 'handcrafted')}, "
            f"template={sum(1 for b in mbench_benign_sample if b.get('source') == 'template')})",
            file=sys.stderr,
        )

    if "pi-eval" in datasets_to_run:
        if not PI_EVAL_PATH.exists():
            print(f"PI-Eval not found: {PI_EVAL_PATH}", file=sys.stderr)
            return 2
        pi_eval_data = load_jsonl(PI_EVAL_PATH)
        print(
            f"[pi-eval] loaded {len(pi_eval_data)} records "
            f"(all attacks, no benigns)",
            file=sys.stderr,
        )

    if "adversarial" in datasets_to_run:
        if not ADVERSARIAL_PATH.exists():
            print(f"Adversarial not found: {ADVERSARIAL_PATH}", file=sys.stderr)
            return 2
        adversarial_data = load_jsonl(ADVERSARIAL_PATH)
        n_att = sum(1 for r in adversarial_data if r.get("label") == "attack")
        n_ben = sum(1 for r in adversarial_data if r.get("label") == "benign")
        print(
            f"[adversarial] loaded {len(adversarial_data)} records "
            f"({n_att} attacks, {n_ben} benigns)",
            file=sys.stderr,
        )

    # ---------- run 3 configs x selected datasets ----------
    total_runs = len(datasets_to_run) * len(RAG_CONFIGS)
    run_idx = 0

    for config_slug, config_payload in RAG_CONFIGS:
        print(
            f"\n{'='*60}\n"
            f"[config] {config_slug}  payload={json.dumps(config_payload)}\n"
            f"{'='*60}",
            file=sys.stderr,
        )

        if "mbench" in datasets_to_run and mbench_attacks is not None:
            run_idx += 1
            print(
                f"\n--- [{run_idx}/{total_runs}] mbench x {config_slug} ---",
                file=sys.stderr,
            )
            run_mbench(
                waf2_url=args.waf2,
                attacks=mbench_attacks,
                benign_sample=mbench_benign_sample,  # type: ignore[arg-type]
                config_slug=config_slug,
                config_payload=config_payload,
                out_dir=out_dir,
            )

        if "pi-eval" in datasets_to_run and pi_eval_data is not None:
            run_idx += 1
            print(
                f"\n--- [{run_idx}/{total_runs}] pi-eval x {config_slug} ---",
                file=sys.stderr,
            )
            run_pi_eval(
                waf2_url=args.waf2,
                dataset=pi_eval_data,
                config_slug=config_slug,
                config_payload=config_payload,
                out_dir=out_dir,
            )

        if "adversarial" in datasets_to_run and adversarial_data is not None:
            run_idx += 1
            print(
                f"\n--- [{run_idx}/{total_runs}] adversarial x {config_slug} ---",
                file=sys.stderr,
            )
            run_adversarial(
                waf2_url=args.waf2,
                dataset=adversarial_data,
                config_slug=config_slug,
                config_payload=config_payload,
                out_dir=out_dir,
            )

    # Restore non-eval config
    _post_config(args.waf2, {"eval_mode": False})

    print(f"\nAll {run_idx} runs complete. Output in {out_dir}/", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
