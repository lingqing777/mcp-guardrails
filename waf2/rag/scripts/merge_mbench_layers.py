"""M-Bench-Core: merge cases JSONL across layers.

Inner-join the four cases JSONL files emitted by run_waf1_on_mbench.mjs (×2
variants) and run_waf2_on_mbench.py (×2 RAG modes) on the trailing colon
segment of case_id (the row index, 0-based 4-digit-padded).

Inputs (look in CASES_DIR for each dataset split):
  - cases-mbench-<split>-waf1-strict.jsonl
  - cases-mbench-<split>-waf1-full.jsonl
  - cases-mbench-<split>-rag-on.jsonl
  - cases-mbench-<split>-rag-off.jsonl

where <split> is "attacks" or "benign".

Output:
  - cases-mbench-merged.jsonl   (per-case merged record across 4 rounds)
  - merge-misses-mbench.json    (cases that failed cross-layer join)

Each merged record contains:
  - source fields (case_id_orig, label, family, subcategory, tool, args, tag,
    paired_with, source, expected_block_by, expected_chain, expected_block_step)
  - 4 round outcomes (waf1_strict, waf1_full, rag_on, rag_off) with
    {blocked, detected_category, detected_namespace, latency_ms, blocked_at_step}
  - 3 layer aggregates:
      waf1_union  = waf1_strict.blocked OR waf1_full.blocked
      waf2_full   = rag_on.blocked
      dual        = waf1_union.blocked OR waf2_full.blocked
  - TP/FP/TN/FN classification per layer (based on label=attack/benign and
    expected_block_step for multi-step)

See openspec/changes/add-mbench-core-attack-benchmark/design.md (D5) and
openspec/specs/m-bench-core-evaluation/spec.md (Req §3/§4/§7).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

# ---------- IO ----------

def _load_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        raise FileNotFoundError(f"missing: {path}")
    out: list[dict] = []
    with path.open("r", encoding="utf-8") as fh:
        for ln in fh:
            ln = ln.strip()
            if not ln:
                continue
            out.append(json.loads(ln))
    return out


def _load_jsonl_optional(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return _load_jsonl(path)


def _join_key(case_id: str) -> str:
    if not case_id:
        return ""
    return case_id.split(":")[-1]


def _by_key(cases: list[dict]) -> dict[str, dict]:
    return {_join_key(c.get("case_id", "")): c for c in cases}


# ---------- TP/FN/FP/TN classification ----------


def classify_case(
    *,
    label: str,
    blocked: bool,
    is_multi_step: bool,
    expected_block_step: int | None,
    blocked_at_step: int | None,
) -> str:
    """Return one of TP / FN / FP / TN.

    Rules:
      attack + blocked       → TP (for multi-step, blocked_at_step <= expected_block_step
                                  is automatic since first-block stops the chain;
                                  blocked_at_step > expected_block_step would still
                                  count as TP — eventual catch.  Currently the
                                  harness stops on first block, so blocked_at_step
                                  is always <= expected_block_step when present.)
      attack + not_blocked   → FN
      benign + blocked       → FP
      benign + not_blocked   → TN
    """
    is_attack = label == "attack"
    if is_attack and blocked:
        return "TP"
    if is_attack and not blocked:
        return "FN"
    if not is_attack and blocked:
        return "FP"
    return "TN"


# ---------- merge core ----------


def merge_split(
    *,
    waf1_strict: list[dict],
    waf1_full: list[dict],
    rag_on: list[dict],
    rag_off: list[dict],
    dataset_rows: list[dict],
) -> tuple[list[dict], dict[str, list[str]]]:
    """Inner-join 4 rounds + the source dataset on row index.

    dataset_rows is the original JSONL (attacks.jsonl or benign.jsonl) so we
    pass through source-of-truth fields (paired_with, expected_*).

    Returns (merged_records, misses_by_layer).
    """
    ws = _by_key(waf1_strict)
    wf = _by_key(waf1_full)
    ro = _by_key(rag_on)
    rf = _by_key(rag_off)
    ds = {str(i).zfill(max(4, len(str(len(dataset_rows) - 1)))): row
          for i, row in enumerate(dataset_rows)}

    all_keys = set(ws) | set(wf) | set(ro) | set(rf) | set(ds)
    common = set(ws) & set(wf) & set(ro) & set(rf) & set(ds)

    misses = {
        "only_strict": sorted(set(ws) - common),
        "only_full": sorted(set(wf) - common),
        "only_rag_on": sorted(set(ro) - common),
        "only_rag_off": sorted(set(rf) - common),
        "only_dataset": sorted(set(ds) - common),
        "missing_dataset": sorted((set(ws) | set(wf) | set(ro) | set(rf)) - set(ds)),
    }
    misses = {k: v for k, v in misses.items() if v}

    merged: list[dict] = []
    for k in sorted(common):
        src = ds[k]
        s = ws[k]
        f = wf[k]
        on = ro[k]
        off = rf[k]
        label = src.get("label", "")
        family = src.get("family", "")
        is_multi = family == "call_chain"

        # WAF1 outcomes — strict on multi-step is "not applicable" but still
        # emitted by the harness; we honor its blocked flag for the union.
        s_blocked = s.get("outcome") == "blocked"
        f_blocked = f.get("outcome") == "blocked"
        on_blocked = on.get("outcome") == "blocked"
        off_blocked = off.get("outcome") == "blocked"

        waf1_union_blocked = s_blocked or f_blocked
        waf2_blocked = on_blocked
        dual_blocked = waf1_union_blocked or waf2_blocked

        expected_block_step = src.get("expected_block_step") if is_multi else None

        record = {
            "case_id": f"mbench:merged:{k}",
            "case_id_orig": src.get("case_id", ""),
            "row_index": int(k) if k.isdigit() else -1,
            "label": label,
            "family": family,
            "subcategory": src.get("subcategory", ""),
            "tool": src.get("tool", "") if not is_multi else "",
            "args": src.get("args") if not is_multi else None,
            "steps": src.get("steps") if is_multi else None,
            "tag": src.get("tag", ""),
            "paired_with": src.get("paired_with"),
            "source": src.get("source"),
            "expected_block_by": src.get("expected_block_by"),
            "expected_chain": src.get("expected_chain") if is_multi else None,
            "expected_block_step": expected_block_step,
            "is_multi_step": is_multi,
            "waf1_strict": {
                "blocked": s_blocked,
                "detected_category": s.get("detected_category", ""),
                "detected_namespace": s.get("detected_namespace", ""),
                "latency_ms": s.get("latency_ms", 0),
                "blocked_at_step": s.get("blocked_at_step"),
                "chain_strict_only": s.get("chain_strict_only", False),
            },
            "waf1_full": {
                "blocked": f_blocked,
                "detected_category": f.get("detected_category", ""),
                "detected_namespace": f.get("detected_namespace", ""),
                "latency_ms": f.get("latency_ms", 0),
                "blocked_at_step": f.get("blocked_at_step"),
            },
            "rag_on": {
                "blocked": on_blocked,
                "detected_category": on.get("detected_category", ""),
                "detected_namespace": on.get("detected_namespace", ""),
                "latency_ms": on.get("latency_ms", 0),
                "waf2_evaluated_step": on.get("waf2_evaluated_step"),
            },
            "rag_off": {
                "blocked": off_blocked,
                "detected_category": off.get("detected_category", ""),
                "detected_namespace": off.get("detected_namespace", ""),
                "latency_ms": off.get("latency_ms", 0),
                "waf2_evaluated_step": off.get("waf2_evaluated_step"),
            },
            # derived layers (used by the report aggregator)
            "waf1_union_blocked": waf1_union_blocked,
            "waf2_blocked": waf2_blocked,
            "dual_blocked": dual_blocked,
            # confusion classification per layer
            "classification": {
                "waf1_strict": classify_case(
                    label=label,
                    blocked=s_blocked,
                    is_multi_step=is_multi,
                    expected_block_step=expected_block_step,
                    blocked_at_step=s.get("blocked_at_step"),
                ),
                "waf1_full": classify_case(
                    label=label,
                    blocked=f_blocked,
                    is_multi_step=is_multi,
                    expected_block_step=expected_block_step,
                    blocked_at_step=f.get("blocked_at_step"),
                ),
                "waf1_union": classify_case(
                    label=label,
                    blocked=waf1_union_blocked,
                    is_multi_step=is_multi,
                    expected_block_step=expected_block_step,
                    blocked_at_step=None,
                ),
                "rag_on": classify_case(
                    label=label,
                    blocked=on_blocked,
                    is_multi_step=is_multi,
                    expected_block_step=expected_block_step,
                    blocked_at_step=None,
                ),
                "rag_off": classify_case(
                    label=label,
                    blocked=off_blocked,
                    is_multi_step=is_multi,
                    expected_block_step=expected_block_step,
                    blocked_at_step=None,
                ),
                "dual": classify_case(
                    label=label,
                    blocked=dual_blocked,
                    is_multi_step=is_multi,
                    expected_block_step=expected_block_step,
                    blocked_at_step=None,
                ),
            },
        }
        merged.append(record)
    return merged, misses


def merge_all_splits(
    cases_dir: Path,
    dataset_dir: Path,
    splits: list[str] = None,
) -> tuple[list[dict], dict[str, dict[str, list[str]]]]:
    """Merge all (attacks + benign) splits found in cases_dir."""
    if splits is None:
        splits = ["attacks", "benign"]
    all_merged: list[dict] = []
    all_misses: dict[str, dict[str, list[str]]] = {}
    for split in splits:
        ws_path = cases_dir / f"cases-mbench-{split}-waf1-strict.jsonl"
        wf_path = cases_dir / f"cases-mbench-{split}-waf1-full.jsonl"
        on_path = cases_dir / f"cases-mbench-{split}-rag-on.jsonl"
        off_path = cases_dir / f"cases-mbench-{split}-rag-off.jsonl"
        ds_path = dataset_dir / f"{split}.jsonl"
        if not ds_path.exists():
            print(f"[merge-mbench] skipping {split} — dataset {ds_path} not found",
                  file=sys.stderr)
            continue
        # Allow each split to be present partially; missing files become empty.
        ws_rows = _load_jsonl_optional(ws_path)
        wf_rows = _load_jsonl_optional(wf_path)
        on_rows = _load_jsonl_optional(on_path)
        off_rows = _load_jsonl_optional(off_path)
        ds_rows = _load_jsonl(ds_path)
        merged, misses = merge_split(
            waf1_strict=ws_rows,
            waf1_full=wf_rows,
            rag_on=on_rows,
            rag_off=off_rows,
            dataset_rows=ds_rows,
        )
        for rec in merged:
            rec["split"] = split
        all_merged.extend(merged)
        if misses:
            all_misses[split] = misses
    return all_merged, all_misses


# ---------- main ----------


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--cases-dir",
        required=True,
        help="directory containing cases-mbench-<split>-<round>.jsonl files",
    )
    ap.add_argument(
        "--dataset-dir",
        required=True,
        help="directory containing attacks.jsonl + benign.jsonl (m-bench-core or pilot/)",
    )
    ap.add_argument(
        "--out-dir",
        required=True,
        help="output directory for cases-mbench-merged.jsonl and merge-misses-mbench.json",
    )
    args = ap.parse_args(argv)

    cases_dir = Path(args.cases_dir)
    dataset_dir = Path(args.dataset_dir)
    out_dir = Path(args.out_dir)
    if not cases_dir.is_dir():
        print(f"not a directory: {cases_dir}", file=sys.stderr)
        return 2
    if not dataset_dir.is_dir():
        print(f"not a directory: {dataset_dir}", file=sys.stderr)
        return 2
    out_dir.mkdir(parents=True, exist_ok=True)

    merged, misses = merge_all_splits(cases_dir, dataset_dir)

    out_path = out_dir / "cases-mbench-merged.jsonl"
    with out_path.open("w", encoding="utf-8") as fh:
        for rec in merged:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")

    misses_path = out_dir / "merge-misses-mbench.json"
    with misses_path.open("w", encoding="utf-8") as fh:
        json.dump(
            {"total_merged": len(merged), "misses": misses},
            fh,
            ensure_ascii=False,
            indent=2,
        )

    unmatched_count = sum(
        len(rows) for split_misses in misses.values() for rows in split_misses.values()
    )
    print(
        f"[merge-mbench] joined={len(merged)} unmatched={unmatched_count} "
        f"→ {out_path}",
        file=sys.stderr,
    )
    if unmatched_count > 0:
        print(
            f"[merge-mbench] warning: {unmatched_count} cases failed cross-layer join "
            f"— see {misses_path}",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
