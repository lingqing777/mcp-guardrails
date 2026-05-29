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
    skipped_layers: list[str] | None = None,
    ablation_label: str = "",
) -> tuple[list[dict], dict[str, list[str]]]:
    """Inner-join 4 rounds + the source dataset on row index.

    dataset_rows is the original JSONL (attacks.jsonl or benign.jsonl) so we
    pass through source-of-truth fields (paired_with, expected_*).

    skipped_layers controls ablation behavior:
      - "waf1" in skipped_layers → WAF1 strict/full rows are NOT required;
        per-case waf1_*.blocked treated as False; waf1_union_blocked = False;
        dual_blocked = waf2_blocked
      - "waf2" in skipped_layers → rag-on/rag-off rows are NOT required;
        per-case rag_*.blocked treated as False; waf2_blocked = False;
        dual_blocked = waf1_union_blocked

    Returns (merged_records, misses_by_layer).
    """
    skipped_layers = list(skipped_layers or [])
    skip_waf1 = "waf1" in skipped_layers
    skip_waf2 = "waf2" in skipped_layers

    ws = _by_key(waf1_strict)
    wf = _by_key(waf1_full)
    ro = _by_key(rag_on)
    rf = _by_key(rag_off)
    ds = {str(i).zfill(max(4, len(str(len(dataset_rows) - 1)))): row
          for i, row in enumerate(dataset_rows)}

    # Common set is the inner-join of the layers that participate in this
    # ablation, plus the dataset. Skipped layers are excluded so their absence
    # doesn't shrink the join.
    participating: list[set[str]] = [set(ds)]
    if not skip_waf1:
        participating.append(set(ws))
        participating.append(set(wf))
    if not skip_waf2:
        participating.append(set(ro))
        # rag_off is OPTIONAL even in non-skip mode (e.g. ablation 6/7 may not
        # have run it); only require it when files exist.
        if rf:
            participating.append(set(rf))
    common = set.intersection(*participating) if participating else set()

    total_layer_keys: set[str] = set()
    if not skip_waf1:
        total_layer_keys |= set(ws) | set(wf)
    if not skip_waf2:
        total_layer_keys |= set(ro) | set(rf)

    misses = {
        "only_strict": sorted(set(ws) - common) if not skip_waf1 else [],
        "only_full": sorted(set(wf) - common) if not skip_waf1 else [],
        "only_rag_on": sorted(set(ro) - common) if not skip_waf2 else [],
        "only_rag_off": sorted(set(rf) - common) if not skip_waf2 and rf else [],
        "only_dataset": sorted(set(ds) - common),
        "missing_dataset": sorted(total_layer_keys - set(ds)),
    }
    misses = {k: v for k, v in misses.items() if v}

    # Stub helpers — return an "all-false" layer outcome for skipped layers.
    def _stub_layer() -> dict:
        return {
            "blocked": False,
            "detected_category": "",
            "detected_namespace": "",
            "latency_ms": 0,
            "blocked_at_step": None,
        }

    merged: list[dict] = []
    for k in sorted(common):
        src = ds[k]
        label = src.get("label", "")
        family = src.get("family", "")
        is_multi = family == "call_chain"

        # WAF1 layer access
        if skip_waf1:
            s = {"outcome": "", "detected_category": "", "detected_namespace": "", "latency_ms": 0, "blocked_at_step": None, "chain_strict_only": False}
            f = {"outcome": "", "detected_category": "", "detected_namespace": "", "latency_ms": 0, "blocked_at_step": None}
            s_blocked = False
            f_blocked = False
        else:
            s = ws[k]
            f = wf[k]
            s_blocked = s.get("outcome") == "blocked"
            f_blocked = f.get("outcome") == "blocked"

        # WAF2 layer access
        if skip_waf2:
            on = {"outcome": "", "detected_category": "", "detected_namespace": "", "latency_ms": 0, "waf2_evaluated_step": None}
            off = {"outcome": "", "detected_category": "", "detected_namespace": "", "latency_ms": 0, "waf2_evaluated_step": None}
            on_blocked = False
            off_blocked = False
        else:
            on = ro[k]
            off = rf.get(k, {"outcome": "", "detected_category": "", "detected_namespace": "", "latency_ms": 0, "waf2_evaluated_step": None, "_stub": True})
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
            "ablation_label": ablation_label,
            "skipped_layers": skipped_layers,
            "waf1_strict": {
                "blocked": s_blocked,
                "detected_category": s.get("detected_category", ""),
                "detected_namespace": s.get("detected_namespace", ""),
                "latency_ms": s.get("latency_ms", 0),
                "blocked_at_step": s.get("blocked_at_step"),
                "chain_strict_only": s.get("chain_strict_only", False),
                **({"_skipped": True} if skip_waf1 else {}),
            },
            "waf1_full": {
                "blocked": f_blocked,
                "detected_category": f.get("detected_category", ""),
                "detected_namespace": f.get("detected_namespace", ""),
                "latency_ms": f.get("latency_ms", 0),
                "blocked_at_step": f.get("blocked_at_step"),
                **({"_skipped": True} if skip_waf1 else {}),
            },
            "rag_on": {
                "blocked": on_blocked,
                "detected_category": on.get("detected_category", ""),
                "detected_namespace": on.get("detected_namespace", ""),
                "latency_ms": on.get("latency_ms", 0),
                "waf2_evaluated_step": on.get("waf2_evaluated_step"),
                "route": on.get("route", ""),
                **({"_skipped": True} if skip_waf2 else {}),
            },
            "rag_off": {
                "blocked": off_blocked,
                "detected_category": off.get("detected_category", ""),
                "detected_namespace": off.get("detected_namespace", ""),
                "latency_ms": off.get("latency_ms", 0),
                "waf2_evaluated_step": off.get("waf2_evaluated_step"),
                "route": off.get("route", ""),
                **({"_skipped": True} if skip_waf2 else {}),
            },
            "waf1_union_blocked": waf1_union_blocked,
            "waf2_blocked": waf2_blocked,
            "dual_blocked": dual_blocked,
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
    *,
    skipped_layers: list[str] | None = None,
    ablation_label: str = "",
) -> tuple[list[dict], dict[str, dict[str, list[str]]]]:
    """Merge all (attacks + benign) splits found in cases_dir."""
    if splits is None:
        splits = ["attacks", "benign"]
    skipped_layers = list(skipped_layers or [])
    skip_waf1 = "waf1" in skipped_layers
    skip_waf2 = "waf2" in skipped_layers

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
        ws_rows = _load_jsonl_optional(ws_path) if not skip_waf1 else []
        wf_rows = _load_jsonl_optional(wf_path) if not skip_waf1 else []
        on_rows = _load_jsonl_optional(on_path) if not skip_waf2 else []
        off_rows = _load_jsonl_optional(off_path) if not skip_waf2 else []
        ds_rows = _load_jsonl(ds_path)
        merged, misses = merge_split(
            waf1_strict=ws_rows,
            waf1_full=wf_rows,
            rag_on=on_rows,
            rag_off=off_rows,
            dataset_rows=ds_rows,
            skipped_layers=skipped_layers,
            ablation_label=ablation_label,
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
    ap.add_argument(
        "--skip-waf1",
        action="store_true",
        help="WAF1-only ablation: do not require WAF1 strict/full jsonl files; "
        "waf1_*.blocked treated as False; dual = waf2_full",
    )
    ap.add_argument(
        "--skip-waf2",
        action="store_true",
        help="WAF2-only ablation: do not require rag-on/rag-off jsonl files; "
        "rag_*.blocked treated as False; dual = waf1_union",
    )
    ap.add_argument(
        "--ablation-label",
        default="",
        help="free-text label written to each merged record's ablation_label field "
        "(e.g. 'WAF1-only', 'Full no-chain')",
    )
    args = ap.parse_args(argv)

    if args.skip_waf1 and args.skip_waf2:
        print(
            "[merge-mbench] error: --skip-waf1 and --skip-waf2 are mutually exclusive "
            "(at least one layer must be evaluated)",
            file=sys.stderr,
        )
        return 2

    skipped_layers: list[str] = []
    if args.skip_waf1:
        skipped_layers.append("waf1")
    if args.skip_waf2:
        skipped_layers.append("waf2")

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

    merged, misses = merge_all_splits(
        cases_dir,
        dataset_dir,
        skipped_layers=skipped_layers,
        ablation_label=args.ablation_label,
    )

    out_path = out_dir / "cases-mbench-merged.jsonl"
    with out_path.open("w", encoding="utf-8") as fh:
        for rec in merged:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")

    misses_path = out_dir / "merge-misses-mbench.json"
    with misses_path.open("w", encoding="utf-8") as fh:
        json.dump(
            {
                "total_merged": len(merged),
                "skipped_layers": skipped_layers,
                "ablation_label": args.ablation_label,
                "misses": misses,
            },
            fh,
            ensure_ascii=False,
            indent=2,
        )

    unmatched_count = sum(
        len(rows) for split_misses in misses.values() for rows in split_misses.values()
    )
    label_segment = f" ablation={args.ablation_label!r}" if args.ablation_label else ""
    skip_segment = f" skipped={skipped_layers}" if skipped_layers else ""
    print(
        f"[merge-mbench]{label_segment}{skip_segment} joined={len(merged)} "
        f"unmatched={unmatched_count} → {out_path}",
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
