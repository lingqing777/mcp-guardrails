"""WAF2 RAG 对抗集评估脚本

数据集: waf2/rag/eval/adversarial.jsonl (30 攻击 + 10 良性)
设计目标: LLM 单凭自己难判别 + 包含 RAG 知识库部分覆盖的攻击模式
用途: 验证 RAG 在"刁钻攻击"上的边界 / 找 KB 该补什么类型

用法:
  # 1. 启动 WAF2 + 配 LLM (任意 OpenAI 兼容 API)
  # 2. 跑对照
  python -m waf2.rag.scripts.eval_adversarial --waf2 http://localhost:8081
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve()
PROJECT_ROOT = HERE.parents[3]
DEFAULT_DATASET = PROJECT_ROOT / "waf2" / "rag" / "eval" / "adversarial.jsonl"


def load_dataset(path: Path):
    attacks, benign = [], []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        d = json.loads(line)
        body = d["body"]
        # body 可能是 JSON 串, 解析后传 dict; 也可能是 XML/纯文本, 原样传
        if isinstance(body, str) and body.strip().startswith(("{", "[")):
            try:
                body = json.loads(body)
            except json.JSONDecodeError:
                pass
        sample = (d["tag"], d["method"], d["path"], body, d.get("note", ""), d.get("category", "unknown"))
        (attacks if d["label"] == "attack" else benign).append(sample)
    return attacks, benign


def post_config(waf2_url: str, payload: dict) -> None:
    req = urllib.request.Request(
        f"{waf2_url}/waf2/config",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    urllib.request.urlopen(req, timeout=10).read()


def reset_stats(waf2_url: str) -> None:
    for endpoint in ("/waf2/reset", "/waf2/cache/clear"):
        urllib.request.urlopen(
            urllib.request.Request(f"{waf2_url}{endpoint}", method="POST"),
            timeout=10,
        ).read()


def send_one(waf2_url: str, method: str, path: str, body):
    url = f"{waf2_url}{path}"
    if isinstance(body, str) and body:
        data = body.encode()
        ctype = "application/xml" if body.lstrip().startswith("<") else "text/plain"
        headers = {"Content-Type": ctype}
    elif body is None or body == "":
        data, headers = None, {}
    else:
        data = json.dumps(body).encode()
        headers = {"Content-Type": "application/json"}

    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return False, False, ""
    except urllib.error.HTTPError as he:
        if he.code == 403:
            try:
                err = json.loads(he.read().decode("utf-8", errors="ignore"))
                if err.get("error") == "WAF2 拦截":
                    return True, bool(err.get("rag_augmented")), err.get("category", "")
            except Exception:
                pass
            return True, False, ""
        return False, False, ""
    except Exception:
        return False, False, ""


def run_round(waf2_url: str, rag_on: bool, attacks, benign, label: str):
    post_config(waf2_url, {"rag_enabled": rag_on})
    reset_stats(waf2_url)
    time.sleep(0.5)

    print(f"\n========== {label} ==========")
    print(f"\n【攻击 {len(attacks)} 条】")
    tp = fn = rag_a = 0
    missed = []
    for i, (tag, m, p, b, note, gold) in enumerate(attacks, 1):
        bl, r, cat = send_one(waf2_url, m, p, b)
        rag_a += int(r)
        if bl:
            tp += 1
            mark = "✓" if cat == gold else "?"
            print(f"  [{i:2d}] ✅ BLOCK {tag:<32s} cat={cat:<22s} {mark}  rag={r}")
        else:
            fn += 1
            print(f"  [{i:2d}] ❌ MISS  {tag:<32s} ({note[:40]})")
            missed.append(tag)

    print(f"\n【良性 {len(benign)} 条】")
    fp = tn = rag_b = 0
    falsepos = []
    for i, (tag, m, p, b, note, _) in enumerate(benign, 1):
        bl, r, cat = send_one(waf2_url, m, p, b)
        rag_b += int(r)
        if not bl:
            tn += 1
            print(f"  [{i:2d}] ✅ PASS  {tag:<22s}  rag={r}")
        else:
            fp += 1
            print(f"  [{i:2d}] ❌ FALSE {tag:<22s}  cat={cat}  rag={r}")
            falsepos.append(tag)

    P = tp / max(tp + fp, 1)
    R = tp / max(tp + fn, 1)
    F = 2 * P * R / max(P + R, 1e-9)
    FPR = fp / max(fp + tn, 1)
    return dict(
        label=label, tp=tp, fp=fp, tn=tn, fn=fn,
        P=P, R=R, F=F, FPR=FPR,
        rag_a=rag_a, rag_b=rag_b,
        missed=missed, falsepos=falsepos,
    )


def main():
    parser = argparse.ArgumentParser(description="WAF2 RAG 对抗集 ON/OFF 对照评估")
    parser.add_argument("--waf2", default="http://localhost:8081", help="WAF2 代理地址")
    parser.add_argument("--dataset", default=str(DEFAULT_DATASET), help="对抗集 jsonl 文件")
    args = parser.parse_args()

    dataset_path = Path(args.dataset)
    if not dataset_path.exists():
        print(f"❌ 数据集不存在: {dataset_path}", file=sys.stderr)
        sys.exit(1)

    attacks, benign = load_dataset(dataset_path)
    print(f"加载: 攻击 {len(attacks)} 条, 良性 {len(benign)} 条")

    off = run_round(args.waf2, False, attacks, benign, "RAG OFF")
    on = run_round(args.waf2, True, attacks, benign, "RAG ON")

    print("\n" + "=" * 70)
    print(f"{'指标':<14s} {'OFF':>10s} {'ON':>10s} {'变化':>10s}")
    print("-" * 70)
    for k, kn in [("P", "Precision"), ("R", "Recall"), ("F", "F1"), ("FPR", "FPR")]:
        d = on[k] - off[k]
        s = "+" if d > 0 else ""
        print(f"{kn:<14s} {off[k]:>10.3f} {on[k]:>10.3f} {s}{d:>9.3f}")
    print("-" * 70)
    print(f"攻击拦截:     OFF {off['tp']}/{len(attacks):<3d}  ON {on['tp']}/{len(attacks):<3d}")
    print(f"误拦良性:     OFF {off['fp']}/{len(benign):<3d}  ON {on['fp']}/{len(benign):<3d}")
    print(f"RAG fire 攻击:                        {on['rag_a']}/{len(attacks)} ({100*on['rag_a']/max(len(attacks),1):.0f}%)")
    print(f"RAG fire 良性:                        {on['rag_b']}/{len(benign)} ({100*on['rag_b']/max(len(benign),1):.0f}%)")

    only_off = set(off["missed"]) - set(on["missed"])
    only_on = set(on["missed"]) - set(off["missed"])
    if only_off:
        print(f"\n💡 RAG 救回的攻击 (OFF 漏检 → ON 拦截): {sorted(only_off)}")
    if only_on:
        print(f"\n⚠️  RAG 反而漏的攻击 (OFF 拦截 → ON 漏检): {sorted(only_on)}")
    if not only_off and not only_on:
        print(f"\n📌 RAG 在该集上无差异: 两轮漏检完全一致 → KB 未覆盖该类攻击")
        common_missed = set(off["missed"]) & set(on["missed"])
        if common_missed:
            print(f"   两轮共同漏检 ({len(common_missed)} 条, 提示 KB 该补的类型):")
            for tag in sorted(common_missed):
                print(f"     - {tag}")


if __name__ == "__main__":
    main()
