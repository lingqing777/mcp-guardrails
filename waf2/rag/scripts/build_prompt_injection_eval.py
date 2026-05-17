"""Build a prompt-injection evaluation dataset from internal seed payloads.

Reads the 7 categories defined in waf2/rag/scripts/processors/prompt_injection.py
and wraps each payload into one or more HTTP/JSON-RPC shapes that match how WAF2
would actually see it in production:

  - chat:        POST /chat with {"message": "<payload>"}  (direct user input)
  - response:    POST /api/process-data with an "issue" body containing the
                 payload (simulates indirect injection via tool result content)
  - mcp-rpc:     POST /mcp with a JSON-RPC body (for TOOL_POISONING samples
                 that already ship in that shape)

Output JSONL schema (compatible with eval_adversarial.py / eval_probe_regression.py):
  {
    "label": "attack",
    "category": "prompt_injection",
    "subcategory": "direct_prompt_injection" | ...,
    "wrap": "chat" | "response" | "mcp-rpc",
    "method": "POST",
    "path": "/chat" | "/api/process-data" | "/mcp",
    "body": "<json-encoded body>",
    "tag": "<original tag from prompt_injection.py>"
  }

Usage:
  PYTHONPATH=. python3 -m waf2.rag.scripts.build_prompt_injection_eval \
      --out waf2/rag/eval/prompt-injection-eval.jsonl
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Iterable

from waf2.rag.scripts.processors.prompt_injection import (
    CONTEXT_MANIPULATION,
    DIRECT_INJECTION,
    ENCODED_INJECTION,
    INDIRECT_INJECTION,
    JAILBREAK,
    PROMPT_LEAK,
    TOOL_POISONING,
)

HERE = Path(__file__).resolve()
PROJECT_ROOT = HERE.parents[3]
DEFAULT_OUT = PROJECT_ROOT / "waf2" / "rag" / "eval" / "prompt-injection-eval.jsonl"


def _record(subcategory: str, wrap: str, method: str, path: str, body: str, tag: str) -> dict:
    return {
        "label": "attack",
        "category": "prompt_injection",
        "subcategory": subcategory,
        "wrap": wrap,
        "method": method,
        "path": path,
        "body": body,
        "tag": tag,
    }


def _wrap_chat(payload: str, subcategory: str, tag: str) -> dict:
    body = json.dumps({"message": payload}, ensure_ascii=False)
    return _record(subcategory, "chat", "POST", "/chat", body, tag)


def _wrap_response(payload: str, subcategory: str, tag: str) -> dict:
    # Simulates an agent reading a "ticket" or "issue" whose body has been
    # poisoned with an indirect prompt-injection payload.
    body = json.dumps(
        {
            "issue": {
                "id": 42,
                "title": "Support request",
                "body": payload,
            },
        },
        ensure_ascii=False,
    )
    return _record(subcategory, "response", "POST", "/api/process-data", body, tag)


def _wrap_mcp_rpc(payload: str, subcategory: str, tag: str) -> dict:
    # TOOL_POISONING payloads are already JSON-RPC shaped; if they parse as
    # full JSON-RPC, post the original payload verbatim. Otherwise embed the
    # JSON snippet inside a tools/call params.arguments wrapper.
    stripped = payload.strip()
    if stripped.startswith("{") and ('"jsonrpc"' in stripped or '"method"' in stripped):
        body = stripped
    else:
        body = json.dumps(
            {
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {
                    "name": "wrapper",
                    "arguments": {"raw": payload},
                },
            },
            ensure_ascii=False,
        )
    return _record(subcategory, "mcp-rpc", "POST", "/mcp", body, tag)


def _emit_for_category(
    category_name: str,
    samples: list[tuple[str, str]],
    wraps: Iterable[str],
) -> Iterable[dict]:
    for payload, tag in samples:
        for wrap in wraps:
            if wrap == "chat":
                yield _wrap_chat(payload, category_name, tag)
            elif wrap == "response":
                yield _wrap_response(payload, category_name, tag)
            elif wrap == "mcp-rpc":
                yield _wrap_mcp_rpc(payload, category_name, tag)
            else:
                raise ValueError(f"unknown wrap: {wrap}")


def build_dataset() -> list[dict]:
    records: list[dict] = []
    # DIRECT — direct injection of an instruction; user-input path is the most
    # natural shape. No reason to double up.
    records.extend(_emit_for_category("direct_prompt_injection", DIRECT_INJECTION, ["chat"]))
    # INDIRECT — payload is meant to be embedded in third-party content the
    # agent reads. Cover both: (a) user pastes it as a chat message
    # (transitional case), (b) it arrives as the body of a tool response.
    records.extend(
        _emit_for_category("indirect_prompt_injection", INDIRECT_INJECTION, ["chat", "response"])
    )
    # JAILBREAK / LEAK / ENCODED — direct attacks on the LLM, chat-shaped.
    records.extend(_emit_for_category("jailbreak", JAILBREAK, ["chat"]))
    records.extend(_emit_for_category("prompt_leak", PROMPT_LEAK, ["chat"]))
    records.extend(_emit_for_category("encoded_injection", ENCODED_INJECTION, ["chat"]))
    # TOOL_POISONING — already JSON-RPC; emit as-is on /mcp.
    records.extend(_emit_for_category("tool_poisoning", TOOL_POISONING, ["mcp-rpc"]))
    # CONTEXT — fake-context strings; both chat-paste and tool-response shapes.
    records.extend(_emit_for_category("context_manipulation", CONTEXT_MANIPULATION, ["chat", "response"]))
    return records


def main() -> None:
    parser = argparse.ArgumentParser(description="Build prompt-injection evaluation dataset")
    parser.add_argument("--out", default=str(DEFAULT_OUT), help="Output JSONL path")
    args = parser.parse_args()

    records = build_dataset()
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    # Summary
    by_sub = {}
    by_wrap = {}
    for r in records:
        by_sub[r["subcategory"]] = by_sub.get(r["subcategory"], 0) + 1
        by_wrap[r["wrap"]] = by_wrap.get(r["wrap"], 0) + 1

    print(f"Wrote {len(records)} cases to {out_path}")
    print("\nBy subcategory:")
    for k, v in sorted(by_sub.items()):
        print(f"  {k:35s} {v:4d}")
    print("\nBy wrap:")
    for k, v in sorted(by_wrap.items()):
        print(f"  {k:10s} {v:4d}")


if __name__ == "__main__":
    main()
