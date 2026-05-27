"""WAF2 RQ5 performance evaluation harness.

Tools:
  - rq5_driver.py:  httpx async load driver (warmup ladder → steady → cooldown)
  - rq5_sampler.py: psutil/docker stats + /waf2/stats time-series sampler
  - rq5_report.py:  merge inputs → report.md (table 5.8 + routing + per-path)
  - run_rq5.py:     orchestrator (parallel driver+sampler, then report, archive)

Run with `python -m waf2.rag.eval.perf.run_rq5 --help`.
"""
