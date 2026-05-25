# Scenario-Playbook

30 end-to-end MCP attack scenarios for thesis chapter 5 RQ1 Part2 evaluation.

- 10 WordPress scenarios
- 10 WooCommerce scenarios
- 10 Supabase scenarios

Each scenario is a 2-4 step call chain. Completely independent from M-Bench-Core.

## Usage

```bash
# WAF1 evaluation (Node.js)
node mcp-hub/scripts/run_waf1_on_scenario_playbook.mjs \
    --jsonl waf2/rag/eval/scenario-playbook/scenarios.jsonl \
    --out-dir waf2/rag/eval/runs/<date>-scenario-playbook/

# WAF2 evaluation (Python)
PYTHONPATH=. python3 -m waf2.rag.scripts.run_waf2_on_scenario_playbook \
    --waf2 http://localhost:8081 \
    --jsonl waf2/rag/eval/scenario-playbook/scenarios.jsonl \
    --out-dir waf2/rag/eval/runs/<date>-scenario-playbook/

# Generate report
PYTHONPATH=. python3 -m waf2.rag.scripts.report_scenario_playbook \
    --waf1-cases <run-dir>/cases-scenario-playbook-waf1-full.jsonl \
    --waf2-cases <run-dir>/cases-scenario-playbook-waf2.jsonl \
    --out <run-dir>/scenario-playbook-summary.md
```
