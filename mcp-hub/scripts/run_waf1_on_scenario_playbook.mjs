#!/usr/bin/env node
// Scenario-Playbook: WAF1 evaluator.
//
// Reads scenario-playbook/scenarios.jsonl (30 multi-step attack chains),
// evaluates each scenario through the WAF1 full pipeline using evaluateChain()
// with per-scenario clientId for call-chain tracking.
//
// case_id: `sp:waf1-full:<NN>` (2-digit 0-padded row index).
//
// Usage:
//   node mcp-hub/scripts/run_waf1_on_scenario_playbook.mjs \
//       --jsonl waf2/rag/eval/scenario-playbook/scenarios.jsonl \
//       --out-dir waf2/rag/eval/runs/<date>-scenario-playbook/

import { mkdirSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { dirname, resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  setupWaf1ForEval,
  evaluateChain,
  assertWaf1HistoryEmpty,
  resetWaf1State,
} from './_waf1_eval_lib.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// ---------- args ----------

function parseArgs(argv) {
  const args = { jsonl: '', outDir: '' };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    const next = () => argv[++i];
    if (a === '--jsonl') args.jsonl = next();
    else if (a === '--out-dir') args.outDir = next();
    else if (a === '-h' || a === '--help') {
      console.error('usage: node run_waf1_on_scenario_playbook.mjs --jsonl <scenarios.jsonl> --out-dir <dir>');
      process.exit(0);
    } else {
      console.error(`unknown arg: ${a}`);
      process.exit(2);
    }
  }
  if (!args.jsonl || !args.outDir) {
    console.error('usage: node run_waf1_on_scenario_playbook.mjs --jsonl <scenarios.jsonl> --out-dir <dir>');
    process.exit(2);
  }
  return args;
}

// ---------- loader ----------

function loadScenarios(jsonlPath) {
  const text = readFileSync(jsonlPath, 'utf8');
  const rows = [];
  for (const ln of text.split('\n')) {
    const s = ln.trim();
    if (!s) continue;
    rows.push(JSON.parse(s));
  }
  return rows;
}

// ---------- runner ----------

function runWaf1(rows, outDir) {
  const outPath = join(outDir, 'cases-scenario-playbook-waf1-full.jsonl');
  const lines = [];
  const width = Math.max(2, String(rows.length - 1).length);

  for (let i = 0; i < rows.length; i++) {
    const row = rows[i];
    const caseId = `sp:waf1-full:${String(i).padStart(width, '0')}`;
    const clientId = `sp-${row.case_id}`;

    // State isolation
    resetWaf1State();
    assertWaf1HistoryEmpty();

    const ctx = { clientId, userId: 'sp-eval', source: 'scenario-playbook' };
    const steps = row.steps || [];
    const chainResult = evaluateChain(steps, ctx);

    const blockedStep = chainResult.blocked_at_step;
    const blockedVerdict = blockedStep !== null
      ? chainResult.step_verdicts.find((s) => s.step === blockedStep)
      : null;

    const rec = {
      case_id: caseId,
      scenario_case_id: row.case_id,
      dataset: 'scenario-playbook',
      round: 'waf1-full',
      row_index: i,
      label: 'attack',
      family: row.family || 'call_chain',
      subcategory: row.subcategory || '',
      platform: row.platform || '',
      scenario_description: row.scenario_description || '',
      tool: '',
      outcome: chainResult.outcome,
      detected_category: blockedVerdict ? blockedVerdict.category : '',
      detected_namespace: blockedVerdict
        ? (blockedVerdict.category === 'callChain'
          ? `waf1.callChain.${row.expected_chain || 'unknown'}`
          : `waf1.${blockedVerdict.category}`)
        : '',
      reason: blockedVerdict ? blockedVerdict.reason : '',
      detector: blockedVerdict ? blockedVerdict.detector : '',
      latency_ms: chainResult.total_latency_ms,
      expected_chain: row.expected_chain || '',
      expected_block_step: typeof row.expected_block_step === 'number' ? row.expected_block_step : null,
      expected_layer: row.expected_layer || '',
      blocked_at_step: blockedStep,
      is_multi_step: true,
      step_verdicts: chainResult.step_verdicts,
      tag: row.tag || '',
    };

    lines.push(JSON.stringify(rec));

    if ((i + 1) % 10 === 0) {
      process.stderr.write(`[waf1-scenario-playbook] ${i + 1}/${rows.length}\n`);
    }
  }

  writeFileSync(outPath, lines.join('\n') + (lines.length ? '\n' : ''), 'utf8');
  const blocked = lines.filter(l => JSON.parse(l).outcome === 'blocked').length;
  process.stderr.write(
    `[waf1-scenario-playbook] DONE ${blocked}/${rows.length} blocked → ${outPath}\n`
  );
  return { path: outPath, blocked, total: rows.length };
}

// ---------- main ----------

function main() {
  const args = parseArgs(process.argv);
  if (!existsSync(args.jsonl)) {
    console.error(`jsonl not found: ${args.jsonl}`);
    process.exit(2);
  }
  mkdirSync(args.outDir, { recursive: true });
  process.stderr.write(`[waf1-scenario-playbook] loading ${args.jsonl}\n`);
  const rows = loadScenarios(args.jsonl);
  process.stderr.write(`[waf1-scenario-playbook] loaded ${rows.length} scenarios\n`);

  setupWaf1ForEval();
  runWaf1(rows, args.outDir);
  process.stderr.write('[waf1-scenario-playbook] done\n');
}

const invokedDirectly = process.argv[1] && resolve(process.argv[1]) === __filename;
if (invokedDirectly) {
  main();
}

export { main, runWaf1 };
