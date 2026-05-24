#!/usr/bin/env node
// M-Bench-Core (MCP-native attack benchmark): WAF1 evaluator.
//
// Reads waf2/rag/eval/m-bench-core/{attacks,benign}.jsonl, dispatches each
// record to single-step or multi-step evaluation based on `family`:
//   - char_injection / prompt_injection_and_priv_esc (single-step) →
//     evaluateWaf1(args, variant, ctx) — uses the args object as-is, no
//     http_request wrapping.
//   - call_chain (multi-step) → evaluateChain(steps, ctx) — runs steps in
//     order through the WAF1 full pipeline with a per-case clientId; the
//     CallChainTracker decides when to block.
//
// case_id: `mbc:waf1-<variant>:<NNNN>` (4-digit 0-padded row index).
//
// State isolation: between every case the harness calls resetWaf1State() +
// assertWaf1HistoryEmpty() so CallChainTracker history from one case never
// leaks into the next.
//
// Strict variant is undefined for multi-step (no per-step strict scan can
// observe chain state). For chains, strict output records the
// `checkRules`-per-step union but tags `chain_strict_only=true`; the merge
// script ignores strict on chains and uses only full.
//
// See openspec/changes/add-mbench-core-attack-benchmark/design.md (D2, D9)
// and openspec/specs/m-bench-core-evaluation/spec.md (Req §4).

import { mkdirSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { dirname, resolve, join, basename } from 'node:path';
import { fileURLToPath } from 'node:url';
import { performance } from 'node:perf_hooks';

import {
  checkRules,
  RULES,
  DEFAULT_RULES_ENABLED,
} from '../src/waf1/rules.js';
import { validateToolCall } from '../src/waf1/index.js';

import {
  stableCaseId,
  classifyStrictResult,
  classifyFullResult,
  setupWaf1ForEval,
  evaluateChain,
  assertWaf1HistoryEmpty,
  resetWaf1State,
} from './_waf1_eval_lib.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// ---------- args ----------

function parseArgs(argv) {
  const args = { jsonl: '', variant: 'both', outDir: '' };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    const next = () => argv[++i];
    if (a === '--jsonl') args.jsonl = next();
    else if (a === '--variant') args.variant = next();
    else if (a === '--out-dir') args.outDir = next();
    else if (a === '-h' || a === '--help') {
      printHelp();
      process.exit(0);
    } else {
      console.error(`unknown arg: ${a}`);
      process.exit(2);
    }
  }
  if (!args.jsonl || !args.outDir) {
    printHelp();
    process.exit(2);
  }
  return args;
}

function printHelp() {
  console.error(
    `usage: node run_waf1_on_mbench.mjs --jsonl <attacks.jsonl|benign.jsonl> --out-dir <dir> [--variant strict|full|both]`
  );
}

// ---------- dataset loader ----------

export function loadMbench(jsonlPath) {
  const text = readFileSync(jsonlPath, 'utf8');
  const rows = [];
  for (const ln of text.split('\n')) {
    const s = ln.trim();
    if (!s) continue;
    rows.push(JSON.parse(s));
  }
  return rows;
}

// ---------- classification helpers ----------

const RULE_CATEGORY_TO_NAMESPACE = {
  sqlInjection: 'waf1.sqlInjection',
  shellInjection: 'waf1.shellInjection',
  xss: 'waf1.xss',
  pathTraversal: 'waf1.pathTraversal',
  sensitiveFiles: 'waf1.sensitiveFiles',
  protocolAttacks: 'waf1.protocolAttacks',
  dataExfiltration: 'waf1.dataExfiltration',
  dangerousOperations: 'waf1.dangerousOperations',
  ssrf: 'waf1.ssrf',
  injectionOther: 'waf1.injectionOther',
  secrets: 'waf1.secrets',
  pii: 'waf1.pii',
  unicode: 'waf1.unicode',
  fuzzy: 'waf1.fuzzy',
  rbac: 'waf1.rbac',
  dynamicPolicy: 'waf1.dynamicPolicy',
  rateLimit: 'waf1.rateLimit',
};

function detectedNamespace(verdict, chainName) {
  if (!verdict || !verdict.blocked) return '';
  if (verdict.category === 'callChain') {
    return chainName
      ? `waf1.callChain.${chainName}`
      : 'waf1.callChain.unknown';
  }
  return RULE_CATEGORY_TO_NAMESPACE[verdict.category] || `waf1.${verdict.category || 'unknown'}`;
}

function inferChainNameFromReason(reason) {
  // CallChainTracker reasons typically include the chain name; best-effort parse.
  // Falls back to '' if not detectable; downstream merge then keeps generic namespace.
  if (!reason) return '';
  for (const name of [
    'supabase_lethal_trifecta',
    'credential_theft',
    'data_exfiltration',
    'recon_then_exploit',
    'prompt_injection_to_exfil',
  ]) {
    if (reason.includes(name)) return name;
  }
  return '';
}

// ---------- envelope (single-step) ----------

function buildBaseCtx(caseId) {
  // Per-case unique clientId keeps each case isolated from prior history.
  // For multi-step cases, the chain uses one stable clientId per case so
  // CallChainTracker groups its steps as one session.
  return {
    clientId: `mbench-${caseId}`,
    userId: 'mbench-anon',
    source: 'mbench-eval',
  };
}

// ---------- single-step evaluation ----------

// For single-step records, the M-Bench-Core sample IS the tools/call envelope
// — args is the full arguments object. We pass it directly to WAF1 (no
// http_request wrapping). Strict variant uses checkRules with the actual
// `tool` from the record for context; full uses validateToolCall.

export function evaluateSingleStep(row, variant, ctx) {
  const { tool, args } = row;
  const argsObj = args || {};
  const t0 = performance.now();
  let raw;
  if (variant === 'strict') {
    raw = checkRules(argsObj, RULES, DEFAULT_RULES_ENABLED, { tool });
  } else {
    raw = validateToolCall(tool, argsObj, ctx);
  }
  const t1 = performance.now();
  const verdict = variant === 'strict'
    ? classifyStrictResult(raw)
    : classifyFullResult(raw);
  return { verdict, latency_ms: Math.round((t1 - t0) * 1000) / 1000 };
}

// ---------- record building ----------

export function buildSingleStepRecord({
  caseId, row, index, variant, latency_ms, verdict,
}) {
  return {
    case_id: caseId,
    dataset: 'mbench',
    round: `waf1-${variant}`,
    row_index: index,
    label: row.label || 'attack',
    family: row.family || '',
    subcategory: row.subcategory || '',
    tool: row.tool || '',
    outcome: verdict.blocked ? 'blocked' : 'passed',
    detected_category: verdict.category || '',
    detected_namespace: detectedNamespace(verdict, inferChainNameFromReason(verdict.reason)),
    reason: verdict.reason || '',
    detector: verdict.detector || '',
    latency_ms,
    waf1_variant: variant,
    expected_block_by: Array.isArray(row.expected_block_by) ? row.expected_block_by : null,
    paired_with: row.paired_with || null,
    source: row.source || null,
    tag: row.tag || '',
    blocked_at_step: null,
    is_multi_step: false,
  };
}

export function buildMultiStepRecord({
  caseId, row, index, variant, chainResult,
}) {
  const blockedStep = chainResult.blocked_at_step;
  const blockedVerdict = blockedStep !== null
    ? chainResult.step_verdicts.find((s) => s.step === blockedStep)
    : null;
  const chainNameFromReason = blockedVerdict
    ? inferChainNameFromReason(blockedVerdict.reason)
    : '';
  const namespace = blockedVerdict
    ? detectedNamespace(blockedVerdict, chainNameFromReason || row.expected_chain)
    : '';
  return {
    case_id: caseId,
    dataset: 'mbench',
    round: `waf1-${variant}`,
    row_index: index,
    label: row.label || 'attack',
    family: row.family || 'call_chain',
    subcategory: row.subcategory || '',
    tool: '',
    outcome: chainResult.outcome,
    detected_category: blockedVerdict ? blockedVerdict.category : '',
    detected_namespace: namespace,
    reason: blockedVerdict ? blockedVerdict.reason : '',
    detector: blockedVerdict ? blockedVerdict.detector : '',
    latency_ms: chainResult.total_latency_ms,
    waf1_variant: variant,
    expected_chain: row.expected_chain || '',
    expected_block_step: typeof row.expected_block_step === 'number'
      ? row.expected_block_step
      : null,
    blocked_at_step: blockedStep,
    is_multi_step: true,
    step_verdicts: chainResult.step_verdicts,
    tag: row.tag || '',
    // strict variant cannot observe chain state; mark when emitted for strict.
    chain_strict_only: variant === 'strict' ? true : false,
  };
}

// ---------- runner ----------

function runVariant({ rows, variant, outDir, sourceJsonl }) {
  const round = `waf1-${variant}`;
  const baseName = basename(sourceJsonl, '.jsonl');
  const outPath = join(outDir, `cases-mbench-${baseName}-${round}.jsonl`);
  const lines = [];
  let tp = 0;
  let fp = 0;
  let tn = 0;
  let fn = 0;
  const width = String(rows.length - 1).length < 4 ? 4 : String(rows.length - 1).length;

  for (let i = 0; i < rows.length; i++) {
    const row = rows[i];
    const isMultiStep = row.family === 'call_chain';
    const caseIdSuffix = String(i).padStart(width, '0');
    const caseId = stableCaseId('mbench', round, caseIdSuffix);
    const ctx = buildBaseCtx(caseId);

    // State isolation: every case starts fresh.
    resetWaf1State();
    assertWaf1HistoryEmpty();

    let rec;
    if (isMultiStep) {
      if (variant === 'strict') {
        // Strict cannot see chain state. Emit a placeholder so case_id alignment
        // is preserved across variants, but mark chain_strict_only=true so
        // merge can treat strict-on-chain as "not applicable".
        const chainSteps = Array.isArray(row.steps) ? row.steps : [];
        const stepVerdicts = chainSteps.map((s, idx) => {
          const t0 = performance.now();
          const raw = checkRules(s.args || {}, RULES, DEFAULT_RULES_ENABLED, { tool: s.tool });
          const t1 = performance.now();
          const v = classifyStrictResult(raw);
          return {
            step: idx + 1,
            blocked: v.blocked,
            category: v.category,
            reason: v.reason,
            detector: v.detector,
            latency_ms: Math.round((t1 - t0) * 1000) / 1000,
          };
        });
        const firstBlocked = stepVerdicts.find((s) => s.blocked);
        rec = buildMultiStepRecord({
          caseId,
          row,
          index: i,
          variant,
          chainResult: {
            blocked_at_step: firstBlocked ? firstBlocked.step : null,
            outcome: firstBlocked ? 'blocked' : 'passed',
            step_verdicts: stepVerdicts,
            total_latency_ms: stepVerdicts.reduce((acc, s) => acc + s.latency_ms, 0),
          },
        });
      } else {
        const chainResult = evaluateChain(row.steps || [], ctx);
        rec = buildMultiStepRecord({ caseId, row, index: i, variant, chainResult });
      }
    } else {
      const { verdict, latency_ms } = evaluateSingleStep(row, variant, ctx);
      rec = buildSingleStepRecord({
        caseId, row, index: i, variant, latency_ms, verdict,
      });
    }

    lines.push(JSON.stringify(rec));

    // Tally confusion (treats `label` as ground truth for both attacks.jsonl
    // and benign.jsonl runs)
    const isAttack = row.label === 'attack';
    const isBlocked = rec.outcome === 'blocked';
    if (isAttack && isBlocked) tp++;
    else if (isAttack && !isBlocked) fn++;
    else if (!isAttack && isBlocked) fp++;
    else tn++;

    if ((i + 1) % 50 === 0) {
      process.stderr.write(
        `[waf1-mbench-${variant}] ${i + 1}/${rows.length}\n`
      );
    }
  }

  writeFileSync(outPath, lines.join('\n') + (lines.length ? '\n' : ''), 'utf8');
  const recall = (tp + fn) ? tp / (tp + fn) : 0;
  const precision = (tp + fp) ? tp / (tp + fp) : 0;
  const fpr = (fp + tn) ? fp / (fp + tn) : 0;
  process.stderr.write(
    `[waf1-mbench-${variant}] DONE TP=${tp} FN=${fn} FP=${fp} TN=${tn} ` +
    `recall=${recall.toFixed(3)} precision=${precision.toFixed(3)} ` +
    `FPR=${fpr.toFixed(3)} → ${outPath}\n`
  );
  return { path: outPath, counts: { tp, fn, fp, tn } };
}

// ---------- main ----------

function main() {
  const args = parseArgs(process.argv);
  if (!existsSync(args.jsonl)) {
    console.error(`jsonl not found: ${args.jsonl}`);
    process.exit(2);
  }
  mkdirSync(args.outDir, { recursive: true });
  process.stderr.write(`[waf1-mbench] loading ${args.jsonl}\n`);
  const rows = loadMbench(args.jsonl);
  process.stderr.write(`[waf1-mbench] loaded ${rows.length} rows\n`);

  setupWaf1ForEval();
  const variants = args.variant === 'both' ? ['strict', 'full'] : [args.variant];
  for (const v of variants) {
    if (!['strict', 'full'].includes(v)) {
      console.error(`unknown variant: ${v}`);
      process.exit(2);
    }
    runVariant({ rows, variant: v, outDir: args.outDir, sourceJsonl: args.jsonl });
  }
  process.stderr.write(`[waf1-mbench] done\n`);
}

const invokedDirectly = process.argv[1] && resolve(process.argv[1]) === __filename;
if (invokedDirectly) {
  main();
}

export {
  main,
  runVariant,
  detectedNamespace,
  inferChainNameFromReason,
};
