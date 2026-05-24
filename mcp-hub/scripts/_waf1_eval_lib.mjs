// Shared helpers for WAF1 evaluation harnesses (CSIC / B-0 / future corpora).
//
// What lives here: pure helpers + WAF1 invocation. What stays in each driver:
// dataset loading, sample envelope construction, case_id formula, output JSONL
// schema.

import { createHash } from 'node:crypto';
import { performance } from 'node:perf_hooks';

import {
  setWaf1Enabled,
  resetWaf1State,
  updateWaf1Config,
  validateToolCall,
  getCallHistory,
} from '../src/waf1/index.js';
import {
  checkRules,
  RULES,
  DEFAULT_RULES_ENABLED,
} from '../src/waf1/rules.js';

// ---------- case_id (mirrors waf2/rag/scripts/_eval_cases.py) ----------

export function bodyHash(payload) {
  if (!payload) return '0'.repeat(12);
  return createHash('sha1').update(payload, 'utf8').digest('hex').slice(0, 12);
}

export function stableCaseId(dataset, ...parts) {
  const joined = parts
    .filter((p) => p != null && p !== '')
    .map(String)
    .join(':');
  return joined ? `${dataset}:${joined}` : dataset;
}

// ---------- verdict classification ----------

export function classifyStrictResult(res) {
  // res from checkRules: { allowed:true } or { allowed:false, reason, category, type }
  if (res.allowed) {
    return { blocked: false, category: '', reason: '', detector: '' };
  }
  return {
    blocked: true,
    category: res.category || 'unknown',
    reason: String(res.reason || '').slice(0, 500),
    detector: 'rules',
  };
}

export function classifyFullResult(res) {
  // res from validateToolCall: { allowed:true } or { allowed:false, status, error:{ reason, category, type, ... } }
  if (res.allowed) {
    return { blocked: false, category: '', reason: '', detector: '' };
  }
  const err = res.error || {};
  const category = err.category || 'unknown';
  const detectorMap = {
    secrets: 'secrets',
    pii: 'pii',
    unicode: 'unicode',
    fuzzy: 'fuzzy',
    rbac: 'rbac',
    dynamicPolicy: 'dynamicPolicy',
    callChain: 'callChain',
    rateLimit: 'rateLimit',
  };
  const detector = detectorMap[category] || 'rules';
  return {
    blocked: true,
    category,
    reason: String(err.reason || '').slice(0, 500),
    detector,
  };
}

// ---------- WAF1 invocation ----------

const HTTP_TOOL = 'http_request';

export function setupWaf1ForEval() {
  setWaf1Enabled(true);
  resetWaf1State();
  // raise rate-limit cap so long sequential runs don't trip it
  updateWaf1Config({
    rateLimit: { maxRequests: 1_000_000, windowMs: 60_000, blockDurationMs: 0 },
  });
}

/**
 * Evaluate one args envelope against WAF1.
 *
 * @param {object} args - `tools/call` arguments object (e.g. {url, method, body})
 * @param {'strict'|'full'} variant
 * @param {object} [ctxBase] - context for full pipeline (clientId/userId/source)
 * @returns {{ verdict: object, latency_ms: number }}
 */
export function evaluateWaf1(args, variant, ctxBase) {
  const t0 = performance.now();
  let raw;
  if (variant === 'strict') {
    raw = checkRules(args, RULES, DEFAULT_RULES_ENABLED, { tool: HTTP_TOOL });
  } else {
    const ctx = {
      ...(ctxBase || {}),
      // unique clientId per call so rate-limit buckets never collide
      clientId: `${(ctxBase && ctxBase.clientId) || 'waf1-eval'}-${process.pid}-${Math.random().toString(36).slice(2, 10)}`,
    };
    raw = validateToolCall(HTTP_TOOL, args, ctx);
  }
  const t1 = performance.now();
  const verdict =
    variant === 'strict' ? classifyStrictResult(raw) : classifyFullResult(raw);
  return { verdict, latency_ms: t1 - t0 };
}

export { resetWaf1State };

// ---------- multi-step chain evaluation (M-Bench-Core) ----------

/**
 * Evaluate a chain of tool calls against WAF1 full pipeline, stopping on the
 * first block. All steps share the caller-provided `ctx` so CallChainTracker
 * groups them as one session.
 *
 * Strict variant is meaningful per-step but cannot see cross-step state, so
 * `evaluateChain` always uses the full pipeline (`validateToolCall`). Callers
 * that need a strict-per-step view should call `checkRules` directly.
 *
 * @param {Array<{tool:string,args:object}>} steps
 * @param {{ clientId: string, userId?: string, source?: string }} ctx
 * @returns {{
 *   blocked_at_step: number|null,
 *   outcome: 'blocked'|'passed',
 *   step_verdicts: Array<{step:number, blocked:boolean, category:string, reason:string, detector:string, latency_ms:number, not_evaluated?:boolean}>,
 *   total_latency_ms: number
 * }}
 */
export function evaluateChain(steps, ctx) {
  if (!Array.isArray(steps) || steps.length === 0) {
    return {
      blocked_at_step: null,
      outcome: 'passed',
      step_verdicts: [],
      total_latency_ms: 0,
    };
  }
  if (!ctx || !ctx.clientId) {
    throw new Error('evaluateChain: ctx.clientId is required for CallChainTracker grouping');
  }
  const step_verdicts = [];
  let blocked_at_step = null;
  let total_latency_ms = 0;
  for (let i = 0; i < steps.length; i++) {
    const stepNum = i + 1;
    if (blocked_at_step !== null) {
      step_verdicts.push({
        step: stepNum,
        blocked: false,
        category: '',
        reason: '',
        detector: '',
        latency_ms: 0,
        not_evaluated: true,
      });
      continue;
    }
    const { tool, args } = steps[i];
    const t0 = performance.now();
    const raw = validateToolCall(tool, args || {}, ctx);
    const t1 = performance.now();
    const verdict = classifyFullResult(raw);
    const latency_ms = Math.round((t1 - t0) * 1000) / 1000;
    total_latency_ms += latency_ms;
    step_verdicts.push({
      step: stepNum,
      blocked: verdict.blocked,
      category: verdict.category,
      reason: verdict.reason,
      detector: verdict.detector,
      latency_ms,
    });
    if (verdict.blocked) {
      blocked_at_step = stepNum;
    }
  }
  return {
    blocked_at_step,
    outcome: blocked_at_step !== null ? 'blocked' : 'passed',
    step_verdicts,
    total_latency_ms: Math.round(total_latency_ms * 1000) / 1000,
  };
}

/**
 * Sanity-check that WAF1 callChain history is empty. Use between cases when
 * running multi-step samples so that prior case state does not pollute the
 * current chain's detection.
 */
export function assertWaf1HistoryEmpty() {
  const history = getCallHistory();
  if (history.length !== 0) {
    throw new Error(
      `WAF1 call history not empty (length=${history.length}); call resetWaf1State() before each multi-step case`
    );
  }
}

export { getCallHistory };
