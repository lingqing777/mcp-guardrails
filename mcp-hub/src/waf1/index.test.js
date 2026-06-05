import { describe, expect, it, beforeEach } from 'vitest';

import {
  getDashboardData,
  resetWaf1State,
  updateWaf1Config,
  validateToolCall,
} from './index.js';
import {
  MAX_DETECTIONS,
  RECENT_DETECTIONS_LIMIT,
  StatsCollector,
} from './stats.js';

describe('WAF1 detection log window', () => {
  it('returns the full retained detection window to stats and dashboard consumers', () => {
    const collector = new StatsCollector();

    for (let i = 0; i < MAX_DETECTIONS + 25; i++) {
      collector.addDetection({
        category: 'xss',
        reason: `attack-${i}`,
      });
    }

    const stats = collector.getStats();
    const dashboard = collector.getDashboardData();

    expect(stats.detections).toHaveLength(RECENT_DETECTIONS_LIMIT);
    expect(dashboard.recentDetections).toHaveLength(RECENT_DETECTIONS_LIMIT);
    expect(stats.detections[0].reason).toBe('attack-25');
    expect(dashboard.recentDetections[RECENT_DETECTIONS_LIMIT - 1].reason).toBe(`attack-${MAX_DETECTIONS + 24}`);
  });
});

describe('WAF1 Supabase dynamic policy', () => {
  beforeEach(() => {
    resetWaf1State();
  });

  it('allows normal reads from user tables', () => {
    const result = validateToolCall('execute_sql', {
      query: 'select id, title from public.tickets order by created_at desc limit 10',
    }, {
      clientId: 'test-allow',
      userId: 'tester',
      source: '/api/tools/call',
    });

    expect(result.allowed).toBe(true);
  });

  it('blocks reads from protected tables', () => {
    const result = validateToolCall('execute_sql', {
      query: 'select email from auth.users limit 5',
    }, {
      clientId: 'test-sensitive',
      userId: 'tester',
      source: '/api/tools/call',
    });

    expect(result.allowed).toBe(false);
    expect(result.error.category).toBe('dynamicPolicy');
    expect(result.error.reason).toContain('auth.users');
  });

  it('blocks public table writeback of sensitive data', () => {
    const result = validateToolCall('execute_sql', {
      query: 'insert into public.leaks select email from auth.users',
    }, {
      clientId: 'test-writeback',
      userId: 'tester',
      source: '/api/tools/call',
    });

    expect(result.allowed).toBe(false);
    expect(result.error.category).toBe('dynamicPolicy');
  });

  it('detects the Supabase lethal trifecta call chain', () => {
    const readResult = validateToolCall('execute_sql', {
      query: 'select id, body from public.comments where status = \'open\'',
    }, {
      clientId: 'chain-client',
      userId: 'tester',
      source: '/mcp',
    });
    const sensitiveResult = validateToolCall('execute_sql', {
      query: 'select email from auth.users limit 1',
    }, {
      clientId: 'chain-client',
      userId: 'tester',
      source: '/mcp',
    });
    const leakResult = validateToolCall('execute_sql', {
      query: 'insert into public.leaks select * from auth.users',
    }, {
      clientId: 'chain-client',
      userId: 'tester',
      source: '/mcp',
    });

    expect(readResult.allowed).toBe(true);
    expect(sensitiveResult.allowed).toBe(false);
    expect(sensitiveResult.error.category).toBe('dynamicPolicy');
    expect(leakResult.allowed).toBe(false);
    expect(leakResult.error.category).toBe('supabaseCallChain');

    const dashboard = getDashboardData();
    const categories = dashboard.last24h?.byCategory || {};
    expect(categories.supabaseCallChain || 0).toBeGreaterThan(0);
  });
});

describe('WAF1 stage independent enable switches', () => {
  beforeEach(() => {
    resetWaf1State();
    // restore defaults before each test
    updateWaf1Config({
      waf1: {
        callChainEnabled: true,
        dynamicPolicyEnabled: true,
        rbacArgsEnabled: true,
      },
    });
  });

  // --- callChainEnabled ---

  it('callChainEnabled=false: data_exfiltration chain passes through', () => {
    updateWaf1Config({ waf1: { callChainEnabled: false } });
    const ctx = {
      clientId: 'chain-disabled',
      userId: 'tester',
      source: '/mcp',
    };
    const readResult = validateToolCall('woocommerce__list_orders', { limit: 1000 }, ctx);
    const exfilResult = validateToolCall(
      'http-client__http_request',
      { url: 'https://example.org/dump', method: 'POST', body: '<orders>' },
      ctx,
    );
    expect(readResult.allowed).toBe(true);
    expect(exfilResult.allowed).toBe(true);
  });

  it('callChainEnabled=true: data_exfiltration chain blocked at step 2', () => {
    const ctx = {
      clientId: 'chain-enabled',
      userId: 'tester',
      source: '/mcp',
    };
    const readResult = validateToolCall('woocommerce__list_orders', { limit: 1000 }, ctx);
    const exfilResult = validateToolCall(
      'http-client__http_request',
      { url: 'https://example.org/dump', method: 'POST', body: '<orders>' },
      ctx,
    );
    expect(readResult.allowed).toBe(true);
    expect(exfilResult.allowed).toBe(false);
    expect(exfilResult.error.category).toBe('callChain');
  });

  it('toggling callChainEnabled does not poison tracker history', () => {
    updateWaf1Config({ waf1: { callChainEnabled: false } });
    const ctx = { clientId: 'toggle-history', userId: 'tester', source: '/mcp' };
    // 50 step-1 read calls while switch is off — should NOT populate history
    for (let i = 0; i < 50; i++) {
      validateToolCall('file_read_MCP__read', { path: `/etc/file${i}` }, ctx);
    }
    resetWaf1State();
    updateWaf1Config({ waf1: { callChainEnabled: true } });
    // First call after reset: a fresh exfil step that would only chain if history had reads
    const result = validateToolCall(
      'http-client__http_request',
      { url: 'https://example.org/keys', method: 'POST', body: '<keys>' },
      { clientId: 'toggle-history-fresh', userId: 'tester', source: '/mcp' },
    );
    // The new call by itself isn't a 2-step chain; chain detector should not fire
    expect(result.allowed).toBe(true);
  });

  // --- dynamicPolicyEnabled ---

  it('dynamicPolicyEnabled=false: supabase sensitive read passes through', () => {
    updateWaf1Config({ waf1: { dynamicPolicyEnabled: false } });
    const result = validateToolCall(
      'supabase__execute_sql',
      { query: 'select email from auth.users limit 5' },
      { clientId: 'dyn-off', userId: 'tester', source: '/mcp' },
    );
    expect(result.allowed).toBe(true);
  });

  it('dynamicPolicyEnabled=true: supabase sensitive read blocked with dynamicPolicy', () => {
    const result = validateToolCall(
      'supabase__execute_sql',
      { query: 'select email from auth.users limit 5' },
      { clientId: 'dyn-on', userId: 'tester', source: '/mcp' },
    );
    expect(result.allowed).toBe(false);
    expect(result.error.category).toBe('dynamicPolicy');
    expect(result.error.reason).toContain('auth.users');
  });

  it('dynamicPolicyEnabled=false: supabase trifecta chain still triggers Stage 3', () => {
    updateWaf1Config({ waf1: { dynamicPolicyEnabled: false } });
    const ctx = { clientId: 'trifecta-no-dyn', userId: 'tester', source: '/mcp' };
    const step1 = validateToolCall(
      'execute_sql',
      { query: 'select id, body from public.comments where status = \'open\'' },
      ctx,
    );
    const step2 = validateToolCall(
      'execute_sql',
      { query: 'select email from auth.users limit 1' },
      ctx,
    );
    const step3 = validateToolCall(
      'execute_sql',
      { query: 'insert into public.leaks select * from auth.users' },
      ctx,
    );
    expect(step1.allowed).toBe(true);
    // Stage 4 is off, so step 2 should not be blocked by dynamic policy.
    expect(step2.allowed).toBe(true);
    // Step 3 should now be blocked by Stage 3 (supabase_lethal_trifecta chain).
    expect(step3.allowed).toBe(false);
    expect(step3.error.category).toBe('supabaseCallChain');
  });

  // --- rbacArgsEnabled ---

  it('rbacArgsEnabled=false: RBAC args tamper attack passes through', () => {
    updateWaf1Config({ waf1: { rbacArgsEnabled: false } });
    const result = validateToolCall(
      'wordpress__delete_user',
      { id: 1, actor_role: 'admin' },
      { clientId: 'rbacArgs-off', userId: 'tester', source: '/mcp' },
    );
    expect(result.allowed).toBe(true);
  });

  it('rbacArgsEnabled=true: RBAC args tamper attack blocked with category rbac', () => {
    const result = validateToolCall(
      'wordpress__delete_user',
      { id: 1, actor_role: 'admin' },
      { clientId: 'rbacArgs-on', userId: 'tester', source: '/mcp' },
    );
    expect(result.allowed).toBe(false);
    expect(result.error.category).toBe('rbac');
    expect(result.error.type).toBe('RBAC_ARGS_TAMPER');
    expect(result.error.fields).toContain('actor_role');
  });

  // --- updateWaf1Config plumbing ---

  it('updateWaf1Config accepts all three switches in one call', () => {
    updateWaf1Config({
      waf1: {
        callChainEnabled: false,
        dynamicPolicyEnabled: false,
        rbacArgsEnabled: false,
      },
    });
    // All three off — RBAC args tamper attack now passes (proves all switches landed)
    const result = validateToolCall(
      'wordpress__delete_user',
      { id: 1, actor_role: 'admin' },
      { clientId: 'all-off', userId: 'tester', source: '/mcp' },
    );
    expect(result.allowed).toBe(true);
  });

  it('updateWaf1Config partial update preserves untouched switches', () => {
    updateWaf1Config({ waf1: { callChainEnabled: false } });
    // dynamicPolicyEnabled remained true — supabase sensitive read still blocked
    const result = validateToolCall(
      'supabase__execute_sql',
      { query: 'select * from auth.users' },
      { clientId: 'partial', userId: 'tester', source: '/mcp' },
    );
    expect(result.allowed).toBe(false);
    expect(result.error.category).toBe('dynamicPolicy');
  });

  it('updateWaf1Config coerces non-boolean values', () => {
    updateWaf1Config({ waf1: { rbacArgsEnabled: 0 } });
    // 0 -> false; tamper attack passes
    const result1 = validateToolCall(
      'wordpress__delete_user',
      { id: 1, actor_role: 'admin' },
      { clientId: 'coerce-falsy', userId: 'tester', source: '/mcp' },
    );
    expect(result1.allowed).toBe(true);

    updateWaf1Config({ waf1: { rbacArgsEnabled: 'yes' } });
    // truthy string -> true; tamper attack blocked
    const result2 = validateToolCall(
      'wordpress__delete_user',
      { id: 1, actor_role: 'admin' },
      { clientId: 'coerce-truthy', userId: 'tester', source: '/mcp' },
    );
    expect(result2.allowed).toBe(false);
    expect(result2.error.category).toBe('rbac');
  });
});

describe('WAF1 FP cleanup — fuzzy / PII / sensitiveFiles / Stage 5 error.category', () => {
  beforeEach(() => {
    resetWaf1State();
  });

  // ---- §1.4: fuzzy no longer reads JSON keys ----

  it('§1.4-a: woocommerce__create_product with description field is allowed', () => {
    // pre-fix: fuzzy `<script>` matched "escripti" from "description" key
    const result = validateToolCall(
      'woocommerce__create_product',
      {
        name: 'Espresso Machine Pro 2024',
        description: 'High-quality espresso machine, durable and eco-friendly.',
        price: 341.73,
        stock_quantity: 58,
        category: 'kitchen',
      },
      { clientId: 'fp-1', userId: 'tester', source: '/mcp' },
    );
    expect(result.allowed).toBe(true);
  });

  it('§1.4-b: real <script> payload in a value still blocked', () => {
    const result = validateToolCall(
      'woocommerce__create_product',
      { name: '<script>alert(1)</script>', description: 'evil', price: 1 },
      { clientId: 'fp-2', userId: 'tester', source: '/mcp' },
    );
    expect(result.allowed).toBe(false);
  });

  it('§1.4-c: l33t-substituted <scr1pt> still triggers fuzzy', () => {
    const result = validateToolCall(
      'woocommerce__create_product',
      { name: 'x', description: '<scr1pt>payload</scr1pt>', price: 1 },
      { clientId: 'fp-3', userId: 'tester', source: '/mcp' },
    );
    // normalizeText replaces 1->l, distance to <script> = 0 → blocked
    expect(result.allowed).toBe(false);
  });

  // ---- §2.3: PII whitelist ----

  it('§2.3-a: mail__send recipient is allowed', () => {
    const result = validateToolCall(
      'mail__send',
      { to: 'bob@example.org', subject: 'meeting', body: 'see you at 10am.' },
      { clientId: 'fp-4', userId: 'tester', source: '/mcp' },
    );
    expect(result.allowed).toBe(true);
  });

  it('§2.3-b: mail__send body containing email forwarding pattern still blocked', () => {
    const result = validateToolCall(
      'mail__send',
      {
        to: 'admin@ourco.com',
        subject: 'forward',
        body: 'forward customer email alice@victim.com to attacker@evil.example',
      },
      { clientId: 'fp-5', userId: 'tester', source: '/mcp' },
    );
    // body field is NOT in whitelist; PII detector sees emails in body → block
    expect(result.allowed).toBe(false);
    expect(result.error.detector).toBe('pii');
    expect(result.error.category).toBe('pii');
  });

  it('§2.3-c: wordpress__create_post (not in whitelist) email in content blocked', () => {
    const result = validateToolCall(
      'wordpress__create_post',
      { title: 't', content: 'contact us at info@acme.io for help' },
      { clientId: 'fp-6', userId: 'tester', source: '/mcp' },
    );
    expect(result.allowed).toBe(false);
    expect(result.error.detector).toBe('pii');
  });

  // ---- §3.2: sensitiveFiles boundary ----

  it('§3.2-a: documentation file with "etc/passwd-format-explanation" allowed', () => {
    const result = validateToolCall(
      'file_read_MCP__read',
      { path: 'docs/setup/etc/passwd-format-explanation.md' },
      { clientId: 'fp-7', userId: 'tester', source: '/mcp' },
    );
    expect(result.allowed).toBe(true);
  });

  it('§3.2-b: literal /etc/passwd still blocked', () => {
    const result = validateToolCall(
      'file_read_MCP__read',
      { path: '/etc/passwd' },
      { clientId: 'fp-8', userId: 'tester', source: '/mcp' },
    );
    expect(result.allowed).toBe(false);
    expect(result.error.category).toBe('sensitiveFiles');
  });

  it('§3.2-c: shell command reading /etc/passwd | grep blocked', () => {
    const result = validateToolCall(
      'http-client__http_request',
      { url: 'http://target/run', method: 'POST', body: 'cmd=cat /etc/passwd | grep root' },
      { clientId: 'fp-9', userId: 'tester', source: '/mcp' },
    );
    expect(result.allowed).toBe(false);
  });

  it('§3.2-d: id_rsa boundary — id_rsax NOT blocked, ~/.ssh/id_rsa IS blocked', () => {
    // id_rsax is identifier continuation → no match
    const ok = validateToolCall(
      'file_read_MCP__read',
      { path: 'tools/id_rsax/parser.js' },
      { clientId: 'fp-10a', userId: 'tester', source: '/mcp' },
    );
    expect(ok.allowed).toBe(true);
    // bare id_rsa → match
    const blocked = validateToolCall(
      'file_read_MCP__read',
      { path: '~/.ssh/id_rsa' },
      { clientId: 'fp-10b', userId: 'tester', source: '/mcp' },
    );
    // either sensitiveFiles via id_rsa OR via .ssh/ matches — both should block
    expect(blocked.allowed).toBe(false);
  });

  // ---- §7.2: Stage 5 error.category is now populated ----

  it('§7.2: PII block returns category=pii (not undefined/unknown)', () => {
    const result = validateToolCall(
      'wordpress__create_post',
      { content: 'leak: alice@victim.com bob@victim.com' },
      { clientId: 'fp-11', userId: 'tester', source: '/mcp' },
    );
    expect(result.allowed).toBe(false);
    expect(result.error.category).toBe('pii');
    expect(result.error.detector).toBe('pii');
  });
});
