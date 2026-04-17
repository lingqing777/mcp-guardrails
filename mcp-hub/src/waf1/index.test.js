import { describe, expect, it, beforeEach } from 'vitest';

import {
  getDashboardData,
  resetWaf1State,
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
