import { describe, expect, it } from 'vitest';

import { extractArgValues } from './utils.js';

describe('extractArgValues', () => {
  it('returns plain string for string value', () => {
    expect(extractArgValues('hello')).toBe('hello');
  });

  it('returns string repr for number / boolean', () => {
    expect(extractArgValues(42)).toBe('42');
    expect(extractArgValues(true)).toBe('true');
  });

  it('returns empty for null / undefined', () => {
    expect(extractArgValues(null)).toBe('');
    expect(extractArgValues(undefined)).toBe('');
  });

  it('returns space-joined values of a flat object, omitting keys', () => {
    const r = extractArgValues({ name: 'Foo', description: 'a kitchen device' });
    expect(r).toBe('Foo a kitchen device');
    // critical: no occurrence of "description" the KEY
    expect(r.includes('description')).toBe(false);
  });

  it('recurses into nested objects (still no keys)', () => {
    const r = extractArgValues({ user: { name: 'Bob', email: 'b@b.com' }, age: 30 });
    expect(r).toContain('Bob');
    expect(r).toContain('b@b.com');
    expect(r).toContain('30');
    expect(r.includes('email')).toBe(false);
    expect(r.includes('user')).toBe(false);
  });

  it('flattens arrays with space separator', () => {
    expect(extractArgValues(['a', 'b', 'c'])).toBe('a b c');
  });

  it('skips empty strings when joining to avoid double spaces', () => {
    expect(extractArgValues({ a: '', b: 'x', c: '' })).toBe('x');
  });

  it('CRITICAL: cross-value 8-gram cannot match <script> via space gap', () => {
    // {a:"<scr", b:"ipt>"} → "<scr ipt>" — the 8-gram "<scr ipt" with literal
    // space in the middle is Levenshtein > 2 from "<script>", preventing the
    // false positive that JSON.stringify({a:"<scr",b:"ipt>"}) could create.
    const r = extractArgValues({ a: '<scr', b: 'ipt>' });
    expect(r).toBe('<scr ipt>');
    // The full string still does NOT contain literal "<script>" anywhere
    expect(r.includes('<script>')).toBe(false);
  });
});
