const SQL_TOOL_NAMES = [
  'execute_sql',
  'supabase__execute_sql',
];

const SENSITIVE_OBJECT_PATTERNS = [
  /\bauth\s*\.\s*users\b/i,
  /\bauth\s*\.\s*sessions\b/i,
  /\bauth\s*\.\s*identities\b/i,
  /\bvault\s*\.\s*secrets\b/i,
  /\binformation_schema\b/i,
  /\bpg_catalog\b/i,
  /\bservice_role\b/i,
  /\bstorage\s*\.\s*objects\b/i,
  /\bprivate\s*\.\s*[a-z0-9_]+\b/i,
  /\b(payment_methods|payments|credit_cards|invoices|billing)\b/i,
  /\b(stripe_customer_id|stripe_customers|stripe_subscriptions)\b/i,
  /\b(api_keys|api_tokens)\b/i,
];

const USER_WRITABLE_PATTERNS = [
  /\bpublic\s*\.\s*(tickets|comments|notes|messages)\b/i,
  /\b(tickets|comments|notes|messages)\b/i,
];

const PUBLIC_WRITE_PATTERNS = [
  /\binsert\s+into\s+public\s*\.\s*([a-z0-9_]+)/i,
  /\bupdate\s+public\s*\.\s*([a-z0-9_]+)/i,
  /\bcreate\s+table\s+public\s*\.\s*([a-z0-9_]+)/i,
];

const EXPORT_PATTERNS = [
  /\bcopy\s*\(/i,
  /\bcopy\b[\s\S]*\bto\b/i,
  /\bpg_write_file\s*\(/i,
  /\bhttp_post\s*\(/i,
];

function uniq(values) {
  return Array.from(new Set(values.filter(Boolean)));
}

export function isSupabaseSqlTool(tool = '') {
  const normalized = String(tool || '').toLowerCase();
  return SQL_TOOL_NAMES.some((name) => normalized === name || normalized.endsWith(`__${name}`));
}

export function extractSqlFromArgs(args = {}) {
  if (typeof args === 'string') return args;
  if (!args || typeof args !== 'object') return '';

  const candidates = [
    args.sql,
    args.query,
    args.statement,
    args.command,
    args.text,
    args.input,
  ];

  for (const candidate of candidates) {
    if (typeof candidate === 'string' && candidate.trim()) {
      return candidate;
    }
  }

  if (Array.isArray(args.statements)) {
    const first = args.statements.find((value) => typeof value === 'string' && value.trim());
    if (first) return first;
  }

  return '';
}

export function normalizeSql(sql = '') {
  return String(sql || '')
    .replace(/--.*$/gm, ' ')
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

export function classifySqlStatement(sql = '') {
  const normalized = normalizeSql(sql).toLowerCase();
  if (!normalized) return 'unknown';

  let probe = normalized;
  if (probe.startsWith('with ')) {
    const match = probe.match(/\)\s*(select|insert|update|delete|create|alter|drop|truncate)\b/i);
    if (match) return match[1].toLowerCase();
  }

  const match = probe.match(/^(select|insert|update|delete|create|alter|drop|truncate|grant|revoke|copy)\b/i);
  return match ? match[1].toLowerCase() : 'unknown';
}

export function analyzeSupabaseSql(sql = '') {
  const normalizedSql = normalizeSql(sql);
  const statementType = classifySqlStatement(normalizedSql);
  const sensitiveObjects = uniq(
    SENSITIVE_OBJECT_PATTERNS
      .map((pattern) => normalizedSql.match(pattern)?.[0]?.replace(/\s+/g, ''))
  );
  const userWritableMatches = USER_WRITABLE_PATTERNS
    .filter((pattern) => pattern.test(normalizedSql))
    .map((pattern) => pattern.source);
  const publicWriteTargets = uniq(
    PUBLIC_WRITE_PATTERNS
      .map((pattern) => normalizedSql.match(pattern)?.[1])
      .map((name) => (name ? `public.${name}` : null))
  );
  const exportMatches = EXPORT_PATTERNS
    .filter((pattern) => pattern.test(normalizedSql))
    .map((pattern) => pattern.source);

  const hasSensitiveRead = sensitiveObjects.length > 0 &&
    /(select|insert|create|copy|with)\b/i.test(normalizedSql);
  const writesToPublic = publicWriteTargets.length > 0;
  const dangerousWriteback = writesToPublic && hasSensitiveRead;

  return {
    sql: normalizedSql,
    statementType,
    sensitiveObjects,
    readsUserWritable: userWritableMatches.length > 0,
    userWritableMatches,
    writesToPublic,
    publicWriteTargets,
    exportsData: exportMatches.length > 0,
    exportMatches,
    dangerousWriteback,
    isReadOnlySelect: statementType === 'select' && !writesToPublic && !hasSensitiveRead && exportMatches.length === 0,
  };
}

export function isSupabaseUserWritableReadCall(tool, args = {}) {
  if (isSupabaseSqlTool(tool)) {
    const sql = extractSqlFromArgs(args);
    if (!sql) return false;
    return analyzeSupabaseSql(sql).readsUserWritable;
  }

  const haystack = `${tool} ${JSON.stringify(args || {})}`;
  return /\b(read|get|fetch|query|list|search)\b/i.test(tool || '') &&
    /\b(tickets|comments|notes|messages)\b/i.test(haystack);
}

export function isSupabaseSensitiveSqlCall(tool, args = {}) {
  if (!isSupabaseSqlTool(tool)) return false;
  const sql = extractSqlFromArgs(args);
  if (!sql) return false;
  return analyzeSupabaseSql(sql).sensitiveObjects.length > 0;
}

export function isSupabaseLeakWriteCall(tool, args = {}) {
  if (!isSupabaseSqlTool(tool)) return false;
  const sql = extractSqlFromArgs(args);
  if (!sql) return false;
  const analysis = analyzeSupabaseSql(sql);
  return analysis.dangerousWriteback || analysis.exportsData;
}

