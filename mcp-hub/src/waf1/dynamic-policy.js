import {
  analyzeSupabaseSql,
  extractSqlFromArgs,
  isSupabaseSqlTool,
} from './supabase-sql.js';

const SQL_RISK_PROFILES = [
  {
    id: 'supabase-execute-sql',
    tools: ['execute_sql', 'supabase__execute_sql'],
    allowedStatementTypes: ['select', 'insert', 'update', 'delete', 'create', 'copy', 'with'],
  },
];

function findProfile(tool) {
  if (!isSupabaseSqlTool(tool)) return null;
  const normalized = String(tool || '').toLowerCase();
  return SQL_RISK_PROFILES.find((profile) =>
    profile.tools.some((name) => normalized === name || normalized.endsWith(`__${name}`))
  ) || null;
}

export function getDynamicPolicyProfiles() {
  return SQL_RISK_PROFILES.slice();
}

export function checkDynamicPolicy(tool, args = {}) {
  const profile = findProfile(tool);
  if (!profile) return { allowed: true };

  const sql = extractSqlFromArgs(args);
  if (!sql) return { allowed: true };

  const analysis = analyzeSupabaseSql(sql);
  if (!profile.allowedStatementTypes.includes(analysis.statementType) && analysis.statementType !== 'unknown') {
    return {
      allowed: false,
      reason: `Supabase 动态策略: execute_sql 不允许执行 ${analysis.statementType.toUpperCase()} 语句`,
      type: 'DYNAMIC_POLICY_BLOCKED',
      category: 'dynamicPolicy',
      profile: profile.id,
      severity: 'high',
      statementType: analysis.statementType,
      direction: 'write',
    };
  }

  if (analysis.dangerousWriteback) {
    return {
      allowed: false,
      reason: `Supabase 动态策略: 检测到将查询结果写回公开表 ${analysis.publicWriteTargets.join(', ')}`,
      type: 'DYNAMIC_POLICY_BLOCKED',
      category: 'dynamicPolicy',
      profile: profile.id,
      severity: 'critical',
      statementType: analysis.statementType,
      publicTargets: analysis.publicWriteTargets,
      direction: 'writeback',
    };
  }

  if (analysis.exportsData) {
    return {
      allowed: false,
      reason: 'Supabase 动态策略: 检测到导出型 SQL 或外部写出行为',
      type: 'DYNAMIC_POLICY_BLOCKED',
      category: 'dynamicPolicy',
      profile: profile.id,
      severity: 'critical',
      statementType: analysis.statementType,
      direction: 'export',
    };
  }

  if (analysis.sensitiveObjects.length > 0) {
    return {
      allowed: false,
      reason: `Supabase 动态策略: execute_sql 访问受保护对象 ${analysis.sensitiveObjects.join(', ')}`,
      type: 'DYNAMIC_POLICY_BLOCKED',
      category: 'dynamicPolicy',
      profile: profile.id,
      severity: 'critical',
      statementType: analysis.statementType,
      protectedObjects: analysis.sensitiveObjects,
      direction: 'read',
    };
  }

  return {
    allowed: true,
    profile: profile.id,
    analysis,
  };
}
