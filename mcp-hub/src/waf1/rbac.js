/**
 * RBAC 访问控制
 * 移植自 Invariant access_control.py
 */

const ROLE_CLAIM_FIELDS = [
  'actor_role', 'x_user_role', 'as_role', 'user_role',
  'claim_override',
];
const PRIV_ESC_FLAG_FIELDS = ['bypass', 'elevated'];

export function detectArgsRoleClaimTampering(args) {
  if (!args || typeof args !== 'object' || Array.isArray(args)) {
    return { tampered: false };
  }
  const matched = [];
  for (const f of ROLE_CLAIM_FIELDS) {
    if (Object.prototype.hasOwnProperty.call(args, f)) matched.push(f);
  }
  for (const f of PRIV_ESC_FLAG_FIELDS) {
    if (args[f] === true) matched.push(f);
  }
  if (matched.length === 0) return { tampered: false };
  return {
    tampered: true,
    fields: matched,
    reason: `检测到 args 中的越权声明字段: ${matched.join(', ')}`,
  };
}

/**
 * RBAC 访问控制器
 */
export class RBACController {
  constructor(config = {}) {
    this.config = {
      enabled: false,
      userRoles: {},          // userId -> roles[]
      roleGrants: {},         // role -> tools[]
      toolRequirements: {},   // tool -> roles[]
      defaultPolicy: 'allow', // 'allow' | 'deny'
      ...config
    };
  }

  /**
   * 更新配置
   */
  updateConfig(newConfig) {
    this.config = { ...this.config, ...newConfig };
    console.log("[WAF1] RBAC 配置已更新");
  }

  /**
   * RBAC 访问控制检查
   * @param {string} userId - 用户 ID
   * @param {string} toolName - 工具名称
   * @returns {object} { allowed, reason, type }
   */
  check(userId, toolName) {
    if (!this.config.enabled) {
      return { allowed: true };
    }

    // 获取用户角色
    const userRoles = this.config.userRoles[userId] || [];

    // 方式1: 检查 toolRequirements (工具 -> 角色)
    if (this.config.toolRequirements[toolName]) {
      const requiredRoles = this.config.toolRequirements[toolName];
      const hasRole = userRoles.some(role =>
        requiredRoles.includes(role) || requiredRoles.includes('*')
      );

      if (!hasRole) {
        return {
          allowed: false,
          reason: `用户 "${userId}" 缺少工具 "${toolName}" 所需的角色: ${requiredRoles.join(', ')}`,
          type: 'RBAC_DENIED',
        };
      }
      return { allowed: true };
    }

    // 方式2: 检查 roleGrants (角色 -> 工具)
    for (const role of userRoles) {
      const grants = this.config.roleGrants[role] || [];
      if (grants.includes('*') || grants.includes(toolName)) {
        return { allowed: true };
      }
    }

    // 默认策略
    if (this.config.defaultPolicy === 'deny') {
      return {
        allowed: false,
        reason: `用户 "${userId}" 没有使用工具 "${toolName}" 的权限`,
        type: 'RBAC_DENIED',
      };
    }

    return { allowed: true };
  }
}
