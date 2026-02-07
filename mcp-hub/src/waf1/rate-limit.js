/**
 * 速率限制
 * 借鉴 Cloudflare/AWS WAF
 */

/**
 * 速率限制器
 */
export class RateLimiter {
  constructor(config = {}) {
    this.store = new Map();
    this.config = {
      enabled: false,
      windowMs: 60000,        // 时间窗口: 1分钟
      maxRequests: 100,       // 窗口内最大请求数
      blockDurationMs: 60000, // 超限后封禁时间
      ...config
    };
  }

  /**
   * 更新配置
   */
  updateConfig(newConfig) {
    this.config = { ...this.config, ...newConfig };
    console.log("[WAF1] 速率限制配置已更新");
  }

  /**
   * 检查速率限制
   * @param {string} identifier - 用户标识 (ID/IP)
   * @returns {object} { allowed, reason, type, retryAfter }
   */
  check(identifier) {
    if (!this.config.enabled) return { allowed: true };

    const now = Date.now();
    let record = this.store.get(identifier);

    // 清理过期记录
    if (record && now - record.windowStart > this.config.windowMs + this.config.blockDurationMs) {
      this.store.delete(identifier);
      record = null;
    }

    if (!record) {
      this.store.set(identifier, { count: 1, windowStart: now, blocked: false });
      return { allowed: true };
    }

    // 检查是否在封禁期
    if (record.blocked) {
      const blockRemaining = (record.windowStart + this.config.windowMs + this.config.blockDurationMs) - now;
      if (blockRemaining > 0) {
        return {
          allowed: false,
          reason: `速率限制: 请等待 ${Math.ceil(blockRemaining / 1000)} 秒`,
          type: 'RATE_LIMITED',
          retryAfter: Math.ceil(blockRemaining / 1000),
        };
      }
      // 封禁期结束，重置
      this.store.set(identifier, { count: 1, windowStart: now, blocked: false });
      return { allowed: true };
    }

    // 检查是否在当前窗口内
    if (now - record.windowStart < this.config.windowMs) {
      record.count++;
      if (record.count > this.config.maxRequests) {
        record.blocked = true;
        return {
          allowed: false,
          reason: `速率限制: 超过 ${this.config.maxRequests} 次/分钟`,
          type: 'RATE_LIMITED',
          retryAfter: Math.ceil(this.config.blockDurationMs / 1000),
        };
      }
      return { allowed: true };
    }

    // 窗口已过期，重置
    this.store.set(identifier, { count: 1, windowStart: now, blocked: false });
    return { allowed: true };
  }

  /**
   * 获取活跃客户端数
   */
  getActiveClients() {
    return this.store.size;
  }
}
