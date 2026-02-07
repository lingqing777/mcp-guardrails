/**
 * 统计与仪表盘数据
 * 借鉴 Cloudflare Security Analytics
 */

// 严重级别定义
export const SEVERITY_LEVELS = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

// 类别 -> 严重级别映射
export const CATEGORY_SEVERITY = {
  // 规则类别
  sqlInjection: 'high',
  shellInjection: 'critical',
  sensitiveFiles: 'high',
  protocolAttacks: 'high',
  dataExfiltration: 'critical',
  xss: 'medium',
  dangerousOperations: 'critical',
  pathTraversal: 'medium',
  ssrf: 'high',
  injectionOther: 'medium',
  // 检测器类别
  secrets: 'critical',
  pii: 'high',
  unicode: 'low',
  fuzzy: 'medium',
  callChain: 'high',
  rbac: 'medium',
};

// MITRE ATT&CK 映射
export const MITRE_MAPPING = {
  sqlInjection: 'T1190',
  shellInjection: 'T1059',
  sensitiveFiles: 'T1005',
  protocolAttacks: 'T1557',
  dataExfiltration: 'T1041',
  xss: 'T1189',
  dangerousOperations: 'T1059',
  pathTraversal: 'T1083',
  ssrf: 'T1090',
  secrets: 'T1552',
  pii: 'T1530',
  callChain: 'T1071',
};

/**
 * 统计收集器
 */
export class StatsCollector {
  constructor() {
    this.stats = {
      total: 0,
      passed: 0,
      blocked: 0,
      blockedByTool: 0,
      blockedByRule: {},
      blockedByDetector: { secrets: 0, pii: 0, unicode: 0, callChain: 0, fuzzy: 0, rbac: 0 },
      detections: [],
    };
  }

  /**
   * 记录请求
   */
  recordRequest() {
    this.stats.total++;
  }

  /**
   * 记录放行
   */
  recordPass() {
    this.stats.passed++;
  }

  /**
   * 记录拦截
   */
  recordBlock(type, category) {
    this.stats.blocked++;
    if (type === 'tool') {
      this.stats.blockedByTool++;
    } else if (type === 'rule' && category) {
      this.stats.blockedByRule[category] = (this.stats.blockedByRule[category] || 0) + 1;
    } else if (type === 'detector' && category) {
      if (this.stats.blockedByDetector[category] !== undefined) {
        this.stats.blockedByDetector[category]++;
      }
    }
  }

  /**
   * 添加检测记录
   */
  addDetection(detection) {
    this.stats.detections.push({
      ...detection,
      ts: Date.now()
    });
    if (this.stats.detections.length > 100) {
      this.stats.detections.shift();
    }
  }

  /**
   * 生成检测标签
   */
  generateLabels(detection) {
    const category = detection.category || detection.detector || 'unknown';
    const severity = CATEGORY_SEVERITY[category] || 'info';
    const mitre = MITRE_MAPPING[category] || null;

    return {
      'cf-waf-action': 'block',
      'cf-waf-rule-id': `waf1-${category}`,
      'cf-threat-score': SEVERITY_LEVELS[severity] * 25,
      category,
      severity,
      severityScore: SEVERITY_LEVELS[severity],
      mitreTactic: mitre,
      timestamp: new Date().toISOString(),
      source: 'waf1',
    };
  }

  /**
   * 获取基础统计
   */
  getStats() {
    return {
      ...this.stats,
      detections: this.stats.detections.slice(-20),
    };
  }

  /**
   * 获取仪表盘数据
   */
  getDashboardData(rateLimiter, cacheSize = 0) {
    const now = Date.now();
    const last24h = this.stats.detections.filter(d => now - d.ts < 86400000);
    const lastHour = this.stats.detections.filter(d => now - d.ts < 3600000);

    // 按类别统计
    const byCategory = {};
    const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    const byHour = {};

    for (const d of last24h) {
      const cat = d.category || d.detector || 'unknown';
      byCategory[cat] = (byCategory[cat] || 0) + 1;

      const severity = CATEGORY_SEVERITY[cat] || 'info';
      bySeverity[severity]++;

      const hour = new Date(d.ts).getHours();
      byHour[hour] = (byHour[hour] || 0) + 1;
    }

    const blockRate = this.stats.total > 0
      ? ((this.stats.blocked / this.stats.total) * 100).toFixed(2)
      : 0;

    return {
      summary: {
        total: this.stats.total,
        passed: this.stats.passed,
        blocked: this.stats.blocked,
        blockRate: `${blockRate}%`,
      },
      last24h: {
        total: last24h.length,
        byCategory,
        bySeverity,
        byHour,
      },
      lastHour: {
        total: lastHour.length,
      },
      detectors: this.stats.blockedByDetector,
      rules: this.stats.blockedByRule,
      recentDetections: this.stats.detections.slice(-10).map(d => ({
        ...d,
        labels: this.generateLabels(d),
      })),
      cache: {
        size: cacheSize,
      },
      rateLimit: {
        enabled: rateLimiter?.config?.enabled || false,
        activeClients: rateLimiter?.getActiveClients() || 0,
      },
    };
  }

  /**
   * 获取时间序列数据
   */
  getTimeSeriesData(intervalMs = 3600000, periods = 24) {
    const now = Date.now();
    const series = [];

    for (let i = periods - 1; i >= 0; i--) {
      const periodStart = now - (i + 1) * intervalMs;
      const periodEnd = now - i * intervalMs;

      const periodDetections = this.stats.detections.filter(
        d => d.ts >= periodStart && d.ts < periodEnd
      );

      series.push({
        timestamp: new Date(periodEnd).toISOString(),
        blocked: periodDetections.length,
        categories: periodDetections.reduce((acc, d) => {
          const cat = d.category || d.detector || 'unknown';
          acc[cat] = (acc[cat] || 0) + 1;
          return acc;
        }, {}),
      });
    }

    return series;
  }

  /**
   * 重置统计
   */
  reset() {
    this.stats = {
      total: 0,
      passed: 0,
      blocked: 0,
      blockedByTool: 0,
      blockedByRule: {},
      blockedByDetector: { secrets: 0, pii: 0, unicode: 0, callChain: 0, fuzzy: 0, rbac: 0 },
      detections: [],
    };
    console.log("[WAF1] 统计数据已重置");
  }
}
