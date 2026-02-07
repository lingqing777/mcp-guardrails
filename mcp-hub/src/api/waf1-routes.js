/**
 * WAF1 仪表盘 API
 * 提供 WAF1 统计、历史、控制等接口
 */

import {
  getWaf1Stats,
  getDashboardData,
  getTimeSeriesData,
  getCallHistory,
  resetStats,
  isWaf1Enabled
} from "../waf1/index.js";

/**
 * 注册 WAF1 API 路由
 */
export function registerWaf1Routes(app, getConfig, setConfig, saveConfig, applyWaf1Config) {
  // 获取基础统计
  app.get("/api/waf1/stats", (req, res) => {
    res.json(getWaf1Stats());
  });

  // 获取完整仪表盘数据
  app.get("/api/waf1/dashboard", (req, res) => {
    res.json(getDashboardData());
  });

  // 获取时间序列数据 (用于图表)
  app.get("/api/waf1/timeseries", (req, res) => {
    const interval = parseInt(req.query.interval) || 3600000;  // 默认 1 小时
    const periods = parseInt(req.query.periods) || 24;        // 默认 24 个周期
    res.json(getTimeSeriesData(interval, periods));
  });

  // 获取调用历史
  app.get("/api/waf1/history", (req, res) => {
    res.json(getCallHistory());
  });

  // 重置统计 (需谨慎)
  app.post("/api/waf1/reset", (req, res) => {
    resetStats();
    res.json({ success: true, message: "统计数据已重置" });
  });

  // WAF1 开关控制
  app.post("/api/waf1/toggle", (req, res) => {
    const { enabled } = req.body;
    if (typeof enabled !== 'boolean') {
      return res.status(400).json({ error: 'enabled 必须是布尔值' });
    }

    const config = getConfig();
    config.waf1.enabled = enabled;
    setConfig(config);
    saveConfig(config);
    applyWaf1Config();

    res.json({
      success: true,
      waf1Enabled: isWaf1Enabled(),
      message: `WAF1 ${enabled ? '已启用' : '已禁用'}`
    });
  });
}
