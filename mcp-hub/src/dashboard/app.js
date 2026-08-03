/**
 * MCP Guardrails Dashboard - 主应用
 * 重构版：使用模块化组件和服务
 */

// ==================== 导入模块 ====================

import api, { getConfig, setConfig as setApiConfig } from './services/api.js';
import { formatLabel, formatTime, formatUptime, escapeHtml } from './utils/formatters.js';
import { renderBarChart, mergeChartData } from './components/Chart.js';
import { renderDetectionList, mergeDetections } from './components/DetectionItem.js';
import { setToggleStates } from './components/Toggle.js';

// ==================== 全局状态 ====================

// LLM Provider 预设映射表
const LLM_PROVIDERS = {
    dashscope:   { label: '通义千问',         format: 'openai',    baseUrl: 'https://dashscope.aliyuncs.com/compatible-mode/v1', model: 'qwen-turbo',                 keyUrl: 'https://bailian.console.aliyun.com/#/api-key' },
    openai:      { label: 'OpenAI',           format: 'openai',    baseUrl: 'https://api.openai.com/v1',                        model: 'gpt-4o-mini',                keyUrl: 'https://platform.openai.com/api-keys' },
    deepseek:    { label: 'DeepSeek',         format: 'openai',    baseUrl: 'https://api.deepseek.com/v1',                      model: 'deepseek-chat',              keyUrl: 'https://platform.deepseek.com/api_keys' },
    grok:        { label: 'Grok',             format: 'openai',    baseUrl: 'https://api.x.ai/v1',                              model: 'grok-2',                     keyUrl: 'https://console.x.ai/' },
    anthropic:   { label: 'Claude',           format: 'anthropic', baseUrl: 'https://api.anthropic.com',                        model: 'claude-sonnet-4-5-20250929', keyUrl: 'https://console.anthropic.com/settings/keys' },
    gemini:      { label: 'Gemini',           format: 'gemini',    baseUrl: 'https://generativelanguage.googleapis.com',        model: 'gemini-2.5-flash',           keyUrl: 'https://aistudio.google.com/apikey' },
    groq:        { label: 'Groq',             format: 'openai',    baseUrl: 'https://api.groq.com/openai/v1',                   model: 'llama-3.3-70b-versatile',    keyUrl: 'https://console.groq.com/keys' },
    mistral:     { label: 'Mistral',          format: 'openai',    baseUrl: 'https://api.mistral.ai/v1',                        model: 'mistral-large-latest',       keyUrl: 'https://console.mistral.ai/api-keys' },
    moonshot:    { label: 'Moonshot',         format: 'openai',    baseUrl: 'https://api.moonshot.cn/v1',                       model: 'moonshot-v1-8k',             keyUrl: 'https://platform.moonshot.cn/console/api-keys' },
    zhipu:       { label: '智谱 AI',          format: 'openai',    baseUrl: 'https://open.bigmodel.cn/api/paas/v4',             model: 'glm-4-flash',                keyUrl: 'https://open.bigmodel.cn/usercenter/apikeys' },
    siliconflow: { label: 'SiliconFlow',      format: 'openai',    baseUrl: 'https://api.siliconflow.cn/v1',                    model: 'deepseek-ai/DeepSeek-V3',    keyUrl: 'https://cloud.siliconflow.cn/account/ak' },
    perplexity:  { label: 'Perplexity',       format: 'openai',    baseUrl: 'https://api.perplexity.ai',                        model: 'sonar',                      keyUrl: 'https://www.perplexity.ai/settings/api' },
    baidu:       { label: '百度文心',         format: 'openai',    baseUrl: 'https://qianfan.baidubce.com/v2',                  model: 'ernie-4.0-8k',               keyUrl: 'https://console.bce.baidu.com/iam/#/iam/apikey' },
    doubao:      { label: '豆包',             format: 'openai',    baseUrl: 'https://ark.cn-beijing.volces.com/api/v3',         model: 'doubao-1.5-pro-32k',         keyUrl: 'https://console.volcengine.com/ark/region:ark+cn-beijing/apiKey' },
    xfyun:       { label: '讯飞星火',         format: 'openai',    baseUrl: 'https://spark-api-open.xf-yun.com/v1',             model: 'generalv3.5',                keyUrl: 'https://console.xfyun.cn/services/bm35' },
    hunyuan:     { label: '腾讯混元',         format: 'openai',    baseUrl: 'https://api.hunyuan.cloud.tencent.com/v1',         model: 'hunyuan-lite',               keyUrl: 'https://console.cloud.tencent.com/cam/capi' },
    ollama:      { label: 'Ollama',           format: 'openai',    baseUrl: 'http://localhost:11434/v1',                        model: 'llama3',                     keyUrl: '' },
    custom:      { label: '自定义',           format: 'openai',    baseUrl: '',                                                 model: '',                           keyUrl: '' }
};

let WAF1_URL = 'http://localhost:4000';
let WAF2_URL = 'http://localhost:8081';
let REFRESH_INTERVAL = 5000;
let refreshTimer = null;

// 数据存储
let waf1Data = null;
let waf2Data = null;
let allDetections = [];
let mcpServers = [];
let selectedServer = null;

// 当前用户信息
let currentUser = null;

// 当前防护模式
let currentMode = 'full';

// 当前测试工具
let currentTestTool = null;

// 图表实例
let trendChart = null;
let pieChart = null;

// 趋势数据历史 (最近 10 分钟，每 5 秒一个点)
let trendHistory = [];
const TREND_MAX_POINTS = 120; // 10分钟 * 60秒 / 5秒 = 120 点

// ==================== 初始化 ====================

document.addEventListener('DOMContentLoaded', () => {
    initTheme();
    checkAuthStatus();
    initTabs();
    loadConfig();
    initConfigPanel();
    initCharts();
    refreshData();
    fetchMcpServers();
    startAutoRefresh();
    initDemo();
});

// ==================== 主题切换 ====================

function initTheme() {
    const savedTheme = localStorage.getItem('theme') || 'dark';
    document.documentElement.setAttribute('data-theme', savedTheme);
    updateThemeIcon(savedTheme);
}

async function toggleTheme(event) {
    const currentTheme = document.documentElement.getAttribute('data-theme');
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';

    // 获取点击位置（圆形展开的圆心）
    const btn = document.querySelector('.theme-toggle');
    const rect = btn.getBoundingClientRect();
    const x = rect.left + rect.width / 2;
    const y = rect.top + rect.height / 2;

    // 如果浏览器支持 View Transitions API 且用户没有 prefers-reduced-motion
    if (document.startViewTransition && !window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
        const transition = document.startViewTransition(() => {
            document.documentElement.setAttribute('data-theme', newTheme);
            localStorage.setItem('theme', newTheme);
            updateThemeIcon(newTheme);
            if (trendChart || pieChart) updateChartsTheme(newTheme);
        });

        await transition.ready;

        // 计算覆盖整个视口所需的最大半径
        const right = window.innerWidth - x;
        const bottom = window.innerHeight - y;
        const maxRadius = Math.hypot(Math.max(x, right), Math.max(y, bottom));

        document.documentElement.animate(
            { clipPath: [`circle(0px at ${x}px ${y}px)`, `circle(${maxRadius}px at ${x}px ${y}px)`] },
            { duration: 500, easing: 'ease-in-out', pseudoElement: '::view-transition-new(root)' }
        );
    } else {
        // 降级：无动画直接切换
        document.documentElement.setAttribute('data-theme', newTheme);
        localStorage.setItem('theme', newTheme);
        updateThemeIcon(newTheme);
        if (trendChart || pieChart) updateChartsTheme(newTheme);
    }
}

function updateThemeIcon(theme) {
    // SVG 图标的显隐通过 CSS [data-theme] 选择器自动控制，无需 JS 操作
}

function updateChartsTheme(theme) {
    const textColor = theme === 'dark' ? '#e4e4e4' : '#1a1a2e';
    const gridColor = theme === 'dark' ? 'rgba(255,255,255,0.1)' : 'rgba(0,0,0,0.1)';

    if (trendChart) {
        trendChart.options.scales.x.ticks.color = textColor;
        trendChart.options.scales.y.ticks.color = textColor;
        trendChart.options.scales.x.grid.color = gridColor;
        trendChart.options.scales.y.grid.color = gridColor;
        trendChart.update('none');
    }

    if (pieChart) {
        pieChart.options.plugins.legend.labels.color = textColor;
        pieChart.update('none');
    }
}

// ==================== 图表初始化 ====================

function initCharts() {
    const theme = document.documentElement.getAttribute('data-theme') || 'dark';
    const textColor = theme === 'dark' ? '#e4e4e4' : '#1a1a2e';
    const gridColor = theme === 'dark' ? 'rgba(255,255,255,0.1)' : 'rgba(0,0,0,0.1)';

    // 趋势图
    const trendCtx = document.getElementById('trend-chart');
    if (trendCtx && typeof Chart !== 'undefined') {
        trendChart = new Chart(trendCtx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [
                    {
                        label: '拦截',
                        data: [],
                        borderColor: '#ff4757',
                        backgroundColor: 'rgba(255, 71, 87, 0.1)',
                        fill: true,
                        tension: 0.4,
                        pointRadius: 0,
                        pointHoverRadius: 4,
                    },
                    {
                        label: '放行',
                        data: [],
                        borderColor: '#00ff88',
                        backgroundColor: 'rgba(0, 255, 136, 0.1)',
                        fill: true,
                        tension: 0.4,
                        pointRadius: 0,
                        pointHoverRadius: 4,
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                interaction: {
                    intersect: false,
                    mode: 'index',
                },
                plugins: {
                    legend: {
                        position: 'top',
                        labels: { color: textColor, usePointStyle: true, padding: 20 }
                    },
                    tooltip: {
                        backgroundColor: 'rgba(0,0,0,0.8)',
                        padding: 12,
                        cornerRadius: 8,
                    }
                },
                scales: {
                    x: {
                        ticks: { color: textColor, maxTicksLimit: 10 },
                        grid: { color: gridColor }
                    },
                    y: {
                        beginAtZero: true,
                        ticks: { color: textColor, stepSize: 1 },
                        grid: { color: gridColor }
                    }
                }
            }
        });
    }

    // 饼图
    const pieCtx = document.getElementById('pie-chart');
    if (pieCtx && typeof Chart !== 'undefined') {
        pieChart = new Chart(pieCtx, {
            type: 'doughnut',
            data: {
                labels: ['SQL 注入', '命令注入', 'XSS', '路径遍历', '其他'],
                datasets: [{
                    data: [0, 0, 0, 0, 0],
                    backgroundColor: [
                        '#ff4757',
                        '#ffa502',
                        '#2ed573',
                        '#1e90ff',
                        '#a55eea'
                    ],
                    borderWidth: 0,
                    hoverOffset: 10
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '60%',
                plugins: {
                    legend: {
                        position: 'right',
                        labels: {
                            color: textColor,
                            usePointStyle: true,
                            padding: 15,
                            font: { size: 12 }
                        }
                    },
                    tooltip: {
                        backgroundColor: 'rgba(0,0,0,0.8)',
                        padding: 12,
                        cornerRadius: 8,
                    }
                }
            }
        });
    }
}

function updateTrendChart(blocked, passed) {
    if (!trendChart) return;

    const now = new Date();
    const timeLabel = now.toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit', second: '2-digit' });

    // 计算增量
    const lastBlocked = trendHistory.length > 0 ? trendHistory[trendHistory.length - 1].blocked : 0;
    const lastPassed = trendHistory.length > 0 ? trendHistory[trendHistory.length - 1].passed : 0;

    const blockedDelta = Math.max(0, blocked - lastBlocked);
    const passedDelta = Math.max(0, passed - lastPassed);

    trendHistory.push({ time: timeLabel, blocked, passed, blockedDelta, passedDelta });

    if (trendHistory.length > TREND_MAX_POINTS) {
        trendHistory.shift();
    }

    trendChart.data.labels = trendHistory.map(h => h.time);
    trendChart.data.datasets[0].data = trendHistory.map(h => h.blockedDelta);
    trendChart.data.datasets[1].data = trendHistory.map(h => h.passedDelta);
    trendChart.update('none');
}

function updatePieChart(categoryData) {
    if (!pieChart || !categoryData) return;

    const categories = {
        'SQL 注入': 0,
        '命令注入': 0,
        'XSS': 0,
        '路径遍历': 0,
        '其他': 0
    };

    // 映射数据
    for (const [key, value] of Object.entries(categoryData)) {
        const lowerKey = key.toLowerCase();
        if (lowerKey.includes('sql')) {
            categories['SQL 注入'] += value;
        } else if (lowerKey.includes('shell') || lowerKey.includes('command') || lowerKey.includes('cmd')) {
            categories['命令注入'] += value;
        } else if (lowerKey.includes('xss') || lowerKey.includes('script')) {
            categories['XSS'] += value;
        } else if (lowerKey.includes('path') || lowerKey.includes('traversal') || lowerKey.includes('lfi')) {
            categories['路径遍历'] += value;
        } else {
            categories['其他'] += value;
        }
    }

    pieChart.data.datasets[0].data = Object.values(categories);
    pieChart.update('none');
}

// 导出主题切换函数
window.toggleTheme = toggleTheme;

// ==================== 认证相关 ====================

async function checkAuthStatus() {
    try {
        const data = await api.auth.checkStatus();
        if (data.authenticated) {
            currentUser = data.username;
            updateUserDisplay();
        }
    } catch (e) {
        console.log('Auth check failed:', e);
    }
}

function updateUserDisplay() {
    const userDisplay = document.getElementById('user-display');
    if (userDisplay && currentUser) {
        userDisplay.innerHTML = `
            <span style="color: #888;">用户:</span> ${escapeHtml(currentUser)}
            <button onclick="logout()" style="margin-left: 12px; padding: 4px 12px; background: rgba(255,71,87,0.2); border: 1px solid rgba(255,71,87,0.3); border-radius: 4px; color: #ff4757; cursor: pointer; font-size: 12px;">登出</button>
        `;
    }
}

async function logout() {
    try {
        await api.auth.logout();
        window.location.href = '/login';
    } catch (e) {
        console.error('Logout failed:', e);
        window.location.href = '/login';
    }
}

// ==================== 标签页导航 ====================

function initTabs() {
    const indicator = document.querySelector('.tab-indicator');

    function updateTabIndicator(animate = true) {
        const activeTab = document.querySelector('.tabs > .tab.active');
        if (!activeTab || !indicator) return;
        if (!animate) indicator.style.transition = 'none';
        indicator.style.width = activeTab.offsetWidth + 'px';
        indicator.style.transform = `translateX(${activeTab.offsetLeft}px)`;
        if (!animate) {
            // Force reflow then restore transition
            indicator.offsetHeight;
            indicator.style.transition = '';
        }
    }

    document.querySelectorAll('.tabs > .tab').forEach(tab => {
        tab.addEventListener('click', () => {
            // 跳过重复点击
            if (tab.classList.contains('active')) return;

            document.querySelectorAll('.tabs > .tab').forEach(t => t.classList.remove('active'));
            tab.classList.add('active');

            document.querySelectorAll('.tab-content').forEach(p => {
                p.style.display = 'none';
                p.classList.remove('panel-entering');
            });
            const panelId = `${tab.dataset.tab}-panel`;
            const panel = document.getElementById(panelId);
            if (panel) {
                panel.style.display = 'block';
                panel.classList.add('panel-entering');
                panel.addEventListener('animationend', () => {
                    panel.classList.remove('panel-entering');
                }, { once: true });
            } else {
                console.error('找不到面板:', panelId);
            }

            updateTabIndicator();

            // 态势感知 Tab 刷新控制
            if (tab.dataset.tab === 'monitor') {
                startMonitorRefresh();
            } else {
                stopMonitorRefresh();
            }
        });
    });

    // 默认态势感知 Tab 激活时启动刷新
    const activeTab = document.querySelector('.tabs > .tab.active');
    if (activeTab && activeTab.dataset.tab === 'monitor') {
        startMonitorRefresh();
    }

    // 初始定位（无动画）
    updateTabIndicator(false);
}

// ==================== 配置管理 ====================

// Format 标签文字映射
const FORMAT_LABELS = {
    openai: 'OpenAI 兼容',
    anthropic: 'Anthropic',
    gemini: 'Gemini 原生'
};

// Provider 卡片点击处理
function onProviderCardClick(card, section) {
    const suffix = section === 'full' ? '' : '-lite';
    const gridEl = document.getElementById(`provider-grid${suffix}`);
    const moreEl = document.getElementById(`provider-more${suffix}`);
    const panelEl = document.getElementById(`provider-config-panel${suffix}`);
    const baseUrlEl = document.getElementById(`cfg-baseurl${suffix}`);
    const modelEl = document.getElementById(`cfg-model${suffix}`);
    const badgeEl = document.getElementById(`cfg-format-badge${suffix}`);
    const keyLinkEl = document.getElementById(`cfg-key-link${suffix}`);
    const apiKeyRowEl = document.getElementById(`cfg-apikey-row${suffix}`);
    const apiKeyHintEl = document.getElementById(`cfg-apikey-hint${suffix}`);
    const formatSelectorEl = document.getElementById(`cfg-format-selector${suffix}`);

    // 切换选中态 — 两个容器都要清除
    if (gridEl) gridEl.querySelectorAll('.provider-card').forEach(c => c.classList.remove('selected'));
    if (moreEl) moreEl.querySelectorAll('.provider-card').forEach(c => c.classList.remove('selected'));
    card.classList.add('selected');

    const providerKey = card.dataset.provider;
    const provider = LLM_PROVIDERS[providerKey];
    if (!provider) return;

    // 填充配置字段
    if (baseUrlEl) baseUrlEl.value = provider.baseUrl;
    if (modelEl) modelEl.value = provider.model;

    // 更新格式标签
    if (badgeEl) {
        badgeEl.textContent = FORMAT_LABELS[provider.format] || provider.format;
        badgeEl.className = `provider-config-format-badge ${provider.format}`;
    }

    // 更新获取 Key 链接
    if (keyLinkEl) {
        if (provider.keyUrl) {
            keyLinkEl.href = provider.keyUrl;
            keyLinkEl.style.display = '';
        } else {
            keyLinkEl.style.display = 'none';
        }
    }

    // Ollama: 隐藏 API Key 行，显示占位提示
    if (providerKey === 'ollama') {
        if (apiKeyRowEl) apiKeyRowEl.classList.add('hidden');
        if (apiKeyHintEl) apiKeyHintEl.style.display = '';
    } else {
        if (apiKeyRowEl) apiKeyRowEl.classList.remove('hidden');
        if (apiKeyHintEl) apiKeyHintEl.style.display = 'none';
    }

    // 自定义: 显示格式选择器，清空字段
    if (formatSelectorEl) {
        formatSelectorEl.style.display = providerKey === 'custom' ? 'flex' : 'none';
    }
    if (providerKey === 'custom') {
        if (baseUrlEl) baseUrlEl.value = '';
        if (modelEl) modelEl.value = '';
    }

    // 展开配置面板
    if (panelEl) panelEl.classList.add('open');
}
window.onProviderCardClick = onProviderCardClick;

// 初始化卡片点击事件绑定
function initProviderCardEvents(section) {
    const suffix = section === 'full' ? '' : '-lite';
    // 绑定主网格和更多区域的所有卡片
    [`provider-grid${suffix}`, `provider-more${suffix}`].forEach(id => {
        const el = document.getElementById(id);
        if (!el) return;
        el.querySelectorAll('.provider-card').forEach(card => {
            card.addEventListener('click', () => onProviderCardClick(card, section));
        });
    });
}

function loadConfig() {
    const config = getConfig();
    WAF1_URL = config.waf1Url;
    WAF2_URL = config.waf2Url;
    REFRESH_INTERVAL = config.refreshInterval;
}

function saveConfig() {
    setApiConfig({
        waf1Url: WAF1_URL,
        waf2Url: WAF2_URL,
        refreshInterval: REFRESH_INTERVAL
    });
    startAutoRefresh();
}

// ==================== 数据刷新 ====================

function startAutoRefresh() {
    if (refreshTimer) clearInterval(refreshTimer);
    refreshTimer = setInterval(refreshData, REFRESH_INTERVAL);
}

async function refreshData() {
    await Promise.all([fetchWaf1Data(), fetchWaf2Data()]);
    updateUI();
}

async function manualRefreshData(btn) {
    const originalText = btn.textContent;
    btn.disabled = true;
    btn.classList.add('btn-loading');
    btn.textContent = '刷新中...';
    try {
        await refreshData();
        btn.classList.remove('btn-loading');
        btn.classList.add('btn-success-flash');
        btn.textContent = '已刷新';
        setTimeout(() => {
            btn.classList.remove('btn-success-flash');
            btn.textContent = originalText;
            btn.disabled = false;
        }, 1200);
    } catch (e) {
        btn.classList.remove('btn-loading');
        btn.textContent = originalText;
        btn.disabled = false;
        showConfigStatus('config-status', 'error', '刷新失败: ' + e.message);
    }
}

async function fetchWaf1Data() {
    try {
        waf1Data = await api.waf1.getDashboard();
        document.getElementById('waf1-status').classList.add('online');
        document.getElementById('waf1-status').classList.remove('offline');
    } catch (e) {
        console.error('WAF1 获取失败:', e);
        document.getElementById('waf1-status').classList.remove('online');
        document.getElementById('waf1-status').classList.add('offline');
        waf1Data = null;
    }
}

async function fetchWaf2Data() {
    try {
        waf2Data = await api.waf2.getDashboard();
        document.getElementById('waf2-status').classList.add('online');
        document.getElementById('waf2-status').classList.remove('offline');
    } catch (e) {
        console.error('WAF2 获取失败:', e);
        document.getElementById('waf2-status').classList.remove('online');
        document.getElementById('waf2-status').classList.add('offline');
        waf2Data = null;
    }
}

// ==================== UI 更新 ====================

function updateUI() {
    updateOverview();
    updateWaf1Panel();
    updateWaf2Panel();
    updateDetectionsPanel();
    updateLLMHealthBanner();
}

function updateLLMHealthBanner() {
    const banner = document.getElementById('llm-health-banner');
    if (!banner) return;
    const llmErrors = waf2Data?.summary?.llm_errors || 0;
    if (llmErrors > 0) {
        banner.style.display = 'flex';
        requestAnimationFrame(() => banner.classList.add('visible'));
    } else {
        banner.classList.remove('visible');
        setTimeout(() => { banner.style.display = 'none'; }, 300);
    }
}

function updateOverview() {
    const waf1Total = waf1Data?.summary?.total || 0;
    const waf2Total = waf2Data?.summary?.total || 0;
    const waf1Blocked = waf1Data?.summary?.blocked || 0;
    const waf2Blocked = waf2Data?.summary?.blocked || 0;
    const waf1Passed = waf1Data?.summary?.passed || 0;
    const waf2Passed = waf2Data?.summary?.passed || 0;

    const totalRequests = waf1Total + waf2Total;
    const totalBlocked = waf1Blocked + waf2Blocked;
    const totalPassed = waf1Passed + waf2Passed;
    const blockRate = totalRequests > 0 ? ((totalBlocked / totalRequests) * 100).toFixed(2) : '0.00';

    document.getElementById('total-requests').textContent = totalRequests;
    document.getElementById('total-blocked').textContent = totalBlocked;
    document.getElementById('total-passed').textContent = totalPassed;
    document.getElementById('block-rate').textContent = blockRate + '%';

    document.getElementById('waf1-blocked').textContent = waf1Blocked;
    document.getElementById('waf1-detail').textContent = `总计 ${waf1Total} 请求`;
    document.getElementById('waf2-blocked').textContent = waf2Blocked;
    document.getElementById('waf2-detail').textContent = `总计 ${waf2Total} 请求`;

    document.getElementById('cache-hit-rate').textContent = waf2Data?.cache?.hit_rate || '-';
    document.getElementById('cache-detail').textContent = `${waf2Data?.cache?.hits || 0} 命中 / ${waf2Data?.cache?.llm_calls || 0} LLM调用`;
    document.getElementById('avg-latency').textContent = (waf2Data?.summary?.avg_latency_ms || '-') + 'ms';

    // 更新 Chart.js 图表
    updateTrendChart(totalBlocked, totalPassed);

    const mergedCategories = mergeChartData(
        waf1Data?.last24h?.byCategory || waf1Data?.rules || waf1Data?.by_category || {},
        waf2Data?.by_category || {}
    );
    updatePieChart(mergedCategories);

    // 使用组件渲染条形图
    const waf1Categories = waf1Data?.last24h?.byCategory || waf1Data?.rules || waf1Data?.by_category || {};
    const waf2Categories = waf2Data?.by_category || {};
    renderBarChart('category-chart', mergeChartData(waf1Categories, waf2Categories), 'default');

    const waf1Severities = waf1Data?.last24h?.bySeverity || waf1Data?.by_severity || {};
    const waf2Severities = waf2Data?.by_severity || {};
    renderBarChart('severity-chart', mergeChartData(waf1Severities, waf2Severities), 'severity');
}

function updateWaf1Panel() {
    if (!waf1Data) {
        document.getElementById('waf1-total').textContent = '-';
        document.getElementById('waf1-blocked-detail').textContent = '-';
        document.getElementById('waf1-passed').textContent = '-';
        document.getElementById('waf1-ratelimit').textContent = '-';
        return;
    }

    document.getElementById('waf1-total').textContent = waf1Data.summary?.total || 0;
    document.getElementById('waf1-blocked-detail').textContent = waf1Data.summary?.blocked || 0;
    document.getElementById('waf1-passed').textContent = waf1Data.summary?.passed || 0;
    document.getElementById('waf1-ratelimit').textContent = waf1Data.summary?.rate_limited || 0;

    renderBarChart('waf1-category-chart', waf1Data.last24h?.byCategory || waf1Data.rules || waf1Data.by_category || {}, 'default');
    renderDetectionList('waf1-detections', waf1Data.recentDetections || waf1Data.recent_detections || [], 'waf1');
}

function updateWaf2Panel() {
    const setText = (id, value) => {
        const el = document.getElementById(id);
        if (el) el.textContent = value;
    };

    if (!waf2Data) {
        [
            'waf2-total',
            'waf2-blocked-req',
            'waf2-blocked-resp',
            'waf2-llm-calls',
            'waf2-local-mode',
            'waf2-score-blocks',
            'waf2-rag-state',
            'waf2-rag-queries',
            'waf2-agent-invocations',
            'waf2-react-rate'
        ].forEach(id => setText(id, '-'));
        setText('waf2-local-detail', 'provider - / model -');
        setText('waf2-score-detail', 'gray - / threshold -');
        setText('waf2-rag-detail', 'KB - 条');
        setText('waf2-rag-query-detail', '空结果 - / 门控 -');
        setText('waf2-agent-detail', '工具调用 -');
        setText('waf2-routing-detail', 'fast - / one-shot - / react -');
        const ragStateEl = document.getElementById('waf2-rag-state');
        if (ragStateEl) ragStateEl.className = 'card-value blue';
        return;
    }

    const summary = waf2Data.summary || {};
    const rag = waf2Data.rag || {};
    const agent = waf2Data.agent || {};
    const routing = waf2Data.routing || {};
    const localFirst = waf2Data.local_first || {};
    const localScore = waf2Data.local_attack_score || {};
    const toolCalls = agent.tool_calls || {};
    const toolCount = Object.values(toolCalls).reduce((sum, value) => sum + Number(value || 0), 0);
    const routeFast = Number(routing.fast_pass || 0);
    const routeOneShot = Number(routing.local_llm_one_shot ?? routing.one_shot ?? 0);
    const routeReact = Number(routing.react_deep_inspection ?? routing.react ?? 0);
    const totalRequests = Number(summary.total || 0);
    const reactRate = totalRequests > 0 ? `${((routeReact / totalRequests) * 100).toFixed(1)}%` : '-';
    const ragLatency = rag.avg_latency_ms !== undefined ? `${rag.avg_latency_ms}ms` : '-';

    setText('waf2-total', summary.total || 0);
    setText('waf2-blocked-req', waf2Data.by_direction?.request || 0);
    setText('waf2-blocked-resp', waf2Data.by_direction?.response || 0);
    setText('waf2-llm-calls', waf2Data.cache?.llm_calls || 0);

    const localModeEl = document.getElementById('waf2-local-mode');
    const locality = localFirst.provider_locality || 'unknown';
    const privacy = localFirst.privacy_mode || '-';
    if (localModeEl) {
        localModeEl.className = `card-value ${locality === 'local' ? 'green' : locality === 'online' ? 'yellow' : 'blue'}`;
    }
    setText('waf2-local-mode', locality === 'local' ? 'LOCAL' : locality === 'online' ? 'ONLINE' : locality.toUpperCase());
    setText('waf2-local-detail', `${privacy} / ${localFirst.model || '-'}`);
    setText('waf2-score-blocks', localScore.direct_blocks || 0);
    setText(
        'waf2-score-detail',
        `gray ${localScore.gray_zone || 0} / threshold ${localScore.block_threshold ?? '-'}`
    );

    const ragStateEl = document.getElementById('waf2-rag-state');
    if (ragStateEl) {
        ragStateEl.className = `card-value ${rag.enabled ? 'green' : 'red'}`;
    }
    setText('waf2-rag-state', rag.enabled ? 'ON' : 'OFF');
    setText('waf2-rag-detail', `KB ${rag.knowledge_base_size || 0} 条 / 平均 ${ragLatency}`);
    setText('waf2-rag-queries', rag.queries || 0);
    setText('waf2-rag-query-detail', `空结果 ${rag.empty_results || 0} / 门控 ${rag.gated || 0}`);
    setText('waf2-agent-invocations', agent.invocations || 0);
    setText('waf2-agent-detail', `工具调用 ${toolCount} 次 / fallback ${routing.agent_fallback || 0}`);
    setText('waf2-react-rate', reactRate);
    setText('waf2-routing-detail', `fast ${routeFast} / llm ${routeOneShot} / deep ${routeReact}`);

    renderBarChart('waf2-category-chart', waf2Data.by_category || {}, 'default');
    renderDetectionList('waf2-detections', waf2Data.recent_detections || [], 'waf2');
}

function updateDetectionsPanel() {
    const waf1Detections = waf1Data?.recentDetections || waf1Data?.recent_detections || [];
    const waf2Detections = waf2Data?.recent_detections || [];

    allDetections = mergeDetections(waf1Detections, waf2Detections, 50);
    renderDetectionList('all-detections', allDetections, 'all');
}

// ==================== 配置面板 ====================

async function selectMode(mode) {
    currentMode = mode;

    document.querySelectorAll('.mode-card').forEach(card => {
        card.classList.toggle('selected', card.dataset.mode === mode);
    });

    // 带动画切换配置面板
    const showIds = mode === 'full'
        ? ['config-full', 'guide-full']
        : ['config-lite', 'guide-lite'];
    const hideIds = mode === 'full'
        ? ['config-lite', 'guide-lite']
        : ['config-full', 'guide-full'];

    hideIds.forEach(id => {
        const el = document.getElementById(id);
        if (el) { el.style.display = 'none'; el.classList.remove('config-entering'); }
    });
    showIds.forEach(id => {
        const el = document.getElementById(id);
        if (el) {
            el.style.display = 'block';
            el.classList.add('config-entering');
            el.addEventListener('animationend', () => {
                el.classList.remove('config-entering');
            }, { once: true });
        }
    });

    const waf1Column = document.getElementById('waf1-rules-column');
    if (waf1Column) {
        waf1Column.classList.toggle('disabled', mode === 'lite');
    }

    try {
        const data = await api.config.setMode(mode);
        if (data.success) {
            showConfigStatus('config-status', 'success', data.message);
        } else {
            showConfigStatus('config-status', 'error', data.error || '切换失败');
        }
    } catch (e) {
        localStorage.setItem('protection_mode', mode);
        showConfigStatus('config-status', 'info', `已切换到${mode === 'full' ? '完整防护' : '轻量防护'}模式 (本地)`);
    }
}

function copyToClipboard(inputId, btn) {
    const input = document.getElementById(inputId);
    navigator.clipboard.writeText(input.value).then(() => {
        const originalText = btn.textContent;
        btn.textContent = '已复制';
        btn.classList.add('copied');
        setTimeout(() => {
            btn.textContent = originalText;
            btn.classList.remove('copied');
        }, 2000);
    });
}

function copyCodeBlock(btn) {
    const codeBlock = btn.parentElement;
    const code = codeBlock.querySelector('code').textContent;
    navigator.clipboard.writeText(code).then(() => {
        const originalText = btn.textContent;
        btn.textContent = '已复制!';
        setTimeout(() => {
            btn.textContent = originalText;
        }, 2000);
    });
}

function togglePasswordVisibility(inputId, btn) {
    const input = document.getElementById(inputId);
    if (input.type === 'password') {
        input.type = 'text';
        btn.textContent = '隐藏';
    } else {
        input.type = 'password';
        btn.textContent = '显示';
    }
}

async function toggleRuleSm(el) {
    el.classList.toggle('active');
    const isActive = el.classList.contains('active');
    const rule = el.dataset.rule;

    const isWaf1Rule = ['sql', 'cmd', 'xss', 'path', 'sensitive'].includes(rule);
    const isWaf2Rule = ['req', 'res', 'cache'].includes(rule);

    if (isWaf1Rule) {
        const ruleMap = {
            'sql': 'sqlInjection',
            'cmd': 'commandInjection',
            'xss': 'xss',
            'path': 'pathTraversal',
            'sensitive': 'sensitiveFiles'
        };
        const ruleName = ruleMap[rule];

        try {
            await api.waf1.updateRules({ [ruleName]: isActive });
            console.log(`[WAF1] 规则 ${ruleName} 已${isActive ? '启用' : '禁用'}`);
        } catch (e) {
            console.error('[WAF1] 规则更新失败:', e);
            el.classList.toggle('active');
        }
    } else if (isWaf2Rule) {
        const featureMap = {
            'req': 'requestAnalysis',
            'res': 'responseAnalysis',
            'cache': 'cache'
        };
        const featureName = featureMap[rule];

        try {
            const data = await api.waf2.updateFeatures({ [featureName]: isActive });
            if (data.success) {
                if (data.synced) {
                    console.log(`[WAF2] 功能 ${featureName} 已${isActive ? '启用' : '禁用'}`);
                } else {
                    console.warn(`[WAF2] 配置已保存但同步失败: ${data.syncError}`);
                }
            }
        } catch (e) {
            console.error('[WAF2] 规则更新失败:', e);
            el.classList.toggle('active');
        }
    }
}

async function applyConfig() {
    // 获取触发按钮并进入 loading 态
    const suffix = currentMode === 'full' ? '' : '-lite';
    const configSection = document.getElementById(currentMode === 'full' ? 'config-full' : 'config-lite');
    const applyBtn = configSection ? configSection.querySelector('.btn-primary[onclick*="applyConfig"]') : null;
    const originalBtnText = applyBtn ? applyBtn.textContent : '';
    if (applyBtn) {
        applyBtn.classList.add('btn-loading');
        applyBtn.textContent = '保存中...';
        applyBtn.disabled = true;
        applyBtn.style.minWidth = applyBtn.offsetWidth + 'px';
    }

    let targetUrl, apiKey, provider, baseUrl, model;

    targetUrl = document.getElementById(`cfg-target-url${suffix}`).value;
    apiKey = document.getElementById(`cfg-apikey${suffix}`).value;
    // 从选中的卡片读取 provider
    const selectedCard = document.querySelector(`#provider-grid${suffix} .provider-card.selected`) ||
                         document.querySelector(`#provider-more${suffix} .provider-card.selected`);
    provider = selectedCard ? selectedCard.dataset.provider : 'dashscope';
    baseUrl = document.getElementById(`cfg-baseurl${suffix}`).value;
    model = document.getElementById(`cfg-model${suffix}`).value;

    // 确定 format：预设 Provider 从映射表取，自定义从 radio 取
    let format;
    if (provider === 'custom') {
        const checked = document.querySelector(`input[name="cfg-format${suffix}"]:checked`);
        format = checked ? checked.value : 'openai';
    } else {
        const p = LLM_PROVIDERS[provider];
        format = p ? p.format : 'openai';
    }

    if (targetUrl && !targetUrl.match(/^https?:\/\/.+/)) {
        if (applyBtn) {
            applyBtn.classList.remove('btn-loading');
            applyBtn.textContent = originalBtnText;
            applyBtn.disabled = false;
        }
        showConfigStatus('config-status', 'error', '目标 URL 格式无效，请输入完整 URL (如 http://example.com)');
        showToast('error', 'URL 格式无效', '请输入完整 URL，如 http://example.com');
        return;
    }

    showConfigStatus('config-status', 'info', '正在保存配置...');

    const llmConfig = {};
    if (provider) llmConfig.provider = provider;
    if (baseUrl) llmConfig.baseUrl = baseUrl;
    if (model) llmConfig.model = model;
    if (apiKey) llmConfig.apiKey = apiKey;
    if (format) llmConfig.format = format;

    // ========== LLM 连通性预检 ==========
    const skipTest = (provider === 'ollama' && !apiKey);
    if (!skipTest && apiKey && baseUrl && model) {
        showConfigStatus('config-status', 'info', '正在验证 API Key...');
        try {
            const testResult = await api.waf2.testLLMKey({ apiKey, baseUrl, model, format });
            if (!testResult.success) {
                const errMsg = testResult.error || 'LLM 连接失败';
                const forceApply = confirm(`API Key 验证失败: ${errMsg}\n\n是否仍然保存配置？`);
                if (!forceApply) {
                    if (applyBtn) {
                        applyBtn.classList.remove('btn-loading');
                        applyBtn.textContent = originalBtnText;
                        applyBtn.disabled = false;
                    }
                    showConfigStatus('config-status', 'warning', 'API Key 验证失败，已取消保存');
                    return;
                }
            }
        } catch (e) {
            const forceApply = confirm(`API Key 验证不可用 (WAF2 未连接): ${e.message}\n\n是否仍然保存配置？`);
            if (!forceApply) {
                if (applyBtn) {
                    applyBtn.classList.remove('btn-loading');
                    applyBtn.textContent = originalBtnText;
                    applyBtn.disabled = false;
                }
                showConfigStatus('config-status', 'warning', 'API Key 验证不可用，已取消保存');
                return;
            }
        }
        showConfigStatus('config-status', 'info', '正在保存配置...');
    }

    try {
        const data = await api.waf2.updateConfig({
            upstream: targetUrl || undefined,
            llm: Object.keys(llmConfig).length > 0 ? llmConfig : undefined
        });
        if (data.success) {
            // 进入 success 态
            if (applyBtn) {
                applyBtn.classList.remove('btn-loading');
                applyBtn.classList.add('btn-success-flash');
                applyBtn.textContent = '已保存';
                setTimeout(() => {
                    applyBtn.classList.remove('btn-success-flash');
                    applyBtn.textContent = originalBtnText;
                    applyBtn.disabled = false;
                }, 1500);
            }
            if (data.synced) {
                showConfigStatus('config-status', 'success', '配置已保存，WAF2 已同步生效');
                showToast('success', '配置已保存', 'WAF2 已同步生效');
            } else {
                const errorMsg = data.syncError ? `: ${data.syncError}` : '';
                showConfigStatus('config-status', 'warning', `配置已保存，但 WAF2 同步失败${errorMsg}`);
                showToast('warning', '配置已保存', `WAF2 同步失败${errorMsg}`);
            }
        } else {
            if (applyBtn) {
                applyBtn.classList.remove('btn-loading');
                applyBtn.textContent = originalBtnText;
                applyBtn.disabled = false;
            }
            showConfigStatus('config-status', 'error', data.error || '保存失败');
            showToast('error', '保存失败', data.error || '未知错误');
        }
    } catch (e) {
        if (applyBtn) {
            applyBtn.classList.remove('btn-loading');
            applyBtn.textContent = originalBtnText;
            applyBtn.disabled = false;
        }
        localStorage.setItem('target_url', targetUrl);
        if (apiKey) localStorage.setItem('llm_apikey', apiKey);
        showConfigStatus('config-status', 'warning', '配置已保存到本地 (MCP Hub 不可用)');
        showToast('warning', '配置已保存到本地', 'MCP Hub 不可用，下次启动后生效');
    }
}

function showConfigStatus(containerId, type, message) {
    const container = document.getElementById(containerId);
    if (!container) return;

    container.innerHTML = `
        <div class="status-message ${type}">
            <span>${type === 'success' ? '✓' : type === 'error' ? '✗' : type === 'warning' ? '⚠' : 'ℹ'}</span>
            <span>${escapeHtml(message)}</span>
        </div>
    `;

    setTimeout(() => {
        container.innerHTML = '';
    }, 5000);
}

/**
 * 全局 Toast 通知
 * @param {'success'|'error'|'warning'|'info'} type
 * @param {string} title
 * @param {string} [detail]
 * @param {number} [duration=5000] ms, 0 = 手动关闭
 */
function showToast(type, title, detail, duration = 5000) {
    const icons = { success: '✓', error: '✗', warning: '⚠', info: 'ℹ' };
    const container = document.getElementById('toast-container');
    if (!container) return;

    const el = document.createElement('div');
    el.className = `toast ${type}`;
    el.innerHTML = `
        <span class="toast-icon">${icons[type] || ''}</span>
        <div class="toast-body">
            <div class="toast-title">${escapeHtml(title)}</div>
            ${detail ? `<div class="toast-detail">${escapeHtml(detail)}</div>` : ''}
        </div>
    `;
    container.appendChild(el);

    const remove = () => {
        el.classList.add('toast-fade-out');
        el.addEventListener('animationend', () => el.remove(), { once: true });
    };

    if (duration > 0) setTimeout(remove, duration);
    el.onclick = remove;
}

async function initConfigPanel() {
    try {
        const config = await api.config.get();

        currentMode = config.mode || 'full';
        document.querySelectorAll('.mode-card').forEach(card => {
            card.classList.toggle('selected', card.dataset.mode === currentMode);
        });
        document.getElementById('config-full').style.display = currentMode === 'full' ? 'block' : 'none';
        document.getElementById('config-lite').style.display = currentMode === 'lite' ? 'block' : 'none';
        document.getElementById('guide-full').style.display = currentMode === 'full' ? 'block' : 'none';
        document.getElementById('guide-lite').style.display = currentMode === 'lite' ? 'block' : 'none';
        const waf1Column = document.getElementById('waf1-rules-column');
        if (waf1Column) waf1Column.classList.toggle('disabled', currentMode === 'lite');

        if (config.waf2?.upstream) {
            const targetFull = document.getElementById('cfg-target-url');
            const targetLite = document.getElementById('cfg-target-url-lite');
            if (targetFull) targetFull.value = config.waf2.upstream;
            if (targetLite) targetLite.value = config.waf2.upstream;
        }

        // 回填 LLM Provider 配置
        if (config.waf2?.llm) {
            const llm = config.waf2.llm;
            ['', '-lite'].forEach(suffix => {
                const section = suffix === '' ? 'full' : 'lite';
                const gridEl = document.getElementById(`provider-grid${suffix}`);
                const moreEl = document.getElementById(`provider-more${suffix}`);
                const baseUrlEl = document.getElementById(`cfg-baseurl${suffix}`);
                const modelEl = document.getElementById(`cfg-model${suffix}`);

                // 绑定卡片点击事件
                initProviderCardEvents(section);

                // 选中已保存的 provider 卡片（搜索主网格和更多区域）
                if (llm.provider) {
                    const card = (gridEl && gridEl.querySelector(`.provider-card[data-provider="${llm.provider}"]`)) ||
                                 (moreEl && moreEl.querySelector(`.provider-card[data-provider="${llm.provider}"]`));
                    if (card) {
                        onProviderCardClick(card, section);
                    }
                }
                // 用服务器保存的值覆盖预设值
                if (baseUrlEl && llm.baseUrl) baseUrlEl.value = llm.baseUrl;
                if (modelEl && llm.model) modelEl.value = llm.model;
                // API Key 回填：已配置时显示占位提示
                const apiKeyEl = document.getElementById(`cfg-apikey${suffix}`);
                if (apiKeyEl && llm.apiKey && llm.apiKey.includes('已配置')) {
                    apiKeyEl.value = '';
                    apiKeyEl.placeholder = '••••••••（已配置，留空则保持不变）';
                    apiKeyEl.dataset.configured = 'true';
                }
                // 自定义 Provider 时恢复 format radio 状态
                if (llm.provider === 'custom' && llm.format) {
                    const radio = document.querySelector(`input[name="cfg-format${suffix}"][value="${llm.format}"]`);
                    if (radio) radio.checked = true;
                }
            });
        } else {
            // 无配置时也要绑定事件
            initProviderCardEvents('full');
            initProviderCardEvents('lite');
        }

        // 使用组件设置开关状态
        if (config.waf1?.rules) {
            const waf1RuleMap = {
                'sqlInjection': 'sql',
                'commandInjection': 'cmd',
                'xss': 'xss',
                'pathTraversal': 'path',
                'sensitiveFiles': 'sensitive'
            };
            const states = {};
            for (const [ruleName, dataRule] of Object.entries(waf1RuleMap)) {
                if (config.waf1.rules[ruleName] !== undefined) {
                    states[dataRule] = config.waf1.rules[ruleName];
                }
            }
            setToggleStates(states);
        }

        if (config.waf2?.features) {
            const waf2FeatureMap = {
                'requestAnalysis': 'req',
                'responseAnalysis': 'res',
                'cache': 'cache'
            };
            const states = {};
            for (const [featureName, dataRule] of Object.entries(waf2FeatureMap)) {
                if (config.waf2.features[featureName] !== undefined) {
                    states[dataRule] = config.waf2.features[featureName];
                }
            }
            setToggleStates(states);
        }

        console.log('[Config] 已从服务器加载配置:', config.mode);
        return;
    } catch (e) {
        console.log('[Config] 无法从服务器加载配置，使用本地存储');
    }

    // 后备：从本地存储加载
    const savedMode = localStorage.getItem('protection_mode') || 'full';
    currentMode = savedMode;
    document.querySelectorAll('.mode-card').forEach(card => {
        card.classList.toggle('selected', card.dataset.mode === currentMode);
    });
    document.getElementById('config-full').style.display = currentMode === 'full' ? 'block' : 'none';
    document.getElementById('config-lite').style.display = currentMode === 'lite' ? 'block' : 'none';
    document.getElementById('guide-full').style.display = currentMode === 'full' ? 'block' : 'none';
    document.getElementById('guide-lite').style.display = currentMode === 'lite' ? 'block' : 'none';

    const savedTarget = localStorage.getItem('target_url');
    if (savedTarget) {
        const targetFull = document.getElementById('cfg-target-url');
        const targetLite = document.getElementById('cfg-target-url-lite');
        if (targetFull) targetFull.value = savedTarget;
        if (targetLite) targetLite.value = savedTarget;
    }

    // 后备路径也要绑定卡片事件
    initProviderCardEvents('full');
    initProviderCardEvents('lite');
}

function toggleConfigSection(sectionId) {
    const section = document.querySelector(`.config-section[data-section-id="${sectionId}"]`);
    if (section) section.classList.toggle('collapsed');
}

function toggleProviderMore(section) {
    const suffix = section === 'full' ? '' : '-lite';
    const moreEl = document.getElementById(`provider-more${suffix}`);
    const toggleBtn = moreEl ? moreEl.nextElementSibling : null;
    if (!moreEl) return;
    const isCollapsed = moreEl.classList.toggle('collapsed');
    if (toggleBtn) {
        toggleBtn.classList.toggle('expanded', !isCollapsed);
        const label = toggleBtn.querySelector('.provider-more-label');
        if (label) label.textContent = isCollapsed ? '更多 Provider' : '收起';
    }
}

function toggleAccordion(id) {
    // Legacy compat — route config-guide to unified mechanism
    if (id === 'config-guide') {
        toggleConfigSection('guide');
        return;
    }

    const item = document.querySelector(`[data-accordion="${id}"]`);
    if (item) {
        item.classList.toggle('expanded');
    }
}

function toggleRule(el) {
    el.classList.toggle('active');
    updateRuleStatus();
    showConfigStatus('waf1-config-status', 'info', '规则配置已更新 (前端演示)');
}

function updateRuleStatus() {
    const activeRules = document.querySelectorAll('[data-rule].toggle-switch.active, [data-detector].toggle-switch.active').length;
    const statusEl = document.getElementById('waf1-rules-status');
    if (statusEl) {
        statusEl.textContent = `${activeRules} 规则启用`;
        statusEl.className = `accordion-status ${activeRules > 0 ? 'active' : 'inactive'}`;
    }
}

function selectModel(el) {
    document.querySelectorAll('.model-option').forEach(opt => opt.classList.remove('selected'));
    el.classList.add('selected');
    showConfigStatus('waf2-config-status', 'info', `已选择模型: ${el.dataset.model}`);
}

function toggleAutoRefresh(el) {
    el.classList.toggle('active');
    if (el.classList.contains('active')) {
        startAutoRefresh();
        showConfigStatus('data-mgmt-status', 'success', '自动刷新已开启');
    } else {
        if (refreshTimer) clearInterval(refreshTimer);
        showConfigStatus('data-mgmt-status', 'warning', '自动刷新已暂停');
    }
}

async function testWaf1Connection() {
    showConfigStatus('waf1-config-status', 'info', '正在测试 WAF1 连接...');
    try {
        const data = await api.waf1.getStats();
        showConfigStatus('waf1-config-status', 'success',
            `WAF1 连接成功! 总请求: ${data.total || 0}, 拦截: ${data.blocked || 0}`);
    } catch (e) {
        showConfigStatus('waf1-config-status', 'error', `WAF1 连接失败: ${e.message}`);
    }
}

async function testWaf2Connection() {
    showConfigStatus('waf2-config-status', 'info', '正在测试 WAF2 连接...');
    try {
        const data = await api.waf2.getStats();
        showConfigStatus('waf2-config-status', 'success',
            `WAF2 连接成功! LLM调用: ${data.llm_calls || 0}, 缓存命中: ${data.cache_hit_rate || '0%'}`);
    } catch (e) {
        showConfigStatus('waf2-config-status', 'error', `WAF2 连接失败: ${e.message}`);
    }
}

async function testLLMConfig() {
    const suffix = currentMode === 'full' ? '' : '-lite';
    const statusEl = document.getElementById(`llm-test-status${suffix}`);
    const testBtn = document.getElementById(`llm-test-btn${suffix}`);

    // 读取当前表单值
    const apiKey = document.getElementById(`cfg-apikey${suffix}`)?.value || '';
    const baseUrl = document.getElementById(`cfg-baseurl${suffix}`)?.value || '';
    const model = document.getElementById(`cfg-model${suffix}`)?.value || '';

    // 确定 format
    const selectedCard = document.querySelector(`#provider-grid${suffix} .provider-card.selected`) ||
                         document.querySelector(`#provider-more${suffix} .provider-card.selected`);
    const providerKey = selectedCard ? selectedCard.dataset.provider : 'dashscope';
    let format;
    if (providerKey === 'custom') {
        const checked = document.querySelector(`input[name="cfg-format${suffix}"]:checked`);
        format = checked ? checked.value : 'openai';
    } else {
        const p = LLM_PROVIDERS[providerKey];
        format = p ? p.format : 'openai';
    }

    // 前端校验
    if (providerKey !== 'ollama' && !apiKey) {
        if (statusEl) {
            statusEl.textContent = '请填写 Key';
            statusEl.className = 'llm-test-indicator error';
        }
        return;
    }
    if (!baseUrl || !model) {
        if (statusEl) {
            statusEl.textContent = '请选择 Provider';
            statusEl.className = 'llm-test-indicator error';
        }
        return;
    }

    // Loading 态：按钮显示旋转图标
    if (testBtn) {
        testBtn.classList.add('testing');
        testBtn.disabled = true;
    }
    if (statusEl) {
        statusEl.textContent = '';
        statusEl.className = 'llm-test-indicator';
    }

    try {
        const result = await api.waf2.testLLMKey({ apiKey, baseUrl, model, format });
        if (result.success) {
            if (statusEl) {
                statusEl.textContent = `✓ ${result.latency_ms}ms`;
                statusEl.className = 'llm-test-indicator success';
            }
        } else {
            if (statusEl) {
                statusEl.textContent = '✗ ' + (result.error || '失败');
                statusEl.className = 'llm-test-indicator error';
            }
        }
    } catch (e) {
        if (statusEl) {
            statusEl.textContent = '✗ ' + e.message;
            statusEl.className = 'llm-test-indicator error';
        }
    } finally {
        if (testBtn) {
            testBtn.classList.remove('testing');
            testBtn.disabled = false;
        }
    }
}

async function testAllConnections() {
    showConfigStatus('api-config-status', 'info', '正在测试所有连接...');
    const results = [];

    try {
        await api.waf1.checkHealth();
        results.push('✅ WAF1');
    } catch { results.push('❌ WAF1'); }

    try {
        await api.waf2.checkHealth();
        results.push('✅ WAF2');
    } catch { results.push('❌ WAF2'); }

    showConfigStatus('api-config-status',
        results.every(r => r.startsWith('✅')) ? 'success' : 'warning',
        `连接测试: ${results.join(', ')}`);
}

async function resetWaf1Stats() {
    if (!confirm('确定要重置 WAF1 统计数据吗？')) return;
    try {
        await api.waf1.reset();
        showConfigStatus('waf1-config-status', 'success', 'WAF1 统计已重置');
        refreshData();
    } catch (e) {
        showConfigStatus('waf1-config-status', 'error', `重置失败: ${e.message}`);
    }
}

async function resetWaf2Stats() {
    if (!confirm('确定要重置 WAF2 统计数据吗？')) return;
    try {
        await api.waf2.reset();
        showConfigStatus('waf2-config-status', 'success', 'WAF2 统计已重置');
        refreshData();
    } catch (e) {
        showConfigStatus('waf2-config-status', 'error', `重置失败: ${e.message}`);
    }
}

function clearWaf2Cache() {
    showConfigStatus('waf2-config-status', 'warning', '缓存清理功能需要后端 API 支持');
}

function saveApiConfig() {
    saveConfig();
    showConfigStatus('api-config-status', 'success', '配置已保存到本地存储');
}

function exportLogs() {
    const logs = {
        waf1: waf1Data,
        waf2: waf2Data,
        detections: allDetections,
        exportTime: new Date().toISOString()
    };

    const blob = new Blob([JSON.stringify(logs, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `waf-logs-${new Date().toISOString().slice(0,10)}.json`;
    a.click();
    URL.revokeObjectURL(url);

    showConfigStatus('data-mgmt-status', 'success', '日志已导出');
}

// ==================== MCP Server 管理 ====================

// 存储 MCP Server 配置
let mcpServerConfigs = [];
let editingServerName = null;  // 正在编辑的 Server 名称

async function fetchMcpServers() {
    try {
        // 获取运行时状态
        const data = await api.servers.list();
        mcpServers = data.servers || [];

        // 获取配置信息
        try {
            const configData = await api.mcpConfig.listServers();
            mcpServerConfigs = configData.servers || [];
            // 更新配置路径显示
            const pathEl = document.getElementById('mcp-config-path');
            if (pathEl && configData.configPath) {
                pathEl.textContent = configData.configPath;
            }
        } catch (e) {
            console.log('获取 MCP 配置失败:', e);
            mcpServerConfigs = [];
        }

        renderServersList();
        if (selectedServer) {
            selectedServer = mcpServers.find(s => s.name === selectedServer.name);
            renderServerDetail();
        }
    } catch (e) {
        console.error('获取 MCP Servers 失败:', e);
        document.getElementById('servers-list').innerHTML =
            '<div class="empty-state">无法连接到 MCP Hub</div>';
    }
}

function renderServersList() {
    const container = document.getElementById('servers-list');

    if (!mcpServers || mcpServers.length === 0) {
        container.innerHTML = '<div class="empty-state">暂无 MCP Server<br><small style="color:#666">点击 + 添加</small></div>';
        return;
    }

    const html = mcpServers.map(server => {
        const tools = server.capabilities?.tools || [];
        const resources = server.capabilities?.resources || [];
        const isSelected = selectedServer?.name === server.name;
        const hasError = server.status === 'error' || server.status === 'disconnected';
        const errorMsg = server.error ? escapeHtml(server.error.substring(0, 50)) : '';

        return `
            <div class="server-list-item ${isSelected ? 'selected' : ''} ${hasError ? 'has-error' : ''}"
                 onclick="selectServer('${escapeHtml(server.name)}')"
                 title="${errorMsg || server.status}">
                <div class="name">
                    ${escapeHtml(server.displayName || server.name)}
                    <span class="server-status ${server.status}">${server.status}</span>
                </div>
                <div class="meta">
                    ${hasError && errorMsg ? `<span class="error-hint">${errorMsg}...</span>` : `${tools.length} tools, ${resources.length} resources`}
                </div>
            </div>
        `;
    }).join('');

    container.innerHTML = html;
}

function selectServer(serverName) {
    selectedServer = mcpServers.find(s => s.name === serverName);
    renderServersList();
    renderServerDetail();
    initInspectorTabs();
}

function renderServerDetail() {
    const emptyEl = document.getElementById('server-detail-empty');
    const detailEl = document.getElementById('server-detail');

    if (!selectedServer) {
        emptyEl.style.display = 'block';
        detailEl.style.display = 'none';
        return;
    }

    emptyEl.style.display = 'none';
    detailEl.style.display = 'block';

    document.getElementById('detail-server-name').textContent = selectedServer.displayName || selectedServer.name;
    document.getElementById('detail-server-status').textContent = selectedServer.status;
    document.getElementById('detail-server-status').className = `server-status ${selectedServer.status}`;
    document.getElementById('detail-version').textContent = selectedServer.serverInfo?.version || '-';
    document.getElementById('detail-uptime').textContent = selectedServer.uptime ? formatUptime(selectedServer.uptime) : '-';
    document.getElementById('detail-transport').textContent = selectedServer.transportType || 'stdio';

    // 显示错误信息
    const errorBanner = document.getElementById('server-error-banner');
    if (selectedServer.error) {
        if (!errorBanner) {
            // 动态创建错误横幅
            const banner = document.createElement('div');
            banner.id = 'server-error-banner';
            banner.className = 'error-banner';
            banner.innerHTML = `<strong>启动失败:</strong> <span id="server-error-msg"></span>`;
            const header = detailEl.querySelector('.server-header');
            header.parentNode.insertBefore(banner, header.nextSibling);
        }
        document.getElementById('server-error-msg').textContent = selectedServer.error;
        document.getElementById('server-error-banner').style.display = 'block';
    } else if (errorBanner) {
        errorBanner.style.display = 'none';
    }

    renderToolsList();
    renderResourcesList();
    renderPromptsList();
}

function initInspectorTabs() {
    document.querySelectorAll('.inspector-tab').forEach(tab => {
        tab.onclick = () => {
            if (tab.classList.contains('active')) return;
            document.querySelectorAll('.inspector-tab').forEach(t => t.classList.remove('active'));
            tab.classList.add('active');

            document.querySelectorAll('.inspector-tab-content').forEach(c => {
                c.style.display = 'none';
                c.classList.remove('panel-entering');
            });
            const panel = document.getElementById(`stab-${tab.dataset.stab}`);
            if (panel) {
                panel.style.display = 'block';
                panel.classList.add('panel-entering');
                panel.addEventListener('animationend', () => {
                    panel.classList.remove('panel-entering');
                }, { once: true });
            }
        };
    });
}

function renderToolsList() {
    const container = document.getElementById('tools-list');
    const tools = selectedServer?.capabilities?.tools || [];

    if (tools.length === 0) {
        container.innerHTML = '<div class="empty-state">暂无工具</div>';
        return;
    }

    const html = tools.map((tool, idx) => {
        const params = tool.inputSchema?.properties || {};
        const required = tool.inputSchema?.required || [];

        const paramBadges = Object.keys(params).map(name => {
            const isReq = required.includes(name);
            return `<span class="param-badge ${isReq ? 'required' : ''}">${escapeHtml(name)}${isReq ? '*' : ''}</span>`;
        }).join('');

        return `
            <div class="tool-card">
                <div class="tool-header">
                    <span class="tool-name">${escapeHtml(tool.name)}</span>
                    <button class="test-btn" onclick="openToolTest(${idx})">测试</button>
                </div>
                <div class="tool-desc">${escapeHtml((tool.description || '无描述').substring(0, 150))}${tool.description?.length > 150 ? '...' : ''}</div>
                <div class="tool-params-preview">${paramBadges || '<span style="color:#666">无参数</span>'}</div>
            </div>
        `;
    }).join('');

    container.innerHTML = html;
}

function renderResourcesList() {
    const container = document.getElementById('resources-list');
    const resources = selectedServer?.capabilities?.resources || [];

    if (resources.length === 0) {
        container.innerHTML = '<div class="empty-state">暂无资源</div>';
        return;
    }

    const html = resources.map(res => `
        <div class="resource-item">
            <div class="resource-name">${escapeHtml(res.name)}</div>
            <div class="resource-uri">${escapeHtml(res.uri)}</div>
            ${res.mimeType ? `<div class="resource-mime">类型: ${escapeHtml(res.mimeType)}</div>` : ''}
            ${res.description ? `<div class="resource-mime">${escapeHtml(res.description)}</div>` : ''}
        </div>
    `).join('');

    container.innerHTML = html;
}

function renderPromptsList() {
    const container = document.getElementById('prompts-list');
    const prompts = selectedServer?.capabilities?.prompts || [];

    if (prompts.length === 0) {
        container.innerHTML = '<div class="empty-state">暂无提示词模板</div>';
        return;
    }

    const html = prompts.map(p => `
        <div class="prompt-item">
            <div class="prompt-name">${escapeHtml(p.name)}</div>
            ${p.description ? `<div class="prompt-desc">${escapeHtml(p.description)}</div>` : ''}
        </div>
    `).join('');

    container.innerHTML = html;
}

function openToolTest(toolIndex) {
    const tools = selectedServer?.capabilities?.tools || [];
    currentTestTool = tools[toolIndex];

    if (!currentTestTool) return;

    document.getElementById('test-tool-name').textContent = currentTestTool.name;
    document.getElementById('tool-test-panel').style.display = 'block';
    document.getElementById('test-output').textContent = '等待执行...';
    document.getElementById('test-output').classList.remove('error');

    const formContainer = document.getElementById('test-form');
    const params = currentTestTool.inputSchema?.properties || {};
    const required = currentTestTool.inputSchema?.required || [];

    if (Object.keys(params).length === 0) {
        formContainer.innerHTML = '<div style="color:#888">此工具无需参数</div>';
        return;
    }

    const formHtml = Object.entries(params).map(([name, prop]) => {
        const isReq = required.includes(name);
        const type = prop.type || 'string';
        let inputHtml = '';

        if (prop.enum) {
            inputHtml = `<select id="param-${escapeHtml(name)}">
                ${prop.enum.map(v => `<option value="${escapeHtml(v)}">${escapeHtml(v)}</option>`).join('')}
            </select>`;
        } else if (type === 'object') {
            inputHtml = `<textarea id="param-${escapeHtml(name)}" rows="2" placeholder='{"key": "value"}'></textarea>`;
        } else {
            inputHtml = `<input type="text" id="param-${escapeHtml(name)}" placeholder="${escapeHtml(prop.description || name)}">`;
        }

        return `
            <div class="form-group">
                <label>${escapeHtml(name)} ${isReq ? '<span class="required">*</span>' : ''}</label>
                ${inputHtml}
            </div>
        `;
    }).join('');

    formContainer.innerHTML = formHtml;
}

function closeToolTest() {
    document.getElementById('tool-test-panel').style.display = 'none';
    currentTestTool = null;
}

async function executeToolTest() {
    if (!currentTestTool || !selectedServer) return;

    const outputEl = document.getElementById('test-output');
    outputEl.textContent = '执行中...';
    outputEl.classList.remove('error');

    const params = currentTestTool.inputSchema?.properties || {};
    const args = {};

    for (const name of Object.keys(params)) {
        const el = document.getElementById(`param-${name}`);
        if (el && el.value) {
            if (params[name].type === 'object') {
                try {
                    args[name] = JSON.parse(el.value);
                } catch {
                    args[name] = el.value;
                }
            } else {
                args[name] = el.value;
            }
        }
    }

    try {
        const result = await api.servers.callTool(selectedServer.name, currentTestTool.name, args);
        outputEl.textContent = JSON.stringify(result, null, 2);

        if (result.error || result.isError) {
            outputEl.classList.add('error');
        }
    } catch (e) {
        outputEl.textContent = `请求失败: ${e.message}`;
        outputEl.classList.add('error');
    }
}

// ==================== 统计重置 ====================

async function resetAllStats() {
    if (!confirm('确定要重置所有统计数据吗？')) return;

    try {
        await Promise.all([
            api.waf1.reset(),
            api.waf2.reset()
        ]);
        await refreshData();
        alert('统计数据已重置');
    } catch (e) {
        alert('重置失败: ' + e.message);
    }
}

// ==================== 全局函数导出 (供 HTML onclick 使用) ====================

window.logout = logout;
window.selectMode = selectMode;
window.copyToClipboard = copyToClipboard;
window.copyCodeBlock = copyCodeBlock;
window.togglePasswordVisibility = togglePasswordVisibility;
window.toggleRuleSm = toggleRuleSm;
window.applyConfig = applyConfig;
window.toggleAccordion = toggleAccordion;
window.toggleConfigSection = toggleConfigSection;
window.toggleProviderMore = toggleProviderMore;
window.toggleRule = toggleRule;
window.selectModel = selectModel;
window.toggleAutoRefresh = toggleAutoRefresh;
window.testWaf1Connection = testWaf1Connection;
window.testWaf2Connection = testWaf2Connection;
window.testLLMConfig = testLLMConfig;
window.testAllConnections = testAllConnections;
window.resetWaf1Stats = resetWaf1Stats;
window.resetWaf2Stats = resetWaf2Stats;
window.clearWaf2Cache = clearWaf2Cache;
window.saveApiConfig = saveApiConfig;
window.exportLogs = exportLogs;
window.refreshData = refreshData;
window.manualRefreshData = manualRefreshData;
window.resetAllStats = resetAllStats;
window.fetchMcpServers = fetchMcpServers;
window.selectServer = selectServer;
window.openToolTest = openToolTest;
window.closeToolTest = closeToolTest;
window.executeToolTest = executeToolTest;

// MCP Server 配置管理
window.openAddServerModal = openAddServerModal;
window.closeServerModal = closeServerModal;
window.selectServerType = selectServerType;
window.saveServer = saveServer;
window.editCurrentServer = editCurrentServer;
window.deleteCurrentServer = deleteCurrentServer;

// ==================== MCP Server 配置 CRUD ====================

function openAddServerModal() {
    editingServerName = null;
    document.getElementById('server-modal-title').textContent = '添加 MCP Server';
    document.getElementById('server-name').value = '';
    document.getElementById('server-name').disabled = false;
    document.getElementById('server-display-name').value = '';
    document.getElementById('server-command').value = '';
    document.getElementById('server-args').value = '';
    document.getElementById('server-env').value = '';
    document.getElementById('server-url').value = '';
    document.getElementById('server-headers').value = '';
    selectServerType('stdio');
    const modal = document.getElementById('server-modal');
    modal.classList.remove('modal-closing');
    modal.style.display = 'flex';
}

function closeServerModal() {
    const modal = document.getElementById('server-modal');
    if (!modal || modal.style.display === 'none') return;
    modal.classList.add('modal-closing');
    modal.addEventListener('animationend', function handler() {
        modal.removeEventListener('animationend', handler);
        modal.style.display = 'none';
        modal.classList.remove('modal-closing');
    });
    editingServerName = null;
}

function selectServerType(type) {
    document.querySelectorAll('.type-option').forEach(opt => {
        opt.classList.toggle('selected', opt.dataset.type === type);
    });
    document.getElementById('stdio-config').style.display = type === 'stdio' ? 'block' : 'none';
    document.getElementById('sse-config').style.display = type === 'sse' ? 'block' : 'none';
}

async function saveServer() {
    const name = document.getElementById('server-name').value.trim();
    const displayName = document.getElementById('server-display-name').value.trim();
    const selectedType = document.querySelector('.type-option.selected')?.dataset.type || 'stdio';

    if (!name) {
        alert('请输入 Server 名称');
        return;
    }

    let serverConfig = {};

    if (displayName) {
        serverConfig.displayName = displayName;
    }

    if (selectedType === 'stdio') {
        const command = document.getElementById('server-command').value.trim();
        const argsStr = document.getElementById('server-args').value.trim();
        const envStr = document.getElementById('server-env').value.trim();

        if (!command) {
            alert('请输入命令');
            return;
        }

        serverConfig.command = command;

        if (argsStr) {
            try {
                const parsed = JSON.parse(argsStr);
                if (!Array.isArray(parsed)) {
                    alert('参数必须是 JSON 数组格式，例如: ["-y", "@pkg/name"]');
                    return;
                }
                serverConfig.args = parsed;
            } catch (e) {
                alert('参数 JSON 格式无效，例如: ["-y", "@pkg/name"]');
                return;
            }
        }

        if (envStr) {
            try {
                serverConfig.env = JSON.parse(envStr);
            } catch (e) {
                alert('环境变量 JSON 格式无效');
                return;
            }
        }
    } else {
        const url = document.getElementById('server-url').value.trim();
        const headersStr = document.getElementById('server-headers').value.trim();

        if (!url) {
            alert('请输入 URL');
            return;
        }

        serverConfig.url = url;

        if (headersStr) {
            try {
                serverConfig.headers = JSON.parse(headersStr);
            } catch (e) {
                alert('Headers JSON 格式无效');
                return;
            }
        }
    }

    try {
        const targetName = editingServerName || name;

        if (editingServerName) {
            await api.mcpConfig.updateServer(editingServerName, serverConfig);
        } else {
            await api.mcpConfig.addServer(name, serverConfig);
        }

        closeServerModal();
        showToast('info', `Server '${targetName}'`, editingServerName ? '配置已更新，正在重新连接...' : '已添加，正在连接...');

        // 轮询等待连接结果
        pollServerStatus(targetName);
    } catch (e) {
        const errMsg = e.data?.error || e.message;
        showToast('error', '保存失败', errMsg, 8000);
    }
}

/**
 * 保存后轮询 server 状态，等待连接结果并弹 toast
 */
function pollServerStatus(serverName, interval = 2000, timeout = 30000) {
    const start = Date.now();

    const poll = async () => {
        try {
            await fetchMcpServers();
            const server = mcpServers.find(s => s.name === serverName);

            if (!server) {
                // server 还没出现在列表中，继续等
                if (Date.now() - start < timeout) {
                    setTimeout(poll, interval);
                }
                return;
            }

            if (server.status === 'connected') {
                showToast('success', `Server '${serverName}' 连接成功`);
                return;
            }

            if (server.status === 'error') {
                showToast('error', `Server '${serverName}' 启动失败`, server.error || '未知错误', 8000);
                return;
            }

            // 还在连接中 (disconnected / connecting 等)
            if (Date.now() - start < timeout) {
                setTimeout(poll, interval);
            } else {
                showToast('warning', `Server '${serverName}'`, '连接超时，请在列表中查看状态', 6000);
            }
        } catch (e) {
            // 网络错误，继续重试
            if (Date.now() - start < timeout) {
                setTimeout(poll, interval);
            }
        }
    };

    // 首次等 1.5 秒让后端处理配置变更
    setTimeout(poll, 1500);
}

function editCurrentServer() {
    if (!selectedServer) return;

    const serverConfig = mcpServerConfigs.find(s => s.name === selectedServer.name);
    if (!serverConfig) {
        alert('无法获取 Server 配置');
        return;
    }

    editingServerName = selectedServer.name;
    document.getElementById('server-modal-title').textContent = '编辑 MCP Server';
    document.getElementById('server-name').value = selectedServer.name;
    document.getElementById('server-name').disabled = true;  // 不允许修改名称
    document.getElementById('server-display-name').value = serverConfig.displayName || '';

    if (serverConfig.command) {
        selectServerType('stdio');
        document.getElementById('server-command').value = serverConfig.command || '';
        document.getElementById('server-args').value = (serverConfig.args && serverConfig.args.length) ? JSON.stringify(serverConfig.args, null, 2) : '';
        document.getElementById('server-env').value = serverConfig.env ? JSON.stringify(serverConfig.env, null, 2) : '';
    } else if (serverConfig.url) {
        selectServerType('sse');
        document.getElementById('server-url').value = serverConfig.url || '';
        document.getElementById('server-headers').value = serverConfig.headers ? JSON.stringify(serverConfig.headers, null, 2) : '';
    }

    const modal = document.getElementById('server-modal');
    modal.classList.remove('modal-closing');
    modal.style.display = 'flex';
}

async function deleteCurrentServer() {
    if (!selectedServer) return;

    if (!confirm(`确定要删除 Server '${selectedServer.name}' 吗？`)) {
        return;
    }

    try {
        await api.mcpConfig.deleteServer(selectedServer.name);
        showToast('success', `Server '${selectedServer.name}' 已删除`);
        selectedServer = null;
        setTimeout(() => fetchMcpServers(), 1000);
    } catch (e) {
        const errMsg = e.data?.error || e.message;
        showToast('error', '删除失败', errMsg, 8000);
    }
}

// 更新 renderServerDetail 以显示配置信息
const originalRenderServerDetail = renderServerDetail;
function renderServerDetailWithConfig() {
    originalRenderServerDetail();

    // 显示配置 JSON
    if (selectedServer) {
        const serverConfig = mcpServerConfigs.find(s => s.name === selectedServer.name);
        const configJsonEl = document.getElementById('server-config-json');
        if (configJsonEl && serverConfig) {
            const { config_source, type, ...cleanConfig } = serverConfig;
            configJsonEl.textContent = JSON.stringify(cleanConfig, null, 2);
        }
    }
}

// 替换原函数
window.renderServerDetail = renderServerDetailWithConfig;

// ==================== 态势感知模块 ====================

// --- State ---
let monitorTimer = null;
let monitorPrevLogIds = new Set();
let monitorPrevWaf1Blocked = 0;
let monitorPrevWaf2Blocked = 0;
let monitorOwaspChart = null;
let monitorCompareChart = null;

// --- Fullscreen (Group 3) ---

function enterMonitorFullscreen() {
    document.body.classList.add('monitor-fullscreen');
    const exitBtn = document.getElementById('monitor-exit-fullscreen');
    if (exitBtn) exitBtn.style.display = 'flex';
    try {
        document.documentElement.requestFullscreen();
    } catch (e) {
        // Safari fallback
        try { document.documentElement.webkitRequestFullscreen(); } catch (_) {}
    }
}

function exitMonitorFullscreen() {
    document.body.classList.remove('monitor-fullscreen');
    const exitBtn = document.getElementById('monitor-exit-fullscreen');
    if (exitBtn) exitBtn.style.display = 'none';
    try {
        if (document.fullscreenElement) {
            document.exitFullscreen();
        } else if (document.webkitFullscreenElement) {
            document.webkitExitFullscreen();
        }
    } catch (_) {}
}

document.addEventListener('fullscreenchange', () => {
    if (!document.fullscreenElement) {
        document.body.classList.remove('monitor-fullscreen');
        const exitBtn = document.getElementById('monitor-exit-fullscreen');
        if (exitBtn) exitBtn.style.display = 'none';
    }
});

document.addEventListener('webkitfullscreenchange', () => {
    if (!document.webkitFullscreenElement) {
        document.body.classList.remove('monitor-fullscreen');
        const exitBtn = document.getElementById('monitor-exit-fullscreen');
        if (exitBtn) exitBtn.style.display = 'none';
    }
});

window.enterMonitorFullscreen = enterMonitorFullscreen;
window.exitMonitorFullscreen = exitMonitorFullscreen;

// --- Data Layer (Group 4) ---

async function monitorRefresh() {
    const WAF2_BASE = localStorage.getItem('waf2_url') || 'http://localhost:8081';

    const [w1Dashboard, w2Dashboard, serversData] = await Promise.all([
        fetch('/api/waf1/dashboard', { credentials: 'include' }).then(r => r.ok ? r.json() : null).catch(() => null),
        fetch(`${WAF2_BASE}/waf2/dashboard`, { credentials: 'include' }).then(r => r.ok ? r.json() : null).catch(() => null),
        fetch('/api/servers', { credentials: 'include' }).then(r => r.ok ? r.json() : null).catch(() => null)
    ]);

    monitorUpdateLogStream(w1Dashboard, w2Dashboard);
    monitorUpdateTopology(w1Dashboard, w2Dashboard, serversData);
    monitorUpdateThreatLevel(w1Dashboard, w2Dashboard);
    monitorUpdateOwaspChart(w1Dashboard, w2Dashboard);
    monitorUpdateCompareChart(w1Dashboard, w2Dashboard);
}

function startMonitorRefresh() {
    if (monitorTimer) return;
    monitorRefresh();
    monitorTimer = setInterval(monitorRefresh, 5000);
}

function stopMonitorRefresh() {
    if (monitorTimer) {
        clearInterval(monitorTimer);
        monitorTimer = null;
    }
}

// --- Panel Rendering (Group 5) ---

function monitorFormatTime(ts) {
    if (!ts) return '--:--:--';
    const d = new Date(ts);
    if (isNaN(d.getTime())) return '--:--:--';
    return d.toLocaleTimeString('zh-CN', { hour12: false });
}

function monitorAnimateValue(el, from, to, duration = 600) {
    if (from === to) return;
    const start = performance.now();
    const step = (now) => {
        const progress = Math.min((now - start) / duration, 1);
        const eased = 1 - Math.pow(1 - progress, 3);
        el.textContent = Math.round(from + (to - from) * eased);
        if (progress < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
}

function monitorSeverityClass(sev) {
    if (!sev) return 'monitor-sev-info';
    const s = sev.toLowerCase();
    if (s === 'critical') return 'monitor-sev-critical';
    if (s === 'high') return 'monitor-sev-high';
    if (s === 'medium') return 'monitor-sev-medium';
    if (s === 'low') return 'monitor-sev-low';
    return 'monitor-sev-info';
}

// 5.1 Attack Log Stream (增量更新: 复用已存在行, 避免全量重绘闪烁)
function monitorUpdateLogStream(waf1, waf2) {
    const container = document.getElementById('monitor-log-stream');
    const emptyEl = document.getElementById('monitor-log-empty');
    const countEl = document.getElementById('monitor-log-count');
    if (!container) return;

    const entries = [];

    if (waf1 && Array.isArray(waf1.recentDetections)) {
        waf1.recentDetections.forEach((d) => {
            const t = d.ts || d.labels?.timestamp || d.timestamp;
            entries.push({
                id: `w1-${d.ts || t}`,
                time: t,
                source: 'WAF1',
                category: d.category || d.labels?.category || 'unknown',
                severity: d.severity || d.labels?.severity || 'medium',
                reason: d.reason || ''
            });
        });
    }

    if (waf2 && Array.isArray(waf2.recent_detections)) {
        waf2.recent_detections.forEach((d) => {
            entries.push({
                id: `w2-${d.timestamp || d.ts}`,
                time: d.timestamp || d.ts,
                source: 'WAF2',
                category: d.category || d.type || 'unknown',
                severity: d.severity || 'medium',
                reason: d.reason || d.details || ''
            });
        });
    }

    entries.sort((a, b) => {
        const ta = a.time ? new Date(a.time).getTime() : 0;
        const tb = b.time ? new Date(b.time).getTime() : 0;
        return tb - ta;
    });

    const display = entries.slice(0, 50);
    if (countEl) countEl.textContent = entries.length;

    if (display.length === 0) {
        if (emptyEl) emptyEl.style.display = 'flex';
        return;
    }
    if (emptyEl) emptyEl.style.display = 'none';

    const newIds = new Set(display.map(e => e.id));

    // 收集已存在的行 (按 data-id), 增量复用
    const existing = new Map();
    Array.from(container.children).forEach(c => {
        if (c !== emptyEl && c.dataset.id) existing.set(c.dataset.id, c);
    });

    let prev = null;
    display.forEach(e => {
        let row = existing.get(e.id);
        const srcClass = e.source === 'WAF1' ? 'monitor-log-source-waf1' : 'monitor-log-source-waf2';
        if (row) {
            // 已存在行: 不重写内容(避免重绘闪烁), 仅用于排序定位
        } else {
            // 新行: 创建并标记 flash 淡入
            row = document.createElement('div');
            row.dataset.id = e.id;
            row.className = 'monitor-log-entry flash';
            row.innerHTML =
                `<span class="monitor-log-time">${monitorFormatTime(e.time)}</span>` +
                `<span class="monitor-log-source ${srcClass}">${e.source}</span>` +
                `<span class="monitor-log-detail">${escapeHtml(e.category)}${e.reason ? ' — ' + escapeHtml(e.reason) : ''}</span>` +
                `<span class="monitor-log-severity ${monitorSeverityClass(e.severity)}">${(e.severity || 'info').toUpperCase()}</span>`;
        }
        // 按顺序就位 (移动已有元素不会触发重绘闪烁)
        const desiredNext = prev ? prev.nextElementSibling : container.firstChild;
        if (desiredNext !== row) {
            if (prev) prev.insertAdjacentElement('afterend', row);
            else container.insertBefore(row, emptyEl);
        }
        prev = row;
    });

    // 移除已不在列表的旧行
    existing.forEach((el, id) => { if (!newIds.has(id)) el.remove(); });
    monitorPrevLogIds = newIds;
}

// 5.2 Topology
function monitorUpdateTopology(waf1, waf2, servers) {
    const mcpCountEl = document.getElementById('m-mcp-count');
    if (servers) {
        const list = servers.servers || servers;
        if (Array.isArray(list)) {
            const online = list.filter(s => s.status === 'connected').length;
            if (mcpCountEl) mcpCountEl.textContent = `${online} 个在线`;
        }
    }

    const waf1Node = document.getElementById('m-node-waf1');
    const waf1Status = waf1Node?.querySelector('.m-node-status');
    if (waf1 && waf1.enabled !== false) {
        waf1Status?.classList.remove('m-status-offline');
        waf1Status?.classList.add('m-status-online');
    } else {
        waf1Status?.classList.remove('m-status-online');
        waf1Status?.classList.add('m-status-offline');
    }

    const waf2Node = document.getElementById('m-node-waf2');
    const waf2Status = waf2Node?.querySelector('.m-node-status');
    if (waf2) {
        waf2Status?.classList.remove('m-status-offline');
        waf2Status?.classList.add('m-status-online');
    } else {
        waf2Status?.classList.remove('m-status-online');
        waf2Status?.classList.add('m-status-offline');
    }

    const waf1Blocked = waf1?.summary?.blocked || waf1?.stats?.blocked || 0;
    const waf2Blocked = (waf2?.summary?.blocked || 0) + (waf2?.stats?.blocked_requests || 0) + (waf2?.stats?.blocked_responses || 0);

    if (waf1Blocked > monitorPrevWaf1Blocked) {
        monitorTriggerNodeAlert('m-node-waf1', 'm-line-agent-waf1');
    }
    if (waf2Blocked > monitorPrevWaf2Blocked) {
        monitorTriggerNodeAlert('m-node-waf2', 'm-line-waf2-target');
    }

    monitorPrevWaf1Blocked = waf1Blocked;
    monitorPrevWaf2Blocked = waf2Blocked;
}

const monitorAlertLast = {};
function monitorTriggerNodeAlert(nodeId, lineId) {
    // 节流: 同一节点 3s 内不重复触发 alert, 避免演示期间持续攻击导致节点狂闪
    const now = Date.now();
    if (monitorAlertLast[nodeId] && now - monitorAlertLast[nodeId] < 3000) return;
    monitorAlertLast[nodeId] = now;
    const node = document.getElementById(nodeId);
    const line = document.getElementById(lineId);
    node?.classList.add('alert');
    line?.classList.add('alert');
    setTimeout(() => {
        node?.classList.remove('alert');
        line?.classList.remove('alert');
    }, 2000);
}

// 5.3 Threat Level
function monitorUpdateThreatLevel(waf1, waf2) {
    const w1s = waf1?.summary || waf1?.stats || {};
    const w2s = waf2?.summary || waf2?.stats || {};

    const totalReqs = (w1s.total || 0) + (w2s.total || w2s.total_requests || 0);
    const totalBlocked = (w1s.blocked || 0) + (w2s.blocked || 0) + (w2s.blocked_requests || 0) + (w2s.blocked_responses || 0);
    const rate = totalReqs > 0 ? Math.round(totalBlocked / totalReqs * 100) : 0;

    const rateEl = document.getElementById('monitor-block-rate');
    if (rateEl && rateEl.dataset.rate !== String(rate)) {
        rateEl.dataset.rate = String(rate);
        rateEl.innerHTML = `${rate}<span class="monitor-ring-unit">%</span>`;
    }

    const sev = { critical: 0, high: 0, medium: 0, low: 0 };

    const w1Sev = waf1?.last24h?.bySeverity || waf1?.summary?.bySeverity || {};
    Object.entries(w1Sev).forEach(([k, v]) => {
        const key = k.toLowerCase();
        if (sev[key] !== undefined) sev[key] += v;
    });

    const w2Sev = waf2?.summary?.by_severity || waf2?.stats?.by_severity || waf2?.by_severity || {};
    Object.entries(w2Sev).forEach(([k, v]) => {
        const key = k.toLowerCase();
        if (sev[key] !== undefined) sev[key] += v;
    });

    const maxCount = Math.max(sev.critical, sev.high, sev.medium, sev.low, 1);

    ['critical', 'high', 'medium', 'low'].forEach(level => {
        const countEl = document.getElementById(`monitor-count-${level}`);
        const barEl = document.getElementById(`monitor-bar-${level}`);
        if (countEl) {
            const prev = parseInt(countEl.textContent) || 0;
            monitorAnimateValue(countEl, prev, sev[level]);
        }
        if (barEl) {
            barEl.style.width = `${Math.round(sev[level] / maxCount * 100)}%`;
        }
    });
}

// 5.4 OWASP Chart
const MONITOR_GRAFANA_COLORS = [
    '#5794f2', '#73bf69', '#e05263', '#ff9830',
    '#b877d9', '#fade2a', '#8ab8ff', '#37872d',
    '#c4162a', '#e0b400'
];

const MONITOR_WAF1_OWASP_MAP = {
    sqlInjection: 'A03:2021', shellInjection: 'A03:2021', xss: 'A03:2021',
    pathTraversal: 'A01:2021', sensitiveFiles: 'A01:2021', dataExfiltration: 'A01:2021',
    ssrf: 'A10:2021', dangerousOperations: 'A03:2021', protocolAttacks: 'A05:2021',
    secrets: 'A02:2021', pii: 'A02:2021',
    callChain: 'LLM01', dynamicPolicy: 'LLM01', supabaseCallChain: 'LLM01'
};

const MONITOR_WAF2_OWASP_MAP = {
    sql_injection: 'A03:2021', command_injection: 'A03:2021', xss: 'A03:2021',
    path_traversal: 'A01:2021', ssrf: 'A10:2021', prompt_injection: 'LLM01',
    sensitive_data_exposure: 'A02:2021'
};

function monitorUpdateOwaspChart(waf1, waf2) {
    const owasp = {};

    const w1Cat = waf1?.last24h?.byCategory || {};
    Object.entries(w1Cat).forEach(([cat, count]) => {
        const code = MONITOR_WAF1_OWASP_MAP[cat];
        if (code && count > 0) owasp[code] = (owasp[code] || 0) + count;
    });

    const w2Cat = waf2?.by_category || {};
    Object.entries(w2Cat).forEach(([cat, count]) => {
        const code = MONITOR_WAF2_OWASP_MAP[cat];
        if (code && count > 0) owasp[code] = (owasp[code] || 0) + count;
    });

    let labels = Object.keys(owasp).filter(k => owasp[k] > 0);
    let values = labels.map(k => owasp[k]);

    if (labels.length === 0) {
        labels = ['暂无数据'];
        values = [0];
    }

    const ctx = document.getElementById('monitor-owasp-chart');
    if (!ctx) return;

    if (!monitorOwaspChart) {
        monitorOwaspChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels,
                datasets: [{
                    data: values,
                    backgroundColor: MONITOR_GRAFANA_COLORS.slice(0, labels.length).map(c => c + '99'),
                    borderColor: MONITOR_GRAFANA_COLORS.slice(0, labels.length),
                    borderWidth: 1,
                    borderRadius: 3,
                    barPercentage: 0.7
                }]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    x: {
                        grid: { color: 'rgba(240,246,252,0.04)' },
                        ticks: { color: '#8b949e', font: { family: "'Inter'", size: 10 } }
                    },
                    y: {
                        grid: { display: false },
                        ticks: { color: '#8b949e', font: { family: "'Inter'", size: 10 } }
                    }
                }
            }
        });
    } else {
        monitorOwaspChart.data.labels = labels;
        monitorOwaspChart.data.datasets[0].data = values;
        monitorOwaspChart.data.datasets[0].backgroundColor = MONITOR_GRAFANA_COLORS.slice(0, labels.length).map(c => c + '99');
        monitorOwaspChart.data.datasets[0].borderColor = MONITOR_GRAFANA_COLORS.slice(0, labels.length);
        monitorOwaspChart.update('none');
    }
}

// 5.5 WAF1 vs WAF2 Compare
function monitorUpdateCompareChart(waf1, waf2) {
    const w1Total = waf1?.summary?.blocked || waf1?.stats?.blocked || 0;
    const w2Total = (waf2?.summary?.blocked || 0) + (waf2?.stats?.blocked_requests || 0) + (waf2?.stats?.blocked_responses || 0);

    const w1El = document.getElementById('monitor-compare-waf1');
    const w2El = document.getElementById('monitor-compare-waf2');
    if (w1El) monitorAnimateValue(w1El, parseInt(w1El.textContent) || 0, w1Total);
    if (w2El) monitorAnimateValue(w2El, parseInt(w2El.textContent) || 0, w2Total);

    const w1Cat = {};
    const w1Rules = waf1?.stats?.byRule || waf1?.rules || waf1?.by_category || {};
    Object.entries(w1Rules).forEach(([k, v]) => { if (v > 0) w1Cat[k] = v; });
    const w1Det = waf1?.stats?.byDetector || {};
    Object.entries(w1Det).forEach(([k, v]) => { if (v > 0) w1Cat[k] = v; });

    const w2Cat = {};
    const w2Rules = waf2?.stats?.by_category || waf2?.by_category || {};
    Object.entries(w2Rules).forEach(([k, v]) => { if (v > 0) w2Cat[k] = v; });

    const allCategories = [...new Set([...Object.keys(w1Cat), ...Object.keys(w2Cat)])];
    if (allCategories.length === 0) allCategories.push('暂无数据');

    const w1Data = allCategories.map(c => w1Cat[c] || 0);
    const w2Data = allCategories.map(c => w2Cat[c] || 0);

    const ctx = document.getElementById('monitor-compare-chart');
    if (!ctx) return;

    if (!monitorCompareChart) {
        monitorCompareChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: allCategories,
                datasets: [
                    {
                        label: 'WAF1',
                        data: w1Data,
                        backgroundColor: 'rgba(87,148,242,0.7)',
                        borderColor: '#5794f2',
                        borderWidth: 1,
                        borderRadius: 3,
                        barPercentage: 0.8,
                        categoryPercentage: 0.6
                    },
                    {
                        label: 'WAF2',
                        data: w2Data,
                        backgroundColor: 'rgba(184,119,217,0.7)',
                        borderColor: '#b877d9',
                        borderWidth: 1,
                        borderRadius: 3,
                        barPercentage: 0.8,
                        categoryPercentage: 0.6
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { color: '#8b949e', boxWidth: 10, font: { family: "'Inter'", size: 10 } }
                    }
                },
                scales: {
                    x: {
                        grid: { display: false },
                        ticks: { color: '#8b949e', font: { family: "'Inter'", size: 9 }, maxRotation: 45 }
                    },
                    y: {
                        grid: { color: 'rgba(240,246,252,0.04)' },
                        ticks: { color: '#8b949e', font: { family: "'Inter'", size: 10 } }
                    }
                }
            }
        });
    } else {
        monitorCompareChart.data.labels = allCategories;
        monitorCompareChart.data.datasets[0].data = w1Data;
        monitorCompareChart.data.datasets[1].data = w2Data;
        monitorCompareChart.update('none');
    }
}

// ==================== 演示 Tab 控制器 ====================

let demoScenarios = [];
let demoCurrentController = null;
let demoLastRun = null; // { scenarioId, wafEnabled }

function initDemo() {
    loadDemoScenarios();
    document.getElementById('demo-retry')?.addEventListener('click', () => {
        if (demoLastRun) runDemo(demoLastRun.scenarioId, demoLastRun.wafEnabled);
    });
}

async function loadDemoScenarios() {
    const container = document.getElementById('demo-scenarios');
    if (!container) return;
    try {
        const data = await api.demo.getScenarios();
        demoScenarios = data.scenarios || [];
        renderDemoScenarios();
    } catch (e) {
        container.innerHTML = `<div class="demo-loading">场景加载失败: ${escapeHtml(e.message)}</div>`;
    }
}

function renderDemoScenarios() {
    const container = document.getElementById('demo-scenarios');
    if (!container) return;
    if (!demoScenarios.length) {
        container.innerHTML = '<div class="demo-loading">暂无场景</div>';
        return;
    }
    container.innerHTML = demoScenarios.map((s) => {
        const ready = s.ready !== false;
        const wafLabel = s.wafLayer ? `防御层: ${escapeHtml(s.wafLayer)}` : '';
        return `
        <div class="demo-scenario-card${ready ? '' : ' demo-scenario-disabled'}">
            <div class="demo-scenario-head">
                <span class="demo-scenario-title">${escapeHtml(s.title)}</span>
                ${wafLabel ? `<span class="demo-scenario-layer">${wafLabel}</span>` : ''}
            </div>
            <div class="demo-scenario-desc">${escapeHtml(s.description || '')}</div>
            <div class="demo-scenario-actions">
                <button class="demo-btn demo-btn-wafon" data-scenario="${escapeHtml(s.id)}" data-waf="1" ${ready ? '' : 'disabled'}>
                    <span class="demo-btn-shield">🛡</span> WAF 开
                </button>
                <button class="demo-btn demo-btn-wafoff" data-scenario="${escapeHtml(s.id)}" data-waf="0" ${ready ? '' : 'disabled'}>
                    <span class="demo-btn-shield demo-btn-shield-off">⊘</span> WAF 关
                </button>
            </div>
        </div>`;
    }).join('');

    container.querySelectorAll('.demo-btn').forEach((btn) => {
        btn.addEventListener('click', () => {
            const scenarioId = btn.dataset.scenario;
            const wafEnabled = btn.dataset.waf === '1';
            runDemo(scenarioId, wafEnabled);
        });
    });
}

async function runDemo(scenarioId, wafEnabled) {
    demoLastRun = { scenarioId, wafEnabled };
    const body = document.getElementById('demo-chat-body');
    const retryBtn = document.getElementById('demo-retry');
    const label = document.getElementById('demo-chat-label');
    const statusDot = document.getElementById('demo-status-dot');

    // 取消上一次未完成的流
    if (demoCurrentController) { try { demoCurrentController.abort(); } catch (e) {} }

    const scenario = demoScenarios.find((s) => s.id === scenarioId) || {};
    label.textContent = `${scenario.title || scenarioId} · ${wafEnabled ? 'WAF 开' : 'WAF 关'}`;
    statusDot.className = 'demo-status-dot demo-status-running';
    retryBtn.disabled = true;

    body.innerHTML = '';
    let assistantEl = null;
    let assistantText = '';
    const ensureThinking = () => {
        // AI 思考中占位气泡 (三个跳动点), 首个 token 到来时替换为文字
        if (!assistantEl) {
            assistantEl = appendBubble(body, 'assistant');
            assistantEl.classList.add('demo-thinking');
            assistantEl.querySelector('.demo-bubble-text').innerHTML = '<span class="demo-thinking-dots"><i></i><i></i><i></i></span>';
            body.scrollTop = body.scrollHeight;
        }
    };
    const setAssistantText = (text) => {
        if (!assistantEl) assistantEl = appendBubble(body, 'assistant');
        assistantEl.classList.remove('demo-thinking');
        assistantEl.querySelector('.demo-bubble-text').textContent = text;
    };
    const clearThinkingIfEmpty = () => {
        // AI 未输出文字就进入下一步: 移除空的思考占位气泡
        if (assistantEl && !assistantText) { assistantEl.remove(); assistantEl = null; }
    };

    try {
        demoCurrentController = await api.demo.chat(scenarioId, wafEnabled, {
            onEvent: (data) => {
                switch (data.event) {
                    case 'user':
                        appendBubble(body, 'user').querySelector('.demo-bubble-text').textContent = data.text;
                        ensureThinking();
                        body.scrollTop = body.scrollHeight;
                        break;
                    case 'token':
                        assistantText += data.text;
                        setAssistantText(assistantText);
                        body.scrollTop = body.scrollHeight;
                        break;
                    case 'tool_call':
                        // 新一轮工具调用: 清掉空思考气泡, 重置 AI 文字气泡, 下次 token 进新气泡
                        clearThinkingIfEmpty();
                        assistantEl = null;
                        assistantText = '';
                        appendToolCard(body, data.tool, data.args, 'pending');
                        body.scrollTop = body.scrollHeight;
                        break;
                    case 'waf':
                        markLastToolWaf(body, data);
                        break;
                    case 'tool_result':
                        markLastToolResult(body, data);
                        body.scrollTop = body.scrollHeight;
                        ensureThinking();
                        break;
                    case 'error':
                        appendBubble(body, 'error').querySelector('.demo-bubble-text').textContent = data.message;
                        break;
                    case 'done':
                        clearThinkingIfEmpty();
                        if (data.note) {
                            const n = appendBubble(body, 'note');
                            n.querySelector('.demo-bubble-text').textContent = data.note;
                        }
                        break;
                }
            },
            onDone: () => {
                statusDot.className = 'demo-status-dot demo-status-idle';
                retryBtn.disabled = false;
            },
            onError: (e) => {
                appendBubble(body, 'error').querySelector('.demo-bubble-text').textContent = `连接失败: ${e.message}`;
                statusDot.className = 'demo-status-dot demo-status-error';
                retryBtn.disabled = false;
            }
        });
    } catch (e) {
        appendBubble(body, 'error').querySelector('.demo-bubble-text').textContent = `启动失败: ${e.message}`;
        statusDot.className = 'demo-status-dot demo-status-error';
        retryBtn.disabled = false;
    }
}

function appendBubble(container, role) {
    const el = document.createElement('div');
    el.className = `demo-bubble demo-bubble-${role}`;
    const labelMap = { user: '用户', assistant: 'AI', error: '错误', note: '提示', stream: '' };
    const label = labelMap[role];
    el.innerHTML = (label ? `<div class="demo-bubble-role">${label}</div>` : '') +
        `<div class="demo-bubble-text"></div>`;
    container.appendChild(el);
    return el;
}

function appendToolCard(container, tool, args, state) {
    const el = document.createElement('div');
    el.className = 'demo-tool-card demo-tool-pending';
    const argPreview = (() => {
        try { return JSON.stringify(args); } catch (e) { return String(args); }
    })();
    el.innerHTML = `
        <div class="demo-tool-head">
            <span class="demo-tool-icon">🔧</span>
            <span class="demo-tool-name">${escapeHtml(tool)}</span>
            <span class="demo-tool-state">执行中…</span>
        </div>
        <pre class="demo-tool-args">${escapeHtml(argPreview)}</pre>
        <div class="demo-tool-waf"></div>
        <div class="demo-tool-result"></div>`;
    container.appendChild(el);
    return el;
}

function markLastToolWaf(container, data) {
    const cards = container.querySelectorAll('.demo-tool-card');
    const card = cards[cards.length - 1];
    if (!card) return;
    const wafEl = card.querySelector('.demo-tool-waf');
    card.classList.remove('demo-tool-pending');
    const layer = data.layer || 'WAF1';
    const verdictHtml = data.verdict === 'blocked'
        ? `<span class="demo-verdict demo-verdict-blocked">⛔ ${escapeHtml(layer)} 拦截</span> <span class="demo-verdict-reason">${escapeHtml(data.reason || '')}</span> <span class="demo-verdict-cat">${escapeHtml(data.category || '')}</span>`
        : `<span class="demo-verdict demo-verdict-allowed">✅ ${escapeHtml(layer)} 放行</span> <span class="demo-verdict-reason">${escapeHtml(data.reason || '')}</span>`;
    // 追加: 同一工具卡可能含 WAF1 + WAF2 两个 verdict (展示 WAF1 漏 / WAF2 拦)
    wafEl.innerHTML = (wafEl.innerHTML ? wafEl.innerHTML + ' ' : '') + verdictHtml;
    if (data.verdict === 'blocked') {
        card.classList.remove('demo-tool-allowed');
        card.classList.add('demo-tool-blocked');
    } else if (!card.classList.contains('demo-tool-blocked')) {
        card.classList.add('demo-tool-allowed');
    }
}

function markLastToolResult(container, data) {
    const cards = container.querySelectorAll('.demo-tool-card');
    const card = cards[cards.length - 1];
    if (!card) return;
    const stateEl = card.querySelector('.demo-tool-state');
    const resEl = card.querySelector('.demo-tool-result');
    const blocked = data.blocked;
    stateEl.textContent = blocked ? '已拦截' : '已返回';
    const content = data.content || data.preview || '';
    if (content) resEl.innerHTML = `<pre class="demo-tool-result-pre">${escapeHtml(content)}</pre>`;
}

function truncateStr(s, n) {
    s = String(s ?? '');
    return s.length > n ? s.slice(0, n) + '…' : s;
}
