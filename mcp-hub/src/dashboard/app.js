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

// ==================== 初始化 ====================

document.addEventListener('DOMContentLoaded', () => {
    checkAuthStatus();
    initTabs();
    loadConfig();
    initConfigPanel();
    refreshData();
    fetchMcpServers();
    startAutoRefresh();
});

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
    document.querySelectorAll('.tabs > .tab').forEach(tab => {
        tab.addEventListener('click', () => {
            document.querySelectorAll('.tabs > .tab').forEach(t => t.classList.remove('active'));
            tab.classList.add('active');

            document.querySelectorAll('.tab-content').forEach(p => p.style.display = 'none');
            const panelId = `${tab.dataset.tab}-panel`;
            const panel = document.getElementById(panelId);
            if (panel) {
                panel.style.display = 'block';
            } else {
                console.error('找不到面板:', panelId);
            }
        });
    });
}

// ==================== 配置管理 ====================

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

    // 使用组件渲染图表
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
    if (!waf2Data) {
        document.getElementById('waf2-total').textContent = '-';
        document.getElementById('waf2-blocked-req').textContent = '-';
        document.getElementById('waf2-blocked-resp').textContent = '-';
        document.getElementById('waf2-llm-calls').textContent = '-';
        return;
    }

    document.getElementById('waf2-total').textContent = waf2Data.summary?.total || 0;
    document.getElementById('waf2-blocked-req').textContent = waf2Data.by_direction?.request || 0;
    document.getElementById('waf2-blocked-resp').textContent = waf2Data.by_direction?.response || 0;
    document.getElementById('waf2-llm-calls').textContent = waf2Data.cache?.llm_calls || 0;

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

    document.getElementById('config-full').style.display = mode === 'full' ? 'block' : 'none';
    document.getElementById('config-lite').style.display = mode === 'lite' ? 'block' : 'none';
    document.getElementById('guide-full').style.display = mode === 'full' ? 'block' : 'none';
    document.getElementById('guide-lite').style.display = mode === 'lite' ? 'block' : 'none';

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
    let targetUrl, apiKey;

    if (currentMode === 'full') {
        targetUrl = document.getElementById('cfg-target-url').value;
        apiKey = document.getElementById('cfg-apikey').value;
    } else {
        targetUrl = document.getElementById('cfg-target-url-lite').value;
        apiKey = document.getElementById('cfg-apikey-lite').value;
    }

    if (targetUrl && !targetUrl.match(/^https?:\/\/.+/)) {
        showConfigStatus('config-status', 'error', '目标 URL 格式无效，请输入完整 URL (如 http://example.com)');
        return;
    }

    showConfigStatus('config-status', 'info', '正在保存配置...');

    try {
        const data = await api.waf2.updateConfig({
            upstream: targetUrl || undefined,
            llm: apiKey ? { apiKey } : undefined
        });
        if (data.success) {
            if (data.synced) {
                showConfigStatus('config-status', 'success', '配置已保存，WAF2 已同步生效');
            } else {
                const errorMsg = data.syncError ? `: ${data.syncError}` : '';
                showConfigStatus('config-status', 'warning', `配置已保存，但 WAF2 同步失败${errorMsg}`);
            }
        } else {
            showConfigStatus('config-status', 'error', data.error || '保存失败');
        }
    } catch (e) {
        localStorage.setItem('target_url', targetUrl);
        if (apiKey) localStorage.setItem('llm_apikey', apiKey);
        showConfigStatus('config-status', 'warning', '配置已保存到本地 (MCP Hub 不可用)');
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
}

function toggleAccordion(id) {
    if (id === 'config-guide') {
        const content = document.getElementById('config-guide-content');
        const chevron = document.getElementById('config-guide-chevron');
        if (content && chevron) {
            const isExpanded = content.style.maxHeight && content.style.maxHeight !== '0px';
            content.style.maxHeight = isExpanded ? '0px' : '500px';
            chevron.style.transform = isExpanded ? 'rotate(0deg)' : 'rotate(180deg)';
        }
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
            document.querySelectorAll('.inspector-tab').forEach(t => t.classList.remove('active'));
            tab.classList.add('active');

            document.querySelectorAll('.inspector-tab-content').forEach(c => c.style.display = 'none');
            document.getElementById(`stab-${tab.dataset.stab}`).style.display = 'block';
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
        const result = await api.servers.callTool(currentTestTool.name, args);
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
window.toggleRule = toggleRule;
window.selectModel = selectModel;
window.toggleAutoRefresh = toggleAutoRefresh;
window.testWaf1Connection = testWaf1Connection;
window.testWaf2Connection = testWaf2Connection;
window.testAllConnections = testAllConnections;
window.resetWaf1Stats = resetWaf1Stats;
window.resetWaf2Stats = resetWaf2Stats;
window.clearWaf2Cache = clearWaf2Cache;
window.saveApiConfig = saveApiConfig;
window.exportLogs = exportLogs;
window.refreshData = refreshData;
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
    document.getElementById('server-modal').style.display = 'flex';
}

function closeServerModal() {
    document.getElementById('server-modal').style.display = 'none';
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
            serverConfig.args = argsStr.split(',').map(s => s.trim()).filter(s => s);
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
        if (editingServerName) {
            // 更新
            await api.mcpConfig.updateServer(editingServerName, serverConfig);
            alert(`Server '${editingServerName}' 已更新，配置将在几秒后生效`);
        } else {
            // 添加
            await api.mcpConfig.addServer(name, serverConfig);
            alert(`Server '${name}' 已添加，配置将在几秒后生效`);
        }

        closeServerModal();
        // 等待配置重新加载后刷新
        setTimeout(() => fetchMcpServers(), 1000);
    } catch (e) {
        const errMsg = e.data?.error || e.message;
        alert('保存失败: ' + errMsg);
    }
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
        document.getElementById('server-args').value = (serverConfig.args || []).join(', ');
        document.getElementById('server-env').value = serverConfig.env ? JSON.stringify(serverConfig.env, null, 2) : '';
    } else if (serverConfig.url) {
        selectServerType('sse');
        document.getElementById('server-url').value = serverConfig.url || '';
        document.getElementById('server-headers').value = serverConfig.headers ? JSON.stringify(serverConfig.headers, null, 2) : '';
    }

    document.getElementById('server-modal').style.display = 'flex';
}

async function deleteCurrentServer() {
    if (!selectedServer) return;

    if (!confirm(`确定要删除 Server '${selectedServer.name}' 吗？`)) {
        return;
    }

    try {
        await api.mcpConfig.deleteServer(selectedServer.name);
        alert(`Server '${selectedServer.name}' 已删除`);
        selectedServer = null;
        setTimeout(() => fetchMcpServers(), 1000);
    } catch (e) {
        const errMsg = e.data?.error || e.message;
        alert('删除失败: ' + errMsg);
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
