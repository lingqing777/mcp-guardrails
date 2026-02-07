// ==================== MCP Guardrails Dashboard ====================
// 配置
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

// 初始化
document.addEventListener('DOMContentLoaded', () => {
    initTabs();
    loadConfig();
    initConfigPanel();
    refreshData();
    fetchMcpServers();
    startAutoRefresh();
});

function initTabs() {
    // 只选择主标签栏中的 .tab (排除 inspector-tab)
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

function loadConfig() {
    // 从 localStorage 加载 URL 配置
    const savedWaf1 = localStorage.getItem('waf1_url');
    const savedWaf2 = localStorage.getItem('waf2_url');
    const savedInterval = localStorage.getItem('refresh_interval');

    if (savedWaf1) WAF1_URL = savedWaf1;
    if (savedWaf2) WAF2_URL = savedWaf2;
    if (savedInterval) REFRESH_INTERVAL = parseInt(savedInterval);
}

function saveConfig() {
    localStorage.setItem('waf1_url', WAF1_URL);
    localStorage.setItem('waf2_url', WAF2_URL);
    localStorage.setItem('refresh_interval', REFRESH_INTERVAL.toString());
    startAutoRefresh();
}

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
        const response = await fetch(`${WAF1_URL}/api/waf1/dashboard`);
        if (response.ok) {
            waf1Data = await response.json();
            document.getElementById('waf1-status').classList.add('online');
            document.getElementById('waf1-status').classList.remove('offline');
        } else {
            throw new Error('WAF1 不可用');
        }
    } catch (e) {
        console.error('WAF1 获取失败:', e);
        document.getElementById('waf1-status').classList.remove('online');
        document.getElementById('waf1-status').classList.add('offline');
        waf1Data = null;
    }
}

async function fetchWaf2Data() {
    try {
        const response = await fetch(`${WAF2_URL}/waf2/dashboard`);
        if (response.ok) {
            waf2Data = await response.json();
            document.getElementById('waf2-status').classList.add('online');
            document.getElementById('waf2-status').classList.remove('offline');
        } else {
            throw new Error('WAF2 不可用');
        }
    } catch (e) {
        console.error('WAF2 获取失败:', e);
        document.getElementById('waf2-status').classList.remove('online');
        document.getElementById('waf2-status').classList.add('offline');
        waf2Data = null;
    }
}

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

    // 合并攻击类型数据 (WAF1: last24h.byCategory 或 rules, WAF2: by_category)
    const categories = {};
    const waf1Categories = waf1Data?.last24h?.byCategory || waf1Data?.rules || waf1Data?.by_category || {};
    Object.entries(waf1Categories).forEach(([k, v]) => {
        categories[k] = (categories[k] || 0) + v;
    });
    if (waf2Data?.by_category) {
        Object.entries(waf2Data.by_category).forEach(([k, v]) => {
            categories[k] = (categories[k] || 0) + v;
        });
    }
    renderBarChart('category-chart', categories, 'default');

    // 合并严重等级数据 (WAF1: last24h.bySeverity, WAF2: by_severity)
    const severities = {};
    const waf1Severities = waf1Data?.last24h?.bySeverity || waf1Data?.by_severity || {};
    Object.entries(waf1Severities).forEach(([k, v]) => {
        severities[k] = (severities[k] || 0) + v;
    });
    if (waf2Data?.by_severity) {
        Object.entries(waf2Data.by_severity).forEach(([k, v]) => {
            severities[k] = (severities[k] || 0) + v;
        });
    }
    renderBarChart('severity-chart', severities, 'severity');
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
    const all = [];

    // WAF1 使用 recentDetections (驼峰), WAF2 使用 recent_detections (下划线)
    const waf1Detections = waf1Data?.recentDetections || waf1Data?.recent_detections || [];
    const waf2Detections = waf2Data?.recent_detections || [];

    waf1Detections.forEach(d => {
        all.push({ ...d, source: 'waf1' });
    });
    waf2Detections.forEach(d => {
        all.push({ ...d, source: 'waf2' });
    });

    // 按时间排序 (WAF1 用 ts 毫秒时间戳, WAF2 用 timestamp ISO字符串)
    all.sort((a, b) => {
        const timeA = a.ts || new Date(a.timestamp || a.labels?.timestamp).getTime();
        const timeB = b.ts || new Date(b.timestamp || b.labels?.timestamp).getTime();
        return timeB - timeA;
    });
    allDetections = all;

    renderDetectionList('all-detections', all.slice(0, 50), 'all');
}

function renderBarChart(containerId, data, type) {
    const container = document.getElementById(containerId);

    if (!data || Object.keys(data).length === 0) {
        container.innerHTML = '<div class="empty-state">暂无数据</div>';
        return;
    }

    const entries = Object.entries(data).sort((a, b) => b[1] - a[1]);
    const maxValue = Math.max(...entries.map(e => e[1]));

    const html = entries.map(([label, value]) => {
        const percentage = maxValue > 0 ? (value / maxValue) * 100 : 0;
        let colorClass = 'default';

        if (type === 'severity') {
            colorClass = label.toLowerCase();
        }

        return `
            <div class="bar-item">
                <div class="bar-label">${formatLabel(label)}</div>
                <div class="bar-container">
                    <div class="bar-fill ${colorClass}" style="width: ${percentage}%">${value}</div>
                </div>
            </div>
        `;
    }).join('');

    container.innerHTML = html;
}

function renderDetectionList(containerId, detections, source) {
    const container = document.getElementById(containerId);

    if (!detections || detections.length === 0) {
        container.innerHTML = '<div class="empty-state">暂无检测记录</div>';
        return;
    }

    const html = detections.map(d => {
        // 兼容 WAF1 和 WAF2 的不同数据格式
        const labels = d.labels || {};
        const severity = d.severity || labels.severity || 'medium';
        const category = d.category || d.detected_by || 'unknown';
        const reason = d.reason || d.message || '检测到威胁';
        // WAF1 用 ts (毫秒时间戳) 或 labels.timestamp, WAF2 用 timestamp
        const timestamp = d.timestamp || labels.timestamp || (d.ts ? new Date(d.ts).toISOString() : null);
        const owasp = d.owasp || labels.owasp || '-';
        const mitre = d.mitre || labels.mitreTactic || '-';
        const direction = d.direction || labels.direction || '-';
        const itemSource = d.source || labels.source || source;
        const tool = d.tool || '-';

        return `
            <div class="detection-item ${severity}">
                <div class="detection-header">
                    <span class="detection-category">
                        ${formatLabel(category)}
                        <span class="waf-badge ${itemSource}">${itemSource.toUpperCase()}</span>
                        <span class="severity-badge ${severity}">${severity.toUpperCase()}</span>
                    </span>
                    <span class="detection-time">${timestamp ? formatTime(timestamp) : '-'}</span>
                </div>
                <div class="detection-details">${reason}</div>
                <div class="detection-tags">
                    ${tool !== '-' ? `<span class="tag direction">Tool: ${tool}</span>` : ''}
                    ${owasp !== '-' ? `<span class="tag owasp">OWASP: ${owasp}</span>` : ''}
                    ${mitre !== '-' ? `<span class="tag mitre">MITRE: ${mitre}</span>` : ''}
                    ${direction !== '-' ? `<span class="tag direction">${direction}</span>` : ''}
                </div>
            </div>
        `;
    }).join('');

    container.innerHTML = html;
}

function formatLabel(label) {
    const labels = {
        'sql_injection': 'SQL 注入',
        'xss': 'XSS 跨站脚本',
        'command_injection': '命令注入',
        'path_traversal': '路径遍历',
        'ssrf': 'SSRF',
        'xxe': 'XXE',
        'prompt_injection': '提示词注入',
        'sensitive_data_exposure': '敏感数据泄露',
        'authentication_bypass': '认证绕过',
        'insecure_deserialization': '不安全反序列化',
        'data_exfiltration': '数据窃取',
        'secrets': '密钥泄露',
        'pii': '个人信息',
        'unicode': 'Unicode 异常',
        'rate_limit': '限流',
        'rbac': '访问控制',
        'critical': '严重',
        'high': '高',
        'medium': '中',
        'low': '低',
        'info': '信息',
        'request': '请求',
        'response': '响应',
    };
    return labels[label?.toLowerCase()] || label;
}

function formatTime(timestamp) {
    const date = new Date(timestamp);
    return date.toLocaleString('zh-CN', {
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
    });
}

// ==================== 配置面板功能 (cc-switch 风格) ====================

// 当前防护模式
let currentMode = 'full';

// 防护模式选择 (调用后端 API)
async function selectMode(mode) {
    currentMode = mode;

    // 更新卡片选中状态
    document.querySelectorAll('.mode-card').forEach(card => {
        card.classList.toggle('selected', card.dataset.mode === mode);
    });

    // 切换配置区块显示
    document.getElementById('config-full').style.display = mode === 'full' ? 'block' : 'none';
    document.getElementById('config-lite').style.display = mode === 'lite' ? 'block' : 'none';

    // 切换配置指引显示
    document.getElementById('guide-full').style.display = mode === 'full' ? 'block' : 'none';
    document.getElementById('guide-lite').style.display = mode === 'lite' ? 'block' : 'none';

    // 切换 WAF1 规则区块状态
    const waf1Column = document.getElementById('waf1-rules-column');
    if (waf1Column) {
        waf1Column.classList.toggle('disabled', mode === 'lite');
    }

    // 调用后端 API 切换模式
    try {
        const resp = await fetch(`${WAF1_URL}/api/config/mode`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ mode })
        });
        const data = await resp.json();
        if (data.success) {
            showConfigStatus('config-status', 'success', data.message);
        } else {
            showConfigStatus('config-status', 'error', data.error || '切换失败');
        }
    } catch (e) {
        // 后端不可用时仅保存到本地
        localStorage.setItem('protection_mode', mode);
        showConfigStatus('config-status', 'info', `已切换到${mode === 'full' ? '完整防护' : '轻量防护'}模式 (本地)`);
    }
}

// 复制到剪贴板
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

// 复制代码块
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

// 切换密码可见性
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

// 紧凑开关切换 (调用后端 API)
async function toggleRuleSm(el) {
    el.classList.toggle('active');
    const isActive = el.classList.contains('active');
    const rule = el.dataset.rule;

    // 判断是 WAF1 还是 WAF2 规则
    const isWaf1Rule = ['sql', 'cmd', 'xss', 'path', 'sensitive'].includes(rule);
    const isWaf2Rule = ['req', 'res', 'cache'].includes(rule);

    if (isWaf1Rule) {
        // WAF1 规则映射
        const ruleMap = {
            'sql': 'sqlInjection',
            'cmd': 'commandInjection',
            'xss': 'xss',
            'path': 'pathTraversal',
            'sensitive': 'sensitiveFiles'
        };
        const ruleName = ruleMap[rule];

        try {
            const resp = await fetch(`${WAF1_URL}/api/config/waf1`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    rules: { [ruleName]: isActive }
                })
            });
            if (resp.ok) {
                console.log(`[WAF1] 规则 ${ruleName} 已${isActive ? '启用' : '禁用'}`);
            }
        } catch (e) {
            console.error('[WAF1] 规则更新失败:', e);
            // 回滚 UI
            el.classList.toggle('active');
        }
    } else if (isWaf2Rule) {
        // WAF2 规则映射
        const featureMap = {
            'req': 'requestAnalysis',
            'res': 'responseAnalysis',
            'cache': 'cache'
        };
        const featureName = featureMap[rule];

        try {
            const resp = await fetch(`${WAF1_URL}/api/config/waf2`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    features: { [featureName]: isActive }
                })
            });
            const data = await resp.json();
            if (data.success) {
                if (data.synced) {
                    console.log(`[WAF2] 功能 ${featureName} 已${isActive ? '启用' : '禁用'}`);
                } else {
                    console.warn(`[WAF2] 配置已保存但同步失败: ${data.syncError}`);
                }
            }
        } catch (e) {
            console.error('[WAF2] 规则更新失败:', e);
            // 回滚 UI
            el.classList.toggle('active');
        }
    }
}

// 应用配置 (调用后端 API，同步到 WAF2)
async function applyConfig() {
    let targetUrl, apiKey;

    if (currentMode === 'full') {
        targetUrl = document.getElementById('cfg-target-url').value;
        apiKey = document.getElementById('cfg-apikey').value;
    } else {
        targetUrl = document.getElementById('cfg-target-url-lite').value;
        apiKey = document.getElementById('cfg-apikey-lite').value;
    }

    // 验证 URL 格式
    if (targetUrl && !targetUrl.match(/^https?:\/\/.+/)) {
        showConfigStatus('config-status', 'error', '目标 URL 格式无效，请输入完整 URL (如 http://example.com)');
        return;
    }

    showConfigStatus('config-status', 'info', '正在保存配置...');

    // 调用后端 API 保存配置并同步到 WAF2
    try {
        const resp = await fetch(`${WAF1_URL}/api/config/waf2`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                upstream: targetUrl || undefined,
                llm: apiKey ? { apiKey } : undefined
            })
        });
        const data = await resp.json();
        if (data.success) {
            // 检查 WAF2 同步状态
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
        // 后端不可用时保存到本地
        localStorage.setItem('target_url', targetUrl);
        if (apiKey) localStorage.setItem('llm_apikey', apiKey);
        showConfigStatus('config-status', 'warning', '配置已保存到本地 (MCP Hub 不可用)');
    }
}

// 显示配置状态 (通用)
function showConfigStatus(containerId, type, message) {
    const container = document.getElementById(containerId);
    if (!container) return;

    container.innerHTML = `
        <div class="status-message ${type}">
            <span>${type === 'success' ? '✓' : type === 'error' ? '✗' : type === 'warning' ? '⚠' : 'ℹ'}</span>
            <span>${message}</span>
        </div>
    `;

    // 自动清除
    setTimeout(() => {
        container.innerHTML = '';
    }, 5000);
}

// 初始化配置面板 (从后端加载配置)
async function initConfigPanel() {
    try {
        // 从后端获取配置
        const resp = await fetch(`${WAF1_URL}/api/config`);
        if (resp.ok) {
            const config = await resp.json();

            // 应用模式 (不触发 API 调用，只更新 UI)
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

            // 填充配置值
            if (config.waf2?.upstream) {
                const targetFull = document.getElementById('cfg-target-url');
                const targetLite = document.getElementById('cfg-target-url-lite');
                if (targetFull) targetFull.value = config.waf2.upstream;
                if (targetLite) targetLite.value = config.waf2.upstream;
            }

            // 加载 WAF1 规则开关状态
            if (config.waf1?.rules) {
                const waf1RuleMap = {
                    'sqlInjection': 'sql',
                    'commandInjection': 'cmd',
                    'xss': 'xss',
                    'pathTraversal': 'path',
                    'sensitiveFiles': 'sensitive'
                };
                for (const [ruleName, dataRule] of Object.entries(waf1RuleMap)) {
                    const toggle = document.querySelector(`[data-rule="${dataRule}"]`);
                    if (toggle && config.waf1.rules[ruleName] !== undefined) {
                        toggle.classList.toggle('active', config.waf1.rules[ruleName]);
                    }
                }
            }

            // 加载 WAF2 功能开关状态
            if (config.waf2?.features) {
                const waf2FeatureMap = {
                    'requestAnalysis': 'req',
                    'responseAnalysis': 'res',
                    'cache': 'cache'
                };
                for (const [featureName, dataRule] of Object.entries(waf2FeatureMap)) {
                    const toggle = document.querySelector(`[data-rule="${dataRule}"]`);
                    if (toggle && config.waf2.features[featureName] !== undefined) {
                        toggle.classList.toggle('active', config.waf2.features[featureName]);
                    }
                }
            }

            console.log('[Config] 已从服务器加载配置:', config.mode);
            return;
        }
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

// 手风琴切换
function toggleAccordion(id) {
    // 处理配置指引特殊情况
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

// 规则开关切换
function toggleRule(el) {
    el.classList.toggle('active');
    updateRuleStatus();
    showConfigStatus('waf1-config-status', 'info', '规则配置已更新 (前端演示)');
}

// 更新规则状态计数
function updateRuleStatus() {
    const activeRules = document.querySelectorAll('[data-rule].toggle-switch.active, [data-detector].toggle-switch.active').length;
    const statusEl = document.getElementById('waf1-rules-status');
    if (statusEl) {
        statusEl.textContent = `${activeRules} 规则启用`;
        statusEl.className = `accordion-status ${activeRules > 0 ? 'active' : 'inactive'}`;
    }
}

// LLM 模型选择
function selectModel(el) {
    document.querySelectorAll('.model-option').forEach(opt => opt.classList.remove('selected'));
    el.classList.add('selected');
    showConfigStatus('waf2-config-status', 'info', `已选择模型: ${el.dataset.model}`);
}

// 自动刷新切换
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

// 测试 WAF1 连接
async function testWaf1Connection() {
    showConfigStatus('waf1-config-status', 'info', '正在测试 WAF1 连接...');

    try {
        const response = await fetch(`${WAF1_URL}/api/waf1/stats`);
        if (response.ok) {
            const data = await response.json();
            showConfigStatus('waf1-config-status', 'success',
                `WAF1 连接成功! 总请求: ${data.total || 0}, 拦截: ${data.blocked || 0}`);
        } else {
            throw new Error(`HTTP ${response.status}`);
        }
    } catch (e) {
        showConfigStatus('waf1-config-status', 'error', `WAF1 连接失败: ${e.message}`);
    }
}

// 测试 WAF2 连接
async function testWaf2Connection() {
    showConfigStatus('waf2-config-status', 'info', '正在测试 WAF2 连接...');

    try {
        const response = await fetch(`${WAF2_URL}/waf2/stats`);
        if (response.ok) {
            const data = await response.json();
            showConfigStatus('waf2-config-status', 'success',
                `WAF2 连接成功! LLM调用: ${data.llm_calls || 0}, 缓存命中: ${data.cache_hit_rate || '0%'}`);
        } else {
            throw new Error(`HTTP ${response.status}`);
        }
    } catch (e) {
        showConfigStatus('waf2-config-status', 'error', `WAF2 连接失败: ${e.message}`);
    }
}

// 测试所有连接
async function testAllConnections() {
    showConfigStatus('api-config-status', 'info', '正在测试所有连接...');

    const results = [];

    try {
        const waf1Resp = await fetch(`${WAF1_URL}/api/health`);
        results.push(waf1Resp.ok ? '✅ WAF1' : '❌ WAF1');
    } catch { results.push('❌ WAF1'); }

    try {
        const waf2Resp = await fetch(`${WAF2_URL}/waf2/health`);
        results.push(waf2Resp.ok ? '✅ WAF2' : '❌ WAF2');
    } catch { results.push('❌ WAF2'); }

    showConfigStatus('api-config-status',
        results.every(r => r.startsWith('✅')) ? 'success' : 'warning',
        `连接测试: ${results.join(', ')}`);
}

// 重置 WAF1 统计
async function resetWaf1Stats() {
    if (!confirm('确定要重置 WAF1 统计数据吗？')) return;

    try {
        await fetch(`${WAF1_URL}/api/waf1/reset`, { method: 'POST' });
        showConfigStatus('waf1-config-status', 'success', 'WAF1 统计已重置');
        refreshData();
    } catch (e) {
        showConfigStatus('waf1-config-status', 'error', `重置失败: ${e.message}`);
    }
}

// 重置 WAF2 统计
async function resetWaf2Stats() {
    if (!confirm('确定要重置 WAF2 统计数据吗？')) return;

    try {
        await fetch(`${WAF2_URL}/waf2/reset`, { method: 'POST' });
        showConfigStatus('waf2-config-status', 'success', 'WAF2 统计已重置');
        refreshData();
    } catch (e) {
        showConfigStatus('waf2-config-status', 'error', `重置失败: ${e.message}`);
    }
}

// 清空 WAF2 缓存 (API 暂未实现)
function clearWaf2Cache() {
    showConfigStatus('waf2-config-status', 'warning', '缓存清理功能需要后端 API 支持');
}

// 保存 API 配置
function saveApiConfig() {
    saveConfig();
    showConfigStatus('api-config-status', 'success', '配置已保存到本地存储');
}

// 导出日志
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

// ==================== MCP Server 管理 (Inspector 风格) ====================

let currentTestTool = null;

async function fetchMcpServers() {
    try {
        const response = await fetch(`${WAF1_URL}/api/servers`);
        if (response.ok) {
            const data = await response.json();
            mcpServers = data.servers || [];
            renderServersList();
            if (selectedServer) {
                selectedServer = mcpServers.find(s => s.name === selectedServer.name);
                renderServerDetail();
            }
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
        container.innerHTML = '<div class="empty-state">暂无 MCP Server</div>';
        return;
    }

    const html = mcpServers.map(server => {
        const tools = server.capabilities?.tools || [];
        const resources = server.capabilities?.resources || [];
        const isSelected = selectedServer?.name === server.name;

        return `
            <div class="server-list-item ${isSelected ? 'selected' : ''}"
                 onclick="selectServer('${server.name}')">
                <div class="name">
                    ${server.displayName || server.name}
                    <span class="server-status ${server.status}">${server.status}</span>
                </div>
                <div class="meta">${tools.length} tools, ${resources.length} resources</div>
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
            return `<span class="param-badge ${isReq ? 'required' : ''}">${name}${isReq ? '*' : ''}</span>`;
        }).join('');

        return `
            <div class="tool-card">
                <div class="tool-header">
                    <span class="tool-name">${tool.name}</span>
                    <button class="test-btn" onclick="openToolTest(${idx})">测试</button>
                </div>
                <div class="tool-desc">${(tool.description || '无描述').substring(0, 150)}${tool.description?.length > 150 ? '...' : ''}</div>
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
            <div class="resource-name">${res.name}</div>
            <div class="resource-uri">${res.uri}</div>
            ${res.mimeType ? `<div class="resource-mime">类型: ${res.mimeType}</div>` : ''}
            ${res.description ? `<div class="resource-mime">${res.description}</div>` : ''}
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
            <div class="prompt-name">${p.name}</div>
            ${p.description ? `<div class="prompt-desc">${p.description}</div>` : ''}
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

    // 生成参数表单
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
            inputHtml = `<select id="param-${name}">
                ${prop.enum.map(v => `<option value="${v}">${v}</option>`).join('')}
            </select>`;
        } else if (type === 'object') {
            inputHtml = `<textarea id="param-${name}" rows="2" placeholder='{"key": "value"}'></textarea>`;
        } else {
            inputHtml = `<input type="text" id="param-${name}" placeholder="${prop.description || name}">`;
        }

        return `
            <div class="form-group">
                <label>${name} ${isReq ? '<span class="required">*</span>' : ''}</label>
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

    // 收集参数
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
        // 调用 MCP Hub 的 tool 执行接口
        const response = await fetch(`${WAF1_URL}/messages`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                method: 'tools/call',
                params: {
                    name: currentTestTool.name,
                    arguments: args
                }
            })
        });

        const result = await response.json();
        outputEl.textContent = JSON.stringify(result, null, 2);

        if (result.error || result.isError) {
            outputEl.classList.add('error');
        }
    } catch (e) {
        outputEl.textContent = `请求失败: ${e.message}`;
        outputEl.classList.add('error');
    }
}

function formatUptime(seconds) {
    if (seconds < 60) return `${seconds}秒`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}分钟`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}小时`;
    return `${Math.floor(seconds / 86400)}天`;
}

// ==================== 统计重置 ====================

async function resetAllStats() {
    if (!confirm('确定要重置所有统计数据吗？')) return;

    try {
        await Promise.all([
            fetch(`${WAF1_URL}/api/waf1/reset`, { method: 'POST' }),
            fetch(`${WAF2_URL}/waf2/reset`, { method: 'POST' })
        ]);
        await refreshData();
        alert('统计数据已重置');
    } catch (e) {
        alert('重置失败: ' + e.message);
    }
}
