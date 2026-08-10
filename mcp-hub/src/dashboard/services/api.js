/**
 * API 服务层 - 统一 API 调用
 * 借鉴 DeepAudit 的 services 层模式
 */

// ==================== 配置 ====================

const _isLocalDev = location.hostname === 'localhost' || location.hostname === '127.0.0.1';

const config = {
    waf1Url: localStorage.getItem('waf1_url') || (_isLocalDev ? 'http://localhost:4000' : ''),
    waf2Url: localStorage.getItem('waf2_url') || (_isLocalDev ? 'http://localhost:8081' : ''),
    refreshInterval: parseInt(localStorage.getItem('refresh_interval')) || 5000
};

// ==================== 基础请求 ====================

async function request(url, options = {}) {
    const defaultOptions = {
        headers: {
            'Content-Type': 'application/json',
        },
        credentials: 'include', // 携带 Cookie
    };

    const response = await fetch(url, { ...defaultOptions, ...options });

    if (!response.ok) {
        const error = new Error(`HTTP ${response.status}`);
        error.status = response.status;
        try {
            error.data = await response.json();
        } catch (e) {
            error.data = null;
        }
        throw error;
    }

    return response.json();
}

// ==================== 认证 API ====================

export const authApi = {
    async checkStatus() {
        return request('/auth/status');
    },

    async login(username, password) {
        return request('/auth/login', {
            method: 'POST',
            body: JSON.stringify({ username, password })
        });
    },

    async logout() {
        return request('/auth/logout', { method: 'POST' });
    }
};

// ==================== WAF1 API ====================

export const waf1Api = {
    async getDashboard() {
        return request(`${config.waf1Url}/api/waf1/dashboard`);
    },

    async getStats() {
        return request(`${config.waf1Url}/api/waf1/stats`);
    },

    async reset() {
        return request(`${config.waf1Url}/api/waf1/reset`, { method: 'POST' });
    },

    async updateRules(rules) {
        return request(`${config.waf1Url}/api/config/waf1`, {
            method: 'POST',
            body: JSON.stringify({ rules })
        });
    },

    async checkHealth() {
        return request(`${config.waf1Url}/api/health`);
    }
};

// ==================== WAF2 API ====================

export const waf2Api = {
    async getDashboard() {
        return request(`${config.waf2Url}/waf2/dashboard`);
    },

    async getStats() {
        return request(`${config.waf2Url}/waf2/stats`);
    },

    async reset() {
        return request(`${config.waf2Url}/waf2/reset`, { method: 'POST' });
    },

    async updateFeatures(features) {
        return request(`${config.waf1Url}/api/config/waf2`, {
            method: 'POST',
            body: JSON.stringify({ features })
        });
    },

    async updateConfig({ upstream, llm }) {
        return request(`${config.waf1Url}/api/config/waf2`, {
            method: 'POST',
            body: JSON.stringify({ upstream, llm })
        });
    },

    async checkHealth() {
        return request(`${config.waf2Url}/waf2/health`);
    }
};

// ==================== 配置 API ====================

export const configApi = {
    async get() {
        return request(`${config.waf1Url}/api/config`);
    },

    async setMode(mode) {
        return request(`${config.waf1Url}/api/config/mode`, {
            method: 'POST',
            body: JSON.stringify({ mode })
        });
    }
};

// ==================== MCP Servers API ====================

export const serversApi = {
    async list() {
        return request(`${config.waf1Url}/api/servers`);
    },

    async callTool(serverName, toolName, args) {
        return request(`${config.waf1Url}/api/tools/call`, {
            method: 'POST',
            body: JSON.stringify({
                server_name: serverName,
                tool: toolName,
                arguments: args
            })
        });
    }
};

// ==================== 演示 API ====================

export const demoApi = {
    async getScenarios() {
        return request(`${config.waf1Url}/api/demo/scenarios`);
    },

    /**
     * SSE 流式演示聊天。返回一个可取消的控制器。
     * onEvent(eventData) 每收到一个 SSE data 事件回调一次。
     * 用 fetch + ReadableStream 解析 SSE (EventSource 不支持 POST)。
     */
    async chat(scenarioId, wafEnabled, { onEvent, onDone, onError } = {}) {
        const controller = new AbortController();
        const resp = await fetch(`${config.waf1Url}/api/demo/chat`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({ scenarioId, wafEnabled }),
            signal: controller.signal,
        });

        if (!resp.ok) {
            const err = new Error(`HTTP ${resp.status}`);
            err.status = resp.status;
            try { err.data = await resp.json(); } catch (e) { err.data = null; }
            if (onError) onError(err);
            return controller;
        }

        const reader = resp.body.getReader();
        const decoder = new TextDecoder();
        let buffer = '';
        try {
            while (true) {
                const { done, value } = await reader.read();
                if (done) break;
                buffer += decoder.decode(value, { stream: true });
                let idx;
                while ((idx = buffer.indexOf('\n\n')) >= 0) {
                    const block = buffer.slice(0, idx);
                    buffer = buffer.slice(idx + 2);
                    for (const line of block.split('\n')) {
                        if (!line.startsWith('data:')) continue;
                        const payload = line.slice(5).trim();
                        if (!payload) continue;
                        let data;
                        try { data = JSON.parse(payload); } catch (e) { continue; }
                        if (onEvent) onEvent(data);
                        if (data.event === 'done' && onDone) onDone(data);
                    }
                }
            }
        } catch (e) {
            if (e.name !== 'AbortError' && onError) onError(e);
        }
        return controller;
    }
};

// ==================== MCP Server 配置管理 API ====================

export const mcpConfigApi = {
    // 获取所有 MCP Server 配置
    async listServers() {
        return request(`${config.waf1Url}/api/mcp-config/servers`);
    },

    // 获取单个 MCP Server 配置
    async getServer(name) {
        return request(`${config.waf1Url}/api/mcp-config/servers/${encodeURIComponent(name)}`);
    },

    // 添加新的 MCP Server
    async addServer(name, serverConfig) {
        return request(`${config.waf1Url}/api/mcp-config/servers`, {
            method: 'POST',
            body: JSON.stringify({ name, ...serverConfig })
        });
    },

    // 更新 MCP Server 配置
    async updateServer(name, serverConfig) {
        return request(`${config.waf1Url}/api/mcp-config/servers/${encodeURIComponent(name)}`, {
            method: 'PUT',
            body: JSON.stringify(serverConfig)
        });
    },

    // 删除 MCP Server
    async deleteServer(name) {
        return request(`${config.waf1Url}/api/mcp-config/servers/${encodeURIComponent(name)}`, {
            method: 'DELETE'
        });
    },

    // 导入配置
    async importServers(servers, merge = true) {
        return request(`${config.waf1Url}/api/mcp-config/import`, {
            method: 'POST',
            body: JSON.stringify({ servers, merge })
        });
    },

    // 导出配置
    async exportServers() {
        return request(`${config.waf1Url}/api/mcp-config/export`);
    }
};

// ==================== 配置管理 ====================

export function getConfig() {
    return { ...config };
}

export function setConfig(newConfig) {
    if (newConfig.waf1Url) {
        config.waf1Url = newConfig.waf1Url;
        localStorage.setItem('waf1_url', newConfig.waf1Url);
    }
    if (newConfig.waf2Url) {
        config.waf2Url = newConfig.waf2Url;
        localStorage.setItem('waf2_url', newConfig.waf2Url);
    }
    if (newConfig.refreshInterval) {
        config.refreshInterval = newConfig.refreshInterval;
        localStorage.setItem('refresh_interval', newConfig.refreshInterval.toString());
    }
}

// ==================== 默认导出 ====================

export default {
    auth: authApi,
    waf1: waf1Api,
    waf2: waf2Api,
    config: configApi,
    servers: serversApi,
    mcpConfig: mcpConfigApi,
    demo: demoApi,
    getConfig,
    setConfig
};
