/**
 * API 服务层 - 统一 API 调用
 * 借鉴 DeepAudit 的 services 层模式
 */

// ==================== 配置 ====================

const config = {
    waf1Url: localStorage.getItem('waf1_url') || 'http://localhost:4000',
    waf2Url: localStorage.getItem('waf2_url') || 'http://localhost:8081',
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

    async callTool(toolName, args) {
        return request(`${config.waf1Url}/messages`, {
            method: 'POST',
            body: JSON.stringify({
                method: 'tools/call',
                params: {
                    name: toolName,
                    arguments: args
                }
            })
        });
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
    getConfig,
    setConfig
};
