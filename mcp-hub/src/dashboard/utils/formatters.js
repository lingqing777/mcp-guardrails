/**
 * 格式化工具函数
 * 从 app.js 提取的公共格式化逻辑
 */

// ==================== 标签翻译 ====================

const LABEL_MAP = {
    // 攻击类型
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
    // 严重等级
    'critical': '严重',
    'high': '高',
    'medium': '中',
    'low': '低',
    'info': '信息',
    // 方向
    'request': '请求',
    'response': '响应',
};

/**
 * 翻译标签
 */
export function formatLabel(label) {
    if (!label) return '-';
    return LABEL_MAP[label.toLowerCase()] || label;
}

// ==================== 时间格式化 ====================

/**
 * 格式化时间戳为本地时间字符串
 */
export function formatTime(timestamp) {
    if (!timestamp) return '-';
    const date = new Date(timestamp);
    return date.toLocaleString('zh-CN', {
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
    });
}

/**
 * 格式化运行时间
 */
export function formatUptime(seconds) {
    if (!seconds || seconds < 0) return '-';
    if (seconds < 60) return `${seconds}秒`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}分钟`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}小时`;
    return `${Math.floor(seconds / 86400)}天`;
}

/**
 * 格式化相对时间（如："3分钟前"）
 */
export function formatRelativeTime(timestamp) {
    if (!timestamp) return '-';
    const now = Date.now();
    const date = new Date(timestamp).getTime();
    const diff = now - date;

    if (diff < 60000) return '刚刚';
    if (diff < 3600000) return `${Math.floor(diff / 60000)}分钟前`;
    if (diff < 86400000) return `${Math.floor(diff / 3600000)}小时前`;
    return `${Math.floor(diff / 86400000)}天前`;
}

// ==================== 数字格式化 ====================

/**
 * 格式化大数字（如：1.2K, 3.4M）
 */
export function formatNumber(num) {
    if (num === null || num === undefined) return '-';
    if (num < 1000) return num.toString();
    if (num < 1000000) return (num / 1000).toFixed(1) + 'K';
    return (num / 1000000).toFixed(1) + 'M';
}

/**
 * 格式化百分比
 */
export function formatPercent(value, total) {
    if (!total || total === 0) return '0.00%';
    return ((value / total) * 100).toFixed(2) + '%';
}

/**
 * 格式化延迟（毫秒）
 */
export function formatLatency(ms) {
    if (ms === null || ms === undefined) return '-';
    if (ms < 1) return '<1ms';
    if (ms < 1000) return `${Math.round(ms)}ms`;
    return `${(ms / 1000).toFixed(2)}s`;
}

// ==================== 颜色工具 ====================

/**
 * 根据严重等级获取颜色类名
 */
export function getSeverityClass(severity) {
    const map = {
        'critical': 'critical',
        'high': 'high',
        'medium': 'medium',
        'low': 'low',
        'info': 'info'
    };
    return map[severity?.toLowerCase()] || 'default';
}

/**
 * 根据状态获取颜色类名
 */
export function getStatusClass(status) {
    const map = {
        'connected': 'online',
        'running': 'online',
        'online': 'online',
        'disconnected': 'offline',
        'error': 'offline',
        'offline': 'offline',
        'pending': 'warning',
        'connecting': 'warning'
    };
    return map[status?.toLowerCase()] || 'default';
}

// ==================== 安全工具 ====================

/**
 * HTML 转义（防 XSS）
 */
export function escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

/**
 * 截断字符串
 */
export function truncate(str, maxLength = 100) {
    if (!str) return '';
    if (str.length <= maxLength) return str;
    return str.substring(0, maxLength) + '...';
}

// ==================== 默认导出 ====================

export default {
    formatLabel,
    formatTime,
    formatUptime,
    formatRelativeTime,
    formatNumber,
    formatPercent,
    formatLatency,
    getSeverityClass,
    getStatusClass,
    escapeHtml,
    truncate
};
