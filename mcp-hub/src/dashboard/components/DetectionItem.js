/**
 * 检测记录条目组件
 */

import { formatLabel, formatTime, escapeHtml } from '../utils/formatters.js';

/**
 * 渲染单个检测记录
 * @param {Object} detection - 检测记录数据
 * @param {string} source - 来源标识 ('waf1' | 'waf2' | 'all')
 */
export function renderDetectionItem(detection, source = 'all') {
    const labels = detection.labels || {};
    const severity = detection.severity || labels.severity || 'medium';
    const category = detection.category || detection.detected_by || 'unknown';
    const reason = detection.reason || detection.message || '检测到威胁';
    const timestamp = detection.timestamp || labels.timestamp ||
                      (detection.ts ? new Date(detection.ts).toISOString() : null);
    const owasp = detection.owasp || labels.owasp || '-';
    const mitre = detection.mitre || labels.mitreTactic || '-';
    const direction = detection.direction || labels.direction || '-';
    const itemSource = detection.source || labels.source || source;
    const tool = detection.tool || '-';

    return `
        <div class="detection-item ${severity}">
            <div class="detection-header">
                <span class="detection-category">
                    ${escapeHtml(formatLabel(category))}
                    <span class="waf-badge ${itemSource}">${itemSource.toUpperCase()}</span>
                    <span class="severity-badge ${severity}">${severity.toUpperCase()}</span>
                </span>
                <span class="detection-time">${timestamp ? formatTime(timestamp) : '-'}</span>
            </div>
            <div class="detection-details">${escapeHtml(reason)}</div>
            <div class="detection-tags">
                ${tool !== '-' ? `<span class="tag direction">Tool: ${escapeHtml(tool)}</span>` : ''}
                ${owasp !== '-' ? `<span class="tag owasp">OWASP: ${escapeHtml(owasp)}</span>` : ''}
                ${mitre !== '-' ? `<span class="tag mitre">MITRE: ${escapeHtml(mitre)}</span>` : ''}
                ${direction !== '-' ? `<span class="tag direction">${escapeHtml(formatLabel(direction))}</span>` : ''}
            </div>
        </div>
    `;
}

/**
 * 渲染检测记录列表
 * @param {string} containerId - 容器 ID
 * @param {Array} detections - 检测记录数组
 * @param {string} source - 来源标识
 */
export function renderDetectionList(containerId, detections, source = 'all') {
    const container = document.getElementById(containerId);
    if (!container) return;

    if (!detections || detections.length === 0) {
        container.innerHTML = '<div class="empty-state">暂无检测记录</div>';
        return;
    }

    const html = detections.map(d => renderDetectionItem(d, source)).join('');
    container.innerHTML = html;
}

/**
 * 合并并排序检测记录
 * @param {Array} waf1Detections - WAF1 检测记录
 * @param {Array} waf2Detections - WAF2 检测记录
 * @param {number} limit - 最大数量
 */
export function mergeDetections(waf1Detections, waf2Detections, limit = 50) {
    const all = [];

    (waf1Detections || []).forEach(d => {
        all.push({ ...d, source: 'waf1' });
    });

    (waf2Detections || []).forEach(d => {
        all.push({ ...d, source: 'waf2' });
    });

    // 按时间排序
    all.sort((a, b) => {
        const timeA = a.ts || new Date(a.timestamp || a.labels?.timestamp).getTime();
        const timeB = b.ts || new Date(b.timestamp || b.labels?.timestamp).getTime();
        return timeB - timeA;
    });

    return all.slice(0, limit);
}

export default {
    renderDetectionItem,
    renderDetectionList,
    mergeDetections
};
