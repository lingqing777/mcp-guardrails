/**
 * 检测记录条目组件
 */

import { formatLabel, formatTime, escapeHtml } from '../utils/formatters.js';

function formatScore(value) {
    const number = Number(value);
    return Number.isFinite(number) ? number.toFixed(3) : '';
}

function renderWaf2DecisionTags(detection) {
    const tags = [];
    const engine = detection.engine || detection.labels?.engine;
    const route = detection.route || detection.labels?.route;
    const ragAugmented = detection.rag_augmented === true;
    const ragGated = detection.rag_gated === true;
    const ragScore = formatScore(detection.rag_top_score);
    const evidenceIds = Array.isArray(detection.evidence_ids) ? detection.evidence_ids : [];
    const routeReasons = Array.isArray(detection.route_reasons) ? detection.route_reasons : [];
    const routeReason = detection.route_reason;
    const providerLocality = detection.provider_locality;
    const privacyMode = detection.privacy_mode;
    const localTopCategory = detection.local_attack_top_category;
    const localTopScore = formatScore(detection.local_attack_top_score);

    if (engine) {
        tags.push(`<span class="tag engine">Engine: ${escapeHtml(formatLabel(engine))}</span>`);
    }
    if (route) {
        tags.push(`<span class="tag route">Route: ${escapeHtml(formatLabel(route))}</span>`);
    }
    if (providerLocality || privacyMode) {
        tags.push(`<span class="tag privacy">${escapeHtml(providerLocality || 'provider')}: ${escapeHtml(privacyMode || '-')}</span>`);
    }
    if (localTopCategory && localTopCategory !== 'none') {
        tags.push(`<span class="tag score">Score: ${escapeHtml(formatLabel(localTopCategory))}${localTopScore ? ` ${localTopScore}` : ''}</span>`);
    }
    if (ragAugmented) {
        tags.push(`<span class="tag rag">RAG: hit${ragScore ? ` ${ragScore}` : ''}</span>`);
    } else if (ragGated) {
        tags.push(`<span class="tag rag-muted">RAG: gated${ragScore ? ` ${ragScore}` : ''}</span>`);
    }
    if (evidenceIds.length > 0) {
        tags.push(`<span class="tag evidence">Evidence: ${escapeHtml(evidenceIds.slice(0, 3).join(', '))}</span>`);
    }
    if (routeReasons.length > 0) {
        const reasonText = routeReasons.slice(0, 3).join(', ');
        tags.push(`<span class="tag route-reason">Why: ${escapeHtml(reasonText)}</span>`);
    } else if (routeReason) {
        tags.push(`<span class="tag route-reason">Why: ${escapeHtml(routeReason)}</span>`);
    }

    return tags.join('');
}

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
    const normalizedSource = String(itemSource || source).toLowerCase();
    const tool = detection.tool || '-';
    const waf2DecisionTags = normalizedSource === 'waf2' ? renderWaf2DecisionTags(detection) : '';

    return `
        <div class="detection-item ${severity}">
            <div class="detection-header">
                <span class="detection-category">
                    ${escapeHtml(formatLabel(category))}
                    <span class="waf-badge ${escapeHtml(normalizedSource)}">${escapeHtml(normalizedSource.toUpperCase())}</span>
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
                ${waf2DecisionTags}
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
        container._lastDataKey = '';
        return;
    }

    // 数据指纹：跳过无变化的重渲染
    const dataKey = JSON.stringify(detections);
    if (container._lastDataKey === dataKey) return;
    container._lastDataKey = dataKey;

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
