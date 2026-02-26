/**
 * 柱状图组件
 */

import { formatLabel } from '../utils/formatters.js';

/**
 * 渲染柱状图
 * @param {string} containerId - 容器 ID
 * @param {Object} data - 数据对象 { label: count }
 * @param {string} type - 图表类型 ('default' | 'severity')
 */
export function renderBarChart(containerId, data, type = 'default') {
    const container = document.getElementById(containerId);
    if (!container) return;

    if (!data || Object.keys(data).length === 0) {
        container.innerHTML = '<div class="empty-state">暂无数据</div>';
        container._lastDataKey = '';
        return;
    }

    // 数据指纹：跳过无变化的重渲染
    const dataKey = JSON.stringify(data);
    if (container._lastDataKey === dataKey) return;
    container._lastDataKey = dataKey;

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

/**
 * 合并多个数据源
 * @param  {...Object} sources - 多个数据对象
 * @returns {Object} 合并后的数据
 */
export function mergeChartData(...sources) {
    const result = {};
    for (const source of sources) {
        if (!source) continue;
        for (const [key, value] of Object.entries(source)) {
            result[key] = (result[key] || 0) + value;
        }
    }
    return result;
}

export default {
    renderBarChart,
    mergeChartData
};
