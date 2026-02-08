/**
 * 统计卡片组件
 */

import { formatNumber, formatPercent } from '../utils/formatters.js';

/**
 * 渲染统计卡片
 * @param {Object} options
 * @param {string} options.title - 卡片标题
 * @param {number|string} options.value - 主要数值
 * @param {string} options.subtitle - 副标题
 * @param {string} options.color - 颜色类名 (blue, red, green, yellow, purple)
 * @param {string} options.id - 元素 ID
 */
export function renderCard({ title, value, subtitle, color = 'blue', id }) {
    return `
        <div class="card">
            <div class="card-title">${title}</div>
            <div class="card-value ${color}" ${id ? `id="${id}"` : ''}>${value ?? '-'}</div>
            <div class="card-subtitle">${subtitle || ''}</div>
        </div>
    `;
}

/**
 * 更新卡片数值
 */
export function updateCard(id, value) {
    const el = document.getElementById(id);
    if (el) {
        el.textContent = value ?? '-';
    }
}

/**
 * 渲染统计卡片组
 * @param {string} containerId - 容器 ID
 * @param {Array} cards - 卡片配置数组
 */
export function renderCardGrid(containerId, cards) {
    const container = document.getElementById(containerId);
    if (!container) return;

    const html = cards.map(card => renderCard(card)).join('');
    container.innerHTML = html;
}

export default {
    renderCard,
    updateCard,
    renderCardGrid
};
