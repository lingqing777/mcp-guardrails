/**
 * 开关组件
 */

/**
 * 创建开关 HTML
 * @param {Object} options
 * @param {string} options.rule - 规则标识
 * @param {boolean} options.active - 是否激活
 * @param {string} options.size - 尺寸 ('sm' | 'default')
 */
export function createToggle({ rule, active = true, size = 'sm' }) {
    const className = size === 'sm' ? 'toggle-sm' : 'toggle-switch';
    return `<div class="${className} ${active ? 'active' : ''}" data-rule="${rule}"></div>`;
}

/**
 * 切换开关状态
 * @param {HTMLElement} el - 开关元素
 * @param {Function} callback - 状态变化回调
 */
export function toggleSwitch(el, callback) {
    el.classList.toggle('active');
    const isActive = el.classList.contains('active');
    const rule = el.dataset.rule;

    if (callback) {
        callback(rule, isActive);
    }

    return isActive;
}

/**
 * 设置开关状态
 * @param {string} rule - 规则标识
 * @param {boolean} active - 是否激活
 */
export function setToggleState(rule, active) {
    const el = document.querySelector(`[data-rule="${rule}"]`);
    if (el) {
        el.classList.toggle('active', active);
    }
}

/**
 * 获取开关状态
 * @param {string} rule - 规则标识
 */
export function getToggleState(rule) {
    const el = document.querySelector(`[data-rule="${rule}"]`);
    return el ? el.classList.contains('active') : false;
}

/**
 * 批量设置开关状态
 * @param {Object} states - { rule: boolean } 映射
 */
export function setToggleStates(states) {
    for (const [rule, active] of Object.entries(states)) {
        setToggleState(rule, active);
    }
}

export default {
    createToggle,
    toggleSwitch,
    setToggleState,
    getToggleState,
    setToggleStates
};
