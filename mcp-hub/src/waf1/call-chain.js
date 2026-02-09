/**
 * 调用链追踪
 * 简化版 Invariant Dataflow
 */

const MAX_HISTORY = 100;

// 危险调用链模式
const DANGEROUS_CHAINS = [
  {
    name: 'data_exfiltration',
    desc: '读取敏感数据后发送到外部',
    steps: [
      { match: (call) => /read|get|fetch|query|search|list/i.test(call.tool) },
      { match: (call) => /send|post|upload|write|push|forward/i.test(call.tool) },
    ],
  },
  {
    name: 'credential_theft',
    desc: '访问凭证后进行网络请求',
    steps: [
      { match: (call) => {
        const s = JSON.stringify(call.args);
        return /password|secret|key|token|credential|\.env|\.ssh|id_rsa/i.test(s);
      }},
      { match: (call) => {
        const s = JSON.stringify(call.args);
        return /https?:\/\/|curl|wget|fetch|request/i.test(s);
      }},
    ],
  },
  {
    name: 'recon_then_exploit',
    desc: '侦察后执行攻击',
    steps: [
      { match: (call) => /scan|nmap|recon|enumerate|discover/i.test(JSON.stringify(call.args)) },
      { match: (call) => /exploit|inject|attack|shell|reverse/i.test(JSON.stringify(call.args)) },
    ],
  },
];

/**
 * 调用链追踪器
 */
export class CallChainTracker {
  constructor(maxHistory = MAX_HISTORY) {
    this.history = [];
    this.maxHistory = maxHistory;
  }

  /**
   * 检测危险调用链
   * @param {string} tool - 工具名称
   * @param {object} args - 参数
   * @returns {object} { detected, chain, desc, calls }
   */
  check(tool, args) {
    // 记录当前调用
    this.history.push({ tool, args, ts: Date.now() });
    if (this.history.length > this.maxHistory) this.history.shift();

    // 只检查最近 5 分钟的调用链
    const recentCalls = this.history.filter(c => Date.now() - c.ts < 300000);

    for (const chain of DANGEROUS_CHAINS) {
      const currentCall = { tool, args };
      const lastStepIdx = chain.steps.length - 1;

      // 当前调用匹配链的最后一步
      if (chain.steps[lastStepIdx].match(currentCall)) {
        // 检查之前的调用是否匹配前面的步骤
        for (let i = recentCalls.length - 2; i >= 0; i--) {
          for (let stepIdx = lastStepIdx - 1; stepIdx >= 0; stepIdx--) {
            if (chain.steps[stepIdx].match(recentCalls[i])) {
              if (stepIdx === 0) {
                // 检测到危险调用链后，清除历史，防止后续请求持续触发
                this.history = [];
                return {
                  detected: true,
                  chain: chain.name,
                  desc: chain.desc,
                  calls: [recentCalls[i], currentCall],
                };
              }
            }
          }
        }
      }
    }

    return { detected: false };
  }

  /**
   * 获取调用历史
   */
  getHistory(limit = 20) {
    return this.history.slice(-limit);
  }

  /**
   * 清空历史
   */
  clear() {
    this.history = [];
  }
}

export { DANGEROUS_CHAINS };
