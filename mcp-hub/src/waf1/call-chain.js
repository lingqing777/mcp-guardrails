/**
 * 调用链追踪
 * 简化版 Invariant Dataflow
 */

import {
  isSupabaseLeakWriteCall,
  isSupabaseSensitiveSqlCall,
  isSupabaseUserWritableReadCall,
} from './supabase-sql.js';

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
  {
    name: 'supabase_lethal_trifecta',
    desc: '读取用户可写内容后执行敏感 SQL 并写回公开表',
    category: 'supabaseCallChain',
    steps: [
      { match: (call) => isSupabaseUserWritableReadCall(call.tool, call.args) },
      { match: (call) => isSupabaseSensitiveSqlCall(call.tool, call.args) },
      { match: (call) => isSupabaseLeakWriteCall(call.tool, call.args) },
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
  check(tool, args, context = {}) {
    const currentTs = Date.now();
    const currentCall = {
      tool,
      args,
      ts: currentTs,
      clientId: context.clientId || 'unknown',
    };

    // 记录当前调用
    this.history.push(currentCall);
    if (this.history.length > this.maxHistory) this.history.shift();

    // 只检查最近 5 分钟的调用链
    const recentCalls = this.history.filter((call) =>
      currentTs - call.ts < 300000 &&
      call.clientId === currentCall.clientId
    );

    for (const chain of DANGEROUS_CHAINS) {
      const lastStepIdx = chain.steps.length - 1;

      // 当前调用匹配链的最后一步
      if (chain.steps[lastStepIdx].match(currentCall)) {
        const matchedCalls = [currentCall];
        let stepIdx = lastStepIdx - 1;

        for (let i = recentCalls.length - 2; i >= 0 && stepIdx >= 0; i--) {
          if (chain.steps[stepIdx].match(recentCalls[i])) {
            matchedCalls.unshift(recentCalls[i]);
            stepIdx--;
          }
        }

        if (stepIdx < 0) {
          // 检测到危险调用链后，清除历史，防止后续请求持续触发
          this.history = [];
          return {
            detected: true,
            chain: chain.name,
            desc: chain.desc,
            category: chain.category || 'callChain',
            calls: matchedCalls,
          };
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
