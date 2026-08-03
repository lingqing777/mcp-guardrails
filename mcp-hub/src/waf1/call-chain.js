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
      { match: (call) => /read|get|fetch|query|search|list|execute_sql/i.test(call.tool) },
      { match: (call) => {
        const t = String(call.tool || '');
        if (/send|post|upload|write|push|forward/i.test(t)) return true;
        // 外发渠道:Github gist / pastebin / snippet / webhook / S3 等也是 exfil 通道
        if (/gist|paste|snippet|webhook|bucket\b|s3_/i.test(t)) return true;
        if (/(^|__)create_(?:gist|paste|snippet|repository|repo|issue|comment|file|or_update_file|pull_request)/i.test(t)) return true;
        // GitHub 其他外发渠道: issue 评论/更新、推送/编辑文件、PR review 等
        if (/(^|__)(add_.*comment|update_issue|push_files|edit_file|update_file|create_review|submit_review)/i.test(t)) return true;
        if (/http_request|http_post|http-client|webhook|fetch_url|request_url/i.test(t)) {
          const a = call.args || {};
          const method = String(a.method || '').toUpperCase();
          if (['POST', 'PUT', 'PATCH'].includes(method)) return true;
        }
        return false;
      }},
    ],
  },
  {
    name: 'credential_theft',
    desc: '访问凭证后进行网络请求',
    steps: [
      { match: (call) => {
        const t = String(call.tool || '');
        // step1 只对"读取/访问"类工具匹配; 外发工具(http_request/create_*/send 等)不作 step1,
        // 避免连续外发调用(如场景二多次 http_request)被误判为"访问凭证后外发"
        if (/http_request|http_post|http-client|webhook|fetch_url|request_url|(^|__)create_|(^|__)add_|(^|__)update_|(^|__)push_|send|post|upload|write|forward/i.test(t)) return false;
        const s = JSON.stringify(call.args);
        return /password|secret|key|token|credential|\.env|\.ssh|id_rsa|\.gnupg|private-keys/i.test(s);
      }},
      { match: (call) => {
        const t = String(call.tool || '');
        const s = JSON.stringify(call.args);
        if (/https?:\/\/|curl|wget|fetch|request/i.test(s)) return true;
        // 外发渠道(同 data_exfiltration step 2)
        if (/gist|paste|snippet|webhook|bucket\b|s3_/i.test(t)) return true;
        if (/(^|__)create_(?:gist|paste|snippet|repository|repo|issue|comment|file|or_update_file|pull_request)/i.test(t)) return true;
        // GitHub 其他外发渠道: issue 评论/更新、推送/编辑文件、PR review 等
        if (/(^|__)(add_.*comment|update_issue|push_files|edit_file|update_file|create_review|submit_review)/i.test(t)) return true;
        return false;
      }},
    ],
  },
  {
    name: 'recon_then_exploit',
    desc: '侦察后执行攻击 / 管理员操作',
    steps: [
      { match: (call) => {
        const t = String(call.tool || '');
        const a = JSON.stringify(call.args || {});
        if (/scan|nmap|recon|enumerate|discover/i.test(a)) return true;
        if (/(^|__)(list|get|enumerate|discover|recon)_/i.test(t)) return true;
        return false;
      }},
      { match: (call) => {
        const t = String(call.tool || '');
        const a = JSON.stringify(call.args || {});
        if (/exploit|inject|attack|shell|reverse/i.test(a)) return true;
        if (/(^|__)(delete|drop|destroy|purge|kill|terminate|remove)_/i.test(t)) return true;
        return false;
      }},
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
          // 检测到危险调用链后保留历史，使重试外发调用仍能被同一调用链触发拦截。
          // (原设计清空历史以防级联告警，但会导致攻击者立即重试绕过：清空后无前置读记录)
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
