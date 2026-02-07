"""
WAF2 - MCP Guardrails 动态防火墙
HTTP 流量层 LLM 动态检测

功能:
1. 请求检测 - LLM 分析入站请求
2. 响应检测 - 检测响应中的敏感数据泄露
3. 缓存机制 - 避免重复调用 LLM
4. 攻击分类 - OWASP 标准分类
5. 统计 API - 与 WAF1 统一的仪表盘接口

参考:
- MCP-Guard 论文 Stage 2/3
- OWASP GenAI Security Project
- Invariant Guardrails
"""

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
import httpx
import requests
import json
import hashlib
from datetime import datetime
from typing import Optional, Dict, Any
from collections import defaultdict

app = FastAPI(title="WAF2 - MCP Guardrails")

# CORS 支持前端访问
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==================== 配置 ====================
import os
from pydantic import BaseModel

# 动态配置 (可通过 API 修改)
class WAF2Config:
    def __init__(self):
        self.enabled = True
        self.upstream = os.environ.get("UPSTREAM", "http://127.0.0.1:3000")
        self.api_key = os.environ.get("QWEN_API_KEY", "")
        self.model = os.environ.get("QWEN_MODEL", "qwen-turbo")
        self.request_analysis = True
        self.response_analysis = True
        self.cache_enabled = True

config = WAF2Config()

# 兼容旧变量名
QWEN_API_URL = "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions"
LOG_FILE = "waf2_log.json"

# 配置更新模型
class ConfigUpdate(BaseModel):
    enabled: Optional[bool] = None
    upstream: Optional[str] = None
    api_key: Optional[str] = None
    model: Optional[str] = None
    request_analysis: Optional[bool] = None
    response_analysis: Optional[bool] = None
    cache_enabled: Optional[bool] = None

# ==================== 缓存机制 ====================

class LLMCache:
    """LLM 结果缓存，避免重复调用"""
    def __init__(self, max_size=500, ttl_seconds=300):
        self.cache = {}
        self.max_size = max_size
        self.ttl = ttl_seconds

    def _hash(self, text: str) -> str:
        return hashlib.md5(text.encode()).hexdigest()

    def get(self, key: str) -> Optional[Dict]:
        h = self._hash(key)
        if h in self.cache:
            entry = self.cache[h]
            if (datetime.now().timestamp() - entry['ts']) < self.ttl:
                return entry['value']
            del self.cache[h]
        return None

    def set(self, key: str, value: Dict):
        if len(self.cache) >= self.max_size:
            oldest = min(self.cache.keys(), key=lambda k: self.cache[k]['ts'])
            del self.cache[oldest]
        self.cache[self._hash(key)] = {'value': value, 'ts': datetime.now().timestamp()}

llm_cache = LLMCache()

# ==================== 统计信息 ====================

stats = {
    'total': 0,
    'passed': 0,
    'blocked': 0,
    'blocked_request': 0,
    'blocked_response': 0,
    'cache_hits': 0,
    'llm_calls': 0,
    'by_category': defaultdict(int),
    'by_severity': defaultdict(int),
    'detections': [],
    'avg_latency_ms': 0,
    'total_latency_ms': 0,
}

# ==================== OWASP 攻击分类 ====================

ATTACK_CATEGORIES = {
    'sql_injection': {'severity': 'high', 'owasp': 'A03:2021', 'mitre': 'T1190'},
    'xss': {'severity': 'medium', 'owasp': 'A03:2021', 'mitre': 'T1189'},
    'command_injection': {'severity': 'critical', 'owasp': 'A03:2021', 'mitre': 'T1059'},
    'path_traversal': {'severity': 'high', 'owasp': 'A01:2021', 'mitre': 'T1083'},
    'ssrf': {'severity': 'high', 'owasp': 'A10:2021', 'mitre': 'T1090'},
    'xxe': {'severity': 'high', 'owasp': 'A05:2021', 'mitre': 'T1059'},
    'prompt_injection': {'severity': 'high', 'owasp': 'LLM01', 'mitre': 'T1557'},
    'data_exfiltration': {'severity': 'critical', 'owasp': 'A01:2021', 'mitre': 'T1041'},
    'sensitive_data_exposure': {'severity': 'high', 'owasp': 'A02:2021', 'mitre': 'T1552'},
    'authentication_bypass': {'severity': 'critical', 'owasp': 'A07:2021', 'mitre': 'T1078'},
    'insecure_deserialization': {'severity': 'critical', 'owasp': 'A08:2021', 'mitre': 'T1059'},
    'unknown': {'severity': 'medium', 'owasp': 'N/A', 'mitre': 'N/A'},
}

SEVERITY_SCORES = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}

# ==================== LLM Prompt====================

REQUEST_ANALYSIS_PROMPT = """你是一个专业的 Web 应用防火墙安全分析师。分析以下 HTTP 请求是否包含攻击。

## 请求信息
- 方法: {method}
- 路径: {path}
- 请求体: {body}

## 分析任务
1. 判断是否为攻击请求
2. 如果是攻击，识别攻击类型

## 攻击类型列表
- sql_injection: SQL 注入
- xss: 跨站脚本
- command_injection: 命令注入
- path_traversal: 路径遍历
- ssrf: 服务端请求伪造
- xxe: XML 外部实体注入
- prompt_injection: 提示词注入
- authentication_bypass: 认证绕过
- insecure_deserialization: 不安全反序列化
- unknown: 其他攻击

## 响应格式 (严格遵守)
如果是正常请求: PASS
如果是攻击: BLOCK|<攻击类型>|<简短原因>

示例:
- PASS
- BLOCK|sql_injection|检测到 UNION SELECT 语句
- BLOCK|command_injection|检测到 shell 命令拼接"""

RESPONSE_ANALYSIS_PROMPT = """你是一个数据泄露防护专家。分析以下 HTTP 响应是否包含敏感数据泄露。

## 响应信息
- 状态码: {status_code}
- 响应体 (前1000字符): {body}

## 检测目标
1. 个人身份信息 (PII): 身份证、手机号、邮箱、银行卡
2. 凭证泄露: API Key、密码、Token、私钥
3. 内部信息: 内部 IP、数据库连接串、调试信息
4. 敏感业务数据: 用户隐私、财务数据

## 响应格式 (严格遵守)
如果无敏感数据: PASS
如果有敏感数据: BLOCK|sensitive_data_exposure|<泄露类型>

示例:
- PASS
- BLOCK|sensitive_data_exposure|响应包含明文密码
- BLOCK|sensitive_data_exposure|响应包含 API Key"""

# ==================== 核心检测函数 ====================

def call_llm(prompt: str) -> str:
    """调用 LLM API (使用动态配置)"""
    if not config.api_key:
        print("[WAF2] 警告: 未配置 API Key，跳过 LLM 检测")
        return "PASS"

    try:
        resp = requests.post(
            QWEN_API_URL,
            headers={
                "Authorization": f"Bearer {config.api_key}",
                "Content-Type": "application/json"
            },
            json={
                "model": config.model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0,
                "max_tokens": 100
            },
            timeout=30
        )
        return resp.json()["choices"][0]["message"]["content"].strip()
    except Exception as e:
        print(f"[WAF2] LLM 调用错误: {e}")
        return "PASS"


def analyze_request(method: str, path: str, body: str) -> Dict[str, Any]:
    """分析请求 (带缓存)"""
    # 检查请求分析是否启用
    if not config.request_analysis:
        return {'blocked': False, 'direction': 'request'}

    cache_key = f"req:{method}:{path}:{body[:200]}"

    # 检查缓存是否启用
    if config.cache_enabled:
        cached = llm_cache.get(cache_key)
        if cached:
            stats['cache_hits'] += 1
            return cached

    stats['llm_calls'] += 1
    prompt = REQUEST_ANALYSIS_PROMPT.format(
        method=method,
        path=path,
        body=body[:500] if body else "(空)"
    )

    result = call_llm(prompt)
    print(f"[WAF2] 请求分析: {result}")

    parsed = parse_llm_result(result, 'request')
    if config.cache_enabled:
        llm_cache.set(cache_key, parsed)
    return parsed


def analyze_response(status_code: int, body: str) -> Dict[str, Any]:
    """分析响应 (检测数据泄露)"""
    # 检查响应分析是否启用
    if not config.response_analysis:
        return {'blocked': False, 'direction': 'response'}

    if status_code >= 400:
        return {'blocked': False, 'direction': 'response'}

    if len(body) < 50:
        return {'blocked': False, 'direction': 'response'}

    cache_key = f"resp:{status_code}:{body[:200]}"

    # 检查缓存是否启用
    if config.cache_enabled:
        cached = llm_cache.get(cache_key)
        if cached:
            stats['cache_hits'] += 1
            return cached

    stats['llm_calls'] += 1
    prompt = RESPONSE_ANALYSIS_PROMPT.format(
        status_code=status_code,
        body=body[:1000]
    )

    result = call_llm(prompt)
    print(f"[WAF2] 响应分析: {result}")

    parsed = parse_llm_result(result, 'response')
    if config.cache_enabled:
        llm_cache.set(cache_key, parsed)
    return parsed


def parse_llm_result(result: str, direction: str) -> Dict[str, Any]:
    """解析 LLM 返回结果"""
    result = result.strip().upper()

    if result.startswith("PASS"):
        return {'blocked': False, 'direction': direction}

    if result.startswith("BLOCK"):
        parts = result.split("|")
        category = parts[1].lower().strip() if len(parts) > 1 else 'unknown'
        reason = parts[2].strip() if len(parts) > 2 else '检测到攻击'

        cat_info = ATTACK_CATEGORIES.get(category, ATTACK_CATEGORIES['unknown'])

        return {
            'blocked': True,
            'direction': direction,
            'category': category,
            'reason': reason,
            'severity': cat_info['severity'],
            'severity_score': SEVERITY_SCORES[cat_info['severity']],
            'owasp': cat_info['owasp'],
            'mitre': cat_info['mitre'],
        }

    return {'blocked': False, 'direction': direction}


def log_detection(data: Dict):
    """记录检测日志"""
    data['timestamp'] = datetime.now().isoformat()
    stats['detections'].append(data)
    if len(stats['detections']) > 100:
        stats['detections'].pop(0)

    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(data, ensure_ascii=False) + "\n")
    except:
        pass

# ==================== 统计 API (必须在代理路由之前注册) ====================

@app.get("/waf2/config")
async def get_config():
    """获取当前配置"""
    return {
        'enabled': config.enabled,
        'upstream': config.upstream,
        'model': config.model,
        'has_api_key': bool(config.api_key),
        'request_analysis': config.request_analysis,
        'response_analysis': config.response_analysis,
        'cache_enabled': config.cache_enabled,
    }


@app.post("/waf2/config")
async def update_config(update: ConfigUpdate):
    """更新配置"""
    if update.enabled is not None:
        config.enabled = update.enabled
    if update.upstream is not None:
        config.upstream = update.upstream
    if update.api_key is not None:
        config.api_key = update.api_key
    if update.model is not None:
        config.model = update.model
    if update.request_analysis is not None:
        config.request_analysis = update.request_analysis
    if update.response_analysis is not None:
        config.response_analysis = update.response_analysis
    if update.cache_enabled is not None:
        config.cache_enabled = update.cache_enabled

    print(f"[WAF2] 配置已更新: enabled={config.enabled}, upstream={config.upstream}")
    return {
        'success': True,
        'message': '配置已更新',
        'config': {
            'enabled': config.enabled,
            'upstream': config.upstream,
            'model': config.model,
            'has_api_key': bool(config.api_key),
            'request_analysis': config.request_analysis,
            'response_analysis': config.response_analysis,
            'cache_enabled': config.cache_enabled,
        }
    }


@app.post("/waf2/cache/clear")
async def clear_cache():
    """清空 LLM 缓存"""
    llm_cache.cache.clear()
    return {'success': True, 'message': '缓存已清空'}


@app.get("/waf2/stats")
async def get_stats():
    """获取基础统计"""
    return {
        'total': stats['total'],
        'passed': stats['passed'],
        'blocked': stats['blocked'],
        'blocked_request': stats['blocked_request'],
        'blocked_response': stats['blocked_response'],
        'cache_hits': stats['cache_hits'],
        'llm_calls': stats['llm_calls'],
        'cache_hit_rate': f"{(stats['cache_hits'] / max(stats['llm_calls'] + stats['cache_hits'], 1) * 100):.1f}%",
        'avg_latency_ms': f"{stats['avg_latency_ms']:.0f}",
    }


@app.get("/waf2/dashboard")
async def get_dashboard():
    """获取完整仪表盘数据"""
    block_rate = (stats['blocked'] / max(stats['total'], 1)) * 100

    return {
        'summary': {
            'total': stats['total'],
            'passed': stats['passed'],
            'blocked': stats['blocked'],
            'block_rate': f"{block_rate:.2f}%",
            'avg_latency_ms': f"{stats['avg_latency_ms']:.0f}",
        },
        'by_direction': {
            'request': stats['blocked_request'],
            'response': stats['blocked_response'],
        },
        'by_category': dict(stats['by_category']),
        'by_severity': dict(stats['by_severity']),
        'cache': {
            'hits': stats['cache_hits'],
            'llm_calls': stats['llm_calls'],
            'hit_rate': f"{(stats['cache_hits'] / max(stats['llm_calls'] + stats['cache_hits'], 1) * 100):.1f}%",
            'size': len(llm_cache.cache),
        },
        'recent_detections': stats['detections'][-10:],
    }


@app.get("/waf2/detections")
async def get_detections():
    """获取最近检测记录"""
    return stats['detections'][-20:]


@app.post("/waf2/reset")
async def reset_stats():
    """重置统计"""
    stats['total'] = 0
    stats['passed'] = 0
    stats['blocked'] = 0
    stats['blocked_request'] = 0
    stats['blocked_response'] = 0
    stats['cache_hits'] = 0
    stats['llm_calls'] = 0
    stats['by_category'].clear()
    stats['by_severity'].clear()
    stats['detections'].clear()
    stats['avg_latency_ms'] = 0
    stats['total_latency_ms'] = 0
    return {'success': True, 'message': '统计数据已重置'}


@app.get("/waf2/health")
async def health_check():
    """健康检查"""
    return {
        'status': 'healthy',
        'enabled': config.enabled,
        'upstream': config.upstream,
        'model': config.model,
        'has_api_key': bool(config.api_key),
        'cache_size': len(llm_cache.cache),
    }

# ==================== 代理路由 (必须在统计 API 之后注册) ====================

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
async def proxy(path: str, request: Request):
    """主代理入口 - 转发所有非 waf2 API 的请求到上游"""
    start_time = datetime.now()

    if request.method == "OPTIONS":
        return Response(status_code=200)

    body = (await request.body()).decode("utf-8", errors="ignore")

    stats['total'] += 1
    print(f"\n[WAF2] ══════════════════════════════════════")
    print(f"[WAF2] {request.method} /{path}")
    if body:
        print(f"[WAF2] Body: {body[:100]}...")

    # ========== 检查 WAF2 是否启用 ==========
    if not config.enabled:
        print(f"[WAF2] ⏸️ WAF2 已禁用，直接转发")
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                headers = {k: v for k, v in request.headers.items()
                          if k.lower() not in ["host", "content-length"]}
                upstream_resp = await client.request(
                    request.method,
                    f"{config.upstream}/{path}",
                    content=body.encode() if body else None,
                    headers=headers
                )
            stats['passed'] += 1
            return Response(
                content=upstream_resp.content,
                status_code=upstream_resp.status_code,
                headers=dict(upstream_resp.headers)
            )
        except Exception as e:
            return Response(content=f"上游服务错误: {e}", status_code=502)

    # ========== 阶段1: 请求检测 ==========
    req_result = analyze_request(request.method, f"/{path}", body)

    if req_result.get('blocked'):
        stats['blocked'] += 1
        stats['blocked_request'] += 1
        stats['by_category'][req_result.get('category', 'unknown')] += 1
        stats['by_severity'][req_result.get('severity', 'medium')] += 1

        log_detection({
            'direction': 'request',
            'method': request.method,
            'path': f"/{path}",
            'body': body[:500],
            **req_result
        })

        elapsed = (datetime.now() - start_time).total_seconds() * 1000
        print(f"[WAF2] ❌ 请求拦截 [{req_result.get('category')}]: {req_result.get('reason')}")
        print(f"[WAF2] ══════════════════════════════════════ ({elapsed:.0f}ms)")

        return Response(
            content=json.dumps({
                'error': 'WAF2 拦截',
                'direction': 'request',
                'category': req_result.get('category'),
                'severity': req_result.get('severity'),
                'reason': req_result.get('reason'),
                'owasp': req_result.get('owasp'),
                'mitre': req_result.get('mitre'),
            }, ensure_ascii=False),
            status_code=403,
            media_type="application/json"
        )

    # ========== 阶段2: 转发请求 ==========
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            headers = {k: v for k, v in request.headers.items()
                      if k.lower() not in ["host", "content-length"]}

            upstream_resp = await client.request(
                request.method,
                f"{config.upstream}/{path}",
                content=body.encode() if body else None,
                headers=headers
            )
            resp_body = upstream_resp.text
            resp_status = upstream_resp.status_code
    except Exception as e:
        print(f"[WAF2] 上游错误: {e}")
        return Response(content=f"上游服务错误: {e}", status_code=502)

    # ========== 阶段3: 响应检测 ==========
    resp_result = analyze_response(resp_status, resp_body)

    if resp_result.get('blocked'):
        stats['blocked'] += 1
        stats['blocked_response'] += 1
        stats['by_category'][resp_result.get('category', 'unknown')] += 1
        stats['by_severity'][resp_result.get('severity', 'medium')] += 1

        log_detection({
            'direction': 'response',
            'method': request.method,
            'path': f"/{path}",
            'status_code': resp_status,
            'response_preview': resp_body[:200],
            **resp_result
        })

        elapsed = (datetime.now() - start_time).total_seconds() * 1000
        print(f"[WAF2] ❌ 响应拦截 [{resp_result.get('category')}]: {resp_result.get('reason')}")
        print(f"[WAF2] ══════════════════════════════════════ ({elapsed:.0f}ms)")

        return Response(
            content=json.dumps({
                'error': 'WAF2 拦截',
                'direction': 'response',
                'category': resp_result.get('category'),
                'severity': resp_result.get('severity'),
                'reason': resp_result.get('reason'),
                'message': '响应包含敏感数据，已被拦截',
            }, ensure_ascii=False),
            status_code=403,
            media_type="application/json"
        )

    # ========== 阶段4: 返回响应 ==========
    stats['passed'] += 1
    elapsed = (datetime.now() - start_time).total_seconds() * 1000
    stats['total_latency_ms'] += elapsed
    stats['avg_latency_ms'] = stats['total_latency_ms'] / stats['total']

    print(f"[WAF2] ✅ 放行 (上游: {resp_status})")
    print(f"[WAF2] ══════════════════════════════════════ ({elapsed:.0f}ms)")

    return Response(
        content=upstream_resp.content,
        status_code=resp_status,
        headers=dict(upstream_resp.headers)
    )

# ==================== 启动 ====================

if __name__ == "__main__":
    import uvicorn
    print("=" * 50)
    print("  WAF2 - MCP Guardrails 动态防火墙")
    print("=" * 50)
    print(f"  监听端口: 8081")
    print(f"  上游地址: {config.upstream}")
    print(f"  LLM 模型: {config.model}")
    print(f"  API Key: {'已配置' if config.api_key else '未配置'}")
    print(f"  功能: 请求检测 + 响应检测 + 缓存")
    print(f"  配置 API: GET/POST /waf2/config")
    print("=" * 50)
    uvicorn.run(app, host="0.0.0.0", port=8081)
