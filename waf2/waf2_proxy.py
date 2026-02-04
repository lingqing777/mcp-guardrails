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

UPSTREAM = os.environ.get("UPSTREAM", "http://127.0.0.1:3000")
QWEN_API_KEY = os.environ.get("QWEN_API_KEY", "sk-9e24ea719c084c1e881f097fa450b7b6")
QWEN_MODEL = os.environ.get("QWEN_MODEL", "qwen-turbo")
QWEN_API_URL = "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions"
LOG_FILE = "waf2_log.json"

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
    """调用 LLM API"""
    try:
        resp = requests.post(
            QWEN_API_URL,
            headers={
                "Authorization": f"Bearer {QWEN_API_KEY}",
                "Content-Type": "application/json"
            },
            json={
                "model": QWEN_MODEL,
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
    cache_key = f"req:{method}:{path}:{body[:200]}"

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
    llm_cache.set(cache_key, parsed)
    return parsed


def analyze_response(status_code: int, body: str) -> Dict[str, Any]:
    """分析响应 (检测数据泄露)"""
    if status_code >= 400:
        return {'blocked': False, 'direction': 'response'}

    if len(body) < 50:
        return {'blocked': False, 'direction': 'response'}

    cache_key = f"resp:{status_code}:{body[:200]}"

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
        'upstream': UPSTREAM,
        'model': QWEN_MODEL,
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
                f"{UPSTREAM}/{path}",
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
    print(f"  上游地址: {UPSTREAM}")
    print(f"  LLM 模型: {QWEN_MODEL}")
    print(f"  功能: 请求检测 + 响应检测 + 缓存")
    print("=" * 50)
    uvicorn.run(app, host="0.0.0.0", port=8081)
