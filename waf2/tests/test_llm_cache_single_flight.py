"""Tests for LLMCache single-flight (improve-waf2-concurrency-for-rq5).

Covers spec scenarios:
  - 同 payload 并发请求合并为单次 LLM 调用
  - 不同 payload 并发请求互不影响
  - LLM 失败时等待方共享异常

Run with:
  PYTHONPATH=waf2 python3 -m pytest waf2/tests/test_llm_cache_single_flight.py -v
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import waf2_proxy as p  # noqa: E402


def _fresh_cache() -> p.LLMCache:
    return p.LLMCache(max_size=64, ttl_seconds=60)


def test_same_key_concurrent_miss_merges_to_one_call():
    """20 同 key 并发请求 → 实际产出函数只被调用 1 次"""
    cache = _fresh_cache()
    calls = {"n": 0}

    async def producer():
        calls["n"] += 1
        await asyncio.sleep(0.05)
        return {"verdict": "BLOCK", "category": "sql_injection"}

    async def run():
        tasks = [cache.single_flight("k1", producer) for _ in range(20)]
        return await asyncio.gather(*tasks)

    results = asyncio.run(run())
    assert calls["n"] == 1, f"expected 1 producer call, got {calls['n']}"
    assert all(r == {"verdict": "BLOCK", "category": "sql_injection"} for r in results)


def test_different_keys_run_independently():
    """10 不同 key 并发 → producer 调用 10 次,互不阻塞"""
    cache = _fresh_cache()
    calls = {"n": 0}

    async def make_producer(label: str):
        async def producer():
            calls["n"] += 1
            await asyncio.sleep(0.01)
            return {"label": label}
        return producer

    async def run():
        tasks = []
        for i in range(10):
            prod = await make_producer(f"k{i}")
            tasks.append(cache.single_flight(f"key{i}", prod))
        return await asyncio.gather(*tasks)

    results = asyncio.run(run())
    assert calls["n"] == 10
    labels = sorted(r["label"] for r in results)
    assert labels == sorted(f"k{i}" for i in range(10))


def test_exception_shared_and_inflight_cleared():
    """合并失败时等待方共享异常,in-flight 表清理,后续相同 key 触发新调用"""
    cache = _fresh_cache()
    attempts = {"n": 0}

    class BoomError(RuntimeError):
        pass

    async def failing_producer():
        attempts["n"] += 1
        await asyncio.sleep(0.01)
        raise BoomError("LLM dead")

    async def good_producer():
        attempts["n"] += 1
        return {"ok": True}

    async def run():
        # 5 concurrent — all should see BoomError
        first_round = [cache.single_flight("kx", failing_producer) for _ in range(5)]
        results_or_excs = await asyncio.gather(*first_round, return_exceptions=True)
        # After failure cleanup, second-round should trigger a NEW producer call
        second = await cache.single_flight("kx", good_producer)
        return results_or_excs, second

    results, second = asyncio.run(run())
    # 5 leaders/waiters all share one BoomError-typed exception
    assert all(isinstance(r, BoomError) for r in results), results
    # first round produces exactly 1 underlying call
    # second round triggers another (because in-flight was cleared)
    assert attempts["n"] == 2, f"expected 2 producer calls total, got {attempts['n']}"
    assert second == {"ok": True}
    # in-flight table is clean
    assert not cache._inflight, f"inflight not cleaned: {cache._inflight}"


def test_cache_hit_skips_single_flight():
    """缓存命中时 single_flight 直接返回,不调用 producer"""
    cache = _fresh_cache()
    cache.set("hot", {"hit": True})
    calls = {"n": 0}

    async def producer():
        calls["n"] += 1
        return {"hit": False}

    result = asyncio.run(cache.single_flight("hot", producer))
    assert result == {"hit": True}
    assert calls["n"] == 0


if __name__ == "__main__":
    test_same_key_concurrent_miss_merges_to_one_call()
    test_different_keys_run_independently()
    test_exception_shared_and_inflight_cleared()
    test_cache_hit_skips_single_flight()
    print("OK - all single-flight tests passed")
