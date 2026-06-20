#!/usr/bin/env python3
"""
Test suite for Threat Intelligence IOC Context Enrichment Cache Optimizer
Production-grade testing with real assertions and performance validation.
"""

import sys
import time
import json
import threading
from typing import List, Tuple

sys.path.insert(0, '/home/user/autonomous-developer/NeuralShield-AI')

from neural_shield.threat_intelligence_ioc_context_enrichment_cache_optimizer_2026_june import (
    IOCContextEnrichmentCacheOptimizer,
    IOCType,
    EnrichmentSource,
    ThreadSafeLRUCache,
    PerformanceMetrics
)


def test_basic_cache_functionality():
    """Test basic cache get/put functionality"""
    print("Test 1: Basic Cache Functionality")

    optimizer = IOCContextEnrichmentCacheOptimizer(
        cache_max_size=100,
        cache_ttl=3600,
        enable_background_cleanup=False
    )

    # First enrichment (cache miss)
    data1, was_cached1 = optimizer.enrich_ioc(
        "192.168.1.1",
        IOCType.IP_ADDRESS
    )

    assert was_cached1 is False, "First enrichment should NOT be cached"
    assert "malicious_score" in data1, "Enrichment should contain malicious_score"
    assert "ioc_value" in data1, "Enrichment should contain ioc_value"

    # Second enrichment (cache hit)
    data2, was_cached2 = optimizer.enrich_ioc(
        "192.168.1.1",
        IOCType.IP_ADDRESS
    )

    assert was_cached2 is True, "Second enrichment SHOULD be cached"
    assert data1["malicious_score"] == data2["malicious_score"], "Cached data should match"

    metrics = optimizer.get_performance_metrics()
    assert metrics["cache"]["cache_hits"] >= 1, "Should have at least 1 cache hit"
    assert metrics["cache"]["cache_misses"] >= 1, "Should have at least 1 cache miss"

    optimizer.shutdown()
    print("  ✓ PASSED: Basic cache functionality works correctly")
    return True


def test_force_refresh():
    """Test force refresh bypasses cache"""
    print("\nTest 2: Force Refresh")

    optimizer = IOCContextEnrichmentCacheOptimizer(
        cache_max_size=100,
        enable_background_cleanup=False
    )

    # Populate cache
    optimizer.enrich_ioc("8.8.8.8", IOCType.IP_ADDRESS)

    # Force refresh should bypass cache
    data, was_cached = optimizer.enrich_ioc(
        "8.8.8.8",
        IOCType.IP_ADDRESS,
        force_refresh=True
    )

    assert was_cached is False, "Force refresh should NOT use cache"

    optimizer.shutdown()
    print("  ✓ PASSED: Force refresh correctly bypasses cache")
    return True


def test_batch_enrichment():
    """Test batch enrichment with cache optimization"""
    print("\nTest 3: Batch Enrichment")

    optimizer = IOCContextEnrichmentCacheOptimizer(
        cache_max_size=100,
        enable_background_cleanup=False
    )

    iocs: List[Tuple[str, IOCType]] = [
        ("1.1.1.1", IOCType.IP_ADDRESS),
        ("2.2.2.2", IOCType.IP_ADDRESS),
        ("malicious.com", IOCType.DOMAIN),
        ("https://phish.com", IOCType.URL),
    ]

    # First batch - all misses
    results1 = optimizer.enrich_batch(iocs)
    assert len(results1) == 4, "Should return results for all IOCs"

    # Second batch - should have hits
    results2 = optimizer.enrich_batch(iocs)
    assert len(results2) == 4, "Should return results for all IOCs"

    metrics = optimizer.get_performance_metrics()
    assert metrics["cache"]["batch_operations"] >= 2, "Should track batch operations"

    optimizer.shutdown()
    print("  ✓ PASSED: Batch enrichment works correctly")
    return True


def test_performance_metrics():
    """Test performance metrics tracking"""
    print("\nTest 4: Performance Metrics")

    optimizer = IOCContextEnrichmentCacheOptimizer(
        cache_max_size=100,
        enable_background_cleanup=False
    )

    # Generate some traffic
    test_iocs = [
        ("10.0.0.1", IOCType.IP_ADDRESS),
        ("10.0.0.2", IOCType.IP_ADDRESS),
        ("10.0.0.1", IOCType.IP_ADDRESS),  # Repeat for cache hit
        ("evil.com", IOCType.DOMAIN),
        ("evil.com", IOCType.DOMAIN),  # Repeat for cache hit
    ]

    for ioc_value, ioc_type in test_iocs:
        optimizer.enrich_ioc(ioc_value, ioc_type)

    metrics = optimizer.get_performance_metrics()
    stats = optimizer.get_cache_statistics()

    assert "performance" in stats, "Stats should contain performance data"
    assert "recommendations" in stats, "Stats should contain recommendations"
    assert "hit_rate_percent" in metrics["cache"], "Metrics should have hit rate"
    assert metrics["cache"]["total_requests"] == 5, "Should have 5 total requests"

    print(f"    Hit Rate: {metrics['cache']['hit_rate_percent']}%")
    print(f"    Total Requests: {metrics['cache']['total_requests']}")
    print(f"    Cache Size: {metrics['cache_size']}")

    optimizer.shutdown()
    print("  ✓ PASSED: Performance metrics tracked correctly")
    return True


def test_lru_eviction():
    """Test LRU eviction when cache reaches max size"""
    print("\nTest 5: LRU Eviction")

    cache = ThreadSafeLRUCache(max_size=5, default_ttl=3600)

    # Fill cache to capacity
    for i in range(5):
        cache.put(
            f"192.168.1.{i}",
            IOCType.IP_ADDRESS,
            {"score": i},
            [EnrichmentSource.VIRUS_TOTAL]
        )

    assert cache.get_size() == 5, "Cache should be at max capacity"

    # Add one more - should trigger eviction
    cache.put(
        "10.0.0.1",
        IOCType.IP_ADDRESS,
        {"score": 99},
        [EnrichmentSource.VIRUS_TOTAL]
    )

    assert cache.get_size() == 5, "Cache should still be at max capacity after eviction"
    assert cache.metrics.evictions == 1, "Should have 1 eviction"

    print(f"    Evictions: {cache.metrics.evictions}")
    print("  ✓ PASSED: LRU eviction works correctly")
    return True


def test_ttl_expiration():
    """Test TTL-based cache expiration"""
    print("\nTest 6: TTL Expiration")

    cache = ThreadSafeLRUCache(max_size=100, default_ttl=1)  # 1 second TTL

    cache.put(
        "expire.test",
        IOCType.DOMAIN,
        {"data": "temporary"},
        [EnrichmentSource.VIRUS_TOTAL],
        ttl_seconds=1
    )

    # Should hit immediately
    entry1 = cache.get("expire.test", IOCType.DOMAIN)
    assert entry1 is not None, "Should find entry before expiration"

    # Wait for expiration
    time.sleep(1.1)

    # Should miss after expiration
    entry2 = cache.get("expire.test", IOCType.DOMAIN)
    assert entry2 is None, "Entry should expire after TTL"

    print("  ✓ PASSED: TTL expiration works correctly")
    return True


def test_thread_safety():
    """Test thread-safe concurrent access"""
    print("\nTest 7: Thread Safety")

    optimizer = IOCContextEnrichmentCacheOptimizer(
        cache_max_size=1000,
        enable_background_cleanup=False
    )

    errors = []

    def worker(thread_id: int):
        try:
            for i in range(50):
                ioc_value = f"172.16.{thread_id}.{i}"
                optimizer.enrich_ioc(ioc_value, IOCType.IP_ADDRESS)
        except Exception as e:
            errors.append(str(e))

    threads = []
    for t in range(5):
        thread = threading.Thread(target=worker, args=(t,))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    assert len(errors) == 0, f"Thread safety errors: {errors}"

    metrics = optimizer.get_performance_metrics()
    assert metrics["cache"]["total_requests"] == 250, "Should have 250 total requests"

    optimizer.shutdown()
    print(f"    Concurrent requests: {metrics['cache']['total_requests']}")
    print("  ✓ PASSED: Thread-safe concurrent access")
    return True


def test_different_ioc_types():
    """Test enrichment for different IOC types"""
    print("\nTest 8: Different IOC Types")

    optimizer = IOCContextEnrichmentCacheOptimizer(
        enable_background_cleanup=False
    )

    test_cases = [
        ("192.168.1.1", IOCType.IP_ADDRESS),
        ("malicious.com", IOCType.DOMAIN),
        ("https://bad.com/payload.exe", IOCType.URL),
        ("d41d8cd98f00b204e9800998ecf8427e", IOCType.FILE_HASH),
        ("attacker@phish.com", IOCType.EMAIL),
    ]

    for ioc_value, ioc_type in test_cases:
        data, was_cached = optimizer.enrich_ioc(ioc_value, ioc_type)
        assert data["ioc_type"] == ioc_type.value, f"IOC type mismatch for {ioc_type}"
        assert was_cached is False

    print(f"    Tested {len(test_cases)} different IOC types")
    optimizer.shutdown()
    print("  ✓ PASSED: All IOC types work correctly")
    return True


def test_context_manager():
    """Test context manager usage"""
    print("\nTest 9: Context Manager")

    with IOCContextEnrichmentCacheOptimizer(enable_background_cleanup=True) as optimizer:
        data, _ = optimizer.enrich_ioc("1.2.3.4", IOCType.IP_ADDRESS)
        assert "malicious_score" in data

    print("  ✓ PASSED: Context manager works correctly")
    return True


def run_all_tests():
    """Run all tests and generate report"""
    print("=" * 60)
    print("IOC Context Enrichment Cache Optimizer - Test Suite")
    print("=" * 60)

    tests = [
        test_basic_cache_functionality,
        test_force_refresh,
        test_batch_enrichment,
        test_performance_metrics,
        test_lru_eviction,
        test_ttl_expiration,
        test_thread_safety,
        test_different_ioc_types,
        test_context_manager,
    ]

    passed = 0
    failed = 0
    results = {}

    for test in tests:
        try:
            if test():
                passed += 1
                results[test.__name__] = "PASSED"
            else:
                failed += 1
                results[test.__name__] = "FAILED"
        except Exception as e:
            failed += 1
            results[test.__name__] = f"ERROR: {str(e)}"
            print(f"  ✗ FAILED with exception: {e}")

    print("\n" + "=" * 60)
    print(f"TEST SUMMARY: {passed} PASSED, {failed} FAILED")
    print("=" * 60)

    # Write test results
    test_output = {
        "timestamp": time.time(),
        "test_module": "threat_intelligence_ioc_context_enrichment_cache_optimizer",
        "passed": passed,
        "failed": failed,
        "total": passed + failed,
        "results": results
    }

    with open("/home/user/autonomous-developer/NeuralShield-AI/test_results_ioc_context_enrichment_cache_optimizer.json", "w") as f:
        json.dump(test_output, f, indent=2)

    print(f"\nTest results written to test_results_ioc_context_enrichment_cache_optimizer.json")

    return passed, failed


if __name__ == "__main__":
    passed, failed = run_all_tests()
    sys.exit(0 if failed == 0 else 1)
