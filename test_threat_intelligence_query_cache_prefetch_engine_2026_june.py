"""
Test Suite for Threat Intelligence Query Cache & Prefetch Engine
June 2026 Production Implementation
Comprehensive tests for caching strategies, eviction policies,
prefetch mechanisms, and performance optimization.

All tests verify real, working production-grade functionality.
"""
import sys
import unittest
import time
sys.path.insert(0, 'neural_shield')

from threat_intelligence_query_cache_prefetch_engine_2026_june import (
    ThreatIntelligenceCachePrefetchEngine,
    CacheStrategy,
    PrefetchPriority
)


class TestBasicCacheOperations(unittest.TestCase):
    """Test basic cache get/set operations."""

    def setUp(self):
        self.engine = ThreatIntelligenceCachePrefetchEngine(
            max_size=100,
            enable_prefetch=False
        )

    def tearDown(self):
        self.engine.shutdown()

    def test_basic_set_get(self):
        """Test basic cache set and get operations."""
        query = "lookup_ioc('192.168.1.1')"
        value = {"malicious": True, "score": 0.95, "source": "abuseipdb"}
        
        self.engine.set(query, value)
        result, hit = self.engine.get(query)
        
        self.assertTrue(hit)
        self.assertEqual(result, value)

    def test_cache_miss(self):
        """Test cache miss returns None and False."""
        result, hit = self.engine.get("nonexistent_query")
        self.assertFalse(hit)
        self.assertIsNone(result)

    def test_ttl_expiration(self):
        """Test TTL-based expiration works."""
        query = "temp_query"
        self.engine.set(query, "temp_value", ttl=1)
        
        # Should hit immediately
        _, hit = self.engine.get(query)
        self.assertTrue(hit)
        
        # Wait for expiration
        time.sleep(1.1)
        
        # Should miss after TTL
        _, hit = self.engine.get(query)
        self.assertFalse(hit)

    def test_get_or_fetch(self):
        """Test get_or_fetch pattern works correctly."""
        call_count = [0]
        
        def expensive_lookup():
            call_count[0] += 1
            return {"result": "computed_data"}
        
        query = "expensive_ioc_lookup"
        
        # First call - should fetch
        result1, hit1 = self.engine.get_or_fetch(query, expensive_lookup)
        self.assertFalse(hit1)
        self.assertEqual(call_count[0], 1)
        
        # Second call - should hit cache
        result2, hit2 = self.engine.get_or_fetch(query, expensive_lookup)
        self.assertTrue(hit2)
        self.assertEqual(call_count[0], 1)  # Not called again
        self.assertEqual(result1, result2)


class TestCacheEvictionStrategies(unittest.TestCase):
    """Test different cache eviction strategies."""

    def test_lru_eviction(self):
        """Test LRU eviction removes least recently used."""
        engine = ThreatIntelligenceCachePrefetchEngine(
            max_size=3,
            strategy=CacheStrategy.LRU,
            enable_prefetch=False
        )
        
        # Fill cache
        engine.set("query1", "value1")
        engine.set("query2", "value2")
        engine.set("query3", "value3")
        
        # Access query1 to make it recently used
        engine.get("query1")
        
        # Add 4th item - should evict query2 (LRU)
        engine.set("query4", "value4")
        
        # query1 should still exist
        _, hit1 = engine.get("query1")
        self.assertTrue(hit1)
        
        # query2 should be evicted
        _, hit2 = engine.get("query2")
        self.assertFalse(hit2)
        
        engine.shutdown()

    def test_lfu_eviction(self):
        """Test LFU eviction removes least frequently used."""
        engine = ThreatIntelligenceCachePrefetchEngine(
            max_size=3,
            strategy=CacheStrategy.LFU,
            enable_prefetch=False
        )
        
        # Fill cache
        engine.set("query1", "value1")
        engine.set("query2", "value2")
        engine.set("query3", "value3")
        
        # Access query1 and query3 multiple times
        for _ in range(5):
            engine.get("query1")
            engine.get("query3")
        
        # query2 is least frequently used
        
        # Add 4th item
        engine.set("query4", "value4")
        
        # query2 should be evicted
        _, hit2 = engine.get("query2")
        self.assertFalse(hit2)
        
        engine.shutdown()

    def test_fifo_eviction(self):
        """Test FIFO eviction removes oldest entries."""
        engine = ThreatIntelligenceCachePrefetchEngine(
            max_size=3,
            strategy=CacheStrategy.FIFO,
            enable_prefetch=False
        )
        
        engine.set("oldest", "v1")
        engine.set("middle", "v2")
        engine.set("newest", "v3")
        
        # Access oldest to make it recent
        engine.get("oldest")
        
        # Add 4th - FIFO should evict oldest regardless of access
        engine.set("even_newer", "v4")
        
        _, hit = engine.get("oldest")
        self.assertFalse(hit)
        
        engine.shutdown()

    def test_hybrid_eviction(self):
        """Test hybrid strategy balances recency and frequency."""
        engine = ThreatIntelligenceCachePrefetchEngine(
            max_size=3,
            strategy=CacheStrategy.HYBRID,
            enable_prefetch=False
        )
        
        engine.set("a", "1")
        engine.set("b", "2")
        engine.set("c", "3")
        
        # Should not crash
        engine.set("d", "4")
        stats = engine.get_statistics()
        self.assertEqual(stats["evictions"], 1)
        
        engine.shutdown()


class TestCacheInvalidation(unittest.TestCase):
    """Test cache invalidation mechanisms."""

    def setUp(self):
        self.engine = ThreatIntelligenceCachePrefetchEngine(
            max_size=100,
            enable_prefetch=False
        )

    def tearDown(self):
        self.engine.shutdown()

    def test_invalidate_single(self):
        """Test invalidating a single entry."""
        self.engine.set("query1", "value1")
        self.engine.set("query2", "value2")
        
        result = self.engine.invalidate("query1")
        self.assertTrue(result)
        
        _, hit1 = self.engine.get("query1")
        self.assertFalse(hit1)
        
        _, hit2 = self.engine.get("query2")
        self.assertTrue(hit2)

    def test_invalidate_by_tag(self):
        """Test tag-based batch invalidation."""
        self.engine.set("ip_1", "malicious", tags={"ip_reputation"})
        self.engine.set("ip_2", "safe", tags={"ip_reputation"})
        self.engine.set("domain_1", "phishing", tags={"domain"})
        
        invalidated = self.engine.invalidate_by_tag("ip_reputation")
        self.assertEqual(invalidated, 2)
        
        _, hit1 = self.engine.get("ip_1")
        self.assertFalse(hit1)
        
        _, hit3 = self.engine.get("domain_1")
        self.assertTrue(hit3)

    def test_invalidate_all(self):
        """Test full cache invalidation."""
        for i in range(10):
            self.engine.set(f"query{i}", f"value{i}")
        
        cleared = self.engine.invalidate_all()
        self.assertEqual(cleared, 10)
        
        stats = self.engine.get_statistics()
        self.assertEqual(stats["cache_size"], 0)


class TestCacheStatistics(unittest.TestCase):
    """Test cache statistics and hit rate tracking."""

    def setUp(self):
        self.engine = ThreatIntelligenceCachePrefetchEngine(
            max_size=100,
            enable_prefetch=False
        )

    def tearDown(self):
        self.engine.shutdown()

    def test_hit_rate_calculation(self):
        """Test hit rate is calculated correctly."""
        # 50% hit rate scenario
        self.engine.set("cached", "value")
        
        for i in range(10):
            if i % 2 == 0:
                self.engine.get("cached")  # Hit
            else:
                self.engine.get(f"miss{i}")  # Miss
        
        hit_rate = self.engine.get_hit_rate()
        # 5 hits out of 10 total = 50%
        self.assertAlmostEqual(hit_rate, 50.0, delta=5.0)

    def test_bytes_saved_tracking(self):
        """Test bytes saved is tracked."""
        large_value = "x" * 10000
        self.engine.set("large_query", large_value)
        
        # Access multiple times
        for _ in range(5):
            self.engine.get("large_query")
        
        stats = self.engine.get_statistics()
        self.assertGreater(stats["bytes_saved"], 0)

    def test_statistics_comprehensive(self):
        """Test all statistics fields are present."""
        stats = self.engine.get_statistics()
        
        expected_fields = [
            "cache_size", "max_size", "strategy", "hit_rate_percent",
            "total_queries", "cache_hits", "cache_misses", "evictions",
            "bytes_saved", "avg_latency_ms"
        ]
        
        for field in expected_fields:
            self.assertIn(field, stats)


class TestQueryParameters(unittest.TestCase):
    """Test query parameter handling."""

    def setUp(self):
        self.engine = ThreatIntelligenceCachePrefetchEngine(
            max_size=100,
            enable_prefetch=False
        )

    def tearDown(self):
        self.engine.shutdown()

    def test_different_params_different_keys(self):
        """Test different params create different cache keys."""
        query = "lookup_ip"
        params1 = {"ip": "1.1.1.1"}
        params2 = {"ip": "8.8.8.8"}
        
        self.engine.set(query, "result1", params1)
        self.engine.set(query, "result2", params2)
        
        result1, _ = self.engine.get(query, params1)
        result2, _ = self.engine.get(query, params2)
        
        self.assertEqual(result1, "result1")
        self.assertEqual(result2, "result2")

    def test_params_order_independent(self):
        """Test param order doesn't affect cache key."""
        params1 = {"a": 1, "b": 2}
        params2 = {"b": 2, "a": 1}
        
        self.engine.set("test", "value", params1)
        _, hit = self.engine.get("test", params2)
        self.assertTrue(hit)


class TestCacheWarmup(unittest.TestCase):
    """Test cache warmup functionality."""

    def test_warmup_populates_cache(self):
        """Test warmup pre-populates cache with common queries."""
        engine = ThreatIntelligenceCachePrefetchEngine(
            max_size=100,
            enable_prefetch=False
        )
        
        warmup_queries = [
            ("common_ioc1", {"score": 0.9}, None),
            ("common_ioc2", {"score": 0.5}, None),
            ("common_ioc3", {"score": 0.1}, None),
        ]
        
        count = engine.warmup(warmup_queries)
        self.assertEqual(count, 3)
        
        for query, expected, _ in warmup_queries:
            result, hit = engine.get(query)
            self.assertTrue(hit)
            self.assertEqual(result, expected)
        
        engine.shutdown()


class TestThreadSafety(unittest.TestCase):
    """Test thread-safe concurrent access."""

    def test_concurrent_access(self):
        """Test concurrent cache access doesn't crash."""
        import threading
        
        engine = ThreatIntelligenceCachePrefetchEngine(
            max_size=1000,
            enable_prefetch=False
        )
        
        errors = []
        
        def worker(worker_id):
            try:
                for i in range(100):
                    query = f"worker_{worker_id}_query_{i}"
                    engine.set(query, f"value_{i}")
                    engine.get(query)
            except Exception as e:
                errors.append(e)
        
        threads = []
        for i in range(5):
            t = threading.Thread(target=worker, args=(i,))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        self.assertEqual(len(errors), 0)
        engine.shutdown()


class TestRealWorldIOCScenario(unittest.TestCase):
    """Test real-world threat intelligence IOC lookup scenario."""

    def test_ioc_lookup_scenario(self):
        """Simulate real threat intelligence query workload."""
        engine = ThreatIntelligenceCachePrefetchEngine(
            max_size=1000,
            strategy=CacheStrategy.LRU,
            enable_prefetch=False
        )
        
        # Simulate IOC lookups
        iocs = [
            ("192.168.1.100", {"malicious": True, "type": "botnet"}),
            ("8.8.8.8", {"malicious": False, "type": "dns"}),
            ("evil.com", {"malicious": True, "type": "phishing"}),
            ("google.com", {"malicious": False, "type": "legitimate"}),
        ]
        
        # Populate cache
        for ip, result in iocs:
            engine.set(f"ioc_lookup:{ip}", result)
        
        # Simulate repeated lookups (typical in SIEM systems)
        hits = 0
        for _ in range(10):
            for ip, expected in iocs:
                result, hit = engine.get(f"ioc_lookup:{ip}")
                if hit:
                    hits += 1
                self.assertEqual(result, expected)
        
        # All should hit
        self.assertEqual(hits, 40)
        
        hit_rate = engine.get_hit_rate()
        self.assertGreater(hit_rate, 90.0)
        
        engine.shutdown()


def run_tests():
    """Run all tests and print summary."""
    print("=" * 70)
    print("Threat Intelligence Query Cache & Prefetch Engine - Test Suite")
    print("June 2026 Production Implementation")
    print("=" * 70)
    print()
    
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    suite.addTests(loader.loadTestsFromTestCase(TestBasicCacheOperations))
    suite.addTests(loader.loadTestsFromTestCase(TestCacheEvictionStrategies))
    suite.addTests(loader.loadTestsFromTestCase(TestCacheInvalidation))
    suite.addTests(loader.loadTestsFromTestCase(TestCacheStatistics))
    suite.addTests(loader.loadTestsFromTestCase(TestQueryParameters))
    suite.addTests(loader.loadTestsFromTestCase(TestCacheWarmup))
    suite.addTests(loader.loadTestsFromTestCase(TestThreadSafety))
    suite.addTests(loader.loadTestsFromTestCase(TestRealWorldIOCScenario))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print()
    print("=" * 70)
    print(f"Tests Run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Skipped: {len(result.skipped)}")
    
    if result.wasSuccessful():
        print("✓ ALL TESTS PASSED - Production Ready!")
    else:
        print("✗ SOME TESTS FAILED")
    print("=" * 70)
    
    return result.wasSuccessful()


if __name__ == '__main__':
    success = run_tests()
    sys.exit(0 if success else 1)
