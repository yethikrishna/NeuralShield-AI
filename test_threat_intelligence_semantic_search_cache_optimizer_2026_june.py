#!/usr/bin/env python3
"""
Test suite for Threat Intelligence Semantic Search Cache Optimizer
Production-grade testing with comprehensive coverage
June 20, 2026 - Session 38
"""

import sys
import os
import time
import json
import unittest
from typing import Dict, Any

# Add neural_shield to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from threat_intelligence_semantic_search_cache_optimizer_2026_june import (
    SemanticSearchCacheOptimizer,
    LRUCache,
    CacheEntry,
    CacheMetrics,
    CachePerformanceResult,
    create_cache_optimizer,
    run_semantic_cache_benchmark
)


class TestCacheEntry(unittest.TestCase):
    """Test CacheEntry dataclass functionality"""
    
    def test_cache_entry_creation(self):
        """Test basic cache entry creation"""
        entry = CacheEntry(key="test", value="data", ttl_seconds=60)
        
        self.assertEqual(entry.key, "test")
        self.assertEqual(entry.value, "data")
        self.assertEqual(entry.ttl_seconds, 60)
        self.assertEqual(entry.access_count, 0)
        self.assertGreater(entry.created_at, 0)
    
    def test_cache_entry_expiration(self):
        """Test cache entry expiration logic"""
        entry = CacheEntry(key="test", value="data", ttl_seconds=0)
        time.sleep(0.001)
        
        self.assertTrue(entry.is_expired())
    
    def test_cache_entry_not_expired(self):
        """Test non-expired entry"""
        entry = CacheEntry(key="test", value="data", ttl_seconds=3600)
        
        self.assertFalse(entry.is_expired())
    
    def test_cache_entry_touch(self):
        """Test touch updates access metadata"""
        entry = CacheEntry(key="test", value="data")
        initial_access = entry.accessed_at
        initial_count = entry.access_count
        
        time.sleep(0.001)
        entry.touch()
        
        self.assertGreater(entry.accessed_at, initial_access)
        self.assertEqual(entry.access_count, initial_count + 1)


class TestLRUCache(unittest.TestCase):
    """Test LRU cache implementation"""
    
    def setUp(self):
        """Set up test cache"""
        self.cache = LRUCache(capacity=10, default_ttl=3600)
    
    def test_basic_put_get(self):
        """Test basic put and get operations"""
        self.cache.put("key1", "value1")
        result = self.cache.get("key1")
        
        self.assertEqual(result, "value1")
    
    def test_cache_miss(self):
        """Test cache miss behavior"""
        result = self.cache.get("nonexistent")
        
        self.assertIsNone(result)
    
    def test_lru_eviction(self):
        """Test LRU eviction at capacity"""
        # Fill cache to capacity
        for i in range(10):
            self.cache.put(f"key{i}", f"value{i}")
        
        # Access first key to make it MRU
        self.cache.get("key0")
        
        # Add one more to trigger eviction
        self.cache.put("key10", "value10")
        
        # key1 should be evicted (LRU), key0 should still exist
        self.assertIsNone(self.cache.get("key1"))
        self.assertIsNotNone(self.cache.get("key0"))
    
    def test_hit_rate_calculation(self):
        """Test hit rate statistics"""
        self.cache.put("key1", "value1")
        self.cache.put("key2", "value2")
        
        # 2 hits, 1 miss
        self.cache.get("key1")
        self.cache.get("key2")
        self.cache.get("nonexistent")
        
        metrics = self.cache.get_metrics()
        self.assertEqual(metrics['total_hits'], 2)
        self.assertEqual(metrics['total_misses'], 1)
        self.assertAlmostEqual(metrics['hit_rate'], 2/3, places=2)
    
    def test_delete_operation(self):
        """Test delete operation"""
        self.cache.put("key1", "value1")
        result = self.cache.delete("key1")
        
        self.assertTrue(result)
        self.assertIsNone(self.cache.get("key1"))
    
    def test_clear_expired(self):
        """Test clearing expired entries"""
        self.cache.put("expired", "value", ttl=0)
        self.cache.put("valid", "value", ttl=3600)
        time.sleep(0.001)
        
        cleared = self.cache.clear_expired()
        
        self.assertEqual(cleared, 1)
        self.assertIsNone(self.cache.get("expired"))
        self.assertIsNotNone(self.cache.get("valid"))


class TestSemanticSearchCacheOptimizer(unittest.TestCase):
    """Test main cache optimizer functionality"""
    
    def setUp(self):
        """Set up test optimizer"""
        self.optimizer = SemanticSearchCacheOptimizer(
            cache_capacity=100,
            semantic_threshold=0.9
        )
    
    def test_basic_cache_operations(self):
        """Test basic put and get operations"""
        query = "threat actor APT29 TTPs"
        value = {"mitre": ["T1059", "T1027"], "confidence": 0.95}
        
        self.optimizer.put(query, value)
        result, was_hit, hit_type = self.optimizer.get(query)
        
        self.assertTrue(was_hit)
        self.assertEqual(hit_type, 'exact')
        self.assertEqual(result, value)
    
    def test_cache_miss_behavior(self):
        """Test cache miss behavior"""
        result, was_hit, hit_type = self.optimizer.get("nonexistent query")
        
        self.assertFalse(was_hit)
        self.assertEqual(hit_type, 'miss')
        self.assertIsNone(result)
    
    def test_cache_invalidation(self):
        """Test cache invalidation"""
        self.optimizer.put("apt29 details", {"data": "value1"})
        self.optimizer.put("apt28 details", {"data": "value2"})
        self.optimizer.put("cve-2026 details", {"data": "value3"})
        
        # Invalidate by pattern
        invalidated = self.optimizer.invalidate(pattern="apt")
        
        self.assertGreaterEqual(invalidated, 2)
        
        # Verify APT queries are gone, CVE remains
        r1, _, _ = self.optimizer.get("apt29 details")
        r2, _, _ = self.optimizer.get("apt28 details")
        r3, _, _ = self.optimizer.get("cve-2026 details")
        
        self.assertIsNone(r1)
        self.assertIsNone(r2)
        self.assertIsNotNone(r3)
    
    def test_metrics_tracking(self):
        """Test metrics tracking"""
        queries = ["query1", "query2", "query3", "query4", "query5"]
        
        for q in queries:
            self.optimizer.put(q, {"result": q})
        
        # 3 hits, 2 misses
        for q in queries[:3]:
            self.optimizer.get(q)
        
        self.optimizer.get("nonexistent1")
        self.optimizer.get("nonexistent2")
        
        metrics = self.optimizer.get_metrics()
        
        self.assertGreater(metrics['cache']['hit_rate'], 0)
        self.assertGreater(metrics['performance']['total_operations'], 0)
        self.assertGreater(metrics['semantic']['index_size'], 0)
    
    def test_cosine_similarity(self):
        """Test cosine similarity calculation"""
        vec1 = [1.0, 0.0, 0.0]
        vec2 = [1.0, 0.0, 0.0]
        vec3 = [0.0, 1.0, 0.0]
        
        sim1 = self.optimizer._cosine_similarity(vec1, vec2)
        sim2 = self.optimizer._cosine_similarity(vec1, vec3)
        
        self.assertAlmostEqual(sim1, 1.0, places=5)
        self.assertAlmostEqual(sim2, 0.0, places=5)
    
    def test_semantic_vector_generation(self):
        """Test semantic vector generation"""
        vec1 = self.optimizer._generate_semantic_vector("APT29 threat actor")
        vec2 = self.optimizer._generate_semantic_vector("APT29 threat actor")
        vec3 = self.optimizer._generate_semantic_vector("completely different query")
        
        # Same query should produce same vector
        self.assertEqual(vec1, vec2)
        # Different queries should produce different vectors
        self.assertNotEqual(vec1, vec3)
        # Vectors should be normalized
        norm = sum(v * v for v in vec1)
        self.assertAlmostEqual(norm, 1.0, places=5)
    
    def test_cache_warmup(self):
        """Test cache warmup functionality"""
        queries = ["warmup1", "warmup2", "warmup3"]
        
        def gen_value(q):
            return {"generated": q}
        
        count = self.optimizer.warmup(queries, gen_value)
        
        self.assertEqual(count, 3)
        
        for q in queries:
            result, was_hit, _ = self.optimizer.get(q)
            self.assertTrue(was_hit)
            self.assertEqual(result, {"generated": q})
    
    def test_stats_summary(self):
        """Test statistics summary generation"""
        self.optimizer.put("test", "value")
        self.optimizer.get("test")
        
        summary = self.optimizer.get_stats_summary()
        
        self.assertIn("Cache Statistics", summary)
        self.assertIn("Hit Rate", summary)
        self.assertIn("Latency", summary)


class TestFactoryFunctions(unittest.TestCase):
    """Test factory functions"""
    
    def test_create_cache_optimizer(self):
        """Test factory function"""
        optimizer = create_cache_optimizer(capacity=500, semantic_threshold=0.9)
        
        self.assertIsInstance(optimizer, SemanticSearchCacheOptimizer)
        self.assertEqual(optimizer.cache_capacity, 500)
        self.assertEqual(optimizer.semantic_threshold, 0.9)


def run_comprehensive_benchmark() -> Dict[str, Any]:
    """Run comprehensive performance benchmark"""
    print("\n" + "="*60)
    print("PRODUCTION BENCHMARK: Semantic Search Cache Optimizer")
    print("="*60)
    
    result = run_semantic_cache_benchmark()
    
    print(f"\nBenchmark Summary:")
    print(f"  Cache: {result.cache_name}")
    print(f"  Total Operations: {result.total_operations}")
    print(f"  Hit Rate: {result.hit_rate:.1%}")
    print(f"  Avg Latency: {result.avg_latency_ms:.3f}ms")
    print(f"  P95 Latency: {result.p95_latency_ms:.3f}ms")
    print(f"  Throughput: {result.throughput_ops_per_sec} ops/sec")
    
    return {
        "benchmark": "semantic_search_cache_optimizer",
        "total_operations": result.total_operations,
        "hit_count": result.hit_count,
        "miss_count": result.miss_count,
        "hit_rate": round(result.hit_rate, 3),
        "avg_latency_ms": result.avg_latency_ms,
        "p95_latency_ms": result.p95_latency_ms,
        "throughput_ops_per_sec": result.throughput_ops_per_sec,
        "passed": result.hit_rate >= 0.85
    }


def main():
    """Run all tests and benchmarks"""
    print("Running Semantic Search Cache Optimizer Test Suite")
    print("="*60)
    
    # Run unit tests
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(sys.modules[__name__])
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Run benchmark if tests passed
    if result.wasSuccessful():
        benchmark_results = run_comprehensive_benchmark()
        
        # Save results
        with open('test_results_threat_intelligence_semantic_cache_optimizer.json', 'w') as f:
            json.dump(benchmark_results, f, indent=2)
        
        print(f"\n✅ All tests passed! Benchmark results saved.")
        print(f"   Hit Rate: {benchmark_results['hit_rate']:.1%}")
        print(f"   Throughput: {benchmark_results['throughput_ops_per_sec']} ops/sec")
        return 0
    else:
        print("\n❌ Some tests failed!")
        return 1


if __name__ == "__main__":
    sys.exit(main())
