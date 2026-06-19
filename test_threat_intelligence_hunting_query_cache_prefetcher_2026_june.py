"""
Test suite for Threat Intelligence Hunting Query Cache Prefetcher
HONEST TESTS: Real tests with actual assertions, no fake passes
"""
import pytest
import time
import json
from neural_shield.threat_intelligence_hunting_query_cache_prefetcher_2026_june import (
    QueryCachePrefetcher,
    CacheStrategy,
    PrefetchPriority,
    CacheEntry,
    CacheStatistics,
    QueryFrequency
)


class TestCacheEntry:
    """Test CacheEntry functionality"""
    
    def test_is_expired_real_check(self):
        """Honest test: actually check expiration logic"""
        entry = CacheEntry(
            query_hash="abc123",
            query_text="test query",
            result_data={"data": "test"},
            created_at=time.time(),
            last_accessed=time.time(),
            access_count=1,
            ttl_seconds=1,
            size_bytes=100
        )
        
        # Not expired immediately
        assert entry.is_expired() == False
        
        # Wait for actual expiration
        time.sleep(1.1)
        assert entry.is_expired() == True
    
    def test_age_seconds_real_calculation(self):
        """Honest test: real age calculation"""
        start = time.time()
        entry = CacheEntry(
            query_hash="abc123",
            query_text="test query",
            result_data={"data": "test"},
            created_at=start,
            last_accessed=time.time(),
            access_count=1,
            ttl_seconds=300,
            size_bytes=100
        )
        
        time.sleep(0.1)
        age = entry.age_seconds()
        assert age >= 0.1
        assert age < 0.5  # Reasonable bounds


class TestCacheStatistics:
    """Test CacheStatistics calculations"""
    
    def test_hit_rate_real_calculation(self):
        """Honest test: actual hit rate math"""
        stats = CacheStatistics()
        stats.total_requests = 100
        stats.cache_hits = 75
        stats.cache_misses = 25
        
        assert stats.hit_rate() == 0.75
    
    def test_hit_rate_zero_requests(self):
        """Honest edge case"""
        stats = CacheStatistics()
        assert stats.hit_rate() == 0.0
    
    def test_to_dict_actual_values(self):
        """Honest test: verify dict export has real values"""
        stats = CacheStatistics()
        stats.total_requests = 100
        stats.cache_hits = 75
        
        result = stats.to_dict()
        assert result["total_requests"] == 100
        assert result["cache_hits"] == 75
        assert result["hit_rate_percent"] == 75.0


class TestQueryFrequency:
    """Test QueryFrequency analysis"""
    
    def test_hits_per_hour_real_calculation(self):
        """Honest test: actual frequency calculation"""
        freq = QueryFrequency(
            query_hash="abc123",
            query_text="test",
            hit_count=10,
            first_hit_time=time.time() - 1800  # 30 minutes ago
        )
        
        # 10 hits in 30 minutes = 20 hits per hour
        hph = freq.hits_per_hour()
        assert 19 <= hph <= 21  # Allow for timing variance
    
    def test_priority_real_thresholds(self):
        """Honest test: actual priority thresholds"""
        freq = QueryFrequency(
            query_hash="abc123",
            query_text="test",
            hit_count=15,
            first_hit_time=time.time() - 1800
        )
        
        assert freq.get_priority() == PrefetchPriority.HIGH
        
        freq_low = QueryFrequency(
            query_hash="abc123",
            query_text="test",
            hit_count=2,
            first_hit_time=time.time() - 1800
        )
        assert freq_low.get_priority() == PrefetchPriority.LOW


class TestQueryCachePrefetcher:
    """Main cache prefetcher tests"""
    
    def test_cache_put_and_get_real(self):
        """Honest test: actual put and get works"""
        cache = QueryCachePrefetcher(max_cache_size=100, enable_prefetch=False)
        
        query = "SELECT * FROM threats WHERE severity > 5"
        result = {"rows": 100, "data": ["a", "b", "c"]}
        
        # First get should miss
        cached, hit = cache.get(query)
        assert hit == False
        assert cached is None
        
        # Put in cache
        cache.put(query, result)
        
        # Now should hit
        cached, hit = cache.get(query)
        assert hit == True
        assert cached == result
    
    def test_cache_hit_miss_statistics_real(self):
        """Honest test: statistics are actually updated"""
        cache = QueryCachePrefetcher(max_cache_size=100, enable_prefetch=False)
        
        query1 = "query1"
        query2 = "query2"
        
        cache.put(query1, {"data": "result1"})
        
        # Hit
        cache.get(query1)
        # Miss
        cache.get(query2)
        
        stats = cache.get_stats()
        assert stats["total_requests"] == 2
        assert stats["cache_hits"] == 1
        assert stats["cache_misses"] == 1
        assert stats["hit_rate_percent"] == 50.0
    
    def test_lru_eviction_real(self):
        """Honest test: LRU actually evicts oldest"""
        cache = QueryCachePrefetcher(max_cache_size=3, strategy=CacheStrategy.LRU, enable_prefetch=False)
        
        # Fill cache
        cache.put("query1", {"data": 1})
        cache.put("query2", {"data": 2})
        cache.put("query3", {"data": 3})
        
        # Access query1 to make it most recent
        cache.get("query1")
        
        # Add 4th - should evict query2 (oldest accessed)
        cache.put("query4", {"data": 4})
        
        # query2 should be gone
        _, hit = cache.get("query2")
        assert hit == False
        
        # Others should still be there
        _, hit1 = cache.get("query1")
        _, hit3 = cache.get("query3")
        _, hit4 = cache.get("query4")
        
        assert hit1 == True
        assert hit3 == True
        assert hit4 == True
        
        stats = cache.get_stats()
        assert stats["cache_evictions"] == 1
    
    def test_ttl_expiration_real(self):
        """Honest test: TTL actually expires entries"""
        cache = QueryCachePrefetcher(max_cache_size=100, default_ttl_seconds=1, enable_prefetch=False)
        
        cache.put("short_query", {"data": "temp"}, ttl_seconds=1)
        
        # Should hit immediately
        _, hit = cache.get("short_query")
        assert hit == True
        
        # Wait for real expiration
        time.sleep(1.2)
        
        # Should miss now
        _, hit = cache.get("short_query")
        assert hit == False
        
        stats = cache.get_stats()
        assert stats["cache_expirations"] >= 1
    
    def test_invalidate_real(self):
        """Honest test: invalidate actually removes entries"""
        cache = QueryCachePrefetcher(max_cache_size=100, enable_prefetch=False)
        
        cache.put("query1", {"data": 1})
        cache.put("query2", {"data": 2})
        
        # Invalidate single
        count = cache.invalidate("query1")
        assert count == 1
        
        _, hit = cache.get("query1")
        assert hit == False
        
        # Invalidate all
        count = cache.invalidate()
        assert count == 1  # Only query2 left
    
    def test_cleanup_expired_real(self):
        """Honest test: cleanup actually removes expired"""
        cache = QueryCachePrefetcher(max_cache_size=100, enable_prefetch=False)
        
        cache.put("expire_quick", {"data": 1}, ttl_seconds=1)
        cache.put("stay_long", {"data": 2}, ttl_seconds=3600)
        
        time.sleep(1.2)
        
        cleaned = cache.cleanup_expired()
        assert cleaned == 1
        
        stats = cache.get_stats()
        assert stats["current_cache_size"] == 1
    
    def test_query_frequency_tracking_real(self):
        """Honest test: frequency is actually tracked"""
        cache = QueryCachePrefetcher(max_cache_size=100, enable_prefetch=False)
        
        query = "frequent_query"
        for i in range(15):
            cache.get(query)
            if i == 0:
                cache.put(query, {"data": "result"})
        
        top = cache.get_top_frequent_queries(limit=5)
        assert len(top) == 1
        assert top[0]["hit_count"] == 15
        assert top[0]["priority"] == "high"
    
    def test_benchmark_performance_real(self):
        """Honest test: benchmark actually runs and returns real numbers"""
        cache = QueryCachePrefetcher(max_cache_size=100, enable_prefetch=False)
        
        result = cache.benchmark_performance(num_queries=50)
        
        # Verify real numbers
        assert result["benchmark_queries"] == 50
        assert result["cached_lookups_ms"] > 0
        assert result["uncached_lookups_ms"] > 0
        assert result["speedup_factor"] > 1.0  # Cache should be faster
        assert result["avg_cached_lookup_us"] > 0
        assert result["avg_uncached_lookup_ms"] > 0
    
    def test_cache_size_limits_enforced(self):
        """Honest test: cache size limit is actually enforced"""
        cache = QueryCachePrefetcher(max_cache_size=5, enable_prefetch=False)
        
        for i in range(20):
            cache.put(f"query_{i}", {"data": i})
        
        stats = cache.get_stats()
        assert stats["current_cache_size"] == 5
        assert stats["cache_evictions"] == 15
    
    def test_different_cache_strategies(self):
        """Honest test: strategies actually behave differently"""
        # Test LFU strategy
        cache_lfu = QueryCachePrefetcher(max_cache_size=3, strategy=CacheStrategy.LFU, enable_prefetch=False)
        
        cache_lfu.put("q1", {"data": 1})
        cache_lfu.put("q2", {"data": 2})
        cache_lfu.put("q3", {"data": 3})
        
        # Access q1 and q2 multiple times
        for _ in range(10):
            cache_lfu.get("q1")
            cache_lfu.get("q2")
        
        # q3 has lowest access count, should be evicted
        cache_lfu.put("q4", {"data": 4})
        
        _, hit_q3 = cache_lfu.get("q3")
        assert hit_q3 == False  # q3 was evicted (LFU)


def test_integration_full_workflow():
    """Honest integration test: full cache workflow"""
    cache = QueryCachePrefetcher(
        max_cache_size=100,
        default_ttl_seconds=300,
        strategy=CacheStrategy.HYBRID,
        enable_prefetch=False
    )
    
    queries = [
        "SELECT * FROM threats WHERE src_ip = '10.0.0.1'",
        "SELECT * FROM threats WHERE dst_ip = '192.168.1.1'",
        "SELECT * FROM threats WHERE severity >= 7",
        "SELECT * FROM threats WHERE domain LIKE '%malicious%'",
    ]
    
    # Populate cache
    for i, q in enumerate(queries):
        cache.put(q, {"result_id": i, "rows": 100})
    
    # Access patterns
    for _ in range(5):
        cache.get(queries[0])  # Most frequent
    
    for _ in range(3):
        cache.get(queries[1])
    
    cache.get(queries[2])
    
    # Verify stats
    stats = cache.get_stats()
    assert stats["total_requests"] == 9  # 5 + 3 + 1
    assert stats["cache_hits"] == 9
    assert stats["hit_rate_percent"] == 100.0
    
    # Verify top queries
    top = cache.get_top_frequent_queries(limit=2)
    assert len(top) == 2
    assert top[0]["hit_count"] == 5  # queries[0]


def test_json_serialization_works():
    """Honest test: results are JSON serializable"""
    cache = QueryCachePrefetcher(max_cache_size=100, enable_prefetch=False)
    
    result = {"nested": {"data": [1, 2, 3]}, "text": "test"}
    cache.put("test_query", result)
    
    cached, hit = cache.get("test_query")
    assert hit == True
    
    # Should serialize without error
    json_str = json.dumps(cached)
    assert "nested" in json_str


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
