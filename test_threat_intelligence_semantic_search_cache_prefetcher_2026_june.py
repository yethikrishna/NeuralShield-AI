#!/usr/bin/env python3
"""
Test Suite for Threat Intelligence Semantic Search Cache Prefetcher
NeuralShield-AI - Production Grade Testing

Runs comprehensive tests including:
- Basic cache operations
- Pattern learning and prediction
- Semantic similarity detection
- Adaptive TTL functionality
- Performance metrics
- Thread safety
"""
import json
import time
import sys
import threading
from typing import Any

# Add module path
sys.path.insert(0, '/home/user/autonomous-developer/NeuralShield-AI')

from neural_shield.threat_intelligence_semantic_search_cache_prefetcher_2026_june import (
    ThreatIntelSemanticCachePrefetcher,
    PrefetchConfig,
    QueryCategory,
    SimpleSemanticHasher
)


def mock_lookup_callback(query: str, category: QueryCategory) -> Any:
    """Mock lookup callback for testing"""
    time.sleep(0.01)  # Simulate lookup latency
    return {
        "query": query,
        "category": category.value,
        "results": [f"result_{i}" for i in range(5)],
        "confidence": 0.85,
        "timestamp": time.time()
    }


def run_tests():
    """Run all tests and generate results"""
    print("=" * 70)
    print("Threat Intelligence Semantic Search Cache Prefetcher - Test Suite")
    print("=" * 70)
    
    test_results = {
        "test_timestamp": time.time(),
        "test_module": "threat_intelligence_semantic_search_cache_prefetcher_2026_june",
        "passed": [],
        "failed": [],
        "performance_metrics": {}
    }
    
    # Test 1: Basic initialization
    print("\n[TEST 1] Basic Initialization")
    try:
        config = PrefetchConfig(max_cache_size=100)
        prefetcher = ThreatIntelSemanticCachePrefetcher(config=config)
        info = prefetcher.get_cache_info()
        assert info["cache_size"] == 0
        assert info["max_cache_size"] == 100
        print("  ✓ Initialization successful")
        test_results["passed"].append("basic_initialization")
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        test_results["failed"].append(f"basic_initialization: {str(e)}")
    
    # Test 2: Store and lookup
    print("\n[TEST 2] Store and Lookup Operations")
    try:
        prefetcher = ThreatIntelSemanticCachePrefetcher()
        
        # Store a result
        query = "CVE-2026-1234 vulnerability details"
        result_data = {"cve": "CVE-2026-1234", "severity": "critical", "score": 9.8}
        prefetcher.store(query, result_data)
        
        # Lookup should find it
        result, was_cached = prefetcher.lookup(query)
        assert was_cached == True
        assert result is not None
        assert result["cve"] == "CVE-2026-1234"
        
        stats = prefetcher.get_statistics()
        assert stats.cache_hits >= 1
        
        print("  ✓ Store and lookup successful")
        test_results["passed"].append("store_lookup")
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        test_results["failed"].append(f"store_lookup: {str(e)}")
    
    # Test 3: Cache miss handling
    print("\n[TEST 3] Cache Miss Handling")
    try:
        prefetcher = ThreatIntelSemanticCachePrefetcher()
        result, was_cached = prefetcher.lookup("completely unknown query 12345")
        assert was_cached == False
        assert result is None
        
        stats = prefetcher.get_statistics()
        assert stats.cache_misses >= 1
        
        print("  ✓ Cache miss handling correct")
        test_results["passed"].append("cache_miss")
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        test_results["failed"].append(f"cache_miss: {str(e)}")
    
    # Test 4: Query categorization
    print("\n[TEST 4] Query Categorization")
    try:
        prefetcher = ThreatIntelSemanticCachePrefetcher()
        
        test_queries = [
            ("ip: 192.168.1.1 lookup", QueryCategory.IOC_LOOKUP),
            ("CVE-2026-9999 exploit details", QueryCategory.CVE_SEARCH),
            ("APT29 threat actor campaign", QueryCategory.THREAT_ACTOR),
            ("ransomware encryption analysis", QueryCategory.MALWARE_ANALYSIS),
            ("MITRE T1059 technique", QueryCategory.MITRE_TECHNIQUE),
        ]
        
        for query, expected_cat in test_queries:
            prefetcher.store(query, {"test": "data"})
            prefetcher.lookup(query)
        
        dist = prefetcher.get_category_distribution()
        assert len(dist) > 0
        
        print("  ✓ Query categorization working")
        test_results["passed"].append("query_categorization")
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        test_results["failed"].append(f"query_categorization: {str(e)}")
    
    # Test 5: Semantic hashing and similarity
    print("\n[TEST 5] Semantic Hashing & Similarity")
    try:
        hasher = SimpleSemanticHasher()
        
        # Similar queries should have high similarity
        hash1 = hasher.compute_hash("CVE-2026-1234 vulnerability details")
        hash2 = hasher.compute_hash("CVE-2026-1234 vulnerability exploit details")
        hash3 = hasher.compute_hash("completely different query here")
        
        sim1 = hasher.compute_similarity(hash1, hash2)
        sim2 = hasher.compute_similarity(hash1, hash3)
        
        assert sim1 > sim2  # Similar queries should be more similar
        
        print("  ✓ Semantic hashing working correctly")
        test_results["passed"].append("semantic_hashing")
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        test_results["failed"].append(f"semantic_hashing: {str(e)}")
    
    # Test 6: Pattern learning
    print("\n[TEST 6] Pattern Learning")
    try:
        prefetcher = ThreatIntelSemanticCachePrefetcher()
        
        # Access same query multiple times
        query = "CVE-2026-5555 vulnerability assessment"
        for i in range(5):
            prefetcher.store(query, {"data": f"result_{i}"})
            prefetcher.lookup(query)
        
        top_patterns = prefetcher.get_top_patterns(limit=5)
        assert len(top_patterns) > 0
        assert top_patterns[0]["frequency"] >= 5
        
        print("  ✓ Pattern learning successful")
        test_results["passed"].append("pattern_learning")
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        test_results["failed"].append(f"pattern_learning: {str(e)}")
    
    # Test 7: Statistics tracking
    print("\n[TEST 7] Statistics Tracking")
    try:
        prefetcher = ThreatIntelSemanticCachePrefetcher()
        
        # Generate some activity
        queries = [
            "CVE-2026-1001 details",
            "CVE-2026-1002 patch",
            "ip: 10.0.0.1 malicious",
            "APT group analysis"
        ]
        
        for q in queries:
            prefetcher.store(q, {"test": True})
            prefetcher.lookup(q)
        
        stats = prefetcher.get_statistics()
        assert stats.total_queries == len(queries)
        assert stats.cache_hits == len(queries)
        assert stats.hit_rate_percent == 100.0
        
        print("  ✓ Statistics tracking accurate")
        test_results["passed"].append("statistics_tracking")
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        test_results["failed"].append(f"statistics_tracking: {str(e)}")
    
    # Test 8: Semantic similarity lookup
    print("\n[TEST 8] Semantic Similar Queries")
    try:
        prefetcher = ThreatIntelSemanticCachePrefetcher()
        
        # Store similar queries
        prefetcher.store("CVE-2026-1234 vulnerability details", {"data": 1})
        prefetcher.store("CVE-2026-1234 exploit analysis", {"data": 2})
        prefetcher.store("totally unrelated query", {"data": 3})
        
        similar = prefetcher.get_semantically_similar(
            "CVE-2026-1234 vulnerability exploit", 
            limit=5
        )
        
        assert len(similar) > 0
        
        print("  ✓ Semantic similarity lookup working")
        test_results["passed"].append("semantic_similarity")
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        test_results["failed"].append(f"semantic_similarity: {str(e)}")
    
    # Test 9: Clear functionality
    print("\n[TEST 9] Clear Functionality")
    try:
        prefetcher = ThreatIntelSemanticCachePrefetcher()
        prefetcher.store("test query", {"data": True})
        prefetcher.lookup("test query")
        
        prefetcher.clear()
        info = prefetcher.get_cache_info()
        
        assert info["cache_size"] == 0
        assert info["learned_patterns"] == 0
        
        print("  ✓ Clear functionality working")
        test_results["passed"].append("clear_functionality")
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        test_results["failed"].append(f"clear_functionality: {str(e)}")
    
    # Test 10: Thread safety basic
    print("\n[TEST 10] Thread Safety")
    try:
        prefetcher = ThreatIntelSemanticCachePrefetcher()
        errors = []
        
        def worker(thread_id):
            try:
                for i in range(10):
                    q = f"thread_{thread_id}_query_{i}"
                    prefetcher.store(q, {"thread": thread_id})
                    prefetcher.lookup(q)
            except Exception as e:
                errors.append(str(e))
        
        threads = [threading.Thread(target=worker, args=(i,)) for i in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert len(errors) == 0
        
        print("  ✓ Thread safety verified")
        test_results["passed"].append("thread_safety")
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        test_results["failed"].append(f"thread_safety: {str(e)}")
    
    # Performance metrics
    print("\n" + "=" * 70)
    print("PERFORMANCE METRICS")
    print("=" * 70)
    
    # Benchmark lookup speed
    prefetcher = ThreatIntelSemanticCachePrefetcher()
    for i in range(100):
        prefetcher.store(f"benchmark_query_{i}", {"data": i})
    
    start = time.time()
    for i in range(100):
        prefetcher.lookup(f"benchmark_query_{i}")
    lookup_time = (time.time() - start) * 1000
    
    test_results["performance_metrics"] = {
        "avg_lookup_ms": round(lookup_time / 100, 4),
        "total_lookups_100_ms": round(lookup_time, 2),
        "cache_capacity": 5000
    }
    
    print(f"  Average lookup time: {test_results['performance_metrics']['avg_lookup_ms']} ms")
    print(f"  100 lookups total: {test_results['performance_metrics']['total_lookups_100_ms']} ms")
    
    # Final summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    print(f"  Passed: {len(test_results['passed'])}")
    print(f"  Failed: {len(test_results['failed'])}")
    print(f"  Success Rate: {round(len(test_results['passed']) / (len(test_results['passed']) + len(test_results['failed'])) * 100, 1)}%")
    
    if test_results["failed"]:
        print("\n  Failed tests:")
        for f in test_results["failed"]:
            print(f"    - {f}")
    
    # Save results
    with open('/home/user/autonomous-developer/NeuralShield-AI/test_results_threat_intelligence_semantic_search_cache_prefetcher.json', 'w') as f:
        json.dump(test_results, f, indent=2)
    
    print(f"\n  Results saved to: test_results_threat_intelligence_semantic_search_cache_prefetcher.json")
    
    return test_results


if __name__ == "__main__":
    results = run_tests()
    sys.exit(0 if len(results["failed"]) == 0 else 1)
