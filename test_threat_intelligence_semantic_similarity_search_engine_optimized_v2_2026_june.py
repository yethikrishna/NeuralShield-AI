#!/usr/bin/env python3
"""
Test Suite for Threat Intelligence Semantic Similarity Search Engine V2
Production-grade validation tests
"""

import json
import sys
import time

sys.path.insert(0, '/home/user/autonomous-developer/NeuralShield-AI')

from neural_shield.threat_intelligence_semantic_similarity_search_engine_optimized_v2_2026_june import (
    SemanticSimilaritySearchEngineV2,
    LRUCache,
    VectorProcessor,
    search_engine_v2
)


def run_test(test_name, test_func):
    """Run a test and report results"""
    print(f"\n{'='*60}")
    print(f"TEST: {test_name}")
    print('='*60)
    try:
        result = test_func()
        print(f"✓ PASSED: {test_name}")
        return result
    except Exception as e:
        print(f"✗ FAILED: {test_name}")
        print(f"  Error: {str(e)}")
        import traceback
        traceback.print_exc()
        return None


def test_lru_cache_basic():
    """Test LRU Cache basic functionality"""
    cache = LRUCache(capacity=3, ttl_seconds=10)
    
    cache.put("key1", "value1")
    cache.put("key2", "value2")
    cache.put("key3", "value3")
    
    assert cache.get("key1") == "value1"
    assert cache.get("key2") == "value2"
    assert cache.get("key3") == "value3"
    assert cache.size() == 3
    
    # Test eviction
    cache.put("key4", "value4")
    assert cache.get("key1") is None  # Evicted
    assert cache.get("key4") == "value4"
    
    print("  - Cache put/get works")
    print("  - LRU eviction works")
    return True


def test_lru_cache_ttl():
    """Test LRU Cache TTL expiration"""
    cache = LRUCache(capacity=10, ttl_seconds=1)
    
    cache.put("temp_key", "temp_value")
    assert cache.get("temp_key") == "temp_value"
    
    time.sleep(1.1)
    assert cache.get("temp_key") is None
    
    print("  - TTL expiration works")
    return True


def test_vector_processor():
    """Test Vector Processor functionality"""
    vp = VectorProcessor(vector_dim=128)
    
    vec1 = vp.compute_vector("ransomware attack")
    vec2 = vp.compute_vector("ransomware attack")
    vec3 = vp.compute_vector("phishing email")
    
    assert len(vec1) == 128
    assert vec1 == vec2  # Deterministic
    assert vec1 != vec3  # Different inputs
    
    sim = VectorProcessor.cosine_similarity(vec1, vec2)
    assert abs(sim - 1.0) < 0.001  # Same vectors
    
    sim_diff = VectorProcessor.cosine_similarity(vec1, vec3)
    assert sim_diff < 0.9  # Different vectors should have lower similarity
    
    print("  - Vector computation is deterministic")
    print("  - Cosine similarity works correctly")
    return True


def test_vector_batch_processing():
    """Test batch vector computation"""
    vp = VectorProcessor(vector_dim=64)
    
    texts = ["ransomware", "phishing", "apt attack", "ddos flood"]
    results = vp.compute_vectors_batch(texts, max_workers=2)
    
    assert len(results) == 4
    for text in texts:
        assert text in results
        assert len(results[text]) == 64
    
    print("  - Batch processing works")
    return True


def test_single_search():
    """Test single query search"""
    engine = SemanticSimilaritySearchEngineV2(similarity_threshold=0.2)
    
    result = engine.search(
        query="ransomware attack extortion",
        max_results=5,
        use_cache=False
    )
    
    assert result["success"] == True
    assert result["query"] == "ransomware attack extortion"
    assert "processing_time_ms" in result
    assert "results" in result
    
    if result["results"]:
        first = result["results"][0]
        assert "threat_id" in first
        assert "similarity_score" in first
        assert "confidence_score" in first
        assert first["similarity_score"] >= 0.2
    
    print(f"  - Found {result['total_matches']} matches")
    print(f"  - Processing time: {result['processing_time_ms']}ms")
    return True


def test_search_caching():
    """Test search result caching"""
    engine = SemanticSimilaritySearchEngineV2(similarity_threshold=0.2)
    
    # First search (cache miss)
    result1 = engine.search("phishing email attack", use_cache=True)
    
    # Second search (cache hit)
    result2 = engine.search("phishing email attack", use_cache=True)
    
    stats = engine.get_stats()
    assert stats["cache_hits"] >= 1
    
    print(f"  - Cache hits: {stats['cache_hits']}")
    print(f"  - Cache hit rate: {stats['cache_hit_rate']}")
    return True


def test_batch_search():
    """Test batch search functionality"""
    engine = SemanticSimilaritySearchEngineV2(similarity_threshold=0.2)
    
    queries = [
        "ransomware extortion",
        "phishing email attachment",
        "sql injection database",
        "zero day exploit patch"
    ]
    
    result = engine.batch_search(queries, max_results=3)
    
    assert result["success"] == True
    assert result["total_queries"] == 4
    assert result["successful_queries"] == 4
    assert len(result["failed_queries"]) == 0
    assert len(result["results"]) == 4
    
    print(f"  - Batch processed {result['total_queries']} queries")
    print(f"  - Processing time: {result['processing_time_ms']}ms")
    return True


def test_threshold_calibration():
    """Test auto-threshold calibration"""
    engine = SemanticSimilaritySearchEngineV2(similarity_threshold=0.5)
    
    sample_queries = [
        "ransomware", "phishing", "apt", "ddos", "malware"
    ]
    
    calibrated = engine.calibrate_threshold(sample_queries, target_precision=0.7)
    
    assert calibrated >= 0.1
    assert calibrated <= 0.9
    assert engine.similarity_threshold == calibrated
    
    print(f"  - Calibrated threshold: {calibrated:.4f}")
    return True


def test_enhanced_confidence_scoring():
    """Test enhanced confidence scoring"""
    engine = SemanticSimilaritySearchEngineV2(similarity_threshold=0.0)
    
    result = engine.search("ransomware", max_results=5, use_cache=False)
    
    for r in result["results"]:
        assert "confidence_score" in r
        assert r["confidence_score"] > 0
        assert r["confidence_score"] <= 1.0
        assert "matched_terms" in r
        assert isinstance(r["matched_terms"], list)
    
    print("  - Confidence scores calculated correctly")
    print("  - Matched terms extracted correctly")
    return True


def test_engine_stats():
    """Test engine statistics tracking"""
    engine = SemanticSimilaritySearchEngineV2()
    
    # Perform some searches
    for i in range(5):
        engine.search(f"test query {i}", use_cache=True)
    
    stats = engine.get_stats()
    
    assert stats["total_searches"] == 5
    assert stats["cache_misses"] == 5
    assert "avg_processing_time_ms" in stats
    assert "cache_hit_rate" in stats
    assert "database_size" in stats
    
    print(f"  - Total searches: {stats['total_searches']}")
    print(f"  - Database size: {stats['database_size']}")
    print(f"  - Avg processing time: {stats['avg_processing_time_ms']:.2f}ms")
    return True


def test_singleton_instance():
    """Test singleton instance works"""
    result = search_engine_v2.search("ransomware attack", use_cache=False)
    assert result["success"] == True
    print("  - Singleton instance functional")
    return True


def main():
    """Run all tests"""
    print("\n" + "="*70)
    print("THREAT INTELLIGENCE SEMANTIC SEARCH ENGINE V2 - TEST SUITE")
    print("="*70)
    
    tests = [
        ("LRU Cache Basic Operations", test_lru_cache_basic),
        ("LRU Cache TTL Expiration", test_lru_cache_ttl),
        ("Vector Processor", test_vector_processor),
        ("Vector Batch Processing", test_vector_batch_processing),
        ("Single Query Search", test_single_search),
        ("Search Result Caching", test_search_caching),
        ("Batch Search", test_batch_search),
        ("Threshold Auto-Calibration", test_threshold_calibration),
        ("Enhanced Confidence Scoring", test_enhanced_confidence_scoring),
        ("Engine Statistics", test_engine_stats),
        ("Singleton Instance", test_singleton_instance),
    ]
    
    passed = 0
    failed = 0
    results = {}
    
    for test_name, test_func in tests:
        result = run_test(test_name, test_func)
        if result is not None:
            passed += 1
            results[test_name] = "PASSED"
        else:
            failed += 1
            results[test_name] = "FAILED"
    
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)
    print(f"Total: {len(tests)}")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    print(f"Success Rate: {(passed/len(tests)*100):.1f}%")
    
    # Save results
    output = {
        "test_timestamp": time.time(),
        "total_tests": len(tests),
        "passed": passed,
        "failed": failed,
        "success_rate": passed/len(tests),
        "results": results,
        "engine_stats": search_engine_v2.get_stats()
    }
    
    with open('/home/user/autonomous-developer/NeuralShield-AI/test_results_threat_intelligence_semantic_similarity_search_engine_optimized_v2.json', 'w') as f:
        json.dump(output, f, indent=2)
    
    print(f"\nResults saved to test_results_threat_intelligence_semantic_similarity_search_engine_optimized_v2.json")
    
    return failed == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
