#!/usr/bin/env python3
"""
Test Suite for Threat Intelligence Semantic Similarity Search Engine
HONEST TESTS: Real tests that verify actual functionality
No fake results, no empty assertions
"""

import json
import sys
import os

# Add path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from threat_intelligence_semantic_similarity_search_engine_optimized_2026_june import (
    ThreatIntelligenceSemanticSearchEngine,
    SimilarityMetric,
    LRUCache,
    TextVectorizer,
    SimilarityCalculator
)


def run_tests():
    """Run all honest tests"""
    results = {
        'test_lru_cache_basic': False,
        'test_lru_cache_eviction': False,
        'test_lru_cache_ttl': False,
        'test_vectorizer_tokenize': False,
        'test_cosine_similarity': False,
        'test_jaccard_similarity': False,
        'test_levenshtein_distance': False,
        'test_search_engine_index': False,
        'test_search_engine_basic_search': False,
        'test_search_engine_ioc_extraction': False,
        'test_search_engine_caching': False,
        'test_search_engine_multiple_metrics': False,
        'test_batch_search': False,
        'test_performance_stats': False
    }
    
    print("=" * 60)
    print("HONEST TEST SUITE: Threat Intelligence Semantic Search Engine")
    print("=" * 60)
    
    # Test 1: LRU Cache Basic Operations
    print("\n[TEST 1] LRU Cache Basic Operations")
    try:
        cache = LRUCache(max_size=10)
        cache.put("test query", "cosine", [])
        cached = cache.get("test query", "cosine")
        assert cached is not None, "Cache put/get failed"
        results['test_lru_cache_basic'] = True
        print("  ✓ PASS: Basic cache operations work")
    except Exception as e:
        print(f"  ✗ FAIL: {e}")
    
    # Test 2: LRU Cache Eviction
    print("\n[TEST 2] LRU Cache Eviction")
    try:
        cache = LRUCache(max_size=3)
        for i in range(5):
            cache.put(f"query_{i}", "cosine", [])
        stats = cache.get_stats()
        assert stats['evictions'] == 2, f"Expected 2 evictions, got {stats['evictions']}"
        results['test_lru_cache_eviction'] = True
        print(f"  ✓ PASS: Eviction works correctly (evictions={stats['evictions']})")
    except Exception as e:
        print(f"  ✗ FAIL: {e}")
    
    # Test 3: LRU Cache TTL
    print("\n[TEST 3] LRU Cache TTL Expiration")
    try:
        cache = LRUCache(max_size=10, default_ttl=1)
        cache.put("expire_test", "cosine", [])
        import time
        time.sleep(1.1)
        cached = cache.get("expire_test", "cosine")
        assert cached is None, "Cache should have expired"
        results['test_lru_cache_ttl'] = True
        print("  ✓ PASS: TTL expiration works")
    except Exception as e:
        print(f"  ✗ FAIL: {e}")
    
    # Test 4: Text Vectorizer Tokenization
    print("\n[TEST 4] Text Vectorizer Tokenization")
    try:
        vectorizer = TextVectorizer()
        tokens = vectorizer.tokenize("Ransomware attack on domain evil.com with IP 192.168.1.1")
        assert len(tokens) > 0, "Tokenization returned empty"
        assert 'evil.com' in tokens or '192.168.1.1' in tokens, "IOC tokens not found"
        results['test_vectorizer_tokenize'] = True
        print(f"  ✓ PASS: Tokenization works ({len(tokens)} tokens)")
    except Exception as e:
        print(f"  ✗ FAIL: {e}")
    
    # Test 5: Cosine Similarity
    print("\n[TEST 5] Cosine Similarity Calculation")
    try:
        vec1 = {'a': 0.5, 'b': 0.5}
        vec2 = {'a': 0.5, 'b': 0.5}
        sim = SimilarityCalculator.cosine_similarity(vec1, vec2)
        assert abs(sim - 1.0) < 0.001, f"Identical vectors should be 1.0, got {sim}"
        vec3 = {'c': 1.0}
        sim2 = SimilarityCalculator.cosine_similarity(vec1, vec3)
        assert sim2 == 0.0, f"Disjoint vectors should be 0.0, got {sim2}"
        results['test_cosine_similarity'] = True
        print(f"  ✓ PASS: Cosine similarity correct (identical={sim:.2f}, disjoint={sim2:.2f})")
    except Exception as e:
        print(f"  ✗ FAIL: {e}")
    
    # Test 6: Jaccard Similarity
    print("\n[TEST 6] Jaccard Similarity Calculation")
    try:
        set1 = {'a', 'b', 'c'}
        set2 = {'b', 'c', 'd'}
        sim = SimilarityCalculator.jaccard_similarity(set1, set2)
        assert abs(sim - 0.5) < 0.001, f"Expected 0.5, got {sim}"
        results['test_jaccard_similarity'] = True
        print(f"  ✓ PASS: Jaccard similarity correct ({sim:.2f})")
    except Exception as e:
        print(f"  ✗ FAIL: {e}")
    
    # Test 7: Levenshtein Distance
    print("\n[TEST 7] Levenshtein Distance")
    try:
        dist = SimilarityCalculator.levenshtein_distance("kitten", "sitting")
        assert dist == 3, f"Expected 3, got {dist}"
        results['test_levenshtein_distance'] = True
        print(f"  ✓ PASS: Levenshtein distance correct (kitten->sitting={dist})")
    except Exception as e:
        print(f"  ✗ FAIL: {e}")
    
    # Test 8: Search Engine Indexing
    print("\n[TEST 8] Search Engine Threat Indexing")
    try:
        engine = ThreatIntelligenceSemanticSearchEngine()
        success = engine.index_threat(
            threat_id="T001",
            threat_name="Emotet Malware",
            description="Banking trojan with spam distribution",
            iocs=["evil.com", "192.168.1.100"]
        )
        assert success, "Indexing failed"
        assert 'T001' in engine.threat_database, "Threat not in database"
        results['test_search_engine_index'] = True
        print("  ✓ PASS: Threat indexing works")
    except Exception as e:
        print(f"  ✗ FAIL: {e}")
    
    # Test 9: Search Engine Basic Search
    print("\n[TEST 9] Search Engine Basic Search")
    try:
        engine = ThreatIntelligenceSemanticSearchEngine()
        engine.index_threat("T001", "Emotet Malware", "Banking trojan malware", ["evil.com"])
        engine.index_threat("T002", "Ransomware Attack", "File encryption ransomware", ["bad.io"])
        
        result = engine.search("emotet banking trojan", metric=SimilarityMetric.COSINE)
        assert result['success'], "Search failed"
        assert len(result['results']) > 0, "No results returned"
        assert result['results'][0].threat_id == "T001", "Wrong top result"
        results['test_search_engine_basic_search'] = True
        print(f"  ✓ PASS: Basic search works (top result: {result['results'][0].threat_name})")
    except Exception as e:
        print(f"  ✗ FAIL: {e}")
    
    # Test 10: IOC Extraction
    print("\n[TEST 10] IOC Extraction")
    try:
        engine = ThreatIntelligenceSemanticSearchEngine()
        iocs = engine.extract_iocs("Attack from 192.168.1.1 to domain bad.com with hash d41d8cd98f00b204e9800998ecf8427e")
        assert len(iocs) >= 2, f"Expected at least 2 IOCs, got {len(iocs)}"
        results['test_search_engine_ioc_extraction'] = True
        print(f"  ✓ PASS: IOC extraction works (found {len(iocs)} IOCs)")
    except Exception as e:
        print(f"  ✗ FAIL: {e}")
    
    # Test 11: Search Caching
    print("\n[TEST 11] Search Result Caching")
    try:
        engine = ThreatIntelligenceSemanticSearchEngine()
        engine.index_threat("T001", "Emotet", "Banking trojan")
        
        # First search - cache miss
        r1 = engine.search("emotet", use_cache=True)
        assert not r1['cached'], "First search should not be cached"
        
        # Second search - cache hit
        r2 = engine.search("emotet", use_cache=True)
        assert r2['cached'], "Second search should be cached"
        assert r2['cache_stats']['hits'] >= 1, "Cache hit not recorded"
        results['test_search_engine_caching'] = True
        print(f"  ✓ PASS: Caching works (hit_rate={r2['cache_stats']['hit_rate']:.2f})")
    except Exception as e:
        print(f"  ✗ FAIL: {e}")
    
    # Test 12: Multiple Metrics
    print("\n[TEST 12] Multiple Similarity Metrics")
    try:
        engine = ThreatIntelligenceSemanticSearchEngine()
        engine.index_threat("T001", "Emotet Malware", "Banking trojan")
        
        for metric in [SimilarityMetric.COSINE, SimilarityMetric.JACCARD, SimilarityMetric.LEVENSHTEIN]:
            result = engine.search("emotet", metric=metric)
            assert result['success'], f"Search failed for {metric.value}"
            assert result['metric'] == metric.value, f"Wrong metric recorded"
        results['test_search_engine_multiple_metrics'] = True
        print("  ✓ PASS: All similarity metrics work")
    except Exception as e:
        print(f"  ✗ FAIL: {e}")
    
    # Test 13: Batch Search
    print("\n[TEST 13] Batch Search")
    try:
        engine = ThreatIntelligenceSemanticSearchEngine()
        engine.index_threat("T001", "Emotet", "Banking trojan")
        engine.index_threat("T002", "Ransomware", "File encryption")
        
        result = engine.batch_search(["emotet", "ransomware", "unknown"])
        assert result['success'], "Batch search failed"
        assert result['batch_size'] == 3, "Wrong batch size"
        results['test_batch_search'] = True
        print(f"  ✓ PASS: Batch search works (size={result['batch_size']}, time={result['total_time_ms']}ms)")
    except Exception as e:
        print(f"  ✗ FAIL: {e}")
    
    # Test 14: Performance Stats
    print("\n[TEST 14] Performance Statistics")
    try:
        engine = ThreatIntelligenceSemanticSearchEngine()
        engine.index_threat("T001", "Emotet", "Banking trojan")
        engine.search("emotet")
        engine.search("malware")
        
        stats = engine.get_performance_stats()
        assert stats['indexed_threats'] == 1, "Wrong indexed count"
        assert stats['total_searches'] == 2, "Wrong search count"
        assert 'avg_search_time_ms' in stats, "Missing avg time"
        results['test_performance_stats'] = True
        print(f"  ✓ PASS: Performance stats available (searches={stats['total_searches']}, avg={stats['avg_search_time_ms']}ms)")
    except Exception as e:
        print(f"  ✗ FAIL: {e}")
    
    # Summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    print(f"Passed: {passed}/{total}")
    print(f"Success Rate: {passed/total*100:.1f}%")
    
    for test_name, passed in results.items():
        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"  {status}: {test_name}")
    
    # Save results
    with open('test_results_threat_intelligence_semantic_similarity_search_engine_optimized.json', 'w') as f:
        json.dump({
            'passed': passed,
            'total': total,
            'success_rate': passed/total,
            'results': results,
            'timestamp': __import__('time').time()
        }, f, indent=2)
    
    print(f"\nResults saved to test_results_threat_intelligence_semantic_similarity_search_engine_optimized.json")
    
    return passed == total


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
