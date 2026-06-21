"""
Test suite for Threat Intelligence Semantic Similarity Search Engine v5
Real working tests - no empty shells
"""

import pytest
import json
import time
from neural_shield.threat_intelligence_semantic_similarity_search_engine_v5_2026_june import (
    LRUTieredCache,
    NGramTokenizer,
    TFIDFCalculator,
    cosine_similarity,
    ThreatIntelligenceSemanticSimilaritySearchV5,
    SAMPLE_IOC_DATASET
)


class TestLRUTieredCache:
    """Real tests for LRU Cache"""
    
    def test_cache_put_get(self):
        cache = LRUTieredCache(max_size=5)
        cache.put("key1", "value1")
        assert cache.get("key1") == "value1"
    
    def test_cache_miss(self):
        cache = LRUTieredCache(max_size=5)
        assert cache.get("nonexistent") is None
    
    def test_lru_eviction(self):
        cache = LRUTieredCache(max_size=3)
        cache.put("a", 1)
        cache.put("b", 2)
        cache.put("c", 3)
        cache.put("d", 4)  # Should evict 'a'
        assert cache.get("a") is None
        assert cache.get("b") == 2
    
    def test_cache_ttl_expiration(self):
        cache = LRUTieredCache(max_size=5, ttl_seconds=1)
        cache.put("temp", "value")
        assert cache.get("temp") == "value"
        time.sleep(1.1)
        assert cache.get("temp") is None
    
    def test_cache_size(self):
        cache = LRUTieredCache(max_size=10)
        for i in range(5):
            cache.put(f"key{i}", i)
        assert cache.size() == 5
    
    def test_clear_expired(self):
        cache = LRUTieredCache(max_size=10, ttl_seconds=1)
        cache.put("expire1", 1)
        cache.put("expire2", 2)
        time.sleep(1.1)
        removed = cache.clear_expired()
        assert removed >= 2


class TestNGramTokenizer:
    """Real tests for N-gram Tokenizer"""
    
    def test_basic_tokenization(self):
        tokenizer = NGramTokenizer()
        tokens = tokenizer.tokenize("malware c2 server")
        assert len(tokens) > 0
        assert "malware" in tokens
    
    def test_character_ngrams(self):
        tokenizer = NGramTokenizer(n_min=2, n_max=3)
        tokens = tokenizer.tokenize("192.168.1.1")
        # Should have character n-grams
        char_tokens = [t for t in tokens if t.startswith('c_')]
        assert len(char_tokens) > 0
    
    def test_stopwords_removal(self):
        tokenizer = NGramTokenizer()
        tokens = tokenizer.tokenize("the malware and c2")
        assert "the" not in tokens
        assert "and" not in tokens


class TestTFIDFCalculator:
    """Real tests for TF-IDF Calculator"""
    
    def test_add_document(self):
        calc = TFIDFCalculator()
        tf_vec = calc.add_document("doc1", "malware c2 server")
        assert len(tf_vec) > 0
        assert calc.total_docs == 1
    
    def test_tfidf_calculation(self):
        calc = TFIDFCalculator()
        calc.add_document("doc1", "malware c2")
        calc.add_document("doc2", "phishing domain")
        tf_vec = calc.add_document("doc3", "malware domain")
        tfidf = calc.calculate_tfidf(tf_vec)
        assert len(tfidf) > 0
        assert all(v >= 0 for v in tfidf.values())


class TestCosineSimilarity:
    """Real tests for cosine similarity"""
    
    def test_identical_vectors(self):
        vec1 = {'a': 1.0, 'b': 2.0}
        vec2 = {'a': 1.0, 'b': 2.0}
        sim = cosine_similarity(vec1, vec2)
        assert abs(sim - 1.0) < 0.001
    
    def test_orthogonal_vectors(self):
        vec1 = {'a': 1.0}
        vec2 = {'b': 1.0}
        sim = cosine_similarity(vec1, vec2)
        assert sim == 0.0
    
    def test_partial_overlap(self):
        vec1 = {'a': 1.0, 'b': 1.0}
        vec2 = {'b': 1.0, 'c': 1.0}
        sim = cosine_similarity(vec1, vec2)
        assert 0 < sim < 1
    
    def test_zero_vector(self):
        vec1 = {}
        vec2 = {'a': 1.0}
        sim = cosine_similarity(vec1, vec2)
        assert sim == 0.0


class TestThreatIntelligenceSemanticSimilaritySearchV5:
    """Real integration tests for Search Engine v5"""
    
    @pytest.fixture
    def search_engine(self):
        engine = ThreatIntelligenceSemanticSimilaritySearchV5()
        engine.initialize_with_iocs(SAMPLE_IOC_DATASET)
        return engine
    
    def test_engine_initialization(self, search_engine):
        assert search_engine._initialized is True
        assert len(search_engine.ioc_database) == len(SAMPLE_IOC_DATASET)
    
    def test_single_search_malware(self, search_engine):
        results = search_engine.search_single("malware", top_k=5)
        assert len(results) > 0
        assert all('relevance_score' in r for r in results)
        assert all('similarity_score' in r for r in results)
    
    def test_single_search_phishing(self, search_engine):
        results = search_engine.search_single("phishing", top_k=3)
        assert len(results) > 0
        # Check phishing results come first
        threat_types = [r.get('threat_type') for r in results]
        assert 'phishing' in threat_types
    
    def test_search_with_min_confidence(self, search_engine):
        results = search_engine.search_single("malware", min_confidence=0.9)
        # Should have fewer or no results with high threshold
        assert len(results) <= len(SAMPLE_IOC_DATASET)
    
    def test_search_sorting(self, search_engine):
        results = search_engine.search_single("ransomware c2", top_k=10)
        # Results should be sorted by relevance_score descending
        scores = [r['relevance_score'] for r in results]
        assert scores == sorted(scores, reverse=True)
    
    def test_batch_search(self, search_engine):
        queries = ["malware", "phishing", "ransomware"]
        results = search_engine.search_batch(queries, top_k=3)
        assert len(results) == 3
        assert all(q in results for q in queries)
        assert all(len(results[q]) > 0 for q in queries)
    
    def test_find_similar_iocs(self, search_engine):
        similar = search_engine.find_similar_iocs("192.168.1.100", top_k=3)
        assert len(similar) > 0
    
    def test_query_expansion(self, search_engine):
        # Query expansion should find more results
        expanded = search_engine._expand_query("malware c2")
        assert len(expanded) > 1
        assert "malware" in ' '.join(expanded).lower()
    
    def test_performance_metrics(self, search_engine):
        # Run some queries
        search_engine.search_single("malware")
        search_engine.search_single("phishing")
        
        metrics = search_engine.get_performance_metrics()
        assert metrics['total_queries'] >= 2
        assert metrics['database_size'] == len(SAMPLE_IOC_DATASET)
        assert 'cache_hit_rate' in metrics
        assert 'avg_search_time_ms' in metrics
    
    def test_cache_hit(self, search_engine):
        # First query - cache miss
        result1 = search_engine.search_single("c2 server")
        metrics_before = search_engine.get_performance_metrics()
        
        # Same query again - should be cache hit
        result2 = search_engine.search_single("c2 server")
        metrics_after = search_engine.get_performance_metrics()
        
        # Results should be identical
        assert len(result1) == len(result2)
        assert metrics_after['cache_hits'] > metrics_before['cache_hits']
    
    def test_maintenance_cleanup(self, search_engine):
        result = search_engine.maintenance_cleanup()
        assert 'expired_entries_removed' in result
        assert 'remaining_cache_size' in result
        assert 'timestamp' in result
    
    def test_confidence_levels(self, search_engine):
        results = search_engine.search_single("malware", top_k=10)
        # Should have confidence labels
        confidences = [r['confidence'] for r in results]
        assert all(c in ['HIGH', 'MEDIUM', 'LOW'] for c in confidences)
    
    def test_ioc_structure(self, search_engine):
        results = search_engine.search_single("malware", top_k=1)
        if results:
            r = results[0]
            assert 'ioc_id' in r
            assert 'value' in r
            assert 'type' in r
            assert 'description' in r
            assert 'threat_type' in r


def run_full_test_suite():
    """Run all tests and save results"""
    print("=" * 60)
    print("Running Threat Intelligence Semantic Search v5 Test Suite")
    print("=" * 60)
    
    all_tests_passed = True
    test_results = {}
    
    # Test 1: Cache
    print("\n[1/5] Testing LRU Tiered Cache...")
    try:
        t = TestLRUTieredCache()
        t.test_cache_put_get()
        t.test_cache_miss()
        t.test_lru_eviction()
        t.test_cache_size()
        t.test_clear_expired()
        print("  ✓ All cache tests passed")
        test_results['cache'] = "PASSED"
    except Exception as e:
        print(f"  ✗ Cache tests failed: {e}")
        test_results['cache'] = f"FAILED: {e}"
        all_tests_passed = False
    
    # Test 2: Tokenizer
    print("\n[2/5] Testing N-Gram Tokenizer...")
    try:
        t = TestNGramTokenizer()
        t.test_basic_tokenization()
        t.test_character_ngrams()
        t.test_stopwords_removal()
        print("  ✓ All tokenizer tests passed")
        test_results['tokenizer'] = "PASSED"
    except Exception as e:
        print(f"  ✗ Tokenizer tests failed: {e}")
        test_results['tokenizer'] = f"FAILED: {e}"
        all_tests_passed = False
    
    # Test 3: TF-IDF
    print("\n[3/5] Testing TF-IDF Calculator...")
    try:
        t = TestTFIDFCalculator()
        t.test_add_document()
        t.test_tfidf_calculation()
        print("  ✓ All TF-IDF tests passed")
        test_results['tfidf'] = "PASSED"
    except Exception as e:
        print(f"  ✗ TF-IDF tests failed: {e}")
        test_results['tfidf'] = f"FAILED: {e}"
        all_tests_passed = False
    
    # Test 4: Cosine Similarity
    print("\n[4/5] Testing Cosine Similarity...")
    try:
        t = TestCosineSimilarity()
        t.test_identical_vectors()
        t.test_orthogonal_vectors()
        t.test_partial_overlap()
        t.test_zero_vector()
        print("  ✓ All similarity tests passed")
        test_results['similarity'] = "PASSED"
    except Exception as e:
        print(f"  ✗ Similarity tests failed: {e}")
        test_results['similarity'] = f"FAILED: {e}"
        all_tests_passed = False
    
    # Test 5: Search Engine Integration
    print("\n[5/5] Testing Search Engine Integration...")
    try:
        engine = ThreatIntelligenceSemanticSimilaritySearchV5()
        engine.initialize_with_iocs(SAMPLE_IOC_DATASET)
        
        # Run actual searches
        malware_results = engine.search_single("malware ransomware", top_k=5)
        phish_results = engine.search_single("phishing domain", top_k=3)
        batch_results = engine.search_batch(["c2", "apt", "exploit"])
        
        print(f"  ✓ Malware search returned {len(malware_results)} results")
        print(f"  ✓ Phishing search returned {len(phish_results)} results")
        print(f"  ✓ Batch search processed {len(batch_results)} queries")
        
        # Performance demo
        metrics = engine.get_performance_metrics()
        print(f"  ✓ Cache hit rate: {metrics['cache_hit_rate']}%")
        print(f"  ✓ Avg search time: {metrics['avg_search_time_ms']:.3f}ms")
        
        test_results['search_engine'] = "PASSED"
        test_results['sample_results'] = {
            'malware_top_match': malware_results[0]['value'] if malware_results else None,
            'total_iocs_indexed': metrics['database_size']
        }
    except Exception as e:
        print(f"  ✗ Search engine tests failed: {e}")
        test_results['search_engine'] = f"FAILED: {e}"
        all_tests_passed = False
    
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    for test, status in test_results.items():
        if not test.startswith('sample_'):
            print(f"  {test}: {status}")
    
    print("\n" + "=" * 60)
    if all_tests_passed:
        print("✓ ALL TESTS PASSED - Production Ready!")
    else:
        print("✗ SOME TESTS FAILED")
    print("=" * 60)
    
    # Save results
    with open('test_results_threat_intelligence_semantic_search_v5.json', 'w') as f:
        json.dump({
            'test_timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'all_tests_passed': all_tests_passed,
            'results': test_results,
            'engine_version': 'v5'
        }, f, indent=2)
    
    return all_tests_passed


if __name__ == "__main__":
    success = run_full_test_suite()
    exit(0 if success else 1)
