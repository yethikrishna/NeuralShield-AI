#!/usr/bin/env python3
"""
Test suite for Threat Intelligence Semantic Similarity Search Engine v4
Comprehensive tests covering all functionality
"""

import sys
import os
import json
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from threat_intelligence_semantic_similarity_search_engine_v4_2026_june import (
    SemanticSearchEngineV4,
    SearchType,
    IOCType,
    IOCNormalizer,
    TFIDFVectorizer,
    ThreadSafeLRUCache
)


def test_ioc_normalizer():
    """Test IOC extraction and normalization"""
    print("Testing IOCNormalizer...")
    
    test_text = """
    Malicious activity detected from IP 192.168.1.100
    Domain: evil-attacker.com
    URL: http://malware-download.com/payload.exe
    MD5 Hash: d41d8cd98f00b204e9800998ecf8427e
    Email: attacker@phishing.com
    """
    
    iocs = IOCNormalizer.extract_iocs(test_text)
    
    assert len(iocs[IOCType.IP]) >= 1, "Should extract IP address"
    assert len(iocs[IOCType.DOMAIN]) >= 1, "Should extract domain"
    assert len(iocs[IOCType.URL]) >= 1, "Should extract URL"
    assert len(iocs[IOCType.HASH]) >= 1, "Should extract file hash"
    assert len(iocs[IOCType.EMAIL]) >= 1, "Should extract email"
    
    print("  ✓ IOC extraction working")
    print(f"    - IPs found: {iocs[IOCType.IP]}")
    print(f"    - Domains found: {iocs[IOCType.DOMAIN]}")
    print(f"    - Hashes found: {iocs[IOCType.HASH]}")
    return True


def test_tfidf_vectorizer():
    """Test TF-IDF vectorizer and cosine similarity"""
    print("Testing TFIDFVectorizer...")
    
    vectorizer = TFIDFVectorizer()
    
    documents = [
        "Ransomware attack encrypts files using AES encryption",
        "Phishing campaign targets enterprise email accounts",
        "SQL injection vulnerability allows database access",
        "DDoS attack overwhelms server with network traffic"
    ]
    
    vectorizer.fit(documents)
    
    # Test cosine similarity
    vec1 = vectorizer.vectorize("ransomware encryption attack")
    vec2 = vectorizer.vectorize("ransomware encrypts files")
    vec3 = vectorizer.vectorize("phishing email campaign")
    
    sim1 = TFIDFVectorizer.cosine_similarity(vec1, vec2)
    sim2 = TFIDFVectorizer.cosine_similarity(vec1, vec3)
    
    assert sim1 > sim2, "Similar documents should have higher similarity"
    assert 0 <= sim1 <= 1, "Similarity should be between 0 and 1"
    
    print(f"  ✓ Cosine similarity working: similar={sim1:.3f}, dissimilar={sim2:.3f}")
    return True


def test_lru_cache():
    """Test Thread-safe LRU Cache"""
    print("Testing ThreadSafeLRUCache...")
    
    cache = ThreadSafeLRUCache(max_size=3)
    
    # Test basic put/get
    cache.put("key1", ["result1"])
    assert cache.get("key1") == ["result1"]
    
    # Test LRU eviction
    cache.put("key2", ["result2"])
    cache.put("key3", ["result3"])
    cache.put("key4", ["result4"])  # Should evict key1
    
    assert cache.get("key1") is None, "key1 should be evicted"
    assert cache.get("key4") is not None, "key4 should exist"
    
    # Test TTL expiration
    cache.put("expire_me", ["temp"], ttl_seconds=1)
    assert cache.get("expire_me") is not None
    time.sleep(1.1)
    assert cache.get("expire_me") is None, "Entry should expire"
    
    print(f"  ✓ LRU Cache working (size={cache.size()})")
    return True


def test_search_engine_basic():
    """Test basic search functionality"""
    print("Testing SemanticSearchEngineV4 (basic)...")
    
    engine = SemanticSearchEngineV4(confidence_threshold=0.1)
    
    sample_threats = [
        {
            "id": "T001",
            "title": "LockBit Ransomware Campaign",
            "description": "LockBit ransomware targets healthcare organizations, encrypting patient data and demanding Bitcoin ransom payments. Uses double extortion tactics.",
            "iocs": ["192.168.1.100", "lockbit-malware.com", "d41d8cd98f00b204e9800998ecf8427e"],
            "severity": "critical",
            "tags": ["ransomware", "extortion", "healthcare"]
        },
        {
            "id": "T002",
            "title": "Phishing Campaign - Office 365",
            "description": "Massive phishing campaign targeting Office 365 users with fake login pages. Steals credentials via credential harvesting.",
            "iocs": ["phishing-login.com", "attacker@fake-microsoft.com"],
            "severity": "high",
            "tags": ["phishing", "credentials", "office365"]
        },
        {
            "id": "T003",
            "title": "Log4j Vulnerability Exploitation",
            "description": "Active exploitation of Log4j CVE-2021-44228 vulnerability. Attackers execute remote code on vulnerable servers.",
            "iocs": ["10.0.0.50", "exploit-c2-server.net"],
            "severity": "critical",
            "tags": ["vulnerability", "rce", "log4j"]
        },
        {
            "id": "T004",
            "title": "DDoS Attack Infrastructure",
            "description": "Distributed Denial of Service attack using botnet infrastructure. Targets financial services during peak hours.",
            "iocs": ["botnet-node-1.com", "198.51.100.25"],
            "severity": "medium",
            "tags": ["ddos", "botnet", "financial"]
        }
    ]
    
    engine.add_threats(sample_threats)
    
    # Test semantic search
    results = engine.search("ransomware healthcare encryption", SearchType.SEMANTIC, limit=5)
    
    assert len(results) > 0, "Should return results"
    assert results[0].threat_id == "T001", "Top result should be LockBit ransomware"
    assert results[0].confidence > 0.3, "Should have good confidence"
    
    print(f"  ✓ Semantic search working: found {len(results)} results")
    print(f"    - Top match: {results[0].title} (confidence: {results[0].confidence})")
    
    # Test IOC search
    ioc_results = engine.search("192.168.1.100 malicious", SearchType.IOC_ONLY)
    assert len(ioc_results) > 0, "Should find IOC matches"
    assert "192.168.1.100" in ioc_results[0].ioc_matches, "Should match specific IOC"
    
    print(f"  ✓ IOC-based search working: matched IOCs {ioc_results[0].ioc_matches}")
    
    return True


def test_batch_search():
    """Test batch search functionality"""
    print("Testing batch search...")
    
    engine = SemanticSearchEngineV4(confidence_threshold=0.1)
    
    sample_threats = [
        {"id": "T1", "title": "Ransomware Threat", "description": "Ransomware encrypts files"},
        {"id": "T2", "title": "Phishing Attack", "description": "Phishing steals credentials"},
        {"id": "T3", "title": "DDoS Campaign", "description": "DDoS attacks servers"}
    ]
    engine.add_threats(sample_threats)
    
    queries = ["ransomware encrypt", "phishing credentials", "ddos attack", "unknown threat"]
    batch_results = engine.batch_search(queries, limit=3)
    
    assert len(batch_results) == 4, "Should return results for all queries"
    assert len(batch_results[0]) > 0, "First query should find results"
    assert len(batch_results[1]) > 0, "Second query should find results"
    
    print(f"  ✓ Batch search working: {len(queries)} queries processed")
    for i, results in enumerate(batch_results):
        print(f"    - Query '{queries[i]}': {len(results)} results")
    
    return True


def test_caching_performance():
    """Test caching performance improvement"""
    print("Testing caching performance...")
    
    engine = SemanticSearchEngineV4(cache_size=100, confidence_threshold=0.0)
    
    threats = [{"id": f"T{i}", "title": f"Threat {i}", "description": f"Description for threat {i} with keywords"} for i in range(50)]
    engine.add_threats(threats)
    
    # First search (cache miss)
    start = time.time()
    engine.search("threat keywords")
    first_time = time.time() - start
    
    # Second search (cache hit)
    start = time.time()
    engine.search("threat keywords")
    second_time = time.time() - start
    
    stats = engine.get_stats()
    
    assert stats['cache_hits'] >= 1, "Should have cache hits"
    assert stats['cache_hit_rate'] > 0, "Should have positive hit rate"
    assert second_time < first_time, "Cached search should be faster"
    
    print(f"  ✓ Caching working: hit_rate={stats['cache_hit_rate']:.2%}")
    print(f"    - First search (miss): {first_time*1000:.2f}ms")
    print(f"    - Second search (hit): {second_time*1000:.2f}ms")
    print(f"    - Speedup: {first_time/second_time:.1f}x faster")
    
    return True


def test_engine_stats():
    """Test engine statistics"""
    print("Testing engine statistics...")
    
    engine = SemanticSearchEngineV4()
    
    threats = [{"id": f"T{i}", "title": f"Test Threat {i}", "description": f"Test description {i}"} for i in range(10)]
    engine.add_threats(threats)
    
    # Perform some searches
    for i in range(5):
        engine.search(f"test query {i}")
    
    stats = engine.get_stats()
    
    assert stats['total_searches'] == 5, "Should track total searches"
    assert stats['database_size'] == 10, "Should track database size"
    assert 'avg_response_time_ms' in stats, "Should track response time"
    assert 'cache_hit_rate' in stats, "Should track hit rate"
    
    print(f"  ✓ Stats working: searches={stats['total_searches']}, db_size={stats['database_size']}")
    print(f"    - Avg response time: {stats['avg_response_time_ms']:.2f}ms")
    
    return True


def run_all_tests():
    """Run all tests and generate report"""
    print("=" * 70)
    print("NeuralShield-AI: Semantic Search Engine v4 - Test Suite")
    print("=" * 70)
    print()
    
    tests = [
        test_ioc_normalizer,
        test_tfidf_vectorizer,
        test_lru_cache,
        test_search_engine_basic,
        test_batch_search,
        test_caching_performance,
        test_engine_stats
    ]
    
    results = []
    start_time = time.time()
    
    for test_func in tests:
        try:
            result = test_func()
            results.append((test_func.__name__, "PASS", None))
            print()
        except Exception as e:
            results.append((test_func.__name__, "FAIL", str(e)))
            print(f"  ✗ FAILED: {e}")
            print()
    
    elapsed = time.time() - start_time
    
    # Summary
    print("=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    
    passed = sum(1 for r in results if r[1] == "PASS")
    failed = sum(1 for r in results if r[1] == "FAIL")
    
    for name, status, error in results:
        status_icon = "✓" if status == "PASS" else "✗"
        print(f"{status_icon} {name}: {status}")
        if error:
            print(f"   Error: {error}")
    
    print()
    print(f"Results: {passed}/{len(tests)} tests passed")
    print(f"Total time: {elapsed:.2f}s")
    print()
    
    # Write test results to JSON
    test_report = {
        "test_suite": "Semantic Search Engine v4",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_tests": len(tests),
        "passed": passed,
        "failed": failed,
        "success_rate": passed / len(tests),
        "elapsed_seconds": elapsed,
        "results": [{"name": r[0], "status": r[1], "error": r[2]} for r in results]
    }
    
    with open("test_results_semantic_similarity_search_engine_v4_2026_june.json", "w") as f:
        json.dump(test_report, f, indent=2)
    
    print(f"Test report written to test_results_semantic_similarity_search_engine_v4_2026_june.json")
    
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
