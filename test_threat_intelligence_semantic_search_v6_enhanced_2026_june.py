#!/usr/bin/env python3
"""
Test suite for Threat Intelligence Semantic Search V6 Enhanced
Production-grade validation with real threat intelligence data
"""

import sys
import json
import time
from datetime import datetime, timedelta

# Add module path
sys.path.insert(0, '/home/user/autonomous-developer/NeuralShield-AI')

from neural_shield.threat_intelligence_semantic_search_v6_enhanced_2026_june import (
    SemanticSearchEngineV6,
    SearchDocument,
    SearchBoostMode,
    CacheStrategy,
    Tokenizer
)


def run_tests():
    """Execute all tests and return results"""
    results = {
        "test_timestamp": datetime.utcnow().isoformat(),
        "module": "threat_intelligence_semantic_search_v6_enhanced_2026_june",
        "tests_passed": 0,
        "tests_failed": 0,
        "test_details": {},
        "performance_metrics": {}
    }

    print("=" * 70)
    print("Testing: Threat Intelligence Semantic Search V6 Enhanced")
    print("=" * 70)

    # Test 1: Tokenizer functionality
    print("\n[Test 1] Tokenizer with threat intel optimization")
    try:
        tokenizer = Tokenizer(min_token_length=2, max_ngram=3)
        test_text = "Ransomware attack exploiting CVE-2024-1234 vulnerability"
        tokens = tokenizer.tokenize(test_text)
        
        assert len(tokens) > 0, "No tokens generated"
        assert "ransomware" in tokens, "Missing 'ransomware' token"
        
        # Test query expansion
        expanded = tokenizer.expand_query(["ransomware"])
        assert "cryptolocker" in expanded, "Missing synonym expansion"
        
        print("  ✓ Tokenizer works correctly")
        print(f"    Tokens generated: {len(tokens)}")
        results["tests_passed"] += 1
        results["test_details"]["tokenizer"] = "PASS"
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        results["tests_failed"] += 1
        results["test_details"]["tokenizer"] = f"FAIL: {e}"

    # Test 2: Document indexing
    print("\n[Test 2] Document indexing and search")
    try:
        engine = SemanticSearchEngineV6(boost_mode=SearchBoostMode.HYBRID)
        
        # Add threat intelligence documents
        docs = [
            SearchDocument(
                doc_id="doc_001",
                title="Ransomware Campaign Analysis",
                content="New ransomware variant using double extortion techniques detected in healthcare sector. Encryption follows AES-256 pattern with unique key derivation.",
                source="threat_feed_a",
                threat_type="ransomware",
                threat_score=85,
                tags=["ransomware", "healthcare", "encryption"]
            ),
            SearchDocument(
                doc_id="doc_002",
                title="Phishing Campaign Detection",
                content="Spear phishing attacks targeting financial institutions with credential harvesting. Domain impersonation of major banks observed.",
                source="threat_feed_b",
                threat_type="phishing",
                threat_score=70,
                tags=["phishing", "finance", "credential"]
            ),
            SearchDocument(
                doc_id="doc_003",
                title="CVE Vulnerability Advisory",
                content="Critical vulnerability CVE-2024-9999 in enterprise software allows remote code execution. Patch available from vendor.",
                source="nvd",
                threat_type="vulnerability",
                threat_score=95,
                tags=["cve", "patch", "rce"]
            ),
            SearchDocument(
                doc_id="doc_004",
                title="APT Actor Infrastructure Report",
                content="Advanced persistent threat group observed using new C2 servers with domain generation algorithms. Tactics match MITRE ATT&CK T1071.",
                source="mandiant",
                threat_type="apt",
                threat_score=90,
                tags=["apt", "c2", "mitre"]
            )
        ]
        
        engine.add_documents_batch(docs)
        index_result = engine.build_index()
        
        assert index_result["success"] == True, "Index build failed"
        assert index_result["num_documents"] == 4, "Wrong document count"
        
        print("  ✓ Index built successfully")
        print(f"    Documents: {index_result['num_documents']}")
        print(f"    Vocabulary: {index_result['vocabulary_size']} terms")
        print(f"    Index time: {index_result['indexing_time_ms']}ms")
        results["tests_passed"] += 1
        results["test_details"]["indexing"] = "PASS"
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        results["tests_failed"] += 1
        results["test_details"]["indexing"] = f"FAIL: {e}"

    # Test 3: Semantic search functionality
    print("\n[Test 3] Semantic search queries")
    try:
        # Search for ransomware
        result = engine.search("ransomware encryption attack", limit=5)
        
        assert result["total"] > 0, "No results returned"
        assert result["results"][0]["threat_type"] == "ransomware", "Top result should be ransomware"
        assert result["from_cache"] == False, "First query should not be cached"
        
        print(f"  ✓ Search returned {result['total']} results")
        print(f"    Query time: {result['query_time_ms']}ms")
        print(f"    Top match: {result['results'][0]['title']} (score: {result['results'][0]['boosted_score']})")
        
        # Test second query (should test relevance)
        result2 = engine.search("vulnerability patch CVE", limit=3)
        assert result2["results"][0]["threat_type"] == "vulnerability", "Should find vulnerability doc"
        
        results["tests_passed"] += 1
        results["test_details"]["search"] = "PASS"
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        results["tests_failed"] += 1
        results["test_details"]["search"] = f"FAIL: {e}"

    # Test 4: Result caching
    print("\n[Test 4] Query result caching")
    try:
        # First query (not cached)
        q1 = engine.search("phishing credential", use_cache=True)
        
        # Second identical query (should hit cache)
        q2 = engine.search("phishing credential", use_cache=True)
        
        assert q2["from_cache"] == True, "Second query should be cached"
        assert q2["total"] == q1["total"], "Cached results should match"
        
        stats = engine.get_stats()
        assert stats["query_stats"]["cache_hits"] >= 1, "Cache hit not recorded"
        
        print(f"  ✓ Caching works correctly")
        print(f"    Cache hits: {stats['query_stats']['cache_hits']}")
        print(f"    Cache size: {stats['cache_stats']['size']}")
        results["tests_passed"] += 1
        results["test_details"]["caching"] = "PASS"
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        results["tests_failed"] += 1
        results["test_details"]["caching"] = f"FAIL: {e}"

    # Test 5: Result boosting
    print("\n[Test 5] Hybrid result boosting")
    try:
        result = engine.search("ransomware", limit=3)
        
        # Verify boosting explanation exists
        for r in result["results"]:
            assert "exact_match_boost" in r["explanation"], "Missing boost explanation"
            assert r["boosted_score"] >= r["similarity_score"], "Boosted score should be >= raw"
        
        print(f"  ✓ Result boosting applied correctly")
        print(f"    Boost modes: {list(result['results'][0]['explanation'].keys())}")
        results["tests_passed"] += 1
        results["test_details"]["boosting"] = "PASS"
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        results["tests_failed"] += 1
        results["test_details"]["boosting"] = f"FAIL: {e}"

    # Test 6: Batch search
    print("\n[Test 6] Batch query processing")
    try:
        queries = ["ransomware attack", "phishing campaign", "vulnerability patch"]
        batch_results = engine.batch_search(queries, limit=3)
        
        assert len(batch_results) == 3, "Should return 3 result sets"
        assert all(r["total"] > 0 for r in batch_results), "All queries should have results"
        
        print(f"  ✓ Batch search completed")
        print(f"    Queries executed: {len(batch_results)}")
        results["tests_passed"] += 1
        results["test_details"]["batch_search"] = "PASS"
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        results["tests_failed"] += 1
        results["test_details"]["batch_search"] = f"FAIL: {e}"

    # Test 7: Performance benchmark
    print("\n[Test 7] Performance benchmark")
    try:
        start_time = time.time()
        num_queries = 50
        
        for i in range(num_queries):
            engine.search(f"test query {i % 5}", use_cache=True)
        
        elapsed = (time.time() - start_time) * 1000
        avg_per_query = elapsed / num_queries
        
        stats = engine.get_stats()
        
        print(f"  ✓ Performance benchmark complete")
        print(f"    Total queries: {num_queries}")
        print(f"    Total time: {elapsed:.1f}ms")
        print(f"    Avg per query: {avg_per_query:.2f}ms")
        print(f"    Cache hit rate: ~{stats['cache_stats']['hit_rate_estimate']:.1f}%")
        
        results["performance_metrics"] = {
            "total_queries": num_queries,
            "total_time_ms": round(elapsed, 2),
            "avg_per_query_ms": round(avg_per_query, 3),
            "cache_hit_rate_estimate": stats["cache_stats"]["hit_rate_estimate"]
        }
        results["tests_passed"] += 1
        results["test_details"]["performance"] = "PASS"
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        results["tests_failed"] += 1
        results["test_details"]["performance"] = f"FAIL: {e}"

    # Summary
    print("\n" + "=" * 70)
    print(f"TEST SUMMARY: {results['tests_passed']} PASSED, {results['tests_failed']} FAILED")
    print("=" * 70)

    results["success"] = results["tests_failed"] == 0
    return results


if __name__ == "__main__":
    test_results = run_tests()
    
    # Save results
    with open("/home/user/autonomous-developer/NeuralShield-AI/test_results_threat_intelligence_semantic_search_v6_enhanced.json", "w") as f:
        json.dump(test_results, f, indent=2)
    
    print(f"\nResults saved to test_results_threat_intelligence_semantic_search_v6_enhanced.json")
    
    sys.exit(0 if test_results["success"] else 1)
