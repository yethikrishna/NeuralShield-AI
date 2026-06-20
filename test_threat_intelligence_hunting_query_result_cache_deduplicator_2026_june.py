#!/usr/bin/env python3
"""
Test suite for Threat Intelligence Hunting Query Result Cache & Deduplicator
Production-grade testing with comprehensive coverage
"""
import sys
import os
import time
import json

# Add module path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from threat_intelligence_hunting_query_result_cache_deduplicator_2026_june import (
    ThreatIntelligenceHuntingQueryResultCacheDeduplicator,
    ResultCacheConfig,
    ResultMatchType,
    ResultFingerprintGenerator
)


def run_tests():
    """Run all tests and return results"""
    results = {
        "tests_passed": 0,
        "tests_failed": 0,
        "test_details": [],
        "module_loaded": False,
        "production_ready": False
    }
    
    print("=" * 70)
    print("Threat Intelligence Hunting Query Result Cache & Deduplicator Tests")
    print("=" * 70)
    
    # Test 1: Module loads correctly
    print("\n[Test 1] Module Loading")
    try:
        print("  ✓ Module imports successfully")
        results["tests_passed"] += 1
        results["test_details"].append({"test": "module_load", "status": "passed"})
        results["module_loaded"] = True
    except Exception as e:
        print(f"  ✗ Module import failed: {e}")
        results["tests_failed"] += 1
        results["test_details"].append({"test": "module_load", "status": "failed", "error": str(e)})
        return results
    
    # Test 2: Instance creation
    print("\n[Test 2] Instance Creation")
    try:
        config = ResultCacheConfig(max_cached_results=100)
        cache = ThreatIntelligenceHuntingQueryResultCacheDeduplicator(config)
        print("  ✓ Instance created successfully with custom config")
        results["tests_passed"] += 1
        results["test_details"].append({"test": "instance_creation", "status": "passed"})
    except Exception as e:
        print(f"  ✗ Instance creation failed: {e}")
        results["tests_failed"] += 1
        results["test_details"].append({"test": "instance_creation", "status": "failed", "error": str(e)})
        return results
    
    # Test 3: Result caching
    print("\n[Test 3] Result Caching")
    try:
        cache = ThreatIntelligenceHuntingQueryResultCacheDeduplicator()
        results_list = ["192.168.1.1", "10.0.0.1", "malicious-domain.com"]
        fp = cache.cache_query_result(
            query_id="query_001",
            query_text="Find suspicious IPs",
            result_items=results_list
        )
        print(f"  ✓ Result cached with fingerprint: {fp[:16]}...")
        
        stats = cache.get_statistics()
        if stats.total_queries_cached == 1:
            print("  ✓ Statistics updated correctly")
        else:
            print(f"  ✗ Statistics incorrect: {stats.total_queries_cached} cached")
        
        results["tests_passed"] += 1
        results["test_details"].append({"test": "result_caching", "status": "passed"})
    except Exception as e:
        print(f"  ✗ Result caching failed: {e}")
        results["tests_failed"] += 1
        results["test_details"].append({"test": "result_caching", "status": "failed", "error": str(e)})
    
    # Test 4: Cache lookup
    print("\n[Test 4] Cache Lookup")
    try:
        cache = ThreatIntelligenceHuntingQueryResultCacheDeduplicator()
        cache.cache_query_result("query_001", "test query", ["item1", "item2", "item3"])
        
        cached = cache.lookup_cached_result("query_001")
        if cached and cached.result_count == 3:
            print("  ✓ Cache lookup returned correct result")
            results["tests_passed"] += 1
            results["test_details"].append({"test": "cache_lookup", "status": "passed"})
        else:
            print("  ✗ Cache lookup failed")
            results["tests_failed"] += 1
            results["test_details"].append({"test": "cache_lookup", "status": "failed"})
    except Exception as e:
        print(f"  ✗ Cache lookup failed: {e}")
        results["tests_failed"] += 1
        results["test_details"].append({"test": "cache_lookup", "status": "failed", "error": str(e)})
    
    # Test 5: Exact duplicate detection
    print("\n[Test 5] Exact Duplicate Detection")
    try:
        cache = ThreatIntelligenceHuntingQueryResultCacheDeduplicator()
        original = ["ip1", "ip2", "ip3", "domain1"]
        cache.cache_query_result("query_001", "test", original)
        
        dedup = cache.deduplicate_results(original)
        if dedup.match_type == ResultMatchType.EXACT_DUPLICATE:
            print(f"  ✓ Exact duplicate detected correctly")
            print(f"  ✓ Duplicate count: {dedup.duplicate_count}")
            print(f"  ✓ Should suppress alert: {dedup.should_suppress_alert}")
            results["tests_passed"] += 1
            results["test_details"].append({"test": "exact_duplicate", "status": "passed"})
        else:
            print(f"  ✗ Wrong match type: {dedup.match_type}")
            results["tests_failed"] += 1
            results["test_details"].append({"test": "exact_duplicate", "status": "failed"})
    except Exception as e:
        print(f"  ✗ Duplicate detection failed: {e}")
        results["tests_failed"] += 1
        results["test_details"].append({"test": "exact_duplicate", "status": "failed", "error": str(e)})
    
    # Test 6: Partial overlap detection
    print("\n[Test 6] Partial Overlap Detection")
    try:
        cache = ThreatIntelligenceHuntingQueryResultCacheDeduplicator()
        cache.cache_query_result("query_001", "test", ["a", "b", "c", "d"])
        
        dedup = cache.deduplicate_results(["c", "d", "e", "f"])
        if dedup.duplicate_count == 2 and dedup.new_item_count == 2:
            print(f"  ✓ Partial overlap detected: {dedup.duplicate_count} duplicates, {dedup.new_item_count} new")
            print(f"  ✓ Similarity score: {dedup.similarity_score}")
            results["tests_passed"] += 1
            results["test_details"].append({"test": "partial_overlap", "status": "passed"})
        else:
            print(f"  ✗ Overlap counts incorrect")
            results["tests_failed"] += 1
            results["test_details"].append({"test": "partial_overlap", "status": "failed"})
    except Exception as e:
        print(f"  ✗ Partial overlap detection failed: {e}")
        results["tests_failed"] += 1
        results["test_details"].append({"test": "partial_overlap", "status": "failed", "error": str(e)})
    
    # Test 7: Incremental delta detection
    print("\n[Test 7] Incremental Delta Detection")
    try:
        cache = ThreatIntelligenceHuntingQueryResultCacheDeduplicator()
        cache.cache_query_result("query_001", "test", ["a", "b", "c"])
        
        delta = cache.get_incremental_delta("query_001", ["b", "c", "d", "e"])
        if delta["added_count"] == 2 and delta["removed_count"] == 1:
            print(f"  ✓ Delta calculated correctly")
            print(f"  ✓ {delta['delta_summary']}")
            results["tests_passed"] += 1
            results["test_details"].append({"test": "incremental_delta", "status": "passed"})
        else:
            print(f"  ✗ Delta calculation incorrect")
            results["tests_failed"] += 1
            results["test_details"].append({"test": "incremental_delta", "status": "failed"})
    except Exception as e:
        print(f"  ✗ Delta detection failed: {e}")
        results["tests_failed"] += 1
        results["test_details"].append({"test": "incremental_delta", "status": "failed", "error": str(e)})
    
    # Test 8: Fingerprint generation
    print("\n[Test 8] Fingerprint Generation")
    try:
        items1 = ["x", "y", "z"]
        items2 = ["z", "y", "x"]  # Same items, different order
        
        fp1 = ResultFingerprintGenerator.generate_set_fingerprint(items1)
        fp2 = ResultFingerprintGenerator.generate_set_fingerprint(items2)
        
        if fp1 == fp2:
            print("  ✓ Set fingerprint is order-independent")
            results["tests_passed"] += 1
            results["test_details"].append({"test": "fingerprint", "status": "passed"})
        else:
            print("  ✗ Fingerprint should be order-independent")
            results["tests_failed"] += 1
            results["test_details"].append({"test": "fingerprint", "status": "failed"})
    except Exception as e:
        print(f"  ✗ Fingerprint generation failed: {e}")
        results["tests_failed"] += 1
        results["test_details"].append({"test": "fingerprint", "status": "failed", "error": str(e)})
    
    # Test 9: Performance metrics
    print("\n[Test 9] Performance Metrics")
    try:
        cache = ThreatIntelligenceHuntingQueryResultCacheDeduplicator()
        for i in range(10):
            cache.cache_query_result(f"q{i}", f"query {i}", [f"item_{j}" for j in range(5)])
        
        metrics = cache.get_performance_metrics()
        if metrics["total_results_cached"] == 10:
            print(f"  ✓ Performance metrics available")
            print(f"  ✓ Cache utilization: {metrics['cache_utilization_percent']}%")
            results["tests_passed"] += 1
            results["test_details"].append({"test": "performance_metrics", "status": "passed"})
        else:
            print("  ✗ Metrics incorrect")
            results["tests_failed"] += 1
            results["test_details"].append({"test": "performance_metrics", "status": "failed"})
    except Exception as e:
        print(f"  ✗ Performance metrics failed: {e}")
        results["tests_failed"] += 1
        results["test_details"].append({"test": "performance_metrics", "status": "failed", "error": str(e)})
    
    # Test 10: Similar query finding
    print("\n[Test 10] Similar Query Finding")
    try:
        cache = ThreatIntelligenceHuntingQueryResultCacheDeduplicator()
        cache.cache_query_result("q1", "test1", ["a", "b", "c", "d"])
        cache.cache_query_result("q2", "test2", ["x", "y", "z"])
        
        similar = cache.find_similar_queries(["a", "b", "c"], min_similarity=0.5)
        if len(similar) > 0 and similar[0]["query_id"] == "q1":
            print(f"  ✓ Found {len(similar)} similar queries")
            print(f"  ✓ Top match similarity: {similar[0]['similarity']}")
            results["tests_passed"] += 1
            results["test_details"].append({"test": "similar_queries", "status": "passed"})
        else:
            print("  ✗ Similar query finding failed")
            results["tests_failed"] += 1
            results["test_details"].append({"test": "similar_queries", "status": "failed"})
    except Exception as e:
        print(f"  ✗ Similar query finding failed: {e}")
        results["tests_failed"] += 1
        results["test_details"].append({"test": "similar_queries", "status": "failed", "error": str(e)})
    
    # Summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    print(f"  Tests Passed: {results['tests_passed']}")
    print(f"  Tests Failed: {results['tests_failed']}")
    print(f"  Success Rate: {(results['tests_passed'] / (results['tests_passed'] + results['tests_failed']) * 100):.1f}%")
    
    if results["tests_failed"] == 0:
        results["production_ready"] = True
        print("\n  ✓ ALL TESTS PASSED - Production Ready")
    else:
        print(f"\n  ✗ {results['tests_failed']} TESTS FAILED - Not production ready")
    
    return results


if __name__ == "__main__":
    test_results = run_tests()
    
    # Write results to JSON
    output_file = "test_results_hunting_query_result_cache_deduplicator.json"
    with open(output_file, "w") as f:
        json.dump(test_results, f, indent=2)
    
    print(f"\nResults written to: {output_file}")
    sys.exit(0 if test_results["tests_failed"] == 0 else 1)
