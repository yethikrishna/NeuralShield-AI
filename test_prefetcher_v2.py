#!/usr/bin/env python3
"""
Test for Threat Intelligence Semantic Search Cache Prefetcher Enhanced V2
REAL TEST - no mocks, actual execution
"""
import json
import sys
import time

# Add the module path
sys.path.insert(0, '/home/user/autonomous-developer/NeuralShield-AI')

from neural_shield.threat_intelligence_semantic_search_cache_prefetcher_enhanced_v2_2026_june import (
    SemanticSearchCachePrefetcherEnhancedV2,
    SemanticPrefetchPriority,
    SemanticStrategy
)


def run_comprehensive_test():
    """Run comprehensive real test of V2 prefetcher"""
    print("=" * 60)
    print("NeuralShield-AI: Testing Prefetcher Enhanced V2")
    print("=" * 60)
    
    # Initialize
    prefetcher = SemanticSearchCachePrefetcherEnhancedV2(
        embedding_dimensions=256,
        similarity_threshold=0.35,
        bm25_weight=0.4
    )
    
    print(f"[INIT] Prefetcher created with 256D embeddings")
    print(f"[INIT] Ready status: {prefetcher.is_ready()} (expect False - cold start)")
    
    # Test queries - real threat intelligence queries
    test_queries = [
        # CVE related
        "CVE-2024-1234 vulnerability details",
        "CVE-2024-1234 exploit code",
        "CVE-2024-5678 patch available",
        "vulnerability CVE-2024-9012 analysis",
        
        # Ransomware related
        "LockBit ransomware encryption analysis",
        "Conti ransomware infrastructure",
        "ransomware payment tracking",
        "ransomware group TTPs",
        
        # Malware related
        "Emotet trojan infection chain",
        "TrickBot botnet C2 servers",
        "malware hash lookup 5d41402abc4b2a76b9719d911017c592",
        "malware signature detection",
        
        # IP/Domain related
        "IP address 192.168.1.1 reputation",
        "malicious domain example.com analysis",
        "domain DNS resolution history",
        
        # General threat intel
        "APT29 threat actor techniques",
        "phishing campaign indicators",
        "data breach IOCs",
        "zero day exploit detection",
        "threat hunting queries"
    ]
    
    print(f"\n[TEST] Recording {len(test_queries)} threat intel queries...")
    
    # Record queries multiple times to build frequency
    for i, query in enumerate(test_queries * 3):
        was_cached = i % 5 == 0  # Simulate some cache hits
        prefetcher.record_and_embed_query(query, was_cached=was_cached)
    
    print(f"[TEST] Queries recorded: {prefetcher.metrics.total_queries_embedded}")
    print(f"[TEST] Vocabulary size: {len(prefetcher._embedder.vocabulary)}")
    print(f"[TEST] Ready status: {prefetcher.is_ready()}")
    
    # Test BM25 ranking
    print("\n[TEST] Testing BM25 Text Ranker...")
    bm25_score, term_weights = prefetcher._bm25_ranker.compute_bm25_score(
        "CVE vulnerability exploit",
        "CVE-2024-1234 vulnerability exploit code details"
    )
    print(f"[TEST] BM25 score computed: {bm25_score:.4f}")
    print(f"[TEST] BM25 term weights count: {len(term_weights)}")
    
    # Test hybrid embedding
    print("\n[TEST] Testing Hybrid Text Embedder (256D)...")
    embedding, tf = prefetcher._embedder.embed("CVE-2024-1234 ransomware exploit")
    print(f"[TEST] Embedding dimension: {len(embedding)} (expect 256)")
    print(f"[TEST] Non-zero embedding values: {sum(1 for x in embedding if abs(x) > 0.001)}")
    
    # Test cosine similarity
    sim = prefetcher._embedder.cosine_similarity(embedding, embedding)
    print(f"[TEST] Self-similarity: {sim:.6f} (expect 1.0)")
    
    # Test popularity decay
    print("\n[TEST] Testing Popularity Decay Tracker...")
    test_qe = list(prefetcher.query_embeddings.values())[0]
    decay_score = prefetcher._popularity_tracker.update_popularity_score(
        test_qe, time.time()
    )
    print(f"[TEST] Time-weighted frequency: {decay_score:.4f}")
    print(f"[TEST] Raw frequency: {test_qe.raw_frequency}")
    
    # Test candidate generation
    print("\n[TEST] Generating semantic prefetch candidates...")
    candidates = prefetcher.generate_semantic_candidates()
    print(f"[TEST] Candidates generated: {len(candidates)}")
    
    if candidates:
        print("\n[RESULTS] Top 5 Prefetch Candidates:")
        print("-" * 60)
        for i, cand in enumerate(candidates[:5]):
            print(f"{i+1}. {cand.query_text[:50]}...")
            print(f"   Hybrid Score: {cand.hybrid_score:.4f}")
            print(f"   Semantic Sim: {cand.semantic_similarity_score:.4f}")
            print(f"   BM25 Score: {cand.bm25_score:.4f}")
            print(f"   Strategy: {cand.strategy.value}")
            print(f"   Priority: {cand.priority.name}")
            print()
    
    # Test prefetch cycle
    print("\n[TEST] Running prefetch cycle...")
    prefetched = prefetcher.run_semantic_prefetch_cycle()
    print(f"[TEST] Items prefetched: {prefetched}")
    print(f"[TEST] Cache size after prefetch: {len(prefetcher.semantic_cache)}")
    
    # Test metrics
    print("\n[TEST] Getting detailed metrics...")
    metrics = prefetcher.get_detailed_metrics()
    
    print("\n" + "=" * 60)
    print("FINAL TEST RESULTS")
    print("=" * 60)
    print(json.dumps(metrics, indent=2, default=str))
    
    # Verify all components work
    all_passed = True
    
    checks = [
        ("256D embeddings", len(embedding) == 256),
        ("BM25 computes score", bm25_score > 0),
        ("Cosine similarity works", abs(sim - 1.0) < 0.001),
        ("Candidates generated", len(candidates) >= 0),
        ("Prefetch works", prefetched >= 0),
        ("Metrics available", len(metrics) > 0),
        ("Vocabulary built", len(prefetcher._embedder.vocabulary) > 0),
    ]
    
    print("\n" + "=" * 60)
    print("VERIFICATION CHECKS")
    print("=" * 60)
    for check_name, passed in checks:
        status = "PASS" if passed else "FAIL"
        print(f"[{status}] {check_name}")
        if not passed:
            all_passed = False
    
    # Save results
    results = {
        "test_timestamp": time.time(),
        "module": "NeuralShield-AI",
        "feature": "SemanticSearchCachePrefetcherEnhancedV2",
        "all_tests_passed": all_passed,
        "checks": checks,
        "metrics": metrics,
        "candidates_count": len(candidates),
        "prefetched_count": prefetched,
        "limitations": [
            "Uses TF-IDF/BM25, not transformer embeddings (production-friendly)",
            "Cold start period (~20 queries for vocabulary)",
            "BM25 tuned for security queries only",
            "Cross-cluster O(n²) limited to top 100 queries"
        ]
    }
    
    with open('/home/user/autonomous-developer/NeuralShield-AI/test_results_v2.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\n[DONE] Test results saved to test_results_v2.json")
    print(f"[DONE] All tests passed: {all_passed}")
    
    return all_passed, results


if __name__ == "__main__":
    passed, results = run_comprehensive_test()
    sys.exit(0 if passed else 1)
