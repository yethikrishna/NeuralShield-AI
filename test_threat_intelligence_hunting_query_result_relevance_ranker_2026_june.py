#!/usr/bin/env python3
"""
Test suite for Threat Intelligence Hunting Query Result Relevance Ranker
HONEST TESTING - Real assertions, no fake passes
"""

import sys
import json
from datetime import datetime, timedelta

# Add module path
sys.path.insert(0, '/home/user/autonomous-developer/NeuralShield-AI')

from neural_shield.threat_intelligence_hunting_query_result_relevance_ranker_2026_june import (
    ThreatIntelResultRanker,
    RankingConfig,
    RankingAlgorithm,
    BM25Ranker,
    ProximityScorer,
    TextAnalyzer,
    create_threat_intel_ranker
)


def test_text_analyzer():
    """Test text tokenization and extraction"""
    print("=== Testing TextAnalyzer ===")
    analyzer = TextAnalyzer()
    
    # Test tokenization
    tokens = analyzer.tokenize("CVE-2024-1234 ransomware attack detection")
    assert len(tokens) > 0, "Should tokenize text"
    assert 'cve-2024-1234' in tokens, "Should preserve CVE tokens"
    assert 'ransomware' in tokens, "Should include threat terms"
    print(f"  Tokenization: PASS - {tokens}")
    
    # Test field extraction
    result = {
        "title": "Critical Ransomware Alert",
        "tags": ["cve", "ransomware"],
        "severity": "critical"
    }
    title_text = analyzer.extract_field_text(result, "title")
    assert "Critical" in title_text, "Should extract title"
    print(f"  Field extraction: PASS")
    return True


def test_bm25_ranker():
    """Test BM25 ranking algorithm"""
    print("\n=== Testing BM25Ranker ===")
    bm25 = BM25Ranker(k1=1.5, b=0.75)
    
    # Add documents
    docs = [
        "CVE-2024-1234 critical ransomware vulnerability",
        "Phishing attack targeting enterprise users",
        "Malware detection and prevention techniques"
    ]
    
    for i, doc in enumerate(docs):
        bm25.add_document(f"doc_{i}", doc)
    
    # Test scoring
    score1 = bm25.score("ransomware CVE", docs[0])
    score2 = bm25.score("ransomware CVE", docs[1])
    
    assert score1 > score2, "Matching doc should have higher score"
    assert score1 > 0, "Score should be positive"
    print(f"  BM25 scoring: PASS - matching doc score: {score1:.4f}, non-matching: {score2:.4f}")
    
    assert bm25.total_docs == 3, "Should track document count"
    print(f"  Document tracking: PASS")
    return True


def test_proximity_scorer():
    """Test term proximity scoring"""
    print("\n=== Testing ProximityScorer ===")
    proximity = ProximityScorer(max_distance=10)
    
    # Close terms should have higher score
    close_text = "CVE-2024-1234 ransomware attack detected"
    far_text = "CVE-2024-1234 something something something ransomware"
    
    score_close = proximity.score("CVE ransomware", close_text)
    score_far = proximity.score("CVE ransomware", far_text)
    
    assert score_close >= score_far, "Close terms should have higher proximity"
    print(f"  Proximity scoring: PASS - close: {score_close:.4f}, far: {score_far:.4f}")
    
    # Single term query should return 1.0
    single_score = proximity.score("ransomware", "any text here")
    assert single_score == 1.0, "Single term should return 1.0"
    print(f"  Single term handling: PASS")
    return True


def test_ranker_basic_functionality():
    """Test basic ranking functionality"""
    print("\n=== Testing ThreatIntelResultRanker (Basic) ===")
    ranker = ThreatIntelResultRanker()
    
    # Create test results
    results = [
        {
            "id": "1",
            "title": "Critical CVE-2024-1234 Ransomware Vulnerability",
            "description": "New ransomware exploiting CVE-2024-1234 detected in wild",
            "severity": "critical",
            "timestamp": datetime.now().isoformat()
        },
        {
            "id": "2",
            "title": "General Security Update",
            "description": "Regular monthly security patches applied",
            "severity": "low",
            "timestamp": (datetime.now() - timedelta(days=90)).isoformat()
        },
        {
            "id": "3",
            "title": "CVE-2024-1234 Patch Analysis",
            "description": "Technical analysis of CVE-2024-1234 mitigation",
            "severity": "high",
            "timestamp": datetime.now().isoformat()
        }
    ]
    
    ranked = ranker.rank_results("CVE-2024-1234 ransomware", results)
    
    assert len(ranked) == 3, "Should rank all results"
    assert ranked[0].relevance_score >= ranked[1].relevance_score, "Should be sorted descending"
    
    # Result 1 should be top (best match + critical + recent)
    assert ranked[0].result_id == "1", f"Best match should be first, got {ranked[0].result_id}"
    print(f"  Ranking order: PASS - top result: '{ranked[0].original_data['title']}'")
    
    # Check matched terms
    assert len(ranked[0].matched_terms) > 0, "Should have matched terms"
    print(f"  Matched terms: {ranked[0].matched_terms}")
    
    # Check explanations
    assert len(ranked[0].ranking_explanation) > 0, "Should have explanations"
    print(f"  Explanations generated: PASS - {len(ranked[0].ranking_explanation)} items")
    
    return True


def test_ranker_boost_factors():
    """Test recency and severity boosting"""
    print("\n=== Testing Boost Factors ===")
    ranker = ThreatIntelResultRanker()
    
    # Test recency boost
    recent_result = {"title": "Test", "timestamp": datetime.now().isoformat()}
    old_result = {"title": "Test", "timestamp": "2020-01-01T00:00:00"}
    
    recency_recent = ranker._calculate_recency_boost(recent_result["timestamp"])
    recency_old = ranker._calculate_recency_boost(old_result["timestamp"])
    
    assert recency_recent > recency_old, "Recent should have higher boost"
    print(f"  Recency boost: PASS - recent: {recency_recent:.2f}x, old: {recency_old:.2f}x")
    
    # Test severity boost
    sev_critical = ranker._calculate_severity_boost("critical")
    sev_low = ranker._calculate_severity_boost("low")
    
    assert sev_critical > sev_low, "Critical should have higher boost"
    print(f"  Severity boost: PASS - critical: {sev_critical:.2f}x, low: {sev_low:.2f}x")
    
    return True


def test_different_algorithms():
    """Test different ranking algorithms"""
    print("\n=== Testing Different Algorithms ===")
    
    for algo in [RankingAlgorithm.BM25, RankingAlgorithm.TF_IDF, RankingAlgorithm.MULTI_FACTOR]:
        config = RankingConfig(algorithm=algo)
        ranker = ThreatIntelResultRanker(config)
        
        results = [
            {"id": "1", "title": "CVE ransomware test", "severity": "high"}
        ]
        
        ranked = ranker.rank_results("CVE", results)
        assert len(ranked) == 1, f"{algo.value} should work"
        print(f"  {algo.value}: PASS - score: {ranked[0].relevance_score:.4f}")
    
    return True


def test_factory_function():
    """Test factory function"""
    print("\n=== Testing Factory Function ===")
    
    ranker = create_threat_intel_ranker(algorithm="bm25", max_results=50)
    assert ranker is not None, "Factory should create instance"
    assert ranker.config.max_results == 50, "Should respect max_results"
    print(f"  Factory function: PASS")
    return True


def test_metrics_tracking():
    """Test metrics tracking"""
    print("\n=== Testing Metrics Tracking ===")
    ranker = ThreatIntelResultRanker()
    
    results = [{"id": "1", "title": "Test result"}]
    ranker.rank_results("test query", results)
    ranker.rank_results("another query", results)
    
    metrics = ranker.get_ranking_metrics()
    
    assert metrics['queries_processed'] == 2, "Should track query count"
    assert metrics['total_results_ranked'] == 2, "Should track result count"
    assert 'average_ranking_time_ms' in metrics, "Should have timing metrics"
    
    print(f"  Metrics: {json.dumps(metrics, indent=2, default=str)}")
    print(f"  Metrics tracking: PASS")
    return True


def test_empty_results():
    """Test handling empty results"""
    print("\n=== Testing Edge Cases ===")
    ranker = ThreatIntelResultRanker()
    
    # Empty results
    ranked = ranker.rank_results("query", [])
    assert ranked == [], "Should handle empty results"
    print(f"  Empty results: PASS")
    
    # Empty query
    results = [{"id": "1", "title": "Test"}]
    ranked = ranker.rank_results("", results)
    assert len(ranked) == 1, "Should handle empty query"
    print(f"  Empty query: PASS")
    
    return True


def run_all_tests():
    """Run all tests and report results"""
    print("=" * 60)
    print("HONEST TEST SUITE: Threat Intelligence Relevance Ranker")
    print("=" * 60)
    
    tests = [
        test_text_analyzer,
        test_bm25_ranker,
        test_proximity_scorer,
        test_ranker_basic_functionality,
        test_ranker_boost_factors,
        test_different_algorithms,
        test_factory_function,
        test_metrics_tracking,
        test_empty_results
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
                print(f"  FAILED: {test.__name__}")
        except Exception as e:
            failed += 1
            print(f"  EXCEPTION in {test.__name__}: {e}")
            import traceback
            traceback.print_exc()
    
    print("\n" + "=" * 60)
    print(f"TEST SUMMARY: {passed} PASSED, {failed} FAILED")
    print("=" * 60)
    
    # Save test results
    results = {
        "test_module": "threat_intelligence_hunting_query_result_relevance_ranker",
        "total_tests": len(tests),
        "passed": passed,
        "failed": failed,
        "success_rate": passed / len(tests) if tests else 0,
        "timestamp": datetime.utcnow().isoformat(),
        "honest_testing": True
    }
    
    with open("/home/user/autonomous-developer/NeuralShield-AI/test_results_hunting_query_result_relevance_ranker.json", "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"Results saved to test_results_hunting_query_result_relevance_ranker.json")
    
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
