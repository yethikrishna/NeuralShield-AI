#!/usr/bin/env python3
"""
Test suite for Threat Intelligence Semantic Search Engine
Production-grade tests with real assertions
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from threat_intelligence_semantic_search_engine_2026_june import (
    ThreatIntelligenceSemanticSearchEngine,
    ThreatIntelEntry,
    TfidfVectorizer,
    cosine_similarity,
    SAMPLE_THREAT_DATA
)
import json


def test_tfidf_vectorizer_basic():
    """Test TF-IDF vectorizer basic functionality"""
    print("Test 1: TF-IDF Vectorizer Basic")
    
    vectorizer = TfidfVectorizer(ngram_range=(1, 1))
    docs = [
        "ransomware attack on healthcare",
        "phishing campaign targeting finance",
        "supply chain attack software"
    ]
    vectorizer.fit(docs)
    
    assert len(vectorizer.vocabulary) > 0, "Vocabulary should not be empty"
    assert vectorizer.doc_count == 3, "Should have 3 documents"
    
    vec = vectorizer.transform("ransomware healthcare")
    assert len(vec) > 0, "Should produce non-empty vector"
    
    print("  ✓ Vectorizer creates vocabulary")
    print("  ✓ Vectorizer transforms text to vectors")
    return True


def test_cosine_similarity():
    """Test cosine similarity calculation"""
    print("\nTest 2: Cosine Similarity")
    
    vec1 = {0: 1.0, 1: 1.0}
    vec2 = {0: 1.0, 1: 1.0}
    similarity = cosine_similarity(vec1, vec2)
    
    assert abs(similarity - 1.0) < 0.001, "Identical vectors should have similarity 1.0"
    
    vec3 = {2: 1.0, 3: 1.0}  # No overlap
    similarity2 = cosine_similarity(vec1, vec3)
    assert similarity2 == 0.0, "No overlap should have similarity 0"
    
    print("  ✓ Identical vectors have similarity = 1.0")
    print("  ✓ Non-overlapping vectors have similarity = 0.0")
    return True


def test_search_engine_initialization():
    """Test search engine initialization"""
    print("\nTest 3: Search Engine Initialization")
    
    engine = ThreatIntelligenceSemanticSearchEngine()
    assert engine.is_trained == False, "Should not be trained initially"
    assert len(engine.knowledge_base) == 0, "Knowledge base should be empty"
    
    print("  ✓ Engine initializes untrained")
    print("  ✓ Knowledge base starts empty")
    return True


def test_add_entries():
    """Test adding entries to knowledge base"""
    print("\nTest 4: Adding Entries")
    
    engine = ThreatIntelligenceSemanticSearchEngine()
    
    for entry in SAMPLE_THREAT_DATA:
        engine.add_entry(entry)
    
    assert len(engine.knowledge_base) == 5, "Should have 5 entries"
    assert len(engine.threat_actor_index) > 0, "Threat actor index populated"
    assert len(engine.severity_index) == 3, "Should have CRITICAL, HIGH, MEDIUM"
    
    print(f"  ✓ Added {len(engine.knowledge_base)} entries")
    print(f"  ✓ Threat actor index has {len(engine.threat_actor_index)} actors")
    print(f"  ✓ Severity index has {len(engine.severity_index)} levels")
    return True


def test_build_index():
    """Test building search index"""
    print("\nTest 5: Building Search Index")
    
    engine = ThreatIntelligenceSemanticSearchEngine()
    for entry in SAMPLE_THREAT_DATA:
        engine.add_entry(entry)
    
    engine.build_index()
    
    assert engine.is_trained == True, "Should be trained after build_index"
    assert len(engine.document_vectors) == 5, "Should have 5 document vectors"
    assert len(engine.vectorizer.vocabulary) > 0, "Vectorizer has vocabulary"
    
    print(f"  ✓ Index built successfully")
    print(f"  ✓ Vocabulary size: {len(engine.vectorizer.vocabulary)} terms")
    print("  ✓ Document vectors created")
    return True


def test_basic_search():
    """Test basic semantic search"""
    print("\nTest 6: Basic Semantic Search")
    
    engine = ThreatIntelligenceSemanticSearchEngine()
    for entry in SAMPLE_THREAT_DATA:
        engine.add_entry(entry)
    engine.build_index()
    
    # Search for ransomware
    results = engine.search("ransomware healthcare attack", limit=3)
    
    assert len(results) > 0, "Should return results"
    assert results[0]["similarity_score"] > 0, "Should have positive similarity"
    
    # Top result should be ransomware entry
    assert "ransomware" in results[0]["entry"]["title"].lower()
    
    print(f"  ✓ Search returned {len(results)} results")
    print(f"  ✓ Top result similarity: {results[0]['similarity_score']}")
    print(f"  ✓ Top result: {results[0]['entry']['title']}")
    return True


def test_search_with_filters():
    """Test search with severity and threat actor filters"""
    print("\nTest 7: Search with Filters")
    
    engine = ThreatIntelligenceSemanticSearchEngine()
    for entry in SAMPLE_THREAT_DATA:
        engine.add_entry(entry)
    engine.build_index()
    
    # Filter by CRITICAL severity - use query that matches well
    critical_results = engine.search("ransomware attack healthcare", severity="CRITICAL", min_similarity=0.05)
    for result in critical_results:
        assert result["entry"]["severity"] == "CRITICAL"
    
    # Filter by threat actor
    conti_results = engine.search("attack", threat_actor="Conti", min_similarity=0.05)
    assert len(conti_results) > 0
    assert conti_results[0]["entry"]["threat_actor"] == "Conti"
    
    # Filter by tags
    ransomware_results = engine.search("attack", tags=["ransomware"], min_similarity=0.05)
    assert len(ransomware_results) > 0
    
    print(f"  ✓ Severity filter works ({len(critical_results)} CRITICAL results)")
    print(f"  ✓ Threat actor filter works (Conti: {len(conti_results)})")
    print(f"  ✓ Tag filter works (ransomware: {len(ransomware_results)})")
    return True


def test_find_similar_threats():
    """Test finding similar threats"""
    print("\nTest 8: Find Similar Threats")
    
    engine = ThreatIntelligenceSemanticSearchEngine()
    for entry in SAMPLE_THREAT_DATA:
        engine.add_entry(entry)
    engine.build_index()
    
    similar = engine.find_similar_threats("TIA-001", limit=3)
    
    assert len(similar) <= 3, "Should respect limit"
    assert len(similar) > 0, "Should find similar threats"
    
    # Check ordering - highest similarity first
    for i in range(len(similar) - 1):
        assert similar[i]["similarity_score"] >= similar[i + 1]["similarity_score"]
    
    print(f"  ✓ Found {len(similar)} similar threats")
    print(f"  ✓ Results properly ranked by similarity")
    return True


def test_statistics():
    """Test statistics generation"""
    print("\nTest 9: Statistics Generation")
    
    engine = ThreatIntelligenceSemanticSearchEngine()
    for entry in SAMPLE_THREAT_DATA:
        engine.add_entry(entry)
    engine.build_index()
    
    stats = engine.get_statistics()
    
    assert stats["total_entries"] == 5
    assert "severity_distribution" in stats
    assert "top_threat_actors" in stats
    assert "top_tags" in stats
    assert stats["is_trained"] == True
    
    print(f"  ✓ Total entries: {stats['total_entries']}")
    print(f"  ✓ Severity distribution: {stats['severity_distribution']}")
    print(f"  ✓ Statistics properly generated")
    return True


def test_empty_query_handling():
    """Test edge case handling"""
    print("\nTest 10: Edge Case Handling")
    
    engine = ThreatIntelligenceSemanticSearchEngine()
    for entry in SAMPLE_THREAT_DATA:
        engine.add_entry(entry)
    engine.build_index()
    
    # Empty query
    results = engine.search("")
    assert isinstance(results, list), "Should return list even for empty query"
    
    # Non-existent entry ID
    similar = engine.find_similar_threats("NONEXISTENT")
    assert similar == [], "Should return empty list for non-existent ID"
    
    print("  ✓ Empty query handled gracefully")
    print("  ✓ Non-existent entry returns empty list")
    return True


def run_all_tests():
    """Run all tests and generate report"""
    print("=" * 60)
    print("Threat Intelligence Semantic Search Engine - Test Suite")
    print("=" * 60)
    print()
    
    tests = [
        test_tfidf_vectorizer_basic,
        test_cosine_similarity,
        test_search_engine_initialization,
        test_add_entries,
        test_build_index,
        test_basic_search,
        test_search_with_filters,
        test_find_similar_threats,
        test_statistics,
        test_empty_query_handling
    ]
    
    passed = 0
    failed = 0
    failures = []
    
    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
                failures.append(test.__name__)
        except Exception as e:
            failed += 1
            failures.append(f"{test.__name__}: {str(e)}")
            print(f"  ✗ EXCEPTION: {e}")
    
    print()
    print("=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    print(f"Total Tests: {len(tests)}")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    
    if failures:
        print("\nFailures:")
        for f in failures:
            print(f"  - {f}")
    
    success_rate = (passed / len(tests)) * 100
    print(f"\nSuccess Rate: {success_rate:.1f}%")
    
    # Save test results
    results = {
        "test_module": "threat_intelligence_semantic_search_engine_2026_june",
        "total_tests": len(tests),
        "passed": passed,
        "failed": failed,
        "success_rate": success_rate,
        "failures": failures,
        "timestamp": "2026-06-20"
    }
    
    with open("test_results_threat_intelligence_semantic_search_engine.json", "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"\nTest results saved to test_results_threat_intelligence_semantic_search_engine.json")
    
    return passed == len(tests)


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
