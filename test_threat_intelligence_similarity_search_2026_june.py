"""
Test suite for Threat Intelligence Similarity Search Engine
Real working tests - no mocks, actual functionality verification
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from neural_shield.threat_intelligence_similarity_search_2026_june import (
    ThreatSimilaritySearchEngine,
    TFIDFVectorizer,
    SimilarityCache
)


def test_tfidf_vectorizer_basic():
    """Test TF-IDF vectorizer basic functionality"""
    print("Test 1: TF-IDF Vectorizer Basic")
    
    vectorizer = TFIDFVectorizer(ngram_range=(1, 1))
    
    documents = [
        "malware attack using ransomware encryption",
        "phishing email with malicious attachment",
        "ransomware attack encrypting files",
        "credential stuffing attack on login endpoint"
    ]
    
    vectorizer.fit(documents)
    print(f"  Vocabulary size: {len(vectorizer.vocabulary)}")
    assert len(vectorizer.vocabulary) > 0, "Vocabulary should be populated"
    
    # Transform and verify
    vec = vectorizer.transform("ransomware attack")
    assert len(vec) > 0, "Should produce non-empty vector"
    print(f"  Vector non-zero elements: {len(vec)}")
    
    # Test cosine similarity
    vec1 = vectorizer.transform("ransomware attack")
    vec2 = vectorizer.transform("ransomware attack encrypting")
    sim = vectorizer.cosine_similarity(vec1, vec2)
    assert 0 < sim <= 1.0, f"Similarity should be between 0 and 1, got {sim}"
    print(f"  Cosine similarity (similar): {sim:.4f}")
    
    vec3 = vectorizer.transform("completely different words here")
    sim_diff = vectorizer.cosine_similarity(vec1, vec3)
    assert sim_diff < sim, "Different texts should have lower similarity"
    print(f"  Cosine similarity (different): {sim_diff:.4f}")
    
    print("  ✓ PASSED")
    return True


def test_similarity_cache():
    """Test LRU cache functionality"""
    print("Test 2: Similarity Cache")
    
    cache = SimilarityCache(max_size=3)
    
    cache.put("doc1", "doc2", 0.85)
    cache.put("doc1", "doc3", 0.75)
    cache.put("doc2", "doc3", 0.65)
    
    assert cache.get("doc1", "doc2") == 0.85, "Should retrieve cached value"
    assert cache.get("doc2", "doc1") == 0.85, "Order should not matter"
    
    # Test eviction
    cache.put("doc4", "doc5", 0.95)
    assert len(cache.cache) == 3, "Should maintain max size"
    print(f"  Cache size after eviction: {len(cache.cache)}")
    
    print("  ✓ PASSED")
    return True


def test_search_engine_add_documents():
    """Test adding documents to search engine"""
    print("Test 3: Search Engine - Add Documents")
    
    engine = ThreatSimilaritySearchEngine(max_documents=100)
    
    # Add sample threat documents
    threats = [
        ("t1", "Ransomware attack encrypts user files with AES encryption", "ransomware", "critical"),
        ("t2", "Phishing campaign targeting employee credentials via email", "phishing", "high"),
        ("t3", "SQL injection attempt on authentication endpoint", "injection", "high"),
        ("t4", "New ransomware variant uses hybrid encryption scheme", "ransomware", "critical"),
        ("t5", "DDoS attack originating from botnet IP addresses", "ddos", "medium"),
        ("t6", "Malware payload delivered via weaponized document", "malware", "high"),
        ("t7", "Credential stuffing attack detected on login API", "credential_stuffing", "medium"),
        ("t8", "Ransomware note demanding bitcoin payment appears", "ransomware", "critical"),
    ]
    
    for doc_id, content, threat_type, severity in threats:
        doc = engine.add_document(
            doc_id=doc_id,
            content=content,
            threat_type=threat_type,
            severity=severity,
            source="test_dataset"
        )
        assert doc.doc_id == doc_id, "Document ID should match"
    
    print(f"  Documents added: {len(engine.documents)}")
    assert len(engine.documents) == 8, "Should have 8 documents"
    
    # Force indexing
    engine.index_all()
    assert engine._fitted == True, "Should be fitted after indexing"
    print(f"  Vocabulary built: {len(engine.vectorizer.vocabulary)} terms")
    
    print("  ✓ PASSED")
    return True


def test_search_engine_find_similar():
    """Test similarity search functionality"""
    print("Test 4: Search Engine - Find Similar")
    
    engine = ThreatSimilaritySearchEngine(max_documents=100)
    
    # Add documents
    threats = [
        ("t1", "Ransomware attack encrypts user files with AES encryption", "ransomware", "critical"),
        ("t2", "Phishing campaign targeting employee credentials via email", "phishing", "high"),
        ("t3", "SQL injection attempt on authentication endpoint", "injection", "high"),
        ("t4", "New ransomware variant uses hybrid encryption scheme", "ransomware", "critical"),
        ("t5", "DDoS attack originating from botnet IP addresses", "ddos", "medium"),
        ("t6", "Malware payload delivered via weaponized document", "malware", "high"),
        ("t7", "Credential stuffing attack detected on login API", "credential_stuffing", "medium"),
        ("t8", "Ransomware note demanding bitcoin payment appears", "ransomware", "critical"),
    ]
    
    for doc_id, content, threat_type, severity in threats:
        engine.add_document(doc_id, content, threat_type, severity, "test")
    
    engine.index_all()
    
    # Search for ransomware-related threats
    results = engine.find_similar("ransomware encryption attack files", top_k=3)
    
    print(f"  Search results found: {len(results)}")
    assert len(results) > 0, "Should find similar documents"
    
    # Verify results are sorted by similarity
    scores = [r["similarity_score"] for r in results]
    assert scores == sorted(scores, reverse=True), "Results should be sorted descending"
    
    print(f"  Top similarity scores: {scores}")
    
    # Test threat type filtering
    filtered = engine.find_similar("attack", threat_type_filter="ransomware")
    for r in filtered:
        assert r["threat_type"] == "ransomware", "Filter should work"
    print(f"  Filtered results (ransomware only): {len(filtered)}")
    
    print("  ✓ PASSED")
    return True


def test_document_clustering():
    """Test document clustering"""
    print("Test 5: Document Clustering")
    
    engine = ThreatSimilaritySearchEngine(max_documents=100)
    
    threats = [
        ("t1", "Ransomware encrypts files with AES", "ransomware", "critical"),
        ("t2", "Ransomware uses hybrid encryption", "ransomware", "critical"),
        ("t3", "Phishing email with malicious link", "phishing", "high"),
        ("t4", "Phishing campaign targets credentials", "phishing", "high"),
        ("t5", "SQL injection on login page", "injection", "high"),
    ]
    
    for doc_id, content, threat_type, severity in threats:
        engine.add_document(doc_id, content, threat_type, severity, "test")
    
    engine.index_all()
    
    clusters = engine.get_document_clusters(threshold=0.1)
    print(f"  Clusters found: {len(clusters)}")
    assert len(clusters) > 0, "Should produce clusters"
    
    for cid, members in clusters.items():
        print(f"    {cid}: {members}")
    
    print("  ✓ PASSED")
    return True


def test_engine_statistics():
    """Test engine statistics"""
    print("Test 6: Engine Statistics")
    
    engine = ThreatSimilaritySearchEngine(max_documents=100)
    
    threats = [
        ("t1", "Ransomware attack encrypts files", "ransomware", "critical"),
        ("t2", "Phishing email with attachment", "phishing", "high"),
        ("t3", "SQL injection attempt", "injection", "high"),
    ]
    
    for doc_id, content, threat_type, severity in threats:
        engine.add_document(doc_id, content, threat_type, severity, "test")
    
    engine.index_all()
    
    # Perform some searches
    engine.find_similar("ransomware attack")
    engine.find_similar("phishing email")
    engine.find_similar("sql injection")
    
    stats = engine.get_stats()
    print(f"  Documents indexed: {stats['documents_indexed']}")
    print(f"  Total searches: {stats['search_statistics']['total_searches']}")
    print(f"  Cache hit rate: {stats['cache_hit_rate']:.4f}")
    print(f"  By threat type: {stats['by_threat_type']}")
    
    assert stats["documents_indexed"] == 3, "Should have 3 documents"
    assert stats["search_statistics"]["total_searches"] == 3, "Should have 3 searches"
    
    print("  ✓ PASSED")
    return True


def test_capacity_eviction():
    """Test document capacity eviction"""
    print("Test 7: Capacity Eviction")
    
    engine = ThreatSimilaritySearchEngine(max_documents=5)
    
    for i in range(10):
        engine.add_document(
            doc_id=f"doc_{i}",
            content=f"This is threat document number {i} about security",
            threat_type="test",
            severity="low"
        )
    
    assert len(engine.documents) == 5, "Should respect max_documents limit"
    print(f"  Documents after eviction: {len(engine.documents)}")
    
    print("  ✓ PASSED")
    return True


def run_all_tests():
    """Run all tests"""
    print("=" * 60)
    print("Threat Intelligence Similarity Search Engine - Test Suite")
    print("=" * 60)
    print()
    
    tests = [
        test_tfidf_vectorizer_basic,
        test_similarity_cache,
        test_search_engine_add_documents,
        test_search_engine_find_similar,
        test_document_clustering,
        test_engine_statistics,
        test_capacity_eviction,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"  ✗ FAILED: {e}")
            failed += 1
        print()
    
    print("=" * 60)
    print(f"Results: {passed} PASSED, {failed} FAILED")
    print("=" * 60)
    
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
