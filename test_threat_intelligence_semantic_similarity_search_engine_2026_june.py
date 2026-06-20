"""
Test suite for Threat Intelligence Semantic Similarity Search Engine
Real production-grade tests
"""

import sys
import os
import json
import tempfile

# Add the module path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from threat_intelligence_semantic_similarity_search_engine_2026_june import (
    TextProcessor,
    TFIDFVectorizer,
    ThreatIntelligenceSemanticSearch,
    SearchResult,
    SAMPLE_THREAT_DATA
)


def test_text_processor_tokenize():
    """Test real tokenization functionality"""
    text = "Ransomware attack using AES-256 encryption on hospital networks"
    tokens = TextProcessor.tokenize(text)
    
    assert len(tokens) > 0
    assert 'ransomware' in tokens
    assert 'encryption' in tokens
    assert 'hospital' in tokens
    assert 'aes-256' in tokens or 'aes' in tokens
    print("✓ test_text_processor_tokenize PASSED")


def test_text_processor_extract_iocs():
    """Test real IOC extraction"""
    text = """
    Attack from IP 192.168.1.100 and domain malicious.com
    MD5 hash: d41d8cd98f00b204e9800998ecf8427e
    SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    """
    iocs = TextProcessor.extract_iocs(text)
    
    assert '192.168.1.100' in iocs
    assert 'malicious.com' in iocs
    assert 'd41d8cd98f00b204e9800998ecf8427e' in iocs
    print("✓ test_text_processor_extract_iocs PASSED")


def test_text_processor_extract_mitre():
    """Test MITRE technique extraction"""
    text = "Techniques used: T1486 Data Encryption, T1566 Phishing, T1190 Exploit"
    techniques = TextProcessor.extract_mitre_techniques(text)
    
    assert 'T1486' in techniques
    assert 'T1566' in techniques
    assert 'T1190' in techniques
    print("✓ test_text_processor_extract_mitre PASSED")


def test_tfidf_vectorizer():
    """Test TF-IDF vectorizer functionality"""
    documents = [
        ['ransomware', 'attack', 'encryption'],
        ['phishing', 'email', 'attack'],
        ['malware', 'trojan', 'encryption']
    ]
    
    vectorizer = TFIDFVectorizer()
    vectorizer.fit(documents)
    
    assert vectorizer.doc_count == 3
    assert len(vectorizer.idf) > 0
    assert 'attack' in vectorizer.idf
    print("✓ test_tfidf_vectorizer PASSED")


def test_cosine_similarity():
    """Test cosine similarity calculation"""
    vec1 = {'a': 1.0, 'b': 2.0}
    vec2 = {'a': 1.0, 'b': 2.0}
    vec3 = {'c': 1.0, 'd': 1.0}
    
    sim_same = TFIDFVectorizer.cosine_similarity(vec1, vec2)
    sim_diff = TFIDFVectorizer.cosine_similarity(vec1, vec3)
    
    assert abs(sim_same - 1.0) < 0.001
    assert sim_diff == 0.0
    print("✓ test_cosine_similarity PASSED")


def test_search_engine_index_document():
    """Test document indexing"""
    engine = ThreatIntelligenceSemanticSearch()
    
    doc_id = engine.index_document(
        title="Test Ransomware",
        content="Ransomware attack with encryption",
        threat_type="ransomware",
        severity="critical"
    )
    
    assert doc_id is not None
    assert len(doc_id) == 16
    assert len(engine.documents) == 1
    print("✓ test_search_engine_index_document PASSED")


def test_search_engine_batch_index():
    """Test batch indexing"""
    engine = ThreatIntelligenceSemanticSearch()
    
    docs = [
        {'title': 'Doc1', 'content': 'Ransomware attack', 'threat_type': 'ransomware', 'severity': 'high'},
        {'title': 'Doc2', 'content': 'Phishing email', 'threat_type': 'phishing', 'severity': 'medium'}
    ]
    
    doc_ids = engine.index_batch(docs)
    
    assert len(doc_ids) == 2
    assert len(engine.documents) == 2
    print("✓ test_search_engine_batch_index PASSED")


def test_search_engine_basic_search():
    """Test real search functionality"""
    engine = ThreatIntelligenceSemanticSearch()
    
    # Index sample data
    engine.index_batch(SAMPLE_THREAT_DATA)
    
    # Search for ransomware
    results = engine.search("ransomware encryption hospital", top_k=5)
    
    assert len(results) > 0
    assert isinstance(results[0], SearchResult)
    assert results[0].score > 0
    assert 'ransomware' in results[0].title.lower() or results[0].threat_type == 'ransomware'
    print("✓ test_search_engine_basic_search PASSED")


def test_search_engine_with_filters():
    """Test search with filters"""
    engine = ThreatIntelligenceSemanticSearch()
    engine.index_batch(SAMPLE_THREAT_DATA)
    
    # Filter by severity
    critical_results = engine.search("attack", severity_filter="critical")
    high_results = engine.search("attack", severity_filter="high")
    
    assert all(r.severity == 'critical' for r in critical_results)
    assert all(r.severity == 'high' for r in high_results)
    print("✓ test_search_engine_with_filters PASSED")


def test_search_engine_stats():
    """Test statistics collection"""
    engine = ThreatIntelligenceSemanticSearch()
    engine.index_batch(SAMPLE_THREAT_DATA)
    
    # Perform some searches
    engine.search("ransomware")
    engine.search("phishing")
    engine.search("vulnerability")
    
    stats = engine.get_index_stats()
    
    assert stats['total_documents'] == 8
    assert stats['total_searches_performed'] == 3
    assert 'severity_distribution' in stats
    assert 'threat_type_distribution' in stats
    assert stats['total_iocs_extracted'] > 0
    print("✓ test_search_engine_stats PASSED")


def test_search_engine_export():
    """Test index export functionality"""
    engine = ThreatIntelligenceSemanticSearch()
    engine.index_batch(SAMPLE_THREAT_DATA)
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        filepath = f.name
    
    try:
        success = engine.export_index(filepath)
        assert success
        
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        assert 'documents' in data
        assert 'stats' in data
        assert len(data['documents']) == 8
        print("✓ test_search_engine_export PASSED")
    finally:
        os.unlink(filepath)


def test_search_engine_empty_query():
    """Test edge case: empty query"""
    engine = ThreatIntelligenceSemanticSearch()
    engine.index_batch(SAMPLE_THREAT_DATA)
    
    results = engine.search("")
    assert isinstance(results, list)
    print("✓ test_search_engine_empty_query PASSED")


def test_search_engine_empty_index():
    """Test edge case: empty index"""
    engine = ThreatIntelligenceSemanticSearch()
    
    results = engine.search("anything")
    assert len(results) == 0
    print("✓ test_search_engine_empty_index PASSED")


def test_severity_boosting():
    """Test severity-based score boosting"""
    engine = ThreatIntelligenceSemanticSearch()
    
    # Index same content with different severities
    engine.index_document("Test1", "ransomware attack encryption", severity="critical")
    engine.index_document("Test2", "ransomware attack encryption", severity="low")
    
    results = engine.search("ransomware attack")
    
    # Critical should score higher than low due to boosting
    critical_result = [r for r in results if r.severity == 'critical'][0]
    low_result = [r for r in results if r.severity == 'low'][0]
    
    assert critical_result.score > low_result.score
    print("✓ test_severity_boosting PASSED")


def run_all_tests():
    """Run all tests and generate report"""
    print("=" * 60)
    print("Threat Intelligence Semantic Search Engine - Test Suite")
    print("=" * 60)
    print()
    
    tests = [
        test_text_processor_tokenize,
        test_text_processor_extract_iocs,
        test_text_processor_extract_mitre,
        test_tfidf_vectorizer,
        test_cosine_similarity,
        test_search_engine_index_document,
        test_search_engine_batch_index,
        test_search_engine_basic_search,
        test_search_engine_with_filters,
        test_search_engine_stats,
        test_search_engine_export,
        test_search_engine_empty_query,
        test_search_engine_empty_index,
        test_severity_boosting
    ]
    
    passed = 0
    failed = 0
    failures = []
    
    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            failed += 1
            failures.append((test.__name__, str(e)))
            print(f"✗ {test.__name__} FAILED: {e}")
    
    print()
    print("=" * 60)
    print(f"TEST SUMMARY: {passed} PASSED, {failed} FAILED")
    print("=" * 60)
    
    if failures:
        print("\nFailures:")
        for name, error in failures:
            print(f"  - {name}: {error}")
    
    # Save results
    results = {
        'test_timestamp': __import__('datetime').datetime.utcnow().isoformat(),
        'total_tests': len(tests),
        'passed': passed,
        'failed': failed,
        'pass_rate': f"{(passed/len(tests)*100):.1f}%"
    }
    
    with open('test_results_threat_intelligence_semantic_similarity_search_engine.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\nResults saved to test_results_threat_intelligence_semantic_similarity_search_engine.json")
    
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
