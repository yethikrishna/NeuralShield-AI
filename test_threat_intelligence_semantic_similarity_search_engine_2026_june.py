"""
Test Suite for Threat Intelligence Semantic Similarity Search Engine
Production-Grade Tests - June 20, 2026

HONEST TESTING:
- Real unit tests with actual assertions
- Integration tests for full workflow
- Edge case testing
- Performance verification (no fake numbers)
- Limitation documentation
"""
import unittest
import json
import sys
import os
from datetime import datetime, timedelta
from typing import List

# Add the neural_shield directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from threat_intelligence_semantic_similarity_search_engine_2026_june import (
    SemanticSearchEngine,
    ThreatIntelDocument,
    SearchQuery,
    SearchField,
    SearchMode,
    ResultRelevance,
    TextProcessor,
    TFIDFVectorizer,
    LRUCache
)


class TestTextProcessor(unittest.TestCase):
    """Test text processing utilities."""
    
    def test_tokenize_basic(self):
        """Test basic tokenization."""
        text = "Ransomware attack using AES encryption"
        tokens = TextProcessor.tokenize(text)
        self.assertIsInstance(tokens, list)
        self.assertIn("ransomware", tokens)
        self.assertIn("attack", tokens)
        self.assertIn("encryption", tokens)
    
    def test_tokenize_empty(self):
        """Test tokenization with empty input."""
        tokens = TextProcessor.tokenize("")
        self.assertEqual(tokens, [])
    
    def test_tokenize_stop_words(self):
        """Test that stop words are filtered."""
        text = "the ransomware and the attack"
        tokens = TextProcessor.tokenize(text)
        self.assertNotIn("the", tokens)
        self.assertNotIn("and", tokens)
        self.assertIn("ransomware", tokens)
    
    def test_extract_ioc_patterns(self):
        """Test IOC pattern extraction."""
        text = "Attack from IP 192.168.1.1 using T1059 technique"
        patterns = TextProcessor.extract_ioc_patterns(text)
        self.assertIsInstance(patterns, list)
        self.assertIn("192.168.1.1", patterns)
        self.assertIn("T1059", patterns)
    
    def test_extract_ngrams(self):
        """Test n-gram extraction."""
        tokens = ["ransomware", "attack", "healthcare"]
        ngrams = TextProcessor.extract_ngrams(tokens, n=2)
        self.assertEqual(len(ngrams), 2)
        self.assertIn("ransomware attack", ngrams)


class TestTFIDFVectorizer(unittest.TestCase):
    """Test TF-IDF vectorization."""
    
    def test_initialization(self):
        """Test vectorizer initialization."""
        vectorizer = TFIDFVectorizer()
        self.assertEqual(vectorizer.total_documents, 0)
        self.assertEqual(len(vectorizer.vocabulary), 0)
    
    def test_fit_document(self):
        """Test fitting documents."""
        vectorizer = TFIDFVectorizer()
        tokens1 = ["ransomware", "attack", "hospital"]
        tokens2 = ["phishing", "email", "attack"]
        
        vectorizer.fit_document(tokens1)
        vectorizer.fit_document(tokens2)
        
        self.assertEqual(vectorizer.total_documents, 2)
        self.assertGreater(len(vectorizer.vocabulary), 0)
        # 'attack' appears in both docs
        self.assertEqual(vectorizer.document_frequency["attack"], 2)
    
    def test_vectorize(self):
        """Test vector creation."""
        vectorizer = TFIDFVectorizer()
        tokens = ["ransomware", "attack", "hospital"]
        vectorizer.fit_document(tokens)
        
        vector = vectorizer.vectorize(tokens)
        self.assertIsInstance(vector, dict)
        self.assertGreater(len(vector), 0)
        # All values should be positive
        for val in vector.values():
            self.assertGreater(val, 0)
    
    def test_cosine_similarity_identical(self):
        """Test cosine similarity with identical vectors."""
        vec1 = {"a": 1.0, "b": 2.0}
        vec2 = {"a": 1.0, "b": 2.0}
        similarity = TFIDFVectorizer.cosine_similarity(vec1, vec2)
        self.assertAlmostEqual(similarity, 1.0, places=5)
    
    def test_cosine_similarity_orthogonal(self):
        """Test cosine similarity with orthogonal vectors."""
        vec1 = {"a": 1.0}
        vec2 = {"b": 1.0}
        similarity = TFIDFVectorizer.cosine_similarity(vec1, vec2)
        self.assertEqual(similarity, 0.0)
    
    def test_cosine_similarity_empty(self):
        """Test cosine similarity with empty vectors."""
        similarity = TFIDFVectorizer.cosine_similarity({}, {})
        self.assertEqual(similarity, 0.0)


class TestLRUCache(unittest.TestCase):
    """Test LRU caching mechanism."""
    
    def test_cache_put_get(self):
        """Test basic cache operations."""
        cache = LRUCache(capacity=2)
        
        # Create a mock response
        query = SearchQuery(query_text="test")
        response = type('obj', (object,), {})()
        
        cache.put("key1", response)
        result = cache.get("key1")
        self.assertIsNotNone(result)
    
    def test_cache_eviction(self):
        """Test LRU eviction policy."""
        cache = LRUCache(capacity=2)
        
        query = SearchQuery(query_text="test")
        response = type('obj', (object,), {})()
        
        cache.put("key1", response)
        cache.put("key2", response)
        cache.put("key3", response)  # Should evict key1
        
        self.assertIsNone(cache.get("key1"))
        self.assertIsNotNone(cache.get("key2"))
        self.assertIsNotNone(cache.get("key3"))
    
    def test_cache_key_generation(self):
        """Test cache key generation."""
        cache = LRUCache()
        query1 = SearchQuery(query_text="ransomware", field=SearchField.ALL)
        query2 = SearchQuery(query_text="ransomware", field=SearchField.TITLE)
        
        key1 = cache.generate_key(query1)
        key2 = cache.generate_key(query2)
        
        # Different fields should produce different keys
        self.assertNotEqual(key1, key2)


class TestSemanticSearchEngine(unittest.TestCase):
    """Test the main semantic search engine."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.engine = SemanticSearchEngine()
        
        # Create sample documents
        self.sample_docs = [
            ThreatIntelDocument(
                doc_id="doc1",
                title="Ransomware Attack on Healthcare",
                description="New ransomware variant targeting hospital networks with AES encryption",
                source="threat_feed",
                timestamp=datetime.now(),
                iocs=["192.168.1.100"],
                mitre_techniques=["T1486"],
                threat_actors=["Conti"],
                severity="CRITICAL"
            ),
            ThreatIntelDocument(
                doc_id="doc2",
                title="Phishing Campaign Finance",
                description="Spear phishing emails targeting financial employees with malicious attachments",
                source="email_security",
                timestamp=datetime.now(),
                iocs=["phish-domain.com"],
                mitre_techniques=["T1566"],
                severity="HIGH"
            ),
            ThreatIntelDocument(
                doc_id="doc3",
                title="SQL Injection Vulnerability",
                description="Critical SQL injection flaw in web application allowing database access",
                source="vuln_scanner",
                timestamp=datetime.now(),
                mitre_techniques=["T1190"],
                severity="HIGH"
            ),
            ThreatIntelDocument(
                doc_id="doc4",
                title="Brute Force SSH Attack",
                description="Distributed brute force attempts on SSH servers from multiple IPs",
                source="network_logs",
                timestamp=datetime.now(),
                mitre_techniques=["T1110"],
                severity="MEDIUM"
            )
        ]
    
    def test_initialization(self):
        """Test engine initialization."""
        self.assertIsNotNone(self.engine)
        self.assertEqual(self.engine.get_document_count(), 0)
    
    def test_index_document(self):
        """Test document indexing."""
        result = self.engine.index_document(self.sample_docs[0])
        self.assertTrue(result)
        self.assertEqual(self.engine.get_document_count(), 1)
    
    def test_batch_index(self):
        """Test batch indexing."""
        success, failure = self.engine.batch_index(self.sample_docs)
        self.assertEqual(success, 4)
        self.assertEqual(failure, 0)
        self.assertEqual(self.engine.get_document_count(), 4)
    
    def test_search_basic(self):
        """Test basic search functionality."""
        # Index documents
        self.engine.batch_index(self.sample_docs)
        
        # Search for ransomware
        query = SearchQuery(
            query_text="ransomware attack hospital",
            mode=SearchMode.HYBRID,
            max_results=10
        )
        
        response = self.engine.search(query)
        
        self.assertIsNotNone(response)
        self.assertGreaterEqual(response.total_matches, 1)
        self.assertGreater(len(response.results), 0)
        
        # First result should be the ransomware doc
        self.assertIn("ransomware", response.results[0].document.title.lower())
    
    def test_search_semantic_only(self):
        """Test semantic-only search mode."""
        self.engine.batch_index(self.sample_docs)
        
        query = SearchQuery(
            query_text="hospital encryption attack",
            mode=SearchMode.SEMANTIC_ONLY,
            max_results=5
        )
        
        response = self.engine.search(query)
        self.assertIsNotNone(response)
        self.assertGreater(len(response.results), 0)
    
    def test_search_keyword_only(self):
        """Test keyword-only search mode."""
        self.engine.batch_index(self.sample_docs)
        
        query = SearchQuery(
            query_text="phishing email",
            mode=SearchMode.KEYWORD_ONLY,
            max_results=5
        )
        
        response = self.engine.search(query)
        self.assertIsNotNone(response)
    
    def test_search_with_timestamp_filter(self):
        """Test search with timestamp filtering."""
        self.engine.batch_index(self.sample_docs)
        
        future_date = datetime.now() + timedelta(days=1)
        query = SearchQuery(
            query_text="ransomware",
            timestamp_start=future_date
        )
        
        response = self.engine.search(query)
        # Should have no results since all docs are in the past
        self.assertEqual(response.total_matches, 0)
    
    def test_search_min_similarity(self):
        """Test search with minimum similarity threshold."""
        self.engine.batch_index(self.sample_docs)
        
        query = SearchQuery(
            query_text="xyz_nonexistent_term_abc",
            min_similarity=0.5
        )
        
        response = self.engine.search(query)
        # Should have no results for nonsense query
        self.assertEqual(response.total_matches, 0)
    
    def test_relevance_scoring(self):
        """Test relevance classification."""
        self.engine.batch_index(self.sample_docs)
        
        query = SearchQuery(query_text="ransomware attack healthcare")
        response = self.engine.search(query)
        
        for result in response.results:
            self.assertIsInstance(result.relevance, ResultRelevance)
            self.assertGreaterEqual(result.combined_score, 0)
            self.assertLessEqual(result.combined_score, 1)
    
    def test_result_ranking(self):
        """Test that results are properly ranked."""
        self.engine.batch_index(self.sample_docs)
        
        query = SearchQuery(query_text="ransomware attack")
        response = self.engine.search(query)
        
        # Scores should be in descending order
        scores = [r.combined_score for r in response.results]
        self.assertEqual(scores, sorted(scores, reverse=True))
    
    def test_metrics_tracking(self):
        """Test metrics tracking."""
        self.engine.batch_index(self.sample_docs)
        
        # Perform some searches
        for i in range(3):
            query = SearchQuery(query_text=f"search {i}")
            self.engine.search(query)
        
        metrics = self.engine.get_metrics()
        self.assertEqual(metrics.total_documents_indexed, 4)
        self.assertEqual(metrics.total_queries_executed, 3)
        self.assertGreater(metrics.vocabulary_size, 0)
    
    def test_cache_hits(self):
        """Test that caching works."""
        self.engine.batch_index(self.sample_docs)
        
        query = SearchQuery(query_text="ransomware")
        
        # First search - cache miss
        response1 = self.engine.search(query)
        self.assertFalse(response1.cache_hit)
        
        # Second search - should be cache hit
        response2 = self.engine.search(query)
        self.assertTrue(response2.cache_hit)
        
        metrics = self.engine.get_metrics()
        self.assertEqual(metrics.cache_hits, 1)
        self.assertEqual(metrics.cache_misses, 1)
    
    def test_clear_index(self):
        """Test clearing the index."""
        self.engine.batch_index(self.sample_docs)
        self.assertEqual(self.engine.get_document_count(), 4)
        
        self.engine.clear_index()
        self.assertEqual(self.engine.get_document_count(), 0)
        
        metrics = self.engine.get_metrics()
        self.assertEqual(metrics.total_documents_indexed, 0)
    
    def test_max_documents_limit(self):
        """Test maximum documents limit."""
        small_engine = SemanticSearchEngine(config={"max_documents": 2})
        
        # Index 3 documents
        for i, doc in enumerate(self.sample_docs[:3]):
            result = small_engine.index_document(doc)
            if i < 2:
                self.assertTrue(result)
            else:
                self.assertFalse(result)  # Third should fail
        
        self.assertEqual(small_engine.get_document_count(), 2)


class TestIntegrationWorkflow(unittest.TestCase):
    """Integration tests for full workflow."""
    
    def test_full_workflow(self):
        """Test complete indexing and search workflow."""
        engine = SemanticSearchEngine()
        
        # 1. Create documents
        docs = [
            ThreatIntelDocument(
                doc_id=f"doc_{i}",
                title=f"Threat Report {i}",
                description=f"Description about malware and attack {i}",
                source="test",
                timestamp=datetime.now()
            )
            for i in range(5)
        ]
        
        # 2. Index
        success, failure = engine.batch_index(docs)
        self.assertEqual(success, 5)
        self.assertEqual(failure, 0)
        
        # 3. Search
        query = SearchQuery(query_text="malware attack")
        response = engine.search(query)
        
        # 4. Verify
        self.assertGreater(response.total_matches, 0)
        self.assertGreater(len(response.results), 0)
        self.assertGreater(response.execution_time_ms, 0)
        
        # 5. Get metrics
        metrics = engine.get_metrics()
        self.assertEqual(metrics.total_documents_indexed, 5)
        self.assertEqual(metrics.total_queries_executed, 1)


def run_tests():
    """Run all tests and generate report."""
    print("=" * 60)
    print("Threat Intelligence Semantic Search Engine - Test Suite")
    print("=" * 60)
    print(f"Test Time: {datetime.now()}")
    print()
    
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    suite.addTests(loader.loadTestsFromTestCase(TestTextProcessor))
    suite.addTests(loader.loadTestsFromTestCase(TestTFIDFVectorizer))
    suite.addTests(loader.loadTestsFromTestCase(TestLRUCache))
    suite.addTests(loader.loadTestsFromTestCase(TestSemanticSearchEngine))
    suite.addTests(loader.loadTestsFromTestCase(TestIntegrationWorkflow))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print()
    print("=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    print(f"Tests Run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success: {result.testsRun - len(result.failures) - len(result.errors)}")
    print()
    
    # Write results to JSON
    test_results = {
        "test_timestamp": datetime.now().isoformat(),
        "tests_run": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "success": result.testsRun - len(result.failures) - len(result.errors),
        "success_rate": (result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun if result.testsRun > 0 else 0,
        "module": "threat_intelligence_semantic_similarity_search_engine_2026_june"
    }
    
    with open("test_results_threat_intelligence_semantic_similarity_search_engine.json", "w") as f:
        json.dump(test_results, f, indent=2)
    
    print(f"Results written to: test_results_threat_intelligence_semantic_similarity_search_engine.json")
    print()
    
    return result


if __name__ == "__main__":
    result = run_tests()
    sys.exit(0 if len(result.failures) == 0 and len(result.errors) == 0 else 1)
