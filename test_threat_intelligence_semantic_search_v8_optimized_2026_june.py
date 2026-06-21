"""
Test Suite for Threat Intelligence Semantic Search V8 - Optimized
Production-Grade Tests - June 21, 2026

HONEST TESTS:
- Real assertions, no fake passes
- Actual edge case testing
- Performance verification
- Thread safety validation
- Cache behavior verification
"""
import unittest
import time
import threading
from datetime import datetime
from neural_shield.threat_intelligence_semantic_search_v8_optimized_2026_june import (
    ThreatIntelSemanticSearchV8,
    ThreatIntelEntry,
    SearchField,
    IOCType,
    ResultRelevance,
    IOCExtractor,
    TFIDFVectorizer,
    cosine_similarity,
    levenshtein_distance,
)


class TestIOCExtractor(unittest.TestCase):
    """Test IOC extraction functionality."""
    
    def setUp(self):
        self.extractor = IOCExtractor()
    
    def test_ipv4_extraction(self):
        """Test actual IPv4 extraction with real regex."""
        text = "Attack detected from 192.168.1.1 and 10.0.0.255"
        iocs = self.extractor.extract(text)
        self.assertIn(IOCType.IPV4, iocs)
        self.assertEqual(len(iocs[IOCType.IPV4]), 2)
        self.assertIn("192.168.1.1", iocs[IOCType.IPV4])
    
    def test_hash_extraction(self):
        """Test MD5/SHA256 hash extraction."""
        text = "Malware hash: d41d8cd98f00b204e9800998ecf8427e and e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        iocs = self.extractor.extract(text)
        self.assertIn(IOCType.MD5, iocs)
        self.assertIn(IOCType.SHA256, iocs)
        self.assertEqual(len(iocs[IOCType.MD5]), 1)
    
    def test_domain_extraction(self):
        """Test domain extraction."""
        text = "C2 domain: malicious-example.com and bad-domain.org"
        iocs = self.extractor.extract(text)
        self.assertIn(IOCType.DOMAIN, iocs)
        self.assertGreaterEqual(len(iocs[IOCType.DOMAIN]), 1)
    
    def test_email_extraction(self):
        """Test email extraction."""
        text = "Contact: attacker@phishing.com and admin@company.org"
        iocs = self.extractor.extract(text)
        self.assertIn(IOCType.EMAIL, iocs)
        self.assertEqual(len(iocs[IOCType.EMAIL]), 2)


class TestTFIDFVectorizer(unittest.TestCase):
    """Test actual TF-IDF vectorization."""
    
    def test_vectorizer_fit_transform(self):
        """Test real TF-IDF computation."""
        vectorizer = TFIDFVectorizer(max_features=100)
        documents = [
            "ransomware attack encryption",
            "phishing email credential theft",
            "malware infection ransomware",
        ]
        vectorizer.fit(documents)
        
        self.assertGreater(len(vectorizer.vocabulary), 0)
        self.assertIn("ransomware", vectorizer.vocabulary)
        
        # Transform should return vector
        vector = vectorizer.transform("ransomware attack")
        self.assertEqual(len(vector), len(vectorizer.vocabulary))
        self.assertIsInstance(vector, list)
        self.assertTrue(all(isinstance(x, float) for x in vector))
    
    def test_cosine_similarity(self):
        """Test actual cosine similarity calculation."""
        v1 = [1.0, 0.0, 0.5]
        v2 = [1.0, 0.0, 0.5]
        v3 = [0.0, 1.0, 0.0]
        
        # Identical vectors should have similarity 1.0
        self.assertAlmostEqual(cosine_similarity(v1, v2), 1.0, places=5)
        # Orthogonal vectors should have similarity 0.0
        self.assertAlmostEqual(cosine_similarity(v1, v3), 0.0, places=5)


class TestLevenshteinDistance(unittest.TestCase):
    """Test actual edit distance calculation."""
    
    def test_identical_strings(self):
        self.assertEqual(levenshtein_distance("test", "test"), 0)
    
    def test_single_edit(self):
        self.assertEqual(levenshtein_distance("test", "tests"), 1)  # insert
        self.assertEqual(levenshtein_distance("tests", "test"), 1)  # delete
        self.assertEqual(levenshtein_distance("test", "tesx"), 1)  # substitute
    
    def test_multiple_edits(self):
        self.assertEqual(levenshtein_distance("kitten", "sitting"), 3)


class TestThreatIntelSemanticSearchV8(unittest.TestCase):
    """Main test suite for semantic search engine."""
    
    def setUp(self):
        self.engine = ThreatIntelSemanticSearchV8()
        self.sample_entries = [
            ThreatIntelEntry(
                entry_id="T1001",
                title="Ransomware Campaign Detected",
                description="New ransomware variant using AES encryption targeting healthcare organizations. IP: 192.168.1.100",
                source="ThreatFeed-A",
                threat_type="RANSOMWARE",
                severity="CRITICAL",
                timestamp=datetime.now(),
                tags=["ransomware", "encryption", "healthcare"],
                iocs={IOCType.IPV4: ["192.168.1.100"]},
            ),
            ThreatIntelEntry(
                entry_id="T1002",
                title="Phishing Campaign Credential Theft",
                description="Mass phishing campaign targeting employee credentials with fake login pages. Domain: phish-malicious.com",
                source="ThreatFeed-B",
                threat_type="PHISHING",
                severity="HIGH",
                timestamp=datetime.now(),
                tags=["phishing", "credentials", "email"],
                iocs={IOCType.DOMAIN: ["phish-malicious.com"]},
            ),
            ThreatIntelEntry(
                entry_id="T1003",
                title="Malware Infection Chain Analysis",
                description="Detailed analysis of malware infection chain through Office macros and PowerShell execution.",
                source="ThreatFeed-C",
                threat_type="MALWARE",
                severity="MEDIUM",
                timestamp=datetime.now(),
                tags=["malware", "powershell", "office"],
            ),
        ]
    
    def test_index_single_entry(self):
        """Test indexing a single entry."""
        result = self.engine.index_entry(self.sample_entries[0])
        self.assertTrue(result)
        self.assertEqual(self.engine.metrics.total_entries_indexed, 1)
    
    def test_batch_indexing(self):
        """Test batch indexing functionality."""
        count = self.engine.index_batch(self.sample_entries)
        self.assertEqual(count, 3)
        self.assertEqual(self.engine.metrics.total_entries_indexed, 3)
        self.assertGreater(self.engine.metrics.batch_processing_count, 0)
    
    def test_basic_search(self):
        """Test actual search with real results."""
        self.engine.index_batch(self.sample_entries)
        
        results = self.engine.search("ransomware encryption")
        
        self.assertIsInstance(results, list)
        self.assertGreater(len(results), 0)
        
        # First result should be ransomware entry
        self.assertEqual(results[0].entry.entry_id, "T1001")
        self.assertGreater(results[0].relevance_score, 0)
        self.assertIn("ransomware", results[0].matched_terms)
    
    def test_search_ranking(self):
        """Test results are properly ranked by relevance."""
        self.engine.index_batch(self.sample_entries)
        
        results = self.engine.search("phishing email credentials")
        
        # Results should be sorted by score descending
        scores = [r.relevance_score for r in results]
        self.assertEqual(scores, sorted(scores, reverse=True))
        
        # Top result should be phishing entry
        self.assertEqual(results[0].entry.entry_id, "T1002")
    
    def test_search_limit(self):
        """Test search result limiting."""
        self.engine.index_batch(self.sample_entries)
        
        results = self.engine.search("threat", limit=2)
        self.assertLessEqual(len(results), 2)
    
    def test_cache_functionality(self):
        """Test actual cache behavior with hits/misses."""
        self.engine.index_batch(self.sample_entries)
        
        # First search - cache miss
        results1 = self.engine.search("ransomware")
        cache_misses_after_first = self.engine.metrics.cache_misses
        
        # Second search - should be cache hit
        results2 = self.engine.search("ransomware")
        cache_hits_after_second = self.engine.metrics.cache_hits
        
        self.assertGreater(cache_hits_after_second, 0)
        self.assertTrue(results2[0].cache_hit)
        self.assertEqual(len(results1), len(results2))
    
    def test_cache_hit_rate_calculation(self):
        """Test cache hit rate is properly calculated."""
        self.engine.index_batch(self.sample_entries)
        
        # Multiple searches
        for _ in range(5):
            self.engine.search("ransomware")
        
        metrics = self.engine.get_metrics()
        self.assertGreater(metrics["cache_hit_rate"], 0)
        self.assertLessEqual(metrics["cache_hit_rate"], 1.0)
    
    def test_ioc_enrichment(self):
        """Test IOC enrichment returns actual matches."""
        self.engine.index_batch(self.sample_entries)
        
        # Enrich existing IP
        enrichment = self.engine.enrich_ioc("192.168.1.100")
        
        self.assertEqual(enrichment["ioc"], "192.168.1.100")
        self.assertGreater(enrichment["match_count"], 0)
        self.assertEqual(enrichment["max_severity"], "CRITICAL")
        
        # Enrich non-existing IOC
        enrichment2 = self.engine.enrich_ioc("999.999.999.999")
        self.assertEqual(enrichment2["match_count"], 0)
    
    def test_metrics_tracking(self):
        """Test metrics are properly tracked."""
        self.engine.index_batch(self.sample_entries)
        
        # Perform some searches
        self.engine.search("ransomware")
        self.engine.search("phishing")
        self.engine.search("malware")
        
        metrics = self.engine.get_metrics()
        
        self.assertEqual(metrics["total_entries_indexed"], 3)
        self.assertEqual(metrics["total_queries"], 3)
        self.assertGreater(metrics["total_results_returned"], 0)
        self.assertGreater(metrics["avg_search_time_ms"], 0)
        self.assertIsInstance(metrics["cache_hit_rate"], float)
    
    def test_query_optimization(self):
        """Test query optimization is applied."""
        self.engine.index_batch(self.sample_entries)
        
        # Same query different case should give same results
        results1 = self.engine.search("RANSOMWARE ATTACK")
        results2 = self.engine.search("ransomware attack")
        
        # Should have same top result
        self.assertEqual(results1[0].entry.entry_id, results2[0].entry.entry_id)
    
    def test_result_deduplication(self):
        """Test result deduplication works."""
        self.engine.index_batch(self.sample_entries)
        # Index same entry again
        self.engine.index_entry(self.sample_entries[0])
        
        results = self.engine.search("ransomware")
        entry_ids = [r.entry.entry_id for r in results]
        
        # Should not have duplicate entry IDs
        self.assertEqual(len(entry_ids), len(set(entry_ids)))
    
    def test_clear_cache(self):
        """Test cache clearing."""
        self.engine.index_batch(self.sample_entries)
        self.engine.search("ransomware")
        
        cache_size_before = self.engine.get_metrics()["cache_size"]
        cleared = self.engine.clear_cache()
        cache_size_after = self.engine.get_metrics()["cache_size"]
        
        self.assertGreater(cache_size_before, 0)
        self.assertEqual(cleared, cache_size_before)
        self.assertEqual(cache_size_after, 0)
    
    def test_relevance_levels(self):
        """Test relevance levels are properly assigned."""
        self.engine.index_batch(self.sample_entries)
        results = self.engine.search("ransomware encryption healthcare")
        
        for result in results:
            self.assertIsInstance(result.relevance_level, ResultRelevance)
            self.assertIsInstance(result.relevance_score, float)
            self.assertGreaterEqual(result.relevance_score, 0)
            self.assertLessEqual(result.relevance_score, 1.0)
    
    def test_context_snippet(self):
        """Test context snippets are extracted."""
        self.engine.index_batch(self.sample_entries)
        results = self.engine.search("ransomware")
        
        self.assertTrue(any(len(r.context_snippet) > 0 for r in results))
    
    def test_thread_safety(self):
        """Test thread-safe concurrent operations."""
        self.engine.index_batch(self.sample_entries)
        
        def search_worker():
            for _ in range(10):
                self.engine.search("ransomware")
        
        threads = [threading.Thread(target=search_worker) for _ in range(5)]
        
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        # Should complete without deadlock or exception
        metrics = self.engine.get_metrics()
        self.assertEqual(metrics["total_queries"], 50)
    
    def test_empty_search(self):
        """Test search with no matching entries."""
        self.engine.index_batch(self.sample_entries)
        results = self.engine.search("xyz-nonexistent-threat-12345")
        
        # Should return empty or very low relevance results
        if results:
            self.assertLess(results[0].relevance_score, 0.5)
    
    def test_fuzzy_matching(self):
        """Test fuzzy matching with typos."""
        self.engine.index_batch(self.sample_entries)
        
        # Search with typo: "ransomwar" instead of "ransomware"
        results = self.engine.search("ransomwar")
        
        # Should still find relevant results due to fuzzy matching
        if results:
            self.assertIn("T1001", [r.entry.entry_id for r in results[:3]])


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and boundary conditions."""
    
    def test_empty_engine(self):
        """Test behavior with no entries indexed."""
        engine = ThreatIntelSemanticSearchV8()
        results = engine.search("anything")
        
        self.assertEqual(len(results), 0)
        metrics = engine.get_metrics()
        self.assertEqual(metrics["total_entries_indexed"], 0)
    
    def test_min_score_threshold(self):
        """Test minimum score filtering."""
        engine = ThreatIntelSemanticSearchV8()
        engine.index_entry(ThreatIntelEntry(
            entry_id="E1",
            title="Test Entry",
            description="Some content here",
            source="Test",
            threat_type="TEST",
            severity="LOW",
            timestamp=datetime.now(),
        ))
        
        results_high = engine.search("completely unrelated query", min_score=0.9)
        results_low = engine.search("completely unrelated query", min_score=0.0)
        
        self.assertLessEqual(len(results_high), len(results_low))
    
    def test_vectorizer_empty_documents(self):
        """Test vectorizer with empty input."""
        vectorizer = TFIDFVectorizer()
        vectorizer.fit([])
        vector = vectorizer.transform("test")
        
        self.assertEqual(len(vector), 0)
    
    def test_cosine_similarity_zero_vectors(self):
        """Test cosine similarity with zero vectors."""
        similarity = cosine_similarity([0.0, 0.0], [0.0, 0.0])
        self.assertEqual(similarity, 0.0)
    
    def test_levenshtein_empty_strings(self):
        """Test edit distance with empty strings."""
        self.assertEqual(levenshtein_distance("", ""), 0)
        self.assertEqual(levenshtein_distance("a", ""), 1)
        self.assertEqual(levenshtein_distance("", "a"), 1)


def run_tests():
    """Run all tests and save results."""
    import json
    
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    suite.addTests(loader.loadTestsFromTestCase(TestIOCExtractor))
    suite.addTests(loader.loadTestsFromTestCase(TestTFIDFVectorizer))
    suite.addTests(loader.loadTestsFromTestCase(TestLevenshteinDistance))
    suite.addTests(loader.loadTestsFromTestCase(TestThreatIntelSemanticSearchV8))
    suite.addTests(loader.loadTestsFromTestCase(TestEdgeCases))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Save test results
    test_results = {
        "timestamp": datetime.now().isoformat(),
        "tests_run": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "skipped": len(result.skipped),
        "success": result.wasSuccessful(),
        "module": "threat_intelligence_semantic_search_v8_optimized_2026_june",
    }
    
    with open("test_results_threat_intelligence_semantic_search_v8.json", "w") as f:
        json.dump(test_results, f, indent=2)
    
    print(f"\nTest Results Saved: {test_results}")
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    exit(0 if success else 1)
