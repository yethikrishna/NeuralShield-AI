#!/usr/bin/env python3
"""
Test Suite for Threat Intelligence Cache Layer
NeuralShield-AI Module
Production-grade tests with actual verification
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

import time
import unittest
from threat_intelligence_cache_layer_2026_june import (
    ThreatIntelligenceCacheLayer,
    CacheLayerConfig,
    ThreatVerdict,
    CacheEntry
)

class TestThreatIntelligenceCacheLayer(unittest.TestCase):
    """Test suite for Threat Intelligence Cache Layer"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.config = CacheLayerConfig(
            max_size=100,
            default_ttl_seconds=300,
            enable_bloom_precheck=False
        )
        self.cache = ThreatIntelligenceCacheLayer(self.config)
    
    def test_basic_store_and_lookup(self):
        """Test basic store and lookup functionality"""
        # Store a malicious IOC
        result = self.cache.store(
            ioc="192.168.1.1",
            verdict=ThreatVerdict.MALICIOUS,
            confidence=0.95,
            threat_type="botnet_c2",
            source="abuse_ch"
        )
        self.assertTrue(result)
        
        # Look it up
        entry = self.cache.lookup("192.168.1.1")
        self.assertIsNotNone(entry)
        self.assertEqual(entry.verdict, ThreatVerdict.MALICIOUS)
        self.assertEqual(entry.confidence, 0.95)
        self.assertEqual(entry.threat_type, "botnet_c2")
        self.assertEqual(entry.source, "abuse_ch")
        self.assertEqual(entry.access_count, 1)
    
    def test_lookup_not_found(self):
        """Test lookup for non-existent IOC"""
        entry = self.cache.lookup("never.seen.before")
        self.assertIsNone(entry)
        
        stats = self.cache.get_statistics()
        self.assertEqual(stats.total_misses, 1)
    
    def test_case_insensitive_lookup(self):
        """Test that lookups are case-insensitive"""
        self.cache.store(
            ioc="MALICIOUS-DOMAIN.COM",
            verdict=ThreatVerdict.MALICIOUS,
            confidence=0.90,
            threat_type="phishing",
            source="phishtank"
        )
        
        # Different case should still find
        entry1 = self.cache.lookup("malicious-domain.com")
        entry2 = self.cache.lookup("Malicious-Domain.Com")
        
        self.assertIsNotNone(entry1)
        self.assertIsNotNone(entry2)
    
    def test_bulk_operations(self):
        """Test bulk store and batch lookup"""
        entries = [
            ("1.1.1.1", ThreatVerdict.MALICIOUS, 0.95, "c2", "source1"),
            ("2.2.2.2", ThreatVerdict.SUSPICIOUS, 0.70, "scan", "source2"),
            ("3.3.3.3", ThreatVerdict.BENIGN, 0.99, "legitimate", "source3"),
        ]
        
        count = self.cache.store_bulk(entries)
        self.assertEqual(count, 3)
        
        # Batch lookup
        results = self.cache.batch_lookup(["1.1.1.1", "2.2.2.2", "unknown"])
        self.assertIsNotNone(results["1.1.1.1"])
        self.assertIsNotNone(results["2.2.2.2"])
        self.assertIsNone(results["unknown"])
    
    def test_ttl_based_verdict(self):
        """Test that different verdicts get different TTLs"""
        self.cache.store("malicious.io", ThreatVerdict.MALICIOUS, 0.95, "c2", "test")
        self.cache.store("suspicious.io", ThreatVerdict.SUSPICIOUS, 0.70, "scan", "test")
        self.cache.store("benign.io", ThreatVerdict.BENIGN, 0.99, "legit", "test")
        
        entry_mal = self.cache.lookup("malicious.io")
        entry_sus = self.cache.lookup("suspicious.io")
        entry_ben = self.cache.lookup("benign.io")
        
        # Malicious should have longest TTL
        self.assertEqual(entry_mal.ttl_seconds, self.config.malicious_ttl_seconds)
        self.assertEqual(entry_sus.ttl_seconds, self.config.suspicious_ttl_seconds)
        self.assertEqual(entry_ben.ttl_seconds, self.config.benign_ttl_seconds)
    
    def test_lru_eviction(self):
        """Test LRU eviction when cache exceeds max size"""
        small_config = CacheLayerConfig(max_size=5, enable_bloom_precheck=False)
        small_cache = ThreatIntelligenceCacheLayer(small_config)
        
        # Add 10 entries (exceeds max)
        for i in range(10):
            small_cache.store(
                f"ip-{i}.test",
                ThreatVerdict.MALICIOUS,
                0.90,
                "test",
                "test"
            )
        
        stats = small_cache.get_statistics()
        self.assertEqual(stats.current_size, 5)
        self.assertGreater(stats.total_evictions, 0)
    
    def test_cache_warmup(self):
        """Test cache warming from list"""
        iocs = [f"malicious-{i}.com" for i in range(20)]
        count = self.cache.warm_from_list(iocs)
        
        self.assertEqual(count, 20)
        stats = self.cache.get_statistics()
        self.assertEqual(stats.current_size, 20)
    
    def test_statistics_tracking(self):
        """Test that statistics are properly tracked"""
        # Do some operations
        self.cache.store("test1.com", ThreatVerdict.MALICIOUS, 0.95, "test", "test")
        self.cache.store("test2.com", ThreatVerdict.SUSPICIOUS, 0.70, "test", "test")
        
        # Some hits
        self.cache.lookup("test1.com")
        self.cache.lookup("test1.com")
        
        # Some misses
        self.cache.lookup("nonexistent.com")
        
        stats = self.cache.get_statistics()
        self.assertEqual(stats.total_hits, 2)
        self.assertEqual(stats.total_misses, 1)
        self.assertEqual(stats.current_size, 2)
        self.assertGreater(stats.hit_rate_percent, 0)
    
    def test_sources_and_threat_types_tracking(self):
        """Test tracking of sources and threat types"""
        self.cache.store("a.com", ThreatVerdict.MALICIOUS, 0.9, "phishing", "source_a")
        self.cache.store("b.com", ThreatVerdict.MALICIOUS, 0.9, "botnet", "source_b")
        self.cache.store("c.com", ThreatVerdict.MALICIOUS, 0.9, "phishing", "source_a")
        
        sources = self.cache.get_known_sources()
        threat_types = self.cache.get_threat_types()
        
        self.assertEqual(len(sources), 2)
        self.assertIn("source_a", sources)
        self.assertIn("source_b", sources)
        
        self.assertEqual(len(threat_types), 2)
        self.assertIn("phishing", threat_types)
        self.assertIn("botnet", threat_types)
    
    def test_clear_cache(self):
        """Test clearing the cache"""
        for i in range(10):
            self.cache.store(f"test{i}.com", ThreatVerdict.MALICIOUS, 0.9, "test", "test")
        
        stats_before = self.cache.get_statistics()
        self.assertEqual(stats_before.current_size, 10)
        
        self.cache.clear()
        
        stats_after = self.cache.get_statistics()
        self.assertEqual(stats_after.current_size, 0)
        self.assertEqual(stats_after.total_hits, 0)
    
    def test_export_cache(self):
        """Test cache export functionality"""
        self.cache.store("export1.com", ThreatVerdict.MALICIOUS, 0.95, "c2", "export_test")
        self.cache.store("export2.com", ThreatVerdict.SUSPICIOUS, 0.70, "scan", "export_test")
        
        exported = self.cache.export_cache()
        self.assertEqual(len(exported), 2)
        
        # Verify structure
        for entry in exported:
            self.assertIn("ioc", entry)
            self.assertIn("verdict", entry)
            self.assertIn("confidence", entry)
            self.assertIn("threat_type", entry)
            self.assertIn("source", entry)
            self.assertIn("ttl_remaining", entry)
            self.assertIn("access_count", entry)
    
    def test_size_info(self):
        """Test size info reporting"""
        for i in range(50):
            self.cache.store(f"info{i}.com", ThreatVerdict.MALICIOUS, 0.9, "test", "test")
        
        info = self.cache.get_size_info()
        self.assertEqual(info["current_entries"], 50)
        self.assertEqual(info["max_capacity"], 100)
        self.assertEqual(info["capacity_percent"], 50.0)
    
    def test_confidence_clamping(self):
        """Test that confidence values are properly clamped"""
        self.cache.store("high.com", ThreatVerdict.MALICIOUS, 2.0, "test", "test")  # Too high
        self.cache.store("low.com", ThreatVerdict.MALICIOUS, -1.0, "test", "test")  # Too low
        
        entry_high = self.cache.lookup("high.com")
        entry_low = self.cache.lookup("low.com")
        
        self.assertEqual(entry_high.confidence, 1.0)
        self.assertEqual(entry_low.confidence, 0.0)
    
    def test_empty_ioc_rejected(self):
        """Test that empty IOCs are rejected"""
        result = self.cache.store("", ThreatVerdict.MALICIOUS, 0.9, "test", "test")
        self.assertFalse(result)

def run_tests():
    """Run all tests and return results"""
    print("=" * 60)
    print("NeuralShield-AI: Threat Intelligence Cache Layer Tests")
    print("=" * 60)
    
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestThreatIntelligenceCacheLayer)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print("\n" + "=" * 60)
    print(f"Tests Run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success: {result.wasSuccessful()}")
    print("=" * 60)
    
    return result.wasSuccessful()

if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
