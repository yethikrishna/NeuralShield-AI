#!/usr/bin/env python3
"""
Test Suite for Threat Intelligence Feed Aggregator with Bloom Filter
June 2026 Production Release - NeuralShield-AI

Real working tests that verify:
1. Bloom filter correctness (no false negatives, controlled false positives)
2. IOC lookup functionality
3. LRU cache behavior
4. Thread safety
5. Statistics and health monitoring
6. Custom IOC addition
7. Batch lookup performance
"""
import sys
import os
import time
import json
import threading
import unittest
from typing import List

# Add module path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from threat_intelligence_feed_aggregator_bloom_filter_2026_june import (
    BloomFilter,
    ThreatFeedAggregator,
    IOCTypes,
    ThreatMatchResult,
    lookup_threat_ioc,
    is_ioc_malicious
)


class TestBloomFilter(unittest.TestCase):
    """Test Bloom Filter core functionality"""
    
    def test_bloom_filter_basic_operations(self):
        """Test basic add and contains operations"""
        bf = BloomFilter(expected_items=1000, false_positive_rate=0.001)
        
        # Add items
        bf.add("test-item-1")
        bf.add("test-item-2")
        bf.add("test-item-3")
        
        # Verify items are found (no false negatives)
        self.assertTrue(bf.contains("test-item-1"))
        self.assertTrue(bf.contains("test-item-2"))
        self.assertTrue(bf.contains("test-item-3"))
        
        # Verify non-existent items are definitely not found
        self.assertFalse(bf.contains("definitely-not-added-item"))
        self.assertFalse(bf.contains("another-non-existent-item"))
        
        print("✓ Bloom filter basic operations passed")
    
    def test_bloom_filter_no_false_negatives(self):
        """Verify NO false negatives - critical property"""
        bf = BloomFilter(expected_items=10000, false_positive_rate=0.0001)
        
        # Add many items
        items = [f"item-{i}" for i in range(1000)]
        for item in items:
            bf.add(item)
        
        # Verify ALL added items are found (no false negatives)
        false_negatives = 0
        for item in items:
            if not bf.contains(item):
                false_negatives += 1
        
        self.assertEqual(false_negatives, 0, "Bloom filter must have ZERO false negatives")
        print(f"✓ No false negatives verified (1000 items checked)")
    
    def test_bloom_filter_false_positive_rate(self):
        """Verify false positive rate is within expected bounds"""
        bf = BloomFilter(expected_items=10000, false_positive_rate=0.01)
        
        # Add 1000 items (10% of capacity)
        for i in range(1000):
            bf.add(f"added-{i}")
        
        # Test for false positives
        false_positives = 0
        total_tests = 10000
        
        for i in range(total_tests):
            if bf.contains(f"not-added-{i}"):
                false_positives += 1
        
        fpr = false_positives / total_tests
        
        # Should be well below 1% (target)
        print(f"✓ False positive rate: {fpr:.4%} ({false_positives}/{total_tests})")
        self.assertLess(fpr, 0.02, "FPR should be reasonable")
    
    def test_bloom_filter_size_calculation(self):
        """Test optimal size and hash count calculations"""
        bf = BloomFilter(expected_items=10000, false_positive_rate=0.001)
        
        # Verify size and hash count are reasonable
        self.assertGreater(bf.size, 0)
        self.assertGreater(bf.hash_count, 0)
        self.assertLess(bf.hash_count, 20)  # Shouldn't need too many hashes
        
        print(f"✓ Bloom filter calculated: size={bf.size} bits, hashes={bf.hash_count}")
    
    def test_bloom_filter_clear(self):
        """Test clearing bloom filter"""
        bf = BloomFilter(expected_items=1000, false_positive_rate=0.001)
        bf.add("test-item")
        self.assertTrue(bf.contains("test-item"))
        
        bf.clear()
        self.assertFalse(bf.contains("test-item"))
        self.assertEqual(len(bf), 0)
        
        print("✓ Bloom filter clear operation passed")
    
    def test_bloom_filter_estimated_fpr(self):
        """Test estimated FPR calculation"""
        bf = BloomFilter(expected_items=10000, false_positive_rate=0.001)
        
        # FPR should increase as we add items
        initial_fpr = bf.get_estimated_fpr()
        
        for i in range(5000):
            bf.add(f"item-{i}")
        
        final_fpr = bf.get_estimated_fpr()
        
        self.assertGreaterEqual(final_fpr, initial_fpr)
        print(f"✓ Estimated FPR: {final_fpr:.6f} after 5000 items")


class TestThreatFeedAggregator(unittest.TestCase):
    """Test Threat Feed Aggregator functionality"""
    
    def setUp(self):
        """Create fresh aggregator for each test"""
        self.aggregator = ThreatFeedAggregator(
            bloom_filter_size=10000,
            false_positive_rate=0.0001,
            enable_background_refresh=False,
            cache_size=1000
        )
    
    def tearDown(self):
        """Cleanup"""
        self.aggregator.shutdown()
    
    def test_aggregator_initialization(self):
        """Test proper initialization"""
        stats = self.aggregator.get_statistics()
        
        self.assertGreater(stats['total_iocs'], 0)
        self.assertEqual(stats['total_lookups'], 0)
        self.assertEqual(stats['cache_hits'], 0)
        
        print(f"✓ Aggregator initialized with {stats['total_iocs']} IOCs")
    
    def test_lookup_malicious_ioc(self):
        """Test lookup of known malicious IOC"""
        # Known malicious domain
        result = self.aggregator.lookup("malicious-example.com", IOCTypes.DOMAIN)
        
        self.assertTrue(result.found)
        self.assertEqual(result.ioc_type, IOCTypes.DOMAIN)
        self.assertGreater(result.confidence, 0.9)
        self.assertTrue(result.bloom_filter_match)
        self.assertGreater(result.lookup_time_ns, 0)
        
        print(f"✓ Malicious IOC detected: {result.ioc_value} (confidence: {result.confidence})")
        print(f"  Lookup time: {result.lookup_time_ns / 1000:.2f} μs")
    
    def test_lookup_benign_ioc(self):
        """Test lookup of benign (non-malicious) IOC"""
        result = self.aggregator.lookup("google.com", IOCTypes.DOMAIN)
        
        self.assertFalse(result.found)
        self.assertEqual(result.confidence, 0.0)
        self.assertFalse(result.bloom_filter_match)
        
        print(f"✓ Benign IOC correctly identified: google.com")
    
    def test_lookup_ip_address(self):
        """Test IP address lookup"""
        result = self.aggregator.lookup("192.168.1.100", IOCTypes.IP_ADDRESS)
        
        self.assertTrue(result.found)
        self.assertIn("C2", result.threat_description)
        
        print(f"✓ Malicious IP detected: {result.ioc_value} - {result.threat_description}")
    
    def test_lookup_file_hash(self):
        """Test file hash lookup"""
        malware_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        result = self.aggregator.lookup(malware_hash, IOCTypes.FILE_HASH_SHA256)
        
        self.assertTrue(result.found)
        self.assertIn("Emotet", result.threat_description)
        
        print(f"✓ Malware hash detected: {result.threat_description}")
    
    def test_ioc_normalization(self):
        """Test IOC normalization for consistent matching"""
        # Different formats should normalize to same match
        result1 = self.aggregator.lookup("MALICIOUS-EXAMPLE.COM", IOCTypes.DOMAIN)
        result2 = self.aggregator.lookup("  malicious-example.com  ", IOCTypes.DOMAIN)
        result3 = self.aggregator.lookup("https://malicious-example.com/", IOCTypes.DOMAIN)
        
        self.assertTrue(result1.found)
        self.assertTrue(result2.found)
        self.assertTrue(result3.found)
        
        print("✓ IOC normalization working (case, whitespace, protocol handling)")
    
    def test_add_custom_ioc(self):
        """Test adding custom IOC to threat store"""
        custom_ioc = "new-threat-domain.xyz"
        
        # Should not exist initially
        result_before = self.aggregator.lookup(custom_ioc, IOCTypes.DOMAIN)
        self.assertFalse(result_before.found)
        
        # Add custom IOC
        self.aggregator.add_custom_ioc(
            value=custom_ioc,
            ioc_type=IOCTypes.DOMAIN,
            source="CustomFeed",
            confidence=0.90,
            description="Custom threat domain"
        )
        
        # Should now be found
        result_after = self.aggregator.lookup(custom_ioc, IOCTypes.DOMAIN)
        self.assertTrue(result_after.found)
        self.assertEqual(result_after.confidence, 0.90)
        
        print(f"✓ Custom IOC added and detected: {custom_ioc}")
    
    def test_batch_lookup(self):
        """Test batch lookup performance"""
        iocs_to_check = [
            ("malicious-example.com", IOCTypes.DOMAIN),
            ("google.com", IOCTypes.DOMAIN),
            ("192.168.1.100", IOCTypes.IP_ADDRESS),
            ("1.1.1.1", IOCTypes.IP_ADDRESS),
            ("evil-apt-domain.ru", IOCTypes.DOMAIN),
            ("safe-site.com", IOCTypes.DOMAIN),
        ]
        
        start_time = time.perf_counter_ns()
        results = self.aggregator.batch_lookup(iocs_to_check)
        total_time = (time.perf_counter_ns() - start_time) / 1000
        
        self.assertEqual(len(results), len(iocs_to_check))
        
        # Count matches
        matches = sum(1 for r in results if r.found)
        self.assertEqual(matches, 3)
        
        print(f"✓ Batch lookup: {len(iocs_to_check)} IOCs in {total_time:.2f} μs total")
        print(f"  Average: {total_time / len(iocs_to_check):.2f} μs per lookup")
    
    def test_lru_cache_functionality(self):
        """Test LRU cache hit/miss behavior"""
        # Lookup same item multiple times
        for _ in range(5):
            self.aggregator.lookup("malicious-example.com", IOCTypes.DOMAIN)
        
        stats = self.aggregator.get_statistics()
        
        # Should have at least some cache hits
        self.assertGreater(stats['cache_hits'], 0)
        self.assertGreater(stats['cache_hit_rate'], 0)
        
        print(f"✓ LRU cache working: hit rate = {stats['cache_hit_rate']:.1%}")
    
    def test_concurrent_lookups_thread_safety(self):
        """Test thread safety with concurrent lookups"""
        errors = []
        
        def lookup_worker():
            try:
                for _ in range(100):
                    self.aggregator.lookup("malicious-example.com", IOCTypes.DOMAIN)
                    self.aggregator.lookup("google.com", IOCTypes.DOMAIN)
            except Exception as e:
                errors.append(e)
        
        # Start multiple threads
        threads = [threading.Thread(target=lookup_worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        self.assertEqual(len(errors), 0, f"Thread safety errors: {errors}")
        print("✓ Thread safety verified (10 concurrent threads, 1000 lookups total)")
    
    def test_refresh_feeds(self):
        """Test feed refresh functionality"""
        stats_before = self.aggregator.get_statistics()
        refresh_result = self.aggregator.refresh_feeds()
        
        self.assertIn('feeds_processed', refresh_result)
        self.assertIn('refresh_time_ms', refresh_result)
        self.assertGreater(refresh_result['feeds_processed'], 0)
        
        print(f"✓ Feed refresh completed: {refresh_result['feeds_processed']} feeds processed")
        print(f"  Refresh time: {refresh_result['refresh_time_ms']:.2f} ms")
    
    def test_ioc_count_statistics(self):
        """Test statistics reporting"""
        stats = self.aggregator.get_statistics()
        
        self.assertIn('total_iocs', stats)
        self.assertIn('iocs_by_type', stats)
        self.assertIn('bloom_filter_items', stats)
        self.assertIn('feed_health', stats)
        
        print(f"✓ Statistics available:")
        print(f"  Total IOCs: {stats['total_iocs']}")
        print(f"  IOCs by type: {stats['iocs_by_type']}")
        print(f"  Bloom filter items: {stats['bloom_filter_items']}")
    
    def test_convenience_functions(self):
        """Test convenience wrapper functions"""
        # Test lookup function
        result = lookup_threat_ioc("malicious-example.com", IOCTypes.DOMAIN)
        self.assertTrue(result.found)
        
        # Test is_malicious function
        self.assertTrue(is_ioc_malicious("malicious-example.com", IOCTypes.DOMAIN, threshold=0.7))
        self.assertFalse(is_ioc_malicious("google.com", IOCTypes.DOMAIN, threshold=0.7))
        
        print("✓ Convenience functions working correctly")


def run_performance_benchmark():
    """Run performance benchmark"""
    print("\n" + "="*60)
    print("PERFORMANCE BENCHMARK")
    print("="*60)
    
    aggregator = ThreatFeedAggregator(
        bloom_filter_size=100000,
        enable_background_refresh=False,
        cache_size=10000
    )
    
    # Benchmark: 10,000 lookups
    num_lookups = 10000
    malicious_iocs = [
        ("malicious-example.com", IOCTypes.DOMAIN),
        ("192.168.1.100", IOCTypes.IP_ADDRESS),
    ]
    benign_iocs = [
        (f"benign-{i}.com", IOCTypes.DOMAIN) for i in range(100)
    ]
    
    all_iocs = malicious_iocs * 100 + benign_iocs * 98
    all_iocs = all_iocs[:num_lookups]
    
    start = time.perf_counter_ns()
    results = aggregator.batch_lookup(all_iocs)
    elapsed_ns = time.perf_counter_ns() - start
    
    matches = sum(1 for r in results if r.found)
    lookups_per_sec = num_lookups / (elapsed_ns / 1e9)
    avg_lookup_ns = elapsed_ns / num_lookups
    
    print(f"Total lookups:    {num_lookups:,}")
    print(f"Threat matches:   {matches}")
    print(f"Total time:       {elapsed_ns / 1e6:.2f} ms")
    print(f"Throughput:       {lookups_per_sec:,.0f} lookups/sec")
    print(f"Average latency:  {avg_lookup_ns:.2f} ns")
    
    stats = aggregator.get_statistics()
    print(f"\nCache hit rate:   {stats['cache_hit_rate']:.1%}")
    print(f"Bloom FPR est:    {stats['bloom_estimated_fpr']:.6f}")
    
    aggregator.shutdown()
    print("="*60)


def main():
    """Run all tests"""
    print("\n" + "="*60)
    print("Threat Intelligence Feed Aggregator - Test Suite")
    print("NeuralShield-AI - June 2026 Production Release")
    print("="*60 + "\n")
    
    # Run unit tests
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    suite.addTests(loader.loadTestsFromTestCase(TestBloomFilter))
    suite.addTests(loader.loadTestsFromTestCase(TestThreatFeedAggregator))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Run performance benchmark if all tests passed
    if result.wasSuccessful():
        run_performance_benchmark()
        
        # Save test results
        test_results = {
            "tests_run": result.testsRun,
            "failures": len(result.failures),
            "errors": len(result.errors),
            "success": result.wasSuccessful(),
            "timestamp": str(__import__('datetime').datetime.now()),
            "module": "threat_intelligence_feed_aggregator_bloom_filter_2026_june"
        }
        
        with open("test_results_threat_intelligence_feed_aggregator_bloom_filter.json", "w") as f:
            json.dump(test_results, f, indent=2)
        
        print("\n✓ ALL TESTS PASSED - Production Ready ✓")
        print(f"✓ Results saved to test_results_threat_intelligence_feed_aggregator_bloom_filter.json")
        
        return 0
    else:
        print("\n✗ TESTS FAILED")
        return 1


if __name__ == "__main__":
    sys.exit(main())
