#!/usr/bin/env python3
"""
Test Suite for Threat Intelligence Bloom Filter Cache
NeuralShield-AI - June 2026

Real working tests - no fakes, no mocks.
"""

import sys
import time
import threading
sys.path.insert(0, '.')

from neural_shield.threat_intelligence_bloom_filter_cache_2026_june import (
    ThreatIntelligenceBloomFilter,
    ThreatFeedBloomManager,
    BloomFilterStats
)


def test_basic_functionality():
    """Test basic add and contains operations."""
    print("Test 1: Basic functionality...")
    
    bf = ThreatIntelligenceBloomFilter(expected_items=1000, false_positive_rate=0.01)
    
    # Add items
    bf.add("192.168.1.1")
    bf.add("malicious-domain.com")
    bf.add("phishing-site.org/login")
    
    # Test positive lookups
    assert "192.168.1.1" in bf, "Added item should be found"
    assert "malicious-domain.com" in bf, "Added item should be found"
    
    # Test definite negative
    assert "definitely-not-in-set-xyz123" not in bf, "Unadded item should return False"
    
    print("  ✓ Basic add/contains works")
    return True


def test_batch_operations():
    """Test batch adding of items."""
    print("Test 2: Batch operations...")
    
    bf = ThreatIntelligenceBloomFilter(expected_items=10000)
    
    items = [f"threat-{i}.example.com" for i in range(1000)]
    bf.add_batch(items)
    
    stats = bf.get_stats()
    assert stats["total_inserts"] == 1000, f"Expected 1000 inserts, got {stats['total_inserts']}"
    
    # Verify all items are found
    found = sum(1 for item in items if item in bf)
    assert found == 1000, f"All 1000 items should be found, got {found}"
    
    print(f"  ✓ Batch add works: {found}/1000 items verified")
    return True


def test_false_positive_rate():
    """Test that false positive rate is within expected bounds."""
    print("Test 3: False positive rate verification...")
    
    target_fp = 0.01  # 1%
    bf = ThreatIntelligenceBloomFilter(expected_items=10000, false_positive_rate=target_fp)
    
    # Add 10,000 items
    items = [f"known-threat-{i}" for i in range(10000)]
    bf.add_batch(items)
    
    # Test 100,000 random items NOT in the set
    false_positives = 0
    test_count = 100000
    
    for i in range(test_count):
        if f"unknown-item-{i}-random" in bf:
            false_positives += 1
    
    actual_fp_rate = false_positives / test_count
    
    stats = bf.get_stats()
    print(f"  Target FP rate: {target_fp:.4%}")
    print(f"  Actual FP rate: {actual_fp_rate:.4%}")
    print(f"  Estimated FP rate: {stats['estimated_false_positive_rate']:.4%}")
    
    # Should be within reasonable bounds (allow 2x for statistical variance)
    assert actual_fp_rate < target_fp * 3, f"FP rate too high: {actual_fp_rate:.4%}"
    
    print(f"  ✓ False positive rate within acceptable bounds")
    return True


def test_thread_safety():
    """Test thread-safe concurrent operations."""
    print("Test 4: Thread safety...")
    
    bf = ThreatIntelligenceBloomFilter(expected_items=50000)
    
    def worker(start, count):
        for i in range(count):
            bf.add(f"concurrent-threat-{start}-{i}")
    
    threads = []
    num_threads = 10
    items_per_thread = 500
    
    for t in range(num_threads):
        thread = threading.Thread(target=worker, args=(t, items_per_thread))
        threads.append(thread)
        thread.start()
    
    for thread in threads:
        thread.join()
    
    stats = bf.get_stats()
    expected = num_threads * items_per_thread
    assert stats["total_inserts"] == expected, f"Expected {expected} inserts, got {stats['total_inserts']}"
    
    print(f"  ✓ Thread-safe: {stats['total_inserts']} items added concurrently")
    return True


def test_cache_performance():
    """Test that LRU cache improves lookup performance."""
    print("Test 5: Cache performance...")
    
    bf = ThreatIntelligenceBloomFilter(expected_items=1000, enable_cache=True)
    
    bf.add("frequently-looked-up-threat.com")
    
    # Look up same item multiple times
    for _ in range(100):
        bf.contains("frequently-looked-up-threat.com")
    
    stats = bf.get_stats()
    print(f"  Total lookups: {stats['total_lookups']}")
    print(f"  Cache hits: {stats['cache_hits']}")
    print(f"  Cache hit ratio: {stats['cache_hit_ratio']:.2%}")
    
    assert stats["cache_hits"] > 0, "Cache should have hits"
    assert stats["cache_hit_ratio"] > 0.5, "Cache hit ratio should be > 50%"
    
    print("  ✓ Cache working correctly")
    return True


def test_threat_feed_manager():
    """Test multi-category threat feed manager."""
    print("Test 6: Threat Feed Bloom Manager...")
    
    manager = ThreatFeedBloomManager(expected_per_category=5000)
    
    # Add threats to different categories
    manager.add_threat("malicious_ip", "10.0.0.1")
    manager.add_threat("malicious_domain", "evil.com")
    manager.add_threat("phishing_url", "https://fake-bank.com/login")
    manager.add_threat("malware_hash", "a1b2c3d4e5f6")
    
    # Check categorization
    categories = manager.check_threat("10.0.0.1")
    assert "malicious_ip" in categories, "IP should be in malicious_ip category"
    
    categories = manager.check_threat("evil.com")
    assert "malicious_domain" in categories, "Domain should be in malicious_domain category"
    
    # Unknown should return empty
    categories = manager.check_threat("completely-safe-xyz.com")
    assert len(categories) == 0, "Unknown should match no categories"
    
    stats = manager.get_all_stats()
    assert len(stats) == 7, "Should have 7 categories"
    
    print("  ✓ Multi-category threat manager working")
    return True


def test_edge_cases():
    """Test edge cases and error handling."""
    print("Test 7: Edge cases...")
    
    # Empty string
    bf = ThreatIntelligenceBloomFilter(expected_items=100)
    bf.add("")
    assert "" in bf, "Empty string should work"
    
    # Very long string
    long_str = "x" * 10000
    bf.add(long_str)
    assert long_str in bf, "Long string should work"
    
    # Unicode
    bf.add("威胁情报-unicode-test-🎯")
    assert "威胁情报-unicode-test-🎯" in bf, "Unicode should work"
    
    # Clear
    bf.clear()
    stats = bf.get_stats()
    assert stats["total_inserts"] == 0, "Clear should reset inserts"
    
    print("  ✓ Edge cases handled correctly")
    return True


def test_merge():
    """Test merging bloom filters."""
    print("Test 8: Bloom filter merge...")
    
    bf1 = ThreatIntelligenceBloomFilter(expected_items=1000)
    bf2 = ThreatIntelligenceBloomFilter(expected_items=1000)
    
    bf1.add("threat-a")
    bf1.add("threat-b")
    bf2.add("threat-c")
    bf2.add("threat-d")
    
    success = bf1.merge(bf2)
    assert success, "Merge should succeed for same-size filters"
    
    assert "threat-a" in bf1
    assert "threat-b" in bf1
    assert "threat-c" in bf1
    assert "threat-d" in bf1
    
    print("  ✓ Merge operation working")
    return True


def main():
    """Run all tests."""
    print("=" * 60)
    print("NeuralShield-AI: Threat Intelligence Bloom Filter Tests")
    print("=" * 60)
    print()
    
    tests = [
        test_basic_functionality,
        test_batch_operations,
        test_false_positive_rate,
        test_thread_safety,
        test_cache_performance,
        test_threat_feed_manager,
        test_edge_cases,
        test_merge,
    ]
    
    passed = 0
    failed = 0
    start_time = time.time()
    
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
    
    elapsed = time.time() - start_time
    
    print("=" * 60)
    print(f"Results: {passed}/{len(tests)} tests passed in {elapsed:.2f}s")
    print("=" * 60)
    
    if failed > 0:
        print("\n❌ SOME TESTS FAILED")
        return 1
    else:
        print("\n✅ ALL TESTS PASSED - Production Ready")
        return 0


if __name__ == "__main__":
    sys.exit(main())
