#!/usr/bin/env python3
"""
Test Suite for NeuralShield AI - IOC Normalization & Batch Deduplication Engine V2
Production-grade tests with real-world scenarios
"""

import sys
import os
import json
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from threat_intelligence_ioc_normalization_batch_deduplication_engine_v2_2026_june import (
    IOCNormalizer,
    IOCBatchDeduplicationEngine,
    LRUCache,
    BloomFilter,
    NormalizedIOC,
    IOCTypes
)


def test_lru_cache_basic():
    """Test LRU Cache basic functionality"""
    print("Testing LRU Cache...")
    cache = LRUCache(capacity=3)

    # Create test IOCs
    ioc1 = NormalizedIOC("192.168.1.1", "192.168.1.1", IOCTypes.IPV4, 0.98)
    ioc2 = NormalizedIOC("evil.com", "evil.com", IOCTypes.DOMAIN, 0.92)
    ioc3 = NormalizedIOC("test@test.com", "test@test.com", IOCTypes.EMAIL, 0.95)
    ioc4 = NormalizedIOC("8.8.8.8", "8.8.8.8", IOCTypes.IPV4, 0.98)

    cache.put("key1", ioc1)
    cache.put("key2", ioc2)
    cache.put("key3", ioc3)

    assert len(cache) == 3, "Cache should have 3 items"
    assert cache.get("key1") == ioc1, "Should retrieve key1"

    # Add 4th item - should evict oldest
    cache.put("key4", ioc4)
    assert len(cache) == 3, "Cache should still have 3 items"
    assert cache.get("key2") is None, "key2 should be evicted"

    print("  ✓ LRU Cache basic functionality PASSED")
    return True


def test_bloom_filter_basic():
    """Test Bloom Filter basic functionality"""
    print("Testing Bloom Filter...")
    bf = BloomFilter(size=1000, hash_count=3)

    bf.add("test_ioc_1")
    bf.add("test_ioc_2")

    assert bf.might_contain("test_ioc_1") == True, "Should contain test_ioc_1"
    assert bf.might_contain("test_ioc_2") == True, "Should contain test_ioc_2"
    assert bf.might_contain("test_ioc_3") == False, "Should not contain test_ioc_3"

    bf.clear()
    assert bf.might_contain("test_ioc_1") == False, "Should be empty after clear"

    print("  ✓ Bloom Filter basic functionality PASSED")
    return True


def test_ioc_type_detection():
    """Test IOC Type Detection"""
    print("Testing IOC Type Detection...")

    test_cases = [
        ("192.168.1.1", IOCTypes.IPV4),
        ("2001:db8::1", IOCTypes.IPV6),
        ("evil.com", IOCTypes.DOMAIN),
        ("http://evil.com/path", IOCTypes.URL),
        ("https://test.com/page?q=1", IOCTypes.URL),
        ("d41d8cd98f00b204e9800998ecf8427e", IOCTypes.MD5),
        ("da39a3ee5e6b4b0d3255bfef95601890afd80709", IOCTypes.SHA1),
        ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", IOCTypes.SHA256),
        ("user@example.com", IOCTypes.EMAIL),
    ]

    all_passed = True
    for value, expected_type in test_cases:
        detected = IOCNormalizer.detect_type(value)
        if detected != expected_type:
            print(f"  ✗ FAIL: {value} -> detected {detected}, expected {expected_type}")
            all_passed = False

    if all_passed:
        print("  ✓ IOC Type Detection PASSED")
    return all_passed


def test_ioc_normalization():
    """Test IOC Normalization"""
    print("Testing IOC Normalization...")

    test_cases = [
        ("  EVIL.COM  ", "evil.com", IOCTypes.DOMAIN),
        ("HTTP://EXAMPLE.COM/PATH/", "example.com/path", IOCTypes.URL),
        ("192.168.001.001", "192.168.1.1", IOCTypes.IPV4),
        ("D41D8CD98F00B204E9800998ECF8427E", "d41d8cd98f00b204e9800998ecf8427e", IOCTypes.MD5),
        ("USER@EXAMPLE.COM", "user@example.com", IOCTypes.EMAIL),
    ]

    all_passed = True
    for input_val, expected_norm, expected_type in test_cases:
        normalized, ioc_type, confidence = IOCNormalizer.normalize(input_val)
        if normalized != expected_norm:
            print(f"  ✗ FAIL: '{input_val}' -> normalized to '{normalized}', expected '{expected_norm}'")
            all_passed = False

    if all_passed:
        print("  ✓ IOC Normalization PASSED")
    return all_passed


def test_single_ioc_processing():
    """Test single IOC processing"""
    print("Testing Single IOC Processing...")
    engine = IOCBatchDeduplicationEngine()

    # First occurrence
    ioc1, is_dup1 = engine.process_single("192.168.1.1", "source1")
    assert is_dup1 == False, "First occurrence should not be duplicate"
    assert ioc1.occurrence_count == 1, "Count should be 1"

    # Second occurrence - should be duplicate
    ioc2, is_dup2 = engine.process_single("192.168.1.1", "source2")
    assert is_dup2 == True, "Second occurrence should be duplicate"
    assert ioc2.occurrence_count == 2, "Count should be 2"
    assert "source2" in ioc2.source_tags, "Should have both source tags"

    print("  ✓ Single IOC Processing PASSED")
    return True


def test_batch_deduplication():
    """Test batch deduplication with real-world data"""
    print("Testing Batch Deduplication...")
    engine = IOCBatchDeduplicationEngine()

    # Create test data with duplicates
    test_iocs = [
        "192.168.1.1",
        "evil.com",
        "192.168.1.1",  # duplicate
        "test@example.com",
        "EVIL.COM",  # duplicate (case insensitive)
        "8.8.8.8",
        "evil.com",  # duplicate
        "http://malware.com/download",
    ]

    result = engine.process_batch(test_iocs, source_tag="test_feed")

    stats = result["statistics"]
    unique_count = len(result["unique_iocs"])

    assert stats["total_processed"] == 8, f"Should process 8 IOCs, got {stats['total_processed']}"
    assert unique_count == 5, f"Should have 5 unique IOCs, got {unique_count}"
    assert stats["total_duplicates"] == 3, f"Should find 3 duplicates, got {stats['total_duplicates']}"
    assert stats["deduplication_rate"] > 0.3, "Deduplication rate should be > 30%"

    print(f"  ✓ Batch Deduplication PASSED: {unique_count} unique, {stats['total_duplicates']} duplicates")
    print(f"    Rate: {stats['deduplication_rate']:.2%}, Speed: {stats['iocs_per_second']:.0f} iocs/sec")
    return True


def test_large_batch_performance():
    """Test performance with large batch"""
    print("Testing Large Batch Performance...")
    engine = IOCBatchDeduplicationEngine(lru_capacity=10000)

    # Generate 1000 IOCs with 50% duplicates
    test_iocs = []
    for i in range(500):
        test_iocs.append(f"192.168.{i//256}.{i%256}")
    for i in range(500):  # duplicates
        test_iocs.append(f"192.168.{i//256}.{i%256}")

    result = engine.process_batch(test_iocs)
    stats = result["statistics"]

    assert stats["total_processed"] == 1000
    assert len(result["unique_iocs"]) == 500
    assert stats["iocs_per_second"] > 1000, f"Should process > 1000 iocs/sec, got {stats['iocs_per_second']:.0f}"

    print(f"  ✓ Large Batch Performance PASSED: {stats['iocs_per_second']:.0f} iocs/sec")
    return True


def test_export_and_statistics():
    """Test export functionality and statistics"""
    print("Testing Export & Statistics...")
    engine = IOCBatchDeduplicationEngine()

    test_iocs = ["192.168.1.1", "evil.com", "test@example.com"]
    engine.process_batch(test_iocs)

    # Test JSON export
    json_export = engine.export_unique_iocs(format_json=True)
    data = json.loads(json_export)
    assert len(data) == 3, "Should export 3 IOCs"

    # Test statistics
    stats = engine.get_statistics()
    assert stats["total_processed"] == 3
    assert stats["total_unique"] == 3
    assert stats["cache_utilization"] < 1.0

    print("  ✓ Export & Statistics PASSED")
    return True


def test_type_distribution():
    """Test IOC type distribution tracking"""
    print("Testing Type Distribution...")
    engine = IOCBatchDeduplicationEngine()

    test_iocs = [
        "192.168.1.1", "8.8.8.8",  # 2 IPs
        "evil.com", "malware.net",  # 2 domains
        "http://test.com",  # 1 URL
        "d41d8cd98f00b204e9800998ecf8427e",  # 1 MD5
    ]

    result = engine.process_batch(test_iocs)
    dist = result["type_distribution"]

    assert dist.get("ipv4", 0) == 2, f"Expected 2 IPv4, got {dist.get('ipv4')}"
    assert dist.get("domain", 0) == 2, f"Expected 2 domains, got {dist.get('domain')}"
    assert dist.get("url", 0) == 1, f"Expected 1 URL, got {dist.get('url')}"

    print(f"  ✓ Type Distribution PASSED: {dist}")
    return True


def run_all_tests():
    """Run all tests and generate report"""
    print("=" * 70)
    print("NeuralShield AI - IOC Normalization & Batch Deduplication Engine V2")
    print("PRODUCTION TEST SUITE")
    print("=" * 70)

    tests = [
        test_lru_cache_basic,
        test_bloom_filter_basic,
        test_ioc_type_detection,
        test_ioc_normalization,
        test_single_ioc_processing,
        test_batch_deduplication,
        test_large_batch_performance,
        test_export_and_statistics,
        test_type_distribution,
    ]

    results = []
    start_time = time.time()

    for test in tests:
        try:
            result = test()
            results.append((test.__name__, result))
        except Exception as e:
            print(f"  ✗ EXCEPTION in {test.__name__}: {e}")
            results.append((test.__name__, False))

    elapsed = time.time() - start_time

    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)

    passed = sum(1 for _, r in results if r)
    total = len(results)

    for name, result in results:
        status = "PASS" if result else "FAIL"
        print(f"  {status}: {name}")

    print(f"\nTotal: {passed}/{total} tests passed in {elapsed:.3f}s")

    # Save test results
    test_results = {
        "test_suite": "IOC Normalization & Batch Deduplication Engine V2",
        "tests_passed": passed,
        "tests_total": total,
        "pass_rate": passed / total,
        "execution_time_seconds": elapsed,
        "results": {name: result for name, result in results}
    }

    with open("test_results_ioc_normalization_batch_deduplication_engine_v2.json", "w") as f:
        json.dump(test_results, f, indent=2)

    print(f"\nTest results saved to test_results_ioc_normalization_batch_deduplication_engine_v2.json")

    return passed == total


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
