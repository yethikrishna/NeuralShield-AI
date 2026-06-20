#!/usr/bin/env python3
"""
Test suite for Threat Intelligence IoC Batch Deduplication & Normalization Engine
NeuralShield-AI - Production-grade testing
"""

import sys
import json
import time
import importlib.util

# Direct import to avoid __init__.py issues
spec = importlib.util.spec_from_file_location(
    "ioc_engine",
    "./neural_shield/threat_intelligence_ioc_batch_deduplication_normalization_engine_2026_june.py"
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

IoCBatchDeduplicationEngine = module.IoCBatchDeduplicationEngine
IoCNormalizer = module.IoCNormalizer
IoCType = module.IoCType
BloomFilter = module.BloomFilter
IoCEntry = module.IoCEntry


def test_ioc_type_detection():
    """Test IoC type detection functionality"""
    print("=== Testing IoC Type Detection ===")
    
    test_cases = [
        ("192.168.1.1", IoCType.IPV4),
        ("2001:db8::1", IoCType.IPV6),
        ("example.com", IoCType.DOMAIN),
        ("www.google.com", IoCType.DOMAIN),
        ("http://example.com/path", IoCType.URL),
        ("https://test.org:443/page?q=1#frag", IoCType.URL),
        ("d41d8cd98f00b204e9800998ecf8427e", IoCType.MD5),
        ("da39a3ee5e6b4b0d3255bfef95601890afd80709", IoCType.SHA1),
        ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", IoCType.SHA256),
        ("user@example.com", IoCType.EMAIL),
        ("not_an_ioc_12345", IoCType.UNKNOWN),
    ]
    
    passed = 0
    failed = 0
    
    for value, expected_type in test_cases:
        detected = IoCNormalizer.detect_type(value)
        if detected == expected_type:
            passed += 1
            print(f"  ✓ {value} -> {detected.value}")
        else:
            failed += 1
            print(f"  ✗ {value} -> Expected {expected_type.value}, got {detected.value}")
    
    print(f"  Results: {passed} passed, {failed} failed")
    return failed == 0


def test_ioc_normalization():
    """Test IoC normalization functionality"""
    print("\n=== Testing IoC Normalization ===")
    
    test_cases = [
        # IP normalization
        ("  192.168.001.001  ", "192.168.1.1", IoCType.IPV4),
        # Domain normalization
        ("EXAMPLE.COM", "example.com", IoCType.DOMAIN),
        ("WWW.GOOGLE.COM.", "google.com", IoCType.DOMAIN),
        # Hash normalization
        ("D41D8CD98F00B204E9800998ECF8427E", "d41d8cd98f00b204e9800998ecf8427e", IoCType.MD5),
        # URL normalization
        ("HTTP://EXAMPLE.COM:80/", "http://example.com", IoCType.URL),
        ("HTTPS://TEST.ORG/PATH#FRAGMENT", "https://test.org/path", IoCType.URL),
        # Email normalization
        ("USER@EXAMPLE.COM", "user@example.com", IoCType.EMAIL),
    ]
    
    passed = 0
    failed = 0
    
    for value, expected_norm, expected_type in test_cases:
        normalized, norm_type = IoCNormalizer.normalize(value)
        if normalized == expected_norm and norm_type == expected_type:
            passed += 1
            print(f"  ✓ '{value}' -> '{normalized}' ({norm_type.value})")
        else:
            failed += 1
            print(f"  ✗ '{value}' -> Expected '{expected_norm}', got '{normalized}'")
    
    print(f"  Results: {passed} passed, {failed} failed")
    return failed == 0


def test_bloom_filter():
    """Test Bloom filter functionality"""
    print("\n=== Testing Bloom Filter ===")
    
    bf = BloomFilter(size=1000, num_hashes=5)
    
    # Add some values
    test_values = ["192.168.1.1", "example.com", "test_hash"]
    for v in test_values:
        bf.add(v)
    
    passed = 0
    failed = 0
    
    # Test definite non-members
    non_members = ["not_added_1", "not_added_2", "10.0.0.1"]
    for v in non_members:
        if not bf.might_contain(v):
            passed += 1
            print(f"  ✓ '{v}' correctly identified as not present")
        else:
            failed += 1
            print(f"  ✗ '{v}' false positive (expected not present)")
    
    # Test members (should always return True)
    for v in test_values:
        if bf.might_contain(v):
            passed += 1
            print(f"  ✓ '{v}' correctly identified as possibly present")
        else:
            failed += 1
            print(f"  ✗ '{v}' should be present")
    
    print(f"  Results: {passed} passed, {failed} failed")
    return failed == 0


def test_exact_deduplication():
    """Test exact duplicate removal"""
    print("\n=== Testing Exact Deduplication ===")
    
    engine = IoCBatchDeduplicationEngine()
    
    # Test with duplicates
    iocs_with_duplicates = [
        "192.168.1.1",
        "192.168.1.1",  # duplicate
        "192.168.1.1",  # duplicate
        "example.com",
        "EXAMPLE.COM",  # normalized duplicate
        "Example.Com",  # normalized duplicate
        "d41d8cd98f00b204e9800998ecf8427e",
        "D41D8CD98F00B204E9800998ECF8427E",  # normalized duplicate
    ]
    
    result = engine.process_batch(iocs_with_duplicates)
    
    print(f"  Total input: {result['statistics']['total_input']}")
    print(f"  Unique IoCs: {result['statistics']['unique_iocs']}")
    print(f"  Exact duplicates removed: {result['statistics']['exact_duplicates_removed']}")
    print(f"  Processing time: {result['processing_time_ms']}ms")
    
    # Expected: 3 unique (1 IP, 1 domain, 1 hash)
    expected_unique = 3
    if result['statistics']['unique_iocs'] == expected_unique:
        print(f"  ✓ Correctly identified {expected_unique} unique IoCs")
        success = True
    else:
        print(f"  ✗ Expected {expected_unique} unique IoCs, got {result['statistics']['unique_iocs']}")
        success = False
    
    return success


def test_fuzzy_deduplication():
    """Test fuzzy duplicate detection"""
    print("\n=== Testing Fuzzy Deduplication ===")
    
    engine = IoCBatchDeduplicationEngine(fuzzy_match_threshold=0.9)
    
    # Test with similar domains (typos)
    iocs = [
        "google.com",
        "goog1e.com",  # typo, similar
        "example.com",
        "examples.com",  # slightly different
    ]
    
    result = engine.process_batch(iocs)
    
    print(f"  Total input: {result['statistics']['total_input']}")
    print(f"  Unique IoCs: {result['statistics']['unique_iocs']}")
    print(f"  Fuzzy duplicates removed: {result['statistics']['fuzzy_duplicates_removed']}")
    
    # Verify we have unique entries
    unique_domains = [ioc.normalized_value for ioc in result['unique_iocs']]
    print(f"  Unique domains: {unique_domains}")
    
    print("  ✓ Fuzzy matching completed successfully")
    return True


def test_performance():
    """Test performance with large batch"""
    print("\n=== Testing Performance ===")
    
    engine = IoCBatchDeduplicationEngine()
    
    # Generate test data
    base_iocs = [
        "192.168.1.1", "10.0.0.1", "172.16.0.1",
        "example.com", "google.com", "github.com",
        "d41d8cd98f00b204e9800998ecf8427e",
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    ]
    
    # Create a large batch with duplicates
    large_batch = []
    for i in range(100):
        for ioc in base_iocs:
            large_batch.append(ioc)
    
    print(f"  Processing {len(large_batch)} IoCs...")
    
    start = time.time()
    result = engine.process_batch(large_batch)
    elapsed = time.time() - start
    
    print(f"  Total input: {result['statistics']['total_input']}")
    print(f"  Unique IoCs: {result['statistics']['unique_iocs']}")
    print(f"  Duplicates removed: {result['duplicates_removed']}")
    print(f"  Processing time: {elapsed*1000:.2f}ms")
    print(f"  Throughput: {len(large_batch)/elapsed:.0f} IoCs/sec")
    
    # Verify all base IoCs are present
    if result['statistics']['unique_iocs'] == len(base_iocs):
        print(f"  ✓ Performance test passed - all duplicates removed efficiently")
        success = True
    else:
        print(f"  ✗ Expected {len(base_iocs)} unique, got {result['statistics']['unique_iocs']}")
        success = False
    
    return success


def test_type_grouping():
    """Test IoC type grouping"""
    print("\n=== Testing Type Grouping ===")
    
    engine = IoCBatchDeduplicationEngine()
    
    mixed_iocs = [
        "192.168.1.1", "10.0.0.1",  # IPs
        "example.com", "google.com",  # domains
        "http://test.com", "https://example.org",  # URLs
        "d41d8cd98f00b204e9800998ecf8427e",  # MD5
        "user@example.com",  # email
    ]
    
    engine.process_batch(mixed_iocs)
    
    ipv4_count = len(engine.get_iocs_by_type(IoCType.IPV4))
    domain_count = len(engine.get_iocs_by_type(IoCType.DOMAIN))
    url_count = len(engine.get_iocs_by_type(IoCType.URL))
    md5_count = len(engine.get_iocs_by_type(IoCType.MD5))
    email_count = len(engine.get_iocs_by_type(IoCType.EMAIL))
    
    print(f"  IPv4: {ipv4_count}")
    print(f"  Domains: {domain_count}")
    print(f"  URLs: {url_count}")
    print(f"  MD5: {md5_count}")
    print(f"  Email: {email_count}")
    
    expected = [2, 2, 2, 1, 1]
    actual = [ipv4_count, domain_count, url_count, md5_count, email_count]
    
    if expected == actual:
        print("  ✓ Type grouping correct")
        return True
    else:
        print(f"  ✗ Expected {expected}, got {actual}")
        return False


def main():
    """Run all tests"""
    print("=" * 60)
    print("NeuralShield-AI - IoC Batch Deduplication Engine Tests")
    print("=" * 60)
    
    tests = [
        test_ioc_type_detection,
        test_ioc_normalization,
        test_bloom_filter,
        test_exact_deduplication,
        test_fuzzy_deduplication,
        test_performance,
        test_type_grouping,
    ]
    
    results = []
    for test in tests:
        try:
            results.append(test())
        except Exception as e:
            print(f"  ✗ Exception: {e}")
            results.append(False)
    
    print("\n" + "=" * 60)
    passed = sum(results)
    total = len(results)
    print(f"TEST SUMMARY: {passed}/{total} tests passed")
    
    # Save results
    test_output = {
        'test_name': 'threat_intelligence_ioc_batch_deduplication_normalization_engine',
        'tests_passed': passed,
        'tests_total': total,
        'success_rate': passed / total if total > 0 else 0,
        'timestamp': time.time()
    }
    
    with open('test_results_ioc_batch_deduplication_engine.json', 'w') as f:
        json.dump(test_output, f, indent=2)
    
    print(f"Results saved to test_results_ioc_batch_deduplication_engine.json")
    print("=" * 60)
    
    return passed == total


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
