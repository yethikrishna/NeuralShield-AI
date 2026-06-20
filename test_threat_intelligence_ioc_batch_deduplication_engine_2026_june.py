#!/usr/bin/env python3
"""
Test Suite for Threat Intelligence IOC Batch Deduplication Engine
NeuralShield-AI - Production Grade Tests
"""
import sys
import os
import json
from datetime import datetime, timedelta

# Add neural_shield to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from threat_intelligence_ioc_batch_deduplication_engine_2026_june import (
    IOCBatchDeduplicationEngine,
    IOCNormalizer,
    IOCType,
    DeduplicationStrategy,
    ConflictResolution,
    IOCEntry
)


def test_ioc_type_detection():
    """Test IOC type detection"""
    print("Testing IOC Type Detection...")
    
    test_cases = [
        ("192.168.1.1", IOCType.IPV4),
        ("2001:db8::1", IOCType.IPV6),
        ("example.com", IOCType.DOMAIN),
        ("www.example.com", IOCType.DOMAIN),
        ("https://example.com/path", IOCType.URL),
        ("5d41402abc4b2a76b9719d911017c592", IOCType.HASH_MD5),
        ("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d", IOCType.HASH_SHA1),
        ("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", IOCType.HASH_SHA256),
        ("user@example.com", IOCType.EMAIL),
        ("malware.exe", IOCType.FILENAME),
    ]
    
    passed = 0
    failed = 0
    for value, expected_type in test_cases:
        detected = IOCNormalizer.detect_type(value)
        if detected == expected_type:
            passed += 1
            print(f"  ✓ {value} -> {detected.value}")
        else:
            failed += 1
            print(f"  ✗ {value} -> Expected {expected_type.value}, got {detected.value}")
    
    print(f"  Type Detection: {passed}/{passed + failed} passed\n")
    return failed == 0


def test_ioc_normalization():
    """Test IOC normalization"""
    print("Testing IOC Normalization...")
    
    test_cases = [
        # IP normalization
        ("  192.168.001.001  ", "192.168.1.1"),
        # Domain normalization
        ("WWW.EXAMPLE.COM", "example.com"),
        ("Example.COM.", "example.com"),
        # URL normalization
        ("HTTPS://EXAMPLE.COM/PATH/", "https://example.com/path"),
        ("https://example.com:443/path#fragment", "https://example.com/path"),
        # Hash normalization
        ("5D41402ABC4B2A76B9719D911017C592", "5d41402abc4b2a76b9719d911017c592"),
        # Email normalization
        ("MAILTO:User@Example.COM", "user@example.com"),
    ]
    
    passed = 0
    failed = 0
    for value, expected_normalized in test_cases:
        normalized, _ = IOCNormalizer.normalize(value)
        if normalized == expected_normalized:
            passed += 1
            print(f"  ✓ '{value}' -> '{normalized}'")
        else:
            failed += 1
            print(f"  ✗ '{value}' -> Expected '{expected_normalized}', got '{normalized}'")
    
    print(f"  Normalization: {passed}/{passed + failed} passed\n")
    return failed == 0


def test_exact_deduplication():
    """Test exact match deduplication"""
    print("Testing Exact Match Deduplication...")
    
    engine = IOCBatchDeduplicationEngine(
        dedup_strategy=DeduplicationStrategy.EXACT_MATCH
    )
    
    # Create test IOCs with duplicates
    test_iocs = [
        {"value": "192.168.1.1", "source": "feed_a", "confidence": 0.8},
        {"value": "192.168.1.1", "source": "feed_b", "confidence": 0.9},  # Duplicate
        {"value": "192.168.1.2", "source": "feed_a", "confidence": 0.7},
        {"value": "192.168.1.1", "source": "feed_c", "confidence": 0.6},  # Duplicate
        {"value": "example.com", "source": "feed_b", "confidence": 0.85},
    ]
    
    result = engine.process_batch(test_iocs, "test_feed")
    
    print(f"  Input: {result.total_input} IOCs")
    print(f"  Unique: {result.unique_after_dedup} IOCs")
    print(f"  Duplicates removed: {result.duplicates_removed}")
    print(f"  Deduplication rate: {result.to_dict()['deduplication_rate']}%")
    
    # Verify
    assert result.total_input == 5, f"Expected 5 input, got {result.total_input}"
    assert result.unique_after_dedup == 3, f"Expected 3 unique, got {result.unique_after_dedup}"
    assert result.duplicates_removed == 2, f"Expected 2 duplicates, got {result.duplicates_removed}"
    
    # Check that merged IOC has multiple feed IDs
    ip_ioc = next((i for i in result.deduplicated_iocs if i.value == "192.168.1.1"), None)
    assert ip_ioc is not None, "IP IOC not found"
    assert len(ip_ioc.feed_ids) == 3, f"Expected 3 feed IDs, got {len(ip_ioc.feed_ids)}"
    assert ip_ioc.confidence == 0.9, f"Expected max confidence 0.9, got {ip_ioc.confidence}"
    
    print("  ✓ Exact deduplication working correctly\n")
    return True


def test_normalized_deduplication():
    """Test normalized match deduplication"""
    print("Testing Normalized Match Deduplication...")
    
    engine = IOCBatchDeduplicationEngine(
        dedup_strategy=DeduplicationStrategy.NORMALIZED_MATCH
    )
    
    # Create test IOCs that are same when normalized
    test_iocs = [
        {"value": "Example.COM", "source": "feed_a"},
        {"value": "www.example.com", "source": "feed_b"},  # Same when normalized
        {"value": "example.com.", "source": "feed_c"},  # Same when normalized
        {"value": "HTTPS://EXAMPLE.COM/PATH/", "source": "feed_a"},
        {"value": "https://example.com/path", "source": "feed_b"},  # Same when normalized
    ]
    
    result = engine.process_batch(test_iocs, "test_feed")
    
    print(f"  Input: {result.total_input} IOCs")
    print(f"  Unique after normalization: {result.unique_after_dedup} IOCs")
    print(f"  Normalized: {result.normalized_count} IOCs")
    
    assert result.unique_after_dedup == 2, f"Expected 2 unique normalized, got {result.unique_after_dedup}"
    
    print("  ✓ Normalized deduplication working correctly\n")
    return True


def test_conflict_resolution_strategies():
    """Test different conflict resolution strategies"""
    print("Testing Conflict Resolution Strategies...")
    
    # Test HIGHEST_CONFIDENCE
    engine = IOCBatchDeduplicationEngine(
        dedup_strategy=DeduplicationStrategy.EXACT_MATCH,
        conflict_resolution=ConflictResolution.HIGHEST_CONFIDENCE
    )
    
    test_iocs = [
        {"value": "192.168.1.1", "confidence": 0.5, "source": "low_quality"},
        {"value": "192.168.1.1", "confidence": 0.9, "source": "high_quality"},
    ]
    
    result = engine.process_batch(test_iocs)
    ioc = result.deduplicated_iocs[0]
    assert ioc.confidence == 0.9, f"Expected 0.9 confidence, got {ioc.confidence}"
    print("  ✓ HIGHEST_CONFIDENCE strategy working")
    
    # Test MOST_TRUSTED_SOURCE
    engine2 = IOCBatchDeduplicationEngine(
        dedup_strategy=DeduplicationStrategy.EXACT_MATCH,
        conflict_resolution=ConflictResolution.MOST_TRUSTED_SOURCE,
        trusted_sources=["virustotal", "alienvault"]
    )
    
    test_iocs2 = [
        {"value": "malware.com", "source": "random_feed", "confidence": 0.5},
        {"value": "malware.com", "source": "virustotal", "confidence": 0.7},
    ]
    
    result2 = engine2.process_batch(test_iocs2)
    ioc2 = result2.deduplicated_iocs[0]
    assert ioc2.source == "virustotal", f"Expected trusted source, got {ioc2.source}"
    assert ioc2.confidence > 0.5, f"Expected boosted confidence"
    print("  ✓ MOST_TRUSTED_SOURCE strategy working")
    
    print("  ✓ All conflict resolution strategies working\n")
    return True


def test_ttl_expiration():
    """Test TTL-based expiration filtering"""
    print("Testing TTL Expiration...")
    
    engine = IOCBatchDeduplicationEngine(
        remove_expired=True,
        default_ttl_days=90
    )
    
    old_date = (datetime.now() - timedelta(days=100)).isoformat()
    
    test_iocs = [
        {"value": "active-ioc.com", "last_seen": datetime.now().isoformat()},
        {"value": "expired-ioc.com", "last_seen": old_date, "ttl_days": 30},
    ]
    
    result = engine.process_batch(test_iocs)
    
    print(f"  Expired removed: {result.expired_removed}")
    assert result.expired_removed == 1, f"Expected 1 expired, got {result.expired_removed}"
    assert result.unique_after_dedup == 1, f"Expected 1 active, got {result.unique_after_dedup}"
    
    # Test without expiration removal
    engine2 = IOCBatchDeduplicationEngine(remove_expired=False)
    result2 = engine2.process_batch(test_iocs)
    assert result2.expired_removed == 0, "Expected 0 expired removed"
    
    print("  ✓ TTL expiration working correctly\n")
    return True


def test_multi_feed_merge():
    """Test merging multiple feeds"""
    print("Testing Multi-Feed Merge...")
    
    engine = IOCBatchDeduplicationEngine()
    
    feed1 = [
        {"value": "192.168.1.1", "source": "feed1"},
        {"value": "10.0.0.1", "source": "feed1"},
    ]
    
    feed2 = [
        {"value": "192.168.1.1", "source": "feed2"},  # Overlap
        {"value": "172.16.0.1", "source": "feed2"},
    ]
    
    result = engine.merge_batches([feed1, feed2], ["feed1", "feed2"])
    
    print(f"  Total input: {result.total_input}")
    print(f"  Unique after merge: {result.unique_after_dedup}")
    
    assert result.total_input == 4
    assert result.unique_after_dedup == 3
    
    # Check overlapping IOC has both feed IDs
    overlapping = next((i for i in result.deduplicated_iocs if i.value == "192.168.1.1"), None)
    assert overlapping is not None
    assert "feed1" in overlapping.feed_ids
    assert "feed2" in overlapping.feed_ids
    
    print("  ✓ Multi-feed merge working correctly\n")
    return True


def test_json_export():
    """Test JSON export functionality"""
    print("Testing JSON Export...")
    
    engine = IOCBatchDeduplicationEngine()
    
    test_iocs = [
        {"value": "192.168.1.1", "source": "test", "confidence": 0.8},
        {"value": "example.com", "source": "test", "confidence": 0.9},
    ]
    
    result = engine.process_batch(test_iocs)
    
    output_path = "/home/user/autonomous-developer/NeuralShield-AI/test_results_ioc_batch_deduplication_engine.json"
    success = engine.export_json(result, output_path)
    
    assert success, "Export failed"
    
    # Verify file exists and is valid JSON
    with open(output_path, 'r') as f:
        data = json.load(f)
    
    assert "summary" in data
    assert "iocs" in data
    assert len(data["iocs"]) == 2
    assert data["summary"]["total_input"] == 2
    
    print(f"  ✓ JSON exported to {output_path}")
    print("  ✓ JSON export working correctly\n")
    return True


def test_ioc_entry_properties():
    """Test IOCEntry computed properties"""
    print("Testing IOCEntry Properties...")
    
    # Test is_expired
    old_entry = IOCEntry(
        value="test.com",
        ioc_type=IOCType.DOMAIN,
        last_seen=datetime.now() - timedelta(days=100),
        ttl_days=30
    )
    assert old_entry.is_expired == True
    
    new_entry = IOCEntry(
        value="test.com",
        ioc_type=IOCType.DOMAIN,
        last_seen=datetime.now(),
        ttl_days=30
    )
    assert new_entry.is_expired == False
    
    # Test age_days
    assert old_entry.age_days >= 0
    assert new_entry.age_days >= 0
    
    # Test to_dict
    d = new_entry.to_dict()
    assert "value" in d
    assert "ioc_type" in d
    assert "is_expired" in d
    assert "age_days" in d
    
    print("  ✓ IOCEntry properties working correctly\n")
    return True


def run_all_tests():
    """Run all tests and generate report"""
    print("=" * 70)
    print("NeuralShield-AI - IOC Batch Deduplication Engine Test Suite")
    print("=" * 70 + "\n")
    
    tests = [
        test_ioc_type_detection,
        test_ioc_normalization,
        test_exact_deduplication,
        test_normalized_deduplication,
        test_conflict_resolution_strategies,
        test_ttl_expiration,
        test_multi_feed_merge,
        test_json_export,
        test_ioc_entry_properties,
    ]
    
    results = []
    for test in tests:
        try:
            results.append(test())
        except Exception as e:
            print(f"  ✗ Test failed with exception: {e}\n")
            results.append(False)
    
    passed = sum(results)
    total = len(results)
    
    print("=" * 70)
    print(f"TEST SUMMARY: {passed}/{total} tests passed")
    print("=" * 70)
    
    if passed == total:
        print("\n✓ ALL TESTS PASSED - Production Ready!")
        return True
    else:
        print(f"\n✗ {total - passed} TEST(S) FAILED")
        return False


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
