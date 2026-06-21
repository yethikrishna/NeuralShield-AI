#!/usr/bin/env python3
"""
Test suite for Threat Intelligence Feed Aggregator with Bloom Filter v2
NeuralShield-AI - Production-grade testing
"""

import sys
import os
import json
import time
import tempfile

# Add neural_shield to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from threat_intelligence_feed_aggregator_bloom_filter_v2_2026_june import (
    BloomFilter,
    IOCEntry,
    ThreatFeedAggregator
)
from datetime import datetime, timedelta


def test_bloom_filter_basic():
    """Test basic bloom filter functionality"""
    print("=" * 60)
    print("TEST 1: Bloom Filter Basic Operations")
    print("=" * 60)

    bf = BloomFilter(expected_items=1000, false_positive_rate=0.001)

    # Add items
    test_items = ["192.168.1.1", "malicious.com", "http://phish.net", "deadbeef1234"]
    for item in test_items:
        bf.add(item)

    # Check items exist
    all_found = True
    for item in test_items:
        if not bf.contains(item):
            print(f"  FAIL: {item} not found in bloom filter")
            all_found = False

    # Check non-existent items (should mostly be False)
    false_positives = 0
    non_existent = ["safe.com", "10.0.0.1", "google.com", "not-in-filter"]
    for item in non_existent:
        if bf.contains(item):
            false_positives += 1

    stats = bf.get_stats()
    print(f"  Items added: {stats['items_added']}")
    print(f"  Memory usage: {stats['memory_kb']:.2f} KB")
    print(f"  Hash functions: {stats['hash_count']}")
    print(f"  False positives in test: {false_positives}/{len(non_existent)}")

    assert all_found, "All added items should be found"
    print("  ✓ PASS: Bloom filter basic operations working")
    return True


def test_bloom_filter_memory_efficiency():
    """Test bloom filter memory efficiency"""
    print("\n" + "=" * 60)
    print("TEST 2: Bloom Filter Memory Efficiency")
    print("=" * 60)

    # 50,000 items with 0.05% false positive rate
    bf = BloomFilter(expected_items=50000, false_positive_rate=0.0005)
    stats = bf.get_stats()

    print(f"  Expected items: 50,000")
    print(f"  Bit array size: {stats['size_bits']:,} bits")
    print(f"  Memory: {stats['memory_kb']:.2f} KB")
    print(f"  Hash functions: {stats['hash_count']}")

    # Verify memory is reasonable (should be < 150KB for 50k items)
    assert stats['memory_kb'] < 150, f"Memory too high: {stats['memory_kb']} KB"
    print("  ✓ PASS: Memory efficiency verified")
    return True


def test_ioc_entry_basic():
    """Test IOCEntry basic functionality"""
    print("\n" + "=" * 60)
    print("TEST 3: IOC Entry Operations")
    print("=" * 60)

    now = datetime.now()
    entry = IOCEntry(
        value="192.168.1.100",
        ioc_type="ip",
        source="abuseipdb",
        confidence=0.95,
        first_seen=now,
        last_seen=now,
        ttl=3600,
        threat_types=["botnet", "brute-force"],
        tags=["malicious", "scanner"]
    )

    # Test not expired
    assert not entry.is_expired(), "Fresh entry should not be expired"

    # Test serialization
    data = entry.to_dict()
    assert data["value"] == "192.168.1.100"
    assert data["confidence"] == 0.95
    assert "botnet" in data["threat_types"]

    print(f"  IOC: {entry.value} ({entry.ioc_type})")
    print(f"  Confidence: {entry.confidence}")
    print(f"  TTL: {entry.ttl}s")
    print("  ✓ PASS: IOC entry operations working")
    return True


def test_aggregator_add_check():
    """Test aggregator add and check operations"""
    print("\n" + "=" * 60)
    print("TEST 4: Aggregator Add & Check")
    print("=" * 60)

    aggregator = ThreatFeedAggregator(
        bloom_expected_items=1000,
        bloom_false_positive_rate=0.001,
        auto_refresh_interval=0
    )

    # Add single IOC
    added, msg = aggregator.add_ioc(
        value="1.2.3.4",
        ioc_type="ip",
        source="abuseipdb",
        confidence=0.9,
        threat_types=["botnet"]
    )

    assert added, f"Should add new IOC: {msg}"
    print(f"  Add result: {msg}")

    # Check IOC exists
    result = aggregator.check_ioc("1.2.3.4", "ip")
    assert result is not None, "Added IOC should be found"
    assert result.value == "1.2.3.4"
    assert result.confidence == 0.9

    # Check non-existent IOC
    not_found = aggregator.check_ioc("9.9.9.9", "ip")
    assert not_found is None, "Non-existent IOC should return None"

    print(f"  Check found: {result.value} (confidence: {result.confidence})")
    print("  ✓ PASS: Add & check operations working")
    return True


def test_aggregator_deduplication():
    """Test bloom filter deduplication"""
    print("\n" + "=" * 60)
    print("TEST 5: Deduplication with Bloom Filter")
    print("=" * 60)

    aggregator = ThreatFeedAggregator(
        bloom_expected_items=1000,
        auto_refresh_interval=0
    )

    # Add same IOC multiple times
    added1, _ = aggregator.add_ioc("malicious.com", "domain", "virustotal", 0.95)
    added2, msg = aggregator.add_ioc("malicious.com", "domain", "virustotal", 0.95)
    added3, _ = aggregator.add_ioc("MALICIOUS.COM", "domain", "virustotal", 0.95)  # Case insensitive

    assert added1 is True, "First add should succeed"
    assert added2 is False, "Duplicate should be detected"
    assert added3 is False, "Case-insensitive duplicate should be detected"

    stats = aggregator.get_stats()
    print(f"  Total active IOCs: {stats['total_active_iocs']}")
    print(f"  Source deduplicated: {stats['source_stats']['virustotal']['deduplicated']}")

    assert stats['total_active_iocs'] == 1, "Should only have 1 unique IOC"
    print("  ✓ PASS: Deduplication working correctly")
    return True


def test_aggregator_batch_operations():
    """Test batch IOC operations"""
    print("\n" + "=" * 60)
    print("TEST 6: Batch Operations")
    print("=" * 60)

    aggregator = ThreatFeedAggregator(auto_refresh_interval=0)

    batch_iocs = [
        {"value": "10.0.0.1", "ioc_type": "ip", "source": "test", "confidence": 0.8},
        {"value": "10.0.0.2", "ioc_type": "ip", "source": "test", "confidence": 0.85},
        {"value": "evil.com", "ioc_type": "domain", "source": "test", "confidence": 0.9},
        {"value": "10.0.0.1", "ioc_type": "ip", "source": "test", "confidence": 0.9},  # Duplicate
        {"value": "http://phish.net/login", "ioc_type": "url", "source": "test", "confidence": 0.95},
    ]

    result = aggregator.batch_add_iocs(batch_iocs)
    print(f"  Processed: {result['total_processed']}")
    print(f"  Added: {result['added']}")
    print(f"  Duplicates: {result['duplicates']}")
    print(f"  Errors: {result['errors']}")

    assert result['total_processed'] == 5
    assert result['added'] == 4
    assert result['duplicates'] == 1
    assert result['errors'] == 0

    stats = aggregator.get_stats()
    print(f"  Final active IOCs: {stats['total_active_iocs']}")
    print("  ✓ PASS: Batch operations working")
    return True


def test_aggregator_expiry_cleanup():
    """Test TTL expiry and cleanup"""
    print("\n" + "=" * 60)
    print("TEST 7: Expiry & Cleanup")
    print("=" * 60)

    aggregator = ThreatFeedAggregator(auto_refresh_interval=0)

    # Add IOC with very short TTL
    aggregator.add_ioc("short-lived.com", "domain", "test", 0.8, ttl=1)
    aggregator.add_ioc("long-lived.com", "domain", "test", 0.8, ttl=3600)

    stats_before = aggregator.get_stats()
    print(f"  Before cleanup: {stats_before['total_active_iocs']} IOCs")

    # Wait for expiry
    time.sleep(1.1)

    cleanup_result = aggregator.cleanup_expired()
    print(f"  Expired removed: {cleanup_result['expired_removed']}")
    print(f"  Remaining active: {cleanup_result['remaining_active']}")

    # Verify short-lived is gone
    short_check = aggregator.check_ioc("short-lived.com", "domain")
    long_check = aggregator.check_ioc("long-lived.com", "domain")

    assert short_check is None, "Expired IOC should be removed"
    assert long_check is not None, "Non-expired IOC should remain"

    print("  ✓ PASS: Expiry & cleanup working")
    return True


def test_aggregator_search_export():
    """Test search and export functionality"""
    print("\n" + "=" * 60)
    print("TEST 8: Search & Export")
    print("=" * 60)

    aggregator = ThreatFeedAggregator(auto_refresh_interval=0)

    # Add IOCs with different threat types
    iocs = [
        {"value": "bot1.ip", "ioc_type": "ip", "source": "test", "confidence": 0.8,
         "threat_types": ["botnet", "scanner"]},
        {"value": "bot2.ip", "ioc_type": "ip", "source": "test", "confidence": 0.85,
         "threat_types": ["botnet"]},
        {"value": "phish.com", "ioc_type": "domain", "source": "test", "confidence": 0.9,
         "threat_types": ["phishing"]},
    ]
    aggregator.batch_add_iocs(iocs)

    # Search by threat type
    botnet_iocs = aggregator.search_by_threat_type("botnet")
    print(f"  Botnet IOCs found: {len(botnet_iocs)}")
    assert len(botnet_iocs) == 2, "Should find 2 botnet IOCs"

    phish_iocs = aggregator.search_by_threat_type("PHISHING")  # Case insensitive
    print(f"  Phishing IOCs found: {len(phish_iocs)}")
    assert len(phish_iocs) == 1, "Should find 1 phishing IOC"

    # Test export
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        temp_path = f.name

    export_success = aggregator.export_to_json(temp_path)
    assert export_success, "Export should succeed"

    # Verify exported data
    with open(temp_path, 'r') as f:
        exported = json.load(f)

    print(f"  Exported IOCs: {exported['total_iocs']}")
    assert exported['total_iocs'] == 3, "Should export all 3 IOCs"

    os.unlink(temp_path)
    print("  ✓ PASS: Search & export working")
    return True


def test_aggregator_stats():
    """Test statistics gathering"""
    print("\n" + "=" * 60)
    print("TEST 9: Statistics Gathering")
    print("=" * 60)

    aggregator = ThreatFeedAggregator(auto_refresh_interval=0)

    # Add various IOCs
    iocs = [
        {"value": "1.1.1.1", "ioc_type": "ip", "source": "abuseipdb", "confidence": 0.9},
        {"value": "2.2.2.2", "ioc_type": "ip", "source": "abuseipdb", "confidence": 0.85},
        {"value": "bad.com", "ioc_type": "domain", "source": "virustotal", "confidence": 0.95},
        {"value": "http://bad.net", "ioc_type": "url", "source": "urlhaus", "confidence": 0.88},
    ]
    aggregator.batch_add_iocs(iocs)

    stats = aggregator.get_stats()

    print(f"  Total active IOCs: {stats['total_active_iocs']}")
    print(f"  By type: {stats['by_ioc_type']}")
    print(f"  By source: {stats['by_source']}")
    print(f"  Bloom filter memory: {stats['bloom_filter']['memory_kb']:.2f} KB")

    assert stats['total_active_iocs'] == 4
    assert stats['by_ioc_type']['ip'] == 2
    assert stats['by_ioc_type']['domain'] == 1
    assert stats['by_ioc_type']['url'] == 1

    print("  ✓ PASS: Statistics gathering working")
    return True


def main():
    """Run all tests"""
    print("\n" + "=" * 60)
    print("NeuralShield-AI: Threat Feed Aggregator v2 Test Suite")
    print("=" * 60)

    tests = [
        test_bloom_filter_basic,
        test_bloom_filter_memory_efficiency,
        test_ioc_entry_basic,
        test_aggregator_add_check,
        test_aggregator_deduplication,
        test_aggregator_batch_operations,
        test_aggregator_expiry_cleanup,
        test_aggregator_search_export,
        test_aggregator_stats,
    ]

    passed = 0
    failed = 0
    failed_tests = []

    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
                failed_tests.append(test.__name__)
        except Exception as e:
            print(f"  ✗ EXCEPTION in {test.__name__}: {e}")
            failed += 1
            failed_tests.append(test.__name__)

    print("\n" + "=" * 60)
    print(f"TEST SUMMARY: {passed}/{len(tests)} PASSED")
    print("=" * 60)

    if failed > 0:
        print(f"FAILED TESTS: {', '.join(failed_tests)}")
        return False

    print("\n✓ ALL TESTS PASSED - Production-grade implementation verified!")
    return True


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
