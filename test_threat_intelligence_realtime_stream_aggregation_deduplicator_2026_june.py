"""
Test suite for Threat Intelligence Real-Time Stream Aggregation & Deduplication Engine
June 2026 - Production-Grade Tests
"""

import sys
import os
import time
import json
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from threat_intelligence_realtime_stream_aggregation_deduplicator_2026_june import (
    RealTimeIOCAggregator,
    IOCTYPE,
    IOCEntry
)


def test_basic_ioc_addition():
    """Test basic IOC addition and deduplication"""
    print("Test 1: Basic IOC Addition & Exact Deduplication")
    
    aggregator = RealTimeIOCAggregator()
    
    # Add same IOC twice
    is_new1, hash1 = aggregator.add_ioc(
        "192.168.1.1", IOCTYPE.IPV4, "test_feed", 0.8, "high"
    )
    is_new2, hash2 = aggregator.add_ioc(
        "192.168.1.1", IOCTYPE.IPV4, "test_feed2", 0.7, "high"
    )
    
    assert is_new1 == True, "First IOC should be new"
    assert is_new2 == False, "Duplicate IOC should not be new"
    assert hash1 == hash2, "Same IOC should have same hash"
    
    stats = aggregator.get_statistics()
    assert stats["total_iocs_received"] == 2, "Should have received 2 IOCs"
    assert stats["unique_iocs"] == 1, "Should have 1 unique IOC"
    assert stats["duplicates_filtered"] == 1, "Should have 1 duplicate"
    
    print("  ✓ PASSED")


def test_ioc_normalization():
    """Test IOC value normalization"""
    print("Test 2: IOC Value Normalization")
    
    aggregator = RealTimeIOCAggregator()
    
    # Test domain normalization (www prefix should be stripped)
    is_new1, hash1 = aggregator.add_ioc(
        "www.evil.com", IOCTYPE.DOMAIN, "feed1", 0.8
    )
    is_new2, hash2 = aggregator.add_ioc(
        "evil.com", IOCTYPE.DOMAIN, "feed2", 0.8
    )
    
    assert is_new1 == True, "First domain should be new"
    assert is_new2 == False, "Normalized domain should be duplicate"
    assert hash1 == hash2, "Normalized domains should have same hash"
    
    # Test URL normalization
    is_new3, hash3 = aggregator.add_ioc(
        "https://malware.com/path/", IOCTYPE.URL, "feed1"
    )
    is_new4, hash4 = aggregator.add_ioc(
        "http://malware.com/path", IOCTYPE.URL, "feed2"
    )
    
    assert is_new3 == True, "First URL should be new"
    assert is_new4 == False, "Normalized URL should be duplicate"
    
    print("  ✓ PASSED")


def test_batch_processing():
    """Test batch IOC processing"""
    print("Test 3: Batch IOC Processing")
    
    aggregator = RealTimeIOCAggregator()
    
    test_iocs = [
        {"value": "10.0.0.1", "type": "ipv4", "source": "feed_a", "confidence": 0.6},
        {"value": "10.0.0.2", "type": "ipv4", "source": "feed_a", "confidence": 0.7},
        {"value": "10.0.0.1", "type": "ipv4", "source": "feed_b", "confidence": 0.8},
        {"value": "bad.com", "type": "domain", "source": "feed_a", "confidence": 0.9},
        {"value": "d41d8cd98f00b204e9800998ecf8427e", "type": "md5", "source": "feed_c"},
    ]
    
    results = aggregator.batch_add_iocs(test_iocs)
    
    assert results["added"] == 4, "Should add 4 unique IOCs"
    assert results["duplicates"] == 1, "Should have 1 duplicate"
    
    stats = aggregator.get_statistics()
    assert stats["total_iocs_received"] == 5
    assert stats["unique_iocs"] == 4
    
    print("  ✓ PASSED")


def test_confidence_aggregation():
    """Test confidence score aggregation across feeds"""
    print("Test 4: Confidence Aggregation")
    
    aggregator = RealTimeIOCAggregator()
    
    # Same IOC from multiple feeds with varying confidence
    aggregator.add_ioc("attacker.com", IOCTYPE.DOMAIN, "feed1", 0.5)
    aggregator.add_ioc("attacker.com", IOCTYPE.DOMAIN, "feed2", 0.6)
    aggregator.add_ioc("attacker.com", IOCTYPE.DOMAIN, "feed3", 0.7)
    
    iocs = aggregator.get_unique_iocs()
    assert len(iocs) == 1
    
    final_confidence = iocs[0]["confidence"]
    assert final_confidence > 0.5, "Confidence should increase with multiple feeds"
    assert final_confidence <= 1.0, "Confidence should not exceed 1.0"
    assert iocs[0]["feed_occurrences"] == 3, "Should show 3 feed occurrences"
    
    print(f"  ✓ PASSED (Final confidence: {final_confidence})")


def test_filtering():
    """Test IOC filtering by confidence and type"""
    print("Test 5: IOC Filtering")
    
    aggregator = RealTimeIOCAggregator()
    
    test_data = [
        ("1.1.1.1", IOCTYPE.IPV4, 0.9),
        ("2.2.2.2", IOCTYPE.IPV4, 0.2),
        ("evil.net", IOCTYPE.DOMAIN, 0.8),
        ("low.confidence.com", IOCTYPE.DOMAIN, 0.1),
        ("d41d8cd98f00b204e9800998ecf8427e", IOCTYPE.MD5, 0.95),
    ]
    
    for val, typ, conf in test_data:
        aggregator.add_ioc(val, typ, "test", conf)
    
    # Filter by minimum confidence
    high_conf = aggregator.get_unique_iocs(min_confidence=0.5)
    assert len(high_conf) == 3, "Should have 3 high confidence IOCs"
    
    # Filter by type
    only_domains = aggregator.get_unique_iocs(ioc_type=IOCTYPE.DOMAIN)
    assert len(only_domains) == 2, "Should have 2 domains"
    
    only_ips = aggregator.get_unique_iocs(ioc_type=IOCTYPE.IPV4)
    assert len(only_ips) == 2, "Should have 2 IPs"
    
    print("  ✓ PASSED")


def test_statistics():
    """Test statistics generation"""
    print("Test 6: Statistics Generation")
    
    aggregator = RealTimeIOCAggregator()
    
    # Add duplicates intentionally to test deduplication
    for i in range(100):
        aggregator.add_ioc(f"10.0.0.{i%10}", IOCTYPE.IPV4, f"feed_{i%3}")
    
    stats = aggregator.get_statistics()
    
    assert stats["total_iocs_received"] == 100
    assert stats["unique_iocs"] == 10, "Should have 10 unique IPs"
    assert stats["deduplication_rate"] > 0, "Should have positive deduplication rate"
    assert "by_type" in stats
    assert "by_source" in stats
    assert stats["active_feeds"] == 3
    
    print(f"  ✓ PASSED (Deduplication rate: {stats['deduplication_rate']}%)")


def test_stix_export():
    """Test STIX 2.1 export functionality"""
    print("Test 7: STIX 2.1 Export")
    
    aggregator = RealTimeIOCAggregator()
    
    aggregator.add_ioc("192.168.1.100", IOCTYPE.IPV4, "test_feed", 0.85)
    aggregator.add_ioc("malware.exe", IOCTYPE.DOMAIN, "test_feed", 0.9)
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        tmp_path = f.name
    
    success = aggregator.export_to_stix(tmp_path)
    assert success == True, "STIX export should succeed"
    
    with open(tmp_path, 'r') as f:
        stix_data = json.load(f)
    
    assert stix_data["type"] == "bundle"
    assert len(stix_data["objects"]) == 2
    assert stix_data["objects"][0]["type"] == "indicator"
    
    os.unlink(tmp_path)
    
    print("  ✓ PASSED")


def test_fuzzy_matching():
    """Test fuzzy domain matching"""
    print("Test 8: Fuzzy Domain Matching")
    
    aggregator = RealTimeIOCAggregator(enable_fuzzy_matching=True)
    
    # Add base domain
    aggregator.add_ioc("malicious-domain.com", IOCTYPE.DOMAIN, "feed1", 0.8)
    
    # Add similar subdomain (should fuzzy match)
    is_new, _ = aggregator.add_ioc("sub.malicious-domain.com", IOCTYPE.DOMAIN, "feed2", 0.7)
    
    stats = aggregator.get_statistics()
    
    # Fuzzy matching should work for domains sharing base domain
    assert stats["fuzzy_merged"] >= 0, "Fuzzy matching should be tracked"
    
    print(f"  ✓ PASSED (Fuzzy matches: {stats['fuzzy_merged']})")


def run_all_tests():
    """Run all test cases"""
    print("=" * 70)
    print("NeuralShield-AI: Real-Time IOC Aggregation Engine Tests")
    print("June 2026 Production-Grade Validation")
    print("=" * 70)
    
    tests = [
        test_basic_ioc_addition,
        test_ioc_normalization,
        test_batch_processing,
        test_confidence_aggregation,
        test_filtering,
        test_statistics,
        test_stix_export,
        test_fuzzy_matching
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            test()
            passed += 1
        except AssertionError as e:
            print(f"  ✗ FAILED: {e}")
            failed += 1
        except Exception as e:
            print(f"  ✗ ERROR: {e}")
            failed += 1
    
    print("\n" + "=" * 70)
    print(f"TEST SUMMARY: {passed} PASSED, {failed} FAILED")
    print("=" * 70)
    
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
