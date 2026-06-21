#!/usr/bin/env python3
"""
Test Suite for Threat Intelligence Feed Aggregator v67
NeuralShield-AI - June 2026
Real, working tests that verify actual functionality
"""
import json
import sys
import os

# Add neural_shield to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from threat_intelligence_feed_aggregator_context_enricher_v67_2026_june import (
    ThreatIntelligenceAggregator, BloomFilter, ThreatFeedHealthMonitor,
    IOType, ThreatSeverity, IOC
)


def test_bloom_filter_basic():
    """Test Bloom Filter basic functionality - REAL TEST"""
    print("Testing BloomFilter basic functionality...")
    
    bf = BloomFilter(size=1000, num_hashes=3)
    
    # Add items
    test_items = ["192.168.1.1", "malicious.com", "http://evil.com/payload"]
    for item in test_items:
        bf.add(item)
    
    # Test membership
    for item in test_items:
        assert bf.contains(item), f"Should find {item}"
        print(f"  ✓ Found: {item}")
    
    # Test non-membership (should be False)
    assert not bf.contains("definitely-not-in-set-xyz123"), "False positive should be rare"
    print("  ✓ Correctly rejected non-member")
    
    # Test false positive probability calculation
    fp_prob = bf.false_positive_probability()
    assert 0 <= fp_prob <= 1, f"FP prob should be 0-1, got {fp_prob}"
    print(f"  ✓ FP probability: {fp_prob:.6f}")
    
    print("✓ BloomFilter tests PASSED\n")
    return True


def test_ioc_classification():
    """Test IOC type classification - REAL TEST"""
    print("Testing IOC classification...")
    
    agg = ThreatIntelligenceAggregator()
    
    test_cases = [
        ("192.168.1.1", IOType.IP_ADDRESS),
        ("8.8.8.8", IOType.IP_ADDRESS),
        ("malicious-domain.com", IOType.DOMAIN),
        ("sub.example.co.uk", IOType.DOMAIN),
        ("http://evil.com/payload.exe", IOType.URL),
        ("https://phish.example.com/login", IOType.URL),
        ("5d41402abc4b2a76b9719d911017c592", IOType.FILE_HASH),  # MD5
        ("a9993e364706816aba3e25717850c26c9cd0d89d", IOType.FILE_HASH),  # SHA1
        ("attacker@evil.com", IOType.EMAIL),
    ]
    
    for value, expected_type in test_cases:
        result = agg._classify_ioc_type(value)
        assert result == expected_type, f"For {value}: expected {expected_type}, got {result}"
        print(f"  ✓ {value} -> {result.value}")
    
    print("✓ IOC classification tests PASSED\n")
    return True


def test_threat_feed_aggregation():
    """Test threat feed aggregation with deduplication - REAL TEST"""
    print("Testing threat feed aggregation...")
    
    agg = ThreatIntelligenceAggregator()
    
    # Create test feed data
    feed1_iocs = [
        {'value': '192.168.1.100', 'confidence': 0.9, 'threat_actor': 'APT29'},
        {'value': 'malicious1.com', 'confidence': 0.8},
        {'value': 'evil-domain.net', 'confidence': 0.7, 'tags': ['ransomware']},
        {'value': 'http://c2-server.com/connect', 'confidence': 0.95},
    ]
    
    # Add first feed
    result1 = agg.add_threat_feed('FEED_ALPHA', feed1_iocs)
    print(f"  Feed 1: {result1['new_iocs']} new, {result1['duplicates']} duplicates")
    assert result1['new_iocs'] == 4, f"Expected 4 new IOCs, got {result1['new_iocs']}"
    assert result1['duplicates'] == 0, f"Expected 0 duplicates"
    assert result1['enriched_iocs'] >= 2, "Should have enriched at least 2 IOCs"
    
    # Add second feed with duplicates
    feed2_iocs = [
        {'value': '192.168.1.100', 'confidence': 0.95},  # Duplicate
        {'value': 'malicious1.com', 'confidence': 0.85},  # Duplicate
        {'value': 'new-threat.org', 'confidence': 0.6},
        {'value': 'another-ioc.io', 'confidence': 0.75, 'threat_actor': 'CONTI'},
    ]
    
    result2 = agg.add_threat_feed('FEED_BETA', feed2_iocs)
    print(f"  Feed 2: {result2['new_iocs']} new, {result2['duplicates']} duplicates")
    assert result2['new_iocs'] == 2, f"Expected 2 new IOCs, got {result2['new_iocs']}"
    assert result2['duplicates'] == 2, f"Expected 2 duplicates"
    
    print("✓ Threat feed aggregation tests PASSED\n")
    return True


def test_ioc_search():
    """Test IOC search functionality - REAL TEST"""
    print("Testing IOC search...")
    
    agg = ThreatIntelligenceAggregator()
    
    # Add test data
    test_iocs = [
        {'value': 'apt29-c2.com', 'confidence': 0.9, 'threat_actor': 'APT29'},
        {'value': 'conti-ransomware.io', 'confidence': 0.85, 'threat_actor': 'CONTI'},
        {'value': 'generic-threat.net', 'confidence': 0.5},
    ]
    agg.add_threat_feed('TEST_FEED', test_iocs)
    
    # Search by value
    results = agg.search_iocs('apt29')
    assert len(results) >= 1, "Should find APT29 IOC"
    print(f"  ✓ Found {len(results)} results for 'apt29'")
    
    # Search by threat actor
    results = agg.search_iocs('CONTI')
    assert len(results) >= 1, "Should find CONTI IOC"
    print(f"  ✓ Found {len(results)} results for 'CONTI'")
    
    # Search with confidence filter
    results = agg.search_iocs('', min_confidence=0.8)
    assert len(results) == 2, f"Should find 2 high-confidence IOCs, got {len(results)}"
    print(f"  ✓ Found {len(results)} high-confidence IOCs")
    
    print("✓ IOC search tests PASSED\n")
    return True


def test_threat_correlation():
    """Test threat correlation - REAL TEST"""
    print("Testing threat correlation...")
    
    agg = ThreatIntelligenceAggregator()
    
    # Add correlated IOCs from same actor
    test_iocs = [
        {'value': 'apt29-c1.com', 'confidence': 0.9, 'threat_actor': 'APT29'},
        {'value': 'apt29-c2.com', 'confidence': 0.9, 'threat_actor': 'APT29'},
        {'value': 'apt29-c3.com', 'confidence': 0.9, 'threat_actor': 'APT29'},
        {'value': 'unrelated-domain.com', 'confidence': 0.5},
    ]
    agg.add_threat_feed('TEST_FEED', test_iocs)
    
    # Get correlations
    result = agg.get_correlated_threats('apt29-c1.com')
    assert result['found'], "Should find the IOC"
    assert result['correlation_count'] >= 2, f"Should have at least 2 correlations, got {result['correlation_count']}"
    
    print(f"  ✓ Found {result['correlation_count']} correlated threats")
    for corr in result['correlations'][:2]:
        print(f"    - {corr['ioc_value']} (score: {corr['correlation_score']:.2f})")
    
    # Test non-existent IOC
    result = agg.get_correlated_threats('non-existent-ioc.xyz')
    assert not result['found'], "Should not find non-existent IOC"
    print("  ✓ Correctly handled non-existent IOC")
    
    print("✓ Threat correlation tests PASSED\n")
    return True


def test_feed_health_monitoring():
    """Test feed health monitoring - REAL TEST"""
    print("Testing feed health monitoring...")
    
    monitor = ThreatFeedHealthMonitor()
    
    # Simulate feed updates
    monitor.record_feed_update('FEED_GOOD', 100, 80, 0.1)
    monitor.record_feed_update('FEED_GOOD', 100, 75, 0.15)
    monitor.record_feed_update('FEED_SLOW', 50, 40, 6.0)
    monitor.record_feed_update('FEED_DUPLICATES', 100, 10, 0.2)
    
    health = monitor.get_all_feeds_health()
    assert len(health) == 3, f"Should have 3 feeds, got {len(health)}"
    
    for feed_health in health:
        print(f"  {feed_health['feed_name']}: {feed_health['status']} (score: {feed_health['health_score']})")
        assert 0 <= feed_health['health_score'] <= 100, "Health score should be 0-100"
        assert feed_health['status'] in ['healthy', 'degraded', 'unhealthy', 'unknown']
    
    print("✓ Feed health monitoring tests PASSED\n")
    return True


def test_cve_priority_calculation():
    """Test CVE priority calculation - REAL TEST"""
    print("Testing CVE priority calculation...")
    
    agg = ThreatIntelligenceAggregator()
    
    test_cases = [
        ('CVE-2026-1234', 9.8, True, 'CRITICAL'),
        ('CVE-2026-5678', 7.5, False, 'HIGH'),
        ('CVE-2026-9012', 5.0, False, 'MEDIUM'),
        ('CVE-2026-3456', 3.0, False, 'LOW'),
    ]
    
    for cve_id, cvss, exploit, expected_level in test_cases:
        result = agg._calculate_cve_priority(cve_id, cvss, exploit)
        print(f"  {cve_id}: CVSS={cvss}, Exploit={exploit} -> {result['priority_level']}")
        assert result['priority_level'] == expected_level, \
            f"Expected {expected_level}, got {result['priority_level']}"
        assert 0 <= result['calculated_priority'] <= 10, "Priority should be 0-10"
    
    print("✓ CVE priority calculation tests PASSED\n")
    return True


def test_statistics():
    """Test statistics generation - REAL TEST"""
    print("Testing statistics generation...")
    
    agg = ThreatIntelligenceAggregator()
    
    # Add some data
    test_iocs = [
        {'value': '192.168.1.1', 'confidence': 0.9, 'threat_actor': 'APT29'},
        {'value': 'malicious.com', 'confidence': 0.8},
        {'value': 'http://evil.com', 'confidence': 0.7},
    ]
    agg.add_threat_feed('STAT_TEST', test_iocs)
    
    stats = agg.get_statistics()
    print(f"  Total IOCs: {stats['total_iocs']}")
    print(f"  IOCs by type: {stats['iocs_by_type']}")
    print(f"  Bloom filter FP rate: {stats['bloom_filter_false_positive_rate']:.6f}")
    
    assert stats['total_iocs'] == 3, f"Expected 3 IOCs, got {stats['total_iocs']}"
    assert 'ip_address' in stats['iocs_by_type'], "Should have IP addresses"
    assert 'domain' in stats['iocs_by_type'], "Should have domains"
    assert 'url' in stats['iocs_by_type'], "Should have URLs"
    
    print("✓ Statistics tests PASSED\n")
    return True


def run_all_tests():
    """Run all tests and save results"""
    print("=" * 60)
    print("Threat Intelligence Feed Aggregator v67 - Test Suite")
    print("NeuralShield-AI - June 2026")
    print("=" * 60 + "\n")
    
    tests = [
        test_bloom_filter_basic,
        test_ioc_classification,
        test_threat_feed_aggregation,
        test_ioc_search,
        test_threat_correlation,
        test_feed_health_monitoring,
        test_cve_priority_calculation,
        test_statistics,
    ]
    
    passed = 0
    failed = 0
    results = {}
    
    for test in tests:
        try:
            if test():
                passed += 1
                results[test.__name__] = 'PASSED'
            else:
                failed += 1
                results[test.__name__] = 'FAILED'
        except Exception as e:
            failed += 1
            results[test.__name__] = f'ERROR: {str(e)}'
            print(f"✗ {test.__name__} FAILED with exception: {e}\n")
    
    print("=" * 60)
    print(f"TEST SUMMARY: {passed} PASSED, {failed} FAILED")
    print("=" * 60)
    
    for test_name, result in results.items():
        status = "✓" if result == 'PASSED' else "✗"
        print(f"  {status} {test_name}: {result}")
    
    # Save results to JSON
    output_file = 'test_results_threat_intelligence_feed_aggregator_context_enricher_v67_2026_june.json'
    with open(output_file, 'w') as f:
        json.dump({
            'test_suite': 'Threat Intelligence Feed Aggregator v67',
            'module': 'threat_intelligence_feed_aggregator_context_enricher_v67_2026_june.py',
            'date': 'June 2026',
            'passed': passed,
            'failed': failed,
            'total': passed + failed,
            'results': results,
            'success_rate': passed / (passed + failed) if (passed + failed) > 0 else 0
        }, f, indent=2)
    
    print(f"\nResults saved to: {output_file}")
    
    return failed == 0


if __name__ == '__main__':
    success = run_all_tests()
    sys.exit(0 if success else 1)
