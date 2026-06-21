#!/usr/bin/env python3
"""
Test suite for Threat Intelligence Context Enricher v72
Real working tests with actual assertions
"""

import json
import sys
import os

# Add module path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from threat_intelligence_context_enricher_v72_2026_june import (
    ThreatIntelligenceContextEnricherV72,
    BloomFilter,
    EnrichmentResult
)


def test_bloom_filter_basic():
    """Test Bloom filter basic functionality"""
    print("Test 1: Bloom Filter Basic Functionality")
    
    bf = BloomFilter(size=1000, hash_count=3)
    
    # Test add and check
    bf.add("test_ioc_123")
    assert bf.might_contain("test_ioc_123") == True, "Bloom filter should contain added item"
    assert bf.might_contain("not_added") == False, "Bloom filter should not contain unadded item"
    
    # Test multiple items
    items = ["192.168.1.1", "malicious.com", "d41d8cd98f00b204e9800998ecf8427e"]
    for item in items:
        bf.add(item)
    
    for item in items:
        assert bf.might_contain(item) == True, f"Bloom filter should contain {item}"
    
    print("  ✓ Bloom filter works correctly")
    return True


def test_ioc_classification():
    """Test IOC type classification"""
    print("\nTest 2: IOC Type Classification")
    
    enricher = ThreatIntelligenceContextEnricherV72()
    
    test_cases = [
        ("192.168.1.1", "ipv4"),
        ("8.8.8.8", "ipv4"),
        ("malicious-domain.com", "domain"),
        ("subdomain.example.co.uk", "domain"),
        ("d41d8cd98f00b204e9800998ecf8427e", "md5"),
        ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "sha256"),
        ("https://evil.com/payload.exe", "url"),
        ("http://phishing-site.com/login", "url"),
    ]
    
    for ioc, expected_type in test_cases:
        result = enricher._classify_ioc_type(ioc)
        assert result == expected_type, f"Expected {expected_type} for {ioc}, got {result}"
        print(f"  ✓ {ioc} -> {result}")
    
    return True


def test_threat_score_calculation():
    """Test threat score calculation"""
    print("\nTest 3: Threat Score Calculation")
    
    enricher = ThreatIntelligenceContextEnricherV72()
    
    # Test with high reputation sources
    score, confidence = enricher._calculate_threat_score("test", ["virustotal", "abuseipdb"])
    assert 0.0 <= score <= 1.0, f"Threat score should be between 0 and 1, got {score}"
    assert 0.0 <= confidence <= 1.0, f"Confidence should be between 0 and 1, got {confidence}"
    assert score > 0.8, f"High reputation sources should give high score, got {score}"
    assert confidence > 0.5, f"Multiple sources should give good confidence, got {confidence}"
    print(f"  ✓ High reputation sources: score={score}, confidence={confidence}")
    
    # Test with no sources
    score2, confidence2 = enricher._calculate_threat_score("test", [])
    assert score2 == 0.1, f"No sources should give default score"
    assert confidence2 == 0.1, f"No sources should give default confidence"
    print(f"  ✓ No sources: score={score2}, confidence={confidence2}")
    
    return True


def test_mitre_mapping():
    """Test MITRE ATT&CK technique mapping"""
    print("\nTest 4: MITRE ATT&CK Mapping")
    
    enricher = ThreatIntelligenceContextEnricherV72()
    
    techniques = enricher._map_mitre_techniques(['phishing', 'malware'])
    assert len(techniques) > 0, "Should map to MITRE techniques"
    assert 'T1566' in techniques, "Phishing should map to T1566"
    assert 'T1059' in techniques, "Malware should map to T1059"
    print(f"  ✓ Mapped techniques: {techniques}")
    
    # Test empty keywords
    empty_techniques = enricher._map_mitre_techniques([])
    assert empty_techniques == [], "No keywords should return empty list"
    print("  ✓ Empty keywords returns empty list")
    
    return True


def test_single_ioc_enrichment():
    """Test single IOC enrichment"""
    print("\nTest 5: Single IOC Enrichment")
    
    enricher = ThreatIntelligenceContextEnricherV72()
    
    result = enricher.enrich_single_ioc(
        ioc="192.168.1.1",
        sources=["virustotal", "internal"],
        context_keywords=["c2"]
    )
    
    assert isinstance(result, EnrichmentResult), "Should return EnrichmentResult object"
    assert result.ioc == "192.168.1.1", "IOC should match"
    assert result.ioc_type == "ipv4", "Should classify as IPv4"
    assert 0.0 <= result.threat_score <= 1.0, "Threat score should be valid"
    assert 0.0 <= result.confidence <= 1.0, "Confidence should be valid"
    assert 'T1071' in result.mitre_techniques, "C2 should map to T1071"
    assert result.context['enrichment_version'] == 'v72', "Version should be v72"
    
    print(f"  ✓ Enriched: {result.ioc} ({result.ioc_type})")
    print(f"    Threat Score: {result.threat_score}, Confidence: {result.confidence}")
    print(f"    MITRE Techniques: {result.mitre_techniques}")
    
    return True


def test_caching_functionality():
    """Test caching functionality"""
    print("\nTest 6: Caching Functionality")
    
    enricher = ThreatIntelligenceContextEnricherV72(cache_ttl=3600)
    
    # First enrichment
    result1 = enricher.enrich_single_ioc("8.8.8.8", use_cache=True)
    initial_processed = enricher.processed_count
    
    # Second enrichment - should hit cache
    result2 = enricher.enrich_single_ioc("8.8.8.8", use_cache=True)
    
    assert enricher.cache_hits >= 1, "Should have cache hit"
    assert enricher.processed_count == initial_processed, "Should not re-process cached item"
    assert result1.ioc == result2.ioc, "Cached result should match"
    
    stats = enricher.get_stats()
    assert stats['cache_hits'] >= 1, "Stats should reflect cache hits"
    assert stats['cache_hit_rate_percent'] > 0, "Cache hit rate should be positive"
    
    print(f"  ✓ Cache hits: {enricher.cache_hits}")
    print(f"  ✓ Cache hit rate: {stats['cache_hit_rate_percent']}%")
    
    return True


def test_batch_enrichment():
    """Test batch enrichment with correlation"""
    print("\nTest 7: Batch Enrichment with Correlation")
    
    enricher = ThreatIntelligenceContextEnricherV72()
    
    iocs = [
        "10.0.0.1",
        "malicious.com",
        "10.0.0.2",
        "phishing-site.org",
        "10.0.0.1",  # Duplicate
    ]
    
    results = enricher.enrich_batch(
        iocs=iocs,
        sources=["virustotal", "threatfox"],
        context_keywords=["c2", "phishing"],
        batch_size=2
    )
    
    # Should have 4 unique results (duplicate removed)
    assert len(results) == 4, f"Should have 4 unique results, got {len(results)}"
    
    # Check correlation weights
    for result in results:
        assert 0.0 <= result.correlation_weight <= 1.0, "Correlation weight should be valid"
    
    print(f"  ✓ Batch processed {len(results)} unique IOCs")
    print(f"  ✓ Correlation weights calculated for all items")
    
    return True


def test_entropy_calculation():
    """Test entropy calculation"""
    print("\nTest 8: Entropy Calculation")
    
    enricher = ThreatIntelligenceContextEnricherV72()
    
    # Random string should have higher entropy
    random_str = "a1b2c3d4e5f6g7h8i9j0"
    low_entropy_str = "aaaaaaaaaaaaaaa"
    
    entropy_random = enricher._calculate_entropy(random_str)
    entropy_low = enricher._calculate_entropy(low_entropy_str)
    
    assert entropy_random > entropy_low, "Random string should have higher entropy"
    assert entropy_random >= 0, "Entropy should be non-negative"
    
    print(f"  ✓ Random string entropy: {entropy_random}")
    print(f"  ✓ Low entropy string: {entropy_low}")
    
    return True


def test_stats_and_export():
    """Test statistics and JSON export"""
    print("\nTest 9: Statistics and JSON Export")
    
    enricher = ThreatIntelligenceContextEnricherV72()
    
    # Process some IOCs
    iocs = ["1.1.1.1", "2.2.2.2", "test-domain.com"]
    results = enricher.enrich_batch(iocs)
    
    # Get stats
    stats = enricher.get_stats()
    assert stats['version'] == 'v72', "Version should be v72"
    assert stats['total_processed'] == 3, "Should have processed 3 IOCs"
    assert 'enrichment_by_type' in stats, "Should have enrichment by type stats"
    
    # Export to JSON
    json_output = enricher.export_results_json(results)
    parsed = json.loads(json_output)
    assert len(parsed) == 3, "JSON should contain all results"
    assert 'ioc' in parsed[0], "JSON should have ioc field"
    assert 'threat_score' in parsed[0], "JSON should have threat_score"
    
    print(f"  ✓ Stats: {stats['total_processed']} processed, {stats['cache_size']} cached")
    print("  ✓ JSON export works correctly")
    
    return True


def run_all_tests():
    """Run all tests and report results"""
    print("=" * 60)
    print("Threat Intelligence Context Enricher v72 - Test Suite")
    print("=" * 60)
    
    tests = [
        test_bloom_filter_basic,
        test_ioc_classification,
        test_threat_score_calculation,
        test_mitre_mapping,
        test_single_ioc_enrichment,
        test_caching_functionality,
        test_batch_enrichment,
        test_entropy_calculation,
        test_stats_and_export,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            if test():
                passed += 1
        except Exception as e:
            failed += 1
            print(f"  ✗ FAILED: {e}")
    
    print("\n" + "=" * 60)
    print(f"TEST SUMMARY: {passed} passed, {failed} failed")
    print("=" * 60)
    
    # Save test results
    results = {
        "test_suite": "threat_intelligence_context_enricher_v72",
        "version": "v72",
        "total_tests": len(tests),
        "passed": passed,
        "failed": failed,
        "success_rate": f"{(passed/len(tests)*100):.1f}%",
        "timestamp": __import__('datetime').datetime.utcnow().isoformat()
    }
    
    with open("test_results_threat_intelligence_context_enricher_v72_2026_june.json", "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"Results saved to test_results_threat_intelligence_context_enricher_v72_2026_june.json")
    
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
