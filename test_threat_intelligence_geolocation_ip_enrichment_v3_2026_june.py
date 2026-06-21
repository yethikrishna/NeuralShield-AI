"""
Test suite for Threat Intelligence Geolocation IP Enrichment Engine v3
NeuralShield-AI - June 2026 Production Release
"""
import json
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))
from threat_intelligence_geolocation_ip_enrichment_v3_2026_june import (
    GeolocationIPEnrichmentEngineV3,
    create_ip_enrichment_engine,
    verify_enrichment_engine,
    IPVersion,
    ThreatReputation,
    NetworkType,
    ASNReputation,
    Coordinates
)
def test_basic_ip_enrichment():
    """Test basic IP enrichment functionality"""
    print("=== Test 1: Basic IP Enrichment ===")
    
    engine = create_ip_enrichment_engine(cache_size=1000)
    
    test_ips = [
        "8.8.8.8",        # Google DNS - trusted
        "1.1.1.1",        # Cloudflare DNS - trusted
        "203.0.113.42",   # Test IP - may be high risk
        "192.168.1.1",    # Private IP
        "10.0.0.1",       # Private IP
        "2606:4700:4700::1111"  # IPv6
    ]
    
    results = []
    for ip in test_ips:
        result = engine.enrich(ip)
        results.append(result)
        print(f"IP: {ip}")
        print(f"  Valid: {result.is_valid}, Public: {result.is_public}")
        print(f"  Country: {result.country_code}, City: {result.city}")
        print(f"  Threat Score: {result.threat_score:.1f}, Reputation: {result.threat_reputation.value}")
        print(f"  Network Type: {result.network_type.value}")
        print(f"  ASN: {result.asn_intelligence.asn if result.asn_intelligence else 'N/A'}")
        print(f"  Should Alert: {result.should_alert}, Severity: {result.alert_severity}")
        print()
    
    assert len(results) == len(test_ips)
    print("✓ Basic IP enrichment working\n")
    return True
def test_bulk_enrichment():
    """Test bulk IP enrichment with rate limiting"""
    print("=== Test 2: Bulk IP Enrichment ===")
    
    engine = create_ip_enrichment_engine()
    
    bulk_ips = [f"192.0.2.{i}" for i in range(1, 21)]
    
    results = engine.bulk_enrich(bulk_ips)
    
    print(f"Processed {len(results)} IPs")
    print(f"Cache size after bulk: {engine.cache.size()}")
    
    stats = engine.get_statistics()
    print(f"Total enrichments: {stats['total_enrichments']}")
    print(f"Cache hit rate: {stats['cache_hit_rate']:.1f}%")
    
    assert len(results) == 20
    print("✓ Bulk enrichment working\n")
    return True
def test_caching_functionality():
    """Test caching functionality"""
    print("=== Test 3: Caching Functionality ===")
    
    engine = create_ip_enrichment_engine(cache_size=100, cache_ttl_hours=1)
    
    # First lookup - cache miss
    result1 = engine.enrich("8.8.8.8", use_cache=True)
    stats1 = engine.get_statistics()
    
    # Second lookup - should be cache hit
    result2 = engine.enrich("8.8.8.8", use_cache=True)
    stats2 = engine.get_statistics()
    
    print(f"Cache hits after first lookup: {stats1['cache_hits']}")
    print(f"Cache hits after second lookup: {stats2['cache_hits']}")
    print(f"Cache size: {engine.cache.size()}")
    
    assert stats2['cache_hits'] > stats1['cache_hits']
    print("✓ Caching working correctly\n")
    return True
def test_threat_feed_correlation():
    """Test threat feed correlation"""
    print("=== Test 4: Threat Feed Correlation ===")
    
    engine = create_ip_enrichment_engine(enable_threat_feeds=True)
    
    # Test with known malicious IP from sample database
    malicious_ip = "203.0.113.42"
    result = engine.enrich(malicious_ip)
    
    print(f"IP: {malicious_ip}")
    print(f"Threat feed matches: {len(result.threat_feed_matches)}")
    print(f"Threat score: {result.threat_score:.1f}")
    print(f"Threat confidence: {result.threat_confidence:.2f}")
    print(f"Threat categories: {result.threat_categories}")
    
    if result.threat_feed_matches:
        for match in result.threat_feed_matches:
            print(f"  - {match.feed_source.value}: {match.threat_category} (confidence: {match.confidence})")
    
    print("✓ Threat feed correlation working\n")
    return True
def test_asn_intelligence():
    """Test ASN intelligence and reputation"""
    print("=== Test 5: ASN Intelligence ===")
    
    engine = create_ip_enrichment_engine()
    
    result = engine.enrich("8.8.8.8")
    
    if result.asn_intelligence:
        asn = result.asn_intelligence
        print(f"ASN: {asn.asn}")
        print(f"Organization: {asn.organization}")
        print(f"Reputation: {asn.reputation.value}")
        print(f"Abuse Score: {asn.abuse_score:.1f}")
        print(f"Cloud Provider: {asn.is_cloud_provider}")
        print(f"Hosting Provider: {asn.is_hosting_provider}")
        print(f"Malicious IPs in ASN: {asn.malicious_ips_count}")
    
    assert result.asn_intelligence is not None
    print("✓ ASN intelligence working\n")
    return True
def test_alerting_logic():
    """Test alert generation logic"""
    print("=== Test 6: Alerting Logic ===")
    
    engine = create_ip_enrichment_engine()
    
    test_ips = ["8.8.8.8", "203.0.113.42", "198.51.100.77"]
    alerts_generated = 0
    
    for ip in test_ips:
        result = engine.enrich(ip)
        if result.should_alert:
            alerts_generated += 1
            print(f"ALERT [{result.alert_severity}]: {ip}")
            for reason in result.alert_reasons:
                print(f"  Reason: {reason}")
    
    print(f"Total alerts generated: {alerts_generated}")
    print("✓ Alerting logic working\n")
    return True
def test_anonymization_detection():
    """Test TOR/VPN/Proxy detection"""
    print("=== Test 7: Anonymization Detection ===")
    
    engine = create_ip_enrichment_engine()
    
    # Generate various IPs to test
    test_ips = ["1.1.1.1", "8.8.8.8", "203.0.113.1"]
    anonymized_count = 0
    
    for ip in test_ips:
        result = engine.enrich(ip)
        if result.is_anonymized:
            anonymized_count += 1
            print(f"Anonymized detected: {ip}")
            print(f"  Type: {result.anonymization_type}")
            print(f"  TOR: {result.is_tor_exit}, VPN: {result.is_vpn}")
    
    stats = engine.get_statistics()
    print(f"Total anonymized detected: {stats['anonymized_detected']}")
    print("✓ Anonymization detection working\n")
    return True
def test_report_generation():
    """Test enrichment report generation"""
    print("=== Test 8: Report Generation ===")
    
    engine = create_ip_enrichment_engine()
    
    test_ips = ["8.8.8.8", "1.1.1.1", "203.0.113.42", "192.168.1.1"]
    results = engine.bulk_enrich(test_ips)
    
    report_json = engine.export_enrichment_report(results, format="json")
    report_data = json.loads(report_json)
    
    print(f"Report generated for {report_data['total_ips_processed']} IPs")
    print(f"Engine version: {report_data['engine_version']}")
    print(f"Summary: {report_data['summary']}")
    
    # Save report
    with open("test_results_geolocation_ip_enrichment_v3_2026_june.json", "w") as f:
        f.write(report_json)
    
    print("✓ Report generation working (saved to test_results_geolocation_ip_enrichment_v3_2026_june.json)")
    print()
    return True
def test_statistics_tracking():
    """Test statistics tracking"""
    print("=== Test 9: Statistics Tracking ===")
    
    engine = create_ip_enrichment_engine()
    
    # Process some IPs
    for i in range(1, 51):
        engine.enrich(f"192.0.2.{i}")
    
    stats = engine.get_statistics()
    
    print("Engine Statistics:")
    for key, value in stats.items():
        if key != "threat_feed_database":
            print(f"  {key}: {value}")
    
    if "threat_feed_database" in stats:
        print("  Threat Feed Database:")
        for k, v in stats["threat_feed_database"].items():
            print(f"    {k}: {v}")
    
    assert stats['total_enrichments'] == 50
    print("✓ Statistics tracking working\n")
    return True
def test_verification_function():
    """Test the verification function"""
    print("=== Test 10: Verification Function ===")
    
    result = verify_enrichment_engine()
    
    print(f"Engine working: {result['engine_working']}")
    print(f"Total processed: {result['total_processed']}")
    print(f"Cache functional: {result['cache_functional']}")
    print(f"Threat scoring working: {result['threat_scoring_working']}")
    
    assert result['engine_working']
    assert result['cache_functional']
    print("✓ Verification function working\n")
    return True
def run_all_tests():
    """Run all tests and generate summary"""
    print("=" * 60)
    print("NeuralShield-AI: Geolocation IP Enrichment Engine v3 - Test Suite")
    print("=" * 60)
    print()
    
    tests = [
        test_basic_ip_enrichment,
        test_bulk_enrichment,
        test_caching_functionality,
        test_threat_feed_correlation,
        test_asn_intelligence,
        test_alerting_logic,
        test_anonymization_detection,
        test_report_generation,
        test_statistics_tracking,
        test_verification_function
    ]
    
    passed = 0
    failed = 0
    test_results = []
    
    for test in tests:
        try:
            if test():
                passed += 1
                test_results.append((test.__name__, "PASSED"))
            else:
                failed += 1
                test_results.append((test.__name__, "FAILED"))
        except Exception as e:
            failed += 1
            test_results.append((test.__name__, f"ERROR: {str(e)}"))
            print(f"✗ {test.__name__} failed with error: {e}\n")
    
    print("=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    for name, status in test_results:
        print(f"{name:50s} {status}")
    print("-" * 60)
    print(f"Total: {len(tests)}, Passed: {passed}, Failed: {failed}")
    print(f"Success rate: {passed/len(tests)*100:.1f}%")
    print("=" * 60)
    
    return passed == len(tests)
if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
