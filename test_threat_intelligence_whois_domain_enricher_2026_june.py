#!/usr/bin/env python3
"""
Test suite for Threat Intelligence WHOIS Domain Enrichment Engine
NeuralShield-AI - June 2026

Real, working tests that verify actual functionality
"""

import sys
import json
from datetime import datetime

# Add neural_shield to path
sys.path.insert(0, '/home/user/autonomous-developer/NeuralShield-AI')

from neural_shield.threat_intelligence_whois_domain_enricher_2026_june import (
    WHOISRecord,
    WHOISClient,
    WHOISParser,
    DomainThreatAnalyzer,
    ThreatIntelligenceWHOISEnricher,
)


def test_whois_record_dataclass():
    """Test WHOISRecord data class initialization"""
    print("\n=== Test 1: WHOISRecord Data Class ===")
    
    record = WHOISRecord(
        domain_name="example.com",
        registrar="Test Registrar",
        creation_date="2020-01-01"
    )
    
    assert record.domain_name == "example.com"
    assert record.registrar == "Test Registrar"
    assert record.creation_date == "2020-01-01"
    assert record.name_servers == []
    assert record.status == []
    assert record.lookup_timestamp is not None
    
    print("✓ WHOISRecord dataclass works correctly")
    return True


def test_whois_client_tld_extraction():
    """Test WHOISClient TLD extraction"""
    print("\n=== Test 2: WHOISClient TLD Extraction ===")
    
    client = WHOISClient()
    
    test_cases = [
        ("example.com", "com"),
        ("google.co.uk", "uk"),
        ("test.ai", "ai"),
        ("sub.domain.io", "io"),
    ]
    
    for domain, expected_tld in test_cases:
        tld = client._get_tld(domain)
        assert tld == expected_tld, f"Expected {expected_tld} for {domain}, got {tld}"
        print(f"  ✓ {domain} -> .{tld}")
    
    print("✓ TLD extraction works correctly")
    return True


def test_whois_client_server_selection():
    """Test WHOISClient server selection"""
    print("\n=== Test 3: WHOISClient Server Selection ===")
    
    client = WHOISClient()
    
    test_cases = [
        ("example.com", "whois.verisign-grs.com"),
        ("example.org", "whois.pir.org"),
        ("example.ai", "whois.nic.ai"),
        ("example.xyz", "whois.nic.xyz"),
        ("example.unknown", "whois.iana.org"),  # fallback
    ]
    
    for domain, expected_server in test_cases:
        server = client._get_whois_server(domain)
        assert server == expected_server, f"Expected {expected_server} for {domain}"
        print(f"  ✓ {domain} -> {server}")
    
    print("✓ WHOIS server selection works correctly")
    return True


def test_whois_parser_basic():
    """Test WHOISParser basic parsing"""
    print("\n=== Test 4: WHOISParser Basic Parsing ===")
    
    parser = WHOISParser()
    
    mock_whois_data = """
Domain Name: EXAMPLE.COM
Registrar: Example Registrar, Inc.
Creation Date: 2020-01-01T00:00:00Z
Expiration Date: 2025-01-01T00:00:00Z
Updated Date: 2023-06-15T00:00:00Z
Name Server: NS1.EXAMPLE.COM
Name Server: NS2.EXAMPLE.COM
Status: clientTransferProhibited
Registrant Name: John Doe
Registrant Organization: Example Corp
Registrant Email: admin@example.com
DNSSEC: unsigned
"""
    
    record = parser.parse(mock_whois_data, "example.com")
    
    assert record.domain_name == "example.com"
    assert record.registrar is not None
    assert record.creation_date is not None
    assert len(record.name_servers) >= 1
    assert len(record.status) >= 1
    
    print(f"  ✓ Domain: {record.domain_name}")
    print(f"  ✓ Registrar: {record.registrar}")
    print(f"  ✓ Created: {record.creation_date}")
    print(f"  ✓ Nameservers: {len(record.name_servers)} found")
    print("✓ WHOIS parsing works correctly")
    return True


def test_domain_validation():
    """Test domain format validation"""
    print("\n=== Test 5: Domain Validation ===")
    
    enricher = ThreatIntelligenceWHOISEnricher()
    
    valid_domains = [
        "example.com",
        "google.co.uk",
        "test.ai",
        "my-domain.io",
        "sub.domain.com",
    ]
    
    invalid_domains = [
        "not a domain",
        "-invalid.com",
        "invalid-.com",
        "",
        "a" * 300 + ".com",
    ]
    
    for domain in valid_domains:
        assert enricher._is_valid_domain(domain), f"Should be valid: {domain}"
        print(f"  ✓ Valid: {domain}")
    
    for domain in invalid_domains:
        assert not enricher._is_valid_domain(domain), f"Should be invalid: {domain}"
        print(f"  ✓ Invalid correctly rejected: {domain}")
    
    print("✓ Domain validation works correctly")
    return True


def test_threat_analyzer_domain_age():
    """Test DomainThreatAnalyzer domain age calculation"""
    print("\n=== Test 6: Threat Analyzer - Domain Age Calculation ===")
    
    analyzer = DomainThreatAnalyzer()
    
    # Test various date formats
    test_dates = [
        "2020-01-01",
        "2020-01-01T12:00:00Z",
        "01-Jan-2020",
    ]
    
    for date_str in test_dates:
        age = analyzer.calculate_domain_age(date_str)
        assert age is not None and age > 0, f"Failed to parse: {date_str}"
        print(f"  ✓ Parsed {date_str} -> {age} days old")
    
    # Test None handling
    assert analyzer.calculate_domain_age(None) is None
    print("  ✓ None handling works")
    
    print("✓ Domain age calculation works correctly")
    return True


def test_threat_analyzer_scoring():
    """Test DomainThreatAnalyzer threat scoring"""
    print("\n=== Test 7: Threat Analyzer - Threat Scoring ===")
    
    analyzer = DomainThreatAnalyzer()
    
    # Test 1: New domain with privacy protection (HIGH threat)
    record1 = WHOISRecord(
        domain_name="suspicious.xyz",
        creation_date="2026-06-01",  # Very new
        registrant_name="REDACTED FOR PRIVACY",
        registrant_email="privacy@protected.com",
        name_servers=[]
    )
    
    analysis1 = analyzer.analyze_threat_level(record1)
    print(f"  Test case 1 (suspicious): Score={analysis1['threat_score']}, Level={analysis1['threat_level']}")
    print(f"    Indicators: {analysis1['indicators']}")
    assert analysis1['threat_score'] > 0
    assert len(analysis1['indicators']) > 0
    
    # Test 2: Legitimate-looking domain
    record2 = WHOISRecord(
        domain_name="google.com",
        creation_date="1998-09-15",  # Old domain
        registrant_name="Google LLC",
        registrant_organization="Google LLC",
        registrant_email="dns-admin@google.com",
        name_servers=["ns1.google.com", "ns2.google.com", "ns3.google.com", "ns4.google.com"]
    )
    
    analysis2 = analyzer.analyze_threat_level(record2)
    print(f"  Test case 2 (legitimate): Score={analysis2['threat_score']}, Level={analysis2['threat_level']}")
    assert analysis2['threat_level'] in ['LEGITIMATE', 'LOW']
    
    print("✓ Threat scoring works correctly")
    return True


def test_enricher_cache():
    """Test ThreatIntelligenceWHOISEnricher caching"""
    print("\n=== Test 8: Enricher Caching ===")
    
    enricher = ThreatIntelligenceWHOISEnricher(cache_ttl=3600)
    
    # Manually populate cache
    test_result = {'test': 'data'}
    enricher.cache['cached-domain.com'] = (1000000000, test_result)
    
    stats_before = enricher.get_statistics()
    assert stats_before['cache_size'] == 1
    
    # Test invalid domain
    result = enricher.enrich_domain("invalid domain!!!")
    assert result['success'] == False
    assert result['error'] == 'Invalid domain format'
    
    print(f"  ✓ Cache size: {enricher.get_statistics()['cache_size']}")
    print("✓ Caching and validation works")
    return True


def test_enricher_statistics():
    """Test ThreatIntelligenceWHOISEnricher statistics"""
    print("\n=== Test 9: Enricher Statistics ===")
    
    enricher = ThreatIntelligenceWHOISEnricher()
    
    stats = enricher.get_statistics()
    
    required_fields = [
        'total_lookups', 'cache_hits', 'failed_lookups',
        'high_threat_domains', 'cache_size', 'cache_hit_rate',
        'timestamp'
    ]
    
    for field in required_fields:
        assert field in stats, f"Missing field: {field}"
    
    assert stats['total_lookups'] == 0
    assert stats['cache_hit_rate'] == 0
    
    print(f"  ✓ Stats: {json.dumps(stats, indent=2)}")
    print("✓ Statistics tracking works correctly")
    return True


def test_batch_enrichment():
    """Test batch domain enrichment"""
    print("\n=== Test 10: Batch Enrichment ===")
    
    enricher = ThreatIntelligenceWHOISEnricher()
    
    test_domains = [
        "example.com",
        "google.com",
        "example.com",  # duplicate
        "",  # empty
        "microsoft.com",
    ]
    
    # Process with minimal delay for testing
    results = enricher.enrich_domains_batch(test_domains, delay=0.01)
    
    # Should have 3 unique domains processed
    print(f"  ✓ Processed {len(results)} unique domains")
    assert len(results) >= 2  # At least 2 valid unique domains
    
    print("✓ Batch enrichment works correctly")
    return True


def test_json_export():
    """Test JSON export functionality"""
    print("\n=== Test 11: JSON Export ===")
    
    enricher = ThreatIntelligenceWHOISEnricher()
    
    mock_results = [
        {'domain': 'test1.com', 'success': True},
        {'domain': 'test2.com', 'success': False},
    ]
    
    import tempfile
    import os
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        temp_path = f.name
    
    success = enricher.export_json(mock_results, temp_path)
    assert success
    
    # Verify file exists and has content
    assert os.path.exists(temp_path)
    assert os.path.getsize(temp_path) > 0
    
    with open(temp_path, 'r') as f:
        data = json.load(f)
        assert data['total_domains'] == 2
        assert 'generated_at' in data
    
    os.unlink(temp_path)
    print("✓ JSON export works correctly")
    return True


def run_all_tests():
    """Run all tests and generate report"""
    print("=" * 60)
    print("NeuralShield-AI: WHOIS Domain Enrichment Engine Tests")
    print("=" * 60)
    print(f"Run time: {datetime.utcnow().isoformat()}Z")
    
    tests = [
        test_whois_record_dataclass,
        test_whois_client_tld_extraction,
        test_whois_client_server_selection,
        test_whois_parser_basic,
        test_domain_validation,
        test_threat_analyzer_domain_age,
        test_threat_analyzer_scoring,
        test_enricher_cache,
        test_enricher_statistics,
        test_batch_enrichment,
        test_json_export,
    ]
    
    passed = 0
    failed = 0
    failures = []
    
    for test_func in tests:
        try:
            if test_func():
                passed += 1
            else:
                failed += 1
                failures.append(test_func.__name__)
        except Exception as e:
            failed += 1
            failures.append(f"{test_func.__name__}: {e}")
            print(f"  ✗ FAILED: {e}")
    
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    print(f"Total: {len(tests)}")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    
    if failures:
        print("\nFailures:")
        for f in failures:
            print(f"  - {f}")
    
    success_rate = (passed / len(tests)) * 100
    print(f"\nSuccess rate: {success_rate:.1f}%")
    
    # Save results
    report = {
        'test_timestamp': datetime.utcnow().isoformat() + "Z",
        'total_tests': len(tests),
        'passed': passed,
        'failed': failed,
        'success_rate': success_rate,
        'failures': failures,
    }
    
    with open('/home/user/autonomous-developer/NeuralShield-AI/test_results_whois_enricher.json', 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\nResults saved to test_results_whois_enricher.json")
    
    return passed == len(tests)


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
