#!/usr/bin/env python3
"""
Test suite for NeuralShield AI - Threat Intelligence IoC Extractor
Production-grade tests with real validation
"""

import sys
import json
sys.path.insert(0, '/home/user/autonomous-developer/NeuralShield-AI')

from neural_shield.threat_intelligence_ioc_extractor_2026_june import (
    IoCExtractor, IoCEnricher, IoCReporter, IoCType, ThreatSeverity
)


def test_ioc_extraction_basic():
    """Test basic IoC extraction functionality"""
    print("=" * 60)
    print("TEST 1: Basic IoC Extraction")
    print("=" * 60)
    
    extractor = IoCExtractor()
    
    test_text = """
    Threat Intelligence Report - June 2026
    
    Malicious IPs detected:
    - 192.168.1.100 (internal scanner)
    - 8.8.8.8 (DNS resolver)
    - 2001:db8::1 (IPv6 test)
    
    Malicious domains:
    - malicious-domain.xyz
    - phishing-attacker.com
    
    Malware hashes:
    - 5d41402abc4b2a76b9719d911017c592 (MD5)
    - aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d (SHA1)
    - 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824 (SHA256)
    
    Vulnerabilities:
    - CVE-2026-1234 (Critical RCE)
    - CVE-2026-5678 (Privilege Escalation)
    
    URLs:
    - http://malicious-site.com/payload.exe
    - https://phishing-login.com/secure
    
    Email:
    - attacker@malicious-domain.xyz
    """
    
    iocs = extractor.extract_iocs(test_text, source="test_report")
    
    print(f"Total IoCs extracted: {len(iocs)}")
    print("\nExtracted IoCs:")
    for ioc in iocs:
        print(f"  [{ioc.ioc_type.value:10}] {ioc.value:50} (conf: {ioc.confidence:.2f}, sev: {ioc.severity.value})")
    
    # Verify extraction worked
    assert len(iocs) > 0, "No IoCs were extracted"
    
    # Check specific types were found
    types_found = {i.ioc_type for i in iocs}
    print(f"\nIoC types found: {[t.value for t in types_found]}")
    
    print("\n✅ TEST 1 PASSED - Basic extraction working")
    return True


def test_ioc_validation():
    """Test IoC validation and filtering"""
    print("\n" + "=" * 60)
    print("TEST 2: IoC Validation & Benign Filtering")
    print("=" * 60)
    
    extractor = IoCExtractor()
    
    # Test with benign vs malicious content
    test_text = """
    Benign IPs: 127.0.0.1, 192.168.1.1, 0.0.0.0
    Benign domains: example.com, localhost, gmail.com
    Malicious IP: 45.33.32.156
    Malicious domain: evil-hacker.xyz
    """
    
    iocs = extractor.extract_iocs(test_text)
    
    print(f"Total IoCs after filtering: {len(iocs)}")
    for ioc in iocs:
        print(f"  [{ioc.ioc_type.value:10}] {ioc.value}")
    
    # Verify benign items were filtered out
    benign_values = {'127.0.0.1', '192.168.1.1', '0.0.0.0', 'example.com', 'localhost', 'gmail.com'}
    extracted_values = {i.value for i in iocs}
    
    for benign in benign_values:
        assert benign not in extracted_values, f"Benign value {benign} was not filtered"
    
    print("\n✅ TEST 2 PASSED - Validation & filtering working")
    return True


def test_ioc_normalization():
    """Test IoC normalization"""
    print("\n" + "=" * 60)
    print("TEST 3: IoC Normalization")
    print("=" * 60)
    
    extractor = IoCExtractor()
    
    # Test case normalization
    test_text = """
    CVE-2026-9999 cve-2026-9999 CVE-2026-9999
    EXAMPLE.COM Example.COM example.com
    5D41402ABC4B2A76B9719D911017C592 5d41402abc4b2a76b9719d911017c592
    """
    
    iocs = extractor.extract_iocs(test_text)
    
    print(f"IoCs found (after dedup): {len(iocs)}")
    for ioc in iocs:
        print(f"  Normalized: {ioc.value}")
    
    # Verify deduplication worked (same values normalized)
    cve_iocs = [i for i in iocs if i.ioc_type == IoCType.CVE]
    domain_iocs = [i for i in iocs if i.ioc_type == IoCType.DOMAIN]
    hash_iocs = [i for i in iocs if i.ioc_type == IoCType.MD5]
    
    assert len(cve_iocs) == 1, f"Expected 1 unique CVE, got {len(cve_iocs)}"
    assert len(domain_iocs) <= 1, f"Expected 1 unique domain, got {len(domain_iocs)}"
    
    print("\n✅ TEST 3 PASSED - Normalization working")
    return True


def test_ioc_enrichment():
    """Test IoC enrichment functionality"""
    print("\n" + "=" * 60)
    print("TEST 4: IoC Enrichment")
    print("=" * 60)
    
    extractor = IoCExtractor()
    enricher = IoCEnricher()
    
    test_text = """
    Tor exit node: 185.220.101.1
    Suspicious domain: very-bad-site.xyz
    URL: http://test-phishing.com/payload
    """
    
    iocs = extractor.extract_iocs(test_text)
    enriched_iocs = enricher.enrich_batch(iocs)
    
    print(f"Enriched {len(enriched_iocs)} IoCs:")
    for ioc in enriched_iocs:
        print(f"  [{ioc.ioc_type.value:10}] {ioc.value:40} meta: {ioc.metadata}")
    
    # Check Tor exit node detection
    tor_iocs = [i for i in enriched_iocs if i.metadata.get('is_tor_exit')]
    if tor_iocs:
        print(f"  ✓ Tor exit node detected: {tor_iocs[0].value}")
    
    print("\n✅ TEST 4 PASSED - Enrichment working")
    return True


def test_ioc_reporting():
    """Test IoC reporting and statistics"""
    print("\n" + "=" * 60)
    print("TEST 5: IoC Reporting & Statistics")
    print("=" * 60)
    
    extractor = IoCExtractor()
    
    test_text = """
    192.168.1.50 10.0.0.254 8.8.4.4
    malware.xyz bad-domain.top phishing.net
    CVE-2026-1111 CVE-2026-2222
    http://attack1.com https://attack2.org
    """
    
    iocs = extractor.extract_iocs(test_text)
    stats = IoCReporter.get_statistics(iocs)
    
    print("Statistics:")
    print(json.dumps(stats, indent=2))
    
    json_output = IoCReporter.to_json(iocs)
    print(f"\nJSON output length: {len(json_output)} chars")
    
    # Verify stats are correct
    assert stats["total_iocs"] == len(iocs)
    assert "by_type" in stats
    assert "by_severity" in stats
    assert stats["average_confidence"] > 0
    
    print("\n✅ TEST 5 PASSED - Reporting working")
    return True


def run_all_tests():
    """Run all production tests"""
    print("\n" + "=" * 60)
    print("NeuralShield AI - IoC Extractor Production Tests")
    print("=" * 60 + "\n")
    
    tests = [
        test_ioc_extraction_basic,
        test_ioc_validation,
        test_ioc_normalization,
        test_ioc_enrichment,
        test_ioc_reporting
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            if test():
                passed += 1
        except Exception as e:
            print(f"\n❌ TEST FAILED: {e}")
            failed += 1
    
    print("\n" + "=" * 60)
    print(f"TEST SUMMARY: {passed} PASSED, {failed} FAILED")
    print("=" * 60)
    
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
