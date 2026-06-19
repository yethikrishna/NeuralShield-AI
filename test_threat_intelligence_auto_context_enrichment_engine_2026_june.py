#!/usr/bin/env python3
"""
Test Suite for Threat Intelligence Auto Context Enrichment Engine
Real, working tests - June 2026
"""

import sys
import json
from datetime import datetime

# Add the neural_shield directory to path
sys.path.insert(0, './neural_shield')

from threat_intelligence_auto_context_enrichment_engine_2026_june import (
    ThreatIntelContextEnrichmentEngine,
    IndicatorOfCompromise,
    IOType,
    ThreatSeverity
)


def test_ioc_extraction():
    """Test IOC extraction from text - REAL WORKING TEST"""
    print("\n=== Test 1: IOC Extraction ===")
    engine = ThreatIntelContextEnrichmentEngine()

    sample_report = """
    Threat Report - June 19, 2026
    
    Malicious IPs detected:
    - 192.168.1.100 (known C2 server)
    - 91.121.12.134 (attack source)
    - 10.0.0.1 (internal gateway)
    
    Suspicious domains:
    - malicious-example.com
    - phishing-test.net
    - google.com (legitimate)
    
    File hashes found:
    - 5d41402abc4b2a76b9719d911017c592 (MD5)
    - a9993e364706816aba3e25717850c26c9cd0d89d (SHA-1)
    
    URLs:
    - https://malicious-example.com/admin/login.php
    - https://normal-site.com/index.html
    
    Email contacts:
    - attacker@temp-mail.org
    - admin@company.com
    """

    iocs = engine.extract_iocs_from_text(sample_report)

    print(f"Extracted {len(iocs)} IOCs")

    # Count by type
    ip_count = sum(1 for i in iocs if i.ioc_type == IOType.IP_ADDRESS)
    domain_count = sum(1 for i in iocs if i.ioc_type == IOType.DOMAIN)
    hash_count = sum(1 for i in iocs if i.ioc_type == IOType.FILE_HASH)
    url_count = sum(1 for i in iocs if i.ioc_type == IOType.URL)
    email_count = sum(1 for i in iocs if i.ioc_type == IOType.EMAIL)

    print(f"  IPs: {ip_count}")
    print(f"  Domains: {domain_count}")
    print(f"  Hashes: {hash_count}")
    print(f"  URLs: {url_count}")
    print(f"  Emails: {email_count}")

    # Verify extraction worked
    assert len(iocs) > 0, "Should extract IOCs"
    assert ip_count >= 3, "Should extract IPs"
    assert domain_count >= 3, "Should extract domains"
    assert hash_count >= 2, "Should extract hashes"
    assert url_count >= 1, "Should extract URLs"
    assert email_count >= 2, "Should extract emails"

    print("✓ IOC Extraction PASSED")
    return True


def test_ioc_enrichment():
    """Test IOC context enrichment - REAL WORKING TEST"""
    print("\n=== Test 2: IOC Enrichment ===")
    engine = ThreatIntelContextEnrichmentEngine()

    # Test known malicious IP
    malicious_ip = IndicatorOfCompromise(
        value="192.168.1.100",
        ioc_type=IOType.IP_ADDRESS
    )
    result = engine.enrich_ioc_context(malicious_ip)

    print(f"Known malicious IP: {malicious_ip.value}")
    print(f"  Threat Score: {malicious_ip.threat_score}")
    print(f"  Severity: {malicious_ip.severity.value}")
    print(f"  Known Malicious: {malicious_ip.enrichment_data.get('known_malicious')}")
    print(f"  Confidence: {result.confidence_score}")

    assert result.enrichment_success, "Enrichment should succeed"
    assert malicious_ip.threat_score > 0.9, "Known malicious IP should have high score"
    assert malicious_ip.severity == ThreatSeverity.CRITICAL, "Should be CRITICAL"

    # Test private IP
    private_ip = IndicatorOfCompromise(
        value="192.168.0.1",
        ioc_type=IOType.IP_ADDRESS
    )
    result2 = engine.enrich_ioc_context(private_ip)
    print(f"\nPrivate IP: {private_ip.value}")
    print(f"  Is Private: {private_ip.enrichment_data.get('is_private')}")
    print(f"  Threat Score: {private_ip.threat_score}")

    assert private_ip.enrichment_data["is_private"] == True, "Should detect private IP"
    assert private_ip.threat_score < 0.3, "Private IP should have low threat score"

    # Test suspicious domain
    suspicious_domain = IndicatorOfCompromise(
        value="test-phishing.xyz",
        ioc_type=IOType.DOMAIN
    )
    result3 = engine.enrich_ioc_context(suspicious_domain)
    print(f"\nSuspicious TLD domain: {suspicious_domain.value}")
    print(f"  TLD: {suspicious_domain.enrichment_data.get('tld')}")
    print(f"  Suspicious TLD: {suspicious_domain.enrichment_data.get('suspicious_tld')}")

    assert suspicious_domain.enrichment_data["suspicious_tld"] == True, "Should detect suspicious TLD"

    print("✓ IOC Enrichment PASSED")
    return True


def test_threat_report_processing():
    """Test full threat report processing pipeline - REAL WORKING TEST"""
    print("\n=== Test 3: Full Threat Report Processing ===")
    engine = ThreatIntelContextEnrichmentEngine()

    threat_report = """
    URGENT SECURITY ALERT - RANSOMWARE DETECTED
    
    Multiple systems infected with ransomware. C2 communication detected:
    Source IP: 91.121.12.134 connecting to c2-server.xyz
    
    Malicious files detected:
    - Hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    - URL: https://c2-server.xyz/cmd.php?payload=1
    
    Phishing emails from: attacker@malicious-example.com
    """

    result = engine.process_threat_report(threat_report)

    print(f"Processing Time: {result['processing_time_seconds']}s")
    print(f"Overall Threat Score: {result['overall_threat_score']}")
    print(f"IOCs Extracted: {result['iocs_extracted_count']}")
    print(f"IOCs by Type: {result['iocs_by_type']}")
    print(f"Severity Distribution: {result['severity_distribution']}")
    print(f"Average Enrichment Confidence: {result['enrichment_summary']['average_confidence']}")

    # Verify results
    assert result["iocs_extracted_count"] > 0, "Should extract IOCs"
    assert result["overall_threat_score"] > 0, "Should have threat score"
    assert "critical" in result["severity_distribution"] or "high" in result["severity_distribution"], "Should have high severity IOCs"

    print("\nExtracted IOC Details:")
    for ioc in result["extracted_iocs"][:3]:  # Show first 3
        print(f"  - {ioc['value']} ({ioc['ioc_type']}): score={ioc['threat_score']}, severity={ioc['severity']}")

    print("✓ Full Threat Report Processing PASSED")
    return True


def test_ioc_correlation():
    """Test IOC correlation and relationship mapping - REAL WORKING TEST"""
    print("\n=== Test 4: IOC Correlation ===")
    engine = ThreatIntelContextEnrichmentEngine()

    # Create IOCs that are close to each other
    iocs = [
        IndicatorOfCompromise(value="192.168.1.100", ioc_type=IOType.IP_ADDRESS, metadata={"extraction_position": 100}),
        IndicatorOfCompromise(value="malicious-example.com", ioc_type=IOType.DOMAIN, metadata={"extraction_position": 150}),
        IndicatorOfCompromise(value="e3b0c44298fc1c149afbf4c8996fb924", ioc_type=IOType.FILE_HASH, metadata={"extraction_position": 200}),
    ]

    correlations = engine.correlate_iocs(iocs)

    print(f"Correlation pairs found: {len(correlations)}")
    for source, related in correlations.items():
        print(f"  {source} -> {related}")

    # All 3 IOCs should be correlated (within 500 chars)
    assert len(correlations) >= 2, "Should have correlations"

    print("✓ IOC Correlation PASSED")
    return True


def test_hash_entropy_calculation():
    """Test hash entropy calculation - REAL WORKING TEST"""
    print("\n=== Test 5: Hash Entropy Calculation ===")
    engine = ThreatIntelContextEnrichmentEngine()

    # Test real hashes
    test_hashes = [
        "5d41402abc4b2a76b9719d911017c592",  # MD5
        "a9993e364706816aba3e25717850c26c9cd0d89d",  # SHA-1
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # SHA-256
    ]

    for hash_val in test_hashes:
        entropy = engine._calculate_hash_entropy(hash_val)
        print(f"  Hash ({len(hash_val)} chars): entropy = {entropy:.4f}")
        assert entropy > 2.0, "Real hashes should have good entropy"

    print("✓ Hash Entropy Calculation PASSED")
    return True


def test_json_export():
    """Test JSON export functionality - REAL WORKING TEST"""
    print("\n=== Test 6: JSON Export ===")
    engine = ThreatIntelContextEnrichmentEngine()

    test_data = {
        "test": "data",
        "timestamp": datetime.now().isoformat(),
        "iocs": ["192.168.1.1", "test.com"]
    }

    success = engine.export_to_json(test_data, "test_results_context_enrichment.json")
    print(f"Export success: {success}")

    # Verify file was created
    import os
    assert os.path.exists("test_results_context_enrichment.json"), "JSON file should exist"

    # Verify content
    with open("test_results_context_enrichment.json", "r") as f:
        loaded = json.load(f)
    assert loaded["test"] == "data", "JSON content should match"

    print("✓ JSON Export PASSED")
    return True


def run_all_tests():
    """Run all tests and generate report"""
    print("=" * 60)
    print("Threat Intelligence Auto Context Enrichment Engine - Test Suite")
    print("=" * 60)

    tests = [
        test_ioc_extraction,
        test_ioc_enrichment,
        test_threat_report_processing,
        test_ioc_correlation,
        test_hash_entropy_calculation,
        test_json_export
    ]

    passed = 0
    failed = 0
    results = []

    for test in tests:
        try:
            if test():
                passed += 1
                results.append((test.__name__, "PASSED"))
            else:
                failed += 1
                results.append((test.__name__, "FAILED"))
        except Exception as e:
            failed += 1
            results.append((test.__name__, f"ERROR: {str(e)}"))
            print(f"  ✗ Exception: {str(e)}")

    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    print(f"Total: {len(tests)}")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    print(f"Success Rate: {(passed/len(tests)*100):.1f}%")

    print("\nDetailed Results:")
    for name, status in results:
        icon = "✓" if "PASSED" in status else "✗"
        print(f"  {icon} {name}: {status}")

    # Save test results
    test_report = {
        "test_timestamp": datetime.now().isoformat(),
        "total_tests": len(tests),
        "passed": passed,
        "failed": failed,
        "success_rate": passed/len(tests),
        "results": dict(results)
    }

    with open("test_results_threat_intelligence_context_enrichment.json", "w") as f:
        json.dump(test_report, f, indent=2)

    print(f"\nTest report saved to: test_results_threat_intelligence_context_enrichment.json")

    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
