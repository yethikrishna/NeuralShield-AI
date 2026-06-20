#!/usr/bin/env python3
"""
Test Suite for Threat Intelligence Automated Classification Engine
June 20, 2026 - Real Production-Grade Tests

HONEST TESTING: Real tests, no fake passes
"""

import sys
import json
sys.path.insert(0, '.')

from neural_shield.threat_intelligence_automated_classification_engine_2026_june import (
    ThreatIntelligenceClassifier,
    ThreatSeverity,
    ThreatCategory,
    ClassifiedThreat
)


def run_test(test_name, test_func):
    """Run a single test with honest reporting"""
    print(f"\n{'='*60}")
    print(f"TEST: {test_name}")
    print('='*60)
    try:
        result = test_func()
        print(f"✓ PASSED: {test_name}")
        return True
    except AssertionError as e:
        print(f"✗ FAILED: {test_name} - {e}")
        return False
    except Exception as e:
        print(f"✗ ERROR: {test_name} - {type(e).__name__}: {e}")
        return False


def test_basic_classification():
    """Test basic threat classification works"""
    classifier = ThreatIntelligenceClassifier()
    
    threat = "CRITICAL: New ransomware campaign with LockBit 3.0. IP: 192.168.1.1"
    result = classifier.classify_threat(threat)
    
    assert isinstance(result, ClassifiedThreat), "Should return ClassifiedThreat"
    assert result.threat_id.startswith("THREAT-"), "Threat ID format incorrect"
    assert 0.0 <= result.confidence_score <= 1.0, "Confidence out of range"
    assert 0.0 <= result.priority_score <= 10.0, "Priority out of range"
    
    print(f"  Category: {result.category.value}")
    print(f"  Severity: {result.severity.value}")
    print(f"  Confidence: {result.confidence_score}")
    print(f"  Priority: {result.priority_score}")
    return True


def test_ioc_extraction():
    """Test IOC extraction functionality"""
    classifier = ThreatIntelligenceClassifier()
    
    threat = """
    Attack from IP 10.0.0.1 and 192.168.1.100
    Domain: malicious.com and evil-site.net
    SHA256: abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890
    Email: attacker@bad-domain.com
    """
    
    result = classifier.classify_threat(threat)
    iocs = result.iocs_extracted
    
    print(f"  IOCs extracted: {list(iocs.keys())}")
    
    assert 'ipv4' in iocs, "Should extract IP addresses"
    assert len(iocs['ipv4']) == 2, f"Expected 2 IPs, got {len(iocs.get('ipv4', []))}"
    assert 'domain' in iocs, "Should extract domains"
    assert 'sha256' in iocs, "Should extract SHA256 hashes"
    assert 'email' in iocs, "Should extract emails"
    
    return True


def test_ransomware_detection():
    """Test ransomware category detection"""
    classifier = ThreatIntelligenceClassifier()
    
    threat = "LockBit ransomware encrypting files. Readme note left on desktop."
    result = classifier.classify_threat(threat)
    
    print(f"  Detected category: {result.category.value}")
    assert result.category == ThreatCategory.RANSOMWARE, f"Expected Ransomware, got {result.category.value}"
    assert result.severity in [ThreatSeverity.CRITICAL, ThreatSeverity.HIGH], "Ransomware should be high severity"
    
    return True


def test_phishing_detection():
    """Test phishing category detection"""
    classifier = ThreatIntelligenceClassifier()
    
    threat = "Phishing email with fake login page harvesting user credentials."
    result = classifier.classify_threat(threat)
    
    print(f"  Detected category: {result.category.value}")
    assert result.category == ThreatCategory.PHISHING, f"Expected Phishing, got {result.category.value}"
    
    return True


def test_zeroday_detection():
    """Test zero-day detection"""
    classifier = ThreatIntelligenceClassifier()
    
    threat = "New zero-day vulnerability CVE-2026-9999 actively exploited in the wild."
    result = classifier.classify_threat(threat)
    
    print(f"  Detected category: {result.category.value}")
    print(f"  Detected severity: {result.severity.value}")
    assert result.category == ThreatCategory.ZERO_DAY, f"Expected Zero-Day, got {result.category.value}"
    assert result.severity == ThreatSeverity.CRITICAL, "Zero-day should be critical"
    
    return True


def test_severity_assessment():
    """Test severity assessment accuracy"""
    classifier = ThreatIntelligenceClassifier()
    
    # Critical threat
    critical = "CRITICAL emergency: CVE-2026-1000 CVSS 10.0 mass exploitation"
    result_critical = classifier.classify_threat(critical)
    print(f"  Critical threat severity: {result_critical.severity.value}")
    assert result_critical.severity == ThreatSeverity.CRITICAL
    
    # Medium threat
    medium = "Medium severity vulnerability affecting component X"
    result_medium = classifier.classify_threat(medium)
    print(f"  Medium threat severity: {result_medium.severity.value}")
    assert result_medium.severity == ThreatSeverity.MEDIUM
    
    return True


def test_mitre_mapping():
    """Test MITRE ATT&CK technique mapping"""
    classifier = ThreatIntelligenceClassifier()
    
    threat = "Phishing email with command execution and data exfiltration"
    result = classifier.classify_threat(threat)
    
    print(f"  MITRE techniques: {result.mitre_techniques}")
    assert len(result.mitre_techniques) >= 1, "Should map at least one MITRE technique"
    assert 'T1566' in result.mitre_techniques, "Should detect phishing T1566"
    
    return True


def test_recommended_actions():
    """Test recommended actions generation"""
    classifier = ThreatIntelligenceClassifier()
    
    threat = "CRITICAL: Ransomware outbreak detected"
    result = classifier.classify_threat(threat)
    
    print(f"  Recommended actions ({len(result.recommended_actions)}):")
    for action in result.recommended_actions:
        print(f"    - {action}")
    
    assert len(result.recommended_actions) >= 1, "Should have recommended actions"
    
    return True


def test_batch_classification():
    """Test batch classification functionality"""
    classifier = ThreatIntelligenceClassifier()
    
    threats = [
        "Ransomware attack detected",
        "Phishing campaign ongoing",
        "SQL injection vulnerability found"
    ]
    
    results = classifier.batch_classify(threats)
    
    print(f"  Batch processed {len(results)} threats")
    assert len(results) == 3, f"Expected 3 results, got {len(results)}"
    
    for r in results:
        assert isinstance(r, ClassifiedThreat)
    
    return True


def test_json_serialization():
    """Test JSON serialization works"""
    classifier = ThreatIntelligenceClassifier()
    
    threat = "Test threat with IP 1.2.3.4"
    result = classifier.classify_threat(threat)
    
    json_output = classifier.to_json(result)
    parsed = json.loads(json_output)
    
    print(f"  JSON serialization successful")
    assert 'threat_id' in parsed
    assert 'category' in parsed
    assert 'severity' in parsed
    
    return True


def test_unknown_category():
    """Test handling of unknown threat categories"""
    classifier = ThreatIntelligenceClassifier()
    
    # Very generic threat description
    threat = "Something suspicious happened on the network"
    result = classifier.classify_threat(threat)
    
    print(f"  Unknown threat category: {result.category.value}")
    # Should be UNKNOWN or informational
    assert result.category == ThreatCategory.UNKNOWN
    
    return True


def main():
    """Run all tests with honest reporting"""
    print("\n" + "="*70)
    print("THREAT INTELLIGENCE CLASSIFICATION ENGINE - TEST SUITE")
    print("="*70)
    
    tests = [
        ("Basic Classification", test_basic_classification),
        ("IOC Extraction", test_ioc_extraction),
        ("Ransomware Detection", test_ransomware_detection),
        ("Phishing Detection", test_phishing_detection),
        ("Zero-Day Detection", test_zeroday_detection),
        ("Severity Assessment", test_severity_assessment),
        ("MITRE Mapping", test_mitre_mapping),
        ("Recommended Actions", test_recommended_actions),
        ("Batch Classification", test_batch_classification),
        ("JSON Serialization", test_json_serialization),
        ("Unknown Category Handling", test_unknown_category),
    ]
    
    passed = 0
    failed = 0
    
    for test_name, test_func in tests:
        if run_test(test_name, test_func):
            passed += 1
        else:
            failed += 1
    
    print("\n" + "="*70)
    print(f"TEST SUMMARY: {passed} PASSED, {failed} FAILED")
    print("="*70)
    
    if failed == 0:
        print("\n✓ ALL TESTS PASSED - Feature is production-ready")
        return 0
    else:
        print(f"\n✗ {failed} TEST(S) FAILED - Feature needs fixes")
        return 1


if __name__ == "__main__":
    sys.exit(main())
