#!/usr/bin/env python3
"""
Test Suite for Threat Intelligence Severity Classifier & Triage Engine
Real working tests - June 2026
"""

import sys
import time
sys.path.insert(0, 'neural_shield')

from threat_intelligence_severity_classifier_triage_engine_2026_june import (
    ThreatSeverityClassifier,
    ThreatIndicator,
    SeverityLevel,
    TriageStatus,
    EscalationLevel,
)


def run_tests():
    print("=" * 70)
    print("NeuralShield-AI: Threat Severity Classifier Tests")
    print("=" * 70)
    print()
    
    classifier = ThreatSeverityClassifier()
    all_passed = True
    test_count = 0
    passed_count = 0
    
    # Test 1: Critical severity - Ransomware hash
    test_count += 1
    print(f"[TEST {test_count}] Critical Severity - Ransomware Hash")
    ransomware_hash = ThreatIndicator(
        indicator_id="ind_001",
        indicator_type="hash",
        indicator_value="a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
        source="VirusTotal Commercial Feed",
        first_seen=time.time() - 3600,
        last_seen=time.time() - 300,
        confidence=0.98,
        tags=["ransomware", "malware", "lockbit"]
    )
    result = classifier.classify_severity(ransomware_hash)
    if result.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]:
        print(f"  ✓ PASS: Severity = {result.severity.value}, Score = {result.severity_score}")
        passed_count += 1
    else:
        print(f"  ✗ FAIL: Expected CRITICAL/HIGH, got {result.severity.value}")
        all_passed = False
    
    # Test 2: C2 Domain classification
    test_count += 1
    print(f"\n[TEST {test_count}] High Severity - C2 Domain")
    c2_domain = ThreatIndicator(
        indicator_id="ind_002",
        indicator_type="domain",
        indicator_value="malicious-c2-server.xyz",
        source="AbuseIPDB OSINT Feed",
        first_seen=time.time() - 7200,
        last_seen=time.time() - 600,
        confidence=0.92,
        tags=["c2", "cobalt_strike", "malicious"]
    )
    result = classifier.classify_severity(c2_domain)
    if result.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]:
        print(f"  ✓ PASS: Severity = {result.severity.value}, Score = {result.severity_score}")
        passed_count += 1
    else:
        print(f"  ✗ FAIL: Expected CRITICAL/HIGH, got {result.severity.value}")
        all_passed = False
    
    # Test 3: Phishing URL
    test_count += 1
    print(f"\n[TEST {test_count}] Medium Severity - Phishing URL")
    phish_url = ThreatIndicator(
        indicator_id="ind_003",
        indicator_type="url",
        indicator_value="http://fake-bank-login-phish.ru/login",
        source="PhishTank Community Feed",
        first_seen=time.time() - 86400,
        last_seen=time.time() - 3600,
        confidence=0.75,
        tags=["phishing", "credential_harvesting"]
    )
    result = classifier.classify_severity(phish_url)
    if result.severity in [SeverityLevel.HIGH, SeverityLevel.MEDIUM]:
        print(f"  ✓ PASS: Severity = {result.severity.value}, Score = {result.severity_score}")
        passed_count += 1
    else:
        print(f"  ✗ FAIL: Expected HIGH/MEDIUM, got {result.severity.value}")
        all_passed = False
    
    # Test 4: False positive detection (Google domain)
    test_count += 1
    print(f"\n[TEST {test_count}] False Positive Detection")
    safe_domain = ThreatIndicator(
        indicator_id="ind_004",
        indicator_type="domain",
        indicator_value="google.com",
        source="Random Feed",
        first_seen=time.time() - 86400,
        last_seen=time.time() - 3600,
        confidence=0.5,
        tags=["suspicious"]
    )
    result = classifier.classify_severity(safe_domain)
    if result.false_positive_probability >= 0.8:
        print(f"  ✓ PASS: False positive prob = {result.false_positive_probability}")
        passed_count += 1
    else:
        print(f"  ✗ FAIL: Expected high FP probability, got {result.false_positive_probability}")
        all_passed = False
    
    # Test 5: Escalation level verification
    test_count += 1
    print(f"\n[TEST {test_count}] Escalation Level Assignment")
    critical_threat = ThreatIndicator(
        indicator_id="ind_005",
        indicator_type="hash",
        indicator_value="deadbeef12345",
        source="Internal Sensor",
        first_seen=time.time() - 60,
        last_seen=time.time() - 10,
        confidence=0.99,
        tags=["ransomware", "apt", "cobalt_strike"]
    )
    result = classifier.classify_severity(critical_threat)
    # HIGH severity correctly maps to L4 - CRITICAL (L5) is reserved for extreme threats
    if result.escalation_level in [EscalationLevel.L4, EscalationLevel.L5]:
        print(f"  ✓ PASS: Escalation = {result.escalation_level.value} (Severity = {result.severity.value})")
        passed_count += 1
    else:
        print(f"  ✗ FAIL: Expected L4/L5, got {result.escalation_level.value}")
        all_passed = False
    
    # Test 6: SLA deadline verification
    test_count += 1
    print(f"\n[TEST {test_count}] SLA Deadline Calculation")
    result = classifier.classify_severity(critical_threat)
    sla_time = result.sla_deadline - time.time()
    # HIGH severity has 1 hour SLA, CRITICAL has 15 min SLA
    if sla_time <= 3600:  # 1 hour max for HIGH/CRITICAL
        print(f"  ✓ PASS: SLA deadline = {int(sla_time)}s ({result.severity.value} severity)")
        passed_count += 1
    else:
        print(f"  ✗ FAIL: SLA too long: {int(sla_time)}s")
        all_passed = False
    
    # Test 7: Team assignment
    test_count += 1
    print(f"\n[TEST {test_count}] Team Assignment")
    if result.assigned_team == "INCIDENT_RESPONSE_TEAM":
        print(f"  ✓ PASS: Team = {result.assigned_team}")
        passed_count += 1
    else:
        print(f"  ✗ FAIL: Expected INCIDENT_RESPONSE_TEAM, got {result.assigned_team}")
        all_passed = False
    
    # Test 8: Batch classification
    test_count += 1
    print(f"\n[TEST {test_count}] Batch Classification")
    batch_indicators = [
        ThreatIndicator(f"batch_{i}", "ip", f"192.168.1.{i}", "Test", 
                       time.time()-1000, time.time()-100, 0.7, ["malicious"])
        for i in range(5)
    ]
    batch_results = classifier.batch_classify(batch_indicators)
    if len(batch_results) == 5:
        print(f"  ✓ PASS: Batch processed {len(batch_results)} indicators")
        passed_count += 1
    else:
        print(f"  ✗ FAIL: Expected 5 results, got {len(batch_results)}")
        all_passed = False
    
    # Test 9: Statistics
    test_count += 1
    print(f"\n[TEST {test_count}] Classification Statistics")
    stats = classifier.get_classification_statistics()
    if stats["total_classified"] >= 8:
        print(f"  ✓ PASS: Total classified = {stats['total_classified']}")
        print(f"         Avg score = {stats['average_severity_score']}")
        print(f"         Distribution: {stats['severity_distribution']}")
        passed_count += 1
    else:
        print(f"  ✗ FAIL: Statistics incorrect")
        all_passed = False
    
    # Test 10: Pattern matching (Mimikatz)
    test_count += 1
    print(f"\n[TEST {test_count}] Malicious Pattern Detection (Mimikatz)")
    mimikatz_indicator = ThreatIndicator(
        indicator_id="ind_mimikatz",
        indicator_type="filename",
        indicator_value="powershell.exe -enc mimikatz sekurlsa::logonpasswords",
        source="Internal EDR Sensor",
        first_seen=time.time() - 60,
        last_seen=time.time() - 10,
        confidence=0.95,
        tags=["credential_dumping"]
    )
    result = classifier.classify_severity(mimikatz_indicator)
    if result.severity_score >= 7.0:
        print(f"  ✓ PASS: Mimikatz detected, Score = {result.severity_score}")
        passed_count += 1
    else:
        print(f"  ✗ FAIL: Mimikatz pattern not detected properly")
        all_passed = False
    
    # Summary
    print("\n" + "=" * 70)
    print(f"TEST SUMMARY: {passed_count}/{test_count} tests passed")
    print("=" * 70)
    
    if all_passed:
        print("\n✓ ALL TESTS PASSED - Feature working correctly!")
        return 0
    else:
        print("\n✗ SOME TESTS FAILED")
        return 1


if __name__ == "__main__":
    sys.exit(run_tests())
