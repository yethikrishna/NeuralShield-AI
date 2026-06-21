#!/usr/bin/env python3
"""
Test suite for Threat Intelligence Alert Correlation & Context Enrichment Engine v62
Real production-grade tests
"""

import sys
import json
import time

# Add the module to path
sys.path.insert(0, '/home/user/autonomous-developer/NeuralShield-AI')

from neural_shield.threat_intelligence_alert_correlation_context_enricher_v62_2026_june import (
    ThreatIndicator,
    SecurityAlert,
    ContextEnricher,
    AlertCorrelator
)


def test_threat_indicator():
    """Test ThreatIndicator data structure"""
    print("Testing ThreatIndicator...")
    
    indicator = ThreatIndicator(
        type="ip",
        value="192.168.1.1",
        source="test_source",
        first_seen=time.time(),
        last_seen=time.time(),
        confidence=0.85,
        threat_type="scanning",
        severity="high"
    )
    
    assert indicator.type == "ip"
    assert indicator.value == "192.168.1.1"
    assert indicator.confidence == 0.85
    
    # Test hash generation
    hash1 = indicator.get_hash()
    indicator2 = ThreatIndicator(
        type="ip",
        value="192.168.1.1",
        source="different",
        first_seen=time.time(),
        last_seen=time.time(),
        confidence=0.9,
        threat_type="c2",
        severity="critical"
    )
    hash2 = indicator2.get_hash()
    
    assert hash1 == hash2, "Same indicator values should produce same hash"
    print("  ✓ ThreatIndicator tests passed")
    return True


def test_security_alert():
    """Test SecurityAlert data structure"""
    print("Testing SecurityAlert...")
    
    indicator = ThreatIndicator(
        type="ip",
        value="10.0.0.1",
        source="test",
        first_seen=time.time(),
        last_seen=time.time(),
        confidence=0.9,
        threat_type="malware",
        severity="critical"
    )
    
    alert = SecurityAlert(
        alert_id="TEST-001",
        timestamp=time.time(),
        source="firewall",
        alert_type="malware_detection",
        severity="high",
        indicators=[indicator]
    )
    
    assert alert.alert_id == "TEST-001"
    assert len(alert.indicators) == 1
    
    key = alert.get_alert_key()
    assert len(key) == 12  # 12 character hex key
    
    print("  ✓ SecurityAlert tests passed")
    return True


def test_context_enricher():
    """Test ContextEnricher functionality"""
    print("Testing ContextEnricher...")
    
    enricher = ContextEnricher()
    
    # Test whitelist
    whitelisted_indicator = ThreatIndicator(
        type="ip",
        value="8.8.8.8",
        source="test",
        first_seen=time.time(),
        last_seen=time.time(),
        confidence=0.5,
        threat_type="unknown",
        severity="low"
    )
    assert enricher.is_whitelisted(whitelisted_indicator) == True
    
    # Test non-whitelisted
    malicious_indicator = ThreatIndicator(
        type="ip",
        value="192.0.2.1",
        source="test",
        first_seen=time.time(),
        last_seen=time.time(),
        confidence=0.9,
        threat_type="c2",
        severity="high"
    )
    assert enricher.is_whitelisted(malicious_indicator) == False
    
    # Test IP enrichment
    ip_context = enricher.enrich_ip("192.168.1.1")
    assert ip_context["is_private"] == True
    assert ip_context["is_loopback"] == False
    
    # Test URL enrichment
    url_context = enricher.enrich_url("http://evil-login-bank.com/login.php?user=test")
    assert url_context["has_suspicious_patterns"] == True
    assert url_context["suspicious_score"] > 0
    
    # Test full indicator enrichment
    enrichment = enricher.enrich_indicator(malicious_indicator)
    assert "enrichment_timestamp" in enrichment
    assert enrichment["is_whitelisted"] == False
    
    print("  ✓ ContextEnricher tests passed")
    return True


def test_alert_correlator():
    """Test AlertCorrelator functionality"""
    print("Testing AlertCorrelator...")
    
    correlator = AlertCorrelator(time_window_minutes=60)
    
    # Create test alerts
    indicator1 = ThreatIndicator(
        type="ip",
        value="192.0.2.100",
        source="ti_feed",
        first_seen=time.time(),
        last_seen=time.time(),
        confidence=0.95,
        threat_type="c2",
        severity="critical"
    )
    
    indicator2 = ThreatIndicator(
        type="ip",
        value="192.0.2.100",
        source="other_feed",
        first_seen=time.time(),
        last_seen=time.time(),
        confidence=0.9,
        threat_type="c2",
        severity="critical"
    )
    
    # Create two similar alerts (should be deduplicated)
    alert1 = SecurityAlert(
        alert_id="ALERT-001",
        timestamp=time.time(),
        source="ids",
        alert_type="c2_connection",
        severity="high",
        indicators=[indicator1]
    )
    
    alert2 = SecurityAlert(
        alert_id="ALERT-002",
        timestamp=time.time() + 300,  # 5 minutes later
        source="ids",
        alert_type="c2_connection",
        severity="high",
        indicators=[indicator2]
    )
    
    # Test deduplication
    unique, duplicates = correlator.deduplicate_alerts([alert1, alert2])
    assert len(unique) == 1
    assert len(duplicates) == 1
    
    # Test similarity calculation
    sim_score = correlator.calculate_similarity(alert1, alert2)
    assert sim_score > 0.7  # High similarity expected
    
    # Test alert enrichment
    enriched = correlator.enrich_alert(alert1)
    assert enriched.enriched_context["indicators_enriched"] > 0
    assert "false_positive_probability" in enriched.__dict__
    
    print("  ✓ AlertCorrelator basic tests passed")
    return True


def test_full_processing_pipeline():
    """Test full end-to-end processing pipeline"""
    print("Testing full processing pipeline...")
    
    correlator = AlertCorrelator(time_window_minutes=60)
    
    # Create multiple test alerts
    alerts = []
    
    # Alert group 1: C2 communications
    for i in range(3):
        indicator = ThreatIndicator(
            type="ip",
            value="192.0.2.100",
            source=f"feed_{i}",
            first_seen=time.time(),
            last_seen=time.time(),
            confidence=0.8 + (i * 0.05),
            threat_type="c2",
            severity="critical"
        )
        alert = SecurityAlert(
            alert_id=f"C2-{i:03d}",
            timestamp=time.time() + (i * 60),
            source="ids",
            alert_type="c2_connection",
            severity="critical",
            indicators=[indicator]
        )
        alerts.append(alert)
    
    # Alert group 2: Phishing URLs
    for i in range(2):
        indicator = ThreatIndicator(
            type="url",
            value=f"http://phish{i}.com/login",
            source="url_feed",
            first_seen=time.time(),
            last_seen=time.time(),
            confidence=0.85,
            threat_type="phishing",
            severity="high"
        )
        alert = SecurityAlert(
            alert_id=f"PHISH-{i:03d}",
            timestamp=time.time() + 100 + (i * 60),
            source="web_proxy",
            alert_type="phishing_attempt",
            severity="high",
            indicators=[indicator]
        )
        alerts.append(alert)
    
    # Process all alerts
    results = correlator.process_alerts(alerts)
    
    # Verify results
    assert results["input_count"] == 5
    assert len(results["unique_alerts"]) >= 2  # At least 2 unique groups
    assert len(results["correlated_groups"]) >= 2
    
    # Check enrichment summary
    assert results["enrichment_summary"]["total_enriched"] > 0
    
    print("  ✓ Full processing pipeline tests passed")
    print(f"    - Input alerts: {results['input_count']}")
    print(f"    - Unique alerts: {len(results['unique_alerts'])}")
    print(f"    - Correlated groups: {len(results['correlated_groups'])}")
    print(f"    - Groups: {list(results['correlated_groups'].keys())}")
    
    return True


def run_all_tests():
    """Run all tests and generate report"""
    print("=" * 60)
    print("Threat Intelligence Alert Correlation v62 - Test Suite")
    print("=" * 60)
    print()
    
    tests = [
        test_threat_indicator,
        test_security_alert,
        test_context_enricher,
        test_alert_correlator,
        test_full_processing_pipeline
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"  ✗ {test.__name__} FAILED: {e}")
            failed += 1
    
    print()
    print("=" * 60)
    print(f"TEST RESULTS: {passed} PASSED, {failed} FAILED")
    print("=" * 60)
    
    # Save test results
    test_results = {
        "test_timestamp": time.time(),
        "module": "threat_intelligence_alert_correlation_context_enricher_v62",
        "total_tests": len(tests),
        "passed": passed,
        "failed": failed,
        "success_rate": passed / len(tests)
    }
    
    with open('/home/user/autonomous-developer/NeuralShield-AI/test_results_threat_intelligence_alert_correlation_context_enricher_v62_2026_june.json', 'w') as f:
        json.dump(test_results, f, indent=2)
    
    print(f"Test results saved to JSON file")
    
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
