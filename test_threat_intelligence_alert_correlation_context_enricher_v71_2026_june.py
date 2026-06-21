#!/usr/bin/env python3
"""
Test suite for Threat Intelligence Alert Correlation Context Enricher v71
Real working tests - production grade verification
"""

import json
import sys
import os

# Add module path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from threat_intelligence_alert_correlation_context_enricher_v71_2026_june import (
    ThreatIntelligenceContextEnricherV71,
    EnrichedAlert
)


def test_basic_enrichment():
    """Test basic alert enrichment functionality"""
    print("=== Test 1: Basic Alert Enrichment ===")
    enricher = ThreatIntelligenceContextEnricherV71()
    
    test_alert = {
        "alert_id": "TEST-001",
        "source": "suricata_ids",
        "ip_address": "192.168.1.100",
        "indicator_type": "botnet",
        "indicator_value": "malware_domain.com",
        "severity": "high",
        "confidence": 0.85,
        "mitre_technique": "T1059"
    }
    
    result = enricher.enrich_alert(test_alert)
    
    assert result is not None, "Alert should be enriched"
    assert result.alert_id == "TEST-001", "Alert ID should match"
    assert result.geolocation_country == "US", "Should have US geolocation"
    assert result.geolocation_city == "New York", "Should have New York city"
    assert result.asn_number == 7018, "Should have correct ASN"
    assert result.threat_reputation_score > 0.8, "Should have high threat reputation"
    assert result.priority_score > 0, "Should have valid priority score"
    assert len(result.deduplication_hash) == 16, "Should have 16 char hash"
    
    print(f"  ✓ Alert enriched successfully")
    print(f"  ✓ Country: {result.geolocation_country}")
    print(f"  ✓ City: {result.geolocation_city}")
    print(f"  ✓ Threat Reputation: {result.threat_reputation_score:.2f}")
    print(f"  ✓ Priority Score: {result.priority_score:.4f}")
    return True


def test_deduplication():
    """Test deduplication functionality"""
    print("\n=== Test 2: Deduplication ===")
    enricher = ThreatIntelligenceContextEnricherV71()
    
    test_alert = {
        "alert_id": "TEST-002",
        "source": "firewall",
        "ip_address": "10.0.0.50",
        "indicator_type": "brute_force",
        "indicator_value": "ssh_login_attempt",
        "severity": "medium",
        "confidence": 0.7
    }
    
    # First alert should be processed
    result1 = enricher.enrich_alert(test_alert)
    assert result1 is not None, "First alert should process"
    
    # Same alert again should be deduplicated
    result2 = enricher.enrich_alert(test_alert)
    assert result2 is None, "Duplicate alert should be filtered"
    
    stats = enricher.get_statistics()
    assert stats["total_processed"] == 2, "Should have processed 2 alerts"
    assert stats["total_deduplicated"] == 1, "Should have deduplicated 1 alert"
    
    print(f"  ✓ Deduplication working correctly")
    print(f"  ✓ Deduplication rate: {stats['deduplication_rate_percent']}%")
    return True


def test_false_positive_detection():
    """Test false positive probability calculation"""
    print("\n=== Test 3: False Positive Detection ===")
    enricher = ThreatIntelligenceContextEnricherV71()
    
    # Known benign IP (Google DNS)
    benign_alert = {
        "alert_id": "TEST-FP-001",
        "source": "dns_monitor",
        "ip_address": "8.8.8.8",
        "indicator_type": "dns_query",
        "indicator_value": "google.com",
        "severity": "low",
        "confidence": 0.3
    }
    
    result = enricher.enrich_alert(benign_alert)
    assert result is not None
    
    # Google DNS should have high false positive probability
    assert result.false_positive_probability > 0.8, "Known benign IP should have high FP prob"
    
    print(f"  ✓ False positive probability: {result.false_positive_probability:.2f}")
    print(f"  ✓ Correctly identified benign IP pattern")
    return True


def test_threat_reputation():
    """Test threat reputation scoring"""
    print("\n=== Test 4: Threat Reputation Scoring ===")
    enricher = ThreatIntelligenceContextEnricherV71()
    
    # Known threat IP - ransomware C2
    threat_alert = {
        "alert_id": "TEST-REP-001",
        "source": "threat_feed",
        "ip_address": "172.16.0.25",
        "indicator_type": "ransomware",
        "indicator_value": "c2_communication",
        "severity": "critical",
        "confidence": 0.95,
        "mitre_technique": "T1486"
    }
    
    result = enricher.enrich_alert(threat_alert)
    assert result is not None
    assert result.threat_reputation_score > 0.7, "Known threat should have high reputation"
    assert result.priority_score > 0.7, "Critical ransomware should have high priority"
    
    print(f"  ✓ Threat reputation: {result.threat_reputation_score:.2f}")
    print(f"  ✓ Priority score: {result.priority_score:.4f}")
    print(f"  ✓ Country: {result.geolocation_country}")
    return True


def test_batch_processing():
    """Test batch alert processing"""
    print("\n=== Test 5: Batch Processing ===")
    enricher = ThreatIntelligenceContextEnricherV71()
    
    test_alerts = [
        {
            "alert_id": f"BATCH-{i:03d}",
            "source": ["suricata", "firewall", "threat_feed"][i % 3],
            "ip_address": ["192.168.1.100", "10.0.0.50", "203.0.113.50", "198.51.100.10"][i % 4],
            "indicator_type": ["botnet", "brute_force", "phishing", "c2_server"][i % 4],
            "indicator_value": f"indicator_{i}",
            "severity": ["low", "medium", "high", "critical"][i % 4],
            "confidence": 0.5 + (i * 0.05) % 0.5
        }
        for i in range(20)
    ]
    
    results = enricher.enrich_alerts_batch(test_alerts)
    
    assert results["success"] == True, "Batch should succeed"
    assert results["total_processed"] == 20, "Should process 20 alerts"
    assert results["processing_time_ms"] >= 0, "Should have valid processing time"
    assert len(results["enriched_alerts"]) > 0, "Should have enriched alerts"
    
    print(f"  ✓ Batch processed {results['total_processed']} alerts")
    print(f"  ✓ Enriched: {results['total_enriched']} alerts")
    print(f"  ✓ Deduplicated: {results['total_deduplicated']} alerts")
    print(f"  ✓ Processing time: {results['processing_time_ms']}ms")
    print(f"  ✓ Correlation groups: {results['correlation_groups_count']}")
    return True


def test_correlation_groups():
    """Test alert correlation grouping"""
    print("\n=== Test 6: Correlation Groups ===")
    enricher = ThreatIntelligenceContextEnricherV71()
    
    # Multiple alerts from same IP should be in same group
    alerts_same_ip = [
        {
            "alert_id": f"CORR-{i}",
            "source": "same_source",
            "ip_address": "192.168.1.100",
            "indicator_type": f"type_{i}",
            "indicator_value": f"val_{i}",
            "severity": "high",
            "confidence": 0.8
        }
        for i in range(5)
    ]
    
    for alert in alerts_same_ip:
        enricher.enrich_alert(alert)
    
    stats = enricher.get_statistics()
    
    # All 5 alerts from same IP should be in 1 correlation group
    assert stats["active_correlation_groups"] == 1, "Same IP should be in same group"
    
    print(f"  ✓ Correlation groups working")
    print(f"  ✓ Active groups: {stats['active_correlation_groups']}")
    return True


def test_statistics():
    """Test statistics tracking"""
    print("\n=== Test 7: Statistics Tracking ===")
    enricher = ThreatIntelligenceContextEnricherV71()
    
    for i in range(10):
        alert = {
            "alert_id": f"STAT-{i}",
            "source": "test",
            "ip_address": f"10.0.0.{i}",
            "indicator_type": "test",
            "indicator_value": "test",
            "severity": "medium",
            "confidence": 0.5
        }
        enricher.enrich_alert(alert)
    
    stats = enricher.get_statistics()
    
    assert stats["total_processed"] == 10
    assert stats["total_enriched"] == 10
    assert stats["enricher_version"] == "v71"
    
    print(f"  ✓ Statistics tracking verified")
    print(f"  ✓ Processed: {stats['total_processed']}")
    print(f"  ✓ Cache size: {stats['cache_size']}")
    return True


def run_all_tests():
    """Run all tests and generate report"""
    print("=" * 60)
    print("Threat Intelligence Context Enricher v71 - Test Suite")
    print("=" * 60)
    
    tests = [
        test_basic_enrichment,
        test_deduplication,
        test_false_positive_detection,
        test_threat_reputation,
        test_batch_processing,
        test_correlation_groups,
        test_statistics,
    ]
    
    passed = 0
    failed = 0
    test_results = []
    
    for test in tests:
        try:
            test()
            passed += 1
            test_results.append({"test": test.__name__, "status": "PASSED"})
        except AssertionError as e:
            failed += 1
            test_results.append({"test": test.__name__, "status": "FAILED", "error": str(e)})
            print(f"  ✗ FAILED: {e}")
        except Exception as e:
            failed += 1
            test_results.append({"test": test.__name__, "status": "ERROR", "error": str(e)})
            print(f"  ✗ ERROR: {e}")
    
    print("\n" + "=" * 60)
    print(f"TEST SUMMARY: {passed} PASSED, {failed} FAILED")
    print("=" * 60)
    
    # Save results
    result_data = {
        "test_suite": "ThreatIntelligenceContextEnricherV71",
        "version": "v71",
        "timestamp": __import__("datetime").datetime.utcnow().isoformat(),
        "passed": passed,
        "failed": failed,
        "total": passed + failed,
        "results": test_results
    }
    
    with open("test_results_threat_intelligence_context_enricher_v71_2026_june.json", "w") as f:
        json.dump(result_data, f, indent=2)
    
    print(f"\nTest results saved to JSON file")
    
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
