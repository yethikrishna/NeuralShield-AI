#!/usr/bin/env python3
"""
Test Suite for NeuralShield-AI v70: Threat Intelligence Alert Correlation & Context Enricher
Production-grade testing - all tests must pass
"""
import sys
import time
import json

# Add module path
sys.path.insert(0, '/home/user/.super_doubao/super-doubao-runtime/workspace/NeuralShield-AI')

from neural_shield.threat_intelligence_alert_correlation_context_enricher_v70_2026_june import (
    AlertContextEnricher,
    SecurityAlert,
    EnrichedAlert,
    AlertSeverity,
    MITRETactic,
    AlertStatus,
    SemanticThreatCache,
    MLFalsePositiveClassifier,
    PlaybookRecommendationEngine,
    AlertDeduplicator,
    AssetContext,
    IOCMetadata
)

def run_test(test_name, test_func):
    """Run a single test and report result"""
    print(f"\n[TEST {test_name}]")
    try:
        result = test_func()
        if result:
            print(f"  ✓ PASSED")
            return True
        else:
            print(f"  ✗ FAILED")
            return False
    except Exception as e:
        print(f"  ✗ FAILED with exception: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_basic_alert_enrichment():
    """TEST 1: Basic alert enrichment functionality"""
    enricher = AlertContextEnricher()
    
    alert = SecurityAlert(
        alert_id="",
        timestamp=time.time(),
        title="Suspicious Network Connection Detected",
        description="External IP attempting to connect to internal service",
        severity=AlertSeverity.MEDIUM,
        source="firewall",
        source_ip="198.51.100.10",
        destination_ip="10.0.1.100",
        destination_port=443
    )
    
    enriched = enricher.enrich_alert(alert)
    
    assert enriched.enriched == True, "Alert should be marked as enriched"
    assert enriched.status == AlertStatus.ENRICHED, "Status should be ENRICHED"
    assert len(enriched.ioc_metadata) > 0, "Should have IOC metadata"
    assert enriched.composite_severity > 0, "Should have composite severity score"
    assert enriched.enrichment_latency_ms > 0, "Should have latency measurement"
    
    print(f"  ✓ Alert enriched: {enriched.alert_id}")
    print(f"  ✓ Composite severity: {enriched.composite_severity:.3f}")
    print(f"  ✓ Latency: {enriched.enrichment_latency_ms:.2f}ms")
    
    return True

def test_semantic_caching():
    """TEST 2: Semantic threat caching feature"""
    cache = SemanticThreatCache(max_size=100)
    
    # Create test metadata
    meta = IOCMetadata(
        ioc_value="198.51.100.10",
        ioc_type="ip",
        threat_score=0.95
    )
    
    # First access (miss)
    cache.put("198.51.100.10", "ip", meta)
    
    # Second access (hit)
    result1 = cache.get("198.51.100.10", "ip")
    result2 = cache.get("198.51.100.11", "ip")  # miss
    
    stats = cache.get_stats()
    
    assert result1 is not None, "Cached entry should be found"
    assert result2 is None, "Non-cached entry should return None"
    assert stats["hits"] >= 1, "Should have cache hits"
    assert stats["misses"] >= 1, "Should have cache misses"
    
    print(f"  ✓ Cache hit rate: {stats['hit_rate']*100:.2f}%")
    print(f"  ✓ Hits: {stats['hits']}, Misses: {stats['misses']}")
    
    return True

def test_alert_correlation_with_timeline():
    """TEST 3: Alert correlation with attack timeline reconstruction"""
    enricher = AlertContextEnricher()
    
    # Create related alerts from same source
    base_time = time.time()
    
    alert1 = SecurityAlert(
        alert_id="",
        timestamp=base_time - 60,
        title="Port Scan Detected",
        description="Nmap scan from external IP",
        severity=AlertSeverity.LOW,
        source="ids",
        source_ip="198.51.100.10",
        destination_ip="10.0.1.100"
    )
    
    alert2 = SecurityAlert(
        alert_id="",
        timestamp=base_time,
        title="Brute Force Login Attempt",
        description="Multiple failed SSH login attempts",
        severity=AlertSeverity.HIGH,
        source="auth_log",
        source_ip="198.51.100.10",
        destination_ip="10.0.1.100"
    )
    
    # Enrich first (goes into buffer)
    enriched1 = enricher.enrich_alert(alert1)
    
    # Enrich second (should correlate with first)
    enriched2 = enricher.enrich_alert(alert2)
    
    assert len(enriched2.correlated_alert_ids) > 0, "Should find correlated alerts"
    assert len(enriched2.timeline_events) > 0, "Should have timeline events"
    
    print(f"  ✓ Correlated alerts: {len(enriched2.correlated_alert_ids)}")
    print(f"  ✓ Timeline events: {len(enriched2.timeline_events)}")
    print(f"  ✓ Correlation score: {enriched2.correlation_score:.3f}")
    
    return True

def test_ml_false_positive_classifier():
    """TEST 4: ML-based false positive classification"""
    classifier = MLFalsePositiveClassifier()
    
    # Create obvious FP alert (private IP, low severity)
    fp_alert = SecurityAlert(
        alert_id="",
        timestamp=time.time(),
        title="Internal Network Scan",
        description="Routine internal monitoring scan",
        severity=AlertSeverity.LOW,
        source="ids",
        source_ip="10.0.0.50",
        destination_ip="10.0.1.100"
    )
    
    fp_prob, confidence = classifier.classify(fp_alert)
    
    assert fp_prob > 0.5, "Private IP low-severity should have high FP probability"
    assert confidence > 0, "Should have confidence score"
    
    print(f"  ✓ False Positive Probability: {fp_prob:.3f}")
    print(f"  ✓ Classification Confidence: {confidence:.3f}")
    
    return True

def test_playbook_recommendations():
    """TEST 5: Automated playbook recommendations"""
    engine = PlaybookRecommendationEngine()
    
    # Create high-severity C2 alert
    alert = SecurityAlert(
        alert_id="",
        timestamp=time.time(),
        title="C2 Beaconing Detected",
        description="Host beaconing to known C2 server",
        severity=AlertSeverity.CRITICAL,
        source="ids",
        source_ip="198.51.100.10",
        destination_ip="10.0.1.100"
    )
    
    # Create enriched mock
    enriched = EnrichedAlert(
        alert_id=alert.alert_id,
        timestamp=alert.timestamp,
        title=alert.title,
        description=alert.description,
        severity=alert.severity,
        source=alert.source,
        composite_severity=0.9
    )
    
    recommendations = engine.recommend_playbooks(enriched)
    
    assert len(recommendations) > 0, "Should return recommendations"
    
    print(f"  ✓ Playbooks recommended: {len(recommendations)}")
    for pb in recommendations:
        print(f"    - {pb.playbook_id}: {pb.playbook_name}")
    
    return True

def test_alert_deduplication():
    """TEST 6: Alert deduplication"""
    deduplicator = AlertDeduplicator(similarity_threshold=0.8)
    
    alert1 = SecurityAlert(
        alert_id="",
        timestamp=time.time(),
        title="Suspicious Connection",
        description="Test alert",
        severity=AlertSeverity.MEDIUM,
        source="firewall",
        source_ip="198.51.100.10",
        destination_ip="10.0.1.100"
    )
    
    # Same alert again (should be duplicate)
    alert2 = SecurityAlert(
        alert_id="",
        timestamp=time.time() + 10,
        title="Suspicious Connection",
        description="Test alert",
        severity=AlertSeverity.MEDIUM,
        source="firewall",
        source_ip="198.51.100.10",
        destination_ip="10.0.1.100"
    )
    
    is_dup1, _ = deduplicator.is_duplicate(alert1)
    is_dup2, dup_of = deduplicator.is_duplicate(alert2)
    
    assert is_dup1 == False, "First alert should not be duplicate"
    assert is_dup2 == True, "Second identical alert should be duplicate"
    
    print(f"  ✓ Duplicate detected: {is_dup2}")
    if dup_of:
        print(f"  ✓ Duplicate of: {dup_of}")
    
    return True

def test_asset_criticality_scoring():
    """TEST 7: Asset criticality weighted severity scoring"""
    enricher = AlertContextEnricher()
    
    # Low criticality asset (dev workstation)
    alert_low = SecurityAlert(
        alert_id="",
        timestamp=time.time(),
        title="Suspicious Activity",
        description="Test alert on low-criticality asset",
        severity=AlertSeverity.MEDIUM,
        source="ids",
        source_ip="198.51.100.10",
        destination_ip="10.0.2.50",  # dev-workstation-01
        asset_id="asset-003"
    )
    
    # High criticality asset (production database)
    alert_high = SecurityAlert(
        alert_id="",
        timestamp=time.time(),
        title="Suspicious Activity",
        description="Test alert on high-criticality asset",
        severity=AlertSeverity.MEDIUM,
        source="ids",
        source_ip="198.51.100.10",
        destination_ip="10.0.1.100",  # prod-db-01
        asset_id="asset-001"
    )
    
    enriched_low = enricher.enrich_alert(alert_low)
    enriched_high = enricher.enrich_alert(alert_high)
    
    assert enriched_high.composite_severity > enriched_low.composite_severity, \
        "High criticality asset should have higher severity"
    
    print(f"  ✓ Low criticality asset score: {enriched_low.composite_severity:.3f}")
    print(f"  ✓ High criticality asset score: {enriched_high.composite_severity:.3f}")
    
    return True

def main():
    """Run all tests"""
    print("=" * 70)
    print("NeuralShield-AI: Testing Threat Intelligence Alert Correlation v70")
    print("=" * 70)
    
    tests = [
        ("1: Basic alert enrichment", test_basic_alert_enrichment),
        ("2: Semantic caching feature", test_semantic_caching),
        ("3: Alert correlation with attack timeline", test_alert_correlation_with_timeline),
        ("4: ML-based false positive classification", test_ml_false_positive_classifier),
        ("5: Automated playbook recommendations", test_playbook_recommendations),
        ("6: Alert deduplication", test_alert_deduplication),
        ("7: Asset criticality weighted scoring", test_asset_criticality_scoring),
    ]
    
    results = []
    for name, func in tests:
        results.append(run_test(name, func))
    
    passed = sum(results)
    total = len(results)
    
    print("\n" + "=" * 70)
    print(f"TEST SUMMARY:")
    print(f"  Passed: {passed}")
    print(f"  Failed: {total - passed}")
    print(f"  Success rate: {passed/total*100:.1f}%")
    print("=" * 70)
    
    # Save results
    result_data = {
        "test_version": "v70",
        "timestamp": time.time(),
        "passed": passed,
        "failed": total - passed,
        "success_rate": passed / total,
        "tests": [t[0] for t in tests]
    }
    
    with open('/home/user/.super_doubao/super-doubao-runtime/workspace/NeuralShield-AI/test_results_alert_correlation_context_enricher_v70_2026_june.json', 'w') as f:
        json.dump(result_data, f, indent=2)
    
    print(f"\nResults saved to test_results_alert_correlation_context_enricher_v70_2026_june.json")
    
    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
