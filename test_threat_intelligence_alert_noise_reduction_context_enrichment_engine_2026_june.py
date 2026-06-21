#!/usr/bin/env python3
"""
Test suite for Threat Intelligence Alert Noise Reduction & Context Enrichment Engine
Production-grade testing for NeuralShield-AI

Author: NeuralShield-AI Team
Date: June 2026
"""

import sys
import json
import time

# Add module path
sys.path.insert(0, '/home/user/autonomous-developer/NeuralShield-AI')

from neural_shield.threat_intelligence_alert_noise_reduction_context_enrichment_engine_2026_june import (
    ThreatIntelligenceAlertEngine,
    AlertNoiseReducer,
    ContextEnrichmentEngine,
    FalsePositiveScorer,
    AlertPrioritizationEngine,
    ThreatAlert,
    AlertContext,
)


def test_alert_noise_reducer():
    """Test AlertNoiseReducer functionality"""
    print("\n=== Testing AlertNoiseReducer ===")
    reducer = AlertNoiseReducer(zscore_threshold=2.0, max_frequency_per_hour=10)
    
    # Create test alert
    alert = ThreatAlert(
        alert_id="test-001",
        timestamp=time.time(),
        threat_type="malware",
        severity="high",
        source_ip="192.168.1.100",
        destination_ip="10.0.0.5",
        indicator="test.exe",
        indicator_type="filehash",
        confidence=0.8,
        raw_data={},
    )
    
    noise_score = reducer.calculate_noise_score(alert)
    print(f"  Noise score for single alert: {noise_score:.4f}")
    assert 0.0 <= noise_score <= 1.0, "Noise score must be between 0 and 1"
    
    # Test frequency-based noise detection
    for i in range(15):  # Exceed max_frequency_per_hour
        alert2 = ThreatAlert(
            alert_id=f"test-freq-{i}",
            timestamp=time.time(),
            threat_type="port-scan",
            severity="low",
            source_ip="10.0.0.1",
            destination_ip="10.0.0.2",
            indicator="frequency-test",
            indicator_type="ip",
            confidence=0.3,
            raw_data={},
        )
        noise_score2 = reducer.calculate_noise_score(alert2)
    
    print(f"  High frequency noise score: {noise_score2:.4f}")
    assert noise_score2 > 0.3, "High frequency should increase noise score"
    print("  ✓ AlertNoiseReducer tests passed")


def test_context_enrichment_engine():
    """Test ContextEnrichmentEngine functionality"""
    print("\n=== Testing ContextEnrichmentEngine ===")
    enricher = ContextEnrichmentEngine()
    
    alert = ThreatAlert(
        alert_id="test-002",
        timestamp=time.time(),
        threat_type="ransomware",
        severity="critical",
        source_ip="203.0.113.50",
        destination_ip="10.0.0.10",
        indicator="ransomware.exe",
        indicator_type="filename",
        confidence=0.95,
        raw_data={},
    )
    
    asset_metadata = {
        'asset_type': 'database',
        'business_impact': 'critical',
        'asset_id': 'DB-PROD-001',
    }
    
    enriched_alert = enricher.enrich_alert(alert, asset_metadata)
    
    print(f"  Asset criticality: {enriched_alert.context.asset_criticality}")
    print(f"  Network zone: {enriched_alert.context.network_zone}")
    print(f"  Enrichment score: {enriched_alert.enrichment_score:.4f}")
    print(f"  Compliance scope: {enriched_alert.context.compliance_scope}")
    
    assert enriched_alert.context.asset_criticality == 'critical'
    assert enriched_alert.context.network_zone == 'dmz'  # 10.0.x.x = dmz
    assert enriched_alert.enrichment_score > 0.5
    assert enriched_alert.context is not None
    print("  ✓ ContextEnrichmentEngine tests passed")


def test_false_positive_scorer():
    """Test FalsePositiveScorer functionality"""
    print("\n=== Testing FalsePositiveScorer ===")
    fp_scorer = FalsePositiveScorer()
    
    # Test high confidence external alert WITH context (low FP probability)
    alert1 = ThreatAlert(
        alert_id="fp-test-001",
        timestamp=time.time(),
        threat_type="exploit",
        severity="critical",
        source_ip="203.0.113.100",  # External IP
        destination_ip="10.0.0.5",
        indicator="CVE-2026-1234",
        indicator_type="cve",
        confidence=0.95,
        raw_data={},
    )
    # Add proper context to avoid "no_context" penalty
    alert1.context = AlertContext(
        asset_id="test-asset",
        asset_criticality="critical",
        asset_type="database",
        network_zone="dmz",
        business_impact="critical",
        compliance_scope=["pci", "gdpr"],
    )
    alert1.enrichment_score = 0.8
    
    fp_prob1 = fp_scorer.calculate_fp_probability(alert1)
    print(f"  High confidence external alert FP probability: {fp_prob1:.4f}")
    assert fp_prob1 < 0.5, "High confidence external alert should have lower FP probability"
    
    # Test low confidence internal alert (high FP probability)
    alert2 = ThreatAlert(
        alert_id="fp-test-002",
        timestamp=time.time(),
        threat_type="port-scan",
        severity="low",
        source_ip="192.168.1.100",  # Internal
        destination_ip="192.168.1.101",  # Internal
        indicator="scan",
        indicator_type="behavior",
        confidence=0.2,
        raw_data={},
    )
    alert2.enrichment_score = 0.2
    
    fp_prob2 = fp_scorer.calculate_fp_probability(alert2)
    print(f"  Low confidence internal alert FP probability: {fp_prob2:.4f}")
    assert fp_prob2 > fp_prob1, "Low confidence internal alert should have higher FP probability"
    
    print("  ✓ FalsePositiveScorer tests passed")


def test_alert_prioritization_engine():
    """Test AlertPrioritizationEngine functionality"""
    print("\n=== Testing AlertPrioritizationEngine ===")
    prioritizer = AlertPrioritizationEngine()
    
    # Critical alert test
    alert = ThreatAlert(
        alert_id="priority-test-001",
        timestamp=time.time(),
        threat_type="ransomware",
        severity="critical",
        source_ip="203.0.113.50",
        destination_ip="10.0.0.10",
        indicator="ransomware.exe",
        indicator_type="filename",
        confidence=0.95,
        raw_data={},
    )
    alert.enrichment_score = 0.9
    alert.noise_score = 0.05
    alert.false_positive_probability = 0.05
    
    priority = prioritizer.calculate_priority(alert)
    print(f"  Critical alert priority score: {priority:.4f}")
    assert priority > 0.7, "Critical alert should have high priority"
    
    # Low priority alert test
    alert2 = ThreatAlert(
        alert_id="priority-test-002",
        timestamp=time.time(),
        threat_type="policy-violation",
        severity="low",
        source_ip="192.168.1.50",
        destination_ip="192.168.1.51",
        indicator="policy",
        indicator_type="behavior",
        confidence=0.3,
        raw_data={},
    )
    alert2.enrichment_score = 0.2
    alert2.noise_score = 0.8
    alert2.false_positive_probability = 0.7
    
    priority2 = prioritizer.calculate_priority(alert2)
    print(f"  Low quality alert priority score: {priority2:.4f}")
    assert priority2 < 0.5, "Low quality alert should have lower priority"
    
    print("  ✓ AlertPrioritizationEngine tests passed")


def test_full_pipeline():
    """Test complete ThreatIntelligenceAlertEngine pipeline"""
    print("\n=== Testing Full Pipeline (ThreatIntelligenceAlertEngine) ===")
    engine = ThreatIntelligenceAlertEngine()
    
    # Test alerts representing different scenarios
    test_alerts = [
        {
            'alert_id': 'alert-critical-001',
            'threat_type': 'ransomware',
            'severity': 'critical',
            'source_ip': '198.51.100.25',
            'destination_ip': '10.0.0.10',
            'indicator': 'evil_ransomware.exe',
            'indicator_type': 'filename',
            'confidence': 0.98,
        },
        {
            'alert_id': 'alert-noise-001',
            'threat_type': 'port-scan',
            'severity': 'low',
            'source_ip': '192.168.1.100',
            'destination_ip': '192.168.1.1',
            'indicator': 'tcp_scan',
            'indicator_type': 'behavior',
            'confidence': 0.25,
        },
        {
            'alert_id': 'alert-medium-001',
            'threat_type': 'credential-stuffing',
            'severity': 'medium',
            'source_ip': '203.0.113.80',
            'destination_ip': '10.1.0.50',
            'indicator': 'auth_attempts',
            'indicator_type': 'behavior',
            'confidence': 0.7,
        },
    ]
    
    asset_metadata = {
        '10.0.0.10': {'asset_type': 'database', 'business_impact': 'critical'},
        '10.1.0.50': {'asset_type': 'web-server', 'business_impact': 'high'},
    }
    
    print(f"  Processing {len(test_alerts)} test alerts...")
    
    results = engine.batch_process(test_alerts, asset_metadata)
    
    for i, result in enumerate(results):
        print(f"\n  Alert {i+1} Results:")
        print(f"    ID: {result['alert_id']}")
        print(f"    Priority Score: {result['final_priority_score']}")
        print(f"    Noise Score: {result['noise_score']}")
        print(f"    FP Probability: {result['false_positive_probability']}")
        print(f"    Recommendation: {result['recommendation']}")
    
    # Verify results
    assert len(results) == 3
    assert all('final_priority_score' in r for r in results)
    assert all(0 <= r['final_priority_score'] <= 1 for r in results)
    
    # Critical alert should have highest priority
    critical_result = results[0]
    noise_result = results[1]
    assert critical_result['final_priority_score'] > noise_result['final_priority_score']
    
    # Get performance stats
    stats = engine.get_performance_stats()
    print(f"\n  Performance Statistics:")
    print(f"    Total processed: {stats['total_alerts_processed']}")
    print(f"    Noise reduction rate: {stats['noise_reduction_rate']}%")
    print(f"    False positive rate: {stats['false_positive_rate']}%")
    print(f"    Avg processing time: {stats['average_processing_time_ms']}ms")
    
    print("  ✓ Full pipeline tests passed")


def test_edge_cases():
    """Test edge cases and boundary conditions"""
    print("\n=== Testing Edge Cases ===")
    engine = ThreatIntelligenceAlertEngine()
    
    # Empty alert
    empty_result = engine.process_alert({})
    print(f"  Empty alert processed successfully: {empty_result['alert_id'] is not None}")
    
    # Very low confidence
    low_conf_result = engine.process_alert({
        'threat_type': 'test',
        'severity': 'low',
        'source_ip': '1.2.3.4',
        'destination_ip': '5.6.7.8',
        'confidence': 0.0,
    })
    print(f"  Zero confidence FP probability: {low_conf_result['false_positive_probability']}")
    assert low_conf_result['false_positive_probability'] > 0.3
    
    # Unknown IP addresses
    unknown_ip_result = engine.process_alert({
        'threat_type': 'exploit',
        'severity': 'high',
        'source_ip': '255.255.255.255',
        'destination_ip': '0.0.0.0',
        'confidence': 0.8,
    })
    print(f"  Unknown IP network zone: {unknown_ip_result['context']['network_zone']}")
    assert unknown_ip_result['context']['network_zone'] == 'unknown'
    
    print("  ✓ Edge case tests passed")


def run_all_tests():
    """Run all tests and generate report"""
    print("=" * 70)
    print("Threat Intelligence Alert Noise Reduction & Context Enrichment Engine")
    print("Production Test Suite - NeuralShield-AI")
    print("=" * 70)
    
    start_time = time.time()
    all_passed = True
    
    try:
        test_alert_noise_reducer()
        test_context_enrichment_engine()
        test_false_positive_scorer()
        test_alert_prioritization_engine()
        test_full_pipeline()
        test_edge_cases()
    except AssertionError as e:
        print(f"\n✗ TEST FAILED: {e}")
        all_passed = False
    except Exception as e:
        print(f"\n✗ UNEXPECTED ERROR: {e}")
        import traceback
        traceback.print_exc()
        all_passed = False
    
    elapsed = time.time() - start_time
    
    print("\n" + "=" * 70)
    if all_passed:
        print("✓ ALL TESTS PASSED")
    else:
        print("✗ SOME TESTS FAILED")
    print(f"Total test time: {elapsed:.2f} seconds")
    print("=" * 70)
    
    # Save test results
    test_results = {
        'test_suite': 'Threat Intelligence Alert Noise Reduction Engine',
        'module': 'neural_shield/threat_intelligence_alert_noise_reduction_context_enrichment_engine_2026_june.py',
        'all_passed': all_passed,
        'test_time_seconds': round(elapsed, 2),
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'version': '1.0.0',
    }
    
    with open('/home/user/autonomous-developer/NeuralShield-AI/test_results_threat_intelligence_alert_noise_reduction_context_enrichment_engine.json', 'w') as f:
        json.dump(test_results, f, indent=2)
    
    print(f"\nTest results saved to: test_results_threat_intelligence_alert_noise_reduction_context_enrichment_engine.json")
    
    return all_passed


if __name__ == '__main__':
    success = run_all_tests()
    sys.exit(0 if success else 1)
