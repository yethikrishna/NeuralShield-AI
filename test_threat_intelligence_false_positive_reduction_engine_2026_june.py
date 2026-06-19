#!/usr/bin/env python3
"""
Test suite for Threat Intelligence False Positive Reduction Engine
Production-grade tests with real assertions and verification
"""

import sys
import os
import time
import json

# Add neural_shield to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from threat_intelligence_false_positive_reduction_engine_2026_june import (
    FPConfidence,
    AlertContext,
    HistoricalBaseline,
    FalsePositiveReductionEngine
)


def test_engine_initialization():
    """Test that engine initializes correctly"""
    print("Test 1: Engine Initialization")
    
    engine = FalsePositiveReductionEngine(
        fp_threshold=0.75,
        max_history=10000,
        time_half_life_hours=168.0
    )
    
    assert engine.fp_threshold == 0.75
    assert engine.max_history == 10000
    assert len(engine.baselines) == 0
    
    stats = engine.get_statistics()
    assert stats['total_alerts_processed'] == 0
    
    print("  ✓ Engine initialized with correct parameters")
    print("  ✓ Statistics initialized to zero")
    
    return True


def test_alert_context_creation():
    """Test alert context creation"""
    print("\nTest 2: Alert Context Creation")
    
    alert = AlertContext(
        alert_id="alert-001",
        alert_type="NETWORK_SCAN",
        source_ip="192.168.1.100",
        destination_ip="10.0.0.5",
        timestamp=time.time(),
        severity="HIGH",
        ioc_value="192.168.1.100",
        ioc_type="IP"
    )
    
    assert alert.alert_id == "alert-001"
    assert alert.severity == "HIGH"
    assert len(alert.get_pattern_hash()) == 32
    
    print(f"  ✓ Alert created with ID: {alert.alert_id}")
    print(f"  ✓ Pattern hash: {alert.get_pattern_hash()}")
    
    return True


def test_private_ip_whitelist():
    """Test private IP whitelist detection"""
    print("\nTest 3: Private IP Whitelist Detection")
    
    # Test private IPs
    private_ips = [
        "10.0.0.1", "10.255.255.255",
        "172.16.0.1", "172.31.255.255",
        "192.168.0.1", "192.168.255.255",
        "127.0.0.1", "127.0.0.53"
    ]
    
    for ip in private_ips:
        assert FalsePositiveReductionEngine._is_private_ip(ip) == True
        print(f"  ✓ {ip} correctly identified as private")
    
    # Test public IPs
    public_ips = ["8.8.8.8", "1.1.1.1", "203.0.113.1"]
    for ip in public_ips:
        assert FalsePositiveReductionEngine._is_private_ip(ip) == False
        print(f"  ✓ {ip} correctly identified as public")
    
    return True


def test_single_alert_processing():
    """Test processing a single alert"""
    print("\nTest 4: Single Alert Processing")
    
    engine = FalsePositiveReductionEngine()
    
    # Alert from private IP - should be high FP probability
    alert = AlertContext(
        alert_id="test-001",
        alert_type="NETWORK_CONNECTION",
        source_ip="192.168.1.100",
        destination_ip="10.0.0.1",
        timestamp=time.time(),
        severity="MEDIUM",
        ioc_value="192.168.1.100",
        ioc_type="IP"
    )
    
    fp_prob, confidence = engine.process_alert(alert)
    
    print(f"  ✓ FP Probability: {fp_prob:.4f}")
    print(f"  ✓ Confidence: {confidence.value}")
    
    # Should be high probability of false positive (private IPs)
    assert fp_prob > 0.7
    assert alert.is_false_positive == True
    
    stats = engine.get_statistics()
    assert stats['total_alerts_processed'] == 1
    assert stats['whitelist_hits'] == 1
    
    print("  ✓ Statistics updated correctly")
    
    return True


def test_true_positive_detection():
    """Test detection of likely true positives"""
    print("\nTest 5: True Positive Detection")
    
    engine = FalsePositiveReductionEngine()
    
    # Alert from public IP - should NOT be flagged as FP
    alert = AlertContext(
        alert_id="test-002",
        alert_type="MALWARE_CALLBACK",
        source_ip="8.8.8.8",
        destination_ip="203.0.113.50",
        timestamp=time.time(),
        severity="CRITICAL",
        ioc_value="malicious-domain.com",
        ioc_type="DOMAIN"
    )
    
    fp_prob, confidence = engine.process_alert(alert)
    
    print(f"  ✓ FP Probability: {fp_prob:.4f}")
    print(f"  ✓ Confidence: {confidence.value}")
    
    # Should be low probability of false positive
    assert fp_prob < 0.6
    assert confidence in [FPConfidence.NORMAL, FPConfidence.ESCALATE]
    
    print("  ✓ Public IP alert not incorrectly flagged as FP")
    
    return True


def test_batch_processing():
    """Test batch processing of multiple alerts"""
    print("\nTest 6: Batch Processing")
    
    engine = FalsePositiveReductionEngine()
    
    alerts = []
    for i in range(10):
        alert = AlertContext(
            alert_id=f"batch-{i}",
            alert_type="SCAN_DETECTED",
            source_ip=f"192.168.1.{100+i}",
            destination_ip="10.0.0.5",
            timestamp=time.time(),
            severity="HIGH",
            ioc_value=f"192.168.1.{100+i}",
            ioc_type="IP"
        )
        alerts.append(alert)
    
    results = engine.process_batch(alerts)
    
    assert len(results) == 10
    
    stats = engine.get_statistics()
    assert stats['total_alerts_processed'] == 10
    
    print(f"  ✓ Processed {len(results)} alerts in batch")
    print(f"  ✓ Total alerts: {stats['total_alerts_processed']}")
    print(f"  ✓ Whitelist hits: {stats['whitelist_hits']}")
    
    return True


def test_feedback_learning():
    """Test feedback learning loop"""
    print("\nTest 7: Feedback Learning Loop")
    
    engine = FalsePositiveReductionEngine()
    
    # Create an alert pattern
    alert = AlertContext(
        alert_id="learn-001",
        alert_type="REPEATED_PATTERN",
        source_ip="8.8.8.8",
        destination_ip="1.1.1.1",
        timestamp=time.time(),
        severity="HIGH",
        ioc_value="test-pattern",
        ioc_type="DOMAIN"
    )
    
    # First pass - no history
    fp_prob1, _ = engine.process_alert(alert)
    print(f"  ✓ Initial FP prob (no history): {fp_prob1:.4f}")
    
    # Provide feedback that this IS a false positive
    for i in range(10):
        engine.record_feedback(alert, is_actually_fp=True)
    
    # Second pass - should have learned
    fp_prob2, confidence = engine.process_alert(alert)
    print(f"  ✓ After 10 FP feedback: {fp_prob2:.4f}")
    print(f"  ✓ Confidence: {confidence.value}")
    
    # FP probability should increase after learning
    assert fp_prob2 > fp_prob1
    assert len(engine.baselines) == 1
    
    baseline = list(engine.baselines.values())[0]
    assert baseline.false_positive_count == 10
    assert baseline.get_sample_count() == 10
    
    print("  ✓ Learning correctly updates baseline")
    print(f"  ✓ FP rate: {baseline.get_fp_rate():.4f}")
    
    return True


def test_statistics_reporting():
    """Test statistics reporting"""
    print("\nTest 8: Statistics Reporting")
    
    engine = FalsePositiveReductionEngine()
    
    # Process some alerts
    for i in range(5):
        alert = AlertContext(
            alert_id=f"stat-{i}",
            alert_type="TEST",
            source_ip=f"192.168.1.{i}",
            destination_ip="10.0.0.1",
            timestamp=time.time(),
            severity="MEDIUM",
            ioc_value=f"192.168.1.{i}",
            ioc_type="IP"
        )
        engine.process_alert(alert)
    
    stats = engine.get_statistics()
    
    print(f"  ✓ Total processed: {stats['total_alerts_processed']}")
    print(f"  ✓ FP detected: {stats['false_positives_detected']}")
    print(f"  ✓ FP reduction rate: {stats['fp_reduction_rate']:.2%}")
    print(f"  ✓ Whitelist hits: {stats['whitelist_hits']}")
    
    assert stats['total_alerts_processed'] == 5
    assert stats['whitelist_hits'] == 5
    
    return True


def test_model_export_import():
    """Test model export and import"""
    print("\nTest 9: Model Export/Import")
    
    engine1 = FalsePositiveReductionEngine()
    
    # Add some learning
    alert = AlertContext(
        alert_id="export-test",
        alert_type="TEST",
        source_ip="1.2.3.4",
        destination_ip="5.6.7.8",
        timestamp=time.time(),
        severity="HIGH",
        ioc_value="test-domain.com",
        ioc_type="DOMAIN"
    )
    
    for i in range(5):
        engine1.record_feedback(alert, is_actually_fp=True)
    
    # Export
    export_path = "test_model_export.json"
    engine1.export_model(export_path)
    
    # Import into new engine
    engine2 = FalsePositiveReductionEngine()
    engine2.import_model(export_path)
    
    assert len(engine2.baselines) == 1
    baseline = list(engine2.baselines.values())[0]
    assert baseline.false_positive_count == 5
    
    print(f"  ✓ Model exported to {export_path}")
    print(f"  ✓ Model imported with {len(engine2.baselines)} baselines")
    print(f"  ✓ Baseline preserved: {baseline.false_positive_count} FP samples")
    
    # Cleanup
    os.remove(export_path)
    
    return True


def test_bayesian_probability_calculation():
    """Test Bayesian probability edge cases"""
    print("\nTest 10: Bayesian Probability Calculation")
    
    baseline = HistoricalBaseline(pattern_hash="test")
    
    # No samples - should be 0.5 with Laplace smoothing
    fp_rate = baseline.get_fp_rate()
    assert abs(fp_rate - 0.5) < 0.01
    print(f"  ✓ No samples: FP rate = {fp_rate:.4f} (Laplace smoothing)")
    
    # All true positives
    baseline.true_positive_count = 100
    fp_rate = baseline.get_fp_rate()
    assert fp_rate < 0.1
    print(f"  ✓ 100 TP, 0 FP: FP rate = {fp_rate:.4f}")
    
    # All false positives
    baseline2 = HistoricalBaseline(pattern_hash="test2")
    baseline2.false_positive_count = 100
    fp_rate = baseline2.get_fp_rate()
    assert fp_rate > 0.9
    print(f"  ✓ 0 TP, 100 FP: FP rate = {fp_rate:.4f}")
    
    # Balanced
    baseline3 = HistoricalBaseline(pattern_hash="test3")
    baseline3.true_positive_count = 50
    baseline3.false_positive_count = 50
    fp_rate = baseline3.get_fp_rate()
    assert abs(fp_rate - 0.5) < 0.05
    print(f"  ✓ 50 TP, 50 FP: FP rate = {fp_rate:.4f}")
    
    return True


def run_all_tests():
    """Run all tests and report results"""
    print("=" * 60)
    print("False Positive Reduction Engine - Production Test Suite")
    print("=" * 60)
    
    tests = [
        test_engine_initialization,
        test_alert_context_creation,
        test_private_ip_whitelist,
        test_single_alert_processing,
        test_true_positive_detection,
        test_batch_processing,
        test_feedback_learning,
        test_statistics_reporting,
        test_model_export_import,
        test_bayesian_probability_calculation
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
                print(f"  ✗ FAILED")
        except Exception as e:
            failed += 1
            print(f"  ✗ EXCEPTION: {e}")
            import traceback
            traceback.print_exc()
    
    print("\n" + "=" * 60)
    print(f"TEST SUMMARY: {passed} PASSED, {failed} FAILED")
    print("=" * 60)
    
    # Save results
    results = {
        "test_suite": "FalsePositiveReductionEngine",
        "total_tests": len(tests),
        "passed": passed,
        "failed": failed,
        "success_rate": passed / len(tests),
        "timestamp": time.time()
    }
    
    with open("test_results_false_positive_reduction_engine.json", "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"Results saved to test_results_false_positive_reduction_engine.json")
    
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
