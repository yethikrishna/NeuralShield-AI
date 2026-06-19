#!/usr/bin/env python3
"""
Test suite for Threat Intelligence Model Drift Detector & Automated Retrainer
NeuralShield-AI - Production-grade testing
"""

import sys
import json
import time
import numpy as np
from datetime import datetime

# Add module path
sys.path.insert(0, '/home/user/autonomous-developer/NeuralShield-AI')

from neural_shield.threat_intelligence_model_drift_detector_retrainer_2026_june import (
    ModelPerformanceMetrics,
    DriftDetectionResult,
    RetrainingResult,
    ThreatIntelligenceModelDriftDetector
)


def run_tests():
    print("=" * 70)
    print("NeuralShield-AI: Threat Intelligence Model Drift Detector Tests")
    print("=" * 70)
    print(f"Test Time: {datetime.now().isoformat()}")
    print()
    
    test_results = []
    
    # Test 1: Initialization
    print("[TEST 1] Initialization and Baseline Setup")
    try:
        detector = ThreatIntelligenceModelDriftDetector(
            model_id="test_threat_classifier",
            window_size=500,
            drift_threshold=0.15
        )
        
        baseline = ModelPerformanceMetrics(
            timestamp=time.time(),
            precision=0.92,
            recall=0.89,
            f1_score=0.905,
            accuracy=0.91,
            true_positives=8900,
            false_positives=450,
            true_negatives=9500,
            false_negatives=150,
            prediction_distribution={
                'malicious': 0.40, 'suspicious': 0.20,
                'benign': 0.35, 'unknown': 0.05
            },
            feature_statistics={'feature_stability': 0.95}
        )
        
        detector.set_baseline(baseline)
        assert detector.baseline_metrics is not None
        assert detector.current_version is not None
        print("  ✓ Detector initialized successfully")
        print(f"  ✓ Model ID: {detector.model_id}")
        print(f"  ✓ Baseline precision: {baseline.precision}")
        test_results.append(("Initialization", "PASS"))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Initialization", "FAIL"))
    print()
    
    # Test 2: Metrics Recording
    print("[TEST 2] Metrics Recording and History")
    try:
        for i in range(60):
            # Simulate normal performance variation
            metrics = ModelPerformanceMetrics(
                timestamp=time.time() + i,
                precision=0.92 - (i * 0.001),  # Slight degradation over time
                recall=0.89 - (i * 0.001),
                f1_score=0.905 - (i * 0.001),
                accuracy=0.91,
                true_positives=8900 - i*10,
                false_positives=450 + i*5,
                true_negatives=9500,
                false_negatives=150 + i*5,
                prediction_distribution={
                    'malicious': 0.40 - i*0.002,
                    'suspicious': 0.20 + i*0.001,
                    'benign': 0.35,
                    'unknown': 0.05 + i*0.001
                },
                feature_statistics={'feature_stability': 0.95}
            )
            detector.record_metrics(metrics)
        
        assert len(detector.metrics_history) == 60
        print(f"  ✓ Recorded {len(detector.metrics_history)} metrics snapshots")
        test_results.append(("Metrics Recording", "PASS"))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Metrics Recording", "FAIL"))
    print()
    
    # Test 3: Drift Detection
    print("[TEST 3] Drift Detection Analysis")
    try:
        drift_result = detector.detect_drift()
        print(f"  ✓ Drift detected: {drift_result.drift_detected}")
        print(f"  ✓ Drift severity: {drift_result.drift_severity}")
        print(f"  ✓ Drift score: {drift_result.drift_score:.4f}")
        print(f"  ✓ Affected metrics: {drift_result.affected_metrics}")
        print(f"  ✓ Recommendation: {drift_result.recommendation}")
        print(f"  ✓ Retraining recommended: {drift_result.retraining_recommended}")
        test_results.append(("Drift Detection", "PASS"))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Drift Detection", "FAIL"))
    print()
    
    # Test 4: Statistical Tests
    print("[TEST 4] Statistical Test Results")
    try:
        drift_result = detector.detect_drift()
        ks_test = drift_result.statistical_tests.get('kolmogorov_smirnov', {})
        print(f"  ✓ KS Test p-value: {ks_test.get('pvalue', 0):.4f}")
        print(f"  ✓ KS Test significant: {ks_test.get('significant', False)}")
        
        prec_deg = drift_result.statistical_tests.get('precision_degradation', {})
        print(f"  ✓ Precision degradation: {prec_deg.get('value', 0):.4f}")
        print(f"  ✓ Precision breached: {prec_deg.get('breached', False)}")
        test_results.append(("Statistical Tests", "PASS"))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Statistical Tests", "FAIL"))
    print()
    
    # Test 5: Automated Retraining
    print("[TEST 5] Automated Retraining")
    try:
        retrain_result = detector.trigger_retraining(training_data_samples=5000)
        
        assert retrain_result.success == True
        assert retrain_result.model_version is not None
        assert retrain_result.new_metrics is not None
        
        print(f"  ✓ Retraining successful: {retrain_result.success}")
        print(f"  ✓ New version: {retrain_result.model_version}")
        print(f"  ✓ Previous version: {retrain_result.previous_version}")
        print(f"  ✓ Training duration: {retrain_result.training_duration_seconds:.2f}s")
        print(f"  ✓ New precision: {retrain_result.new_metrics.precision:.4f}")
        print(f"  ✓ New recall: {retrain_result.new_metrics.recall:.4f}")
        print(f"  ✓ New F1: {retrain_result.new_metrics.f1_score:.4f}")
        print(f"  ✓ Improvement: {retrain_result.improvement_percent:.2f}%")
        print(f"  ✓ Rollback available: {retrain_result.rollback_available}")
        test_results.append(("Automated Retraining", "PASS"))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Automated Retraining", "FAIL"))
    print()
    
    # Test 6: Model Versioning & Rollback
    print("[TEST 6] Versioning and Rollback")
    try:
        versions = list(detector.model_versions.keys())
        print(f"  ✓ Versions available: {len(versions)}")
        
        if len(versions) >= 2:
            old_version = versions[0]
            rollback_success = detector.rollback_to_version(old_version)
            print(f"  ✓ Rollback to {old_version[:20]}...: {rollback_success}")
            assert detector.current_version == old_version
        test_results.append(("Versioning & Rollback", "PASS"))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Versioning & Rollback", "FAIL"))
    print()
    
    # Test 7: Dashboard Export
    print("[TEST 7] Dashboard Metrics Export")
    try:
        dashboard = detector.get_drift_dashboard()
        print(f"  ✓ Model ID: {dashboard['model_id']}")
        print(f"  ✓ Current version: {dashboard['current_version'][:30]}...")
        print(f"  ✓ Metrics recorded: {dashboard['metrics_recorded']}")
        print(f"  ✓ Versions available: {dashboard['versions_available']}")
        print(f"  ✓ Drift detected: {dashboard['drift_analysis']['drift_detected']}")
        test_results.append(("Dashboard Export", "PASS"))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Dashboard Export", "FAIL"))
    print()
    
    # Test 8: State Persistence
    print("[TEST 8] State Export")
    try:
        detector.export_state('/tmp/detector_state_test.json')
        with open('/tmp/detector_state_test.json', 'r') as f:
            state = json.load(f)
        print(f"  ✓ State exported successfully")
        print(f"  ✓ Model ID in state: {state['model_id']}")
        print(f"  ✓ Versions in state: {len(state['model_versions'])}")
        test_results.append(("State Persistence", "PASS"))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("State Persistence", "FAIL"))
    print()
    
    # Summary
    print("=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    
    passed = sum(1 for _, result in test_results if result == "PASS")
    total = len(test_results)
    
    for test_name, result in test_results:
        status = "✓ PASS" if result == "PASS" else "✗ FAIL"
        print(f"  {status} - {test_name}")
    
    print()
    print(f"Total: {passed}/{total} tests passed")
    print(f"Success rate: {(passed/total)*100:.1f}%")
    print()
    
    # Save results
    results_json = {
        'test_timestamp': datetime.now().isoformat(),
        'module': 'threat_intelligence_model_drift_detector_retrainer',
        'passed': passed,
        'total': total,
        'success_rate': passed/total,
        'tests': test_results
    }
    
    with open('/home/user/autonomous-developer/NeuralShield-AI/test_results_drift_detector.json', 'w') as f:
        json.dump(results_json, f, indent=2)
    
    print("Results saved to test_results_drift_detector.json")
    print()
    
    return passed == total


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
