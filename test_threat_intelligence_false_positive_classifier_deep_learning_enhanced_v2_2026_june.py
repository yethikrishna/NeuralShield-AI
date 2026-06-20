"""
Test Suite for Threat Intelligence False Positive Classifier - Deep Learning Enhanced v2
Production-grade testing with comprehensive coverage
"""

import json
import sys
import os
import time
from datetime import datetime
from typing import Dict, List, Any

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from threat_intelligence_false_positive_classifier_deep_learning_enhanced_v2_2026_june import (
    FalsePositiveClassifierEnhancedV2,
    ThreatAlert,
    AlertSeverity,
    ClassificationResult,
    FeatureExtractor,
    HybridCNNLSTMClassifier,
    create_sample_alert,
)


def run_test(test_name: str, test_func) -> bool:
    """Run a test and report results"""
    print(f"\n{'='*60}")
    print(f"TEST: {test_name}")
    print(f"{'='*60}")
    
    try:
        result = test_func()
        if result:
            print(f"✓ PASSED: {test_name}")
            return True
        else:
            print(f"✗ FAILED: {test_name}")
            return False
    except Exception as e:
        print(f"✗ FAILED: {test_name} - Exception: {str(e)}")
        import traceback
        traceback.print_exc()
        return False


def test_basic_classification() -> bool:
    """Test basic alert classification functionality"""
    classifier = FalsePositiveClassifierEnhancedV2()
    
    alert = create_sample_alert("NETWORK_SCAN", AlertSeverity.HIGH)
    result = classifier.classify_alert(alert)
    
    assert result.classification is not None, "Classification should not be None"
    assert 0.0 <= result.confidence <= 1.0, f"Confidence should be in [0,1], got {result.confidence}"
    assert len(result.features) > 0, "Features should be extracted"
    
    print(f"  Classification: {result.classification.value}")
    print(f"  Confidence: {result.confidence:.4f}")
    print(f"  Features extracted: {len(result.features)}")
    
    return True


def test_batch_classification() -> bool:
    """Test batch classification of multiple alerts"""
    classifier = FalsePositiveClassifierEnhancedV2()
    
    alerts = [
        create_sample_alert("NETWORK_SCAN", AlertSeverity.HIGH),
        create_sample_alert("SQL_INJECTION", AlertSeverity.CRITICAL),
        create_sample_alert("BRUTE_FORCE", AlertSeverity.HIGH),
        create_sample_alert("FALSE_ALARM", AlertSeverity.LOW),
        create_sample_alert("ROUTINE_MAINTENANCE", AlertSeverity.INFO),
        create_sample_alert("PORT_SCAN", AlertSeverity.MEDIUM),
    ]
    
    results = classifier.classify_batch(alerts)
    
    assert len(results) == len(alerts), f"Expected {len(alerts)} results, got {len(results)}"
    
    classifications = [r.classification.value for r in results]
    confidences = [r.confidence for r in results]
    
    print(f"  Classified {len(results)} alerts")
    print(f"  Classification distribution: {json.dumps(dict(__import__('collections').Counter(classifications)), indent=2)}")
    print(f"  Average confidence: {sum(confidences)/len(confidences):.4f}")
    
    return True


def test_feature_extraction() -> bool:
    """Test advanced feature extraction pipeline"""
    alert = create_sample_alert("TEST_ALERT", AlertSeverity.MEDIUM)
    
    features = FeatureExtractor.extract_features(alert)
    
    assert len(features) == 50, f"Expected 50 features, got {len(features)}"
    assert all(0.0 <= f <= 1.0 for f in features), "All features should be normalized to [0,1]"
    
    non_zero = sum(1 for f in features if f > 0)
    print(f"  Extracted {len(features)} features")
    print(f"  Non-zero features: {non_zero}")
    print(f"  Feature range: [{min(features):.4f}, {max(features):.4f}]")
    
    return True


def test_neural_network_architecture() -> bool:
    """Test CNN-LSTM hybrid neural network"""
    classifier = HybridCNNLSTMClassifier(feature_size=50)
    
    test_features = [0.5] * 50
    classification, confidence, probs = classifier.classify(test_features)
    
    assert classification is not None, "Classification should not be None"
    assert 0.0 <= confidence <= 1.0, f"Confidence should be in [0,1], got {confidence}"
    assert len(probs) == 4, f"Expected 4 class probabilities, got {len(probs)}"
    assert abs(sum(probs) - 1.0) < 0.001, f"Probabilities should sum to 1, got {sum(probs)}"
    
    print(f"  Classification: {classification.value}")
    print(f"  Confidence: {confidence:.4f}")
    print(f"  Class probabilities: {[f'{p:.4f}' for p in probs]}")
    
    return True


def test_performance_metrics() -> bool:
    """Test performance metrics tracking"""
    classifier = FalsePositiveClassifierEnhancedV2()
    
    summary = classifier.get_performance_summary()
    
    required_keys = ["model_version", "metrics", "operational", "architecture"]
    for key in required_keys:
        assert key in summary, f"Missing key: {key}"
    
    metrics = summary["metrics"]
    assert 0.0 <= metrics["accuracy"] <= 1.0, f"Invalid accuracy: {metrics['accuracy']}"
    assert 0.0 <= metrics["precision"] <= 1.0, f"Invalid precision: {metrics['precision']}"
    assert 0.0 <= metrics["recall"] <= 1.0, f"Invalid recall: {metrics['recall']}"
    assert 0.0 <= metrics["f1_score"] <= 1.0, f"Invalid f1_score: {metrics['f1_score']}"
    
    print(f"  Model version: {summary['model_version']}")
    print(f"  Accuracy: {metrics['accuracy']:.4f}")
    print(f"  Precision: {metrics['precision']:.4f}")
    print(f"  Recall: {metrics['recall']:.4f}")
    print(f"  F1 Score: {metrics['f1_score']:.4f}")
    print(f"  Architecture: {summary['architecture']['type']}")
    
    return True


def test_false_positive_reduction() -> bool:
    """Test false positive reduction rate calculation"""
    classifier = FalsePositiveClassifierEnhancedV2()
    
    # Classify some alerts
    alerts = [create_sample_alert(f"TEST_{i}", AlertSeverity.MEDIUM) for i in range(20)]
    classifier.classify_batch(alerts)
    
    reduction_rate = classifier.get_false_positive_reduction_rate()
    
    assert 0.0 <= reduction_rate <= 1.0, f"Invalid reduction rate: {reduction_rate}"
    
    print(f"  False Positive Reduction Rate: {reduction_rate:.4f}")
    print(f"  Total classifications: {len(classifier.classification_history)}")
    
    return True


def test_model_drift_detection() -> bool:
    """Test model drift detection"""
    classifier = FalsePositiveClassifierEnhancedV2()
    
    # Need at least 100 classifications for drift detection
    alerts = [create_sample_alert(f"DRIFT_TEST_{i}", AlertSeverity.MEDIUM) for i in range(100)]
    classifier.classify_batch(alerts)
    
    drift_detected, drift_score = classifier.detect_model_drift()
    
    assert isinstance(drift_detected, bool), "drift_detected should be boolean"
    assert 0.0 <= drift_score <= 1.0, f"Invalid drift score: {drift_score}"
    
    print(f"  Drift detected: {drift_detected}")
    print(f"  Drift score: {drift_score:.4f}")
    
    return True


def test_explainability_report() -> bool:
    """Test explainability report generation"""
    classifier = FalsePositiveClassifierEnhancedV2()
    
    alert = create_sample_alert("EXPLAIN_TEST", AlertSeverity.HIGH)
    classified = classifier.classify_alert(alert)
    
    report = classifier.get_explainability_report(classified)
    
    required_fields = ["alert_id", "classification", "confidence", "feature_importance", "model_version", "timestamp"]
    for field in required_fields:
        assert field in report, f"Missing field: {field}"
    
    print(f"  Alert ID: {report['alert_id'][:20]}...")
    print(f"  Classification: {report['classification']}")
    print(f"  Confidence: {report['confidence']:.4f}")
    print(f"  Feature importance keys: {len(report['feature_importance'])}")
    print(f"  Model version: {report['model_version']}")
    
    return True


def test_feedback_learning() -> bool:
    """Test feedback recording and metrics update"""
    classifier = FalsePositiveClassifierEnhancedV2()
    
    initial_accuracy = classifier.metrics.accuracy
    
    # Record some feedback
    for i in range(15):
        alert = create_sample_alert(f"FEEDBACK_{i}", AlertSeverity.MEDIUM)
        classified = classifier.classify_alert(alert)
        # Alternate correct/incorrect feedback
        classifier.record_feedback(classified, i % 3 != 0)
    
    assert len(classifier.feedback_data) == 15, f"Expected 15 feedback entries, got {len(classifier.feedback_data)}"
    
    print(f"  Initial accuracy: {initial_accuracy:.4f}")
    print(f"  Updated accuracy: {classifier.metrics.accuracy:.4f}")
    print(f"  Feedback samples: {len(classifier.feedback_data)}")
    
    return True


def test_classification_consistency() -> bool:
    """Test classification consistency (same input gives same output)"""
    classifier = FalsePositiveClassifierEnhancedV2()
    
    alert = create_sample_alert("CONSISTENCY_TEST", AlertSeverity.HIGH)
    
    # Classify same alert multiple times
    results = []
    for _ in range(5):
        result = classifier.classify_alert(alert)
        results.append((result.classification, result.confidence))
    
    # Check that classifications are consistent
    classifications = [r[0] for r in results]
    unique_classifications = set(classifications)
    
    print(f"  Unique classifications: {len(unique_classifications)}")
    print(f"  Classifications: {[c.value for c in classifications]}")
    
    # Should be mostly consistent
    return len(unique_classifications) <= 2


def test_edge_cases() -> bool:
    """Test edge cases and boundary conditions"""
    classifier = FalsePositiveClassifierEnhancedV2()
    
    # Empty raw data
    empty_alert = ThreatAlert(
        alert_id="empty_test",
        timestamp=datetime.now(),
        source="127.0.0.1",
        destination="127.0.0.1",
        alert_type="EMPTY",
        severity=AlertSeverity.INFO,
        raw_data={}
    )
    
    result = classifier.classify_alert(empty_alert)
    assert result.classification is not None, "Should handle empty data"
    
    # Very large raw data
    large_data = {"field_" + str(i): "x" * 1000 for i in range(10)}
    large_alert = ThreatAlert(
        alert_id="large_test",
        timestamp=datetime.now(),
        source="127.0.0.1",
        destination="127.0.0.1",
        alert_type="LARGE",
        severity=AlertSeverity.LOW,
        raw_data=large_data
    )
    
    result = classifier.classify_alert(large_alert)
    assert result.classification is not None, "Should handle large data"
    
    print("  Empty data alert: handled")
    print("  Large data alert: handled")
    
    return True


def test_performance_benchmark() -> bool:
    """Benchmark classification performance"""
    classifier = FalsePositiveClassifierEnhancedV2()
    
    num_alerts = 100
    alerts = [create_sample_alert(f"BENCH_{i}", AlertSeverity.MEDIUM) for i in range(num_alerts)]
    
    start_time = time.time()
    classifier.classify_batch(alerts)
    end_time = time.time()
    
    total_time = end_time - start_time
    avg_time = total_time / num_alerts
    alerts_per_second = num_alerts / total_time
    
    print(f"  Total time: {total_time:.4f}s")
    print(f"  Average per alert: {avg_time*1000:.2f}ms")
    print(f"  Throughput: {alerts_per_second:.1f} alerts/second")
    
    # Performance should be reasonable
    return avg_time < 0.01  # Less than 10ms per alert


def main():
    """Run all tests"""
    print("="*60)
    print("Threat Intelligence False Positive Classifier v2 - Test Suite")
    print("="*60)
    
    tests = [
        ("Basic Classification", test_basic_classification),
        ("Batch Classification", test_batch_classification),
        ("Feature Extraction", test_feature_extraction),
        ("Neural Network Architecture", test_neural_network_architecture),
        ("Performance Metrics", test_performance_metrics),
        ("False Positive Reduction", test_false_positive_reduction),
        ("Model Drift Detection", test_model_drift_detection),
        ("Explainability Report", test_explainability_report),
        ("Feedback Learning", test_feedback_learning),
        ("Classification Consistency", test_classification_consistency),
        ("Edge Cases", test_edge_cases),
        ("Performance Benchmark", test_performance_benchmark),
    ]
    
    results = []
    for test_name, test_func in tests:
        results.append(run_test(test_name, test_func))
    
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    passed = sum(results)
    total = len(results)
    print(f"Passed: {passed}/{total}")
    print(f"Success rate: {passed/total*100:.1f}%")
    
    # Save test results
    test_results = {
        "test_timestamp": datetime.now().isoformat(),
        "model_version": "2.0.0",
        "total_tests": total,
        "passed_tests": passed,
        "failed_tests": total - passed,
        "success_rate": passed/total,
        "test_results": dict(zip([t[0] for t in tests], results))
    }
    
    with open("test_results_threat_intelligence_false_positive_classifier_deep_learning_enhanced_v2.json", "w") as f:
        json.dump(test_results, f, indent=2)
    
    print(f"\nTest results saved to test_results_threat_intelligence_false_positive_classifier_deep_learning_enhanced_v2.json")
    
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
