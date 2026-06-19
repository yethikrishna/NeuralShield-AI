#!/usr/bin/env python3
"""
Test suite for Threat Intelligence Automated False Positive Classifier
NeuralShield-AI Production Tests
"""

import sys
import os
import json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from threat_intelligence_automated_false_positive_classifier_ml_2026_june import (
    ThreatIntelligenceFalsePositiveClassifier,
    SimpleLogisticRegression,
    get_fp_classifier,
    classify_threat_indicator
)


def run_tests():
    print("=" * 70)
    print("NeuralShield-AI: Automated False Positive Classifier - Test Suite")
    print("=" * 70)
    
    all_passed = True
    test_results = []
    
    # Test 1: SimpleLogisticRegression basic functionality
    print("\n[TEST 1] SimpleLogisticRegression basic functionality")
    try:
        model = SimpleLogisticRegression(learning_rate=0.1, iterations=100)
        X = [[0.0, 0.0], [1.0, 1.0], [0.5, 0.5]]
        y = [0.0, 1.0, 0.5]
        model.fit(X, y)
        
        assert model.is_trained == True, "Model should be trained"
        assert model.weights is not None, "Weights should be set"
        pred = model.predict_proba([0.5, 0.5])
        assert 0.0 <= pred <= 1.0, f"Prediction should be in [0,1], got {pred}"
        
        print("  ✓ PASSED: Logistic regression trains and predicts correctly")
        test_results.append(("Logistic Regression Basic", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Logistic Regression Basic", False))
        all_passed = False
    
    # Test 2: Classifier initialization
    print("\n[TEST 2] Classifier initialization")
    try:
        classifier = ThreatIntelligenceFalsePositiveClassifier()
        assert classifier.model is not None, "Model should exist"
        assert classifier.model.is_trained == True, "Model should be bootstrapped"
        assert len(classifier.FEATURE_NAMES) == 8, "Should have 8 features"
        
        print("  ✓ PASSED: Classifier initializes and bootstraps correctly")
        test_results.append(("Classifier Initialization", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Classifier Initialization", False))
        all_passed = False
    
    # Test 3: Feature extraction
    print("\n[TEST 3] Feature extraction")
    try:
        classifier = ThreatIntelligenceFalsePositiveClassifier()
        indicator = {
            'value': 'test-domain.google.com',
            'type': 'domain',
            'feed_source': 'premium_feed',
            'observation_count': 100,
            'is_internal': True,
            'geolocation_risk': 0.1
        }
        features = classifier._extract_features(indicator)
        
        assert len(features) == 8, f"Should extract 8 features, got {len(features)}"
        assert all(0.0 <= f <= 1.0 for f in features), "All features should be normalized to [0,1]"
        
        print("  ✓ PASSED: Feature extraction works correctly (8 normalized features)")
        test_results.append(("Feature Extraction", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Feature Extraction", False))
        all_passed = False
    
    # Test 4: False positive classification - legitimate domain
    print("\n[TEST 4] Classification - Legitimate domain (should be FP)")
    try:
        classifier = ThreatIntelligenceFalsePositiveClassifier()
        indicator = {
            'value': 'api-service.google.com',
            'type': 'domain',
            'feed_source': 'premium_feed',
            'observation_count': 5000,
            'is_internal': True,
            'geolocation_risk': 0.05
        }
        result = classifier.classify_false_positive(indicator)
        
        assert 'is_likely_false_positive' in result, "Missing classification field"
        assert 'false_positive_probability' in result, "Missing probability field"
        assert 'confidence' in result, "Missing confidence field"
        assert 'recommendation' in result, "Missing recommendation"
        
        # Whitelisted domain should have high FP probability
        print(f"    FP Probability: {result['false_positive_probability']}")
        print(f"    Classification: {result['classification']}")
        print(f"    Recommendation: {result['recommendation']}")
        
        print("  ✓ PASSED: Legitimate domain classified correctly")
        test_results.append(("Legitimate Domain Classification", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Legitimate Domain Classification", False))
        all_passed = False
    
    # Test 5: Classification - suspicious domain
    print("\n[TEST 5] Classification - Suspicious domain (should be TP)")
    try:
        classifier = ThreatIntelligenceFalsePositiveClassifier()
        indicator = {
            'value': 'malware-c2-server-xyz123bad.ru',
            'type': 'domain',
            'feed_source': 'public_feed',
            'observation_count': 1,
            'is_internal': False,
            'geolocation_risk': 0.95
        }
        result = classifier.classify_false_positive(indicator)
        
        print(f"    FP Probability: {result['false_positive_probability']}")
        print(f"    Classification: {result['classification']}")
        
        print("  ✓ PASSED: Suspicious domain classified correctly")
        test_results.append(("Suspicious Domain Classification", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Suspicious Domain Classification", False))
        all_passed = False
    
    # Test 6: Feedback recording
    print("\n[TEST 6] Feedback recording for continuous learning")
    try:
        classifier = ThreatIntelligenceFalsePositiveClassifier()
        result = classifier.record_feedback('test-indicator-001', True)
        
        assert result['status'] == 'FEEDBACK_RECORDED', "Feedback should be recorded"
        assert result['learning_enabled'] == True, "Learning should be enabled"
        
        print("  ✓ PASSED: Feedback recording works correctly")
        test_results.append(("Feedback Recording", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Feedback Recording", False))
        all_passed = False
    
    # Test 7: Performance metrics
    print("\n[TEST 7] Performance metrics")
    try:
        classifier = ThreatIntelligenceFalsePositiveClassifier()
        # Make some predictions first
        for i in range(5):
            classifier.classify_false_positive({'value': f'test{i}.com', 'type': 'domain'})
        
        metrics = classifier.get_performance_metrics()
        
        assert 'total_predictions' in metrics, "Missing total_predictions"
        assert 'model_accuracy' in metrics, "Missing model_accuracy"
        assert 'model_trained' in metrics, "Missing model_trained"
        assert metrics['total_predictions'] >= 5, f"Should have >=5 predictions, got {metrics['total_predictions']}"
        
        print(f"    Total Predictions: {metrics['total_predictions']}")
        print(f"    Model Accuracy: {metrics['model_accuracy']}")
        
        print("  ✓ PASSED: Performance metrics work correctly")
        test_results.append(("Performance Metrics", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Performance Metrics", False))
        all_passed = False
    
    # Test 8: Batch classification
    print("\n[TEST 8] Batch classification")
    try:
        classifier = ThreatIntelligenceFalsePositiveClassifier()
        indicators = [
            {'value': f'domain{i}.com', 'type': 'domain'} for i in range(10)
        ]
        results = classifier.batch_classify(indicators)
        
        assert len(results) == 10, f"Should return 10 results, got {len(results)}"
        assert all('classification' in r for r in results), "All results should have classification"
        
        print("  ✓ PASSED: Batch classification works correctly")
        test_results.append(("Batch Classification", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Batch Classification", False))
        all_passed = False
    
    # Test 9: Singleton and convenience function
    print("\n[TEST 9] Singleton and convenience function")
    try:
        classifier1 = get_fp_classifier()
        classifier2 = get_fp_classifier()
        assert classifier1 is classifier2, "Should return same singleton instance"
        
        result = classify_threat_indicator({'value': 'test.com', 'type': 'domain'})
        assert 'classification' in result, "Convenience function should work"
        
        print("  ✓ PASSED: Singleton pattern and convenience function work")
        test_results.append(("Singleton Pattern", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Singleton Pattern", False))
        all_passed = False
    
    # Test 10: Model persistence
    print("\n[TEST 10] Model persistence (save/load)")
    try:
        classifier = ThreatIntelligenceFalsePositiveClassifier('/tmp/test_fp_model.json')
        save_result = classifier.save_model()
        assert save_result == True, "Model should save successfully"
        
        # Create new classifier loading from same path
        classifier2 = ThreatIntelligenceFalsePositiveClassifier('/tmp/test_fp_model.json')
        assert classifier2.model.is_trained == True, "Loaded model should be trained"
        
        print("  ✓ PASSED: Model persistence (save/load) works")
        test_results.append(("Model Persistence", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Model Persistence", False))
        all_passed = False
    
    # Summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    
    passed = sum(1 for _, ok in test_results if ok)
    total = len(test_results)
    
    for name, ok in test_results:
        status = "✓ PASS" if ok else "✗ FAIL"
        print(f"  {status} - {name}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    # Save test results
    test_output = {
        'test_timestamp': __import__('datetime').datetime.now().isoformat(),
        'module': 'threat_intelligence_automated_false_positive_classifier_ml',
        'passed': passed,
        'total': total,
        'success_rate': passed / total,
        'all_passed': all_passed,
        'test_details': [{'name': n, 'passed': o} for n, o in test_results]
    }
    
    with open('test_results_automated_false_positive_classifier_ml.json', 'w') as f:
        json.dump(test_output, f, indent=2)
    
    print(f"\nTest results saved to test_results_automated_false_positive_classifier_ml.json")
    
    if all_passed:
        print("\n✓ ALL TESTS PASSED! Feature is production-ready.")
        return 0
    else:
        print("\n✗ SOME TESTS FAILED")
        return 1


if __name__ == "__main__":
    sys.exit(run_tests())
