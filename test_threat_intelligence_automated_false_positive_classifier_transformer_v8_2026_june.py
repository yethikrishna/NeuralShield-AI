#!/usr/bin/env python3
"""
Test suite for NeuralShield-AI Transformer V8 False Positive Classifier
June 2026 Production Implementation

Honest Testing: This test suite verifies actual functionality with real inputs.
No mock data, no fake performance numbers.
"""

import sys
import json
from datetime import datetime

sys.path.insert(0, 'neural_shield')

from threat_intelligence_automated_false_positive_classifier_transformer_v8_2026_june import (
    TransformerV8FalsePositiveClassifier,
    ClassificationResult
)


def run_tests():
    """Run all classification tests"""
    print("=" * 70)
    print("NeuralShield-AI: Transformer V8 False Positive Classifier Tests")
    print("=" * 70)
    print(f"Test Time: {datetime.now().isoformat()}")
    print()
    
    classifier = TransformerV8FalsePositiveClassifier(
        enable_confidence_calibration=True
    )
    
    test_results = {
        "test_suite": "transformer_v8_fp_classifier",
        "test_time": datetime.now().isoformat(),
        "model_version": classifier.version,
        "tests_passed": 0,
        "tests_failed": 0,
        "test_cases": []
    }
    
    # Test Case 1: Clear False Positive - Internal IP
    print("[Test 1] Clear False Positive - Internal IP (192.168.1.1)")
    result1 = classifier.classify(
        alert_id="ALERT-001",
        indicator="192.168.1.1",
        alert_type="network_ip",
        source_reliability=0.7,
        historical_fp_rate=0.0,
        correlation_count=0,
        alert_volume=1
    )
    print(f"  Result: FP={result1.is_false_positive}, Confidence={result1.confidence_score}")
    print(f"  Reason: {result1.classification_reason}")
    print(f"  Recommendation: {result1.recommendation}")
    print(f"  Processing Time: {result1.processing_time_ms}ms")
    
    test1_passed = result1.is_false_positive == True
    if test1_passed:
        print("  ✓ PASSED: Correctly identified internal IP as false positive")
        test_results["tests_passed"] += 1
    else:
        print("  ✗ FAILED: Should have identified internal IP as false positive")
        test_results["tests_failed"] += 1
    
    test_results["test_cases"].append({
        "test_id": 1,
        "name": "internal_ip_false_positive",
        "passed": test1_passed,
        "is_false_positive": result1.is_false_positive,
        "confidence": result1.confidence_score
    })
    print()
    
    # Test Case 2: Clear False Positive - Localhost
    print("[Test 2] Clear False Positive - Localhost")
    result2 = classifier.classify(
        alert_id="ALERT-002",
        indicator="localhost",
        alert_type="network_domain",
        source_reliability=0.5,
        historical_fp_rate=0.0,
        correlation_count=0,
        alert_volume=1
    )
    print(f"  Result: FP={result2.is_false_positive}, Confidence={result2.confidence_score}")
    print(f"  Reason: {result2.classification_reason}")
    
    test2_passed = result2.is_false_positive == True
    if test2_passed:
        print("  ✓ PASSED: Correctly identified localhost as false positive")
        test_results["tests_passed"] += 1
    else:
        print("  ✗ FAILED: Should have identified localhost as false positive")
        test_results["tests_failed"] += 1
    
    test_results["test_cases"].append({
        "test_id": 2,
        "name": "localhost_false_positive",
        "passed": test2_passed,
        "is_false_positive": result2.is_false_positive,
        "confidence": result2.confidence_score
    })
    print()
    
    # Test Case 3: Legitimate Service - Google
    print("[Test 3] Legitimate Service Domain - google.com")
    result3 = classifier.classify(
        alert_id="ALERT-003",
        indicator="google.com",
        alert_type="network_domain",
        source_reliability=0.8,
        historical_fp_rate=0.0,
        correlation_count=0,
        alert_volume=1
    )
    print(f"  Result: FP={result3.is_false_positive}, Confidence={result3.confidence_score}")
    print(f"  Reason: {result3.classification_reason}")
    
    test3_passed = result3.is_false_positive == True
    if test3_passed:
        print("  ✓ PASSED: Correctly identified google.com as false positive")
        test_results["tests_passed"] += 1
    else:
        print("  ✗ FAILED: Should have identified google.com as false positive")
        test_results["tests_failed"] += 1
    
    test_results["test_cases"].append({
        "test_id": 3,
        "name": "legitimate_service_domain",
        "passed": test3_passed,
        "is_false_positive": result3.is_false_positive,
        "confidence": result3.confidence_score
    })
    print()
    
    # Test Case 4: Suspicious Domain - Potential True Positive
    print("[Test 4] Suspicious Domain - Potential True Positive")
    result4 = classifier.classify(
        alert_id="ALERT-004",
        indicator="malicious-attack-domain-xzy123.xyz",
        alert_type="network_domain",
        source_reliability=0.9,
        historical_fp_rate=0.0,
        correlation_count=5,
        alert_volume=10
    )
    print(f"  Result: FP={result4.is_false_positive}, Confidence={result4.confidence_score}")
    print(f"  Reason: {result4.classification_reason}")
    print(f"  FP Probability: {result4.false_positive_probability}")
    
    test4_passed = result4.is_false_positive == False
    if test4_passed:
        print("  ✓ PASSED: Correctly flagged suspicious domain for review")
        test_results["tests_passed"] += 1
    else:
        print("  ✗ FAILED: Should have flagged suspicious domain")
        test_results["tests_failed"] += 1
    
    test_results["test_cases"].append({
        "test_id": 4,
        "name": "suspicious_domain_true_positive",
        "passed": test4_passed,
        "is_false_positive": result4.is_false_positive,
        "confidence": result4.confidence_score
    })
    print()
    
    # Test Case 5: Batch Processing
    print("[Test 5] Batch Processing - 5 alerts")
    batch_alerts = [
        {"alert_id": "BATCH-001", "indicator": "10.0.0.1", "alert_type": "ip"},
        {"alert_id": "BATCH-002", "indicator": "github.com", "alert_type": "domain"},
        {"alert_id": "BATCH-003", "indicator": "cloudflare.com", "alert_type": "domain"},
        {"alert_id": "BATCH-004", "indicator": "random-string-abc123.biz", "alert_type": "domain"},
        {"alert_id": "BATCH-005", "indicator": "172.16.0.50", "alert_type": "ip"},
    ]
    
    batch_results = classifier.batch_classify(batch_alerts)
    print(f"  Batch Size: {len(batch_alerts)}, Results: {len(batch_results)}")
    
    fp_count = sum(1 for r in batch_results if r.is_false_positive)
    tp_count = len(batch_results) - fp_count
    print(f"  False Positives Identified: {fp_count}")
    print(f"  True Positives Flagged: {tp_count}")
    
    test5_passed = len(batch_results) == len(batch_alerts) and fp_count >= 3
    if test5_passed:
        print("  ✓ PASSED: Batch processing completed correctly")
        test_results["tests_passed"] += 1
    else:
        print("  ✗ FAILED: Batch processing issue")
        test_results["tests_failed"] += 1
    
    test_results["test_cases"].append({
        "test_id": 5,
        "name": "batch_processing",
        "passed": test5_passed,
        "batch_size": len(batch_alerts),
        "fp_count": fp_count,
        "tp_count": tp_count
    })
    print()
    
    # Test Case 6: Feature Importance Report
    print("[Test 6] Feature Importance Report")
    importance_report = classifier.get_feature_importance_report()
    print(f"  Features Tracked: {len(importance_report)}")
    print(f"  Top Features: {list(importance_report.items())[:3]}")
    
    test6_passed = len(importance_report) > 0
    if test6_passed:
        print("  ✓ PASSED: Feature importance tracking working")
        test_results["tests_passed"] += 1
    else:
        print("  ✗ FAILED: Feature importance not tracked")
        test_results["tests_failed"] += 1
    
    test_results["test_cases"].append({
        "test_id": 6,
        "name": "feature_importance",
        "passed": test6_passed,
        "features_tracked": len(importance_report)
    })
    print()
    
    # Test Case 7: Model Stats
    print("[Test 7] Model Statistics")
    stats = classifier.get_model_stats()
    print(f"  Version: {stats['version']}")
    print(f"  Total Classifications: {stats['total_classifications']}")
    print(f"  Attention Heads: {stats['attention_heads']}")
    
    test7_passed = stats["total_classifications"] > 0 and stats["version"] == "v8-transformer-2026-june"
    if test7_passed:
        print("  ✓ PASSED: Model statistics accurate")
        test_results["tests_passed"] += 1
    else:
        print("  ✗ FAILED: Model statistics incorrect")
        test_results["tests_failed"] += 1
    
    test_results["test_cases"].append({
        "test_id": 7,
        "name": "model_statistics",
        "passed": test7_passed,
        "total_classifications": stats["total_classifications"]
    })
    print()
    
    # Summary
    print("=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    print(f"Tests Passed: {test_results['tests_passed']}")
    print(f"Tests Failed: {test_results['tests_failed']}")
    print(f"Total Tests: {test_results['tests_passed'] + test_results['tests_failed']}")
    print(f"Success Rate: {(test_results['tests_passed'] / (test_results['tests_passed'] + test_results['tests_failed']) * 100):.1f}%")
    print()
    
    # Honest Limitations Disclosure
    print("=" * 70)
    print("HONEST LIMITATIONS DISCLOSURE")
    print("=" * 70)
    print("1. This is a rule-based + statistical classifier, NOT a real transformer neural network")
    print("2. Uses 'transformer-inspired' attention weighting in name only")
    print("3. Pattern matching is limited to predefined regex patterns")
    print("4. No actual machine learning training - weights are manually tuned")
    print("5. Confidence calibration is simple Platt scaling, not learned")
    print("6. Feature importance is heuristic, not SHAP/LIME based")
    print("7. No online learning capability - requires code changes to update patterns")
    print("=" * 70)
    
    # Save results
    with open("test_results_transformer_v8_fp_classifier.json", "w") as f:
        json.dump(test_results, f, indent=2)
    
    print(f"\nResults saved to: test_results_transformer_v8_fp_classifier.json")
    
    return test_results


if __name__ == "__main__":
    results = run_tests()
    sys.exit(0 if results["tests_failed"] == 0 else 1)
