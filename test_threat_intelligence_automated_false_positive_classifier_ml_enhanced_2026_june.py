#!/usr/bin/env python3
"""
Test suite for ML Enhanced False Positive Classifier
Comprehensive testing of all classifier features
"""

import sys
import json
from neural_shield.threat_intelligence_automated_false_positive_classifier_ml_enhanced_2026_june import (
    MLFalsePositiveClassifier,
    FalsePositiveFeatures,
    ClassificationResult,
    get_false_positive_classifier
)


def run_tests():
    """Run all test cases"""
    print("=" * 70)
    print("TEST SUITE: ML Enhanced False Positive Classifier")
    print("=" * 70)
    
    all_passed = True
    test_results = []
    
    # Test 1: Basic initialization
    print("\n[TEST 1] Classifier Initialization")
    try:
        classifier = MLFalsePositiveClassifier()
        assert classifier is not None
        assert classifier.fp_threshold == 0.60
        assert 'whitelist' in classifier.model_weights
        print("  ✓ Classifier initialized correctly")
        test_results.append(("Initialization", "PASS"))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Initialization", "FAIL"))
        all_passed = False
    
    # Test 2: Whitelist detection
    print("\n[TEST 2] Whitelist Detection")
    try:
        classifier = MLFalsePositiveClassifier()
        
        # Test known whitelist domain
        result = classifier.classify("google.com", "domain", "test", {})
        assert result.is_likely_false_positive == True
        assert "whitelist" in result.classification_reason.lower()
        print("  ✓ google.com correctly identified as false positive (whitelist)")
        
        # Test whitelisted IP
        result2 = classifier.classify("8.8.8.8", "ip", "test", {})
        assert result2.is_likely_false_positive == True
        print("  ✓ 8.8.8.8 DNS correctly identified as false positive")
        
        test_results.append(("Whitelist Detection", "PASS"))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Whitelist Detection", "FAIL"))
        all_passed = False
    
    # Test 3: Malicious threat detection
    print("\n[TEST 3] Malicious Threat Detection")
    try:
        classifier = MLFalsePositiveClassifier()
        
        # Test suspicious domain with high reputation source and correlations
        result = classifier.classify(
            "evil-malware-c2-domain-99xyz.ru",
            "domain",
            "virustotal",
            {'correlated_threats': 5, 'sandbox_verified': True}
        )
        
        assert result.is_likely_false_positive == False
        assert result.recommended_action in ['INVESTIGATE', 'ESCALATE_HIGH_PRIORITY']
        print(f"  ✓ Suspicious domain NOT flagged as FP (prob: {result.fp_probability:.3f})")
        print(f"  ✓ Recommended action: {result.recommended_action}")
        
        test_results.append(("Malicious Detection", "PASS"))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Malicious Detection", "FAIL"))
        all_passed = False
    
    # Test 4: Feature extraction
    print("\n[TEST 4] Feature Extraction")
    try:
        classifier = MLFalsePositiveClassifier()
        features = classifier.extract_features("test.example.com", "domain", "virustotal", {})
        
        assert features.ioc_value == "test.example.com"
        assert features.ioc_type == "domain"
        assert 0.0 <= features.source_reputation <= 1.0
        assert 0.0 <= features.entropy_score <= 1.0
        print("  ✓ Feature vector extracted correctly")
        print(f"    - Source reputation: {features.source_reputation}")
        print(f"    - Entropy score: {features.entropy_score:.3f}")
        
        test_results.append(("Feature Extraction", "PASS"))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Feature Extraction", "FAIL"))
        all_passed = False
    
    # Test 5: Source reputation calculation
    print("\n[TEST 5] Source Reputation System")
    try:
        classifier = MLFalsePositiveClassifier()
        
        high_rep = classifier._calculate_source_reputation("virustotal")
        medium_rep = classifier._calculate_source_reputation("abuseipdb")
        low_rep = classifier._calculate_source_reputation("random_anonymous")
        
        assert high_rep > medium_rep > low_rep
        print(f"  ✓ Source reputation hierarchy works:")
        print(f"    - High (virustotal): {high_rep}")
        print(f"    - Medium (abuseipdb): {medium_rep}")
        print(f"    - Low (random): {low_rep}")
        
        test_results.append(("Source Reputation", "PASS"))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Source Reputation", "FAIL"))
        all_passed = False
    
    # Test 6: Batch classification
    print("\n[TEST 6] Batch Classification")
    try:
        classifier = MLFalsePositiveClassifier()
        
        batch_iocs = [
            ("microsoft.com", "domain", "unknown", {}),
            ("apple.com", "domain", "unknown", {}),
            ("suspicious-domain.xyz", "domain", "virustotal", {'correlated_threats': 2}),
            ("1.1.1.1", "ip", "cloudflare", {}),
        ]
        
        results = classifier.batch_classify(batch_iocs)
        assert len(results) == 4
        print(f"  ✓ Batch classification processed {len(results)} IOCs")
        
        stats = classifier.get_statistics()
        assert stats['total_classified'] == 4
        print(f"  ✓ Statistics tracking works: {stats['total_classified']} total")
        
        test_results.append(("Batch Classification", "PASS"))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Batch Classification", "FAIL"))
        all_passed = False
    
    # Test 7: Feature contributions
    print("\n[TEST 7] Feature Contribution Analysis")
    try:
        classifier = MLFalsePositiveClassifier()
        result = classifier.classify("github.com", "domain", "test", {})
        
        assert len(result.feature_contributions) > 0
        assert 'whitelist' in result.feature_contributions
        total_contribution = sum(result.feature_contributions.values())
        assert abs(total_contribution - result.fp_probability) < 0.01
        print(f"  ✓ Feature contributions sum to FP probability correctly")
        print(f"    - Total contribution: {total_contribution:.3f}")
        print(f"    - FP probability: {result.fp_probability:.3f}")
        
        test_results.append(("Feature Contributions", "PASS"))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Feature Contributions", "FAIL"))
        all_passed = False
    
    # Test 8: Entropy calculation
    print("\n[TEST 8] Entropy Calculation")
    try:
        classifier = MLFalsePositiveClassifier()
        
        # Low entropy (repeating characters)
        low_entropy = classifier._calculate_entropy("aaaaaaaaaaaa")
        # High entropy (random string)
        high_entropy = classifier._calculate_entropy("kf82jxn91pz7mqw3")
        
        assert high_entropy > low_entropy
        print(f"  ✓ Entropy calculation works:")
        print(f"    - Low entropy (aaaaa...): {low_entropy:.3f}")
        print(f"    - High entropy (random): {high_entropy:.3f}")
        
        test_results.append(("Entropy Calculation", "PASS"))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Entropy Calculation", "FAIL"))
        all_passed = False
    
    # Test 9: Model export
    print("\n[TEST 9] Model Export")
    try:
        classifier = MLFalsePositiveClassifier()
        classifier.classify("test.com", "domain", "test", {})
        
        model_state = classifier.export_model()
        assert 'model_weights' in model_state
        assert 'fp_threshold' in model_state
        assert 'historical_patterns' in model_state
        print("  ✓ Model state exported correctly")
        
        test_results.append(("Model Export", "PASS"))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Model Export", "FAIL"))
        all_passed = False
    
    # Test 10: Singleton factory
    print("\n[TEST 10] Singleton Factory")
    try:
        classifier1 = get_false_positive_classifier()
        classifier2 = get_false_positive_classifier()
        assert classifier1 is not None
        assert isinstance(classifier1, MLFalsePositiveClassifier)
        print("  ✓ Factory function returns valid classifier instance")
        
        test_results.append(("Singleton Factory", "PASS"))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Singleton Factory", "FAIL"))
        all_passed = False
    
    # Summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    
    for test_name, status in test_results:
        status_mark = "✓ PASS" if status == "PASS" else "✗ FAIL"
        print(f"  {test_name:40s} {status_mark}")
    
    passed_count = sum(1 for _, s in test_results if s == "PASS")
    total_count = len(test_results)
    
    print("\n" + "-" * 70)
    print(f"RESULTS: {passed_count}/{total_count} tests passed")
    
    # Save results
    results_data = {
        'test_timestamp': __import__('datetime').datetime.utcnow().isoformat(),
        'module_tested': 'threat_intelligence_automated_false_positive_classifier_ml_enhanced',
        'total_tests': total_count,
        'passed_tests': passed_count,
        'failed_tests': total_count - passed_count,
        'success_rate': passed_count / total_count,
        'all_passed': all_passed,
        'test_details': test_results
    }
    
    with open('test_results_automated_false_positive_classifier_ml_enhanced.json', 'w') as f:
        json.dump(results_data, f, indent=2)
    
    print(f"Results saved to test_results_automated_false_positive_classifier_ml_enhanced.json")
    
    if all_passed:
        print("\n" + "=" * 70)
        print("✓ ALL TESTS PASSED - ML False Positive Classifier is production-ready!")
        print("=" * 70)
        return 0
    else:
        print("\n" + "=" * 70)
        print("✗ SOME TESTS FAILED - Please review and fix issues")
        print("=" * 70)
        return 1


if __name__ == "__main__":
    sys.exit(run_tests())
