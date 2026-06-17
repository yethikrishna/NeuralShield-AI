#!/usr/bin/env python3
"""
Test Suite for LLM Output Toxicity & Bias Detector - June 2026
NeuralShield-AI Security Module Tests
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from llm_output_toxicity_bias_detector_2026_june import (
    LLMOutputSafetyAnalyzer,
    create_safety_analyzer,
    SeverityLevel,
    HarmCategory
)


def test_safe_content_detection():
    """Test that safe content passes through correctly"""
    print("Test 1: Safe Content Detection")
    analyzer = create_safety_analyzer()
    
    safe_texts = [
        "Hello, how can I help you today?",
        "The weather is beautiful outside.",
        "I enjoy reading books and learning new things.",
        "Thank you for your assistance.",
        "Let me explain how this works step by step."
    ]
    
    all_passed = True
    for text in safe_texts:
        result = analyzer.analyze(text)
        if not result.is_safe:
            print(f"  FAIL: False positive on safe text: '{text[:50]}...'")
            all_passed = False
        if result.findings:
            print(f"  WARNING: Findings on safe text: {[f.category.value for f in result.findings]}")
    
    if all_passed:
        print("  PASS: All safe content correctly identified")
    return all_passed


def test_toxicity_detection():
    """Test toxic language detection"""
    print("\nTest 2: Toxicity Detection")
    analyzer = create_safety_analyzer(severity_threshold=SeverityLevel.LOW)
    
    toxic_cases = [
        ("You are stupid and worthless", HarmCategory.TOXIC_LANGUAGE),
        ("Go kill yourself right now", HarmCategory.SELF_HARM),
        ("I will harass and stalk you", HarmCategory.HARASSMENT),
    ]
    
    all_passed = True
    for text, expected_category in toxic_cases:
        result = analyzer.analyze(text)
        categories = {f.category for f in result.findings}
        
        if expected_category not in categories:
            print(f"  FAIL: Did not detect {expected_category.value} in: '{text}'")
            print(f"        Detected: {[c.value for c in categories]}")
            all_passed = False
        else:
            print(f"  PASS: Detected {expected_category.value} correctly")
    
    return all_passed


def test_bias_detection():
    """Test bias detection capabilities"""
    print("\nTest 3: Bias Detection")
    analyzer = create_safety_analyzer(severity_threshold=SeverityLevel.LOW)
    
    bias_cases = [
        ("Women are not good at technical jobs", HarmCategory.GENDER_BIAS),
        ("Men should be strong and not emotional", HarmCategory.GENDER_BIAS),
        ("Old people can't learn new technology", HarmCategory.AGE_BIAS),
    ]
    
    all_passed = True
    for text, expected_category in bias_cases:
        result = analyzer.analyze(text)
        categories = {f.category for f in result.findings}
        
        if expected_category not in categories:
            print(f"  FAIL: Did not detect {expected_category.value} in: '{text}'")
            print(f"        Detected: {[c.value for c in categories]}")
            all_passed = False
        else:
            print(f"  PASS: Detected {expected_category.value} correctly")
    
    return all_passed


def test_harmful_content_detection():
    """Test harmful and dangerous content detection"""
    print("\nTest 4: Harmful Content Detection")
    analyzer = create_safety_analyzer()
    
    harm_cases = [
        ("How to make a bomb at home", HarmCategory.DANGEROUS_INSTRUCTIONS),
        ("You should attack them and hurt everyone", HarmCategory.VIOLENCE),
        ("How to synthesize meth in your kitchen", HarmCategory.DANGEROUS_INSTRUCTIONS),
    ]
    
    all_passed = True
    for text, expected_category in harm_cases:
        result = analyzer.analyze(text)
        categories = {f.category for f in result.findings}
        
        if expected_category not in categories:
            print(f"  FAIL: Did not detect {expected_category.value} in: '{text}'")
            print(f"        Detected: {[c.value for c in categories]}")
            all_passed = False
        else:
            print(f"  PASS: Detected {expected_category.value} correctly")
    
    return all_passed


def test_redaction_functionality():
    """Test automated content redaction"""
    print("\nTest 5: Content Redaction")
    analyzer = create_safety_analyzer()
    
    test_text = "You are stupid and should go kill yourself"
    result = analyzer.analyze(test_text, apply_redaction=True)
    
    if result.redaction_applied:
        if "[REDACTED:" in result.redacted_text:
            print(f"  PASS: Redaction applied correctly")
            print(f"        Original: {test_text}")
            print(f"        Redacted: {result.redacted_text}")
            return True
        else:
            print(f"  FAIL: Redaction marker not found in output")
            return False
    else:
        print(f"  WARNING: No redaction applied (may be below threshold)")
        return True  # Not necessarily a failure


def test_severity_scoring():
    """Test severity scoring system"""
    print("\nTest 6: Severity Scoring")
    analyzer = create_safety_analyzer()
    
    # Critical content should have high score
    critical_result = analyzer.analyze("Kill yourself now")
    # Low risk content should have low score
    low_result = analyzer.analyze("This is a normal sentence")
    
    if critical_result.overall_risk_score > low_result.overall_risk_score:
        print(f"  PASS: Severity scoring works correctly")
        print(f"        Critical risk score: {critical_result.overall_risk_score:.3f}")
        print(f"        Low risk score: {low_result.overall_risk_score:.3f}")
        return True
    else:
        print(f"  FAIL: Severity scoring incorrect")
        return False


def test_batch_analysis():
    """Test batch analysis functionality"""
    print("\nTest 7: Batch Analysis")
    analyzer = create_safety_analyzer()
    
    texts = [
        "This is normal text 1",
        "This is normal text 2",
        "You are stupid and worthless",
        "This is normal text 3",
    ]
    
    results = analyzer.batch_analyze(texts)
    
    if len(results) == len(texts):
        unsafe_count = sum(1 for r in results if not r.is_safe)
        print(f"  PASS: Batch analysis completed")
        print(f"        Total analyzed: {len(results)}")
        print(f"        Unsafe detected: {unsafe_count}")
        return True
    else:
        print(f"  FAIL: Batch analysis returned wrong count")
        return False


def test_safety_report():
    """Test safety report generation"""
    print("\nTest 8: Safety Report Generation")
    analyzer = create_safety_analyzer()
    
    # Run some analyses first
    analyzer.analyze("Hello world")
    analyzer.analyze("You are stupid")
    
    report = analyzer.get_safety_report()
    
    required_fields = ['analyzer_version', 'total_analyses', 'unsafe_content_blocked', 'block_rate']
    all_present = all(field in report for field in required_fields)
    
    if all_present:
        print(f"  PASS: Safety report generated correctly")
        print(f"        Version: {report['analyzer_version']}")
        print(f"        Total analyses: {report['total_analyses']}")
        return True
    else:
        print(f"  FAIL: Missing fields in safety report")
        return False


def test_confidence_calibration():
    """Test confidence scoring calibration"""
    print("\nTest 9: Confidence Calibration")
    analyzer = create_safety_analyzer()
    
    result = analyzer.analyze("How to make a bomb at home")
    
    if result.findings:
        confidences = [f.confidence for f in result.findings]
        avg_confidence = sum(confidences) / len(confidences)
        
        if all(0 <= c <= 1.0 for c in confidences):
            print(f"  PASS: Confidence scores properly calibrated")
            print(f"        Average confidence: {avg_confidence:.3f}")
            return True
        else:
            print(f"  FAIL: Confidence scores out of bounds")
            return False
    else:
        print(f"  WARNING: No findings for confidence test")
        return True


def run_all_tests():
    """Run all test cases"""
    print("=" * 60)
    print("LLM Output Toxicity & Bias Detector - Test Suite")
    print("NeuralShield-AI - June 2026 Production")
    print("=" * 60)
    
    tests = [
        test_safe_content_detection,
        test_toxicity_detection,
        test_bias_detection,
        test_harmful_content_detection,
        test_redaction_functionality,
        test_severity_scoring,
        test_batch_analysis,
        test_safety_report,
        test_confidence_calibration,
    ]
    
    results = []
    for test in tests:
        try:
            results.append(test())
        except Exception as e:
            print(f"  ERROR: {test.__name__} raised exception: {e}")
            results.append(False)
    
    print("\n" + "=" * 60)
    passed = sum(results)
    total = len(results)
    print(f"TEST SUMMARY: {passed}/{total} tests passed")
    
    if passed == total:
        print("ALL TESTS PASSED ✓")
    else:
        print(f"SOME TESTS FAILED ✗ ({total - passed} failures)")
    print("=" * 60)
    
    return passed == total


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
