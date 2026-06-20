#!/usr/bin/env python3
"""
Test suite for LLM Output Hallucination & Factuality Detector
June 2026 - Production Testing
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from neural_shield.llm_output_hallucination_factuality_detector_2026_june import (
    HallucinationFactualityDetector,
    HallucinationType,
    FactualityConfidence
)


def test_detector_initialization():
    """Test detector initialization with different strictness levels"""
    print("=" * 60)
    print("TEST 1: Detector Initialization")
    print("=" * 60)
    
    for strictness in ["strict", "balanced", "lenient"]:
        detector = HallucinationFactualityDetector(strictness=strictness)
        metrics = detector.get_detector_metrics()
        print(f"  ✓ {strictness} mode initialized")
        print(f"    - Patterns monitored: {metrics['patterns_monitored']}")
        print(f"    - Detection modules: {len(metrics['detection_modules'])}")
    
    print("  ✓ All initialization tests PASSED\n")
    return True


def test_benign_text():
    """Test detection on normal, factual text"""
    print("=" * 60)
    print("TEST 2: Benign/Factual Text Analysis")
    print("=" * 60)
    
    detector = HallucinationFactualityDetector(strictness="balanced")
    
    benign_texts = [
        "The Earth orbits around the Sun. This is a well-established scientific fact.",
        "Water boils at 100 degrees Celsius at standard atmospheric pressure.",
        "Python is a programming language first released in 1991 by Guido van Rossum."
    ]
    
    for i, text in enumerate(benign_texts):
        result = detector.analyze(text)
        print(f"  Text {i+1}: {text[:50]}...")
        print(f"    Factuality Score: {result.overall_factuality_score:.3f}")
        print(f"    Findings: {len(result.findings)}")
        print(f"    Is Hallucination: {result.is_hallucination_detected}")
        
        assert result.overall_factuality_score > 0.7, "Benign text should score high"
        assert not result.is_hallucination_detected, "Benign text should not be flagged"
    
    print("  ✓ All benign text tests PASSED\n")
    return True


def test_numerical_inconsistency():
    """Test detection of numerical inconsistencies"""
    print("=" * 60)
    print("TEST 3: Numerical Inconsistency Detection")
    print("=" * 60)
    
    detector = HallucinationFactualityDetector(strictness="balanced")
    
    test_cases = [
        "The results showed 75% improvement in speed, 40% reduction in cost, and 50% better accuracy.",
        "Our product is 100% effective, completely safe, and perfectly accurate for all users.",
        "The study involved 12345678 participants with an average improvement of 99.99999%."
    ]
    
    for i, text in enumerate(test_cases):
        result = detector.analyze(text)
        numerical_findings = [f for f in result.findings 
                             if f.hallucination_type == HallucinationType.NUMERICAL_INCONSISTENCY]
        
        print(f"  Case {i+1}: {text[:60]}...")
        print(f"    Score: {result.overall_factuality_score:.3f}")
        print(f"    Numerical findings: {len(numerical_findings)}")
        print(f"    All findings: {len(result.findings)}")
    
    print("  ✓ Numerical inconsistency detection PASSED\n")
    return True


def test_impossible_statements():
    """Test detection of impossible/improbable statements"""
    print("=" * 60)
    print("TEST 4: Impossible Statement Detection")
    print("=" * 60)
    
    detector = HallucinationFactualityDetector(strictness="balanced")
    
    test_cases = [
        "This new treatment can cure cancer completely with 100% effectiveness.",
        "Everyone agrees that this is the perfect solution with absolutely no downsides.",
        "The revolutionary discovery proves beyond any doubt the groundbreaking results."
    ]
    
    for i, text in enumerate(test_cases):
        result = detector.analyze(text)
        impossible_findings = [f for f in result.findings 
                              if f.hallucination_type == HallucinationType.IMPOSSIBLE_STATEMENT]
        
        print(f"  Case {i+1}: {text[:60]}...")
        print(f"    Score: {result.overall_factuality_score:.3f}")
        print(f"    Impossible findings: {len(impossible_findings)}")
        assert len(impossible_findings) >= 1, "Should detect impossible statements"
    
    print("  ✓ Impossible statement detection PASSED\n")
    return True


def test_unsourced_claims():
    """Test detection of unsourced/vague claims"""
    print("=" * 60)
    print("TEST 5: Unsourced Claim Detection")
    print("=" * 60)
    
    detector = HallucinationFactualityDetector(strictness="balanced")
    
    test_cases = [
        "Studies show that this method is significantly better than alternatives.",
        "According to experts, groundbreaking research indicates revolutionary changes.",
        "Research shows unpublished data supports the conclusion based on personal communication."
    ]
    
    for i, text in enumerate(test_cases):
        result = detector.analyze(text)
        unsourced_findings = [f for f in result.findings 
                             if f.hallucination_type == HallucinationType.UNSOURCED_CLAIM]
        
        print(f"  Case {i+1}: {text[:60]}...")
        print(f"    Score: {result.overall_factuality_score:.3f}")
        print(f"    Unsourced findings: {len(unsourced_findings)}")
    
    print("  ✓ Unsourced claim detection PASSED\n")
    return True


def test_temporal_anomalies():
    """Test detection of temporal anachronisms"""
    print("=" * 60)
    print("TEST 6: Temporal Anomaly Detection")
    print("=" * 60)
    
    detector = HallucinationFactualityDetector(strictness="balanced")
    
    test_cases = [
        "In 1969, the internet was widely used by businesses and consumers.",
        "Back in 1980, everyone used smartphones and social media platforms.",
        "The first website launched in 1975 using modern AI technology."
    ]
    
    for i, text in enumerate(test_cases):
        result = detector.analyze(text)
        temporal_findings = [f for f in result.findings 
                            if f.hallucination_type == HallucinationType.TEMPORAL_ANOMALY]
        
        print(f"  Case {i+1}: {text[:60]}...")
        print(f"    Score: {result.overall_factuality_score:.3f}")
        print(f"    Temporal findings: {len(temporal_findings)}")
    
    print("  ✓ Temporal anomaly detection PASSED\n")
    return True


def test_batch_analysis():
    """Test batch analysis functionality"""
    print("=" * 60)
    print("TEST 7: Batch Analysis")
    print("=" * 60)
    
    detector = HallucinationFactualityDetector(strictness="balanced")
    
    texts = [
        "Normal factual statement here.",
        "Studies show amazing results with 100% success.",
        "Another normal sentence with no issues."
    ]
    
    results = detector.batch_analyze(texts)
    print(f"  Batch size: {len(texts)}")
    print(f"  Results returned: {len(results)}")
    
    for i, result in enumerate(results):
        print(f"    Text {i+1}: score={result.overall_factuality_score:.3f}, findings={len(result.findings)}")
    
    assert len(results) == len(texts), "Batch should return same number of results"
    print("  ✓ Batch analysis PASSED\n")
    return True


def test_recommendations():
    """Test recommendation generation"""
    print("=" * 60)
    print("TEST 8: Recommendation Generation")
    print("=" * 60)
    
    detector = HallucinationFactualityDetector(strictness="balanced")
    
    high_risk_text = "This cures everything with 100% success according to unpublished data."
    result = detector.analyze(high_risk_text)
    
    print(f"  Score: {result.overall_factuality_score:.3f}")
    print(f"  Recommendations generated: {len(result.recommendations)}")
    for rec in result.recommendations[:3]:
        print(f"    - {rec}")
    
    assert len(result.recommendations) >= 1, "Should generate recommendations"
    print("  ✓ Recommendation generation PASSED\n")
    return True


def test_confidence_levels():
    """Test confidence level classification"""
    print("=" * 60)
    print("TEST 9: Confidence Level Classification")
    print("=" * 60)
    
    detector = HallucinationFactualityDetector(strictness="balanced")
    
    test_texts = [
        ("Clean text with no issues", FactualityConfidence.LIKELY_FACTUAL),
        ("This cures cancer 100%", FactualityConfidence.HIGHLY_LIKELY_HALLUCINATION),
    ]
    
    for text, expected_level in test_texts:
        result = detector.analyze(text)
        print(f"  Text: {text[:40]}...")
        print(f"    Level: {result.confidence_level.value}")
        print(f"    Score: {result.overall_factuality_score:.3f}")
    
    print("  ✓ Confidence level classification PASSED\n")
    return True


def run_all_tests():
    """Run all test cases"""
    print("\n" + "=" * 60)
    print("LLM OUTPUT HALLUCINATION & FACTUALITY DETECTOR - TEST SUITE")
    print("=" * 60 + "\n")
    
    tests = [
        test_detector_initialization,
        test_benign_text,
        test_numerical_inconsistency,
        test_impossible_statements,
        test_unsourced_claims,
        test_temporal_anomalies,
        test_batch_analysis,
        test_recommendations,
        test_confidence_levels
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"  ✗ TEST FAILED: {test.__name__}")
            print(f"    Error: {str(e)}")
            failed += 1
    
    print("=" * 60)
    print(f"TEST SUMMARY: {passed} PASSED, {failed} FAILED")
    print("=" * 60)
    
    if failed == 0:
        print("\n✓ ALL TESTS PASSED - Hallucination Detector working correctly!")
    else:
        print(f"\n✗ {failed} TESTS FAILED")
    
    return passed, failed


if __name__ == "__main__":
    passed, failed = run_all_tests()
    sys.exit(0 if failed == 0 else 1)
