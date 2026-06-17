#!/usr/bin/env python3
"""
Test Suite for Multimodal Hallucination & Factuality Detector
Production-grade tests with real-world scenarios
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from multimodal_hallucination_factuality_detector_2026_june import MultimodalHallucinationDetector


def test_initialization():
    """Test detector initialization"""
    print("Test 1: Initialization")
    detector = MultimodalHallucinationDetector()
    assert detector is not None
    assert detector.SEVERITY_HIGH == 0.85
    assert detector.SEVERITY_MEDIUM == 0.6
    assert detector.SEVERITY_LOW == 0.3
    print("  ✓ Initialization successful")
    return True


def test_clean_output_no_source():
    """Test detection on clean output without source context"""
    print("\nTest 2: Clean output (no source context)")
    detector = MultimodalHallucinationDetector()

    clean_text = """
    The quick brown fox jumps over the lazy dog.
    This is a standard sentence used for testing purposes.
    It contains all letters of the English alphabet.
    """

    is_hallucinating, report = detector.detect_hallucination(clean_text)
    print(f"  Score: {report['hallucination_score']}")
    print(f"  Severity: {report['severity']}")
    print(f"  Findings: {report['findings']}")

    # Should have low score due to no source context penalty only
    assert report['hallucination_score'] < 0.5
    print("  ✓ Clean output correctly assessed")
    return True


def test_clear_hallucination():
    """Test detection on clearly hallucinated content"""
    print("\nTest 3: Clear hallucination detection")
    detector = MultimodalHallucinationDetector()

    hallucinated_text = """
    According to a 2025 study by Dr. Alexander Hamilton at the University of Neverland,
    everyone knows that eating 100 bananas per day increases lifespan by 50 years.
    Statistics show that 99% of people who follow this diet live to be 150 years old.
    """

    source_context = """
    Bananas are a good source of potassium. A medium banana contains about 422mg of potassium.
    The recommended daily intake of potassium for adults is 4700mg.
    """

    is_hallucinating, report = detector.detect_hallucination(hallucinated_text, source_context)
    print(f"  Score: {report['hallucination_score']}")
    print(f"  Severity: {report['severity']}")
    print(f"  Findings: {report['findings']}")
    print(f"  Is Hallucinating: {is_hallucinating}")

    assert is_hallucinating == True
    assert report['severity'] in ['HIGH', 'MEDIUM']
    assert len(report['findings']) > 0
    print("  ✓ Hallucination correctly detected")
    return True


def test_numerical_inconsistency():
    """Test detection of numerical inconsistencies"""
    print("\nTest 4: Numerical inconsistency detection")
    detector = MultimodalHallucinationDetector()

    output_text = """
    The company reported revenue of $15 million in Q1 2026, with 25% growth year-over-year.
    They employed 500 people across 10 different offices.
    """

    source_context = """
    The company reported revenue of $10.5 million in Q1 2026, with 12% growth year-over-year.
    They employed 320 people across 7 different offices.
    """

    is_hallucinating, report = detector.detect_hallucination(output_text, source_context)
    print(f"  Score: {report['hallucination_score']}")
    print(f"  Findings: {report['findings']}")

    numerical_findings = [f for f in report['findings'] if 'unverified_number' in str(f)]
    assert len(numerical_findings) > 0
    print("  ✓ Numerical inconsistencies detected")
    return True


def test_entity_verification():
    """Test entity verification against source context"""
    print("\nTest 5: Entity verification")
    detector = MultimodalHallucinationDetector()

    output_text = """
    CEO John Smith announced the partnership with XYZ Corporation.
    The deal was signed in Paris last week.
    """

    source_context = """
    CEO Sarah Johnson announced the partnership with ABC Industries.
    The deal was signed in London last month.
    """

    is_hallucinating, report = detector.detect_hallucination(output_text, source_context)
    print(f"  Score: {report['hallucination_score']}")
    print(f"  Entities analyzed: {report['entities_analyzed']}")
    print(f"  Findings: {report['findings']}")

    assert report['entities_analyzed'] > 0
    print("  ✓ Entity verification working")
    return True


def test_batch_detection():
    """Test batch processing capability"""
    print("\nTest 6: Batch detection")
    detector = MultimodalHallucinationDetector()

    outputs = [
        "This is normal output with no issues.",
        "According to studies everyone knows this is true.",
        "The Eiffel Tower is located in France."
    ]

    sources = [
        "Normal content here.",
        "",
        "Paris is the capital of France."
    ]

    results = detector.batch_detect(outputs, sources)
    print(f"  Batch processed: {len(results)} items")
    assert len(results) == 3
    assert all('hallucination_score' in r for r in results)
    print("  ✓ Batch detection working correctly")
    return True


def test_detection_summary():
    """Test summary statistics generation"""
    print("\nTest 7: Detection summary statistics")
    detector = MultimodalHallucinationDetector()

    # Run some detections
    detector.detect_hallucination("Test output 1")
    detector.detect_hallucination("Test output 2")

    summary = detector.get_detection_summary()
    print(f"  Total scans: {summary['total_scans']}")
    print(f"  Detection rate: {summary['detection_rate']}")

    assert summary['total_scans'] >= 2
    assert 'pattern_breakdown' in summary
    print("  ✓ Summary statistics generated")
    return True


def test_report_structure():
    """Test that report contains all required fields"""
    print("\nTest 8: Report structure validation")
    detector = MultimodalHallucinationDetector()

    _, report = detector.detect_hallucination("Test content", "Source context")

    required_fields = [
        'hallucination_score',
        'severity',
        'is_hallucinating',
        'findings',
        'source_context_used',
        'entities_analyzed',
        'detection_timestamp',
        'content_hash'
    ]

    for field in required_fields:
        assert field in report, f"Missing field: {field}"

    print("  ✓ All required fields present in report")
    return True


def run_all_tests():
    """Run all tests and generate report"""
    print("=" * 60)
    print("Multimodal Hallucination Detector - Test Suite")
    print("=" * 60)

    tests = [
        test_initialization,
        test_clean_output_no_source,
        test_clear_hallucination,
        test_numerical_inconsistency,
        test_entity_verification,
        test_batch_detection,
        test_detection_summary,
        test_report_structure
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
            print(f"  ✗ FAILED: {e}")
            failed += 1

    print("\n" + "=" * 60)
    print(f"RESULTS: {passed} PASSED, {failed} FAILED")
    print("=" * 60)

    return passed, failed


if __name__ == "__main__":
    passed, failed = run_all_tests()
    sys.exit(0 if failed == 0 else 1)
