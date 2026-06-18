#!/usr/bin/env python3
"""
Test suite for Threat Intelligence Signature Drift Detector with Auto-Rollback
NeuralShield-AI - Production Grade Tests
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from threat_intelligence_signature_drift_detector_rollback_2026_june import (
    SignatureDriftDetector,
    SignatureVersion,
    DriftMetrics
)


def test_signature_registration():
    """Test signature registration and baseline establishment"""
    print("Test 1: Signature Registration and Baseline")
    
    detector = SignatureDriftDetector()
    
    sig = detector.register_signature(
        signature_id="SQL_INJECTION_001",
        pattern="(union|select|insert|delete|drop).*--",
        version="1.0.0",
        confidence_score=0.92
    )
    
    assert sig.signature_id == "SQL_INJECTION_001"
    assert sig.version == "1.0.0"
    assert sig.is_stable == True
    assert sig.hash_digest != ""
    
    print(f"  ✓ Registered signature: {sig.signature_id} v{sig.version}")
    print(f"  ✓ Hash digest: {sig.hash_digest[:16]}...")
    print("  ✓ PASS\n")


def test_no_drift_detection():
    """Test that similar patterns don't trigger drift"""
    print("Test 2: No Drift Detection (Similar Patterns)")
    
    detector = SignatureDriftDetector()
    
    detector.register_signature(
        signature_id="XSS_001",
        pattern="<script.*>.*</script>",
        version="1.0.0"
    )
    
    # Very similar pattern - should NOT trigger drift
    new_pattern = "<script.*src.*>.*</script>"
    should_rollback, metrics = detector.should_rollback("XSS_001", new_pattern)
    
    assert metrics is not None
    assert metrics.cosine_similarity > 0.8  # High similarity
    assert should_rollback == False
    
    print(f"  ✓ Cosine similarity: {metrics.cosine_similarity:.3f}")
    print(f"  ✓ KL divergence: {metrics.kl_divergence:.3f}")
    print(f"  ✓ Drift score: {metrics.drift_score:.3f}")
    print(f"  ✓ Rollback needed: {should_rollback}")
    print("  ✓ PASS\n")


def test_significant_drift_detection():
    """Test that significantly different patterns DO trigger drift"""
    print("Test 3: Significant Drift Detection")
    
    detector = SignatureDriftDetector(drift_threshold=0.3)
    
    detector.register_signature(
        signature_id="CMD_INJECTION_001",
        pattern=";.*(rm|cp|mv|chmod|wget|curl)",
        version="1.0.0"
    )
    
    # Completely different pattern - SHOULD trigger drift
    new_pattern = "javascript:alert\\(.*\\)"
    should_rollback, metrics = detector.should_rollback("CMD_INJECTION_001", new_pattern)
    
    assert metrics is not None
    assert metrics.drift_detected == True
    assert metrics.cosine_similarity < 0.7  # Low similarity
    assert should_rollback == True
    
    print(f"  ✓ Cosine similarity: {metrics.cosine_similarity:.3f}")
    print(f"  ✓ Drift score: {metrics.drift_score:.3f}")
    print(f"  ✓ Drift detected: {metrics.drift_detected}")
    print(f"  ✓ Auto-rollback triggered: {should_rollback}")
    print("  ✓ PASS\n")


def test_rollback_functionality():
    """Test rollback to stable version functionality"""
    print("Test 4: Rollback to Stable Version")
    
    detector = SignatureDriftDetector()
    
    detector.register_signature(
        signature_id="PATH_TRAVERSAL_001",
        pattern="../|..\\|%2e%2e%2f",
        version="1.0.0",
        confidence_score=0.95
    )
    
    # Register new version
    detector.register_signature(
        signature_id="PATH_TRAVERSAL_001",
        pattern="../|..\\|%2e%2e%2f|~",
        version="1.0.1",
        confidence_score=0.90
    )
    
    # Mark as stable
    detector.mark_as_stable("PATH_TRAVERSAL_001", "1.0.1")
    
    # Now trigger rollback
    rolled_back = detector.rollback_to_stable("PATH_TRAVERSAL_001")
    
    assert rolled_back is not None
    assert rolled_back.version == "1.0.1"
    assert rolled_back.is_stable == True
    assert len(detector.rollback_events) == 1
    
    print(f"  ✓ Rolled back to version: {rolled_back.version}")
    print(f"  ✓ Stable confidence: {rolled_back.confidence_score}")
    print(f"  ✓ Rollback events logged: {len(detector.rollback_events)}")
    print("  ✓ PASS\n")


def test_drift_summary_metrics():
    """Test drift summary and statistics reporting"""
    print("Test 5: Drift Summary and Statistics")
    
    detector = SignatureDriftDetector()
    
    # Register multiple signatures
    detector.register_signature("SIG_1", "pattern1.*", "1.0.0")
    detector.register_signature("SIG_2", "pattern2.*", "1.0.0")
    
    # Generate some drift checks
    detector.detect_drift("SIG_1", "pattern1.*modified")
    detector.detect_drift("SIG_1", "completely_different")
    detector.detect_drift("SIG_2", "pattern2.*v2")
    
    summary = detector.get_drift_summary()
    
    assert summary["total_signature_checks"] == 3
    assert summary["active_stable_signatures"] == 2
    assert summary["average_similarity"] > 0
    
    print(f"  ✓ Total checks: {summary['total_signature_checks']}")
    print(f"  ✓ Stable signatures: {summary['active_stable_signatures']}")
    print(f"  ✓ Avg similarity: {summary['average_similarity']:.3f}")
    print(f"  ✓ Drift rate: {summary['drift_rate']:.2%}")
    print("  ✓ PASS\n")


def test_edit_distance_calculation():
    """Test Levenshtein edit distance calculation"""
    print("Test 6: Edit Distance Calculation")
    
    detector = SignatureDriftDetector()
    
    dist1 = detector._levenshtein_distance("kitten", "sitting")
    dist2 = detector._levenshtein_distance("same", "same")
    dist3 = detector._levenshtein_distance("", "test")
    
    assert dist1 == 3  # kitten -> sitting requires 3 edits
    assert dist2 == 0  # identical strings
    assert dist3 == 4  # empty to test
    
    print(f"  ✓ kitten -> sitting: {dist1} edits")
    print(f"  ✓ same -> same: {dist2} edits")
    print(f"  ✓ empty -> test: {dist3} edits")
    print("  ✓ PASS\n")


def test_cosine_similarity():
    """Test cosine similarity between vectors"""
    print("Test 7: Cosine Similarity")
    
    detector = SignatureDriftDetector()
    
    vec1 = detector._char_frequency_vector("hello world")
    vec2 = detector._char_frequency_vector("hello world")
    vec3 = detector._char_frequency_vector("xyz abc")
    
    sim_identical = detector._cosine_similarity(vec1, vec2)
    sim_different = detector._cosine_similarity(vec1, vec3)
    
    assert abs(sim_identical - 1.0) < 0.001  # Almost identical
    assert sim_different < 0.5  # Different
    
    print(f"  ✓ Identical similarity: {sim_identical:.3f}")
    print(f"  ✓ Different similarity: {sim_different:.3f}")
    print("  ✓ PASS\n")


def test_state_export():
    """Test state export functionality"""
    print("Test 8: State Export")
    
    detector = SignatureDriftDetector()
    
    detector.register_signature("EXPORT_TEST", "export.*pattern", "2.0.0", 0.88)
    detector.detect_drift("EXPORT_TEST", "export.*pattern.v2")
    
    state_json = detector.export_state()
    
    assert "stable_signatures" in state_json
    assert "drift_summary" in state_json
    assert "EXPORT_TEST" in state_json
    
    print("  ✓ State exported as JSON")
    print("  ✓ Contains stable signatures")
    print("  ✓ Contains drift summary")
    print("  ✓ PASS\n")


def test_unknown_signature_handling():
    """Test handling of unknown signatures"""
    print("Test 9: Unknown Signature Handling")
    
    detector = SignatureDriftDetector()
    
    # Should return None for unknown signatures
    metrics = detector.detect_drift("UNKNOWN_SIG", "any pattern")
    rolled_back = detector.rollback_to_stable("UNKNOWN_SIG")
    
    assert metrics is None
    assert rolled_back is None
    
    print("  ✓ Unknown signature returns None for drift detection")
    print("  ✓ Unknown signature returns None for rollback")
    print("  ✓ PASS\n")


def run_all_tests():
    """Run all test cases"""
    print("=" * 60)
    print("NeuralShield-AI: Signature Drift Detector - Test Suite")
    print("=" * 60 + "\n")
    
    tests_passed = 0
    tests_failed = 0
    
    test_functions = [
        test_signature_registration,
        test_no_drift_detection,
        test_significant_drift_detection,
        test_rollback_functionality,
        test_drift_summary_metrics,
        test_edit_distance_calculation,
        test_cosine_similarity,
        test_state_export,
        test_unknown_signature_handling
    ]
    
    for test_func in test_functions:
        try:
            test_func()
            tests_passed += 1
        except AssertionError as e:
            print(f"  ✗ FAILED: {e}")
            tests_failed += 1
        except Exception as e:
            print(f"  ✗ ERROR: {e}")
            tests_failed += 1
    
    print("=" * 60)
    print(f"TEST RESULTS: {tests_passed} PASSED, {tests_failed} FAILED")
    print("=" * 60)
    
    return tests_passed, tests_failed


if __name__ == "__main__":
    passed, failed = run_all_tests()
    sys.exit(0 if failed == 0 else 1)
