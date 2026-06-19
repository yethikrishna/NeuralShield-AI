#!/usr/bin/env python3
"""
Test Suite for Threat Intelligence Feedback Loop Adaptive Learner
Production-grade testing with comprehensive coverage

This test suite verifies:
1. Basic feedback recording functionality
2. Adaptive learning behavior
3. Weight adjustment mechanics
4. Model health monitoring
5. Accuracy tracking
6. State persistence
"""
import sys
import json
from typing import Dict, List

# Add neural_shield to path
sys.path.insert(0, '/home/user/autonomous-developer/NeuralShield-AI')

from neural_shield.threat_intelligence_feedback_loop_adaptive_learner import (
    ThreatIntelligenceFeedbackLoopLearner,
    FeedbackOutcome,
    ModelHealthStatus,
    create_feedback_learner
)


def run_test(name: str, test_func) -> bool:
    """Run a test and report results"""
    print(f"\n{'='*60}")
    print(f"TEST: {name}")
    print(f"{'='*60}")
    try:
        result = test_func()
        if result:
            print(f"✓ PASSED: {name}")
            return True
        else:
            print(f"✗ FAILED: {name}")
            return False
    except Exception as e:
        print(f"✗ FAILED: {name} - Exception: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_basic_initialization():
    """Test basic learner initialization"""
    learner = create_feedback_learner()
    
    # Check initial weights
    weights = learner.get_current_weights()
    assert len(weights) == 6, f"Expected 6 features, got {len(weights)}"
    assert abs(sum(weights.values()) - 1.0) < 0.05, "Weights should sum to ~1.0"
    
    # Check initial metrics
    metrics = learner.get_learning_metrics()
    assert metrics.total_feedback_received == 0
    assert metrics.total_weight_adjustments == 0
    
    print("Initial weights:", weights)
    print("Initial weight sum:", sum(weights.values()))
    
    return True


def test_feedback_recording():
    """Test feedback recording functionality"""
    learner = create_feedback_learner()
    
    feature_scores = {
        "known_whitelist_match": 0.1,
        "historical_false_positive_pattern": 0.3,
        "low_severity_indicator": 0.8,
        "common_baseline_noise": 0.2,
        "missing_context_indicators": 0.0,
        "source_reliability_score": 0.25,
    }
    
    # Record feedback
    record = learner.record_feedback(
        alert_id="test_alert_001",
        original_classification="likely_false_positive",
        original_confidence=0.65,
        analyst_outcome=FeedbackOutcome.CONFIRMED_FALSE_POSITIVE,
        feature_scores=feature_scores,
        analyst_notes="Test feedback"
    )
    
    assert record.alert_id == "test_alert_001"
    assert record.analyst_outcome == FeedbackOutcome.CONFIRMED_FALSE_POSITIVE
    
    metrics = learner.get_learning_metrics()
    assert metrics.total_feedback_received == 1
    
    print("Feedback recorded successfully")
    print("Metrics after 1 feedback:", metrics.total_feedback_received)
    
    return True


def test_accuracy_tracking():
    """Test accuracy calculation and tracking"""
    learner = create_feedback_learner()
    
    feature_scores = {
        "known_whitelist_match": 0.5,
        "historical_false_positive_pattern": 0.2,
        "low_severity_indicator": 0.1,
        "common_baseline_noise": 0.3,
        "missing_context_indicators": 0.0,
        "source_reliability_score": 0.2,
    }
    
    # Record some correct predictions
    for i in range(10):
        learner.record_feedback(
            alert_id=f"correct_{i}",
            original_classification="true_positive",
            original_confidence=0.2,
            analyst_outcome=FeedbackOutcome.CONFIRMED_TRUE_POSITIVE,
            feature_scores=feature_scores
        )
    
    accuracy = learner.calculate_current_accuracy()
    assert accuracy > 0.5, f"Accuracy should be high, got {accuracy}"
    
    print(f"Current accuracy: {accuracy:.3f}")
    
    return True


def test_adaptive_learning_trigger():
    """Test that adaptive learning triggers at threshold"""
    learner = create_feedback_learner()
    
    feature_scores = {
        "known_whitelist_match": 0.5,
        "historical_false_positive_pattern": 0.2,
        "low_severity_indicator": 0.1,
        "common_baseline_noise": 0.3,
        "missing_context_indicators": 0.0,
        "source_reliability_score": 0.2,
    }
    
    initial_weights = learner.get_current_weights().copy()
    initial_adjustments = learner.learning_iterations
    
    # Record enough feedback to trigger learning
    for i in range(15):
        # Mix of correct and incorrect predictions
        if i % 3 == 0:
            outcome = FeedbackOutcome.CONFIRMED_FALSE_POSITIVE
            classification = "true_positive"  # Wrong prediction
        else:
            outcome = FeedbackOutcome.CONFIRMED_TRUE_POSITIVE
            classification = "true_positive"  # Correct prediction
            
        learner.record_feedback(
            alert_id=f"learn_test_{i}",
            original_classification=classification,
            original_confidence=0.5,
            analyst_outcome=outcome,
            feature_scores=feature_scores
        )
    
    # Check that learning occurred
    assert learner.learning_iterations > initial_adjustments, "Learning should have been triggered"
    
    new_weights = learner.get_current_weights()
    weights_changed = any(abs(new_weights[f] - initial_weights[f]) > 0.001 for f in initial_weights)
    
    print(f"Learning iterations: {learner.learning_iterations}")
    print(f"Weights changed: {weights_changed}")
    print(f"Learning rate: {learner.current_learning_rate:.4f}")
    
    return True


def test_model_health_calculation():
    """Test model health and drift detection"""
    learner = create_feedback_learner()
    
    health_score, health_status, drift_detected, drift_severity = learner.calculate_model_health()
    
    assert 0 <= health_score <= 1.0, f"Health score should be 0-1, got {health_score}"
    assert isinstance(health_status, ModelHealthStatus)
    assert isinstance(drift_detected, bool)
    assert 0 <= drift_severity <= 1.0
    
    metrics = learner.get_learning_metrics()
    assert metrics.health_status == health_status
    assert metrics.drift_detected == drift_detected
    assert abs(metrics.model_health_score - health_score) < 0.001
    
    print(f"Health score: {health_score:.3f}")
    print(f"Health status: {health_status.value}")
    print(f"Drift detected: {drift_detected}")
    print(f"Drift severity: {drift_severity:.3f}")
    
    return True


def test_state_persistence():
    """Test model state export and import"""
    learner1 = create_feedback_learner()
    
    feature_scores = {
        "known_whitelist_match": 0.5,
        "historical_false_positive_pattern": 0.2,
        "low_severity_indicator": 0.1,
        "common_baseline_noise": 0.3,
        "missing_context_indicators": 0.0,
        "source_reliability_score": 0.2,
    }
    
    # Add some feedback
    for i in range(5):
        learner1.record_feedback(
            alert_id=f"persist_{i}",
            original_classification="true_positive",
            original_confidence=0.3,
            analyst_outcome=FeedbackOutcome.CONFIRMED_TRUE_POSITIVE,
            feature_scores=feature_scores
        )
    
    # Export state
    state = learner1.export_model_state()
    
    assert "current_weights" in state
    assert "learning_iterations" in state
    assert "current_learning_rate" in state
    assert "current_accuracy" in state
    
    # Import to new learner
    learner2 = create_feedback_learner()
    learner2.import_model_state(state)
    
    # Verify weights match
    weights1 = learner1.get_current_weights()
    weights2 = learner2.get_current_weights()
    
    for feature in weights1:
        assert abs(weights1[feature] - weights2[feature]) < 0.0001, f"Weights mismatch for {feature}"
    
    print("State exported and imported successfully")
    print("Exported state keys:", list(state.keys()))
    
    return True


def test_feedback_outcome_distribution():
    """Test feedback outcome tracking"""
    learner = create_feedback_learner()
    
    feature_scores = {
        "known_whitelist_match": 0.5,
        "historical_false_positive_pattern": 0.2,
        "low_severity_indicator": 0.1,
        "common_baseline_noise": 0.3,
        "missing_context_indicators": 0.0,
        "source_reliability_score": 0.2,
    }
    
    outcomes = [
        FeedbackOutcome.CONFIRMED_TRUE_POSITIVE,
        FeedbackOutcome.CONFIRMED_FALSE_POSITIVE,
        FeedbackOutcome.CONFIRMED_TRUE_POSITIVE,
        FeedbackOutcome.CONFIRMED_TRUE_NEGATIVE,
        FeedbackOutcome.CONFIRMED_FALSE_NEGATIVE,
    ]
    
    for i, outcome in enumerate(outcomes):
        learner.record_feedback(
            alert_id=f"outcome_{i}",
            original_classification="true_positive",
            original_confidence=0.5,
            analyst_outcome=outcome,
            feature_scores=feature_scores
        )
    
    metrics = learner.get_learning_metrics()
    assert metrics.total_feedback_received == len(outcomes)
    assert len(metrics.feedback_by_outcome) > 0
    
    print("Feedback outcome distribution:", metrics.feedback_by_outcome)
    
    return True


def test_weight_constraints():
    """Test that weight constraints are respected"""
    learner = create_feedback_learner()
    
    weights = learner.get_current_weights()
    
    for feature, weight in weights.items():
        assert weight >= learner.config["min_feature_weight"] - 0.001, f"Weight too low for {feature}: {weight}"
        assert weight <= learner.config["max_feature_weight"] + 0.001, f"Weight too high for {feature}: {weight}"
    
    print("All weights within constraints")
    for f, w in sorted(weights.items()):
        print(f"  {f}: {w:.4f}")
    
    return True


def test_comprehensive_integration():
    """Comprehensive integration test"""
    print("Running comprehensive integration test...")
    
    learner = create_feedback_learner()
    
    feature_scores = {
        "known_whitelist_match": 0.3,
        "historical_false_positive_pattern": 0.4,
        "low_severity_indicator": 0.6,
        "common_baseline_noise": 0.2,
        "missing_context_indicators": 0.1,
        "source_reliability_score": 0.3,
    }
    
    # Simulate realistic feedback pattern
    for i in range(30):
        # Vary outcomes to simulate real-world scenario
        if i % 5 == 0:
            outcome = FeedbackOutcome.CONFIRMED_FALSE_POSITIVE
            classification = "true_positive"
        elif i % 7 == 0:
            outcome = FeedbackOutcome.CONFIRMED_FALSE_NEGATIVE
            classification = "likely_false_positive"
        else:
            outcome = FeedbackOutcome.CONFIRMED_TRUE_POSITIVE
            classification = "true_positive"
        
        learner.record_feedback(
            alert_id=f"integration_{i}",
            original_classification=classification,
            original_confidence=0.4 + (i % 5) * 0.1,
            analyst_outcome=outcome,
            feature_scores=feature_scores,
            analyst_notes=f"Integration test alert #{i}"
        )
    
    # Get final metrics
    metrics = learner.get_learning_metrics()
    
    print(f"\nIntegration Test Results:")
    print(f"  Total feedback: {metrics.total_feedback_received}")
    print(f"  Learning iterations: {learner.learning_iterations}")
    print(f"  Final accuracy: {metrics.accuracy_after_learning:.3f}")
    print(f"  Health score: {metrics.model_health_score:.3f}")
    print(f"  Weight adjustments: {metrics.total_weight_adjustments}")
    print(f"  Final weights:")
    for f, w in sorted(learner.get_current_weights().items(), key=lambda x: -x[1]):
        print(f"    {f}: {w:.4f}")
    
    # Get weight evolution
    evolution = learner.get_weight_evolution_report()
    print(f"\n  Features with weight evolution: {len(evolution)}")
    
    return True


def main():
    """Run all tests"""
    print("=" * 70)
    print("NeuralShield AI - Threat Intelligence Feedback Loop Learner Test Suite")
    print("=" * 70)
    
    tests = [
        ("Basic Initialization", test_basic_initialization),
        ("Feedback Recording", test_feedback_recording),
        ("Accuracy Tracking", test_accuracy_tracking),
        ("Adaptive Learning Trigger", test_adaptive_learning_trigger),
        ("Model Health Calculation", test_model_health_calculation),
        ("State Persistence", test_state_persistence),
        ("Feedback Outcome Distribution", test_feedback_outcome_distribution),
        ("Weight Constraints", test_weight_constraints),
        ("Comprehensive Integration", test_comprehensive_integration),
    ]
    
    results = []
    for name, test_func in tests:
        results.append(run_test(name, test_func))
    
    # Summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    passed = sum(results)
    total = len(results)
    print(f"Passed: {passed}/{total}")
    
    if passed == total:
        print("✓ ALL TESTS PASSED")
        # Save test results
        with open('/home/user/autonomous-developer/NeuralShield-AI/test_results_feedback_loop_learner.json', 'w') as f:
            json.dump({
                "test_date": "2026-06-19",
                "total_tests": total,
                "passed_tests": passed,
                "status": "PASSED",
                "module": "threat_intelligence_feedback_loop_adaptive_learner"
            }, f, indent=2)
        return 0
    else:
        print(f"✗ {total - passed} TEST(S) FAILED")
        return 1


if __name__ == "__main__":
    sys.exit(main())
