"""
Test Suite for NeuralShield Error Resilience v17
Adaptive Resilience Controller with Intelligent Failure Prediction

DIMENSION E - Error Resilience
ADD-ONLY - tests only, no production code modifications
"""

import pytest
import time
import threading
from neural_shield.error_resilience_adaptive_controller_v17_2026_june import (
    HealthMonitor, HealthScore, HealthStatus,
    AdaptiveThresholdController, FailurePrediction,
    FailurePredictor, FailurePattern,
    DynamicDegradationManager, ResiliencePolicy,
    PredictiveCircuitBreaker,
    AdaptiveResilienceController, adaptive_resilience,
    adaptively_resilient, ResilienceError
)

# -----------------------------------------------------------------------------
# HEALTH MONITOR TESTS
# -----------------------------------------------------------------------------

class TestHealthMonitor:
    def test_health_monitor_initialization(self):
        hm = HealthMonitor("test")
        health = hm.get_health()
        assert health.overall == 100.0
        assert health.status == HealthStatus.HEALTHY
    
    def test_health_monitor_success_recording(self):
        hm = HealthMonitor("test")
        hm.record_request(success=True, latency_ms=50.0)
        health = hm.get_health()
        assert health.overall > 90.0
        assert health.error_rate_score > 90.0
    
    def test_health_monitor_error_impacts_score(self):
        hm = HealthMonitor("test")
        for _ in range(20):
            hm.record_request(success=False)
        health = hm.get_health()
        assert health.overall < 80.0
    
    def test_health_status_boundaries(self):
        assert HealthScore(overall=95.0).status == HealthStatus.HEALTHY
        assert HealthScore(overall=80.0).status == HealthStatus.DEGRADED
        assert HealthScore(overall=60.0).status == HealthStatus.STRESSED
        assert HealthScore(overall=40.0).status == HealthStatus.CRITICAL
        assert HealthScore(overall=20.0).status == HealthStatus.UNHEALTHY
    
    def test_saturation_impacts_health(self):
        hm = HealthMonitor("test")
        hm.set_saturation(80.0)
        health = hm.get_health()
        assert health.saturation_score == 20.0

# -----------------------------------------------------------------------------
# ADAPTIVE THRESHOLD TESTS
# -----------------------------------------------------------------------------

class TestAdaptiveThresholdController:
    def test_initialization(self):
        atc = AdaptiveThresholdController("test")
        assert atc.name == "test"
    
    def test_learning_from_samples(self):
        atc = AdaptiveThresholdController("test")
        for _ in range(100):
            atc.record_sample(success=True, response_time_ms=100.0)
        threshold = atc.get_optimal_failure_threshold()
        assert threshold >= 2
        timeout = atc.get_optimal_timeout_ms()
        assert timeout > 100.0
    
    def test_failure_prediction_low_risk_initially(self):
        atc = AdaptiveThresholdController("test")
        prediction = atc.get_failure_prediction()
        assert prediction == FailurePrediction.LOW_RISK
    
    def test_adapts_to_high_failure_rate(self):
        atc = AdaptiveThresholdController("test")
        # Record many failures
        for _ in range(60):
            atc.record_sample(success=False)
        threshold = atc.get_optimal_failure_threshold()
        # Should become more sensitive (lower threshold)
        assert threshold <= 5

# -----------------------------------------------------------------------------
# FAILURE PREDICTOR TESTS
# -----------------------------------------------------------------------------

class TestFailurePredictor:
    def test_initialization(self):
        fp = FailurePredictor("test")
        assert fp.name == "test"
    
    def test_records_success_and_failure(self):
        fp = FailurePredictor("test")
        fp.record_success("mod1", "op1")
        fp.record_failure("mod1", "op1", "type1")
        # Should not raise
    
    def test_prediction_based_on_patterns(self):
        fp = FailurePredictor("test")
        # Record many failures
        for _ in range(30):
            fp.record_failure("mod1", "op1")
        prediction = fp.get_prediction("mod1", "op1")
        # Should predict higher risk
        assert prediction in [
            FailurePrediction.MEDIUM_RISK,
            FailurePrediction.HIGH_RISK,
            FailurePrediction.IMMINENT
        ]
    
    def test_system_wide_risk(self):
        fp = FailurePredictor("test")
        risk = fp.get_system_wide_risk()
        assert "overall_risk" in risk
        assert "avg_failure_rate" in risk

# -----------------------------------------------------------------------------
# FAILURE PATTERN TESTS
# -----------------------------------------------------------------------------

class TestFailurePattern:
    def test_failure_rate_calculation(self):
        fp = FailurePattern(module="test", operation="test")
        fp.record_failure("type1")
        fp.record_success()
        rate = fp.get_failure_rate(60)
        assert rate == 0.5
    
    def test_empty_pattern_zero_rate(self):
        fp = FailurePattern()
        assert fp.get_failure_rate() == 0.0
    
    def test_failure_trend(self):
        fp = FailurePattern()
        # Should work without errors
        trend = fp.get_failure_trend()
        assert isinstance(trend, float)

# -----------------------------------------------------------------------------
# DEGRADATION MANAGER TESTS
# -----------------------------------------------------------------------------

class TestDynamicDegradationManager:
    def test_initialization(self):
        dm = DynamicDegradationManager()
        assert dm is not None
    
    def test_sets_degradation_level_based_on_health(self):
        dm = DynamicDegradationManager()
        # Full health = full features
        dm.set_health(HealthScore(overall=90.0))
        assert dm.is_feature_available("feature1", "full") == True
        
        # Low health = no full features
        dm.set_health(HealthScore(overall=20.0))
        assert dm.is_feature_available("feature1", "full") == False
    
    def test_minimal_level_allows_minimal_features(self):
        dm = DynamicDegradationManager()
        dm.set_health(HealthScore(overall=40.0))
        # Should allow minimal level features
        assert dm.is_feature_available("feature1", "minimal") == True
    
    def test_get_summary(self):
        dm = DynamicDegradationManager()
        summary = dm.get_degradation_summary()
        assert "current_level" in summary
        assert "health_score" in summary

# -----------------------------------------------------------------------------
# PREDICTIVE CIRCUIT BREAKER TESTS
# -----------------------------------------------------------------------------

class TestPredictiveCircuitBreaker:
    def test_initial_state_closed(self):
        pcb = PredictiveCircuitBreaker("test", failure_threshold=3)
        allowed, reason = pcb.allow_request("mod", "op")
        assert allowed == True
    
    def test_trips_after_consecutive_failures(self):
        pcb = PredictiveCircuitBreaker("test", failure_threshold=3)
        # Record failures
        for _ in range(5):
            pcb.record_result("mod", "op", success=False)
        # Should be tripped
        allowed, reason = pcb.allow_request("mod", "op")
        assert allowed == False
    
    def test_records_success(self):
        pcb = PredictiveCircuitBreaker("test")
        pcb.record_result("mod", "op", success=True, latency_ms=10.0)
        # Should not raise
    
    def test_get_status(self):
        pcb = PredictiveCircuitBreaker("test")
        status = pcb.get_status()
        assert "name" in status
        assert "state" in status
        assert "consecutive_failures" in status

# -----------------------------------------------------------------------------
# CONTROLLER TESTS
# -----------------------------------------------------------------------------

class TestAdaptiveResilienceController:
    def test_singleton_pattern(self):
        c1 = AdaptiveResilienceController()
        c2 = AdaptiveResilienceController()
        assert c1 is c2
    
    def test_get_circuit_breaker(self):
        controller = AdaptiveResilienceController()
        cb = controller.get_circuit_breaker("test_cb")
        assert cb is not None
    
    def test_records_operations(self):
        controller = AdaptiveResilienceController()
        controller.record_operation("mod", "op", success=True, latency_ms=50.0)
        # Should not raise
    
    def test_system_health_report(self):
        controller = AdaptiveResilienceController()
        report = controller.get_system_health()
        assert "health_score" in report
        assert "health_status" in report
        assert "degradation" in report
        assert "risk_assessment" in report

# -----------------------------------------------------------------------------
# DECORATOR TESTS
# -----------------------------------------------------------------------------

class TestAdaptiveDecorator:
    def test_decorator_preserves_function(self):
        @adaptively_resilient(module="test", operation="test_op")
        def test_func(x, y):
            return x + y
        
        assert test_func(2, 3) == 5
    
    def test_decorator_with_fallback(self):
        def fallback():
            return "fallback_result"
        
        @adaptively_resilient(module="test", operation="test_op", fallback=fallback)
        def test_func():
            return "normal"
        
        assert test_func() == "normal"

# -----------------------------------------------------------------------------
# CONCURRENCY TESTS
# -----------------------------------------------------------------------------

class TestConcurrency:
    def test_health_monitor_thread_safe(self):
        hm = HealthMonitor("concurrent")
        threads = []
        
        def worker():
            for _ in range(10):
                hm.record_request(success=True, latency_ms=10.0)
        
        for _ in range(10):
            t = threading.Thread(target=worker)
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        # Should complete without deadlock or corruption
    
    def test_controller_thread_safe(self):
        controller = AdaptiveResilienceController()
        threads = []
        
        def worker():
            for _ in range(10):
                controller.record_operation("mod", "op", success=True)
        
        for _ in range(10):
            t = threading.Thread(target=worker)
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        # Should complete without errors

# -----------------------------------------------------------------------------
# BACKWARD COMPATIBILITY TESTS
# -----------------------------------------------------------------------------

class TestBackwardCompatibility:
    def test_no_breaking_changes(self):
        """Verify existing code patterns still work."""
        # All new components are additive
        hm = HealthMonitor("compat_test")
        assert hm is not None
        
        controller = AdaptiveResilienceController()
        assert controller is not None
    
    def test_global_instance_available(self):
        """Verify global singleton is properly exported."""
        assert adaptive_resilience is not None
        assert isinstance(adaptive_resilience, AdaptiveResilienceController)

# -----------------------------------------------------------------------------
# RUN TESTS
# -----------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 60)
    print("NeuralShield Error Resilience v17 - Test Suite")
    print("=" * 60)
    
    # Run self-tests from module
    from neural_shield.error_resilience_adaptive_controller_v17_2026_june import run_self_tests
    results = run_self_tests()
    
    print(f"\nFinal: {results['tests_passed']}/{results['tests_passed'] + results['tests_failed']} tests passed")
    
    if results['tests_failed'] > 0:
        exit(1)
    exit(0)
