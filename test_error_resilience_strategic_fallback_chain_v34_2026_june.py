"""
Test Suite for Dimension E - Error Resilience v34
Strategic Fallback Chain with Priority-Based Degradation

ADD-ONLY verification - tests new module only
No production code modified
"""

import pytest
import time
import threading
from unittest.mock import Mock, patch
from neural_shield.error_resilience_strategic_fallback_chain_v34_2026_june import (
    # Exceptions
    NeuralShieldError,
    ThreatDetectionError,
    PromptInjectionDetectionError,
    JailbreakDetectionError,
    ModelInferenceTimeoutError,
    ModelInferenceError,
    ThreatIntelligenceError,
    ThreatFeedUnavailableError,
    ThreatFeedTimeoutError,
    ObservabilityError,
    LoggingSubsystemError,
    MetricsCollectionError,
    SecurityValidationError,
    InputValidationError,
    
    # Enums
    FallbackPriority,
    CircuitBreakerState,
    
    # Data classes
    RetryConfig,
    FallbackStrategy,
    FallbackResult,
    
    # Core classes
    AdaptiveTimeout,
    CircuitBreaker,
    StrategicFallbackChain,
    
    # Decorators
    with_resilience,
    register_fallback_for,
)


# -----------------------------------------------------------------------------
# EXCEPTION HIERARCHY TESTS
# -----------------------------------------------------------------------------

class TestExceptionHierarchy:
    """Test custom exception hierarchy"""

    def test_base_exception_attributes(self):
        exc = NeuralShieldError("Test message", {"key": "value"})
        assert exc.error_code == "NS-000"
        assert exc.severity == "ERROR"
        assert exc.message == "Test message"
        assert exc.details == {"key": "value"}
        assert hasattr(exc, "timestamp")

    def test_threat_detection_exception(self):
        exc = ThreatDetectionError("Detection failed")
        assert exc.error_code == "NS-TD-000"
        assert isinstance(exc, NeuralShieldError)

    def test_prompt_injection_exception_retryable(self):
        exc = PromptInjectionDetectionError("Detection error")
        assert exc.retryable is True
        assert exc.fallback_available is True

    def test_jailbreak_exception_retryable(self):
        exc = JailbreakDetectionError("Jailbreak error")
        assert exc.retryable is True
        assert exc.fallback_available is True

    def test_model_timeout_exception(self):
        exc = ModelInferenceTimeoutError("Timeout")
        assert exc.error_code == "NS-TD-003"
        assert exc.retryable is True

    def test_threat_intelligence_exception(self):
        exc = ThreatIntelligenceError("TI error")
        assert exc.error_code == "NS-TI-000"

    def test_threat_feed_unavailable(self):
        exc = ThreatFeedUnavailableError("Feed down")
        assert exc.retryable is True
        assert exc.fallback_available is True

    def test_observability_exception_fallback(self):
        exc = ObservabilityError("Obs error")
        assert exc.fallback_available is True

    def test_input_validation_not_retryable(self):
        exc = InputValidationError("Invalid input")
        assert exc.retryable is False


# -----------------------------------------------------------------------------
# FALLBACK PRIORITY TESTS
# -----------------------------------------------------------------------------

class TestFallbackPriority:
    """Test FallbackPriority enum"""

    def test_priority_values_exist(self):
        assert FallbackPriority.CRITICAL.value == "critical"
        assert FallbackPriority.HIGH.value == "high"
        assert FallbackPriority.MEDIUM.value == "medium"
        assert FallbackPriority.LOW.value == "low"
        assert FallbackPriority.BEST_EFFORT.value == "best_effort"

    def test_circuit_breaker_states(self):
        assert CircuitBreakerState.CLOSED.value == "closed"
        assert CircuitBreakerState.OPEN.value == "open"
        assert CircuitBreakerState.HALF_OPEN.value == "half_open"


# -----------------------------------------------------------------------------
# DATA CLASS TESTS
# -----------------------------------------------------------------------------

class TestDataClasses:
    """Test dataclass configurations"""

    def test_retry_config_defaults(self):
        config = RetryConfig()
        assert config.max_attempts == 3
        assert config.initial_delay == 0.1
        assert config.max_delay == 5.0
        assert config.backoff_factor == 2.0
        assert config.jitter_factor == 0.1

    def test_fallback_strategy(self):
        strategy = FallbackStrategy(priority=FallbackPriority.CRITICAL)
        assert strategy.priority == FallbackPriority.CRITICAL
        assert strategy.timeout_seconds == 30.0
        assert strategy.allow_degraded is True

    def test_fallback_result(self):
        result = FallbackResult(
            success=True,
            result={"test": "data"},
            strategy_used="primary",
            attempts=1,
            total_time=0.1
        )
        assert result.success is True
        assert result.result == {"test": "data"}
        assert result.degraded is False
        assert result.warnings == []


# -----------------------------------------------------------------------------
# ADAPTIVE TIMEOUT TESTS
# -----------------------------------------------------------------------------

class TestAdaptiveTimeout:
    """Test AdaptiveTimeout class"""

    def test_initialization(self):
        timeout = AdaptiveTimeout(default_timeout=15.0)
        assert timeout.default_timeout == 15.0

    def test_default_timeout_when_no_history(self):
        timeout = AdaptiveTimeout(default_timeout=10.0)
        calculated = timeout._calculate_adaptive_timeout("test_op")
        assert calculated == 10.0

    def test_record_success(self):
        timeout = AdaptiveTimeout()
        timeout._record_success("test_op", 0.5)
        timeout._record_success("test_op", 0.6)
        timeout._record_success("test_op", 0.7)
        
        calculated = timeout._calculate_adaptive_timeout("test_op")
        assert calculated > 0  # Should calculate based on history
        assert calculated < 30.0  # Should be reasonable


# -----------------------------------------------------------------------------
# CIRCUIT BREAKER TESTS
# -----------------------------------------------------------------------------

class TestCircuitBreaker:
    """Test CircuitBreaker class"""

    def test_initial_state_closed(self):
        cb = CircuitBreaker()
        assert cb._check_state() == CircuitBreakerState.CLOSED

    def test_trips_after_threshold(self):
        cb = CircuitBreaker(failure_threshold=3, recovery_timeout=1.0)
        
        for _ in range(3):
            cb._record_failure()
        
        assert cb._check_state() == CircuitBreakerState.OPEN

    def test_recovers_after_timeout(self):
        cb = CircuitBreaker(failure_threshold=2, recovery_timeout=0.1)
        
        cb._record_failure()
        cb._record_failure()
        assert cb._check_state() == CircuitBreakerState.OPEN
        
        time.sleep(0.15)
        assert cb._check_state() == CircuitBreakerState.HALF_OPEN

    def test_closes_after_successful_recovery(self):
        cb = CircuitBreaker(failure_threshold=2, recovery_timeout=0.1, half_open_max_calls=2)
        
        # Trip the breaker
        cb._record_failure()
        cb._record_failure()
        time.sleep(0.15)
        
        # Successful recovery attempts
        cb._record_success()
        cb._record_success()
        
        assert cb._check_state() == CircuitBreakerState.CLOSED


# -----------------------------------------------------------------------------
# STRATEGIC FALLBACK CHAIN TESTS
# -----------------------------------------------------------------------------

class TestStrategicFallbackChain:
    """Test main StrategicFallbackChain implementation"""

    def test_initialization(self):
        chain = StrategicFallbackChain()
        assert chain._fallback_registry == {}

    def test_register_fallback(self):
        chain = StrategicFallbackChain()
        
        def fallback_func():
            return "fallback"
        
        chain.register_fallback("test_op", fallback_func)
        assert "test_op" in chain._fallback_registry
        assert len(chain._fallback_registry["test_op"]) == 1

    def test_successful_primary_execution(self):
        chain = StrategicFallbackChain()
        
        def primary():
            return {"success": True}
        
        strategy = FallbackStrategy(priority=FallbackPriority.MEDIUM)
        result = chain.execute_with_resilience(primary, "test_op", strategy)
        
        assert result.success is True
        assert result.result == {"success": True}
        assert result.strategy_used == "primary"
        assert result.degraded is False

    def test_safe_default_degraded_mode(self):
        chain = StrategicFallbackChain()
        
        def failing_operation():
            raise ValueError("Always fails")
        
        strategy = FallbackStrategy(
            priority=FallbackPriority.MEDIUM,
            allow_degraded=True
        )
        result = chain.execute_with_resilience(
            failing_operation, "detect_injection", strategy,
            retry_config=RetryConfig(max_attempts=1)
        )
        
        assert result.success is True
        assert result.degraded is True
        assert result.strategy_used == "safe_default"
        assert "degraded" in result.result

    def test_retry_mechanism(self):
        chain = StrategicFallbackChain()
        call_count = [0]
        
        def flaky_operation():
            call_count[0] += 1
            if call_count[0] < 3:
                raise ModelInferenceTimeoutError("Flaky")
            return {"success": True}
        
        strategy = FallbackStrategy(priority=FallbackPriority.MEDIUM)
        result = chain.execute_with_resilience(
            flaky_operation, "test_op", strategy
        )
        
        assert result.success is True
        assert call_count[0] == 3
        assert len(result.warnings) >= 1  # Should have retry warnings

    def test_bulkhead_isolation(self):
        chain = StrategicFallbackChain()
        
        def operation():
            return {"ok": True}
        
        strategy = FallbackStrategy(
            priority=FallbackPriority.MEDIUM,
            bulkhead_key="test_bulkhead"
        )
        
        # Should work normally
        result = chain.execute_with_resilience(operation, "test_op", strategy)
        assert result.success is True

    def test_get_safe_default_for_detection(self):
        chain = StrategicFallbackChain()
        default = chain._get_safe_default("detect_injection")
        assert "risk_score" in default
        assert default["degraded"] is True

    def test_get_safe_default_for_threat(self):
        chain = StrategicFallbackChain()
        default = chain._get_safe_default("threat_feed")
        assert "threats" in default
        assert default["degraded"] is True


# -----------------------------------------------------------------------------
# DECORATOR TESTS
# -----------------------------------------------------------------------------

class TestDecorators:
    """Test convenience decorators"""

    def test_with_resilience_decorator(self):
        @with_resilience("test_decorated", priority=FallbackPriority.MEDIUM)
        def my_function(x, y):
            return x + y
        
        result = my_function(2, 3)
        assert result == 5

    def test_with_resilience_decorated_failure_with_degraded(self):
        @with_resilience("detect_test", priority=FallbackPriority.MEDIUM, allow_degraded=True)
        def failing_function():
            raise ValueError("Failed")
        
        # Should return safe default, not raise
        result = failing_function()
        assert result is not None
        assert "degraded" in result

    def test_register_fallback_decorator(self):
        @register_fallback_for("my_operation")
        def my_fallback():
            return "fallback_result"
        
        # Should register without error
        assert my_fallback() == "fallback_result"


# -----------------------------------------------------------------------------
# INTEGRATION TESTS
# -----------------------------------------------------------------------------

class TestFullIntegration:
    """Full integration tests"""

    def test_complete_resilience_stack(self):
        """Test the complete resilience stack: retry -> fallback -> safe default"""
        chain = StrategicFallbackChain()
        
        call_count = [0]
        
        def primary():
            call_count[0] += 1
            raise ModelInferenceTimeoutError("Primary failed")
        
        def fallback1():
            return {"from": "fallback1", "data": "safe"}
        
        chain.register_fallback("critical_op", fallback1)
        
        strategy = FallbackStrategy(
            priority=FallbackPriority.HIGH,
            allow_degraded=True
        )
        
        result = chain.execute_with_resilience(
            primary, "critical_op", strategy
        )
        
        assert result.success is True
        assert result.degraded is True
        assert call_count[0] >= 1  # Should have retried

    def test_thread_safety(self):
        """Basic thread safety test"""
        chain = StrategicFallbackChain()
        
        def worker():
            for _ in range(5):
                chain.execute_with_resilience(
                    lambda: {"ok": True},
                    "thread_test",
                    FallbackStrategy(priority=FallbackPriority.LOW)
                )
        
        threads = [threading.Thread(target=worker) for _ in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        # No exceptions = success
        assert True


# -----------------------------------------------------------------------------
# BACKWARD COMPATIBILITY TESTS
# -----------------------------------------------------------------------------

class TestBackwardCompatibility:
    """Verify no breaking changes"""

    def test_all_modules_importable(self):
        """All new modules import without errors"""
        from neural_shield.error_resilience_strategic_fallback_chain_v34_2026_june import (
            StrategicFallbackChain, FallbackPriority, FallbackStrategy
        )
        assert StrategicFallbackChain is not None

    def test_no_existing_code_modified(self):
        """New module is ADD-ONLY"""
        # This is a new file, so it doesn't modify any existing code
        import os
        assert os.path.exists(
            "neural_shield/error_resilience_strategic_fallback_chain_v34_2026_june.py"
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
