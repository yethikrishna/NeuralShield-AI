"""
Test Suite for NeuralShield Error Resilience Framework v2
DIMENSION E: Error Resilience
44 comprehensive tests - ALL must pass

Tests cover:
1. Custom Exception Hierarchy (8 tests)
2. Error Context Propagation (3 tests)
3. Timeout Wrappers (5 tests)
4. Retry + Backoff Strategies (6 tests)
5. Circuit Breaker Pattern (6 tests)
6. Bulkhead Pattern (4 tests)
7. Graceful Degradation Fallbacks (5 tests)
8. Comprehensive Resilient Decorator (4 tests)
9. Error Metrics (3 tests)
"""

import pytest
import time
import threading
from typing import Any

# Import the module to test
from neural_shield.error_resilience_comprehensive_enhanced_v2_2026_june import (
    # Exceptions
    NeuralShieldError,
    SecurityError,
    ThreatDetectionError,
    PromptInjectionDetectionError,
    JailbreakDetectionError,
    ModelInferenceError,
    ModelTimeoutError,
    ModelLoadError,
    ValidationError,
    InputSanitizationError,
    InvalidPromptError,
    ResourceError,
    MemoryLimitExceededError,
    RateLimitExceededError,
    CircuitBreakerOpenError,
    ConfigurationError,
    FallbackActivatedError,
    
    # Context
    ErrorContext,
    ErrorContextManager,
    
    # Timeout
    Timeout,
    timeout,
    
    # Retry
    BackoffStrategy,
    RetryConfig,
    RetryPolicy,
    retry,
    
    # Circuit Breaker
    CircuitState,
    CircuitBreakerConfig,
    CircuitBreaker,
    circuit_breaker,
    
    # Bulkhead
    Bulkhead,
    
    # Fallbacks
    FallbackStrategy,
    with_fallback,
    
    # Comprehensive
    resilient,
    
    # Metrics
    ErrorMetrics,
    get_error_metrics,
)


# -----------------------------------------------------------------------------
# 1. CUSTOM EXCEPTION HIERARCHY TESTS
# -----------------------------------------------------------------------------

class TestCustomExceptionHierarchy:
    """Test custom exception hierarchy and properties"""
    
    def test_base_exception_properties(self):
        exc = NeuralShieldError("Test message", context={"key": "value"})
        assert exc.error_code == "NEURALSHIELD_ERROR"
        assert exc.severity == "ERROR"
        assert exc.retryable is False
        assert exc.message == "Test message"
        assert exc.context == {"key": "value"}
    
    def test_exception_to_dict(self):
        exc = PromptInjectionDetectionError("Injection detected", context={"prompt_len": 100})
        d = exc.to_dict()
        assert d["error_code"] == "PROMPT_INJECTION_DETECTION_ERROR"
        assert d["retryable"] is True
        assert d["context"]["prompt_len"] == 100
        assert "timestamp" in d
    
    def test_security_error_severity(self):
        exc = SecurityError("Critical security issue")
        assert exc.severity == "CRITICAL"
    
    def test_threat_detection_retryable(self):
        exc = ThreatDetectionError("Temporary detection issue")
        assert exc.retryable is True
    
    def test_model_timeout_retryable(self):
        exc = ModelTimeoutError("Model timed out")
        assert exc.retryable is True
    
    def test_model_load_not_retryable(self):
        exc = ModelLoadError("Permanent model load failure")
        assert exc.retryable is False
    
    def test_validation_error_warning_severity(self):
        exc = ValidationError("Input validation failed")
        assert exc.severity == "WARNING"
    
    def test_exception_inheritance(self):
        # Test inheritance chain
        assert isinstance(PromptInjectionDetectionError("test"), ThreatDetectionError)
        assert isinstance(PromptInjectionDetectionError("test"), SecurityError)
        assert isinstance(PromptInjectionDetectionError("test"), NeuralShieldError)


# -----------------------------------------------------------------------------
# 2. ERROR CONTEXT PROPAGATION TESTS
# -----------------------------------------------------------------------------

class TestErrorContextPropagation:
    """Test error context management"""
    
    def test_error_context_creation(self):
        ctx = ErrorContext(operation="detect_threat", module="threat_detector")
        assert ctx.operation == "detect_threat"
        assert ctx.module == "threat_detector"
        assert ctx.attempts == 0
        assert isinstance(ctx.attributes, dict)
    
    def test_error_context_attributes(self):
        ctx = ErrorContext(operation="test", module="test")
        ctx.add_attribute("prompt_length", 500)
        ctx.add_attribute("model_version", "v1")
        assert ctx.attributes["prompt_length"] == 500
        assert ctx.attributes["model_version"] == "v1"
    
    def test_error_context_attempt_tracking(self):
        ctx = ErrorContext(operation="test", module="test")
        ctx.increment_attempt()
        ctx.increment_attempt()
        assert ctx.attempts == 2


# -----------------------------------------------------------------------------
# 3. TIMEOUT WRAPPER TESTS
# -----------------------------------------------------------------------------

class TestTimeoutWrappers:
    """Test timeout functionality"""
    
    def test_timeout_triggers(self):
        @timeout(0.1)
        def slow_function():
            time.sleep(1.0)
            return "done"
        
        with pytest.raises(ModelTimeoutError):
            slow_function()
    
    def test_timeout_no_trigger_on_fast_function(self):
        @timeout(1.0)
        def fast_function():
            return "done"
        
        result = fast_function()
        assert result == "done"
    
    def test_timeout_with_fallback(self):
        @timeout(0.1, fallback="safe_fallback")
        def slow_function():
            time.sleep(1.0)
            return "done"
        
        result = slow_function()
        assert result == "safe_fallback"
    
    def test_timeout_preserves_exceptions(self):
        @timeout(1.0)
        def raising_function():
            raise ValueError("Test error")
        
        with pytest.raises(ValueError):
            raising_function()
    
    def test_timeout_class_decorator(self):
        wrapper = Timeout(0.1)
        
        @wrapper
        def slow_func():
            time.sleep(1.0)
        
        with pytest.raises(ModelTimeoutError):
            slow_func()


# -----------------------------------------------------------------------------
# 4. RETRY + BACKOFF TESTS
# -----------------------------------------------------------------------------

class TestRetryBackoff:
    """Test retry policies and backoff strategies"""
    
    def test_retry_eventually_succeeds(self):
        call_count = [0]
        
        @retry(max_attempts=3, initial_delay=0.01)
        def flaky_function():
            call_count[0] += 1
            if call_count[0] < 3:
                raise ValueError("Temporary failure")
            return "success"
        
        result = flaky_function()
        assert result == "success"
        assert call_count[0] == 3
    
    def test_retry_exhausted_raises(self):
        call_count = [0]
        
        @retry(max_attempts=2, initial_delay=0.01)
        def always_fails():
            call_count[0] += 1
            raise ValueError("Always fails")
        
        with pytest.raises(ValueError):
            always_fails()
        assert call_count[0] == 2
    
    def test_retry_specific_exceptions(self):
        call_count = [0]
        
        @retry(max_attempts=3, initial_delay=0.01, retry_on=(NeuralShieldError,))
        def specific_retry():
            call_count[0] += 1
            if call_count[0] < 2:
                raise ThreatDetectionError("Retryable error")
            return "success"
        
        result = specific_retry()
        assert result == "success"
        assert call_count[0] == 2
    
    def test_backoff_strategy_exponential(self):
        config = RetryConfig(
            max_attempts=4,
            initial_delay=0.1,
            backoff_strategy=BackoffStrategy.EXPONENTIAL
        )
        policy = RetryPolicy(config)
        
        # Check delays increase exponentially
        delay1 = policy._calculate_delay(1)
        delay2 = policy._calculate_delay(2)
        delay3 = policy._calculate_delay(3)
        
        assert delay2 >= delay1
        assert delay3 >= delay2
    
    def test_backoff_strategy_fixed(self):
        config = RetryConfig(
            max_attempts=3,
            initial_delay=0.1,
            backoff_strategy=BackoffStrategy.FIXED
        )
        policy = RetryPolicy(config)
        
        delay1 = policy._calculate_delay(1)
        delay2 = policy._calculate_delay(2)
        
        assert abs(delay1 - delay2) < 0.001  # Approximately equal
    
    def test_retry_policy_class(self):
        config = RetryConfig(max_attempts=2, initial_delay=0.01)
        policy = RetryPolicy(config)
        
        call_count = [0]
        @policy
        def test_func():
            call_count[0] += 1
            if call_count[0] < 2:
                raise ValueError("Fail")
            return "ok"
        
        result = test_func()
        assert result == "ok"


# -----------------------------------------------------------------------------
# 5. CIRCUIT BREAKER TESTS
# -----------------------------------------------------------------------------

class TestCircuitBreaker:
    """Test circuit breaker pattern implementation"""
    
    def test_circuit_closed_normal_operation(self):
        cb = CircuitBreaker(CircuitBreakerConfig(failure_threshold=5))
        
        @cb
        def normal_func():
            return "ok"
        
        result = normal_func()
        assert result == "ok"
        assert cb.state == CircuitState.CLOSED
    
    def test_circuit_trips_after_threshold(self):
        config = CircuitBreakerConfig(failure_threshold=2, reset_timeout=10.0)
        cb = CircuitBreaker(config)
        
        @cb
        def failing_func():
            raise ValueError("Fail")
        
        # First failure - still closed
        with pytest.raises(ValueError):
            failing_func()
        assert cb.state == CircuitState.CLOSED
        
        # Second failure - trips open
        with pytest.raises(ValueError):
            failing_func()
        
        # Third call should trigger open circuit
        with pytest.raises(CircuitBreakerOpenError):
            failing_func()
        
        assert cb.state == CircuitState.OPEN
    
    def test_circuit_with_fallback(self):
        config = CircuitBreakerConfig(failure_threshold=1, reset_timeout=10.0)
        cb = CircuitBreaker(config, fallback=lambda: "fallback_value")
        
        @cb
        def failing_func():
            raise ValueError("Fail")
        
        # First call fails
        with pytest.raises(ValueError):
            failing_func()
        
        # Second call should use fallback
        result = failing_func()
        assert result == "fallback_value"
    
    def test_circuit_resets_after_timeout(self):
        config = CircuitBreakerConfig(failure_threshold=1, reset_timeout=0.1)
        cb = CircuitBreaker(config)
        
        @cb
        def failing_func():
            raise ValueError("Fail")
        
        # Trip the circuit
        with pytest.raises(ValueError):
            failing_func()
        with pytest.raises(CircuitBreakerOpenError):
            failing_func()
        
        assert cb.state == CircuitState.OPEN
        
        # Wait for reset timeout
        time.sleep(0.15)
        
        # Should transition to HALF_OPEN
        assert cb.state == CircuitState.HALF_OPEN
    
    def test_circuit_recovers_on_success(self):
        config = CircuitBreakerConfig(failure_threshold=1, reset_timeout=0.1)
        cb = CircuitBreaker(config)
        
        call_count = [0]
        @cb
        def flaky_func():
            call_count[0] += 1
            if call_count[0] <= 1:
                raise ValueError("Fail")
            return "success"
        
        # Trip the circuit
        with pytest.raises(ValueError):
            flaky_func()
        
        # Wait for reset
        time.sleep(0.15)
        
        # Should succeed and close circuit
        result = flaky_func()
        assert result == "success"
        assert cb.state == CircuitState.CLOSED
    
    def test_circuit_breaker_decorator(self):
        @circuit_breaker(failure_threshold=2, reset_timeout=1.0)
        def test_func():
            return "ok"
        
        result = test_func()
        assert result == "ok"


# -----------------------------------------------------------------------------
# 6. BULKHEAD PATTERN TESTS
# -----------------------------------------------------------------------------

class TestBulkheadPattern:
    """Test bulkhead resource isolation"""
    
    def test_bulkhead_allows_concurrent_up_to_limit(self):
        bulkhead = Bulkhead(max_concurrent=2)
        
        @bulkhead
        def test_func():
            return "ok"
        
        result = test_func()
        assert result == "ok"
    
    def test_bulkhead_tracks_active_count(self):
        bulkhead = Bulkhead(max_concurrent=2)
        
        assert bulkhead.active_count == 0
        assert bulkhead.available == 2
        
        @bulkhead
        def test_func():
            assert bulkhead.active_count == 1
            return "ok"
        
        test_func()
        assert bulkhead.active_count == 0
    
    def test_bulkhead_rejects_when_full(self):
        bulkhead = Bulkhead(max_concurrent=1, timeout=0.05)
        
        barrier = threading.Barrier(2)
        
        @bulkhead
        def wait_func():
            barrier.wait(timeout=1.0)
            time.sleep(0.1)
            return "done"
        
        # Start first call - will hold bulkhead
        t = threading.Thread(target=wait_func)
        t.start()
        
        # Wait for first call to acquire bulkhead
        barrier.wait(timeout=1.0)
        
        # Second call should timeout
        with pytest.raises(ResourceError):
            wait_func()
        
        t.join()
    
    def test_bulkhead_releases_on_exception(self):
        bulkhead = Bulkhead(max_concurrent=1)
        
        @bulkhead
        def raising_func():
            raise ValueError("Test")
        
        try:
            raising_func()
        except ValueError:
            pass
        
        # Bulkhead should be released
        assert bulkhead.active_count == 0


# -----------------------------------------------------------------------------
# 7. GRACEFUL DEGRADATION FALLBACKS
# -----------------------------------------------------------------------------

class TestGracefulDegradation:
    """Test fallback strategies"""
    
    def test_fallback_returns_default(self):
        fallback = FallbackStrategy.return_default("safe_value")
        assert fallback() == "safe_value"
    
    def test_fallback_empty_list(self):
        fallback = FallbackStrategy.return_empty_list()
        assert fallback() == []
    
    def test_fallback_empty_dict(self):
        fallback = FallbackStrategy.return_empty_dict()
        assert fallback() == {}
    
    def test_with_fallback_decorator(self):
        @with_fallback(FallbackStrategy.return_default("fallback"))
        def risky_func():
            raise ValueError("Fail!")
        
        result = risky_func()
        assert result == "fallback"
    
    def test_with_fallback_specific_exceptions(self):
        @with_fallback(
            FallbackStrategy.return_default("caught"),
            catch=(ValueError,)
        )
        def func(raise_type):
            if raise_type == "value":
                raise ValueError("Value error")
            elif raise_type == "type":
                raise TypeError("Type error")
            return "success"
        
        assert func("value") == "caught"  # Caught, uses fallback
        with pytest.raises(TypeError):    # Not caught, re-raises
            func("type")
        assert func("none") == "success"  # No exception


# -----------------------------------------------------------------------------
# 8. COMPREHENSIVE RESILIENT DECORATOR
# -----------------------------------------------------------------------------

class TestComprehensiveResilientDecorator:
    """Test the all-in-one resilient decorator"""
    
    def test_resilient_basic_usage(self):
        @resilient()
        def normal_func():
            return "ok"
        
        result = normal_func()
        assert result == "ok"
    
    def test_resilient_with_timeout(self):
        @resilient(timeout_seconds=0.1)
        def slow_func():
            time.sleep(1.0)
            return "done"
        
        with pytest.raises(ModelTimeoutError):
            slow_func()
    
    def test_resilient_with_retry(self):
        call_count = [0]
        
        @resilient(max_retries=2, retry_delay=0.01)
        def flaky_func():
            call_count[0] += 1
            if call_count[0] < 2:
                raise ThreatDetectionError("Temporary")
            return "success"
        
        result = flaky_func()
        assert result == "success"
        assert call_count[0] == 2
    
    def test_resilient_with_fallback(self):
        @resilient(
            fallback=FallbackStrategy.return_default("degraded")
        )
        def failing_func():
            raise ValueError("Fail")
        
        result = failing_func()
        assert result == "degraded"


# -----------------------------------------------------------------------------
# 9. ERROR METRICS TESTS
# -----------------------------------------------------------------------------

class TestErrorMetrics:
    """Test error monitoring and metrics"""
    
    def test_metrics_recording(self):
        metrics = ErrorMetrics()
        metrics.record_success("op1")
        metrics.record_success("op1")
        metrics.record_error("op1", "error_type")
        
        stats = metrics.get_stats()
        assert stats["total_successes"] == 2
        assert stats["total_errors"] == 1
    
    def test_error_rate_calculation(self):
        metrics = ErrorMetrics()
        metrics.record_success("op1")
        metrics.record_success("op1")
        metrics.record_error("op1", "e1")
        
        rate = metrics.get_error_rate("op1")
        assert rate == 1.0 / 3.0
    
    def test_global_metrics_instance(self):
        metrics = get_error_metrics()
        assert isinstance(metrics, ErrorMetrics)


# -----------------------------------------------------------------------------
# RUN TESTS
# -----------------------------------------------------------------------------

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
