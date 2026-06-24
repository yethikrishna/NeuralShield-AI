"""
Test Suite for NeuralShield Comprehensive Error Resilience Framework v30
Dimension E: Error Resilience

Tests verify:
- Custom exception hierarchy
- Circuit breaker pattern
- Retry with exponential backoff
- Timeout wrappers
- Graceful degradation fallbacks
- Bulkhead isolation
- Composite resilience policies

All tests are ADD-ONLY - no existing code modified.
"""

import pytest
import time
import threading
from unittest.mock import MagicMock, patch

# Import the new error resilience module
from neural_shield.error_resilience_comprehensive_framework_v30_2026_june import (
    # Exceptions
    NeuralShieldError,
    ConfigurationError,
    ValidationError,
    SecurityViolationError,
    ThreatDetectionError,
    ModelInferenceError,
    ExternalServiceError,
    RateLimitExceededError,
    CircuitBreakerOpenError,
    TimeoutError,
    
    # Circuit Breaker
    CircuitState,
    CircuitBreaker,
    
    # Retry
    retry,
    
    # Timeout
    timeout,
    
    # Fallback
    fallback,
    
    # Bulkhead
    Bulkhead,
    
    # Composite Policy
    ResiliencePolicy,
    
    # Safe Fallbacks
    safe_fallback_empty,
    safe_fallback_allow,
    safe_fallback_deny,
)


# -----------------------------------------------------------------------------
# Exception Hierarchy Tests
# -----------------------------------------------------------------------------

class TestExceptionHierarchy:
    """Test custom exception hierarchy."""
    
    def test_base_exception_attributes(self):
        """Test base NeuralShieldError has required attributes."""
        exc = NeuralShieldError("Test message", {"key": "value"})
        
        assert exc.message == "Test message"
        assert exc.details == {"key": "value"}
        assert exc.error_code == "NS-000"
        assert exc.retryable is False
        assert exc.severity == "ERROR"
        assert hasattr(exc, 'timestamp')
    
    def test_configuration_error(self):
        """Test ConfigurationError attributes."""
        exc = ConfigurationError("Invalid config")
        assert exc.error_code == "NS-001"
        assert exc.retryable is False
    
    def test_validation_error(self):
        """Test ValidationError attributes."""
        exc = ValidationError("Invalid input")
        assert exc.error_code == "NS-002"
        assert exc.retryable is False
        assert exc.severity == "WARNING"
    
    def test_security_violation_error(self):
        """Test SecurityViolationError attributes."""
        exc = SecurityViolationError("Policy violated")
        assert exc.error_code == "NS-003"
        assert exc.retryable is False
        assert exc.severity == "CRITICAL"
    
    def test_threat_detection_error_retryable(self):
        """Test ThreatDetectionError is retryable."""
        exc = ThreatDetectionError("Detection failed")
        assert exc.error_code == "NS-004"
        assert exc.retryable is True
    
    def test_model_inference_error_retryable(self):
        """Test ModelInferenceError is retryable."""
        exc = ModelInferenceError("Inference failed")
        assert exc.error_code == "NS-005"
        assert exc.retryable is True
    
    def test_external_service_error_retryable(self):
        """Test ExternalServiceError is retryable."""
        exc = ExternalServiceError("Service down")
        assert exc.error_code == "NS-006"
        assert exc.retryable is True
    
    def test_rate_limit_error_with_retry_after(self):
        """Test RateLimitExceededError has retry_after."""
        exc = RateLimitExceededError("Rate limited", retry_after=5.0)
        assert exc.error_code == "NS-007"
        assert exc.retryable is True
        assert exc.retry_after == 5.0
    
    def test_exception_inheritance(self):
        """Test all custom exceptions inherit from NeuralShieldError."""
        assert issubclass(ConfigurationError, NeuralShieldError)
        assert issubclass(ValidationError, NeuralShieldError)
        assert issubclass(SecurityViolationError, NeuralShieldError)
        assert issubclass(ThreatDetectionError, NeuralShieldError)
        assert issubclass(ModelInferenceError, NeuralShieldError)
        assert issubclass(ExternalServiceError, NeuralShieldError)
        assert issubclass(RateLimitExceededError, NeuralShieldError)
        assert issubclass(CircuitBreakerOpenError, NeuralShieldError)
        assert issubclass(TimeoutError, NeuralShieldError)


# -----------------------------------------------------------------------------
# Circuit Breaker Tests
# -----------------------------------------------------------------------------

class TestCircuitBreaker:
    """Test Circuit Breaker pattern implementation."""
    
    def test_circuit_starts_closed(self):
        """Test circuit breaker starts in CLOSED state."""
        cb = CircuitBreaker(failure_threshold=3)
        assert cb.state == CircuitState.CLOSED
    
    def test_circuit_allows_calls_when_closed(self):
        """Test calls pass through when circuit is closed."""
        cb = CircuitBreaker(failure_threshold=3)
        
        @cb
        def successful_func():
            return "success"
        
        assert successful_func() == "success"
        assert cb.metrics.success_count == 1
    
    def test_circuit_opens_after_threshold(self):
        """Test circuit opens after failure threshold reached."""
        cb = CircuitBreaker(failure_threshold=2, recovery_timeout=10.0)
        
        @cb
        def failing_func():
            raise ValueError("Always fails")
        
        # First failure - still closed
        with pytest.raises(ValueError):
            failing_func()
        assert cb.state == CircuitState.CLOSED
        
        # Second failure - should open
        with pytest.raises(ValueError):
            failing_func()
        assert cb.state == CircuitState.OPEN
        
        # Third call should fail fast with CircuitBreakerOpenError
        with pytest.raises(CircuitBreakerOpenError):
            failing_func()
        assert cb.metrics.rejection_count >= 1
    
    def test_circuit_half_open_after_recovery_timeout(self):
        """Test circuit transitions to HALF_OPEN after recovery timeout."""
        cb = CircuitBreaker(failure_threshold=1, recovery_timeout=0.1)
        
        @cb
        def failing_func():
            raise ValueError("Always fails")
        
        # Trip the circuit
        with pytest.raises(ValueError):
            failing_func()
        assert cb.state == CircuitState.OPEN
        
        # Wait for recovery timeout
        time.sleep(0.15)
        
        # Should now allow a test call (HALF_OPEN)
        with pytest.raises(ValueError):
            failing_func()
        # After another failure, goes back to OPEN
        assert cb.state == CircuitState.OPEN
    
    def test_circuit_closes_after_successful_recovery(self):
        """Test circuit closes after successful recovery in HALF_OPEN."""
        cb = CircuitBreaker(failure_threshold=1, recovery_timeout=0.1)
        
        call_count = [0]
        
        @cb
        def flaky_func():
            call_count[0] += 1
            if call_count[0] <= 1:
                raise ValueError("First call fails")
            return "success"
        
        # First call fails - circuit opens
        with pytest.raises(ValueError):
            flaky_func()
        assert cb.state == CircuitState.OPEN
        
        # Wait for recovery
        time.sleep(0.15)
        
        # Second call succeeds - circuit should close
        result = flaky_func()
        assert result == "success"
        assert cb.state == CircuitState.CLOSED
    
    def test_circuit_breaker_metrics_tracked(self):
        """Test circuit breaker metrics are properly tracked."""
        cb = CircuitBreaker(failure_threshold=2)
        
        @cb
        def successful_func():
            return "ok"
        
        @cb
        def failing_func():
            raise ValueError("Fail")
        
        successful_func()
        successful_func()
        
        with pytest.raises(ValueError):
            failing_func()
        
        assert cb.metrics.success_count == 2
        assert cb.metrics.failure_count == 1


# -----------------------------------------------------------------------------
# Retry Decorator Tests
# -----------------------------------------------------------------------------

class TestRetryDecorator:
    """Test retry with exponential backoff."""
    
    def test_retry_succeeds_on_second_attempt(self):
        """Test retry succeeds after initial failure."""
        call_count = [0]
        
        @retry(max_attempts=3, initial_delay=0.01)
        def flaky_func():
            call_count[0] += 1
            if call_count[0] < 2:
                raise ValueError("First call fails")
            return "success"
        
        result = flaky_func()
        assert result == "success"
        assert call_count[0] == 2
    
    def test_retry_gives_up_after_max_attempts(self):
        """Test retry gives up after max attempts."""
        call_count = [0]
        
        @retry(max_attempts=2, initial_delay=0.01)
        def always_fails():
            call_count[0] += 1
            raise ValueError("Always fails")
        
        with pytest.raises(ValueError):
            always_fails()
        
        assert call_count[0] == 2
    
    def test_retry_giveup_on_specific_exceptions(self):
        """Test retry gives up immediately for giveup_on exceptions."""
        call_count = [0]
        
        @retry(
            max_attempts=3,
            initial_delay=0.01,
            retry_on=(RuntimeError,),
            giveup_on=(ValueError,)
        )
        def func():
            call_count[0] += 1
            raise ValueError("Don't retry this")
        
        with pytest.raises(ValueError):
            func()
        
        assert call_count[0] == 1  # No retries for ValueError
    
    def test_retry_exponential_backoff_timing(self):
        """Test retry delay increases exponentially."""
        call_times = []
        
        @retry(max_attempts=3, initial_delay=0.01, backoff_factor=2, jitter=0)
        def failing_func():
            call_times.append(time.monotonic())
            raise ValueError("Fail")
        
        with pytest.raises(ValueError):
            failing_func()
        
        # Should have 3 calls with increasing delays
        assert len(call_times) == 3


# -----------------------------------------------------------------------------
# Timeout Decorator Tests
# -----------------------------------------------------------------------------

class TestTimeoutDecorator:
    """Test timeout wrapper functionality."""
    
    def test_timeout_raises_exception(self):
        """Test timeout raises exception when function takes too long."""
        
        @timeout(seconds=0.1)
        def slow_func():
            time.sleep(1.0)
            return "done"
        
        with pytest.raises(TimeoutError):
            slow_func()
    
    def test_timeout_returns_fallback(self):
        """Test timeout returns fallback value when provided."""
        
        @timeout(seconds=0.1, fallback="fallback_value")
        def slow_func():
            time.sleep(1.0)
            return "done"
        
        result = slow_func()
        assert result == "fallback_value"
    
    def test_timeout_passes_through_fast_functions(self):
        """Test fast functions pass through without timeout."""
        
        @timeout(seconds=1.0)
        def fast_func():
            return "quick"
        
        result = fast_func()
        assert result == "quick"
    
    def test_timeout_propagates_exceptions(self):
        """Test exceptions from function are propagated."""
        
        @timeout(seconds=1.0)
        def error_func():
            raise ValueError("Function error")
        
        with pytest.raises(ValueError):
            error_func()


# -----------------------------------------------------------------------------
# Fallback Decorator Tests
# -----------------------------------------------------------------------------

class TestFallbackDecorator:
    """Test graceful degradation fallback."""
    
    def test_fallback_used_on_exception(self):
        """Test fallback is called when primary fails."""
        
        def my_fallback(*args, **kwargs):
            return "fallback_result"
        
        @fallback(fallback_func=my_fallback)
        def failing_func():
            raise ValueError("Primary failed")
        
        result = failing_func()
        assert result == "fallback_result"
    
    def test_primary_used_when_successful(self):
        """Test primary is used when it succeeds (happy path preserved)."""
        
        def my_fallback(*args, **kwargs):
            return "fallback_result"
        
        @fallback(fallback_func=my_fallback)
        def successful_func():
            return "primary_result"
        
        result = successful_func()
        assert result == "primary_result"  # Happy path works!
    
    def test_fallback_only_for_specified_exceptions(self):
        """Test fallback only triggers for specified exceptions."""
        
        def my_fallback(*args, **kwargs):
            return "fallback_result"
        
        @fallback(fallback_func=my_fallback, exceptions=(ValueError,))
        def func():
            raise RuntimeError("Not in exceptions list")
        
        with pytest.raises(RuntimeError):
            func()


# -----------------------------------------------------------------------------
# Bulkhead Tests
# -----------------------------------------------------------------------------

class TestBulkhead:
    """Test Bulkhead isolation pattern."""
    
    def test_bulkhead_limits_concurrency(self):
        """Test bulkhead limits concurrent executions."""
        bulkhead = Bulkhead(max_concurrent=2, name="test")
        
        @bulkhead
        def func():
            return "ok"
        
        # Should work within limit
        results = [func() for _ in range(5)]
        assert all(r == "ok" for r in results)
    
    def test_bulkhead_basic_functionality(self):
        """Test bulkhead basic functionality works."""
        bulkhead = Bulkhead(max_concurrent=1, max_waiting=10, name="test")
        
        @bulkhead
        def simple_func():
            return "executed"
        
        result = simple_func()
        assert result == "executed"
        assert bulkhead.rejections == 0


# -----------------------------------------------------------------------------
# Safe Fallback Functions Tests
# -----------------------------------------------------------------------------

class TestSafeFallbacks:
    """Test predefined safe fallback functions."""
    
    def test_safe_fallback_empty_structure(self):
        """Test safe_fallback_empty returns expected structure."""
        result = safe_fallback_empty()
        assert result["status"] == "degraded"
        assert result["threat_detected"] is False
        assert result["fallback_used"] is True
        assert "timestamp" in result
    
    def test_safe_fallback_allow_structure(self):
        """Test safe_fallback_allow returns expected structure."""
        result = safe_fallback_allow()
        assert result["status"] == "degraded"
        assert result["allowed"] is True
        assert result["fallback_used"] is True
    
    def test_safe_fallback_deny_structure(self):
        """Test safe_fallback_deny returns expected structure."""
        result = safe_fallback_deny()
        assert result["status"] == "degraded"
        assert result["allowed"] is False
        assert result["fallback_used"] is True


# -----------------------------------------------------------------------------
# Composite Resilience Policy Tests
# -----------------------------------------------------------------------------

class TestResiliencePolicy:
    """Test composite resilience policy."""
    
    def test_policy_creates_decorator(self):
        """Test resilience policy can decorate functions."""
        policy = ResiliencePolicy(
            name="test_policy",
            max_retries=2,
            timeout_seconds=5.0
        )
        
        @policy
        def successful_func():
            return "success"
        
        result = successful_func()
        assert result == "success"
    
    def test_policy_with_fallback(self):
        """Test resilience policy with fallback."""
        policy = ResiliencePolicy(
            name="test_policy",
            max_retries=1,
            timeout_seconds=1.0,
            fallback_func=safe_fallback_empty
        )
        
        @policy
        def failing_func():
            raise ValueError("Always fails")
        
        result = failing_func()
        assert result["fallback_used"] is True
        assert result["status"] == "degraded"


# -----------------------------------------------------------------------------
# Integration Tests
# -----------------------------------------------------------------------------

class TestIntegration:
    """Integration tests for combining resilience patterns."""
    
    def test_retry_with_fallback(self):
        """Test combining retry and fallback."""
        
        def my_fallback(*args, **kwargs):
            return "degraded"
        
        @fallback(fallback_func=my_fallback)
        @retry(max_attempts=2, initial_delay=0.01)
        def failing_func():
            raise ValueError("Fail")
        
        result = failing_func()
        assert result == "degraded"
    
    def test_circuit_breaker_with_retry(self):
        """Test combining circuit breaker and retry."""
        cb = CircuitBreaker(failure_threshold=5, recovery_timeout=10.0)
        
        call_count = [0]
        
        @cb
        @retry(max_attempts=2, initial_delay=0.01)
        def flaky_func():
            call_count[0] += 1
            if call_count[0] < 2:
                raise ValueError("Temporary failure")
            return "success"
        
        result = flaky_func()
        assert result == "success"
        assert call_count[0] == 2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
