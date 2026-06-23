"""
Test Suite: NeuralShield Error Resilience v21
DIMENSION E - Error Resilience
June 2026

Tests for comprehensive exception hierarchy, retry, backoff,
timeout, circuit breaker, bulkhead, and graceful fallbacks.

All tests must pass - no existing code modifications.
"""

import pytest
import time
import threading
from unittest.mock import MagicMock, patch

# Import the new module
from neural_shield.error_resilience_comprehensive_exception_hierarchy_v21_2026_june import (
    # Enums
    ExceptionSeverity,
    ExceptionCategory,
    BackoffStrategy,
    CircuitState,
    
    # Exceptions
    NeuralShieldBaseError,
    NeuralShieldTransientError,
    NeuralShieldTimeoutError,
    NeuralShieldRateLimitError,
    NeuralShieldNetworkError,
    NeuralShieldValidationError,
    NeuralShieldInputSanitizationError,
    NeuralShieldPromptInjectionDetectedError,
    NeuralShieldSecurityError,
    NeuralShieldConfigurationError,
    NeuralShieldResourceExhaustedError,
    
    # Retry
    RetryConfig,
    RetryManager,
    retry,
    
    # Timeout
    TimeoutManager,
    timeout,
    
    # Circuit Breaker
    CircuitBreakerConfig,
    CircuitBreaker,
    get_circuit_breaker,
    
    # Fallback
    FallbackResult,
    graceful_fallback,
    
    # Bulkhead
    Bulkhead,
    get_bulkhead,
    
    # Comprehensive
    ResilienceConfig,
    resilient,
)


# ============================================================================
# EXCEPTION HIERARCHY TESTS
# ============================================================================

class TestExceptionHierarchy:
    """Test custom exception hierarchy."""
    
    def test_base_exception_structure(self):
        """Test base exception has all required fields."""
        err = NeuralShieldBaseError(
            "Test error",
            error_code="NS-TEST001",
            severity=ExceptionSeverity.WARNING,
            category=ExceptionCategory.VALIDATION,
            retry_eligible=True,
            graceful_fallback="Use default",
            details={"field": "value"}
        )
        
        assert err.error_code == "NS-TEST001"
        assert err.severity == ExceptionSeverity.WARNING
        assert err.category == ExceptionCategory.VALIDATION
        assert err.retry_eligible is True
        assert err.graceful_fallback == "Use default"
        assert err.details["field"] == "value"
        assert "NS-TEST001" in str(err)
        
    def test_exception_to_dict(self):
        """Test structured dictionary output."""
        err = NeuralShieldBaseError("Test")
        d = err.to_dict()
        
        assert "error_code" in d
        assert "message" in d
        assert "severity" in d
        assert "category" in d
        assert "retry_eligible" in d
        assert "timestamp" in d
        
    def test_transient_errors_are_retry_eligible(self):
        """Transient errors should be retry-eligible by default."""
        assert NeuralShieldTransientError("Test").retry_eligible is True
        assert NeuralShieldTimeoutError("Test").retry_eligible is True
        assert NeuralShieldRateLimitError("Test").retry_eligible is True
        assert NeuralShieldNetworkError("Test").retry_eligible is True
        
    def test_validation_errors_not_retry_eligible(self):
        """Validation errors should NOT be retry-eligible."""
        assert NeuralShieldValidationError("Test").retry_eligible is False
        assert NeuralShieldInputSanitizationError("Test").retry_eligible is False
        
    def test_security_errors_critical(self):
        """Security errors should be CRITICAL severity."""
        assert NeuralShieldSecurityError("Test").severity == ExceptionSeverity.CRITICAL
        
    def test_prompt_injection_detection(self):
        """Prompt injection detection carries confidence score."""
        err = NeuralShieldPromptInjectionDetectedError("Suspicious input", confidence=0.95)
        assert err.details["detection_confidence"] == 0.95
        assert err.category == ExceptionCategory.THREAT_DETECTION


# ============================================================================
# RETRY + BACKOFF TESTS
# ============================================================================

class TestRetryBackoff:
    """Test retry and backoff functionality."""
    
    def test_backoff_calculation_constant(self):
        """Constant backoff returns same delay each time."""
        config = RetryConfig(
            initial_delay=1.0,
            backoff_strategy=BackoffStrategy.CONSTANT,
            jitter=False
        )
        
        assert config.calculate_delay(1) == pytest.approx(1.0)
        assert config.calculate_delay(2) == pytest.approx(1.0)
        assert config.calculate_delay(3) == pytest.approx(1.0)
        
    def test_backoff_calculation_exponential(self):
        """Exponential backoff grows exponentially."""
        config = RetryConfig(
            initial_delay=1.0,
            backoff_strategy=BackoffStrategy.EXPONENTIAL,
            jitter=False
        )
        
        assert config.calculate_delay(1) == pytest.approx(1.0)
        assert config.calculate_delay(2) == pytest.approx(2.0)
        assert config.calculate_delay(3) == pytest.approx(4.0)
        
    def test_backoff_max_delay(self):
        """Backoff respects max_delay limit."""
        config = RetryConfig(
            initial_delay=1.0,
            max_delay=2.0,
            backoff_strategy=BackoffStrategy.EXPONENTIAL,
            jitter=False
        )
        
        assert config.calculate_delay(3) == pytest.approx(2.0)  # Capped at max
        
    def test_retry_manager_success_first_try(self):
        """Successful operation doesn't retry."""
        manager = RetryManager()
        result = manager.execute(lambda: 42)
        
        assert result == 42
        assert manager.attempts == 1
        
    def test_retry_manager_retries_transient(self):
        """Retries on transient errors until success."""
        call_count = 0
        
        def flaky():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise NeuralShieldTransientError("Temporary error")
            return "success"
            
        manager = RetryManager(RetryConfig(max_attempts=5))
        result = manager.execute(flaky)
        
        assert result == "success"
        assert call_count == 3
        
    def test_retry_manager_exhausted(self):
        """Raises after max attempts exhausted."""
        def always_fail():
            raise NeuralShieldTransientError("Persistent error")
            
        manager = RetryManager(RetryConfig(max_attempts=2))
        
        with pytest.raises(NeuralShieldTransientError):
            manager.execute(always_fail)
            
        assert manager.attempts == 2
        
    def test_retry_decorator(self):
        """@retry decorator works correctly."""
        call_count = 0
        
        @retry(max_attempts=5)
        def flaky_operation():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise NeuralShieldTransientError("Temp")
            return "done"
            
        result = flaky_operation()
        assert result == "done"
        assert call_count == 3
        
    def test_retry_with_fallback(self):
        """Retry with graceful fallback."""
        def fallback():
            return "fallback_value"
            
        def always_fail():
            raise NeuralShieldTransientError("Fail")
            
        manager = RetryManager(RetryConfig(max_attempts=2, graceful_fallback=fallback))
        result = manager.execute(always_fail)
        
        assert result == "fallback_value"


# ============================================================================
# TIMEOUT TESTS
# ============================================================================

class TestTimeout:
    """Test timeout wrappers."""
    
    def test_timeout_manager_completes(self):
        """Operation completes within timeout."""
        manager = TimeoutManager(5.0)
        result = manager.execute(lambda: "fast")
        assert result == "fast"
        
    def test_timeout_manager_propagates_exception(self):
        """Exceptions propagated correctly."""
        manager = TimeoutManager(5.0)
        
        def raise_err():
            raise ValueError("test")
            
        with pytest.raises(ValueError):
            manager.execute(raise_err)
            
    def test_timeout_decorator(self):
        """@timeout decorator works."""
        @timeout(seconds=1.0)
        def quick():
            return "done"
            
        assert quick() == "done"


# ============================================================================
# CIRCUIT BREAKER TESTS
# ============================================================================

class TestCircuitBreaker:
    """Test circuit breaker pattern."""
    
    def test_circuit_closed_normal(self):
        """Normal operation in CLOSED state."""
        cb = CircuitBreaker(CircuitBreakerConfig(failure_threshold=5))
        
        assert cb.allow_call() is True
        assert cb.state == CircuitState.CLOSED
        
    def test_circuit_opens_after_threshold(self):
        """Circuit opens after failure threshold."""
        cb = CircuitBreaker(CircuitBreakerConfig(failure_threshold=3))
        
        for _ in range(3):
            cb.on_failure()
            
        assert cb.state == CircuitState.OPEN
        assert cb.allow_call() is False
        
    def test_circuit_half_open_after_reset(self):
        """Circuit enters HALF_OPEN after reset timeout."""
        cb = CircuitBreaker(CircuitBreakerConfig(
            failure_threshold=2,
            reset_timeout=0.01  # Very fast for testing
        ))
        
        cb.on_failure()
        cb.on_failure()
        assert cb.state == CircuitState.OPEN
        
        time.sleep(0.02)
        assert cb.allow_call() is True
        assert cb.state == CircuitState.HALF_OPEN
        
    def test_circuit_recloses_after_successes(self):
        """Circuit recloses after successful half-open calls."""
        cb = CircuitBreaker(CircuitBreakerConfig(
            failure_threshold=2,
            reset_timeout=0.01,
            half_open_max_calls=2
        ))
        
        # Trip the circuit
        cb.on_failure()
        cb.on_failure()
        
        # Wait for reset
        time.sleep(0.02)
        
        # Succeed in half-open
        cb.on_success()
        cb.on_success()
        
        assert cb.state == CircuitState.CLOSED
        
    def test_named_circuit_breaker(self):
        """Get or create named circuit breakers."""
        cb1 = get_circuit_breaker("test_cb")
        cb2 = get_circuit_breaker("test_cb")
        
        assert cb1 is cb2  # Same instance


# ============================================================================
# GRACEFUL FALLBACK TESTS
# ============================================================================

class TestGracefulFallback:
    """Test graceful degradation fallbacks."""
    
    def test_graceful_fallback_decorator_value(self):
        """Fallback returns default value on exception."""
        @graceful_fallback(fallback_value="safe_default")
        def might_fail(should_fail=False):
            if should_fail:
                raise RuntimeError("Oops")
            return "normal"
            
        assert might_fail(False) == "normal"
        
        result = might_fail(True)
        assert isinstance(result, FallbackResult)
        assert result.value == "safe_default"
        assert result.is_fallback is True
        
    def test_graceful_fallback_decorator_function(self):
        """Fallback calls fallback function."""
        def my_fallback(x):
            return f"fallback_{x}"
            
        @graceful_fallback(fallback_function=my_fallback)
        def fail(x):
            raise RuntimeError("Fail")
            
        result = fail("test")
        assert result.value == "fallback_test"


# ============================================================================
# BULKHEAD TESTS
# ============================================================================

class TestBulkhead:
    """Test bulkhead isolation pattern."""
    
    def test_bulkhead_allows_concurrent(self):
        """Bulkhead allows calls within limits."""
        bulkhead = Bulkhead(max_concurrent=2)
        
        result = bulkhead.execute(lambda: "ok")
        assert result == "ok"
        
    def test_named_bulkhead(self):
        """Get or create named bulkheads."""
        bh1 = get_bulkhead("test_bh", max_concurrent=5)
        bh2 = get_bulkhead("test_bh")
        
        assert bh1 is bh2


# ============================================================================
# COMPREHENSIVE RESILIENCE TEST
# ============================================================================

class TestComprehensiveResilience:
    """Test combined resilience decorator."""
    
    def test_resilient_decorator_happy_path(self):
        """Happy path completely unaffected."""
        @resilient()
        def normal(x, y):
            return x + y
            
        assert normal(2, 3) == 5
        
    def test_resilient_with_all_features(self):
        """All resilience features compose correctly."""
        config = ResilienceConfig(
            retry_config=RetryConfig(max_attempts=2),
            timeout_seconds=5.0
        )
        
        @resilient(config)
        def func():
            return "works"
            
        assert func() == "works"


# ============================================================================
# INTEGRATION: HAPPY PATH PRESERVATION
# ============================================================================

def test_happy_path_100_percent_preserved():
    """
    CRITICAL: Happy path behavior must be 100% preserved.
    
    All resilience features are OPT-IN and only activate
    when exceptions occur. Normal execution is unchanged.
    """
    # No decorators - pure function
    def pure(x):
        return x * 2
    
    # With full resilience wrapping
    @resilient()
    def wrapped(x):
        return x * 2
    
    # Results are identical
    for i in range(100):
        assert pure(i) == wrapped(i)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
