"""
Tests for NeuralShield Error Resilience Framework v13 - June 22, 2026

Covers:
- Custom exception hierarchies
- Retry decorators (sync + async)
- Timeout decorators (sync + async)
- Circuit breaker pattern
- Graceful degradation
- Bulkhead pattern
- Safe executor
"""

import pytest
import asyncio
import time
import threading
from neural_shield.error_resilience_comprehensive_v13_2026_june import (
    # Exceptions
    NeuralShieldError,
    SecurityError,
    ThreatDetectionError,
    ValidationError,
    TimeoutError,
    CircuitBreakerOpenError,
    ResourceExhaustedError,
    
    # Strategies
    RetryStrategy,
    CircuitState,
    
    # Configs
    RetryConfig,
    CircuitBreakerConfig,
    FallbackStrategy,
    
    # Decorators
    retry,
    async_retry,
    timeout,
    async_timeout,
    graceful_degradation,
    
    # Classes
    CircuitBreaker,
    Bulkhead,
    SafeExecutor,
    
    # Utilities
    calculate_backoff,
    create_robust_executor,
)


# ============================================================================
# EXCEPTION HIERARCHY TESTS
# ============================================================================

class TestExceptionHierarchy:
    def test_base_exception_attributes(self):
        err = NeuralShieldError("test message", "TEST_CODE", {"key": "value"})
        assert err.message == "test message"
        assert err.code == "TEST_CODE"
        assert err.details == {"key": "value"}
        assert hasattr(err, 'timestamp')
    
    def test_exception_inheritance(self):
        assert issubclass(SecurityError, NeuralShieldError)
        assert issubclass(ThreatDetectionError, SecurityError)
        assert issubclass(ValidationError, NeuralShieldError)
        assert issubclass(TimeoutError, NeuralShieldError)


# ============================================================================
# BACKOFF CALCULATION TESTS
# ============================================================================

class TestBackoffCalculation:
    def test_exponential_backoff(self):
        config = RetryConfig(
            initial_delay=0.1,
            max_delay=10.0,
            strategy=RetryStrategy.EXPONENTIAL,
            jitter=False
        )
        assert calculate_backoff(0, config) == pytest.approx(0.1)
        assert calculate_backoff(1, config) == pytest.approx(0.2)
        assert calculate_backoff(2, config) == pytest.approx(0.4)
    
    def test_linear_backoff(self):
        config = RetryConfig(
            initial_delay=0.1,
            strategy=RetryStrategy.LINEAR,
            jitter=False
        )
        assert calculate_backoff(0, config) == pytest.approx(0.1)
        assert calculate_backoff(1, config) == pytest.approx(0.2)
    
    def test_max_delay_cap(self):
        config = RetryConfig(
            initial_delay=1.0,
            max_delay=2.0,
            strategy=RetryStrategy.EXPONENTIAL,
            jitter=False
        )
        assert calculate_backoff(5, config) <= 2.0
    
    def test_jitter_adds_randomness(self):
        config = RetryConfig(
            initial_delay=1.0,
            strategy=RetryStrategy.EXPONENTIAL,
            jitter=True
        )
        delays = [calculate_backoff(0, config) for _ in range(10)]
        assert len(set(delays)) > 1


# ============================================================================
# RETRY DECORATOR TESTS
# ============================================================================

class TestRetryDecorator:
    def test_retry_succeeds_on_second_attempt(self):
        call_count = [0]
        
        @retry(RetryConfig(max_attempts=3))
        def flaky_function():
            call_count[0] += 1
            if call_count[0] < 2:
                raise ValueError("temporary error")
            return "success"
        
        result = flaky_function()
        assert result == "success"
        assert call_count[0] == 2
    
    def test_retry_exhausted_raises(self):
        call_count = [0]
        
        @retry(RetryConfig(max_attempts=2))
        def always_fails():
            call_count[0] += 1
            raise ValueError("permanent error")
        
        with pytest.raises(ValueError):
            always_fails()
        assert call_count[0] == 2
    
    def test_retry_with_fallback_value(self):
        @retry(RetryConfig(max_attempts=2, fallback_value="default"))
        def always_fails():
            raise ValueError("error")
        
        result = always_fails()
        assert result == "default"


# ============================================================================
# TIMEOUT DECORATOR TESTS
# ============================================================================

class TestTimeoutDecorator:
    def test_timeout_completes_normally(self):
        @timeout(1.0)
        def quick_function():
            return "done"
        
        result = quick_function()
        assert result == "done"
    
    def test_timeout_triggers(self):
        @timeout(0.1)
        def slow_function():
            time.sleep(1.0)
            return "done"
        
        with pytest.raises(TimeoutError):
            slow_function()
    
    def test_timeout_with_fallback(self):
        @timeout(0.1, fallback="default")
        def slow_function():
            time.sleep(1.0)
            return "done"
        
        result = slow_function()
        assert result == "default"


# ============================================================================
# CIRCUIT BREAKER TESTS
# ============================================================================

class TestCircuitBreaker:
    def test_circuit_starts_closed(self):
        cb = CircuitBreaker()
        assert cb.state == CircuitState.CLOSED
    
    def test_circuit_trips_after_failures(self):
        cb = CircuitBreaker(CircuitBreakerConfig(failure_threshold=2))
        
        cb.record_failure()
        cb.record_failure()
        
        assert cb.state == CircuitState.OPEN
        assert not cb.can_execute()
    
    def test_circuit_recovers_after_timeout(self):
        cb = CircuitBreaker(CircuitBreakerConfig(
            failure_threshold=2,
            recovery_timeout=0.1
        ))
        
        cb.record_failure()
        cb.record_failure()
        assert cb.state == CircuitState.OPEN
        
        time.sleep(0.15)
        assert cb.state == CircuitState.HALF_OPEN
    
    def test_circuit_closes_after_success_in_half_open(self):
        cb = CircuitBreaker(CircuitBreakerConfig(
            failure_threshold=2,
            recovery_timeout=0.1,
            half_open_max_calls=1
        ))
        
        # Trip and wait for half-open
        cb.record_failure()
        cb.record_failure()
        time.sleep(0.15)
        
        # Access state first to trigger transition check
        _ = cb.state
        
        # Success in half-open should close
        cb.record_success()
        
        # Access state again to trigger check
        assert cb.state == CircuitState.CLOSED
    
    def test_circuit_breaker_decorator(self):
        cb = CircuitBreaker(CircuitBreakerConfig(failure_threshold=2))
        call_count = [0]
        
        @cb(fallback="safe_value")
        def protected_func():
            call_count[0] += 1
            if call_count[0] <= 2:
                raise ValueError("error")
            return "success"
        
        with pytest.raises(ValueError):
            protected_func()
        with pytest.raises(ValueError):
            protected_func()
        
        result = protected_func()
        assert result == "safe_value"


# ============================================================================
# GRACEFUL DEGRADATION TESTS
# ============================================================================

class TestGracefulDegradation:
    def test_primary_succeeds(self):
        def fallback1():
            return "fallback1"
        
        @graceful_degradation(FallbackStrategy(
            primary=lambda: "primary",
            fallbacks=[(fallback1, None)],
            default_value="default"
        ))
        def my_func():
            return "primary_result"
        
        result = my_func()
        assert result == "primary_result"
    
    def test_uses_fallback_when_primary_fails(self):
        def fallback():
            return "fallback_result"
        
        @graceful_degradation(FallbackStrategy(
            primary=lambda: (_ for _ in ()).throw(ValueError()),
            fallbacks=[(fallback, None)],
        ))
        def my_func():
            raise ValueError("primary failed")
        
        result = my_func()
        assert result == "fallback_result"
    
    def test_uses_default_when_all_fail(self):
        @graceful_degradation(FallbackStrategy(
            primary=lambda: (_ for _ in ()).throw(ValueError()),
            fallbacks=[(lambda: (_ for _ in ()).throw(ValueError()), None)],
            default_value="ultimate_fallback"
        ))
        def my_func():
            raise ValueError("always fails")
        
        result = my_func()
        assert result == "ultimate_fallback"


# ============================================================================
# BULKHEAD TESTS
# ============================================================================

class TestBulkhead:
    def test_bulkhead_limits_concurrency(self):
        bulkhead = Bulkhead(max_concurrent=2)
        assert bulkhead.max_concurrent == 2
        
        @bulkhead(timeout=0.1)
        def limited_func():
            return "ok"
        
        result = limited_func()
        assert result == "ok"
    
    def test_bulkhead_with_fallback(self):
        bulkhead = Bulkhead(max_concurrent=1)
        
        @bulkhead(timeout=0.01, fallback="degraded")
        def limited_func():
            time.sleep(0.1)
            return "ok"
        
        t = threading.Thread(target=limited_func)
        t.start()
        time.sleep(0.005)
        
        result = limited_func()
        assert result == "degraded"
        
        t.join()


# ============================================================================
# SAFE EXECUTOR TESTS
# ============================================================================

class TestSafeExecutor:
    def test_safe_executor_success(self):
        def good_func():
            return 42
        
        result = SafeExecutor.execute(good_func)
        assert result.success is True
        assert result.value == 42
        assert result.error is None
        assert result.execution_time >= 0
    
    def test_safe_executor_failure(self):
        def bad_func():
            raise ValueError("test error")
        
        result = SafeExecutor.execute(bad_func)
        assert result.success is False
        assert result.value is None
        assert isinstance(result.error, ValueError)
        assert result.execution_time >= 0


# ============================================================================
# FACTORY METHOD TESTS
# ============================================================================

class TestFactoryMethods:
    def test_create_robust_executor(self):
        cb, bh = create_robust_executor(
            max_retries=3,
            timeout_seconds=5.0,
            circuit_failure_threshold=5,
            bulkhead_capacity=10,
            name="test"
        )
        assert isinstance(cb, CircuitBreaker)
        assert isinstance(bh, Bulkhead)
        assert cb.name == "test"
        assert bh.name == "test"


# ============================================================================
# INTEGRATION TESTS
# ============================================================================

class TestIntegration:
    def test_multiple_decorators_stack(self):
        call_count = [0]
        
        @retry(RetryConfig(max_attempts=3))
        @timeout(1.0)
        def robust_function():
            call_count[0] += 1
            if call_count[0] < 2:
                raise ValueError("temporary")
            return "success"
        
        result = robust_function()
        assert result == "success"
        assert call_count[0] == 2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
