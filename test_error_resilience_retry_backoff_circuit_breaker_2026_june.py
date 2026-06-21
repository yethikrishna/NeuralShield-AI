"""
Tests for Error Resilience Module - Dimension E
Retry, Backoff, Circuit Breaker, Timeout, and Bulkhead Patterns
"""

import pytest
import time
import threading
from unittest.mock import MagicMock, patch

from neural_shield.error_resilience_retry_backoff_circuit_breaker_2026_june import (
    ExponentialBackoff,
    CircuitBreaker,
    CircuitState,
    CircuitBreakerConfig,
    RetryConfig,
    Bulkhead,
    FallbackChain,
    with_retry,
    with_timeout,
    with_circuit_breaker,
    with_graceful_degradation,
    with_bulkhead,
    get_circuit_breaker,
    get_bulkhead,
    get_all_resilience_metrics,
    MaxRetriesExceededError,
    CircuitBreakerError,
    TimeoutError,
    FallbackNotAvailableError,
    ResilienceError,
)


class TestExponentialBackoff:
    """Tests for exponential backoff strategy."""
    
    def test_initial_delay(self):
        backoff = ExponentialBackoff(initial_delay=0.1)
        delay = backoff.calculate_delay(0)
        assert 0.05 <= delay <= 0.15  # With jitter
    
    def test_no_jitter(self):
        backoff = ExponentialBackoff(initial_delay=0.1, jitter=False)
        delay = backoff.calculate_delay(0)
        assert delay == 0.1
    
    def test_exponential_growth(self):
        backoff = ExponentialBackoff(initial_delay=0.1, factor=2.0, jitter=False)
        assert backoff.calculate_delay(0) == 0.1
        assert backoff.calculate_delay(1) == 0.2
        assert backoff.calculate_delay(2) == 0.4
    
    def test_max_delay(self):
        backoff = ExponentialBackoff(initial_delay=0.1, max_delay=0.5, jitter=False)
        assert backoff.calculate_delay(10) == 0.5


class TestCircuitBreaker:
    """Tests for circuit breaker pattern."""
    
    def test_initial_state_closed(self):
        cb = CircuitBreaker()
        assert cb.get_state() == CircuitState.CLOSED
        assert cb.allow_request() is True
    
    def test_transition_to_open_after_failures(self):
        config = CircuitBreakerConfig(failure_threshold=3)
        cb = CircuitBreaker(config)
        
        # Record failures
        cb.record_failure()
        cb.record_failure()
        assert cb.get_state() == CircuitState.CLOSED
        assert cb.allow_request() is True
        
        cb.record_failure()
        assert cb.get_state() == CircuitState.OPEN
        assert cb.allow_request() is False
    
    def test_open_state_rejects_requests(self):
        config = CircuitBreakerConfig(failure_threshold=1, recovery_timeout=10.0)
        cb = CircuitBreaker(config)
        cb.record_failure()
        
        assert cb.allow_request() is False
    
    def test_half_open_after_recovery_timeout(self):
        config = CircuitBreakerConfig(failure_threshold=1, recovery_timeout=0.1)
        cb = CircuitBreaker(config)
        cb.record_failure()
        
        assert cb.get_state() == CircuitState.OPEN
        
        # Wait for recovery timeout
        time.sleep(0.15)
        
        assert cb.get_state() == CircuitState.HALF_OPEN
        assert cb.allow_request() is True
    
    def test_half_open_limited_calls(self):
        config = CircuitBreakerConfig(
            failure_threshold=1,
            recovery_timeout=0.1,
            half_open_max_calls=2
        )
        cb = CircuitBreaker(config)
        cb.record_failure()
        time.sleep(0.15)  # Transition to half-open
        
        assert cb.allow_request() is True
        assert cb.allow_request() is True
        assert cb.allow_request() is False  # Exceeded half-open limit
    
    def test_success_closes_circuit_from_half_open(self):
        config = CircuitBreakerConfig(
            failure_threshold=1,
            recovery_timeout=0.1,
            success_threshold=1
        )
        cb = CircuitBreaker(config)
        cb.record_failure()
        time.sleep(0.15)
        
        # First allow a request to trigger state transition to half-open
        cb.allow_request()
        # Multiple successes needed to close
        cb.record_success()
        cb.record_success()
        assert cb.get_state() == CircuitState.CLOSED
    
    def test_failure_reopens_from_half_open(self):
        config = CircuitBreakerConfig(failure_threshold=1, recovery_timeout=0.1)
        cb = CircuitBreaker(config)
        cb.record_failure()
        time.sleep(0.15)
        
        # First allow a request to transition state check
        cb.allow_request()
        cb.record_failure()
        assert cb.get_state() == CircuitState.OPEN
    
    def test_get_metrics(self):
        cb = CircuitBreaker()
        metrics = cb.get_metrics()
        assert "state" in metrics
        assert "failure_count" in metrics
        assert "success_count" in metrics


class TestRetryDecorator:
    """Tests for @with_retry decorator."""
    
    def test_succeeds_on_first_try(self):
        call_count = [0]
        
        @with_retry()
        def succeed():
            call_count[0] += 1
            return "success"
        
        result = succeed()
        assert result == "success"
        assert call_count[0] == 1
    
    def test_retries_on_failure(self):
        call_count = [0]
        
        @with_retry(config=RetryConfig(max_attempts=3))
        def flaky():
            call_count[0] += 1
            if call_count[0] < 3:
                raise ValueError("temporary error")
            return "success"
        
        result = flaky()
        assert result == "success"
        assert call_count[0] == 3
    
    def test_max_retries_exceeded(self):
        call_count = [0]
        
        @with_retry(config=RetryConfig(max_attempts=2))
        def always_fails():
            call_count[0] += 1
            raise ValueError("permanent error")
        
        with pytest.raises(MaxRetriesExceededError):
            always_fails()
        
        assert call_count[0] == 2
    
    def test_stop_on_exceptions(self):
        call_count = [0]
        
        class PermanentError(Exception):
            pass
        
        @with_retry(config=RetryConfig(
            max_attempts=3,
            stop_on_exceptions=(PermanentError,)
        ))
        def fails_permanently():
            call_count[0] += 1
            raise PermanentError("stop")
        
        with pytest.raises(PermanentError):
            fails_permanently()
        
        assert call_count[0] == 1  # No retries for permanent errors


class TestTimeoutDecorator:
    """Tests for @with_timeout decorator."""
    
    def test_completes_before_timeout(self):
        @with_timeout(1.0)
        def fast():
            return "done"
        
        result = fast()
        assert result == "done"
    
    def test_times_out(self):
        @with_timeout(0.1)
        def slow():
            time.sleep(1.0)
            return "done"
        
        with pytest.raises(TimeoutError):
            slow()
    
    def test_timeout_with_fallback(self):
        def fallback():
            return "fallback"
        
        @with_timeout(0.1, fallback=fallback)
        def slow():
            time.sleep(1.0)
            return "done"
        
        result = slow()
        assert result == "fallback"


class TestCircuitBreakerDecorator:
    """Tests for @with_circuit_breaker decorator."""
    
    def test_circuit_allows_when_closed(self):
        cb = CircuitBreaker()
        
        @with_circuit_breaker(cb)
        def service():
            return "ok"
        
        result = service()
        assert result == "ok"
    
    def test_circuit_rejects_when_open(self):
        config = CircuitBreakerConfig(failure_threshold=1)
        cb = CircuitBreaker(config)
        cb.record_failure()
        
        @with_circuit_breaker(cb)
        def service():
            return "ok"
        
        with pytest.raises(CircuitBreakerError):
            service()
    
    def test_circuit_open_with_fallback(self):
        config = CircuitBreakerConfig(failure_threshold=1)
        cb = CircuitBreaker(config)
        cb.record_failure()
        
        def fallback():
            return "degraded"
        
        @with_circuit_breaker(cb, fallback=fallback)
        def service():
            return "ok"
        
        result = service()
        assert result == "degraded"


class TestGracefulDegradation:
    """Tests for @with_graceful_degradation decorator."""
    
    def test_uses_primary_when_working(self):
        def fallback():
            return "fallback"
        
        @with_graceful_degradation(fallback)
        def primary():
            return "primary"
        
        result = primary()
        assert result == "primary"
    
    def test_uses_fallback_on_failure(self):
        def fallback():
            return "fallback"
        
        @with_graceful_degradation(fallback)
        def primary():
            raise ValueError("error")
        
        result = primary()
        assert result == "fallback"


class TestBulkhead:
    """Tests for bulkhead pattern."""
    
    def test_acquire_release(self):
        bh = Bulkhead(max_concurrent=2)
        
        assert bh.acquire() is True
        assert bh.acquire() is True
        bh.release()
        assert bh.acquire() is True
    
    def test_bulkhead_limits_concurrency(self):
        bh = Bulkhead(max_concurrent=1)
        
        assert bh.acquire() is True
        assert bh.acquire(timeout=0.01) is False  # Would block
        bh.release()
    
    def test_bulkhead_metrics(self):
        bh = Bulkhead(max_concurrent=5)
        bh.acquire()
        bh.acquire()
        
        metrics = bh.get_metrics()
        assert metrics["max_concurrent"] == 5
        assert metrics["active_count"] == 2
        assert metrics["available"] == 3


class TestBulkheadDecorator:
    """Tests for @with_bulkhead decorator."""
    
    def test_bulkhead_allows(self):
        bh = Bulkhead(max_concurrent=10)
        
        @with_bulkhead(bh)
        def operation():
            return "ok"
        
        result = operation()
        assert result == "ok"
    
    def test_bulkhead_rejects_when_full(self):
        bh = Bulkhead(max_concurrent=1)
        bh.acquire()  # Take the only slot
        
        @with_bulkhead(bh, timeout=0.01)
        def operation():
            return "ok"
        
        with pytest.raises(ResilienceError):
            operation()
        
        bh.release()


class TestFallbackChain:
    """Tests for FallbackChain."""
    
    def test_primary_succeeds(self):
        primary = lambda: "primary"
        fallback1 = lambda: "fallback1"
        
        chain = FallbackChain(primary, fallback1)
        result = chain()
        assert result == "primary"
    
    def test_fallback_succeeds(self):
        primary = lambda: (_ for _ in ()).throw(ValueError("fail"))
        fallback1 = lambda: "fallback1"
        
        chain = FallbackChain(primary, fallback1)
        result = chain()
        assert result == "fallback1"
    
    def test_chain_fallbacks(self):
        primary = lambda: (_ for _ in ()).throw(ValueError("fail"))
        fallback1 = lambda: (_ for _ in ()).throw(ValueError("fail"))
        fallback2 = lambda: "fallback2"
        
        chain = FallbackChain(primary, fallback1, fallback2)
        result = chain()
        assert result == "fallback2"
    
    def test_all_fallbacks_fail(self):
        primary = lambda: (_ for _ in ()).throw(ValueError("fail"))
        fallback1 = lambda: (_ for _ in ()).throw(ValueError("fail"))
        
        chain = FallbackChain(primary, fallback1)
        with pytest.raises(FallbackNotAvailableError):
            chain()


class TestSharedInstances:
    """Tests for shared resilience components."""
    
    def test_get_circuit_breaker(self):
        cb1 = get_circuit_breaker("test_cb")
        cb2 = get_circuit_breaker("test_cb")
        assert cb1 is cb2
    
    def test_get_bulkhead(self):
        bh1 = get_bulkhead("test_bh")
        bh2 = get_bulkhead("test_bh")
        assert bh1 is bh2
    
    def test_get_all_metrics(self):
        # Create some shared instances
        get_circuit_breaker("metrics_test")
        get_bulkhead("metrics_test")
        
        metrics = get_all_resilience_metrics()
        assert "circuit_breakers" in metrics
        assert "bulkheads" in metrics


class TestIntegration:
    """Integration tests combining multiple resilience patterns."""
    
    def test_retry_with_circuit_breaker(self):
        """Test retry and circuit breaker working together."""
        call_count = [0]
        cb = CircuitBreaker(CircuitBreakerConfig(failure_threshold=5))
        
        @with_circuit_breaker(cb)
        @with_retry(config=RetryConfig(max_attempts=3))
        def flaky_service():
            call_count[0] += 1
            if call_count[0] < 3:
                raise ValueError("temporary error")
            return "success"
        
        result = flaky_service()
        assert result == "success"
    
    def test_all_patterns_together(self):
        """Test full resilience stack."""
        cb = CircuitBreaker()
        bh = Bulkhead(max_concurrent=10)
        
        def fallback():
            return "degraded_mode"
        
        @with_bulkhead(bh)
        @with_circuit_breaker(cb, fallback=fallback)
        @with_timeout(1.0)
        @with_retry()
        def robust_service():
            return "all_good"
        
        result = robust_service()
        assert result == "all_good"


def test_module_imports():
    """Test all public exports are available."""
    from neural_shield import error_resilience_retry_backoff_circuit_breaker_2026_june
    
    assert hasattr(error_resilience_retry_backoff_circuit_breaker_2026_june, "CircuitBreaker")
    assert hasattr(error_resilience_retry_backoff_circuit_breaker_2026_june, "with_retry")
    assert hasattr(error_resilience_retry_backoff_circuit_breaker_2026_june, "with_timeout")
    assert hasattr(error_resilience_retry_backoff_circuit_breaker_2026_june, "Bulkhead")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
