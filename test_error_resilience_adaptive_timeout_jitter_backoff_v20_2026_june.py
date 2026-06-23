"""
Test suite for NeuralShield Error Resilience v20
Adaptive Timeout with Jitter + Configurable Backoff Strategies

DIMENSION E - Error Resilience
Tests cover:
- Backoff calculator strategies (exponential, linear, fixed, fibonacci, jitter)
- Adaptive timeout with jitter
- Circuit breaker state machine
- Bulkhead resource isolation
- Retry decorator with fallback
- Timeout decorator
- Combined resilience decorator
- Orchestrator singleton pattern
- Exception hierarchies
"""

import pytest
import time
import threading
from unittest.mock import patch, MagicMock

from neural_shield.error_resilience_adaptive_timeout_jitter_backoff_v20_2026_june import (
    BackoffStrategy,
    CircuitState,
    ErrorResilienceError,
    TimeoutError,
    CircuitBreakerOpenError,
    MaxRetriesExceededError,
    BulkheadCapacityExceededError,
    RetryConfig,
    CircuitBreakerConfig,
    BulkheadConfig,
    TimeoutConfig,
    BackoffCalculator,
    AdaptiveTimeout,
    CircuitBreaker,
    Bulkhead,
    ErrorResilienceOrchestrator,
    with_retry,
    with_timeout,
    with_bulkhead,
    with_resilience,
)


class TestExceptionHierarchies:
    """Test custom exception hierarchy."""

    def test_base_exception(self):
        """Test base exception inheritance."""
        assert issubclass(TimeoutError, ErrorResilienceError)
        assert issubclass(CircuitBreakerOpenError, ErrorResilienceError)
        assert issubclass(MaxRetriesExceededError, ErrorResilienceError)
        assert issubclass(BulkheadCapacityExceededError, ErrorResilienceError)

    def test_exception_messages(self):
        """Test exception message formatting."""
        exc = MaxRetriesExceededError("Test message")
        assert "Test message" in str(exc)


class TestBackoffCalculator:
    """Test backoff calculation strategies."""

    def test_fixed_backoff(self):
        """Test fixed delay backoff strategy."""
        config = RetryConfig(
            strategy=BackoffStrategy.FIXED,
            initial_delay=0.5,
            max_delay=10.0
        )
        
        for attempt in range(1, 6):
            delay = BackoffCalculator.calculate(attempt, config)
            assert delay == 0.5

    def test_linear_backoff(self):
        """Test linear backoff strategy."""
        config = RetryConfig(
            strategy=BackoffStrategy.LINEAR,
            initial_delay=0.1,
            max_delay=10.0
        )
        
        assert BackoffCalculator.calculate(1, config) == pytest.approx(0.1)
        assert BackoffCalculator.calculate(2, config) == pytest.approx(0.2)
        assert BackoffCalculator.calculate(3, config) == pytest.approx(0.3)

    def test_exponential_backoff(self):
        """Test exponential backoff strategy."""
        config = RetryConfig(
            strategy=BackoffStrategy.EXPONENTIAL,
            initial_delay=0.1,
            backoff_multiplier=2.0,
            max_delay=10.0
        )
        
        assert BackoffCalculator.calculate(1, config) == pytest.approx(0.1)
        assert BackoffCalculator.calculate(2, config) == pytest.approx(0.2)
        assert BackoffCalculator.calculate(3, config) == pytest.approx(0.4)
        assert BackoffCalculator.calculate(4, config) == pytest.approx(0.8)

    def test_fibonacci_backoff(self):
        """Test fibonacci backoff strategy."""
        config = RetryConfig(
            strategy=BackoffStrategy.FIBONACCI,
            initial_delay=0.1,
            max_delay=10.0
        )
        
        # Fibonacci sequence: 0.1, 0.1, 0.2, 0.3, 0.5
        assert BackoffCalculator.calculate(1, config) == pytest.approx(0.1)
        assert BackoffCalculator.calculate(2, config) == pytest.approx(0.1)
        assert BackoffCalculator.calculate(3, config) == pytest.approx(0.2)
        assert BackoffCalculator.calculate(4, config) == pytest.approx(0.3)

    def test_exponential_with_jitter(self):
        """Test exponential backoff with jitter."""
        config = RetryConfig(
            strategy=BackoffStrategy.EXPONENTIAL_WITH_JITTER,
            initial_delay=0.1,
            jitter_factor=0.5,
            max_delay=10.0
        )
        
        delays = [BackoffCalculator.calculate(3, config) for _ in range(100)]
        # Verify jitter produces different values
        assert len(set(delays)) > 1
        # Verify within expected range
        base = 0.1 * (2 ** 2)  # 0.4
        for d in delays:
            assert base * 0.5 <= d <= base * 1.5

    def test_max_delay_clamping(self):
        """Test max delay enforcement."""
        config = RetryConfig(
            strategy=BackoffStrategy.EXPONENTIAL,
            initial_delay=1.0,
            max_delay=2.0
        )
        
        delay = BackoffCalculator.calculate(10, config)
        assert delay <= 2.0


class TestAdaptiveTimeout:
    """Test adaptive timeout with jitter."""

    def test_basic_timeout(self):
        """Test basic timeout without adaptation."""
        config = TimeoutConfig(timeout_seconds=5.0, adaptive=False)
        timeout = AdaptiveTimeout(config)
        
        assert timeout.get_timeout() == pytest.approx(5.0, rel=0.1)

    def test_timeout_with_jitter(self):
        """Test timeout with jitter applied."""
        config = TimeoutConfig(timeout_seconds=5.0, jitter_percentage=0.2, adaptive=False)
        timeout = AdaptiveTimeout(config)
        
        timeouts = [timeout.get_timeout() for _ in range(100)]
        # Verify jitter produces variation
        assert len(set(timeouts)) > 1
        for t in timeouts:
            assert 4.0 <= t <= 6.0

    def test_adaptive_timeout_learning(self):
        """Test adaptive timeout learns from history."""
        config = TimeoutConfig(timeout_seconds=10.0, adaptive=True, history_window=10)
        timeout = AdaptiveTimeout(config)
        
        # Record fast operations
        for _ in range(10):
            timeout.record_success(0.1)
        
        adaptive_value = timeout.get_timeout()
        # Should be much lower than initial 10s
        assert adaptive_value < 5.0

    def test_adaptive_timeout_minimum(self):
        """Test adaptive timeout has minimum value."""
        config = TimeoutConfig(timeout_seconds=5.0, jitter_percentage=0.5)
        timeout = AdaptiveTimeout(config)
        
        for _ in range(100):
            t = timeout.get_timeout()
            assert t >= 0.1  # Minimum enforced


class TestCircuitBreaker:
    """Test circuit breaker state machine."""

    def test_initial_state_closed(self):
        """Test circuit breaker starts closed."""
        cb = CircuitBreaker(CircuitBreakerConfig(failure_threshold=5))
        assert cb.state == CircuitState.CLOSED
        assert cb.allow_request() is True

    def test_circuit_opens_on_threshold(self):
        """Test circuit opens after failure threshold."""
        cb = CircuitBreaker(CircuitBreakerConfig(failure_threshold=3))
        
        for _ in range(2):
            cb.record_failure()
            assert cb.state == CircuitState.CLOSED
        
        cb.record_failure()
        assert cb.state == CircuitState.OPEN
        assert cb.allow_request() is False

    def test_circuit_half_open_after_timeout(self):
        """Test circuit transitions to half-open after reset timeout."""
        cb = CircuitBreaker(CircuitBreakerConfig(
            failure_threshold=1,
            reset_timeout=0.1
        ))
        
        cb.record_failure()
        assert cb.state == CircuitState.OPEN
        
        time.sleep(0.15)
        assert cb.allow_request() is True
        assert cb.state == CircuitState.HALF_OPEN

    def test_circuit_closes_after_successes(self):
        """Test circuit closes after successful recoveries."""
        cb = CircuitBreaker(CircuitBreakerConfig(
            failure_threshold=1,
            success_threshold=2,
            reset_timeout=0.01
        ))
        
        cb.record_failure()
        time.sleep(0.02)
        cb.allow_request()  # Transition to half-open
        
        cb.record_success()
        assert cb.state == CircuitState.HALF_OPEN
        cb.record_success()
        assert cb.state == CircuitState.CLOSED

    def test_circuit_reopens_on_half_open_failure(self):
        """Test circuit reopens if half-open test fails."""
        cb = CircuitBreaker(CircuitBreakerConfig(
            failure_threshold=1,
            reset_timeout=0.01
        ))
        
        cb.record_failure()
        time.sleep(0.02)
        cb.allow_request()  # Transition to half-open
        
        cb.record_failure()
        assert cb.state == CircuitState.OPEN


class TestBulkhead:
    """Test bulkhead resource isolation."""

    def test_bulkhead_acquire_release(self):
        """Test basic acquire/release cycle."""
        bulkhead = Bulkhead(BulkheadConfig(max_concurrent=2))
        
        assert bulkhead.acquire() is True
        assert bulkhead.active_count == 1
        bulkhead.release()
        assert bulkhead.active_count == 0

    def test_bulkhead_capacity_limit(self):
        """Test bulkhead enforces concurrent limit."""
        bulkhead = Bulkhead(BulkheadConfig(max_concurrent=1, queue_timeout=0.01))
        
        assert bulkhead.acquire() is True
        
        # Second acquire should timeout
        assert bulkhead.acquire() is False

    def test_bulkhead_concurrent_access(self):
        """Test bulkhead under concurrent access."""
        bulkhead = Bulkhead(BulkheadConfig(max_concurrent=3))
        barrier = threading.Barrier(4)
        
        results = []
        
        def worker():
            barrier.wait()
            results.append(bulkhead.acquire(timeout=0.1))
        
        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        # Exactly 3 should succeed, 1 should fail
        assert sum(results) == 3


class TestRetryDecorator:
    """Test @with_retry decorator."""

    def test_retry_succeeds_eventually(self):
        """Test retry succeeds after initial failures."""
        call_count = [0]
        
        @with_retry(config=RetryConfig(max_attempts=3))
        def flaky_function():
            call_count[0] += 1
            if call_count[0] < 3:
                raise ValueError("Temporary error")
            return "success"
        
        result = flaky_function()
        assert result == "success"
        assert call_count[0] == 3

    def test_max_retries_exceeded(self):
        """Test exception raised when max retries exceeded."""
        call_count = [0]
        
        @with_retry(config=RetryConfig(max_attempts=3))
        def always_fails():
            call_count[0] += 1
            raise ValueError("Permanent error")
        
        with pytest.raises(MaxRetriesExceededError):
            always_fails()
        
        assert call_count[0] == 3

    def test_retry_with_fallback(self):
        """Test fallback is used when retries exhausted."""
        def fallback_func():
            return "fallback_result"
        
        @with_retry(config=RetryConfig(max_attempts=2), fallback=fallback_func)
        def always_fails():
            raise ValueError("Error")
        
        result = always_fails()
        assert result == "fallback_result"

    def test_stop_on_exceptions(self):
        """Test certain exceptions stop retry immediately."""
        call_count = [0]
        
        class FatalError(Exception):
            pass
        
        @with_retry(config=RetryConfig(
            max_attempts=5,
            stop_on_exceptions=(FatalError,)
        ))
        def fatal_function():
            call_count[0] += 1
            raise FatalError("Stop immediately")
        
        with pytest.raises(FatalError):
            fatal_function()
        
        assert call_count[0] == 1  # No retries for fatal errors


class TestTimeoutDecorator:
    """Test @with_timeout decorator."""

    def test_function_completes_within_timeout(self):
        """Test function completes normally within timeout."""
        @with_timeout(timeout_seconds=1.0)
        def fast_function():
            return "done"
        
        result = fast_function()
        assert result == "done"

    def test_function_exceeds_timeout(self):
        """Test timeout enforcement."""
        @with_timeout(timeout_seconds=0.1)
        def slow_function():
            time.sleep(1.0)
            return "done"
        
        with pytest.raises(TimeoutError):
            slow_function()

    def test_timeout_with_fallback(self):
        """Test fallback used on timeout."""
        def fallback_func():
            return "fallback"
        
        @with_timeout(timeout_seconds=0.1, fallback=fallback_func)
        def slow_function():
            time.sleep(1.0)
            return "done"
        
        result = slow_function()
        assert result == "fallback"


class TestBulkheadDecorator:
    """Test @with_bulkhead decorator."""

    def test_bulkhead_decorator_basic(self):
        """Test basic bulkhead decorator usage."""
        @with_bulkhead("test_op", BulkheadConfig(max_concurrent=5))
        def protected_function():
            return "protected"
        
        result = protected_function()
        assert result == "protected"

    def test_bulkhead_decorator_with_fallback(self):
        """Test bulkhead with fallback on capacity exceeded."""
        def fallback():
            return "degraded"
        
        @with_bulkhead("test_capacity", BulkheadConfig(max_concurrent=1, queue_timeout=0.01), fallback=fallback)
        def protected():
            time.sleep(0.1)
            return "normal"
        
        results = []
        barrier = threading.Barrier(2)
        
        def worker():
            barrier.wait()
            results.append(protected())
        
        threads = [threading.Thread(target=worker) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        # One should get normal, one should get fallback
        assert "normal" in results
        assert "degraded" in results


class TestOrchestrator:
    """Test ErrorResilienceOrchestrator singleton."""

    def test_singleton_behavior(self):
        """Test orchestrator is singleton."""
        orch1 = ErrorResilienceOrchestrator()
        orch2 = ErrorResilienceOrchestrator()
        
        assert orch1 is orch2

    def test_circuit_breaker_registry(self):
        """Test circuit breaker registry."""
        orch = ErrorResilienceOrchestrator()
        cb1 = orch.get_circuit_breaker("test_service")
        cb2 = orch.get_circuit_breaker("test_service")
        
        assert cb1 is cb2

    def test_status_reporting(self):
        """Test status reporting."""
        orch = ErrorResilienceOrchestrator()
        cb = orch.get_circuit_breaker("status_test")
        cb.record_failure()
        
        status = orch.get_status()
        assert "circuit_breakers" in status
        assert "status_test" in status["circuit_breakers"]


class TestCombinedResilience:
    """Test combined resilience decorator."""

    def test_combined_decorator(self):
        """Test @with_resilience combined decorator."""
        call_count = [0]
        
        @with_resilience(
            retry_config=RetryConfig(max_attempts=3),
            circuit_breaker_name="combined_test"
        )
        def resilient_function():
            call_count[0] += 1
            if call_count[0] < 2:
                raise ValueError("Temporary")
            return "resilient"
        
        result = resilient_function()
        assert result == "resilient"
        assert call_count[0] == 2


class TestHappyPathPreservation:
    """Verify happy path behavior is 100% preserved."""

    def test_no_resilience_overhead(self):
        """Test normal execution without errors works identically."""
        @with_resilience(
            retry_config=RetryConfig(max_attempts=3),
            bulkhead_name="happy_path"
        )
        def normal_function(x, y):
            return x + y
        
        # Multiple calls to verify consistency
        for i in range(10):
            assert normal_function(i, i * 2) == i * 3

    def test_original_function_metadata_preserved(self):
        """Test function metadata is preserved by decorators."""
        def original_func():
            """Original docstring."""
            pass
        
        decorated = with_retry()(original_func)
        
        assert decorated.__name__ == "original_func"
        assert decorated.__doc__ == "Original docstring."


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
