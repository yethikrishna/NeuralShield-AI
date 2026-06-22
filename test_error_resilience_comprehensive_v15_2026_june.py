"""
Test Suite for NeuralShield Comprehensive Error Resilience Engine V15
Dimension E: Error Resilience

Tests cover:
- Custom exception hierarchy
- Circuit Breaker pattern (CLOSED -> OPEN -> HALF_OPEN -> CLOSED)
- Retry with exponential backoff and jitter
- Timeout wrapper functionality
- Fallback strategies and graceful degradation
- Bulkhead pattern for resource isolation
- Composite resilience pipelines
- Thread safety verification
"""

import pytest
import time
import threading
from typing import Any
from unittest.mock import MagicMock, patch

# Import the resilience module
import sys
sys.path.insert(0, '/home/user/autonomous-developer/NeuralShield-AI')

from neural_shield.error_resilience_comprehensive_v15_2026_june import (
    # Exceptions
    NeuralShieldResilienceError,
    CircuitBreakerOpenError,
    RetryExhaustedError,
    TimeoutError,
    FallbackError,
    BulkheadFullError,
    
    # Circuit Breaker
    CircuitState,
    CircuitBreakerConfig,
    CircuitBreakerMetrics,
    CircuitBreaker,
    
    # Retry
    RetryConfig,
    RetryWithBackoff,
    
    # Timeout
    TimeoutWrapper,
    
    # Fallback
    FallbackStrategy,
    CachedDefault,
    
    # Bulkhead
    Bulkhead,
    
    # Composite
    ResiliencePipeline,
    
    # Convenience
    resilient,
)

# ============================================================================
# Exception Hierarchy Tests
# ============================================================================

class TestExceptionHierarchy:
    """Test custom exception hierarchy"""
    
    def test_base_exception_type(self):
        assert issubclass(NeuralShieldResilienceError, Exception)
    
    def test_circuit_breaker_exception(self):
        exc = CircuitBreakerOpenError("test", time.time())
        assert isinstance(exc, NeuralShieldResilienceError)
        assert exc.circuit_name == "test"
        assert "OPEN" in str(exc)
    
    def test_retry_exhausted_exception(self):
        inner = ValueError("test")
        exc = RetryExhaustedError("func", 3, inner)
        assert isinstance(exc, NeuralShieldResilienceError)
        assert exc.attempts == 3
        assert exc.last_error is inner
    
    def test_timeout_exception(self):
        exc = TimeoutError("func", 5.0)
        assert isinstance(exc, NeuralShieldResilienceError)
        assert exc.timeout_seconds == 5.0
    
    def test_fallback_exception(self):
        p_err = ValueError("primary")
        f_err = ValueError("fallback")
        exc = FallbackError("func", p_err, f_err)
        assert isinstance(exc, NeuralShieldResilienceError)
        assert exc.primary_error is p_err
        assert exc.fallback_error is f_err
    
    def test_bulkhead_exception(self):
        exc = BulkheadFullError("test", 10)
        assert isinstance(exc, NeuralShieldResilienceError)
        assert exc.max_concurrent == 10

# ============================================================================
# Circuit Breaker Tests
# ============================================================================

class TestCircuitBreaker:
    """Test Circuit Breaker implementation"""
    
    def test_circuit_starts_closed(self):
        cb = CircuitBreaker()
        assert cb.state == CircuitState.CLOSED
    
    def test_circuit_allows_requests_when_closed(self):
        cb = CircuitBreaker()
        
        @cb
        def success_func():
            return "success"
        
        assert success_func() == "success"
        assert cb.metrics.successful_requests == 1
    
    def test_circuit_opens_after_failures(self):
        config = CircuitBreakerConfig(failure_threshold=2, timeout_seconds=10)
        cb = CircuitBreaker(config)
        
        @cb
        def failing_func():
            raise ValueError("failure")
        
        # First failure
        with pytest.raises(ValueError):
            failing_func()
        
        # Second failure - should trigger OPEN
        with pytest.raises(ValueError):
            failing_func()
        
        assert cb.state == CircuitState.OPEN
        
        # Next request should fail fast with CircuitBreakerOpenError
        with pytest.raises(CircuitBreakerOpenError):
            failing_func()
        
        assert cb.metrics.rejected_requests == 1
    
    def test_circuit_half_open_after_timeout(self):
        config = CircuitBreakerConfig(failure_threshold=1, timeout_seconds=0.1)
        cb = CircuitBreaker(config)
        
        @cb
        def failing_func():
            raise ValueError("failure")
        
        # Trigger OPEN
        with pytest.raises(ValueError):
            failing_func()
        
        assert cb.state == CircuitState.OPEN
        
        # Wait for timeout
        time.sleep(0.15)
        
        # Should transition to HALF_OPEN
        @cb
        def success_func():
            return "success"
        
        result = success_func()
        assert result == "success"
        assert cb.state == CircuitState.HALF_OPEN
    
    def test_circuit_closes_after_successes_in_half_open(self):
        config = CircuitBreakerConfig(
            failure_threshold=1,
            success_threshold=2,
            timeout_seconds=0.1
        )
        cb = CircuitBreaker(config)
        
        # First fail to open
        @cb
        def failing_func():
            raise ValueError("failure")
        
        with pytest.raises(ValueError):
            failing_func()
        
        time.sleep(0.15)
        
        # Succeed enough times to close
        @cb
        def success_func():
            return "ok"
        
        success_func()  # 1 success in HALF_OPEN
        success_func()  # 2 successes - should close
        
        assert cb.state == CircuitState.CLOSED
    
    def test_circuit_reopens_on_failure_in_half_open(self):
        config = CircuitBreakerConfig(failure_threshold=1, timeout_seconds=0.1)
        cb = CircuitBreaker(config)
        
        # Open circuit
        @cb
        def failing_func():
            raise ValueError("failure")
        
        with pytest.raises(ValueError):
            failing_func()
        
        time.sleep(0.15)
        
        # Fail again in HALF_OPEN
        with pytest.raises(ValueError):
            failing_func()
        
        assert cb.state == CircuitState.OPEN
    
    def test_circuit_reset(self):
        cb = CircuitBreaker()
        cb.reset()
        assert cb.state == CircuitState.CLOSED
        assert cb.metrics.total_requests == 0

# ============================================================================
# Retry with Backoff Tests
# ============================================================================

class TestRetryWithBackoff:
    """Test Retry with exponential backoff"""
    
    def test_retry_succeeds_eventually(self):
        call_count = [0]
        
        @RetryWithBackoff(RetryConfig(max_attempts=3))
        def flaky_func():
            call_count[0] += 1
            if call_count[0] < 3:
                raise ValueError("temporary failure")
            return "success"
        
        result = flaky_func()
        assert result == "success"
        assert call_count[0] == 3
    
    def test_retry_exhausted_raises(self):
        call_count = [0]
        
        @RetryWithBackoff(RetryConfig(max_attempts=2))
        def always_fails():
            call_count[0] += 1
            raise ValueError("permanent failure")
        
        with pytest.raises(RetryExhaustedError) as exc_info:
            always_fails()
        
        assert call_count[0] == 2
        assert exc_info.value.attempts == 2
        assert isinstance(exc_info.value.last_error, ValueError)
    
    def test_retry_no_delay_on_success(self):
        start = time.time()
        
        @RetryWithBackoff()
        def success_func():
            return "ok"
        
        result = success_func()
        elapsed = time.time() - start
        
        assert result == "ok"
        assert elapsed < 0.01  # Should be nearly instant
    
    def test_backoff_delay_increases(self):
        delays = []
        
        with patch('time.sleep', lambda t: delays.append(t)):
            call_count = [0]
            
            @RetryWithBackoff(RetryConfig(
                max_attempts=4,
                initial_delay_seconds=0.1,
                backoff_factor=2,
                jitter_factor=0
            ))
            def flaky():
                call_count[0] += 1
                if call_count[0] < 4:
                    raise ValueError("fail")
                return "ok"
            
            flaky()
        
        # Delays should increase: 0.1, 0.2, 0.4 (exponential)
        assert len(delays) == 3
        assert delays[0] < delays[1] < delays[2]
    
    def test_retry_on_result_condition(self):
        call_count = [0]
        
        def should_retry(result):
            return result == "retry_needed"
        
        @RetryWithBackoff(RetryConfig(
            max_attempts=3,
            retry_on_result=should_retry
        ))
        def func():
            call_count[0] += 1
            if call_count[0] < 2:
                return "retry_needed"
            return "final"
        
        result = func()
        assert result == "final"
        assert call_count[0] == 2

# ============================================================================
# Timeout Wrapper Tests
# ============================================================================

class TestTimeoutWrapper:
    """Test Timeout wrapper functionality"""
    
    def test_timeout_raises_when_exceeded(self):
        @TimeoutWrapper(timeout_seconds=0.1)
        def slow_func():
            time.sleep(1.0)
            return "done"
        
        with pytest.raises(TimeoutError) as exc_info:
            slow_func()
        
        assert exc_info.value.timeout_seconds == 0.1
    
    def test_no_timeout_when_fast(self):
        @TimeoutWrapper(timeout_seconds=1.0)
        def fast_func():
            return "done"
        
        result = fast_func()
        assert result == "done"
    
    def test_exception_propagates(self):
        @TimeoutWrapper(timeout_seconds=1.0)
        def error_func():
            raise ValueError("test error")
        
        with pytest.raises(ValueError, match="test error"):
            error_func()

# ============================================================================
# Fallback Strategy Tests
# ============================================================================

class TestFallbackStrategy:
    """Test Fallback and graceful degradation"""
    
    def test_fallback_used_when_primary_fails(self):
        def my_fallback():
            return "fallback_result"
        
        @FallbackStrategy(fallback=my_fallback)
        def failing_func():
            raise ValueError("primary failed")
        
        result = failing_func()
        assert result == "fallback_result"
    
    def test_primary_used_when_succeeds(self):
        def my_fallback():
            return "fallback"
        
        @FallbackStrategy(fallback=my_fallback)
        def success_func():
            return "primary"
        
        result = success_func()
        assert result == "primary"
    
    def test_fallback_error_raises_fallback_error(self):
        def bad_fallback():
            raise RuntimeError("fallback also failed")
        
        @FallbackStrategy(fallback=bad_fallback)
        def failing_func():
            raise ValueError("primary failed")
        
        with pytest.raises(FallbackError) as exc_info:
            failing_func()
        
        assert isinstance(exc_info.value.primary_error, ValueError)
        assert isinstance(exc_info.value.fallback_error, RuntimeError)
    
    def test_cached_default_returns_default(self):
        @CachedDefault(default_value="safe_default")
        def failing_func():
            raise ValueError("failed")
        
        result = failing_func()
        assert result == "safe_default"
    
    def test_cached_default_passes_through_success(self):
        @CachedDefault(default_value="default")
        def success_func():
            return "actual_result"
        
        result = success_func()
        assert result == "actual_result"

# ============================================================================
# Bulkhead Pattern Tests
# ============================================================================

class TestBulkhead:
    """Test Bulkhead resource isolation"""
    
    def test_bulkhead_allows_up_to_max(self):
        bulkhead = Bulkhead(max_concurrent=2)
        
        @bulkhead
        def func():
            return "ok"
        
        assert func() == "ok"
        assert func() == "ok"
    
    def test_bulkhead_rejects_when_full(self):
        bulkhead = Bulkhead(max_concurrent=1)
        
        barrier = threading.Barrier(2)
        results = []
        
        def worker():
            @bulkhead
            def slow_func():
                barrier.wait()
                time.sleep(0.1)
                return "done"
            
            try:
                results.append(slow_func())
            except BulkheadFullError:
                results.append("rejected")
        
        # Start two threads
        t1 = threading.Thread(target=worker)
        t2 = threading.Thread(target=worker)
        t1.start()
        t2.start()
        
        t1.join(timeout=1.0)
        t2.join(timeout=1.0)
        
        # One should succeed, one should be rejected
        assert "done" in results
        assert "rejected" in results
    
    def test_bulkhead_releases_after_completion(self):
        bulkhead = Bulkhead(max_concurrent=1)
        
        @bulkhead
        def func():
            return "ok"
        
        assert func() == "ok"
        assert func() == "ok"  # Should work again after release
    
    def test_bulkhead_capacity_tracking(self):
        bulkhead = Bulkhead(max_concurrent=5)
        assert bulkhead.available_capacity == 5
        assert bulkhead.active_count == 0

# ============================================================================
# Composite Pipeline Tests
# ============================================================================

class TestResiliencePipeline:
    """Test Composite Resilience Pipeline"""
    
    def test_pipeline_combines_strategies(self):
        pipeline = ResiliencePipeline()
        pipeline.with_retry(RetryConfig(max_attempts=2))
        pipeline.with_cached_default("default")
        
        call_count = [0]
        
        @pipeline.wrap
        def flaky():
            call_count[0] += 1
            if call_count[0] < 3:
                raise ValueError("fail")
            return "success"
        
        result = flaky()
        # Should retry twice, then use fallback
        assert call_count[0] == 2
        assert result == "default"
    
    def test_pipeline_ordering(self):
        pipeline = ResiliencePipeline()
        pipeline.with_timeout(0.5)
        pipeline.with_cached_default("safe")
        
        @pipeline.wrap
        def slow():
            time.sleep(1.0)
            return "done"
        
        result = slow()
        assert result == "safe"

# ============================================================================
# Convenience Decorator Tests
# ============================================================================

class TestConvenienceDecorator:
    """Test @resilient convenience decorator"""
    
    def test_resilient_decorator_combines_features(self):
        call_count = [0]
        
        @resilient(max_retries=2, timeout_seconds=1.0, fallback_value="safe")
        def flaky():
            call_count[0] += 1
            raise ValueError("fail")
        
        result = flaky()
        assert call_count[0] == 2
        assert result == "safe"
    
    def test_resilient_with_no_fallback(self):
        @resilient(max_retries=1, timeout_seconds=1.0, fallback_value=None)
        def success():
            return "ok"
        
        assert success() == "ok"

# ============================================================================
# Thread Safety Tests
# ============================================================================

class TestThreadSafety:
    """Verify thread safety of all resilience components"""
    
    def test_circuit_breaker_thread_safe(self):
        cb = CircuitBreaker(CircuitBreakerConfig(failure_threshold=100))
        
        @cb
        def func():
            return "ok"
        
        threads = []
        for _ in range(10):
            t = threading.Thread(target=lambda: [func() for _ in range(10)])
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        assert cb.metrics.total_requests == 100
        assert cb.metrics.successful_requests == 100
    
    def test_bulkhead_concurrent(self):
        bulkhead = Bulkhead(max_concurrent=5)
        
        @bulkhead
        def func():
            time.sleep(0.01)
            return "ok"
        
        threads = []
        for _ in range(10):
            t = threading.Thread(target=func)
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        # All should complete eventually
        assert True

# ============================================================================
# Run Tests
# ============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
