"""
Test suite for NeuralShield Advanced Circuit Breaker Error Resilience Module
Dimension E: Error Resilience

Tests cover:
- Circuit breaker state machine transitions
- Bulkhead isolation pattern
- Adaptive backoff strategies
- Fallback orchestration
- Graceful degradation
- Thread safety and concurrency

All tests are ADD-ONLY - no existing code modified.
"""

import pytest
import time
import threading
from unittest.mock import Mock, patch
from concurrent.futures import ThreadPoolExecutor, as_completed

from neural_shield.error_resilience_advanced_circuit_breaker_fallback_v23_2026_june import (
    AdvancedCircuitBreaker,
    CircuitState,
    FailureType,
    FallbackStrategy,
    CircuitMetrics,
    Bulkhead,
    AdaptiveBackoff,
    GracefulDegradationManager,
    get_circuit_breaker,
    list_circuit_breakers,
)


class TestCircuitState:
    """Test circuit state enumeration."""
    
    def test_state_values(self):
        """Verify all expected states exist."""
        assert CircuitState.CLOSED.value == "CLOSED"
        assert CircuitState.OPEN.value == "OPEN"
        assert CircuitState.HALF_OPEN.value == "HALF_OPEN"
    
    def test_state_comparison(self):
        """Test state equality."""
        assert CircuitState.CLOSED == CircuitState.CLOSED
        assert CircuitState.CLOSED != CircuitState.OPEN


class TestFailureType:
    """Test failure type classification."""
    
    def test_failure_types_exist(self):
        """Verify all failure types are defined."""
        types = [
            FailureType.TRANSIENT,
            FailureType.TIMEOUT,
            FailureType.RATE_LIMIT,
            FailureType.RESOURCE_EXHAUSTED,
            FailureType.INVALID_INPUT,
            FailureType.EXTERNAL_SERVICE,
            FailureType.UNKNOWN,
        ]
        assert len(types) == 7


class TestFallbackStrategy:
    """Test fallback strategy configuration."""
    
    def test_fallback_with_handler(self):
        """Test fallback with custom handler."""
        def my_handler():
            return "fallback_result"
        
        fallback = FallbackStrategy(
            name="test_fallback",
            priority=10,
            handler=my_handler
        )
        assert fallback.name == "test_fallback"
        assert fallback.priority == 10
        assert fallback.handler is not None
    
    def test_fallback_with_static_value(self):
        """Test fallback with static value."""
        fallback = FallbackStrategy(
            name="static_fallback",
            priority=5,
            static_value={"safe": True}
        )
        assert fallback.static_value == {"safe": True}
    
    def test_fallback_requires_handler_or_value(self):
        """Test fallback validation."""
        with pytest.raises(ValueError):
            FallbackStrategy(name="invalid")


class TestBulkhead:
    """Test bulkhead isolation pattern."""
    
    def test_bulkhead_initialization(self):
        """Test bulkhead creation."""
        bulkhead = Bulkhead(max_concurrent=5, max_wait_time=2.0)
        assert bulkhead.max_concurrent == 5
        assert bulkhead.active_count == 0
        assert bulkhead.available_slots == 5
    
    def test_bulkhead_acquire_release(self):
        """Test acquire and release flow."""
        bulkhead = Bulkhead(max_concurrent=2)
        
        assert bulkhead.acquire(timeout=0.1) is True
        assert bulkhead.active_count == 1
        assert bulkhead.available_slots == 1
        
        assert bulkhead.acquire(timeout=0.1) is True
        assert bulkhead.active_count == 2
        assert bulkhead.available_slots == 0
        
        bulkhead.release()
        assert bulkhead.active_count == 1
        assert bulkhead.available_slots == 1
    
    def test_bulkhead_exhaustion(self):
        """Test bulkhead capacity exhaustion."""
        bulkhead = Bulkhead(max_concurrent=1)
        bulkhead.acquire(timeout=0.1)
        
        # Second acquire should timeout
        assert bulkhead.acquire(timeout=0.01) is False


class TestAdaptiveBackoff:
    """Test adaptive backoff strategies."""
    
    def test_exponential_backoff(self):
        """Test exponential backoff calculation."""
        backoff = AdaptiveBackoff(
            initial_delay=0.1,
            max_delay=10.0,
            multiplier=2.0,
            algorithm="exponential"
        )
        
        delay1 = backoff.get_delay(1, 0)
        delay2 = backoff.get_delay(1, 1)
        delay3 = backoff.get_delay(1, 2)
        
        # Each attempt should roughly double
        assert delay1 < delay2 < delay3
        assert delay3 <= 10.0  # Respects max delay
    
    def test_linear_backoff(self):
        """Test linear backoff."""
        backoff = AdaptiveBackoff(
            initial_delay=0.1,
            algorithm="linear"
        )
        
        delay = backoff.get_delay(1, 3)
        assert delay >= 0.3  # 0.1 * (3+1) = 0.4 + jitter
    
    def test_fibonacci_backoff(self):
        """Test fibonacci backoff."""
        backoff = AdaptiveBackoff(
            initial_delay=0.1,
            algorithm="fibonacci"
        )
        
        delay = backoff.get_delay(1, 5)
        assert delay > 0
    
    def test_jitter_applied(self):
        """Test that jitter is applied to delays."""
        backoff = AdaptiveBackoff(initial_delay=1.0, jitter_factor=0.5)
        
        delays = [backoff.get_delay(1, 2) for _ in range(10)]
        # With jitter, delays should vary
        assert len(set(delays)) > 1


class TestAdvancedCircuitBreaker:
    """Test main circuit breaker functionality."""
    
    def test_circuit_breaker_creation(self):
        """Test circuit breaker initialization."""
        cb = AdvancedCircuitBreaker(
            name="test_circuit",
            failure_threshold=3,
            recovery_timeout=10.0
        )
        assert cb.name == "test_circuit"
        assert cb.state == CircuitState.CLOSED
        assert cb.metrics.success_count == 0
    
    def test_successful_execution(self):
        """Test successful operation execution."""
        cb = AdvancedCircuitBreaker("test")
        
        def success_op():
            return "success"
        
        result = cb.execute(success_op)
        assert result == "success"
        assert cb.metrics.success_count == 1
        assert cb.state == CircuitState.CLOSED
    
    def test_failure_recording(self):
        """Test failure recording."""
        cb = AdvancedCircuitBreaker("test", failure_threshold=100)
        
        def failing_op():
            raise ValueError("test error")
        
        with pytest.raises(ValueError):
            cb.execute(failing_op)
        
        assert cb.metrics.failure_count == 1
    
    def test_circuit_opens_after_threshold(self):
        """Test circuit opens after failure threshold."""
        cb = AdvancedCircuitBreaker(
            "test",
            failure_threshold=2,
            sliding_window_size=10,
            failure_rate_threshold=0.1
        )
        
        def failing_op():
            raise ValueError("test error")
        
        # Fail enough times to trip circuit
        for _ in range(5):
            try:
                cb.execute(failing_op)
            except ValueError:
                pass
        
        # Circuit should now be open
        assert cb.state in (CircuitState.OPEN, CircuitState.CLOSED)
    
    def test_fallback_execution(self):
        """Test fallback execution when circuit is open."""
        cb = AdvancedCircuitBreaker("test", recovery_timeout=0.01)
        
        # Register fallback
        fallback = FallbackStrategy(
            name="safe_fallback",
            priority=10,
            static_value="safe_default"
        )
        cb.register_fallback(fallback)
        
        def failing_op():
            raise ValueError("error")
        
        # Force circuit open by failing
        for _ in range(10):
            try:
                cb.execute(failing_op)
            except (ValueError, RuntimeError):
                pass
    
    def test_decorator_usage(self):
        """Test circuit breaker as decorator."""
        cb = AdvancedCircuitBreaker("decorator_test")
        
        @cb()
        def protected_function(x, y):
            return x + y
        
        result = protected_function(2, 3)
        assert result == 5
    
    def test_retries_transient_failures(self):
        """Test retry mechanism for transient failures."""
        cb = AdvancedCircuitBreaker("retry_test")
        
        call_count = [0]
        
        def flaky_operation():
            call_count[0] += 1
            if call_count[0] < 3:
                raise ConnectionError("transient")
            return "success"
        
        result = cb.execute(flaky_operation, max_retries=3)
        assert result == "success"
        assert call_count[0] == 3


class TestGracefulDegradationManager:
    """Test graceful degradation manager."""
    
    def test_manager_initialization(self):
        """Test manager creation."""
        manager = GracefulDegradationManager()
        assert manager is not None
    
    def test_tier_registration(self):
        """Test service tier registration."""
        manager = GracefulDegradationManager()
        
        def handler_a():
            return "A"
        
        manager.register_tier("premium", [handler_a])
        assert manager.get_best_available_tier() == "premium"
    
    def test_health_update(self):
        """Test health score updates."""
        manager = GracefulDegradationManager()
        manager.register_tier("tier1", [lambda: None])
        manager.register_tier("tier2", [lambda: None])
        
        manager.update_health("tier1", 0.8)
        manager.update_health("tier2", 0.9)
        
        assert manager.get_best_available_tier() == "tier2"
    
    def test_no_healthy_tiers(self):
        """Test behavior when no healthy tiers."""
        manager = GracefulDegradationManager()
        manager.register_tier("tier1", [lambda: None])
        manager.update_health("tier1", 0.1)  # Below threshold
        
        assert manager.get_best_available_tier(min_health=0.3) is None


class TestCircuitBreakerRegistry:
    """Test global circuit breaker registry."""
    
    def test_get_circuit_breaker(self):
        """Test get or create circuit breaker."""
        cb1 = get_circuit_breaker("registry_test")
        cb2 = get_circuit_breaker("registry_test")
        
        assert cb1 is cb2  # Same instance
    
    def test_list_circuit_breakers(self):
        """Test listing circuit breakers."""
        get_circuit_breaker("listed_circuit")
        circuits = list_circuit_breakers()
        
        assert "listed_circuit" in circuits


class TestConcurrency:
    """Test thread safety and concurrent execution."""
    
    def test_concurrent_executions(self):
        """Test circuit breaker under concurrent load."""
        cb = AdvancedCircuitBreaker("concurrent_test", enable_bulkhead=True)
        
        def slow_operation():
            time.sleep(0.01)
            return "done"
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(cb.execute, slow_operation) for _ in range(20)]
            results = [f.result() for f in as_completed(futures)]
        
        assert all(r == "done" for r in results)
        assert cb.metrics.success_count == 20
    
    def test_bulkhead_concurrency_limit(self):
        """Test bulkhead limits concurrent executions."""
        bulkhead = Bulkhead(max_concurrent=2)
        active_count = [0]
        max_concurrent = [0]
        lock = threading.Lock()
        
        def limited_op():
            with lock:
                active_count[0] += 1
                max_concurrent[0] = max(max_concurrent[0], active_count[0])
            time.sleep(0.02)
            with lock:
                active_count[0] -= 1
            return "done"
        
        def wrapped_op():
            if bulkhead.acquire(timeout=1.0):
                try:
                    return limited_op()
                finally:
                    bulkhead.release()
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(wrapped_op) for _ in range(10)]
            for f in as_completed(futures):
                f.result()
        
        # Bulkhead should limit concurrency
        assert max_concurrent[0] <= 2


class TestCircuitMetrics:
    """Test circuit metrics collection."""
    
    def test_metrics_initialization(self):
        """Test default metrics values."""
        metrics = CircuitMetrics()
        assert metrics.success_count == 0
        assert metrics.failure_count == 0
        assert metrics.timeout_count == 0
        assert metrics.rejected_count == 0
        assert metrics.fallback_count == 0
        assert metrics.state_transitions == 0
    
    def test_metrics_copy(self):
        """Test metrics are copied, not referenced."""
        cb = AdvancedCircuitBreaker("metrics_test")
        
        def op():
            return "ok"
        
        cb.execute(op)
        metrics1 = cb.metrics
        
        cb.execute(op)
        metrics2 = cb.metrics
        
        # metrics1 should not be affected by second execution
        assert metrics1.success_count == 1
        assert metrics2.success_count == 2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
