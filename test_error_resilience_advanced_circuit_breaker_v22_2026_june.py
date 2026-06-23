"""
Test suite for Error Resilience v22 - Advanced Circuit Breaker with Fallback Orchestration

100% ADD-ONLY tests - no existing tests modified
All existing tests must continue to pass
"""

import pytest
import time
import threading
from neural_shield.error_resilience_advanced_circuit_breaker_fallback_v22_2026_june import (
    AdvancedCircuitBreaker,
    CircuitBreakerConfig,
    CircuitState,
    CircuitBreakerOpenError,
    BulkheadIsolator,
    BulkheadConfig,
    BulkheadTimeoutError,
    PriorityFallbackOrchestrator,
    FallbackPriority,
    FallbackChainExhaustedError,
    AdaptiveTimeoutWithJitter,
    RetryConfig,
    GracefulDegradationManager,
    DegradationLevel,
    NoImplementationError,
    with_circuit_breaker,
    with_bulkhead,
    with_retry,
    create_error_resilience_v22,
)


class TestAdvancedCircuitBreaker:
    """Tests for Advanced Circuit Breaker with half-open state."""
    
    def test_circuit_starts_closed(self):
        breaker = AdvancedCircuitBreaker()
        assert breaker.state == CircuitState.CLOSED
    
    def test_allow_request_when_closed(self):
        breaker = AdvancedCircuitBreaker()
        assert breaker.allow_request() is True
    
    def test_successful_call_records_success(self):
        breaker = AdvancedCircuitBreaker()
        
        def success_func():
            return "success"
        
        result = breaker.execute(success_func)
        assert result == "success"
        assert breaker.metrics.success_calls == 1
        assert breaker.metrics.failure_calls == 0
    
    def test_failed_call_records_failure(self):
        breaker = AdvancedCircuitBreaker()
        
        def fail_func():
            raise ValueError("test error")
        
        with pytest.raises(ValueError):
            breaker.execute(fail_func)
        
        assert breaker.metrics.failure_calls == 1
        assert breaker.metrics.success_calls == 0
    
    def test_circuit_opens_after_threshold(self):
        config = CircuitBreakerConfig(
            failure_threshold=2,
            min_calls_to_open=2,
            sampling_window=10,
        )
        breaker = AdvancedCircuitBreaker(config)
        
        def fail_func():
            raise ValueError("test error")
        
        for _ in range(5):
            try:
                breaker.execute(fail_func)
            except (ValueError, CircuitBreakerOpenError):
                pass
        
        assert breaker.state == CircuitState.OPEN
    
    def test_open_circuit_rejects_requests(self):
        config = CircuitBreakerConfig(
            failure_threshold=2,
            min_calls_to_open=2,
            sampling_window=10,
        )
        breaker = AdvancedCircuitBreaker(config)
        
        def fail_func():
            raise ValueError("test error")
        
        for _ in range(5):
            try:
                breaker.execute(fail_func)
            except (ValueError, CircuitBreakerOpenError):
                pass
        
        with pytest.raises(CircuitBreakerOpenError):
            breaker.execute(lambda: "success")
    
    def test_half_open_transition_after_timeout(self):
        config = CircuitBreakerConfig(
            failure_threshold=2,
            min_calls_to_open=2,
            sampling_window=10,
            reset_timeout=0.1,
        )
        breaker = AdvancedCircuitBreaker(config)
        
        def fail_func():
            raise ValueError("test error")
        
        for _ in range(5):
            try:
                breaker.execute(fail_func)
            except (ValueError, CircuitBreakerOpenError):
                pass
        
        assert breaker.state == CircuitState.OPEN
        
        time.sleep(0.15)
        
        assert breaker.state == CircuitState.HALF_OPEN
    
    def test_half_open_success_closes_circuit(self):
        config = CircuitBreakerConfig(
            failure_threshold=2,
            min_calls_to_open=2,
            sampling_window=10,
            reset_timeout=0.1,
            success_threshold=2,
        )
        breaker = AdvancedCircuitBreaker(config)
        
        def fail_func():
            raise ValueError("test error")
        
        for _ in range(5):
            try:
                breaker.execute(fail_func)
            except (ValueError, CircuitBreakerOpenError):
                pass
        
        time.sleep(0.15)
        
        def success_func():
            return "success"
        
        for _ in range(3):
            breaker.execute(success_func)
        
        assert breaker.state == CircuitState.CLOSED
    
    def test_half_open_failure_reopens_circuit(self):
        config = CircuitBreakerConfig(
            failure_threshold=2,
            min_calls_to_open=2,
            sampling_window=10,
            reset_timeout=0.1,
        )
        breaker = AdvancedCircuitBreaker(config)
        
        def fail_func():
            raise ValueError("test error")
        
        for _ in range(5):
            try:
                breaker.execute(fail_func)
            except (ValueError, CircuitBreakerOpenError):
                pass
        
        time.sleep(0.15)
        
        with pytest.raises(ValueError):
            breaker.execute(fail_func)
        
        assert breaker.state == CircuitState.OPEN
    
    def test_circuit_metrics_tracked_correctly(self):
        breaker = AdvancedCircuitBreaker()
        
        def success_func():
            return "success"
        
        def fail_func():
            raise ValueError("test error")
        
        for _ in range(5):
            breaker.execute(success_func)
        
        for _ in range(3):
            try:
                breaker.execute(fail_func)
            except ValueError:
                pass
        
        metrics = breaker.metrics
        assert metrics.total_calls == 8
        assert metrics.success_calls == 5
        assert metrics.failure_calls == 3


class TestBulkheadIsolator:
    """Tests for Bulkhead isolation pattern."""
    
    def test_bulkhead_allows_calls_within_limit(self):
        config = BulkheadConfig(max_concurrent_calls=5)
        bulkhead = BulkheadIsolator(config)
        
        result = bulkhead.execute(lambda: "success")
        assert result == "success"
    
    def test_bulkhead_tracks_active_calls(self):
        bulkhead = BulkheadIsolator(BulkheadConfig(max_concurrent_calls=5))
        assert bulkhead.active_calls == 0
        
        barrier = threading.Barrier(2)
        
        def blocking_func():
            barrier.wait()
            barrier.wait()
            return "done"
        
        thread = threading.Thread(target=lambda: bulkhead.execute(blocking_func))
        thread.start()
        
        barrier.wait()
        assert bulkhead.active_calls == 1
        barrier.wait()
        thread.join()
        
        assert bulkhead.active_calls == 0
    
    def test_bulkhead_available_capacity(self):
        bulkhead = BulkheadIsolator(BulkheadConfig(max_concurrent_calls=5))
        assert bulkhead.available_capacity == 5
    
    def test_bulkhead_timeout_when_full(self):
        config = BulkheadConfig(
            max_concurrent_calls=1,
            max_wait_time=0.1,
        )
        bulkhead = BulkheadIsolator(config)
        
        barrier = threading.Barrier(2)
        
        def blocking_func():
            barrier.wait()
            time.sleep(0.5)
            return "done"
        
        thread = threading.Thread(target=lambda: bulkhead.execute(blocking_func))
        thread.start()
        
        barrier.wait()
        
        with pytest.raises(BulkheadTimeoutError):
            bulkhead.execute(lambda: "too late")
        
        thread.join()


class TestPriorityFallbackOrchestrator:
    """Tests for priority-based fallback orchestration."""
    
    def test_primary_succeeds_no_fallback(self):
        orchestrator = PriorityFallbackOrchestrator()
        
        def primary():
            return "primary"
        
        result = orchestrator.execute(primary)
        assert result == "primary"
    
    def test_fallback_called_when_primary_fails(self):
        orchestrator = PriorityFallbackOrchestrator()
        orchestrator.add_fallback(1, lambda: "fallback")
        
        def primary():
            raise ValueError("primary failed")
        
        result = orchestrator.execute(primary, priority=FallbackPriority.HIGH)
        assert result == "fallback"
    
    def test_low_priority_no_fallback(self):
        orchestrator = PriorityFallbackOrchestrator()
        orchestrator.add_fallback(1, lambda: "fallback")
        
        def primary():
            raise ValueError("primary failed")
        
        with pytest.raises(FallbackChainExhaustedError):
            orchestrator.execute(primary, priority=FallbackPriority.LOW)
    
    def test_critical_priority_all_fallbacks(self):
        orchestrator = PriorityFallbackOrchestrator()
        orchestrator.add_fallback(1, lambda: (_ for _ in ()).throw(ValueError("f1")))
        orchestrator.add_fallback(2, lambda: (_ for _ in ()).throw(ValueError("f2")))
        orchestrator.add_fallback(3, lambda: "final_fallback")
        
        def primary():
            raise ValueError("primary failed")
        
        result = orchestrator.execute(primary, priority=FallbackPriority.CRITICAL)
        assert result == "final_fallback"
    
    def test_all_fallbacks_exhausted_raises(self):
        orchestrator = PriorityFallbackOrchestrator()
        orchestrator.add_fallback(1, lambda: (_ for _ in ()).throw(ValueError("f1")))
        
        def primary():
            raise ValueError("primary failed")
        
        with pytest.raises(FallbackChainExhaustedError):
            orchestrator.execute(primary, priority=FallbackPriority.HIGH)


class TestAdaptiveTimeoutWithJitter:
    """Tests for retry with jitter backoff."""
    
    def test_succeeds_on_first_try(self):
        retry = AdaptiveTimeoutWithJitter()
        call_count = [0]
        
        def func():
            call_count[0] += 1
            return "success"
        
        result = retry.execute(func)
        assert result == "success"
        assert call_count[0] == 1
    
    def test_retries_on_failure(self):
        retry = AdaptiveTimeoutWithJitter(RetryConfig(max_attempts=3, initial_delay=0.01))
        call_count = [0]
        
        def func():
            call_count[0] += 1
            if call_count[0] < 3:
                raise ValueError("fail")
            return "success"
        
        result = retry.execute(func)
        assert result == "success"
        assert call_count[0] == 3
    
    def test_exhausts_attempts_raises(self):
        retry = AdaptiveTimeoutWithJitter(RetryConfig(max_attempts=2, initial_delay=0.01))
        call_count = [0]
        
        def func():
            call_count[0] += 1
            raise ValueError("always fail")
        
        with pytest.raises(ValueError):
            retry.execute(func)
        
        assert call_count[0] == 2


class TestGracefulDegradationManager:
    """Tests for graceful degradation manager."""
    
    def test_uses_full_quality_when_healthy(self):
        manager = GracefulDegradationManager()
        manager.register_implementation(DegradationLevel.FULL, lambda: "full")
        
        result = manager.execute()
        assert result == "full"
        assert manager.current_level == DegradationLevel.FULL
    
    def test_degrades_on_high_error_rate(self):
        manager = GracefulDegradationManager()
        manager.register_implementation(DegradationLevel.FULL, lambda: (_ for _ in ()).throw(ValueError()))
        manager.register_implementation(DegradationLevel.REDUCED, lambda: "reduced")
        manager.register_implementation(DegradationLevel.MINIMAL, lambda: "minimal")
        
        for _ in range(30):
            try:
                manager.execute()
            except Exception:
                pass
        
        assert manager.current_level in (DegradationLevel.REDUCED, DegradationLevel.MINIMAL)
    
    def test_no_implementation_raises(self):
        manager = GracefulDegradationManager()
        
        with pytest.raises(NoImplementationError):
            manager.execute()


class TestDecorators:
    """Tests for convenience decorators."""
    
    def test_circuit_breaker_decorator(self):
        @with_circuit_breaker()
        def my_func():
            return "success"
        
        result = my_func()
        assert result == "success"
        assert hasattr(my_func, "circuit_breaker")
    
    def test_bulkhead_decorator(self):
        @with_bulkhead()
        def my_func():
            return "success"
        
        result = my_func()
        assert result == "success"
        assert hasattr(my_func, "bulkhead")
    
    def test_retry_decorator(self):
        @with_retry()
        def my_func():
            return "success"
        
        result = my_func()
        assert result == "success"
        assert hasattr(my_func, "retry")


class TestFactoryFunction:
    """Tests for main factory function."""
    
    def test_create_all_components(self):
        components = create_error_resilience_v22()
        
        assert components["version"] == "v22"
        assert components["enabled"] is True
        assert components["circuit_breaker"] is not None
        assert components["bulkhead"] is not None
        assert components["retry_manager"] is not None
        assert components["fallback_orchestrator"] is not None
        assert components["degradation_manager"] is not None
    
    def test_create_with_disabled_components(self):
        components = create_error_resilience_v22(
            enable_circuit_breaker=False,
            enable_bulkhead=False,
        )
        
        assert components["circuit_breaker"] is None
        assert components["bulkhead"] is None
        assert components["retry_manager"] is not None


class TestThreadSafety:
    """Thread safety tests."""
    
    def test_circuit_breaker_concurrent_access(self):
        breaker = AdvancedCircuitBreaker()
        errors = []
        
        def worker():
            try:
                for _ in range(100):
                    try:
                        breaker.execute(lambda: time.sleep(0.001))
                    except Exception:
                        pass
            except Exception as e:
                errors.append(e)
        
        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert len(errors) == 0
    
    def test_bulkhead_concurrent_access(self):
        bulkhead = BulkheadIsolator(BulkheadConfig(max_concurrent_calls=5))
        errors = []
        
        def worker():
            try:
                for _ in range(20):
                    bulkhead.execute(lambda: time.sleep(0.001))
            except Exception as e:
                errors.append(e)
        
        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        # Some timeouts are expected under load, but no crashes
        for e in errors:
            assert isinstance(e, BulkheadTimeoutError)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
