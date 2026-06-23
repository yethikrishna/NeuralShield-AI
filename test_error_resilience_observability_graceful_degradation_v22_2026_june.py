"""
Test Suite for NeuralShield Error Resilience v22
===============================================
DIMENSION E - Error Resilience
ADD-ONLY COMPLIANT - NO PRODUCTION CODE MODIFIED

Covers:
1. Custom exception hierarchy
2. Circuit breaker state machine
3. Bulkhead concurrency limiting
4. Retry with backoff strategies
5. Timeout with jitter
6. Graceful degradation fallbacks
7. Singleton pattern
8. Backward compatibility
9. Thread safety
10. Observability v12 integration wrappers
"""

import pytest
import time
import threading
from unittest.mock import Mock, patch

from neural_shield.error_resilience_observability_graceful_degradation_v22_2026_june import (
    # Exceptions
    NeuralShieldResilienceError,
    TimeoutError,
    CircuitBreakerOpenError,
    RetryExhaustedError,
    BulkheadFullError,
    FallbackActivatedError,
    
    # Enums
    CircuitState,
    BackoffStrategy,
    FallbackStrategy,
    
    # Config
    ResilienceConfigV22,
    TimeoutConfig,
    CircuitBreakerConfig,
    RetryConfig,
    BulkheadConfig,
    FallbackConfig,
    
    # Components
    CircuitBreaker,
    Bulkhead,
    DegradationCache,
    calculate_backoff,
    
    # Main class
    NeuralShieldResilienceV22,
    ObservabilityResilienceWrappersV22,
    
    # Accessors
    get_resilience_manager,
    RESILIENCE_VERSION,
    RESILIENCE_FEATURES
)


# -----------------------------------------------------------------------------
# Test 1: Exception Hierarchy
# -----------------------------------------------------------------------------
class TestExceptionHierarchyV22:
    """Test custom exception hierarchy"""
    
    def test_base_exception_inheritance(self):
        """All resilience exceptions inherit from base class"""
        assert issubclass(TimeoutError, NeuralShieldResilienceError)
        assert issubclass(CircuitBreakerOpenError, NeuralShieldResilienceError)
        assert issubclass(RetryExhaustedError, NeuralShieldResilienceError)
        assert issubclass(BulkheadFullError, NeuralShieldResilienceError)
        assert issubclass(FallbackActivatedError, NeuralShieldResilienceError)
    
    def test_timeout_error_message_format(self):
        """Timeout error contains operation name and timing info"""
        err = TimeoutError("test_op", 5.0, 6.5)
        assert "test_op" in str(err)
        assert "6.5" in str(err)
        assert "5.0" in str(err)
        assert err.operation == "test_op"
        assert err.timeout_seconds == 5.0
        assert err.elapsed_seconds == 6.5
    
    def test_circuit_breaker_error_message(self):
        """Circuit breaker error contains circuit name and recovery time"""
        err = CircuitBreakerOpenError("test_circuit", 25.5)
        assert "test_circuit" in str(err)
        assert "25.5" in str(err)
        assert err.circuit_name == "test_circuit"
        assert err.recovery_time_remaining == 25.5
    
    def test_retry_exhausted_error_message(self):
        """Retry error contains attempts and original error"""
        original = ValueError("original error")
        err = RetryExhaustedError("test_op", 3, original)
        assert "test_op" in str(err)
        assert "3" in str(err)
        assert "original error" in str(err)
        assert err.attempts == 3
        assert err.last_error is original
    
    def test_bulkhead_full_error_message(self):
        """Bulkhead error contains concurrency info"""
        err = BulkheadFullError("test_bh", 100, 100)
        assert "test_bh" in str(err)
        assert "100/100" in str(err)
        assert err.current_concurrency == 100


# -----------------------------------------------------------------------------
# Test 2: Circuit Breaker State Machine
# -----------------------------------------------------------------------------
class TestCircuitBreakerV22:
    """Test circuit breaker state transitions"""
    
    def test_initial_state_closed(self):
        """Circuit breaker starts in CLOSED state"""
        config = CircuitBreakerConfig(enabled=True)
        cb = CircuitBreaker("test", config)
        assert cb.state == CircuitState.CLOSED
        assert cb.allow_request() is True
    
    def test_transitions_to_open_after_failures(self):
        """Circuit opens after threshold failures"""
        config = CircuitBreakerConfig(enabled=True, failure_threshold=3)
        cb = CircuitBreaker("test", config)
        
        for _ in range(3):
            cb.record_failure()
        
        assert cb.state == CircuitState.OPEN
        assert cb.allow_request() is False
    
    def test_transitions_to_half_open_after_timeout(self):
        """Circuit enters half-open after reset timeout"""
        config = CircuitBreakerConfig(enabled=True, failure_threshold=2, reset_timeout_seconds=0.1)
        cb = CircuitBreaker("test", config)
        
        cb.record_failure()
        cb.record_failure()
        assert cb.state == CircuitState.OPEN
        
        time.sleep(0.15)
        assert cb.allow_request() is True  # Triggers transition check
        assert cb.state == CircuitState.HALF_OPEN
    
    def test_recloses_after_successes_in_half_open(self):
        """Circuit re-closes after successful recovery attempts"""
        config = CircuitBreakerConfig(enabled=True, failure_threshold=2, success_threshold=2, reset_timeout_seconds=0.1)
        cb = CircuitBreaker("test", config)
        
        # Trip circuit
        cb.record_failure()
        cb.record_failure()
        
        # Wait for half-open
        time.sleep(0.15)
        cb.allow_request()  # Trigger transition
        
        # Recovery successes
        cb.record_success()
        cb.record_success()
        
        assert cb.state == CircuitState.CLOSED
    
    def test_reopens_on_failure_in_half_open(self):
        """Circuit re-opens if recovery fails"""
        config = CircuitBreakerConfig(enabled=True, failure_threshold=2, reset_timeout_seconds=0.1)
        cb = CircuitBreaker("test", config)
        
        cb.record_failure()
        cb.record_failure()
        time.sleep(0.15)
        cb.allow_request()
        
        cb.record_failure()
        assert cb.state == CircuitState.OPEN
    
    def test_recovery_time_calculation(self):
        """Recovery time remaining calculated correctly"""
        config = CircuitBreakerConfig(enabled=True, failure_threshold=2, reset_timeout_seconds=1.0)
        cb = CircuitBreaker("test", config)
        
        assert cb.get_recovery_time_remaining() == 0.0
        
        cb.record_failure()
        cb.record_failure()
        
        remaining = cb.get_recovery_time_remaining()
        assert 0 < remaining <= 1.0


# -----------------------------------------------------------------------------
# Test 3: Bulkhead Concurrency Limiting
# -----------------------------------------------------------------------------
class TestBulkheadV22:
    """Test bulkhead isolation"""
    
    def test_bulkhead_acquire_release(self):
        """Basic acquire/release works"""
        config = BulkheadConfig(enabled=True, max_concurrent_operations=5)
        bh = Bulkhead("test", config)
        
        assert bh.acquire() is True
        assert bh.current_concurrency == 1
        
        bh.release()
        assert bh.current_concurrency == 0
    
    def test_bulkhead_blocks_at_capacity(self):
        """Bulkhead rejects when at max capacity"""
        config = BulkheadConfig(enabled=True, max_concurrent_operations=2, max_waiting_operations=0)
        bh = Bulkhead("test", config)
        
        bh.acquire()
        bh.acquire()
        
        # Third acquire should fail
        assert bh.acquire() is False
        assert bh.current_concurrency == 2
    
    def test_bulkhead_context_manager(self):
        """Context manager works correctly"""
        config = BulkheadConfig(enabled=True, max_concurrent_operations=1)
        bh = Bulkhead("test", config)
        
        with bh:
            assert bh.current_concurrency == 1
        
        assert bh.current_concurrency == 0
    
    def test_bulkhead_no_op_when_disabled(self):
        """Bulkhead is no-op when disabled"""
        config = BulkheadConfig(enabled=False)
        bh = Bulkhead("test", config)
        
        for _ in range(1000):
            assert bh.acquire() is True
        assert bh.current_concurrency == 0
    
    def test_bulkhead_thread_safety(self):
        """Bulkhead handles concurrent access"""
        config = BulkheadConfig(enabled=True, max_concurrent_operations=10)
        bh = Bulkhead("test", config)
        
        errors = []
        
        def worker():
            try:
                with bh:
                    time.sleep(0.01)
            except Exception as e:
                errors.append(e)
        
        threads = [threading.Thread(target=worker) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert len(errors) == 0
        assert bh.current_concurrency == 0


# -----------------------------------------------------------------------------
# Test 4: Backoff Calculation
# -----------------------------------------------------------------------------
class TestBackoffCalculationV22:
    """Test backoff strategy calculations"""
    
    def test_fixed_backoff(self):
        """Fixed strategy returns constant delay"""
        config = RetryConfig(backoff_strategy=BackoffStrategy.FIXED, initial_delay_seconds=0.5)
        
        for attempt in range(1, 6):
            delay = calculate_backoff(attempt, config)
            assert delay == pytest.approx(0.5, abs=0.01)
    
    def test_linear_backoff(self):
        """Linear strategy scales with attempt"""
        config = RetryConfig(backoff_strategy=BackoffStrategy.LINEAR, initial_delay_seconds=0.1)
        
        assert calculate_backoff(1, config) == pytest.approx(0.1, abs=0.01)
        assert calculate_backoff(2, config) == pytest.approx(0.2, abs=0.01)
        assert calculate_backoff(3, config) == pytest.approx(0.3, abs=0.01)
    
    def test_exponential_backoff(self):
        """Exponential strategy doubles each attempt"""
        config = RetryConfig(backoff_strategy=BackoffStrategy.EXPONENTIAL, initial_delay_seconds=0.1)
        
        assert calculate_backoff(1, config) == pytest.approx(0.1, abs=0.01)
        assert calculate_backoff(2, config) == pytest.approx(0.2, abs=0.01)
        assert calculate_backoff(3, config) == pytest.approx(0.4, abs=0.01)
        assert calculate_backoff(4, config) == pytest.approx(0.8, abs=0.01)
    
    def test_decorrelated_jitter_backoff(self):
        """Jittered backoff produces varying delays"""
        config = RetryConfig(backoff_strategy=BackoffStrategy.DECORRELATED_JITTER, initial_delay_seconds=0.1)
        
        delays = [calculate_backoff(3, config) for _ in range(10)]
        # Should have some variation due to jitter
        assert len(set(round(d, 4) for d in delays)) > 1
    
    def test_max_delay_cap(self):
        """Backoff respects max delay cap"""
        config = RetryConfig(
            backoff_strategy=BackoffStrategy.EXPONENTIAL,
            initial_delay_seconds=1.0,
            max_delay_seconds=5.0
        )
        
        assert calculate_backoff(10, config) <= 5.0


# -----------------------------------------------------------------------------
# Test 5: Degradation Cache
# -----------------------------------------------------------------------------
class TestDegradationCacheV22:
    """Test graceful degradation cache"""
    
    def test_cache_put_get(self):
        """Basic cache operations work"""
        cache = DegradationCache(ttl_seconds=60)
        
        cache.put("key1", "value1")
        assert cache.get("key1") == "value1"
    
    def test_cache_miss_returns_none(self):
        """Missing key returns None"""
        cache = DegradationCache()
        assert cache.get("nonexistent") is None
    
    def test_cache_expires_after_ttl(self):
        """Cache entries expire after TTL"""
        cache = DegradationCache(ttl_seconds=0.1)
        
        cache.put("key1", "value1")
        assert cache.get("key1") == "value1"
        
        time.sleep(0.15)
        assert cache.get("key1") is None
    
    def test_cache_clear(self):
        """Cache clear removes all entries"""
        cache = DegradationCache()
        
        cache.put("key1", "value1")
        cache.put("key2", "value2")
        cache.clear()
        
        assert cache.get("key1") is None
        assert cache.get("key2") is None


# -----------------------------------------------------------------------------
# Test 6: Main Resilience Manager
# -----------------------------------------------------------------------------
class TestNeuralShieldResilienceV22:
    """Test main resilience manager"""
    
    def setup_method(self):
        """Reset singleton before each test"""
        NeuralShieldResilienceV22._instance = None
    
    def test_singleton_pattern(self):
        """Manager implements singleton pattern"""
        m1 = NeuralShieldResilienceV22.get_instance()
        m2 = NeuralShieldResilienceV22.get_instance()
        assert m1 is m2
    
    def test_all_features_disabled_by_default(self):
        """ALL features DISABLED by default - OPT-IN philosophy"""
        manager = NeuralShieldResilienceV22.get_instance()
        
        assert manager.config.timeout.enabled is False
        assert manager.config.circuit_breaker.enabled is False
        assert manager.config.retry.enabled is False
        assert manager.config.bulkhead.enabled is False
        assert manager.config.fallback.enabled is False
    
    def test_enable_all_convenience(self):
        """enable_all() turns on all features"""
        manager = NeuralShieldResilienceV22.get_instance()
        manager.enable_all()
        
        assert manager.config.timeout.enabled is True
        assert manager.config.circuit_breaker.enabled is True
        assert manager.config.retry.enabled is True
        assert manager.config.bulkhead.enabled is True
        assert manager.config.fallback.enabled is True
    
    def test_fallback_returns_default_when_enabled(self):
        """Fallback returns default value on exception"""
        manager = NeuralShieldResilienceV22.get_instance()
        manager.enable_all()
        
        def failing_func():
            raise ValueError("test error")
        
        wrapped = manager.wrap_with_fallback(failing_func, fallback_value="safe_default")
        result = wrapped()
        assert result == "safe_default"
    
    def test_no_op_when_disabled(self):
        """All wrappers are no-op when disabled"""
        manager = NeuralShieldResilienceV22.get_instance()
        
        call_count = [0]
        def test_func():
            call_count[0] += 1
            return "success"
        
        wrapped = manager.wrap_all(test_func)
        result = wrapped()
        
        assert result == "success"
        assert call_count[0] == 1
    
    def test_retry_retries_on_failure(self):
        """Retry wrapper retries configured number of times"""
        manager = NeuralShieldResilienceV22.get_instance()
        manager.config.retry.enabled = True
        manager.config.retry.max_attempts = 3
        
        call_count = [0]
        def flaky_func():
            call_count[0] += 1
            if call_count[0] < 3:
                raise ValueError("temporary failure")
            return "success"
        
        wrapped = manager.wrap_with_retry(flaky_func)
        result = wrapped()
        
        assert result == "success"
        assert call_count[0] == 3
    
    def test_status_summary(self):
        """Status summary returns correct structure"""
        manager = NeuralShieldResilienceV22.get_instance()
        status = manager.get_status_summary()
        
        assert "version" in status
        assert status["version"] == "v22"
        assert "enabled_features" in status
        assert "circuit_breakers" in status
        assert "bulkheads" in status


# -----------------------------------------------------------------------------
# Test 7: Observability Integration Wrappers
# -----------------------------------------------------------------------------
class TestObservabilityResilienceWrappersV22:
    """Test pre-built wrappers for observability v12"""
    
    def setup_method(self):
        NeuralShieldResilienceV22._instance = None
    
    def test_docs_search_wrapper_exists(self):
        """Docs search wrapper available"""
        wrapper = ObservabilityResilienceWrappersV22.get_resilient_docs_search
        assert callable(wrapper)
    
    def test_docs_lookup_wrapper_exists(self):
        """Docs lookup wrapper available"""
        wrapper = ObservabilityResilienceWrappersV22.get_resilient_docs_lookup
        assert callable(wrapper)
    
    def test_prometheus_export_wrapper_exists(self):
        """Prometheus export wrapper available"""
        wrapper = ObservabilityResilienceWrappersV22.get_resilient_prometheus_export
        assert callable(wrapper)
    
    def test_health_check_wrapper_exists(self):
        """Health check wrapper available"""
        wrapper = ObservabilityResilienceWrappersV22.get_resilient_health_check
        assert callable(wrapper)
    
    def test_threat_intel_wrapper_exists(self):
        """Threat intel feed wrapper available"""
        wrapper = ObservabilityResilienceWrappersV22.get_resilient_threat_intel_feed
        assert callable(wrapper)
    
    def test_wrappers_passthrough_when_disabled(self):
        """All wrappers pass through when resilience disabled"""
        def original_func(x):
            return x * 2
        
        wrapped = ObservabilityResilienceWrappersV22.get_resilient_docs_search(original_func)
        assert wrapped(5) == 10


# -----------------------------------------------------------------------------
# Test 8: Backward Compatibility
# -----------------------------------------------------------------------------
class TestBackwardCompatibilityV22:
    """Test backward compatibility guarantees"""
    
    def setup_method(self):
        NeuralShieldResilienceV22._instance = None
    
    def test_legacy_accessor_works(self):
        """Legacy get_resilience_manager accessor works"""
        manager = get_resilience_manager()
        assert isinstance(manager, NeuralShieldResilienceV22)
    
    def test_version_identification(self):
        """Version constants available"""
        assert RESILIENCE_VERSION == "v22"
        assert len(RESILIENCE_FEATURES) > 0
    
    def test_no_breaking_changes_to_config(self):
        """Config objects have expected structure"""
        config = ResilienceConfigV22()
        assert hasattr(config, "timeout")
        assert hasattr(config, "circuit_breaker")
        assert hasattr(config, "retry")
        assert hasattr(config, "bulkhead")
        assert hasattr(config, "fallback")
    
    def test_happy_path_preserved(self):
        """Happy path behavior 100% preserved when disabled"""
        manager = NeuralShieldResilienceV22.get_instance()
        
        def original(a, b, c=3):
            return a + b + c
        
        wrapped = manager.wrap_all(original)
        
        # Original function signature and behavior preserved
        assert wrapped(1, 2) == 6  # 1+2+3
        assert wrapped(1, 2, c=10) == 13
        assert wrapped(10, 20, 30) == 60


# -----------------------------------------------------------------------------
# Test 9: Error Path Coverage
# -----------------------------------------------------------------------------
class TestErrorPathsV22:
    """Test edge cases and error paths"""
    
    def setup_method(self):
        NeuralShieldResilienceV22._instance = None
    
    def test_retry_exhausted_raises(self):
        """RetryExhaustedError raised when all attempts fail"""
        manager = NeuralShieldResilienceV22.get_instance()
        manager.config.retry.enabled = True
        manager.config.retry.max_attempts = 2
        
        def always_fails():
            raise ValueError("permanent failure")
        
        wrapped = manager.wrap_with_retry(always_fails)
        
        with pytest.raises(RetryExhaustedError) as exc:
            wrapped()
        
        assert exc.value.attempts == 2
    
    def test_circuit_breaker_rejects_when_open(self):
        """CircuitBreakerOpenError raised when circuit open"""
        manager = NeuralShieldResilienceV22.get_instance()
        manager.config.circuit_breaker.enabled = True
        manager.config.circuit_breaker.failure_threshold = 2
        
        def always_fails():
            raise ValueError("failure")
        
        wrapped = manager.wrap_with_circuit_breaker(always_fails, "test_circuit")
        
        # Trip the circuit
        for _ in range(2):
            try:
                wrapped()
            except ValueError:
                pass
        
        # Now should raise CircuitBreakerOpenError
        with pytest.raises(CircuitBreakerOpenError):
            wrapped()
    
    def test_fallback_uses_cached_value(self):
        """Fallback returns cached value when strategy is RETURN_CACHED"""
        manager = NeuralShieldResilienceV22.get_instance()
        manager.config.fallback.enabled = True
        manager.config.fallback.default_strategy = FallbackStrategy.RETURN_CACHED
        
        call_count = [0]
        
        def sometimes_fails():
            call_count[0] += 1
            if call_count[0] == 1:
                return "good_value"
            raise ValueError("failed")
        
        wrapped = manager.wrap_with_fallback(sometimes_fails)
        
        # First call succeeds and caches
        assert wrapped() == "good_value"
        # Second call fails but returns cached
        assert wrapped() == "good_value"


# -----------------------------------------------------------------------------
# Test 10: Thread Safety Validation
# -----------------------------------------------------------------------------
class TestThreadSafetyV22:
    """Test concurrent access safety"""
    
    def setup_method(self):
        NeuralShieldResilienceV22._instance = None
    
    def test_concurrent_singleton_access(self):
        """Singleton handles concurrent initialization"""
        instances = []
        
        def get_instance():
            instances.append(NeuralShieldResilienceV22.get_instance())
        
        threads = [threading.Thread(target=get_instance) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        # All should be the same instance
        assert all(i is instances[0] for i in instances)
    
    def test_concurrent_circuit_breaker_access(self):
        """Circuit breaker handles concurrent recording"""
        config = CircuitBreakerConfig(enabled=True, failure_threshold=100)
        cb = CircuitBreaker("test", config)
        
        def record_failures():
            for _ in range(10):
                cb.record_failure()
        
        threads = [threading.Thread(target=record_failures) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert cb._failure_count == 100


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
