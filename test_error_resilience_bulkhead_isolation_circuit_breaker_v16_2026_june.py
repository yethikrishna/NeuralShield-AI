"""
Tests for NeuralShield Error Resilience: Bulkhead Isolation Circuit Breaker v16
Dimension E - Error Resilience Enhancement
ADD-ONLY TESTS: No existing production code modified
"""

import pytest
import time
import threading
from unittest.mock import Mock, patch

from neural_shield.error_resilience_bulkhead_isolation_circuit_breaker_v16_2026_june import (
    CircuitState,
    BulkheadStatus,
    CircuitBreakerConfig,
    BulkheadConfig,
    CircuitBreaker,
    BulkheadIsolation,
    IsolatedModuleRegistry,
    isolated_module,
    get_registry,
    CircuitOpenError,
    BulkheadRejectedError,
    BulkheadTimeoutError,
    empty_dict_fallback,
    none_fallback,
    false_fallback,
    zero_score_fallback,
)


class TestBulkheadIsolation:
    """Tests for BulkheadIsolation class"""

    def test_bulkhead_successful_execution(self):
        """Test normal successful execution through bulkhead"""
        bulkhead = BulkheadIsolation("test_module")
        
        def success_func(x, y):
            return x + y
        
        result = bulkhead.execute(success_func, 2, 3)
        assert result == 5
        
        metrics = bulkhead.get_metrics()
        assert metrics["successful_requests"] == 1
        assert metrics["total_requests"] == 1
        assert metrics["failed_requests"] == 0

    def test_bulkhead_exception_propagation(self):
        """Test that exceptions are properly propagated"""
        bulkhead = BulkheadIsolation("test_module")
        
        def error_func():
            raise ValueError("Test error")
        
        with pytest.raises(ValueError, match="Test error"):
            bulkhead.execute(error_func)
        
        metrics = bulkhead.get_metrics()
        assert metrics["failed_requests"] == 1

    def test_bulkhead_status_healthy(self):
        """Test bulkhead reports healthy status when not loaded"""
        bulkhead = BulkheadIsolation("test_module", BulkheadConfig(max_concurrent_requests=10))
        assert bulkhead.get_status() == BulkheadStatus.HEALTHY

    def test_bulkhead_metrics_tracking(self):
        """Test metrics are properly tracked"""
        bulkhead = BulkheadIsolation("test_module")
        
        def quick_func():
            return "ok"
        
        for _ in range(5):
            bulkhead.execute(quick_func)
        
        metrics = bulkhead.get_metrics()
        assert metrics["total_requests"] == 5
        assert metrics["successful_requests"] == 5
        assert metrics["avg_response_time_ms"] >= 0


class TestCircuitBreaker:
    """Tests for CircuitBreaker class"""

    def test_circuit_closed_normal_operation(self):
        """Test circuit allows requests when closed"""
        cb = CircuitBreaker("test_cb")
        
        def success_func():
            return "success"
        
        result = cb.execute(success_func)
        assert result == "success"
        assert cb.state == CircuitState.CLOSED

    def test_circuit_trips_after_failures(self):
        """Test circuit trips after exceeding failure threshold"""
        cb = CircuitBreaker("test_cb", CircuitBreakerConfig(failure_threshold=3))
        
        def failing_func():
            raise RuntimeError("Failure")
        
        # First 3 failures should trip the circuit
        for _ in range(3):
            with pytest.raises(RuntimeError):
                cb.execute(failing_func)
        
        # Circuit should now be open
        assert cb.state == CircuitState.OPEN
        
        # Next request should fail fast with CircuitOpenError
        with pytest.raises(CircuitOpenError):
            cb.execute(failing_func)

    def test_circuit_with_fallback(self):
        """Test fallback is used when circuit is open"""
        def my_fallback():
            return "fallback_result"
        
        cb = CircuitBreaker(
            "test_cb",
            CircuitBreakerConfig(failure_threshold=2),
            fallback=my_fallback
        )
        
        def failing_func():
            raise RuntimeError("Failure")
        
        # Trip the circuit
        for _ in range(2):
            with pytest.raises(RuntimeError):
                cb.execute(failing_func)
        
        # Now should use fallback
        result = cb.execute(failing_func)
        assert result == "fallback_result"

    def test_circuit_half_open_recovery(self):
        """Test circuit recovers after successful requests in half-open"""
        cb = CircuitBreaker(
            "test_cb",
            CircuitBreakerConfig(
                failure_threshold=2,
                success_threshold=2,
                reset_timeout_seconds=0.1
            )
        )
        
        def failing_func():
            raise RuntimeError("Failure")
        
        def success_func():
            return "ok"
        
        # Trip the circuit
        for _ in range(2):
            with pytest.raises(RuntimeError):
                cb.execute(failing_func)
        
        assert cb.state == CircuitState.OPEN
        
        # Wait for reset timeout
        time.sleep(0.15)
        
        # Should transition to HALF_OPEN on check
        assert cb.state == CircuitState.HALF_OPEN
        
        # Successful requests should close circuit
        cb.execute(success_func)
        cb.execute(success_func)
        assert cb.state == CircuitState.CLOSED

    def test_circuit_get_status(self):
        """Test status reporting"""
        cb = CircuitBreaker("test_cb")
        status = cb.get_status()
        
        assert "name" in status
        assert "state" in status
        assert "failure_count" in status
        assert "bulkhead" in status
        assert status["state"] == "CLOSED"


class TestIsolatedModuleRegistry:
    """Tests for IsolatedModuleRegistry class"""

    def test_register_and_get_module(self):
        """Test module registration and retrieval"""
        registry = IsolatedModuleRegistry()
        
        cb = registry.register_module("test_module")
        assert cb is not None
        
        retrieved = registry.get_module("test_module")
        assert retrieved is cb

    def test_get_all_statuses(self):
        """Test getting all module statuses"""
        registry = IsolatedModuleRegistry()
        registry.register_module("module1")
        registry.register_module("module2")
        
        statuses = registry.get_all_statuses()
        assert len(statuses) == 2
        assert "module1" in statuses
        assert "module2" in statuses

    def test_get_system_health(self):
        """Test system health summary"""
        registry = IsolatedModuleRegistry()
        registry.register_module("module1")
        registry.register_module("module2")
        
        health = registry.get_system_health()
        assert health["total_modules"] == 2
        assert health["healthy_modules"] == 2
        assert health["health_score"] == 1.0


class TestIsolatedModuleDecorator:
    """Tests for @isolated_module decorator"""

    def test_decorator_basic_functionality(self):
        """Test decorator wraps function correctly"""
        @isolated_module("decorated_func")
        def add(a, b):
            return a + b
        
        result = add(2, 3)
        assert result == 5

    def test_decorator_with_fallback(self):
        """Test decorator with fallback function"""
        def safe_fallback(*args, **kwargs):
            return "safe"
        
        @isolated_module("failing_func", fallback=safe_fallback)
        def always_fail():
            raise RuntimeError("Always fails")
        
        # First failures propagate
        for _ in range(5):
            with pytest.raises(RuntimeError):
                always_fail()
        
        # After circuit trips, fallback is used
        result = always_fail()
        assert result == "safe"


class TestDefaultFallbacks:
    """Tests for default fallback functions"""

    def test_empty_dict_fallback(self):
        assert empty_dict_fallback() == {}

    def test_none_fallback(self):
        assert none_fallback() is None

    def test_false_fallback(self):
        assert false_fallback() is False

    def test_zero_score_fallback(self):
        assert zero_score_fallback() == 0.0


class TestGlobalRegistry:
    """Tests for global registry"""

    def test_get_registry_returns_singleton(self):
        """Test get_registry returns same instance"""
        r1 = get_registry()
        r2 = get_registry()
        assert r1 is r2


class TestConcurrency:
    """Tests for concurrent execution"""

    def test_concurrent_bulkhead_requests(self):
        """Test bulkhead handles concurrent requests"""
        bulkhead = BulkheadIsolation(
            "concurrent_test",
            BulkheadConfig(max_concurrent_requests=5, max_waiting_requests=20)
        )
        
        results = []
        errors = []
        
        def worker():
            try:
                result = bulkhead.execute(lambda: time.sleep(0.01) or "ok")
                results.append(result)
            except Exception as e:
                errors.append(e)
        
        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert len(results) == 10
        assert len(errors) == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
