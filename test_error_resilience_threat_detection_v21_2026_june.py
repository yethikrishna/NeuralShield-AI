"""
Test Suite for Error Resilience Framework v21
NeuralShield-AI | Session 129 | Dimension E

STRICT DIMENSION C COMPLIANCE:
- Only tests added - NO PRODUCTION CODE MODIFIED
- All existing tests must continue to pass
- All new tests must pass
"""

import unittest
import time
import threading
from unittest.mock import patch, MagicMock

# Import the new resilience module
import sys
sys.path.insert(0, '/home/user/autonomous-developer/NeuralShield-AI')

from neural_shield.error_resilience_threat_detection_v21_2026_june import (
    # Exceptions
    NeuralShieldError,
    ThreatDetectionError,
    DetectionTimeoutError,
    DetectionFailedError,
    DetectionTemporaryError,
    DetectionPermanentError,
    ResourceExhaustedError,
    CircuitBreakerOpenError,
    FallbackActivatedError,
    
    # Circuit Breaker
    CircuitState,
    CircuitBreakerConfig,
    CircuitBreaker,
    get_circuit_breaker,
    
    # Timeout
    Timeout,
    timeout,
    
    # Retry
    RetryConfig,
    RetryStrategy,
    retry,
    
    # Fallback
    FallbackStrategy,
    with_fallback,
    
    # Bulkhead
    Bulkhead,
    get_bulkhead,
    
    # Factories
    create_resilient_detector,
    create_simple_resilience_wrapper,
    
    # Version
    get_version_info,
    is_backward_compatible,
    VERSION,
    VERSION_CODE
)


class TestCustomExceptionHierarchy(unittest.TestCase):
    """Test custom exception hierarchy and properties."""
    
    def test_base_exception_properties(self):
        """Test base exception has all required properties."""
        err = NeuralShieldError("test message", "NS_TEST_001", True, {"key": "value"})
        self.assertEqual(str(err), "test message")
        self.assertEqual(err.error_code, "NS_TEST_001")
        self.assertTrue(err.retryable)
        self.assertEqual(err.details["key"], "value")
        self.assertIsNotNone(err.timestamp)
    
    def test_exception_inheritance(self):
        """Test proper exception inheritance chain."""
        self.assertTrue(issubclass(ThreatDetectionError, NeuralShieldError))
        self.assertTrue(issubclass(DetectionTimeoutError, ThreatDetectionError))
        self.assertTrue(issubclass(DetectionFailedError, ThreatDetectionError))
        self.assertTrue(issubclass(DetectionTemporaryError, ThreatDetectionError))
        self.assertTrue(issubclass(DetectionPermanentError, ThreatDetectionError))
        self.assertTrue(issubclass(ResourceExhaustedError, NeuralShieldError))
        self.assertTrue(issubclass(CircuitBreakerOpenError, NeuralShieldError))
    
    def test_timeout_exception_details(self):
        """Test timeout exception includes timeout seconds."""
        err = DetectionTimeoutError(timeout_seconds=5.5)
        self.assertEqual(err.details["timeout_seconds"], 5.5)
        self.assertTrue(err.retryable)
    
    def test_permanent_error_not_retryable(self):
        """Test permanent errors are NOT retryable."""
        err = DetectionPermanentError()
        self.assertFalse(err.retryable)
    
    def test_temporary_error_is_retryable(self):
        """Test temporary errors ARE retryable."""
        err = DetectionTemporaryError(retry_after_seconds=2.0)
        self.assertTrue(err.retryable)
        self.assertEqual(err.details["retry_after_seconds"], 2.0)


class TestCircuitBreaker(unittest.TestCase):
    """Test Circuit Breaker pattern implementation."""
    
    def test_circuit_starts_closed(self):
        """New circuit breaker should start in CLOSED state."""
        cb = CircuitBreaker("test")
        self.assertEqual(cb.state, CircuitState.CLOSED)
        self.assertEqual(cb.stats.total_calls, 0)
    
    def test_successful_call_no_state_change(self):
        """Successful calls should keep circuit CLOSED."""
        cb = CircuitBreaker("test", CircuitBreakerConfig(failure_threshold=3))
        
        def success_func():
            return "success"
        
        for _ in range(10):
            result = cb.execute(success_func)
            self.assertEqual(result, "success")
        
        self.assertEqual(cb.state, CircuitState.CLOSED)
        self.assertEqual(cb.stats.success_count, 10)
        self.assertEqual(cb.stats.failure_count, 0)
    
    def test_failure_threshold_opens_circuit(self):
        """Circuit should OPEN after exceeding failure threshold."""
        cb = CircuitBreaker("test", CircuitBreakerConfig(
            failure_threshold=2,
            reset_timeout_seconds=30.0
        ))
        
        def failing_func():
            raise DetectionFailedError("test failure")
        
        # First failure
        with self.assertRaises(DetectionFailedError):
            cb.execute(failing_func)
        self.assertEqual(cb.state, CircuitState.CLOSED)
        
        # Second failure - should open circuit
        with self.assertRaises(DetectionFailedError):
            cb.execute(failing_func)
        self.assertEqual(cb.state, CircuitState.OPEN)
    
    def test_open_circuit_blocks_calls(self):
        """Open circuit should block calls with CircuitBreakerOpenError."""
        cb = CircuitBreaker("test", CircuitBreakerConfig(
            failure_threshold=1,
            reset_timeout_seconds=30.0
        ))
        
        def failing_func():
            raise DetectionFailedError("test")
        
        # Trigger circuit open
        with self.assertRaises(DetectionFailedError):
            cb.execute(failing_func)
        
        # Next call should be blocked
        with self.assertRaises(CircuitBreakerOpenError) as ctx:
            cb.execute(failing_func)
        
        self.assertEqual(ctx.exception.details["circuit_name"], "test")
        self.assertGreater(cb.stats.rejected_calls, 0)
    
    def test_circuit_decorator_usage(self):
        """Test circuit breaker as a decorator."""
        cb = CircuitBreaker("decorator_test")
        
        @cb
        def my_func():
            return "decorated"
        
        self.assertEqual(my_func(), "decorated")
    
    def test_circuit_reset(self):
        """Manual reset should return circuit to CLOSED state."""
        cb = CircuitBreaker("test", CircuitBreakerConfig(failure_threshold=1))
        
        def failing_func():
            raise DetectionFailedError("test")
        
        with self.assertRaises(DetectionFailedError):
            cb.execute(failing_func)
        
        cb.reset()
        self.assertEqual(cb.state, CircuitState.CLOSED)
        self.assertEqual(cb.stats.total_calls, 0)
    
    def test_global_registry(self):
        """Test circuit breaker registry returns same instance."""
        cb1 = get_circuit_breaker("registry_test")
        cb2 = get_circuit_breaker("registry_test")
        self.assertIs(cb1, cb2)


class TestTimeoutWrapper(unittest.TestCase):
    """Test timeout wrapper functionality."""
    
    def test_timeout_decorator_completes(self):
        """Function completing within timeout should succeed."""
        @timeout(seconds=1.0)
        def quick_func():
            return "done"
        
        self.assertEqual(quick_func(), "done")
    
    def test_timeout_decorator_raises(self):
        """Function exceeding timeout should raise DetectionTimeoutError."""
        @timeout(seconds=0.1)
        def slow_func():
            time.sleep(0.5)
            return "too slow"
        
        with self.assertRaises(DetectionTimeoutError):
            slow_func()
    
    def test_timeout_context_manager(self):
        """Test timeout as context manager."""
        with timeout(seconds=1.0):
            result = "success"
        
        self.assertEqual(result, "success")
    
    def test_timeout_preserves_original_exception(self):
        """Non-timeout exceptions should propagate normally."""
        @timeout(seconds=1.0)
        def error_func():
            raise ValueError("original error")
        
        with self.assertRaises(ValueError):
            error_func()


class TestRetryStrategy(unittest.TestCase):
    """Test retry with exponential backoff."""
    
    def test_retry_succeeds_eventually(self):
        """Function that fails then succeeds should eventually succeed."""
        call_count = [0]
        
        @retry(max_attempts=3, initial_delay_seconds=0.01)
        def flaky_func():
            call_count[0] += 1
            if call_count[0] < 3:
                raise DetectionTemporaryError("temporary failure")
            return "success"
        
        result = flaky_func()
        self.assertEqual(result, "success")
        self.assertEqual(call_count[0], 3)
    
    def test_retry_max_attempts_exceeded(self):
        """Function always failing should raise after max attempts."""
        call_count = [0]
        
        @retry(max_attempts=2, initial_delay_seconds=0.01)
        def always_fails():
            call_count[0] += 1
            raise DetectionTemporaryError("always fails")
        
        with self.assertRaises(DetectionTemporaryError):
            always_fails()
        
        self.assertEqual(call_count[0], 2)
    
    def test_retry_only_configured_exceptions(self):
        """Non-configured exceptions should NOT be retried."""
        call_count = [0]
        
        @retry(max_attempts=3, initial_delay_seconds=0.01)
        def permanent_fail():
            call_count[0] += 1
            raise DetectionPermanentError("permanent")
        
        with self.assertRaises(DetectionPermanentError):
            permanent_fail()
        
        self.assertEqual(call_count[0], 1)  # No retry
    
    def test_retry_delay_calculation(self):
        """Test backoff delay calculation with jitter."""
        config = RetryConfig(
            initial_delay_seconds=0.1,
            backoff_factor=2.0,
            max_delay_seconds=1.0
        )
        strategy = RetryStrategy(config)
        
        delays = [strategy._calculate_delay(i) for i in range(5)]
        
        # Should increase exponentially
        self.assertLess(delays[0], delays[1])
        self.assertLess(delays[1], delays[2])
        # Should not exceed max_delay
        for d in delays:
            self.assertLessEqual(d, 1.0)


class TestFallbackStrategy(unittest.TestCase):
    """Test graceful degradation fallbacks."""
    
    def test_primary_succeeds_no_fallback(self):
        """Primary succeeding should not call fallbacks."""
        strategy = FallbackStrategy()
        
        def primary():
            return "primary"
        
        def fallback():
            return "fallback"
        
        strategy.add_fallback(fallback)
        result = strategy.execute(primary)
        self.assertEqual(result, "primary")
    
    def test_primary_fails_fallback_succeeds(self):
        """Primary failing should activate fallback."""
        strategy = FallbackStrategy()
        call_tracker = {"fallback": False}
        
        def primary():
            raise DetectionFailedError("primary failed")
        
        def fallback():
            call_tracker["fallback"] = True
            return "fallback result"
        
        strategy.add_fallback(fallback)
        result = strategy.execute(primary)
        self.assertEqual(result, "fallback result")
        self.assertTrue(call_tracker["fallback"])
    
    def test_fallback_chain(self):
        """Multiple fallbacks should be tried in order."""
        strategy = FallbackStrategy()
        call_order = []
        
        def primary():
            call_order.append("primary")
            raise DetectionFailedError()
        
        def fallback1():
            call_order.append("fallback1")
            raise DetectionFailedError()
        
        def fallback2():
            call_order.append("fallback2")
            return "fallback2 result"
        
        strategy.add_fallback(fallback1)
        strategy.add_fallback(fallback2)
        
        result = strategy.execute(primary)
        self.assertEqual(result, "fallback2 result")
        self.assertEqual(call_order, ["primary", "fallback1", "fallback2"])
    
    def test_default_fallback(self):
        """Default fallback should be last resort."""
        strategy = FallbackStrategy()
        
        def primary():
            raise DetectionFailedError()
        
        def default():
            return "default"
        
        strategy.set_default(default)
        result = strategy.execute(primary)
        self.assertEqual(result, "default")
    
    def test_all_fallbacks_fail(self):
        """All fallbacks failing should raise permanent error."""
        strategy = FallbackStrategy()
        
        def primary():
            raise DetectionFailedError("primary")
        
        def fallback():
            raise DetectionFailedError("fallback")
        
        strategy.add_fallback(fallback)
        
        with self.assertRaises(DetectionPermanentError) as ctx:
            strategy.execute(primary)
        
        self.assertIn("failures", ctx.exception.details)


class TestBulkheadIsolation(unittest.TestCase):
    """Test bulkhead resource isolation."""
    
    def test_bulkhead_executes_successfully(self):
        """Bulkhead should execute functions normally."""
        bulkhead = Bulkhead("test", max_concurrent=5)
        
        def my_func():
            return "success"
        
        result = bulkhead.execute(my_func)
        self.assertEqual(result, "success")
        self.assertEqual(bulkhead.stats["executed"], 1)
    
    def test_bulkhead_queue_rejection(self):
        """Bulkhead should reject when queue is full."""
        bulkhead = Bulkhead("reject_test", max_concurrent=1, max_queue_size=0)
        
        def slow_func():
            time.sleep(0.2)
            return "done"
        
        # Start one function to occupy the slot
        t = threading.Thread(target=lambda: bulkhead.execute(slow_func))
        t.start()
        time.sleep(0.01)  # Give thread time to acquire semaphore
        
        # Next call should be rejected immediately
        with self.assertRaises(ResourceExhaustedError):
            bulkhead.execute(lambda: "too late")
        
        t.join()
    
    def test_bulkhead_decorator(self):
        """Test bulkhead as decorator."""
        bulkhead = Bulkhead("decorator")
        
        @bulkhead
        def decorated():
            return "decorated"
        
        self.assertEqual(decorated(), "decorated")
    
    def test_bulkhead_registry(self):
        """Test bulkhead registry returns same instance."""
        b1 = get_bulkhead("registry_test")
        b2 = get_bulkhead("registry_test")
        self.assertIs(b1, b2)


class TestFactoryFunctions(unittest.TestCase):
    """Test convenience factory functions."""
    
    def test_create_resilient_detector(self):
        """Test full resilience stack factory."""
        call_count = [0]
        
        def flaky_detector():
            call_count[0] += 1
            if call_count[0] < 2:
                raise DetectionTemporaryError("flaky")
            return {"threat": False}
        
        resilient = create_resilient_detector(
            flaky_detector,
            name="test_detector",
            timeout_seconds=5.0,
            max_attempts=3,
            enable_circuit=True,
            enable_bulkhead=True
        )
        
        result = resilient()
        self.assertEqual(result["threat"], False)
        self.assertEqual(call_count[0], 2)
    
    def test_simple_wrapper(self):
        """Test simple resilience wrapper."""
        wrapper = create_simple_resilience_wrapper(
            timeout_seconds=1.0,
            max_attempts=2
        )
        
        @wrapper
        def my_func():
            return "wrapped"
        
        self.assertEqual(my_func(), "wrapped")


class TestVersionAndMetadata(unittest.TestCase):
    """Test version information and metadata."""
    
    def test_version_info(self):
        """Version info should contain all required fields."""
        info = get_version_info()
        self.assertEqual(info["version"], VERSION)
        self.assertEqual(info["version_code"], VERSION_CODE)
        self.assertEqual(info["dimension"], "E - Error Resilience")
        self.assertEqual(info["session"], "129")
        self.assertIn("features", info)
        self.assertGreater(len(info["features"]), 0)
    
    def test_backward_compatibility(self):
        """Should always be backward compatible."""
        self.assertTrue(is_backward_compatible())


class TestThreadSafety(unittest.TestCase):
    """Test thread safety of components."""
    
    def test_circuit_breaker_thread_safe(self):
        """Circuit breaker should handle concurrent access."""
        cb = CircuitBreaker("thread_test", CircuitBreakerConfig(failure_threshold=100))
        
        def worker():
            for _ in range(10):
                try:
                    cb.execute(lambda: "ok")
                except:
                    pass
        
        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        self.assertEqual(cb.stats.total_calls, 100)
    
    def test_bulkhead_concurrent_limit(self):
        """Bulkhead should enforce max_concurrent limit."""
        max_concurrent = 3
        bulkhead = Bulkhead("concurrent_test", max_concurrent=max_concurrent)
        active_count = [0]
        max_active = [0]
        lock = threading.Lock()
        
        def limited_func():
            with lock:
                active_count[0] += 1
                max_active[0] = max(max_active[0], active_count[0])
            time.sleep(0.05)
            with lock:
                active_count[0] -= 1
        
        def worker():
            bulkhead.execute(limited_func)
        
        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        # Should never exceed max_concurrent
        self.assertLessEqual(max_active[0], max_concurrent)


if __name__ == '__main__':
    unittest.main(verbosity=2)
