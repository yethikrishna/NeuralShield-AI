"""
Test Suite for NeuralShield Error Resilience Engine v12
DIMENSION E: Error Resilience - ADD-ONLY
All tests are NEW - no modifications to existing tests
"""

import sys
import time
import threading
import unittest
from typing import Dict, Any

# Add the source directory
sys.path.insert(0, '/home/user/autonomous-developer/NeuralShield-AI')

from neural_shield.error_resilience_enhanced_circuit_breaker_v12_2026_june import (
    # Exceptions
    NeuralShieldError,
    ThreatDetectionError,
    PromptInjectionDetectionError,
    ModelInferenceError,
    ModelTimeoutError,
    ConfigurationError,
    ValidationError,
    RateLimitExceededError,
    CircuitBreakerOpenError,
    GracefulDegradationError,
    
    # Circuit Breaker
    CircuitBreaker,
    CircuitState,
    
    # Retry
    retry,
    RetryStrategy,
    
    # Timeout
    timeout,
    
    # Graceful Degradation
    GracefulDegradation,
    FallbackStrategy,
    
    # Bulkhead
    Bulkhead,
    
    # Global functions
    get_circuit_breaker,
    get_bulkhead,
    get_graceful_degradation,
    safe_execute,
    get_all_resilience_stats
)

class TestCustomExceptionHierarchy(unittest.TestCase):
    """Test custom exception hierarchy"""
    
    def test_base_exception_attributes(self):
        err = NeuralShieldError("Test error", {"key": "value"})
        self.assertEqual(err.error_code, "NS_E001")
        self.assertFalse(err.retryable)
        self.assertEqual(err.severity, "ERROR")
        self.assertEqual(err.details, {"key": "value"})
        self.assertIsNotNone(err.timestamp)
    
    def test_threat_detection_error_is_retryable(self):
        err = ThreatDetectionError("Threat detection failed")
        self.assertTrue(err.retryable)
        self.assertEqual(err.error_code, "NS_T001")
    
    def test_configuration_error_not_retryable(self):
        err = ConfigurationError("Bad config")
        self.assertFalse(err.retryable)
        self.assertEqual(err.severity, "CRITICAL")
    
    def test_validation_error_not_retryable(self):
        err = ValidationError("Invalid input")
        self.assertFalse(err.retryable)
    
    def test_exception_inheritance(self):
        self.assertTrue(issubclass(PromptInjectionDetectionError, ThreatDetectionError))
        self.assertTrue(issubclass(ModelTimeoutError, ModelInferenceError))
        self.assertTrue(issubclass(ThreatDetectionError, NeuralShieldError))

class TestCircuitBreaker(unittest.TestCase):
    """Test Circuit Breaker pattern"""
    
    def test_circuit_starts_closed(self):
        cb = CircuitBreaker(failure_threshold=3, name="test")
        self.assertEqual(cb.state, CircuitState.CLOSED)
        self.assertTrue(cb.can_execute())
    
    def test_circuit_opens_after_threshold(self):
        cb = CircuitBreaker(failure_threshold=2, name="test2")
        
        @cb
        def failing_func():
            raise ValueError("Always fails")
        
        # First failure
        with self.assertRaises(ValueError):
            failing_func()
        self.assertEqual(cb.state, CircuitState.CLOSED)
        
        # Second failure - should open
        with self.assertRaises(ValueError):
            failing_func()
        self.assertEqual(cb.state, CircuitState.OPEN)
        
        # Third call should fail fast with CircuitBreakerOpenError
        with self.assertRaises(CircuitBreakerOpenError):
            failing_func()
    
    def test_circuit_half_open_transition(self):
        cb = CircuitBreaker(
            failure_threshold=1,
            recovery_timeout=0.1,
            half_open_max_calls=1,
            name="test3"
        )
        
        @cb
        def failing_func():
            raise ValueError("Always fails")
        
        # Trigger open
        with self.assertRaises(ValueError):
            failing_func()
        self.assertEqual(cb.state, CircuitState.OPEN)
        
        # Wait for recovery timeout
        time.sleep(0.15)
        self.assertEqual(cb.state, CircuitState.HALF_OPEN)
    
    def test_circuit_closes_after_success_in_half_open(self):
        cb = CircuitBreaker(
            failure_threshold=1,
            recovery_timeout=0.1,
            half_open_max_calls=1,
            name="test4"
        )
        
        call_count = [0]
        
        @cb
        def sometimes_fails():
            call_count[0] += 1
            if call_count[0] <= 1:
                raise ValueError("First call fails")
            return "success"
        
        # Trigger open
        with self.assertRaises(ValueError):
            sometimes_fails()
        
        # Wait and succeed
        time.sleep(0.15)
        result = sometimes_fails()
        self.assertEqual(result, "success")
        self.assertEqual(cb.state, CircuitState.CLOSED)
    
    def test_circuit_breaker_stats(self):
        cb = CircuitBreaker(failure_threshold=5, name="test_stats")
        
        @cb
        def succeeds():
            return "ok"
        
        succeeds()
        succeeds()
        
        stats = cb.get_stats()
        self.assertEqual(stats["stats"]["successes"], 2)
        self.assertEqual(stats["state"], "CLOSED")

class TestRetryDecorator(unittest.TestCase):
    """Test retry with backoff strategies"""
    
    def test_retry_succeeds_on_second_attempt(self):
        call_count = [0]
        
        @retry(max_attempts=3, initial_delay=0.01, jitter=False)
        def flaky_func():
            call_count[0] += 1
            if call_count[0] < 2:
                raise ValueError("Temporary failure")
            return "success"
        
        result = flaky_func()
        self.assertEqual(result, "success")
        self.assertEqual(call_count[0], 2)
    
    def test_retry_exponential_backoff(self):
        timestamps = []
        
        @retry(max_attempts=3, initial_delay=0.01, strategy=RetryStrategy.EXPONENTIAL, jitter=False)
        def failing_func():
            timestamps.append(time.time())
            raise ValueError("Always fails")
        
        start = time.time()
        with self.assertRaises(ValueError):
            failing_func()
        
        # Should have taken roughly 0.01 + 0.02 = 0.03 seconds
        elapsed = time.time() - start
        self.assertGreaterEqual(elapsed, 0.02)
    
    def test_retry_with_fallback(self):
        call_count = [0]
        
        def my_fallback():
            return "fallback_result"
        
        @retry(max_attempts=2, initial_delay=0.01, fallback=my_fallback)
        def always_fails():
            call_count[0] += 1
            raise ValueError("Fail")
        
        result = always_fails()
        self.assertEqual(result, "fallback_result")
        self.assertEqual(call_count[0], 2)
    
    def test_retry_specific_exceptions(self):
        call_count = [0]
        
        @retry(max_attempts=3, initial_delay=0.01, retry_on=(ValueError,))
        def selective_retry():
            call_count[0] += 1
            if call_count[0] < 2:
                raise ValueError("Retry this")
            raise TypeError("Don't retry this")
        
        with self.assertRaises(TypeError):
            selective_retry()
        self.assertEqual(call_count[0], 2)

class TestTimeoutDecorator(unittest.TestCase):
    """Test timeout wrapper"""
    
    def test_timeout_raises(self):
        @timeout(seconds=0.1)
        def slow_func():
            time.sleep(1.0)
            return "done"
        
        with self.assertRaises(TimeoutError):
            slow_func()
    
    def test_timeout_with_fallback(self):
        def fallback():
            return "fallback"
        
        @timeout(seconds=0.1, fallback=fallback)
        def slow_func():
            time.sleep(1.0)
            return "done"
        
        result = slow_func()
        self.assertEqual(result, "fallback")
    
    def test_no_timeout_when_fast(self):
        @timeout(seconds=1.0)
        def fast_func():
            return "done"
        
        result = fast_func()
        self.assertEqual(result, "done")
    
    def test_custom_exception_class(self):
        @timeout(seconds=0.1, exception_class=ModelTimeoutError)
        def slow_func():
            time.sleep(1.0)
        
        with self.assertRaises(ModelTimeoutError):
            slow_func()

class TestGracefulDegradation(unittest.TestCase):
    """Test graceful degradation manager"""
    
    def setUp(self):
        self.gd = GracefulDegradation()
    
    def test_primary_succeeds(self):
        def primary():
            return "primary_result"
        
        result = self.gd.get_cached_or_fallback("test_op", primary)
        self.assertEqual(result, "primary_result")
    
    def test_fallback_on_failure(self):
        def primary():
            raise ValueError("Failed")
        
        def fallback():
            return "fallback_result"
        
        self.gd.register_fallback("test_op2", fallback)
        result = self.gd.get_cached_or_fallback("test_op2", primary)
        self.assertEqual(result, "fallback_result")
    
    def test_default_on_failure(self):
        def primary():
            raise ValueError("Failed")
        
        result = self.gd.get_cached_or_fallback("test_op3", primary, default="my_default")
        self.assertEqual(result, "my_default")
    
    def test_cache_used_on_failure(self):
        call_count = [0]
        
        def primary():
            call_count[0] += 1
            if call_count[0] == 1:
                return "cached_value"
            raise ValueError("Now failing")
        
        # First call succeeds and caches
        result1 = self.gd.get_cached_or_fallback("test_op4", primary)
        self.assertEqual(result1, "cached_value")
        
        # Second call fails, uses cache
        result2 = self.gd.get_cached_or_fallback("test_op4", primary)
        self.assertEqual(result2, "cached_value")
    
    def test_degradation_stats(self):
        def primary():
            raise ValueError("Failed")
        
        self.gd.get_cached_or_fallback("op1", primary, default="d1")
        self.gd.get_cached_or_fallback("op1", primary, default="d1")
        self.gd.get_cached_or_fallback("op2", primary, default="d2")
        
        stats = self.gd.get_degradation_stats()
        self.assertEqual(stats["total_degradations"], 3)
        self.assertEqual(stats["by_operation"]["op1"], 2)
        self.assertEqual(stats["by_operation"]["op2"], 1)

class TestBulkhead(unittest.TestCase):
    """Test Bulkhead pattern"""
    
    def test_bulkhead_rejects_when_full(self):
        bh = Bulkhead(max_concurrent=1, name="test_bh")
        
        barrier = threading.Barrier(2)
        results = []
        
        def func():
            barrier.wait(timeout=1.0)
            time.sleep(0.1)
            return "done"
        
        @bh
        def wrapped():
            return func()
        
        def thread1():
            try:
                results.append(("success", wrapped()))
            except Exception as e:
                results.append(("error", type(e).__name__))
        
        def thread2():
            time.sleep(0.01)  # Let thread1 acquire first
            try:
                results.append(("success", wrapped()))
            except Exception as e:
                results.append(("error", type(e).__name__))
        
        t1 = threading.Thread(target=thread1)
        t2 = threading.Thread(target=thread2)
        t1.start()
        t2.start()
        
        # Release barrier
        time.sleep(0.05)
        barrier.wait(timeout=1.0)
        
        t1.join()
        t2.join()
        
        # One should succeed, one should be rejected
        self.assertEqual(len(results), 2)
        error_types = [r[1] for r in results if r[0] == "error"]
        self.assertIn("RateLimitExceededError", error_types)
    
    def test_bulkhead_stats(self):
        bh = Bulkhead(max_concurrent=5, name="stats_test")
        
        @bh
        def succeeds():
            return "ok"
        
        succeeds()
        stats = bh.get_stats()
        self.assertEqual(stats["active"], 0)
        self.assertEqual(stats["rejected"], 0)

class TestSafeExecute(unittest.TestCase):
    """Test safe_execute convenience function"""
    
    def test_safe_execute_success(self):
        def succeeds():
            return "ok"
        
        result = safe_execute(succeeds)
        self.assertEqual(result, "ok")
    
    def test_safe_execute_with_default(self):
        def fails():
            raise ValueError("Fail")
        
        result = safe_execute(fails, default="default_val")
        self.assertEqual(result, "default_val")
    
    def test_safe_execute_with_timeout(self):
        def slow():
            time.sleep(1.0)
            return "done"
        
        result = safe_execute(slow, timeout_sec=0.1, default="timeout_fallback")
        self.assertEqual(result, "timeout_fallback")
    
    def test_safe_execute_with_retries(self):
        call_count = [0]
        
        def flaky():
            call_count[0] += 1
            if call_count[0] < 2:
                raise ValueError("Temporary")
            return "success"
        
        result = safe_execute(flaky, max_retries=2)
        self.assertEqual(result, "success")
        self.assertEqual(call_count[0], 2)

class TestGlobalFunctions(unittest.TestCase):
    """Test global convenience functions"""
    
    def test_get_circuit_breaker_singleton(self):
        cb1 = get_circuit_breaker("global_test")
        cb2 = get_circuit_breaker("global_test")
        self.assertIs(cb1, cb2)
    
    def test_get_bulkhead_singleton(self):
        bh1 = get_bulkhead("global_bh")
        bh2 = get_bulkhead("global_bh")
        self.assertIs(bh1, bh2)
    
    def test_get_graceful_degradation(self):
        gd1 = get_graceful_degradation()
        gd2 = get_graceful_degradation()
        self.assertIs(gd1, gd2)
    
    def test_get_all_resilience_stats(self):
        # Create some components
        get_circuit_breaker("stats_cb")
        get_bulkhead("stats_bh")
        
        stats = get_all_resilience_stats()
        self.assertIn("circuit_breakers", stats)
        self.assertIn("bulkheads", stats)
        self.assertIn("graceful_degradation", stats)
        self.assertIn("timestamp", stats)

def run_tests():
    """Run all tests and return results"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    suite.addTests(loader.loadTestsFromTestCase(TestCustomExceptionHierarchy))
    suite.addTests(loader.loadTestsFromTestCase(TestCircuitBreaker))
    suite.addTests(loader.loadTestsFromTestCase(TestRetryDecorator))
    suite.addTests(loader.loadTestsFromTestCase(TestTimeoutDecorator))
    suite.addTests(loader.loadTestsFromTestCase(TestGracefulDegradation))
    suite.addTests(loader.loadTestsFromTestCase(TestBulkhead))
    suite.addTests(loader.loadTestsFromTestCase(TestSafeExecute))
    suite.addTests(loader.loadTestsFromTestCase(TestGlobalFunctions))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return {
        "total": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "passed": result.testsRun - len(result.failures) - len(result.errors),
        "success": result.wasSuccessful()
    }

if __name__ == "__main__":
    results = run_tests()
    print(f"\n{'='*60}")
    print(f"TEST RESULTS: {results['passed']}/{results['total']} PASSED")
    print(f"Failures: {results['failures']}, Errors: {results['errors']}")
    print(f"Success: {results['success']}")
    print(f"{'='*60}")
    
    import json
    with open("test_results_error_resilience_v12_2026_june.json", "w") as f:
        json.dump(results, f, indent=2)
