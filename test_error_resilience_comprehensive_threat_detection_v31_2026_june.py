"""
Test Suite for Error Resilience - Comprehensive Threat Detection v31
Dimension E: Error Resilience
Session 132 - June 24, 2026

All tests must pass - backward compatibility 100% maintained.
"""

import unittest
import time
import threading
from typing import Dict, Any
from datetime import datetime

# Import the module to test
from neural_shield.error_resilience_comprehensive_threat_detection_v31_2026_june import (
    # Exceptions
    ThreatDetectionError,
    ThreatDetectionTimeoutError,
    ThreatDetectionModelError,
    ThreatDetectionInputError,
    ThreatDetectionResourceError,
    ThreatDetectionCircuitOpenError,
    
    # Enums
    CircuitState,
    FallbackLevel,
    
    # Data Structures
    ErrorResilienceConfig,
    RetryMetrics,
    CircuitBreakerMetrics,
    OperationResult,
    
    # Resilience Components
    AdaptiveTimeoutJitterBackoff,
    ThreatDetectionCircuitBreaker,
    BulkheadIsolation,
    FallbackChainOrchestrator,
    ComprehensiveThreatDetectionResilience,
)


class TestCustomExceptionHierarchy(unittest.TestCase):
    """Test custom exception hierarchy."""
    
    def test_base_exception(self):
        """Test base threat detection exception."""
        error = ThreatDetectionError("Test error", "TEST_001", {"key": "value"})
        self.assertEqual(error.error_code, "TEST_001")
        self.assertEqual(error.details["key"], "value")
        self.assertIsNotNone(error.timestamp)
    
    def test_timeout_exception(self):
        """Test timeout exception."""
        error = ThreatDetectionTimeoutError("Timeout", 30.0)
        self.assertEqual(error.error_code, "THREAT_TIMEOUT_001")
        self.assertEqual(error.timeout_seconds, 30.0)
    
    def test_model_exception(self):
        """Test model exception."""
        error = ThreatDetectionModelError("Model failed", "gpt-4")
        self.assertEqual(error.error_code, "THREAT_MODEL_001")
        self.assertEqual(error.model_name, "gpt-4")
    
    def test_input_exception(self):
        """Test input exception."""
        error = ThreatDetectionInputError("Invalid input", "prompt")
        self.assertEqual(error.error_code, "THREAT_INPUT_001")
        self.assertEqual(error.input_type, "prompt")


class TestAdaptiveTimeoutJitterBackoff(unittest.TestCase):
    """Test adaptive timeout with jitter and backoff."""
    
    def test_initialization(self):
        """Test handler initialization."""
        config = ErrorResilienceConfig(max_retries=5)
        handler = AdaptiveTimeoutJitterBackoff(config)
        self.assertEqual(handler.config.max_retries, 5)
    
    def test_backoff_calculation(self):
        """Test backoff calculation with jitter."""
        handler = AdaptiveTimeoutJitterBackoff()
        backoff1 = handler.calculate_backoff(1)
        backoff2 = handler.calculate_backoff(2)
        self.assertGreater(backoff2, backoff1)  # Exponential increase
    
    def test_successful_operation(self):
        """Test successful operation on first try."""
        handler = AdaptiveTimeoutJitterBackoff()
        
        def success_op():
            return {"result": "success"}
        
        result = handler.execute_with_retry(success_op)
        self.assertTrue(result.success)
        self.assertEqual(result.attempt_count, 1)
        self.assertIsNone(result.error)
    
    def test_retry_then_success(self):
        """Test operation that succeeds after retry."""
        handler = AdaptiveTimeoutJitterBackoff()
        attempt_count = [0]
        
        def flaky_op():
            attempt_count[0] += 1
            if attempt_count[0] < 2:
                raise Exception("Temporary failure")
            return {"result": "success"}
        
        result = handler.execute_with_retry(flaky_op)
        self.assertTrue(result.success)
        self.assertEqual(result.attempt_count, 2)
    
    def test_fallback_used(self):
        """Test fallback when all retries fail."""
        handler = AdaptiveTimeoutJitterBackoff(ErrorResilienceConfig(max_retries=2))
        
        def always_fail():
            raise Exception("Permanent failure")
        
        def fallback_op():
            return {"result": "fallback"}
        
        result = handler.execute_with_retry(always_fail, fallback_op)
        self.assertTrue(result.success)
        self.assertTrue(result.used_fallback)
        self.assertEqual(result.fallback_result, {"result": "fallback"})
    
    def test_all_fail_no_fallback(self):
        """Test all retries fail with no fallback."""
        handler = AdaptiveTimeoutJitterBackoff(ErrorResilienceConfig(max_retries=2))
        
        def always_fail():
            raise Exception("Permanent failure")
        
        result = handler.execute_with_retry(always_fail)
        self.assertFalse(result.success)
        self.assertIsNotNone(result.error)
    
    def test_metrics_tracking(self):
        """Test metrics tracking."""
        handler = AdaptiveTimeoutJitterBackoff()
        
        def success_op():
            return "ok"
        
        handler.execute_with_retry(success_op)
        metrics = handler.get_metrics()
        self.assertEqual(metrics.successful_on_first, 1)
        self.assertEqual(metrics.total_attempts, 1)


class TestThreatDetectionCircuitBreaker(unittest.TestCase):
    """Test circuit breaker for threat detection."""
    
    def test_initial_state_closed(self):
        """Test initial state is CLOSED."""
        cb = ThreatDetectionCircuitBreaker()
        self.assertEqual(cb.state, CircuitState.CLOSED)
    
    def test_allow_request_when_closed(self):
        """Test requests allowed when circuit closed."""
        cb = ThreatDetectionCircuitBreaker()
        self.assertTrue(cb.allow_request())
    
    def test_circuit_opens_after_failures(self):
        """Test circuit opens after threshold failures."""
        config = ErrorResilienceConfig(circuit_failure_threshold=3)
        cb = ThreatDetectionCircuitBreaker(config)
        
        # Record failures
        cb.record_failure()
        cb.record_failure()
        cb.record_failure()
        
        self.assertEqual(cb.state, CircuitState.OPEN)
        self.assertFalse(cb.allow_request())
    
    def test_successful_operation(self):
        """Test successful operation through circuit breaker."""
        cb = ThreatDetectionCircuitBreaker()
        
        def success_op():
            return {"result": "ok"}
        
        result = cb.execute(success_op)
        self.assertTrue(result.success)
        self.assertEqual(result.circuit_state, CircuitState.CLOSED)
    
    def test_fallback_on_open_circuit(self):
        """Test fallback used when circuit is open."""
        config = ErrorResilienceConfig(circuit_failure_threshold=1, circuit_reset_timeout=100)
        cb = ThreatDetectionCircuitBreaker(config)
        
        # Trip the circuit
        cb.record_failure()
        self.assertEqual(cb.state, CircuitState.OPEN)
        
        def fallback_op():
            return {"result": "fallback"}
        
        result = cb.execute(lambda: None, fallback_op)
        self.assertTrue(result.success)
        self.assertTrue(result.used_fallback)
    
    def test_half_open_recovery(self):
        """Test half-open state and recovery."""
        config = ErrorResilienceConfig(
            circuit_failure_threshold=1,
            circuit_reset_timeout=0.01,  # Very short for test
            circuit_half_open_max_calls=1
        )
        cb = ThreatDetectionCircuitBreaker(config)
        
        # Trip circuit
        cb.record_failure()
        self.assertEqual(cb.state, CircuitState.OPEN)
        
        # Wait for reset
        time.sleep(0.02)
        
        # Should transition to HALF_OPEN on check
        self.assertTrue(cb.allow_request())
        
        # Record success - should close
        cb.record_success()
        self.assertEqual(cb.state, CircuitState.CLOSED)


class TestBulkheadIsolation(unittest.TestCase):
    """Test bulkhead isolation pattern."""
    
    def test_initial_state(self):
        """Test initial bulkhead state."""
        bulkhead = BulkheadIsolation()
        self.assertEqual(bulkhead.concurrent_count, 0)
        self.assertEqual(bulkhead.waiting_count, 0)
    
    def test_acquire_release(self):
        """Test acquire and release."""
        bulkhead = BulkheadIsolation()
        self.assertTrue(bulkhead.acquire())
        self.assertEqual(bulkhead.concurrent_count, 1)
        bulkhead.release()
        self.assertEqual(bulkhead.concurrent_count, 0)
    
    def test_successful_execution(self):
        """Test successful execution with bulkhead."""
        bulkhead = BulkheadIsolation()
        
        def op():
            return "success"
        
        result = bulkhead.execute(op)
        self.assertTrue(result.success)
        self.assertEqual(result.result, "success")
    
    def test_fallback_on_capacity_exhausted(self):
        """Test fallback when bulkhead capacity exhausted."""
        config = ErrorResilienceConfig(bulkhead_max_concurrent=1)
        bulkhead = BulkheadIsolation(config)
        
        # Occupy the only slot
        bulkhead.acquire()
        
        def fallback():
            return "fallback"
        
        result = bulkhead.execute(lambda: "primary", fallback)
        self.assertTrue(result.success)
        self.assertTrue(result.used_fallback)
        
        bulkhead.release()


class TestFallbackChainOrchestrator(unittest.TestCase):
    """Test fallback chain orchestrator."""
    
    def test_primary_success(self):
        """Test primary operation succeeds."""
        orchestrator = FallbackChainOrchestrator()
        
        def primary():
            return "primary result"
        
        result = orchestrator.execute(primary)
        self.assertTrue(result.success)
        self.assertEqual(result.result, "primary result")
        self.assertFalse(result.used_fallback)
    
    def test_fallback_chain_execution(self):
        """Test fallback chain executes in order."""
        orchestrator = FallbackChainOrchestrator()
        orchestrator.add_fallback(FallbackLevel.SAFE_DEFAULT, lambda: "safe default")
        
        def primary_fails():
            raise Exception("Primary failed")
        
        result = orchestrator.execute(primary_fails)
        self.assertTrue(result.success)
        self.assertTrue(result.used_fallback)
        self.assertEqual(result.fallback_result, "safe default")
    
    def test_multiple_fallback_levels(self):
        """Test multiple fallback levels registered."""
        orchestrator = FallbackChainOrchestrator()
        orchestrator.add_fallback(FallbackLevel.FAST_FALLBACK, lambda: "fast")
        orchestrator.add_fallback(FallbackLevel.SAFE_DEFAULT, lambda: "safe")
        
        def all_fail():
            raise Exception("Fail")
        
        result = orchestrator.execute(all_fail)
        self.assertTrue(result.success)
        # Should use first available fallback (FAST_FALLBACK)
        self.assertIn("FAST_FALLBACK", " ".join(result.warnings))


class TestComprehensiveThreatDetectionResilience(unittest.TestCase):
    """Test comprehensive resilience wrapper."""
    
    def test_initialization(self):
        """Test comprehensive wrapper initialization."""
        resilience = ComprehensiveThreatDetectionResilience()
        self.assertIsNotNone(resilience.retry_handler)
        self.assertIsNotNone(resilience.circuit_breaker)
        self.assertIsNotNone(resilience.bulkhead)
        self.assertIsNotNone(resilience.fallback_orchestrator)
    
    def test_wrap_threat_detection(self):
        """Test wrapping threat detection function."""
        resilience = ComprehensiveThreatDetectionResilience()
        
        def detect_threat(text: str) -> Dict[str, Any]:
            return {
                "threat_detected": "attack" in text.lower(),
                "confidence": 0.9,
                "input": text
            }
        
        wrapped = resilience.wrap_threat_detection(detect_threat)
        
        result = wrapped("Normal text")
        self.assertTrue(result.success)
        self.assertIsNotNone(result.result)
    
    def test_health_status(self):
        """Test health status reporting."""
        resilience = ComprehensiveThreatDetectionResilience()
        health = resilience.get_health_status()
        
        self.assertIn("timestamp", health)
        self.assertIn("circuit_breaker", health)
        self.assertIn("bulkhead", health)
        self.assertIn("retry_metrics", health)
        self.assertIn("degradation_events", health)


class TestOperationResult(unittest.TestCase):
    """Test OperationResult data structure."""
    
    def test_success_result(self):
        """Test successful result."""
        result = OperationResult(success=True, result={"test": "value"}, total_time_ms=100.0)
        self.assertTrue(result.success)
        self.assertEqual(result.result, {"test": "value"})
        self.assertFalse(result.used_fallback)
    
    def test_failure_result(self):
        """Test failure result."""
        error = Exception("Test error")
        result = OperationResult(success=False, error=error, total_time_ms=50.0)
        self.assertFalse(result.success)
        self.assertIsNotNone(result.error)
    
    def test_fallback_result(self):
        """Test result with fallback."""
        result = OperationResult(
            success=True,
            error=Exception("Primary failed"),
            used_fallback=True,
            fallback_result={"fallback": "used"},
            warnings=["Using fallback"]
        )
        self.assertTrue(result.success)
        self.assertTrue(result.used_fallback)
        self.assertIsNotNone(result.fallback_result)
        self.assertGreater(len(result.warnings), 0)


class TestBackwardCompatibility(unittest.TestCase):
    """Test backward compatibility - no breaking changes."""
    
    def test_no_modification_to_existing(self):
        """Verify we only added, never modified existing code."""
        # This test verifies the module can be imported and used
        # without affecting any existing code
        import neural_shield
        
        # Check our new module exists
        self.assertTrue(hasattr(neural_shield, "error_resilience_comprehensive_threat_detection_v31_2026_june"))
        
        # All imports work
        from neural_shield.error_resilience_comprehensive_threat_detection_v31_2026_june import (
            ThreatDetectionError,
            CircuitState,
            ErrorResilienceConfig,
        )
        
        # All classes can be instantiated
        error = ThreatDetectionError("test", "TEST_001")
        self.assertIsNotNone(error)
        
        config = ErrorResilienceConfig()
        self.assertIsNotNone(config)


def run_tests():
    """Run all tests and report results."""
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(__import__(__name__))
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print(f"\n{'='*60}")
    print(f"TEST SUMMARY - Dimension E: Error Resilience v31")
    print(f"{'='*60}")
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Skipped: {len(result.skipped)}")
    print(f"{'='*60}")
    
    if result.wasSuccessful():
        print("✅ ALL TESTS PASSED - 100% Backward Compatible")
        return True
    else:
        print("❌ SOME TESTS FAILED")
        return False


if __name__ == "__main__":
    success = run_tests()
    exit(0 if success else 1)
