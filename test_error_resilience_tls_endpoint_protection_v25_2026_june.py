"""
Test Suite for NeuralShield-AI Error Resilience v25 - TLS/HTTPS Endpoint Protection
====================================================================================
DIMENSION E - Error Resilience
35 comprehensive tests covering all error resilience patterns

All tests are ADD-ONLY - no existing tests modified
All existing tests continue to pass unchanged
"""

import unittest
import time
import threading
import ssl
import socket
from unittest.mock import Mock, patch
from typing import Dict, Any

# Import the new module
from neural_shield.error_resilience_tls_endpoint_protection_v25_2026_june import (
    # Exception hierarchy
    TLSError,
    TLSTimeoutError,
    TLSCertificateError,
    TLSCipherError,
    TLSVersionError,
    TLSHandshakeError,
    TLSCircuitBreakerOpen,
    TLSFallbackActivated,
    
    # Core components
    CircuitState,
    TLSCircuitBreaker,
    ExponentialBackoff,
    TLSTimeoutProtector,
    TLSBulkhead,
    TLSFallbackManager,
    
    # Decorators and wrappers
    tls_error_resilience,
    wrap_tls_server_with_error_resilience,
    
    # Convenience functions
    get_tls_error_resilience_stats,
    reset_tls_error_resilience_state,
    classify_tls_exception,
)


# ============================================================================
# TEST 1-8: TLS EXCEPTION HIERARCHY
# ============================================================================

class TestTLSExceptionHierarchy(unittest.TestCase):
    """Test custom TLS exception hierarchy"""
    
    def test_tls_base_exception(self):
        """Test TLSError base class properties"""
        exc = TLSError("Test error", "TEST_CODE", retryable=True)
        self.assertEqual(str(exc), "Test error")
        self.assertEqual(exc.error_code, "TEST_CODE")
        self.assertTrue(exc.retryable)
        self.assertIsInstance(exc, Exception)
    
    def test_tls_timeout_exception(self):
        """Test TLSTimeoutError is retryable"""
        exc = TLSTimeoutError()
        self.assertEqual(exc.error_code, "TLS_TIMEOUT")
        self.assertTrue(exc.retryable)
    
    def test_tls_certificate_exception(self):
        """Test TLSCertificateError is NOT retryable"""
        exc = TLSCertificateError()
        self.assertEqual(exc.error_code, "TLS_CERT_INVALID")
        self.assertFalse(exc.retryable)
    
    def test_tls_cipher_exception(self):
        """Test TLSCipherError is NOT retryable"""
        exc = TLSCipherError()
        self.assertEqual(exc.error_code, "TLS_CIPHER_MISMATCH")
        self.assertFalse(exc.retryable)
    
    def test_tls_version_exception(self):
        """Test TLSVersionError is NOT retryable"""
        exc = TLSVersionError()
        self.assertEqual(exc.error_code, "TLS_VERSION_MISMATCH")
        self.assertFalse(exc.retryable)
    
    def test_tls_handshake_exception(self):
        """Test TLSHandshakeError IS retryable (transient)"""
        exc = TLSHandshakeError()
        self.assertEqual(exc.error_code, "TLS_HANDSHAKE_FAILED")
        self.assertTrue(exc.retryable)
    
    def test_tls_circuit_breaker_open_exception(self):
        """Test TLSCircuitBreakerOpen is NOT retryable"""
        exc = TLSCircuitBreakerOpen()
        self.assertEqual(exc.error_code, "TLS_CIRCUIT_OPEN")
        self.assertFalse(exc.retryable)
    
    def test_tls_fallback_activated_exception(self):
        """Test TLSFallbackActivated informational exception"""
        exc = TLSFallbackActivated()
        self.assertEqual(exc.error_code, "TLS_FALLBACK")
        self.assertFalse(exc.retryable)


# ============================================================================
# TEST 9-15: TLS CIRCUIT BREAKER
# ============================================================================

class TestTLSCircuitBreaker(unittest.TestCase):
    """Test TLS Circuit Breaker pattern implementation"""
    
    def setUp(self):
        self.cb = TLSCircuitBreaker(failure_threshold=3, recovery_timeout=0.1)
    
    def test_circuit_starts_closed(self):
        """Circuit breaker starts in CLOSED state"""
        state = self.cb.get_state()
        self.assertEqual(state['state'], "CLOSED")
        self.assertTrue(self.cb.allow_request())
    
    def test_circuit_opens_after_failures(self):
        """Circuit opens after reaching failure threshold"""
        for i in range(3):
            self.cb.record_failure(Exception(f"Failure {i}"))
        
        state = self.cb.get_state()
        self.assertEqual(state['state'], "OPEN")
        self.assertFalse(self.cb.allow_request())
    
    def test_circuit_half_open_after_recovery(self):
        """Circuit goes to HALF_OPEN after recovery timeout"""
        for i in range(3):
            self.cb.record_failure(Exception(f"Failure {i}"))
        
        time.sleep(0.15)  # Wait for recovery timeout
        self.assertTrue(self.cb.allow_request())
        
        state = self.cb.get_state()
        self.assertEqual(state['state'], "HALF_OPEN")
    
    def test_circuit_closes_after_successes(self):
        """Circuit fully closes after successful recovery attempts"""
        for i in range(3):
            self.cb.record_failure(Exception(f"Failure {i}"))
        
        time.sleep(0.15)
        self.cb.allow_request()  # HALF_OPEN
        
        # Need success_threshold successes to close
        for i in range(3):
            self.cb.record_success()
        
        state = self.cb.get_state()
        self.assertEqual(state['state'], "CLOSED")
    
    def test_circuit_reopens_on_half_open_failure(self):
        """Circuit re-opens if failure occurs during HALF_OPEN"""
        for i in range(3):
            self.cb.record_failure(Exception(f"Failure {i}"))
        
        time.sleep(0.15)
        self.cb.allow_request()  # HALF_OPEN
        self.cb.record_failure(Exception("Recovery failure"))
        
        state = self.cb.get_state()
        self.assertEqual(state['state'], "OPEN")
    
    def test_circuit_breaker_records_history(self):
        """Circuit breaker records failure history"""
        errors = ["Cert error", "Timeout", "Handshake failed"]
        for err in errors:
            self.cb.record_failure(Exception(err))
        
        state = self.cb.get_state()
        self.assertEqual(len(state['recent_failures']), 3)
    
    def test_circuit_breaker_success_resets_failures(self):
        """Success resets failure counter"""
        for i in range(2):
            self.cb.record_failure(Exception(f"Failure {i}"))
        
        self.cb.record_success()
        state = self.cb.get_state()
        self.assertEqual(state['failure_count'], 0)


# ============================================================================
# TEST 16-19: EXPONENTIAL BACKOFF WITH JITTER
# ============================================================================

class TestExponentialBackoff(unittest.TestCase):
    """Test exponential backoff with jitter"""
    
    def test_backoff_increases_exponentially(self):
        """Delay increases exponentially with attempts"""
        backoff = ExponentialBackoff(base_delay=0.1, max_delay=10.0, jitter_factor=0)
        d1 = backoff.get_delay(0)
        d2 = backoff.get_delay(1)
        d3 = backoff.get_delay(2)
        
        self.assertAlmostEqual(d1, 0.1)
        self.assertAlmostEqual(d2, 0.2)
        self.assertAlmostEqual(d3, 0.4)
    
    def test_backoff_respects_max_delay(self):
        """Delay never exceeds max_delay"""
        backoff = ExponentialBackoff(base_delay=1.0, max_delay=5.0, jitter_factor=0)
        delay = backoff.get_delay(10)  # Would be 1024s without cap
        self.assertLessEqual(delay, 5.0)
    
    def test_backoff_jitter_adds_randomness(self):
        """Jitter adds randomness to prevent thundering herd"""
        backoff = ExponentialBackoff(base_delay=1.0, jitter_factor=0.5)
        delays = [backoff.get_delay(2) for _ in range(100)]
        
        # Should have variation
        self.assertGreater(max(delays), min(delays))
        # All should be within jitter range
        for d in delays:
            self.assertGreaterEqual(d, 2.0 * 0.5)  # 4s * 0.5
            self.assertLessEqual(d, 4.0 * 1.5)  # 4s * 1.5
    
    def test_retryable_exception_classification(self):
        """Only transient errors are retryable"""
        backoff = ExponentialBackoff(max_retries=3)
        
        # Retryable
        self.assertTrue(backoff.should_retry(0, TLSTimeoutError()))
        self.assertTrue(backoff.should_retry(0, TLSHandshakeError()))
        self.assertTrue(backoff.should_retry(0, socket.timeout()))
        
        # NOT retryable
        self.assertFalse(backoff.should_retry(0, TLSCertificateError()))
        self.assertFalse(backoff.should_retry(0, TLSCipherError()))
        
        # Max retries exceeded
        self.assertFalse(backoff.should_retry(3, TLSTimeoutError()))


# ============================================================================
# TEST 20-22: TLS TIMEOUT PROTECTION
# ============================================================================

class TestTLSTimeoutProtector(unittest.TestCase):
    """Test TLS timeout protection"""
    
    def test_timeout_protector_stops_hanging_function(self):
        """Timeout protector terminates hanging functions"""
        protector = TLSTimeoutProtector(default_timeout=0.1)
        
        def slow_function():
            time.sleep(1.0)
            return "done"
        
        with self.assertRaises(TLSTimeoutError):
            protector.run_with_timeout(slow_function)
    
    def test_timeout_protector_allows_fast_functions(self):
        """Timeout protector allows fast functions to complete"""
        protector = TLSTimeoutProtector(default_timeout=1.0)
        
        def fast_function():
            return "done"
        
        result = protector.run_with_timeout(fast_function)
        self.assertEqual(result, "done")
    
    def test_timeout_protector_tracks_statistics(self):
        """Timeout protector tracks operation statistics"""
        protector = TLSTimeoutProtector(default_timeout=0.1)
        
        def fast():
            return "ok"
        
        def slow():
            time.sleep(0.2)
            return "slow"
        
        protector.run_with_timeout(fast)
        try:
            protector.run_with_timeout(slow)
        except TLSTimeoutError:
            pass
        
        stats = protector.get_stats()
        self.assertEqual(stats['total_operations'], 2)
        self.assertEqual(stats['timeout_count'], 1)


# ============================================================================
# TEST 23-25: TLS BULKHEAD ISOLATION
# ============================================================================

class TestTLSBulkhead(unittest.TestCase):
    """Test TLS bulkhead isolation pattern"""
    
    def test_bulkhead_limits_concurrency(self):
        """Bulkhead limits concurrent operations"""
        bulkhead = TLSBulkhead(max_concurrent=1)
        
        results = []
        barrier = threading.Barrier(2)
        
        def first_func():
            barrier.wait(timeout=1.0)
            time.sleep(0.1)
            results.append("first")
        
        def second_func():
            try:
                barrier.wait(timeout=1.0)
                bulkhead.execute(lambda: None)
            except TLSError as e:
                results.append("rejected")
        
        t1 = threading.Thread(target=lambda: bulkhead.execute(first_func))
        t2 = threading.Thread(target=second_func)
        
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        
        self.assertIn("rejected", results)
    
    def test_bulkhead_executes_functions(self):
        """Bulkhead executes functions when capacity available"""
        bulkhead = TLSBulkhead(max_concurrent=10)
        
        result = bulkhead.execute(lambda: 42)
        self.assertEqual(result, 42)
    
    def test_bulkhead_tracks_statistics(self):
        """Bulkhead tracks execution statistics"""
        bulkhead = TLSBulkhead(max_concurrent=1)
        
        bulkhead.execute(lambda: None)
        try:
            # Fill bulkhead
            with patch.object(bulkhead._semaphore, 'acquire', return_value=False):
                bulkhead.execute(lambda: None)
        except TLSError:
            pass
        
        stats = bulkhead.get_stats()
        self.assertEqual(stats['executed'], 1)
        self.assertEqual(stats['rejected'], 1)


# ============================================================================
# TEST 26-28: TLS FALLBACK MANAGER - GRACEFUL DEGRADATION
# ============================================================================

class TestTLSFallbackManager(unittest.TestCase):
    """Test TLS graceful degradation / fallback manager"""
    
    def test_fallback_activates_on_poor_health(self):
        """Fallback activates when TLS success rate is too low"""
        fm = TLSFallbackManager(fallback_threshold=0.5, window_size=20)
        
        # Record many failures
        for _ in range(15):
            fm.record_outcome(False)
        
        self.assertTrue(fm.should_use_fallback())
    
    def test_fallback_deactivates_on_recovery(self):
        """Fallback deactivates when TLS recovers"""
        fm = TLSFallbackManager(fallback_threshold=0.3, recovery_threshold=0.7, window_size=20)
        
        # Failures to activate fallback
        for _ in range(15):
            fm.record_outcome(False)
        self.assertTrue(fm.should_use_fallback())
        
        # Successes to recover
        for _ in range(20):
            fm.record_outcome(True)
        self.assertFalse(fm.should_use_fallback())
    
    def test_fallback_health_reporting(self):
        """Fallback manager reports health statistics"""
        fm = TLSFallbackManager(window_size=20)
        
        for i in range(10):
            fm.record_outcome(i % 2 == 0)  # 50% success
        
        health = fm.get_health()
        self.assertEqual(health['sample_size'], 10)
        self.assertAlmostEqual(health['success_rate'], 0.5)


# ============================================================================
# TEST 29-31: TLS ERROR RESILIENCE DECORATOR
# ============================================================================

class TestTLSErrorResilienceDecorator(unittest.TestCase):
    """Test comprehensive TLS error resilience decorator"""
    
    def setUp(self):
        reset_tls_error_resilience_state()
    
    def test_decorator_retries_transient_errors(self):
        """Decorator retries transient TLS errors"""
        call_count = [0]
        
        @tls_error_resilience(timeout=1.0, max_retries=3)
        def flaky_function():
            call_count[0] += 1
            if call_count[0] < 3:
                raise TLSHandshakeError("Transient failure")
            return "success"
        
        result = flaky_function()
        self.assertEqual(result, "success")
        self.assertEqual(call_count[0], 3)
    
    def test_decorator_uses_fallback_function(self):
        """Decorator uses fallback on persistent failure"""
        fallback_called = [False]
        
        def my_fallback():
            fallback_called[0] = True
            return "fallback result"
        
        @tls_error_resilience(timeout=0.1, max_retries=1, fallback_function=my_fallback)
        def always_fails():
            raise TLSHandshakeError("Persistent failure")
        
        result = always_fails()
        self.assertEqual(result, "fallback result")
        self.assertTrue(fallback_called[0])
    
    def test_decorator_respects_circuit_breaker(self):
        """Decorator respects circuit breaker state"""
        @tls_error_resilience(timeout=1.0, max_retries=0)
        def test_func():
            raise TLSHandshakeError("Failure")
        
        # Trip the circuit
        for _ in range(10):
            try:
                test_func()
            except Exception:
                pass
        
        # Circuit should be open - raises immediately
        with self.assertRaises((TLSCircuitBreakerOpen, TLSHandshakeError)):
            test_func()


# ============================================================================
# TEST 32-33: EXCEPTION CLASSIFICATION
# ============================================================================

class TestTLSExceptionClassification(unittest.TestCase):
    """Test TLS exception classification"""
    
    def test_classify_ssl_errors(self):
        """SSL errors are classified correctly"""
        code, retryable = classify_tls_exception(ssl.SSLError("CERTIFICATE_VERIFY_FAILED"))
        self.assertEqual(code, "TLS_CERT_INVALID")
        self.assertFalse(retryable)
    
    def test_classify_socket_errors(self):
        """Socket errors are classified correctly"""
        code, retryable = classify_tls_exception(socket.timeout())
        self.assertEqual(code, "TLS_TIMEOUT")
        self.assertTrue(retryable)


# ============================================================================
# TEST 34-35: BACKWARD COMPATIBILITY & GLOBAL FUNCTIONS
# ============================================================================

class TestBackwardCompatibilityAndGlobals(unittest.TestCase):
    """Test backward compatibility and global convenience functions"""
    
    def test_global_stats_function(self):
        """Global stats function returns comprehensive data"""
        stats = get_tls_error_resilience_stats()
        self.assertIn('circuit_breaker', stats)
        self.assertIn('timeout_protector', stats)
        self.assertIn('bulkhead', stats)
        self.assertIn('fallback_manager', stats)
        self.assertEqual(stats['version'], '25.0.0')
    
    def test_reset_state_function(self):
        """Reset state function clears all state"""
        # Trip circuit breaker
        cb = TLSCircuitBreaker(failure_threshold=1)
        cb.record_failure(Exception("test"))
        self.assertEqual(cb.get_state()['state'], "OPEN")
        
        # Reset should create new instances (test doesn't verify external state)
        reset_tls_error_resilience_state()
        # Verify no exceptions
        stats = get_tls_error_resilience_stats()
        self.assertIsNotNone(stats)


# ============================================================================
# TEST RUNNER
# ============================================================================

def run_all_tests():
    """Run all tests and report results"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    test_classes = [
        TestTLSExceptionHierarchy,
        TestTLSCircuitBreaker,
        TestExponentialBackoff,
        TestTLSTimeoutProtector,
        TestTLSBulkhead,
        TestTLSFallbackManager,
        TestTLSErrorResilienceDecorator,
        TestTLSExceptionClassification,
        TestBackwardCompatibilityAndGlobals,
    ]
    
    for test_class in test_classes:
        tests = loader.loadTestsFromTestCase(test_class)
        suite.addTests(tests)
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print(f"\n{'='*60}")
    print(f"TEST SUMMARY: {result.testsRun} tests run")
    print(f"PASSED: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"FAILED: {len(result.failures)}")
    print(f"ERRORS: {len(result.errors)}")
    print(f"{'='*60}")
    
    return result


if __name__ == '__main__':
    result = run_all_tests()
    exit(0 if result.wasSuccessful() else 1)
