"""
Test Suite: Error Resilience Comprehensive Coverage v27
Dimension E - Error Resilience
Tests for:
- Exception hierarchy
- Retry with backoff and jitter
- Circuit breaker pattern
- Graceful degradation
- Bulkhead isolation
"""

import unittest
import time
import threading
from unittest.mock import Mock, patch
from typing import Any

# Import error resilience modules
from neural_shield.error_resilience_enhanced_exception_hierarchy_v27_2026_june import (
    NeuralShieldBaseException,
    ValidationError,
    EmptyInputError,
    InputTooLongError,
    InvalidFormatError,
    SecurityError,
    ThreatDetectedError,
    PromptInjectionDetectedError,
    JailbreakDetectedError,
    ProcessingError,
    ModelInferenceError,
    ExternalServiceError,
    ResourceExhaustedError,
    TimeoutError,
    RateLimitExceededError,
    ConfigurationError,
    MissingConfigurationError,
    GracefulDegradationActivated,
    ErrorSeverity,
    ErrorCategory
)

from neural_shield.error_resilience_adaptive_retry_backoff_jitter_v28_2026_june import (
    RetryConfig,
    RetryStats,
    RetryStrategy,
    JitterType,
    BackoffStrategy,
    retry,
    retry_with_stats,
    RetryBudget
)

from neural_shield.error_resilience_circuit_breaker_graceful_degradation_v29_2026_june import (
    CircuitBreaker,
    CircuitBreakerConfig,
    CircuitState,
    CircuitOpenError,
    circuit_breaker,
    GracefulDegradation,
    Bulkhead,
    BulkheadExhaustedError,
    get_circuit_breaker,
    get_bulkhead,
    get_graceful_degradation
)


class TestExceptionHierarchy(unittest.TestCase):
    """Test custom exception hierarchy."""
    
    def test_base_exception_has_context(self):
        """Test base exception has proper context and ID."""
        exc = NeuralShieldBaseException(
            message="Test error",
            error_code="TEST_001",
            context={"key": "value"}
        )
        
        self.assertIsNotNone(exc.error_id)
        self.assertEqual(exc.error_code, "TEST_001")
        self.assertEqual(exc.context["key"], "value")
        self.assertIn("TEST_001", str(exc))
        
    def test_exception_to_dict(self):
        """Test exception serialization to dict."""
        exc = NeuralShieldBaseException("Test", context={"foo": "bar"})
        d = exc.to_dict()
        
        self.assertIn("error_id", d)
        self.assertIn("message", d)
        self.assertIn("severity", d)
        self.assertEqual(d["context"]["foo"], "bar")
        
    def test_validation_errors(self):
        """Test validation exception types."""
        with self.assertRaises(EmptyInputError) as ctx:
            raise EmptyInputError("username")
        self.assertIn("username", str(ctx.exception))
        
        with self.assertRaises(InputTooLongError) as ctx:
            raise InputTooLongError("input", 100, 150)
        self.assertEqual(ctx.exception.context["max_length"], 100)
        
        with self.assertRaises(InvalidFormatError) as ctx:
            raise InvalidFormatError("email", "user@domain.com")
        self.assertIn("email", str(ctx.exception))
        
    def test_security_errors(self):
        """Test security exception types."""
        with self.assertRaises(PromptInjectionDetectedError) as ctx:
            raise PromptInjectionDetectedError(confidence=0.95, injection_type="direct")
        self.assertEqual(ctx.exception.severity, ErrorSeverity.CRITICAL)
        self.assertAlmostEqual(ctx.exception.context["confidence"], 0.95)
        
        with self.assertRaises(JailbreakDetectedError) as ctx:
            raise JailbreakDetectedError(confidence=0.87, attack_pattern="DAN")
        self.assertEqual(ctx.exception.category, ErrorCategory.SECURITY_ERROR)
        
    def test_processing_errors(self):
        """Test processing exception types."""
        with self.assertRaises(ModelInferenceError) as ctx:
            raise ModelInferenceError(model_name="bert-base")
        self.assertTrue(ctx.exception.retryable)
        
        with self.assertRaises(ExternalServiceError) as ctx:
            raise ExternalServiceError(service_name="virustotal", status_code=429)
        self.assertEqual(ctx.exception.context["status_code"], 429)
        
    def test_resource_errors(self):
        """Test resource and timeout exceptions."""
        with self.assertRaises(ResourceExhaustedError) as ctx:
            raise ResourceExhaustedError("memory", 0.95, 0.90)
        self.assertTrue(ctx.exception.retryable)
        
        with self.assertRaises(TimeoutError) as ctx:
            raise TimeoutError("model_inference", 30.0)
        self.assertEqual(ctx.exception.context["timeout_seconds"], 30.0)
        
        with self.assertRaises(RateLimitExceededError) as ctx:
            raise RateLimitExceededError("api_calls", retry_after_seconds=60)
        self.assertEqual(ctx.exception.context["retry_after_seconds"], 60)
        
    def test_configuration_errors(self):
        """Test configuration exceptions."""
        with self.assertRaises(MissingConfigurationError) as ctx:
            raise MissingConfigurationError("api_key")
        self.assertFalse(ctx.exception.retryable)
        
    def test_graceful_degradation_signal(self):
        """Test graceful degradation is non-error exception."""
        signal = GracefulDegradationActivated(
            feature="ml_detection",
            fallback_mode="heuristic_only",
            reason="model unavailable"
        )
        self.assertEqual(signal.feature, "ml_detection")
        self.assertEqual(signal.fallback_mode, "heuristic_only")


class TestRetryStrategy(unittest.TestCase):
    """Test retry with backoff and jitter."""
    
    def test_retry_success_first_attempt(self):
        """Test successful execution on first attempt."""
        def success_func():
            return "success"
            
        strategy = RetryStrategy(RetryConfig(max_attempts=3))
        result, stats = strategy.execute(success_func)
        
        self.assertEqual(result, "success")
        self.assertTrue(stats.successful)
        self.assertEqual(stats.attempt, 1)
        self.assertEqual(len(stats.errors), 0)
        
    def test_retry_eventually_succeeds(self):
        """Test retry succeeds after failures."""
        call_count = [0]
        
        def flaky_func():
            call_count[0] += 1
            if call_count[0] < 3:
                raise ValueError("Temporary error")
            return "success"
            
        strategy = RetryStrategy(RetryConfig(
            max_attempts=5,
            initial_delay=0.01,
            max_delay=0.1
        ))
        result, stats = strategy.execute(flaky_func)
        
        self.assertEqual(result, "success")
        self.assertTrue(stats.successful)
        self.assertEqual(stats.attempt, 3)
        self.assertEqual(len(stats.errors), 2)
        
    def test_retry_exhausted_raises(self):
        """Test exception raised after all retries exhausted."""
        def always_fails():
            raise ValueError("Permanent error")
            
        strategy = RetryStrategy(RetryConfig(
            max_attempts=3,
            initial_delay=0.01
        ))
        
        with self.assertRaises(ValueError) as ctx:
            strategy.execute(always_fails)
            
        self.assertEqual(str(ctx.exception), "Permanent error")
        
    def test_retry_decorator(self):
        """Test retry decorator."""
        call_count = [0]
        
        @retry(max_attempts=5, initial_delay=0.01)
        def flaky_func():
            call_count[0] += 1
            if call_count[0] < 3:
                raise ValueError("Temporary")
            return "success"
            
        result = flaky_func()
        self.assertEqual(result, "success")
        self.assertEqual(call_count[0], 3)
        
    def test_retry_with_stats_decorator(self):
        """Test retry decorator returning stats."""
        call_count = [0]
        
        @retry_with_stats(max_attempts=5, initial_delay=0.01)
        def flaky_func():
            call_count[0] += 1
            if call_count[0] < 3:
                raise ValueError("Temporary")
            return "success"
            
        result, stats = flaky_func()
        self.assertEqual(result, "success")
        self.assertEqual(stats.attempt, 3)
        
    def test_backoff_strategies(self):
        """Test different backoff strategies produce valid delays."""
        config = RetryConfig(initial_delay=0.1, multiplier=2, max_delay=10)
        
        for strategy_type in BackoffStrategy:
            config.backoff_strategy = strategy_type
            strategy = RetryStrategy(config)
            
            for attempt in range(5):
                delay = strategy.calculate_delay(attempt)
                self.assertGreaterEqual(delay, 0)
                self.assertLessEqual(delay, 10)
                
    def test_jitter_types(self):
        """Test jitter types produce valid delays."""
        config = RetryConfig(initial_delay=1.0, max_delay=10)
        
        for jitter_type in JitterType:
            config.jitter_type = jitter_type
            strategy = RetryStrategy(config)
            
            delays = [strategy.calculate_delay(i) for i in range(5)]
            for delay in delays:
                self.assertGreaterEqual(delay, 0)
                
    def test_retry_budget(self):
        """Test retry budget limits retries."""
        budget = RetryBudget(max_retries_per_minute=5, max_concurrent_retries=10)
        
        for _ in range(5):
            self.assertTrue(budget.can_retry())
            budget.record_retry_start()
            
        # Should exceed rate limit
        self.assertFalse(budget.can_retry())
        
    def test_dont_retry_exceptions(self):
        """Test certain exceptions don't trigger retry."""
        class PermanentError(Exception):
            pass
            
        strategy = RetryStrategy(RetryConfig(
            max_attempts=3,
            initial_delay=0.01,
            dont_retry_on_exceptions=(PermanentError,)
        ))
        
        def raise_permanent():
            raise PermanentError("Don't retry")
            
        with self.assertRaises(PermanentError):
            strategy.execute(raise_permanent)


class TestCircuitBreaker(unittest.TestCase):
    """Test circuit breaker pattern."""
    
    def test_circuit_closed_normal_operation(self):
        """Test normal operation when circuit is closed."""
        cb = CircuitBreaker(name="test")
        
        def success_func():
            return "success"
            
        result = cb.execute(success_func)
        self.assertEqual(result, "success")
        self.assertEqual(cb.state, CircuitState.CLOSED)
        
    def test_circuit_opens_after_failures(self):
        """Test circuit opens after failure threshold."""
        config = CircuitBreakerConfig(
            failure_threshold=3,
            recovery_timeout_seconds=1.0
        )
        cb = CircuitBreaker(config, name="test")
        
        def failing_func():
            raise ValueError("Failure")
            
        # Trigger failures
        for _ in range(3):
            with self.assertRaises(ValueError):
                cb.execute(failing_func)
                
        # Circuit should now be open
        self.assertEqual(cb.state, CircuitState.OPEN)
        
        # Next call should be rejected immediately
        with self.assertRaises(CircuitOpenError):
            cb.execute(failing_func)
            
    def test_circuit_half_open_recovery(self):
        """Test circuit transitions to half-open after timeout."""
        config = CircuitBreakerConfig(
            failure_threshold=2,
            recovery_timeout_seconds=0.1,
            success_threshold=2
        )
        cb = CircuitBreaker(config, name="test")
        
        def failing_func():
            raise ValueError("Failure")
            
        # Open the circuit
        for _ in range(2):
            with self.assertRaises(ValueError):
                cb.execute(failing_func)
                
        self.assertEqual(cb.state, CircuitState.OPEN)
        
        # Wait for recovery timeout
        time.sleep(0.15)
        
        def success_func():
            return "success"
            
        # Should transition to half-open and allow request
        result = cb.execute(success_func)
        self.assertEqual(result, "success")
        self.assertIn(cb.state, (CircuitState.HALF_OPEN, CircuitState.CLOSED))
        
    def test_circuit_breaker_decorator(self):
        """Test circuit breaker decorator."""
        call_count = [0]
        
        @circuit_breaker(failure_threshold=3, recovery_timeout_seconds=1.0)
        def flaky_func():
            call_count[0] += 1
            if call_count[0] < 5:
                raise ValueError("Fail")
            return "success"
            
        # Trigger circuit open
        for _ in range(3):
            with self.assertRaises(ValueError):
                flaky_func()
                
        # Circuit should be open
        with self.assertRaises(CircuitOpenError):
            flaky_func()
            
    def test_circuit_fallback(self):
        """Test fallback function when circuit is open."""
        def fallback():
            return "fallback_result"
            
        config = CircuitBreakerConfig(
            failure_threshold=2,
            recovery_timeout_seconds=10.0,
            fallback_function=fallback
        )
        cb = CircuitBreaker(config, name="test")
        
        def failing_func():
            raise ValueError("Failure")
            
        # Open circuit
        for _ in range(2):
            with self.assertRaises(ValueError):
                cb.execute(failing_func)
                
        # Should use fallback
        result = cb.execute(failing_func)
        self.assertEqual(result, "fallback_result")
        
    def test_circuit_reset(self):
        """Test manual circuit reset."""
        cb = CircuitBreaker(name="test")
        cb.force_open()
        self.assertEqual(cb.state, CircuitState.OPEN)
        
        cb.reset()
        self.assertEqual(cb.state, CircuitState.CLOSED)
        
    def test_global_circuit_registry(self):
        """Test global circuit breaker registry."""
        cb1 = get_circuit_breaker("api_service")
        cb2 = get_circuit_breaker("api_service")
        
        self.assertIs(cb1, cb2)


class TestGracefulDegradation(unittest.TestCase):
    """Test graceful degradation."""
    
    def test_graceful_degradation_fallback(self):
        """Test fallback when primary fails."""
        gd = GracefulDegradation()
        
        def primary(x):
            raise ValueError("Primary failed")
            
        def fallback(x):
            return f"fallback_{x}"
            
        gd.register_feature("test_feature", primary, fallback)
        
        result = gd.execute("test_feature", primary, "input")
        self.assertEqual(result, "fallback_input")
        
    def test_global_graceful_degradation(self):
        """Test global graceful degradation instance."""
        gd = get_graceful_degradation()
        self.assertIsInstance(gd, GracefulDegradation)


class TestBulkhead(unittest.TestCase):
    """Test bulkhead isolation pattern."""
    
    def test_bulkhead_acquire_release(self):
        """Test basic bulkhead acquire and release."""
        bulkhead = Bulkhead(max_concurrent_requests=2, name="test")
        
        self.assertTrue(bulkhead.acquire())
        self.assertEqual(bulkhead.active_requests, 1)
        
        bulkhead.release()
        self.assertEqual(bulkhead.active_requests, 0)
        
    def test_bulkhead_exhausted(self):
        """Test bulkhead rejects when capacity exhausted."""
        bulkhead = Bulkhead(
            max_concurrent_requests=2,
            max_queue_size=0,
            name="test"
        )
        
        bulkhead.acquire()
        bulkhead.acquire()
        
        # Third request should be rejected
        self.assertFalse(bulkhead.acquire())
        
    def test_bulkhead_context_manager(self):
        """Test bulkhead as context manager."""
        bulkhead = Bulkhead(max_concurrent_requests=1, name="test")
        
        with bulkhead():
            self.assertEqual(bulkhead.active_requests, 1)
            
        self.assertEqual(bulkhead.active_requests, 0)
        
    def test_bulkhead_exhausted_raises(self):
        """Test context manager raises on exhaustion."""
        bulkhead = Bulkhead(
            max_concurrent_requests=1,
            max_queue_size=0,
            name="test"
        )
        
        bulkhead.acquire()
        
        with self.assertRaises(BulkheadExhaustedError):
            with bulkhead():
                pass
                
    def test_global_bulkhead_registry(self):
        """Test global bulkhead registry."""
        bh1 = get_bulkhead("database", max_concurrent=5)
        bh2 = get_bulkhead("database")
        
        self.assertIs(bh1, bh2)
        self.assertEqual(bh1.max_concurrent_requests, 5)


class TestIntegration(unittest.TestCase):
    """Integration tests for error resilience patterns."""
    
    def test_retry_with_circuit_breaker(self):
        """Test retry and circuit breaker working together."""
        call_count = [0]
        
        def flaky_external_call():
            call_count[0] += 1
            if call_count[0] < 4:
                raise ConnectionError("Network error")
            return "success"
            
        # Wrap with both patterns
        @retry(max_attempts=5, initial_delay=0.01)
        @circuit_breaker(failure_threshold=10, recovery_timeout_seconds=5.0)
        def protected_call():
            return flaky_external_call()
            
        result = protected_call()
        self.assertEqual(result, "success")
        self.assertEqual(call_count[0], 4)
        
    def test_exception_chain_with_retry(self):
        """Test exception information preserved through retry."""
        strategy = RetryStrategy(RetryConfig(
            max_attempts=3,
            initial_delay=0.01
        ))
        
        def raise_custom():
            raise ExternalServiceError(
                service_name="test_api",
                status_code=500
            )
            
        with self.assertRaises(ExternalServiceError) as ctx:
            strategy.execute(raise_custom)
            
        self.assertEqual(ctx.exception.context["service_name"], "test_api")
        self.assertEqual(ctx.exception.context["status_code"], 500)


if __name__ == "__main__":
    unittest.main(verbosity=2)
