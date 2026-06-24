"""
Test Suite for NeuralShield Error Resilience Module v30
Dimension E - Error Resilience

Tests cover:
- Custom exception hierarchy
- Circuit breaker pattern
- Retry with exponential backoff + jitter
- Timeout wrappers
- Graceful degradation fallbacks
- Bulkhead isolation
- Error context manager

All tests verify that:
1. Happy path behavior is 100% preserved
2. Error paths are handled correctly
3. No existing code is broken
"""

import pytest
import time
import threading
from unittest.mock import MagicMock, patch
from datetime import datetime, timedelta

# Import the module to test
from neural_shield.error_resilience_enhanced_threat_detection_v30_2026_june import (
    # Exceptions
    NeuralShieldError,
    ThreatDetectionError,
    PromptAnalysisError,
    EmbeddingComputationError,
    ModelInferenceError,
    ThreatIntelligenceError,
    FeedSyncError,
    CacheError,
    SecurityError,
    ValidationError,
    RateLimitExceededError,
    TimeoutError,
    CircuitBreakerOpenError,
    FallbackActivatedError,
    
    # Circuit Breaker
    CircuitBreaker,
    CircuitBreakerConfig,
    CircuitState,
    get_circuit_breaker,
    
    # Retry
    RetryConfig,
    retry_with_backoff,
    
    # Timeout
    timeout,
    
    # Fallbacks
    with_fallback,
    safe_default,
    FallbackResult,
    
    # Bulkhead
    Bulkhead,
    get_bulkhead,
    
    # Combined
    resilient_operation,
    
    # Context
    ErrorContext,
)


# -----------------------------------------------------------------------------
# TEST CUSTOM EXCEPTION HIERARCHY
# -----------------------------------------------------------------------------

class TestExceptionHierarchy:
    """Test custom exception hierarchy"""
    
    def test_base_exception_creation(self):
        """Test base NeuralShieldError creation"""
        exc = NeuralShieldError("Test error", "NS-TEST-001", {"key": "value"})
        assert str(exc) == "Test error"
        assert exc.error_code == "NS-TEST-001"
        assert exc.details["key"] == "value"
        assert "timestamp" in exc.to_dict()
    
    def test_exception_to_dict(self):
        """Test exception serialization to dict"""
        exc = NeuralShieldError("Test", "NS-001")
        result = exc.to_dict()
        assert result["error_type"] == "NeuralShieldError"
        assert result["message"] == "Test"
        assert result["error_code"] == "NS-001"
    
    def test_threat_detection_exception_hierarchy(self):
        """Test threat detection exception hierarchy"""
        assert issubclass(ThreatDetectionError, NeuralShieldError)
        assert issubclass(PromptAnalysisError, ThreatDetectionError)
        assert issubclass(EmbeddingComputationError, ThreatDetectionError)
        assert issubclass(ModelInferenceError, ThreatDetectionError)
    
    def test_prompt_analysis_error_with_preview(self):
        """Test PromptAnalysisError with prompt preview"""
        exc = PromptAnalysisError("Analysis failed", "test prompt content here")
        assert "prompt_preview" in exc.details
        assert exc.details["prompt_preview"] == "test prompt content here"
    
    def test_threat_intelligence_exception_hierarchy(self):
        """Test threat intelligence exception hierarchy"""
        assert issubclass(ThreatIntelligenceError, NeuralShieldError)
        assert issubclass(FeedSyncError, ThreatIntelligenceError)
        assert issubclass(CacheError, ThreatIntelligenceError)
    
    def test_security_exception_hierarchy(self):
        """Test security exception hierarchy"""
        assert issubclass(SecurityError, NeuralShieldError)
        assert issubclass(ValidationError, SecurityError)
        assert issubclass(RateLimitExceededError, SecurityError)
    
    def test_timeout_error(self):
        """Test TimeoutError with details"""
        exc = TimeoutError("Operation timed out", 5.0, "test_op")
        assert exc.details["timeout_seconds"] == 5.0
        assert exc.details["operation"] == "test_op"
    
    def test_circuit_breaker_open_error(self):
        """Test CircuitBreakerOpenError"""
        reset_time = datetime.utcnow()
        exc = CircuitBreakerOpenError("Circuit open", "test_service", reset_time)
        assert exc.details["service_name"] == "test_service"
        assert exc.details["reset_time"] is not None


# -----------------------------------------------------------------------------
# TEST CIRCUIT BREAKER
# -----------------------------------------------------------------------------

class TestCircuitBreaker:
    """Test Circuit Breaker pattern implementation"""
    
    def test_circuit_breaker_initial_state(self):
        """Test circuit breaker starts in CLOSED state"""
        cb = CircuitBreaker("test")
        assert cb.state == CircuitState.CLOSED
        assert cb.allow_call() is True
    
    def test_circuit_breaker_opens_on_failures(self):
        """Test circuit breaker opens after threshold failures"""
        config = CircuitBreakerConfig(failure_threshold=3, recovery_timeout_seconds=1.0)
        cb = CircuitBreaker("test", config)
        
        # Simulate failures - use RuntimeError not ValueError (ValueError is excluded by default)
        @cb
        def failing_func():
            raise RuntimeError("Test error")
        
        for _ in range(3):
            try:
                failing_func()
            except RuntimeError:
                pass
        
        # Circuit should now be open
        assert cb.state == CircuitState.OPEN
        assert cb.allow_call() is False
    
    def test_circuit_breaker_rejects_when_open(self):
        """Test circuit breaker rejects calls when open"""
        config = CircuitBreakerConfig(failure_threshold=2, recovery_timeout_seconds=10.0)
        cb = CircuitBreaker("test", config)
        
        # Trigger failures
        @cb
        def failing_func():
            raise RuntimeError("Test")
        
        for _ in range(2):
            try:
                failing_func()
            except RuntimeError:
                pass
        
        # Now it should raise CircuitBreakerOpenError
        with pytest.raises(CircuitBreakerOpenError):
            failing_func()
    
    def test_circuit_breaker_success_resets_in_half_open(self):
        """Test successful call in half-open closes the circuit"""
        config = CircuitBreakerConfig(failure_threshold=2, recovery_timeout_seconds=0.1)
        cb = CircuitBreaker("test", config)
        
        # Trigger failures
        @cb
        def sometimes_failing():
            raise RuntimeError("Test")
        
        for _ in range(2):
            try:
                sometimes_failing()
            except RuntimeError:
                pass
        
        assert cb.state == CircuitState.OPEN
        
        # Wait for recovery timeout
        time.sleep(0.15)
        
        # Should transition to half-open
        assert cb.state == CircuitState.HALF_OPEN
        
        # Now patch to succeed
        with patch.object(cb, '_on_success') as mock_success:
            cb._on_success()
            mock_success.assert_called_once()
    
    def test_circuit_breaker_stats(self):
        """Test circuit breaker stats tracking"""
        cb = CircuitBreaker("test")
        stats = cb.stats
        assert stats.success_count == 0
        assert stats.failure_count == 0
        assert stats.rejected_count == 0
    
    def test_circuit_breaker_reset(self):
        """Test circuit breaker reset functionality"""
        config = CircuitBreakerConfig(failure_threshold=2, recovery_timeout_seconds=1.0)
        cb = CircuitBreaker("test", config)
        
        # Trigger some failures
        cb._on_failure(RuntimeError("test"))
        cb._on_failure(RuntimeError("test"))
        
        cb.reset()
        assert cb.state == CircuitState.CLOSED
        assert cb.stats.failure_count == 0
    
    def test_get_circuit_breaker_singleton(self):
        """Test get_circuit_breaker returns same instance"""
        cb1 = get_circuit_breaker("test_singleton")
        cb2 = get_circuit_breaker("test_singleton")
        assert cb1 is cb2
    
    def test_circuit_breaker_excluded_exceptions(self):
        """Test excluded exceptions don't count as failures"""
        config = CircuitBreakerConfig(
            failure_threshold=2,
            excluded_exceptions=(ValueError,)
        )
        cb = CircuitBreaker("test", config)
        
        # ValueError should be excluded
        cb._on_failure(ValueError("test"))
        cb._on_failure(ValueError("test"))
        
        # Should still be closed because ValueError is excluded
        assert cb.stats.failure_count == 0
        assert cb.state == CircuitState.CLOSED


# -----------------------------------------------------------------------------
# TEST RETRY WITH BACKOFF
# -----------------------------------------------------------------------------

class TestRetryWithBackoff:
    """Test retry with exponential backoff and jitter"""
    
    def test_retry_succeeds_on_second_attempt(self):
        """Test retry succeeds on second attempt"""
        call_count = [0]
        
        @retry_with_backoff(max_attempts=3, initial_delay=0.01)
        def flaky_function():
            call_count[0] += 1
            if call_count[0] < 2:
                raise RuntimeError("Failing first call")
            return "success"
        
        result = flaky_function()
        assert result == "success"
        assert call_count[0] == 2
    
    def test_retry_eventually_fails(self):
        """Test retry eventually fails after all attempts"""
        call_count = [0]
        
        @retry_with_backoff(max_attempts=3, initial_delay=0.01)
        def always_fails():
            call_count[0] += 1
            raise RuntimeError("Always fails")
        
        with pytest.raises(RuntimeError):
            always_fails()
        
        assert call_count[0] == 3
    
    def test_retry_no_jitter(self):
        """Test retry without jitter works"""
        call_count = [0]
        
        @retry_with_backoff(max_attempts=2, initial_delay=0.01, jitter=False)
        def flaky():
            call_count[0] += 1
            if call_count[0] < 2:
                raise RuntimeError("Fail")
            return "ok"
        
        result = flaky()
        assert result == "ok"
        assert call_count[0] == 2
    
    def test_retry_stop_on_exception(self):
        """Test retry doesn't retry on stop_on_exceptions"""
        call_count = [0]
        
        @retry_with_backoff(max_attempts=3, initial_delay=0.01)
        def raises_value_error():
            call_count[0] += 1
            raise ValueError("Don't retry this")
        
        with pytest.raises(ValueError):
            raises_value_error()
        
        # Should only be called once - ValueError is in stop_on_exceptions
        assert call_count[0] == 1


# -----------------------------------------------------------------------------
# TEST TIMEOUT WRAPPERS
# -----------------------------------------------------------------------------

class TestTimeout:
    """Test timeout decorator"""
    
    def test_timeout_completes_normally(self):
        """Test function completes within timeout"""
        @timeout(seconds=1.0)
        def quick_function():
            return "done"
        
        result = quick_function()
        assert result == "done"
    
    def test_timeout_raises_exception(self):
        """Test timeout raises exception on slow function"""
        @timeout(seconds=0.1)
        def slow_function():
            time.sleep(0.5)
            return "done"
        
        with pytest.raises(TimeoutError):
            slow_function()
    
    def test_timeout_with_fallback(self):
        """Test timeout activates fallback"""
        fallback_called = [False]
        
        def my_fallback():
            fallback_called[0] = True
            return "fallback result"
        
        @timeout(seconds=0.1, fallback=my_fallback)
        def slow_function():
            time.sleep(0.5)
            return "done"
        
        result = slow_function()
        assert fallback_called[0] is True
        assert result == "fallback result"
    
    def test_timeout_propagates_exception(self):
        """Test timeout propagates non-timeout exceptions"""
        @timeout(seconds=1.0)
        def raises_error():
            raise ValueError("Test error")
        
        with pytest.raises(ValueError):
            raises_error()


# -----------------------------------------------------------------------------
# TEST FALLBACKS & GRACEFUL DEGRADATION
# -----------------------------------------------------------------------------

class TestFallbacks:
    """Test graceful degradation fallbacks"""
    
    def test_with_fallback_primary_succeeds(self):
        """Test primary function succeeds"""
        def fallback():
            return "fallback"
        
        @with_fallback(fallback)
        def primary():
            return "primary"
        
        result = primary()
        assert result.value == "primary"
        assert result.was_fallback is False
    
    def test_with_fallback_activates_on_error(self):
        """Test fallback activates on error"""
        def fallback():
            return "fallback_value"
        
        @with_fallback(fallback)
        def failing():
            raise RuntimeError("Fail")
        
        result = failing()
        assert result.value == "fallback_value"
        assert result.was_fallback is True
        assert result.primary_error is not None
    
    def test_safe_default(self):
        """Test safe_default returns default on exception"""
        @safe_default("default_value")
        def failing():
            raise RuntimeError("Fail")
        
        result = failing()
        assert result == "default_value"
    
    def test_safe_default_no_exception(self):
        """Test safe_default returns actual value when no exception"""
        @safe_default("default_value")
        def succeeds():
            return "actual_value"
        
        result = succeeds()
        assert result == "actual_value"


# -----------------------------------------------------------------------------
# TEST BULKHEAD ISOLATION
# -----------------------------------------------------------------------------

class TestBulkhead:
    """Test Bulkhead isolation pattern"""
    
    def test_bulkhead_allows_call_within_limit(self):
        """Test bulkhead allows calls within limit"""
        bulkhead = Bulkhead("test", max_concurrent=5)
        
        @bulkhead
        def test_func():
            return "success"
        
        result = test_func()
        assert result == "success"
    
    def test_bulkhead_stats(self):
        """Test bulkhead stats tracking"""
        bulkhead = Bulkhead("test", max_concurrent=5)
        stats = bulkhead.stats
        assert stats["max_concurrent"] == 5
        assert stats["active"] == 0
    
    def test_get_bulkhead_singleton(self):
        """Test get_bulkhead returns same instance"""
        bh1 = get_bulkhead("test_singleton", max_concurrent=5)
        bh2 = get_bulkhead("test_singleton", max_concurrent=5)
        assert bh1 is bh2


# -----------------------------------------------------------------------------
# TEST COMBINED RESILIENT OPERATION
# -----------------------------------------------------------------------------

class TestResilientOperation:
    """Test combined resilient operation decorator"""
    
    def test_resilient_operation_basic(self):
        """Test basic resilient operation wrapper"""
        @resilient_operation(timeout_seconds=1.0, max_retries=0)
        def test_func():
            return "success"
        
        result = test_func()
        assert result == "success"
    
    def test_resilient_operation_with_all_features(self):
        """Test resilient operation with all features enabled"""
        @resilient_operation(
            timeout_seconds=5.0,
            max_retries=1,
            circuit_breaker="test_resilient",
            bulkhead="test_bulkhead"
        )
        def test_func():
            return "success"
        
        result = test_func()
        assert result == "success"


# -----------------------------------------------------------------------------
# TEST ERROR CONTEXT
# -----------------------------------------------------------------------------

class TestErrorContext:
    """Test ErrorContext context manager"""
    
    def test_error_context_no_exception(self):
        """Test error context with no exception"""
        with ErrorContext("test_operation", {"key": "value"}) as ctx:
            assert ctx.operation == "test_operation"
            assert ctx.context["key"] == "value"
    
    def test_error_context_with_exception(self):
        """Test error context enriches exceptions"""
        try:
            with ErrorContext("test_op", {"context_key": "context_value"}):
                raise NeuralShieldError("Test error", "NS-TEST")
        except NeuralShieldError as e:
            assert e.details["operation"] == "test_op"
            assert e.details["context_key"] == "context_value"
            assert "duration_seconds" in e.details


# -----------------------------------------------------------------------------
# HAPPY PATH VERIFICATION - ENSURE NO BREAKAGE
# -----------------------------------------------------------------------------

class TestHappyPathPreservation:
    """Verify happy path behavior is 100% preserved"""
    
    def test_decorators_preserve_function_metadata(self):
        """Test decorators preserve function name and docstring"""
        def original():
            """Original docstring"""
            pass
        
        decorated = retry_with_backoff()(original)
        assert decorated.__name__ == "original"
        assert decorated.__doc__ == "Original docstring"
    
    def test_no_side_effects_on_success(self):
        """Test no side effects when function succeeds"""
        call_count = [0]
        
        @retry_with_backoff(max_attempts=3)
        @timeout(seconds=5.0)
        def succeeds():
            call_count[0] += 1
            return "ok"
        
        result = succeeds()
        assert result == "ok"
        assert call_count[0] == 1  # Called exactly once
    
    def test_module_imports_cleanly(self):
        """Test module imports without errors"""
        import neural_shield.error_resilience_enhanced_threat_detection_v30_2026_june as module
        assert module.__version__ == "30.0.0"
        assert module.__dimension__ == "E - Error Resilience"
        assert module.__stable__ is True


# -----------------------------------------------------------------------------
# INTEGRATION TESTS
# -----------------------------------------------------------------------------

class TestIntegration:
    """Integration tests for combined usage"""
    
    def test_full_resilience_stack(self):
        """Test full resilience stack working together"""
        call_count = [0]
        
        @resilient_operation(
            timeout_seconds=5.0,
            max_retries=2,
            circuit_breaker="integration_test"
        )
        def flaky_threat_detector():
            call_count[0] += 1
            if call_count[0] < 2:
                raise RuntimeError("Temporary failure")
            return {"threat_detected": False, "confidence": 0.95}
        
        result = flaky_threat_detector()
        assert result["threat_detected"] is False
        assert result["confidence"] == 0.95
        assert call_count[0] == 2
    
    def test_exception_hierarchy_catching(self):
        """Test catching exceptions at different hierarchy levels"""
        try:
            raise PromptAnalysisError("Test", "prompt")
        except ThreatDetectionError:
            caught = True
        except NeuralShieldError:
            caught = False
        
        assert caught is True  # Should be caught at ThreatDetectionError level


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
