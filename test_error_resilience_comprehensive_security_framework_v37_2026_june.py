"""
Tests for Error Resilience Comprehensive Security Framework v37
Dimension E: Error Resilience - June 2026

All tests verify happy path behavior is 100% preserved.
No existing tests are modified - only new tests added.
"""

import pytest
import time
import threading
from unittest.mock import MagicMock, patch

from neural_shield.error_resilience_comprehensive_security_framework_v37_2026_june import (
    # Exceptions
    NeuralShieldError,
    NeuralShieldWarning,
    NeuralShieldCritical,
    ThreatDetectionError,
    ThreatDetectionTimeout,
    ThreatDetectionTemporaryFailure,
    ThreatDetectionPermanentFailure,
    ModelInferenceError,
    ModelInferenceTimeout,
    ModelInferenceOverloaded,
    ModelInferenceUnavailable,
    SecurityValidationError,
    InputValidationError,
    RateLimitExceeded,
    
    # Retry
    RetryStrategy,
    RetryConfig,
    RetryManager,
    
    # Timeout
    TimeoutContext,
    TimeoutManager,
    
    # Fallback
    FallbackStrategy,
    FallbackConfig,
    GracefulDegradationManager,
    
    # Composite
    SecurityErrorResilienceManager,
)


# -----------------------------------------------------------------------------
# Exception Hierarchy Tests
# -----------------------------------------------------------------------------

class TestExceptionHierarchy:
    """Test custom exception hierarchy."""
    
    def test_base_exception_attributes(self):
        """Test base exception has required attributes."""
        exc = NeuralShieldError("Test message", details={"key": "value"})
        assert exc.error_code == "NEURALSHIELD_ERROR"
        assert exc.severity == "ERROR"
        assert exc.details == {"key": "value"}
        assert exc.timestamp is not None
    
    def test_warning_exception(self):
        """Test warning exception inheritance."""
        exc = NeuralShieldWarning("Test")
        assert isinstance(exc, NeuralShieldError)
        assert exc.severity == "WARNING"
    
    def test_critical_exception(self):
        """Test critical exception inheritance."""
        exc = NeuralShieldCritical("Test")
        assert isinstance(exc, NeuralShieldError)
        assert exc.severity == "CRITICAL"
    
    def test_threat_detection_exceptions(self):
        """Test threat detection exception hierarchy."""
        assert issubclass(ThreatDetectionTimeout, ThreatDetectionError)
        assert issubclass(ThreatDetectionTimeout, NeuralShieldWarning)
        assert issubclass(ThreatDetectionTemporaryFailure, ThreatDetectionError)
        assert issubclass(ThreatDetectionPermanentFailure, NeuralShieldCritical)
    
    def test_model_inference_exceptions(self):
        """Test model inference exception hierarchy."""
        assert issubclass(ModelInferenceTimeout, ModelInferenceError)
        assert issubclass(ModelInferenceOverloaded, NeuralShieldWarning)
        assert issubclass(ModelInferenceUnavailable, NeuralShieldCritical)
    
    def test_security_validation_exceptions(self):
        """Test security validation exception hierarchy."""
        assert issubclass(InputValidationError, SecurityValidationError)
        assert issubclass(RateLimitExceeded, NeuralShieldWarning)


# -----------------------------------------------------------------------------
# Retry Manager Tests
# -----------------------------------------------------------------------------

class TestRetryManager:
    """Test retry manager functionality."""
    
    def test_retry_happy_path_no_error(self):
        """Happy path: function succeeds on first try."""
        retry_manager = RetryManager(RetryConfig(max_attempts=3))
        
        call_count = [0]
        
        @retry_manager
        def successful_function():
            call_count[0] += 1
            return "success"
        
        result = successful_function()
        assert result == "success"
        assert call_count[0] == 1  # Only called once
    
    def test_retry_eventually_succeeds(self):
        """Test function succeeds after temporary failures."""
        retry_manager = RetryManager(RetryConfig(max_attempts=3, initial_delay=0.001))
        
        call_count = [0]
        
        @retry_manager
        def flaky_function():
            call_count[0] += 1
            if call_count[0] < 3:
                raise ThreatDetectionTemporaryFailure("Temporary error")
            return "success"
        
        result = flaky_function()
        assert result == "success"
        assert call_count[0] == 3  # Succeeds on 3rd try
    
    def test_retry_exhausted_raises(self):
        """Test exception raised when all retries fail."""
        retry_manager = RetryManager(RetryConfig(max_attempts=2, initial_delay=0.001))
        
        call_count = [0]
        
        @retry_manager
        def always_fails():
            call_count[0] += 1
            raise ThreatDetectionTemporaryFailure("Always fails")
        
        with pytest.raises(ThreatDetectionTemporaryFailure):
            always_fails()
        
        assert call_count[0] == 2
    
    def test_non_retryable_exception_passthrough(self):
        """Non-retryable exceptions pass through immediately."""
        retry_manager = RetryManager(RetryConfig(max_attempts=3))
        
        call_count = [0]
        
        @retry_manager
        def permanent_failure():
            call_count[0] += 1
            raise ThreatDetectionPermanentFailure("Permanent error")
        
        with pytest.raises(ThreatDetectionPermanentFailure):
            permanent_failure()
        
        assert call_count[0] == 1  # No retries
    
    def test_retry_stats_tracking(self):
        """Test retry statistics are tracked."""
        retry_manager = RetryManager(RetryConfig(max_attempts=2, initial_delay=0.001))
        
        @retry_manager
        def flaky():
            raise ThreatDetectionTemporaryFailure("Error")
        
        with pytest.raises(ThreatDetectionTemporaryFailure):
            flaky()
        
        stats = retry_manager.get_retry_stats()
        assert len(stats) > 0


# -----------------------------------------------------------------------------
# Timeout Manager Tests
# -----------------------------------------------------------------------------

class TestTimeoutManager:
    """Test timeout manager functionality."""
    
    def test_timeout_happy_path_no_timeout(self):
        """Happy path: function completes within timeout."""
        timeout_manager = TimeoutManager(default_timeout=1.0)
        
        @timeout_manager.with_timeout(0.5)
        def fast_function():
            return "done"
        
        result = fast_function()
        assert result == "done"
    
    def test_timeout_context_propagation(self):
        """Test timeout context propagates to nested calls."""
        timeout_manager = TimeoutManager()
        
        @timeout_manager.with_timeout(1.0, "outer")
        def outer():
            return timeout_manager._get_current_context()
        
        ctx = outer()
        assert ctx is not None
        assert ctx.operation_name == "outer"
        assert ctx.remaining_time() > 0
    
    def test_timeout_check_raises_when_expired(self):
        """Test timeout check raises when deadline expired."""
        timeout_manager = TimeoutManager()
        
        @timeout_manager.with_timeout(0.001)
        def slow_function():
            time.sleep(0.01)
            timeout_manager.check_timeout()
        
        with pytest.raises(ThreatDetectionTimeout):
            slow_function()
    
    def test_timeout_context_thread_safety(self):
        """Test timeout context is thread-local."""
        timeout_manager = TimeoutManager()
        contexts = []
        
        def worker(name):
            @timeout_manager.with_timeout(1.0, name)
            def func():
                time.sleep(0.01)
                return timeout_manager._get_current_context()
            contexts.append(func())
        
        t1 = threading.Thread(target=worker, args=("thread1",))
        t2 = threading.Thread(target=worker, args=("thread2",))
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        
        assert len(contexts) == 2
        assert contexts[0].operation_name != contexts[1].operation_name


# -----------------------------------------------------------------------------
# Graceful Degradation Manager Tests
# -----------------------------------------------------------------------------

class TestGracefulDegradationManager:
    """Test graceful degradation functionality."""
    
    def test_happy_path_no_fallback(self):
        """Happy path: no fallback needed, function succeeds normally."""
        fallback_manager = GracefulDegradationManager()
        
        @fallback_manager.with_fallback(FallbackConfig(default_value="fallback"))
        def normal_function():
            return "normal"
        
        result = normal_function()
        assert result == "normal"  # No fallback activated
    
    def test_fallback_returns_default_on_error(self):
        """Test fallback returns default value when function errors."""
        fallback_manager = GracefulDegradationManager()
        
        @fallback_manager.with_fallback(FallbackConfig(
            strategy=FallbackStrategy.RETURN_DEFAULT,
            default_value="safe_default",
            log_warnings=False
        ))
        def failing_function():
            raise ValueError("Something went wrong")
        
        result = failing_function()
        assert result == "safe_default"
    
    def test_fallback_returns_cached_value(self):
        """Test cached value fallback strategy."""
        fallback_manager = GracefulDegradationManager()
        call_count = [0]
        
        @fallback_manager.with_fallback(FallbackConfig(
            strategy=FallbackStrategy.RETURN_CACHED,
            default_value="default",
            cache_ttl=60.0,
            log_warnings=False
        ))
        def flaky_function():
            call_count[0] += 1
            if call_count[0] == 1:
                return "first_result"
            raise ValueError("Error")
        
        # First call succeeds and caches
        assert flaky_function() == "first_result"
        # Second call fails but returns cached value
        assert flaky_function() == "first_result"
    
    def test_fallback_function_called(self):
        """Test degraded functionality fallback strategy."""
        fallback_manager = GracefulDegradationManager()
        
        def degraded_version():
            return "degraded_result"
        
        @fallback_manager.with_fallback(FallbackConfig(
            strategy=FallbackStrategy.DEGRADE_FUNCTIONALITY,
            fallback_function=degraded_version,
            log_warnings=False
        ))
        def failing_function():
            raise ValueError("Error")
        
        result = failing_function()
        assert result == "degraded_result"
    
    def test_fallback_stats_tracking(self):
        """Test fallback statistics are tracked."""
        fallback_manager = GracefulDegradationManager()
        
        @fallback_manager.with_fallback(FallbackConfig(
            default_value="default",
            log_warnings=False
        ))
        def failing():
            raise ValueError("Error")
        
        failing()
        failing()
        
        stats = fallback_manager.get_fallback_stats()
        assert stats["total_fallbacks"] == 2


# -----------------------------------------------------------------------------
# Composite Manager Tests
# -----------------------------------------------------------------------------

class TestSecurityErrorResilienceManager:
    """Test composite error resilience manager."""
    
    def test_happy_path_all_features(self):
        """Happy path: all features wrap function without breaking behavior."""
        resilience = SecurityErrorResilienceManager()
        
        @resilience.secure_operation(timeout=1.0, retry=True, fallback=True)
        def secure_function(x, y):
            return x + y
        
        result = secure_function(2, 3)
        assert result == 5  # Normal behavior preserved
    
    def test_health_metrics_available(self):
        """Test health metrics are available."""
        resilience = SecurityErrorResilienceManager()
        metrics = resilience.get_health_metrics()
        
        assert "retry_stats" in metrics
        assert "fallback_stats" in metrics
        assert "timestamp" in metrics


# -----------------------------------------------------------------------------
# Integration Tests
# -----------------------------------------------------------------------------

class TestErrorResilienceIntegration:
    """Integration tests for error resilience features."""
    
    def test_full_security_pipeline_resilience(self):
        """Test full security pipeline with all resilience features."""
        resilience = SecurityErrorResilienceManager(default_timeout=5.0)
        
        detection_results = []
        
        @resilience.secure_operation(timeout=2.0, retry=True, fallback=True)
        def detect_threats(input_text: str) -> dict:
            detection_results.append(input_text)
            return {
                "input": input_text,
                "threat_detected": False,
                "confidence": 0.95
            }
        
        # Happy path - normal operation
        result = detect_threats("test input")
        assert result["threat_detected"] is False
        assert result["confidence"] == 0.95
        assert len(detection_results) == 1
    
    def test_exception_chaining_preserved(self):
        """Test exception chaining is properly preserved."""
        retry_manager = RetryManager(RetryConfig(max_attempts=1, initial_delay=0.001))
        
        original_error = ValueError("Original cause")
        
        @retry_manager
        def failing_func():
            raise ThreatDetectionTemporaryFailure("Wrapper") from original_error
        
        try:
            failing_func()
        except ThreatDetectionTemporaryFailure as e:
            assert e.__cause__ is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
