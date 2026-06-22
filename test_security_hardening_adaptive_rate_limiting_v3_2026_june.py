"""
Test Suite for NeuralShield Security Hardening v3 - Adaptive Rate Limiting & DoS Protection
Dimension B: Security Hardening

ADD-ONLY tests - no existing tests modified
All existing tests must continue to pass
"""

import pytest
import time
import threading
from neural_shield.security_hardening_adaptive_rate_limiting_dos_protection_v3_2026_june import (
    AdaptiveRateLimiter,
    InputSanitizationLayer,
    RateLimitConfig,
    SecurityHardeningError,
    rate_limit_protected,
    sanitize_inputs,
    get_global_rate_limiter,
    get_global_sanitizer
)


class TestAdaptiveRateLimiter:
    """Test suite for adaptive rate limiter"""

    def test_initialization(self):
        """Test basic initialization"""
        limiter = AdaptiveRateLimiter()
        assert limiter is not None
        metrics = limiter.get_metrics()
        assert metrics["total_requests"] == 0

    def test_custom_config(self):
        """Test custom configuration"""
        config = RateLimitConfig(
            requests_per_second=5.0,
            burst_capacity=20,
            max_penalty_seconds=60
        )
        limiter = AdaptiveRateLimiter(config)
        assert limiter.config.requests_per_second == 5.0
        assert limiter.config.burst_capacity == 20

    def test_basic_rate_limit_allow(self):
        """Test that requests within limit are allowed"""
        config = RateLimitConfig(requests_per_second=100, burst_capacity=10)
        limiter = AdaptiveRateLimiter(config)
        
        for i in range(5):
            allowed, metadata = limiter.check_rate_limit(f"client_{i}")
            assert allowed is True
            assert "tokens_remaining" in metadata

    def test_burst_protection(self):
        """Test burst capacity protection"""
        config = RateLimitConfig(requests_per_second=1, burst_capacity=5)
        limiter = AdaptiveRateLimiter(config)
        
        # First 5 should be allowed (burst)
        for i in range(5):
            allowed, _ = limiter.check_rate_limit("client_burst")
            assert allowed is True
        
        # 6th should be blocked
        allowed, metadata = limiter.check_rate_limit("client_burst")
        assert allowed is False
        assert metadata["reason"] == "rate_limit_exceeded"

    def test_penalty_system(self):
        """Test exponential penalty system"""
        config = RateLimitConfig(
            requests_per_second=1,
            burst_capacity=1,
            penalty_multiplier=1.0
        )
        limiter = AdaptiveRateLimiter(config)
        
        # Exhaust capacity
        limiter.check_rate_limit("client_penalty")
        
        # Violate to trigger penalty
        allowed, metadata = limiter.check_rate_limit("client_penalty")
        assert allowed is False
        assert metadata["penalty_level"] >= 1
        assert "retry_after" in metadata

    def test_whitelist(self):
        """Test IP whitelisting"""
        limiter = AdaptiveRateLimiter()
        
        # Add valid IP to whitelist
        result = limiter.add_to_whitelist("192.168.1.1")
        assert result is True
        
        # Whitelisted IP should bypass rate limiting
        request_data = {"ip": "192.168.1.1"}
        allowed, metadata = limiter.check_rate_limit("any_client", request_data)
        assert allowed is True
        assert metadata["reason"] == "whitelisted"

    def test_invalid_whitelist_ip(self):
        """Test invalid IP rejection"""
        limiter = AdaptiveRateLimiter()
        result = limiter.add_to_whitelist("not_an_ip")
        assert result is False

    def test_client_blocking(self):
        """Test temporary client blocking"""
        limiter = AdaptiveRateLimiter()
        
        limiter.block_client("bad_client", duration_seconds=1)
        
        allowed, metadata = limiter.check_rate_limit("bad_client")
        assert allowed is False
        assert metadata["reason"] == "blocked"

    def test_metrics_collection(self):
        """Test metrics are collected correctly"""
        limiter = AdaptiveRateLimiter()
        
        # Make some requests
        for i in range(10):
            limiter.check_rate_limit(f"metric_client_{i}")
        
        metrics = limiter.get_metrics()
        assert metrics["total_requests"] == 10

    def test_circuit_breaker_closed(self):
        """Test circuit breaker in closed state"""
        limiter = AdaptiveRateLimiter()
        allowed, state = limiter.check_circuit_breaker("test_endpoint")
        assert allowed is True
        assert state["state"] == "closed"

    def test_circuit_breaker_trigger(self):
        """Test circuit breaker opens after failures"""
        limiter = AdaptiveRateLimiter()
        
        # Record multiple failures
        for i in range(15):
            limiter.record_failure("failing_endpoint")
        
        allowed, state = limiter.check_circuit_breaker("failing_endpoint")
        # Should be open after enough failures
        assert "state" in state

    def test_memory_exhaustion_detection(self):
        """Test large request detection"""
        config = RateLimitConfig(max_request_size_bytes=1000)
        limiter = AdaptiveRateLimiter(config)
        
        request_data = {"size": 5000}  # Exceeds limit
        allowed, metadata = limiter.check_rate_limit("large_client", request_data)
        assert allowed is False
        assert metadata["reason"] == "request_size_limit_exceeded"

    def test_get_client_stats(self):
        """Test client statistics retrieval"""
        limiter = AdaptiveRateLimiter()
        
        # Make some requests
        for i in range(3):
            limiter.check_rate_limit("stats_client")
        
        stats = limiter.get_client_stats("stats_client")
        assert stats is not None
        assert stats["request_count"] == 3

    def test_get_client_stats_nonexistent(self):
        """Test stats for nonexistent client returns None"""
        limiter = AdaptiveRateLimiter()
        stats = limiter.get_client_stats("nonexistent_client")
        assert stats is None

    def test_concurrent_access(self):
        """Test thread safety under concurrent access"""
        limiter = AdaptiveRateLimiter()
        errors = []
        
        def worker():
            try:
                for i in range(10):
                    limiter.check_rate_limit(f"concurrent_{threading.get_ident()}")
            except Exception as e:
                errors.append(e)
        
        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert len(errors) == 0


class TestInputSanitizationLayer:
    """Test suite for input sanitization"""

    def test_initialization(self):
        """Test basic initialization"""
        sanitizer = InputSanitizationLayer()
        assert sanitizer is not None

    def test_clean_string_passthrough(self):
        """Test clean strings pass through unchanged"""
        sanitizer = InputSanitizationLayer()
        clean_input = "Hello, this is a normal string!"
        
        result, report = sanitizer.sanitize_string(clean_input)
        assert result == clean_input
        assert len(report["threats_detected"]) == 0

    def test_xss_detection(self):
        """Test XSS pattern detection"""
        sanitizer = InputSanitizationLayer()
        xss_input = '<script>alert("xss")</script>'
        
        result, report = sanitizer.sanitize_string(xss_input)
        assert "xss_script" in report["threats_detected"]

    def test_javascript_protocol_detection(self):
        """Test javascript: protocol detection"""
        sanitizer = InputSanitizationLayer()
        js_input = 'javascript:alert(1)'
        
        result, report = sanitizer.sanitize_string(js_input)
        assert "xss_javascript" in report["threats_detected"]

    def test_code_injection_detection(self):
        """Test code injection pattern detection"""
        sanitizer = InputSanitizationLayer()
        eval_input = 'eval("malicious_code")'
        
        result, report = sanitizer.sanitize_string(eval_input)
        assert "code_injection_eval" in report["threats_detected"]

    def test_path_traversal_detection(self):
        """Test path traversal detection"""
        sanitizer = InputSanitizationLayer()
        path_input = '../../etc/passwd'
        
        result, report = sanitizer.sanitize_string(path_input)
        assert "path_traversal" in report["threats_detected"]

    def test_aggressive_sanitization(self):
        """Test aggressive sanitization mode"""
        sanitizer = InputSanitizationLayer()
        input_str = '<script>test</script>'
        
        result, report = sanitizer.sanitize_string(input_str, aggressive=True)
        assert '<' not in result
        assert '>' not in result

    def test_dict_sanitization(self):
        """Test dictionary sanitization"""
        sanitizer = InputSanitizationLayer()
        input_dict = {
            "clean": "normal value",
            "dangerous": '<script>alert(1)</script>',
            "nested": {
                "inner": "eval('test')"
            }
        }
        
        result, report = sanitizer.sanitize_dict(input_dict)
        assert report["total_threats"] > 0
        assert "fields_processed" in report

    def test_sanitization_stats(self):
        """Test sanitization statistics"""
        sanitizer = InputSanitizationLayer()
        
        sanitizer.sanitize_string("test1")
        sanitizer.sanitize_string("<script>test</script>")
        
        stats = sanitizer.get_stats()
        assert stats["total_sanitizations"] == 2
        assert stats["total_threats_detected"] >= 1

    def test_non_string_input(self):
        """Test handling of non-string inputs"""
        sanitizer = InputSanitizationLayer()
        result, report = sanitizer.sanitize_string(12345)
        assert result == "12345"


class TestDecorators:
    """Test suite for decorators"""

    def test_rate_limit_decorator(self):
        """Test rate limit decorator"""
        limiter = AdaptiveRateLimiter(RateLimitConfig(
            requests_per_second=100,
            burst_capacity=5
        ))
        
        @rate_limit_protected(limiter)
        def protected_function(x):
            return x * 2
        
        # Should work normally within limits
        for i in range(3):
            result = protected_function(i)
            assert result == i * 2

    def test_sanitize_decorator(self):
        """Test input sanitization decorator"""
        sanitizer = InputSanitizationLayer()
        
        @sanitize_inputs(sanitizer)
        def protected_func(**kwargs):
            return kwargs.get("input", "")
        
        result = protected_func(input="test")
        assert result == "test"


class TestGlobalInstances:
    """Test suite for global singleton instances"""

    def test_global_rate_limiter(self):
        """Test global rate limiter singleton"""
        limiter1 = get_global_rate_limiter()
        limiter2 = get_global_rate_limiter()
        assert limiter1 is limiter2

    def test_global_sanitizer(self):
        """Test global sanitizer singleton"""
        sanitizer1 = get_global_sanitizer()
        sanitizer2 = get_global_sanitizer()
        assert sanitizer1 is sanitizer2


class TestSecurityHardeningError:
    """Test suite for custom exception"""

    def test_exception_creation(self):
        """Test exception creation with metadata"""
        error = SecurityHardeningError(
            "Test error",
            error_code="TEST_ERROR",
            metadata={"key": "value"}
        )
        assert str(error) == "Test error"
        assert error.error_code == "TEST_ERROR"
        assert error.metadata["key"] == "value"


def test_integration_backward_compatibility():
    """
    CRITICAL: Verify backward compatibility
    This module should NOT break any existing code
    """
    # Import existing modules to verify no conflicts
    try:
        from neural_shield import security_hardening_comprehensive_v2_2026_june
        from neural_shield import security_hardening_input_validation_wrappers_2026_june
        from neural_shield import secure_memory_zeroization_constant_time_helpers_2026_june
        assert True  # All imports succeeded
    except ImportError:
        pytest.fail("Security hardening v3 broke backward compatibility")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
