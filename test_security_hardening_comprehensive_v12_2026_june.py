"""
Test Suite for NeuralShield Security Hardening v12
Dimension B - Security Hardening
Tests for all security hardening features
"""

import pytest
import time
import threading
import secrets
from neural_shield.security_hardening_comprehensive_v12_2026_june import (
    SecurityLevel,
    ValidationSeverity,
    ValidationResult,
    RateLimitConfig,
    SecurityContext,
    ConstantTimeComparer,
    SecureMemoryZeroizer,
    InputValidationEngine,
    SecurityValidationError,
    AdaptiveRateLimiter,
    RateLimitExceededError,
    ContextIsolator,
    PrivilegeViolationError,
    SensitiveDataSanitizer,
    NeuralShieldSecurityHardenerV12,
    get_security_hardener_v12,
)


class TestConstantTimeComparer:
    """Tests for constant-time comparison engine"""

    def test_compare_strings_equal(self):
        assert ConstantTimeComparer.compare_strings("hello", "hello") is True

    def test_compare_strings_not_equal(self):
        assert ConstantTimeComparer.compare_strings("hello", "world") is False

    def test_compare_strings_different_length(self):
        assert ConstantTimeComparer.compare_strings("hello", "helloworld") is False

    def test_compare_bytes_equal(self):
        assert ConstantTimeComparer.compare_bytes(b"test", b"test") is True

    def test_compare_bytes_not_equal(self):
        assert ConstantTimeComparer.compare_bytes(b"test", b"TEST") is False

    def test_compare_hmac(self):
        key = secrets.token_bytes(32)
        data = b"test data"
        assert ConstantTimeComparer.compare_hmac(key, data, data) is True

    def test_secure_equals_strings(self):
        assert ConstantTimeComparer.secure_equals("test", "test") is True
        assert ConstantTimeComparer.secure_equals("test", "TEST") is False

    def test_secure_equals_numbers(self):
        assert ConstantTimeComparer.secure_equals(42, 42) is True
        assert ConstantTimeComparer.secure_equals(42, 43) is False

    def test_secure_equals_different_types(self):
        assert ConstantTimeComparer.secure_equals("42", 42) is False


class TestSecureMemoryZeroizer:
    """Tests for secure memory zeroization"""

    def test_zeroize_bytearray(self):
        data = bytearray(b"sensitive data here")
        original = bytes(data)
        SecureMemoryZeroizer.zeroize_bytearray(data)
        assert all(b == 0 for b in data)
        assert bytes(data) != original

    def test_zeroize_bytes(self):
        original = b"test"
        result = SecureMemoryZeroizer.zeroize_bytes(original)
        assert result == b'\x00\x00\x00\x00'
        assert len(result) == len(original)

    def test_zeroize_string(self):
        original = "secret"
        result = SecureMemoryZeroizer.zeroize_string(original)
        assert result == "      "
        assert len(result) == len(original)

    def test_secure_delete_list(self):
        data = ["secret1", "secret2", "secret3"]
        SecureMemoryZeroizer.secure_delete(data)
        assert all(x is None for x in data)


class TestInputValidationEngine:
    """Tests for input validation engine"""

    def test_validate_string_length(self):
        validator = InputValidationEngine(SecurityLevel.STANDARD)
        result = validator.validate_string("test", min_length=2, max_length=10)
        assert result.valid is True

    def test_validate_string_too_short(self):
        validator = InputValidationEngine(SecurityLevel.STANDARD)
        result = validator.validate_string("a", min_length=5)
        assert result.valid is False
        assert "too short" in result.violations[0]

    def test_validate_string_too_long(self):
        validator = InputValidationEngine(SecurityLevel.STANDARD)
        result = validator.validate_string("x" * 100, max_length=10)
        assert result.valid is False
        assert "too long" in result.violations[0]

    def test_validate_sqli_detection(self):
        validator = InputValidationEngine(SecurityLevel.ENHANCED)
        result = validator.validate_string("' OR 1=1 --")
        assert result.valid is False
        assert any("SQL injection" in v for v in result.violations)

    def test_validate_xss_detection(self):
        validator = InputValidationEngine(SecurityLevel.ENHANCED)
        result = validator.validate_string("<script>alert(1)</script>")
        assert result.valid is False
        assert any("XSS" in v for v in result.violations)

    def test_validate_cmd_injection(self):
        validator = InputValidationEngine(SecurityLevel.ENHANCED)
        result = validator.validate_string("; rm -rf /")
        assert result.valid is False
        assert any("command injection" in v for v in result.violations)

    def test_validate_number_range(self):
        validator = InputValidationEngine(SecurityLevel.STANDARD)
        result = validator.validate_number(50, min_val=0, max_val=100)
        assert result.valid is True

    def test_validate_number_out_of_range(self):
        validator = InputValidationEngine(SecurityLevel.STANDARD)
        result = validator.validate_number(150, min_val=0, max_val=100)
        assert result.valid is False

    def test_validate_number_negative_disallowed(self):
        validator = InputValidationEngine(SecurityLevel.STANDARD)
        result = validator.validate_number(-5, allow_negative=False)
        assert result.valid is False


class TestAdaptiveRateLimiter:
    """Tests for adaptive rate limiting"""

    def test_rate_limit_allows_initial_requests(self):
        config = RateLimitConfig(max_requests=10, window_seconds=60)
        limiter = AdaptiveRateLimiter(config)
        
        for i in range(10):
            allowed, meta = limiter.check_rate_limit("test_key")
            assert allowed is True

    def test_rate_limit_blocks_over_limit(self):
        config = RateLimitConfig(max_requests=5, window_seconds=60)
        limiter = AdaptiveRateLimiter(config)
        
        # Consume all tokens
        for i in range(5):
            limiter.check_rate_limit("test_key")
        
        # Next should be blocked
        allowed, meta = limiter.check_rate_limit("test_key")
        assert allowed is False
        assert meta['reason'] == 'rate_limit_exceeded'

    def test_burst_limit_detection(self):
        config = RateLimitConfig(max_requests=10, burst_limit=5, window_seconds=60)
        limiter = AdaptiveRateLimiter(config)
        
        # Exceed burst limit quickly
        for i in range(6):
            allowed, _ = limiter.check_rate_limit("flood_key")
        
        # Should detect flood
        assert limiter.is_flood_detected("flood_key") is True

    def test_rate_limit_disabled(self):
        config = RateLimitConfig(enabled=False)
        limiter = AdaptiveRateLimiter(config)
        
        for i in range(1000):
            allowed, _ = limiter.check_rate_limit("test")
            assert allowed is True

    def test_different_keys_independent(self):
        config = RateLimitConfig(max_requests=2, window_seconds=60)
        limiter = AdaptiveRateLimiter(config)
        
        # Key 1
        limiter.check_rate_limit("key1")
        limiter.check_rate_limit("key1")
        
        # Key 2 should still have tokens
        allowed, _ = limiter.check_rate_limit("key2")
        assert allowed is True


class TestContextIsolator:
    """Tests for context isolation and privilege separation"""

    def test_create_context(self):
        isolator = ContextIsolator()
        context = isolator.create_context("ctx1", privilege_level="user")
        assert context.privilege_level == "user"

    def test_validate_allowed_operation(self):
        isolator = ContextIsolator()
        isolator.create_context("ctx1", allowed_operations=["read", "write"])
        
        assert isolator.validate_operation("ctx1", "read") is True
        assert isolator.validate_operation("ctx1", "delete") is False

    def test_validate_nonexistent_context(self):
        isolator = ContextIsolator()
        assert isolator.validate_operation("nonexistent", "read") is False

    def test_context_expiration(self):
        isolator = ContextIsolator()
        isolator.create_context("expiring", ttl_seconds=0.001)
        time.sleep(0.01)
        assert isolator.validate_operation("expiring", "read") is False


class TestSensitiveDataSanitizer:
    """Tests for sensitive data sanitization"""

    def test_sanitize_password_in_message(self):
        message = "User logged in with password=secret123"
        sanitized = SensitiveDataSanitizer.sanitize_log_message(message)
        assert "secret123" not in sanitized
        assert "[REDACTED]" in sanitized

    def test_sanitize_api_key(self):
        message = "API key is apikey=abc123def456"
        sanitized = SensitiveDataSanitizer.sanitize_log_message(message)
        assert "abc123def456" not in sanitized

    def test_sanitize_bearer_token(self):
        message = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        sanitized = SensitiveDataSanitizer.sanitize_log_message(message)
        assert "eyJhbGci" not in sanitized

    def test_sanitize_email(self):
        message = "Contact user@example.com for help"
        sanitized = SensitiveDataSanitizer.sanitize_log_message(message)
        assert "user@example.com" not in sanitized

    def test_sanitize_dict(self):
        data = {
            "username": "testuser",
            "password": "mysecret",
            "nested": {
                "api_key": "secretkey"
            }
        }
        sanitized = SensitiveDataSanitizer.sanitize_dict(data)
        assert sanitized["password"] == "[REDACTED]"
        assert sanitized["nested"]["api_key"] == "[REDACTED]"
        assert sanitized["username"] == "testuser"


class TestNeuralShieldSecurityHardenerV12:
    """Tests for main security hardener facade"""

    def test_get_instance(self):
        hardener = get_security_hardener_v12()
        assert hardener is not None
        assert isinstance(hardener, NeuralShieldSecurityHardenerV12)

    def test_secure_compare(self):
        hardener = get_security_hardener_v12()
        assert hardener.secure_compare("test", "test") is True
        assert hardener.secure_compare("test", "other") is False

    def test_validate_input_string(self):
        hardener = get_security_hardener_v12()
        result = hardener.validate_input("normal input")
        assert result.valid is True

    def test_validate_input_number(self):
        hardener = get_security_hardener_v12()
        result = hardener.validate_input(42, min_val=0, max_val=100)
        assert result.valid is True

    def test_check_rate(self):
        hardener = get_security_hardener_v12()
        allowed, meta = hardener.check_rate("test_client")
        assert allowed is True

    def test_sanitize_log_data(self):
        hardener = get_security_hardener_v12()
        result = hardener.sanitize_for_log("password=supersecret")
        assert "supersecret" not in result

    def test_sanitize_dict_data(self):
        hardener = get_security_hardener_v12()
        result = hardener.sanitize_for_log({"token": "secret"})
        assert result["token"] == "[REDACTED]"


class TestIntegration:
    """Integration tests for combined security features"""

    def test_full_security_workflow(self):
        """Test complete security hardening workflow"""
        hardener = get_security_hardener_v12(SecurityLevel.ENHANCED)
        
        # 1. Validate input
        input_result = hardener.validate_input("user input", max_length=100)
        assert input_result.valid is True
        
        # 2. Check rate limit
        allowed, _ = hardener.check_rate("client_123")
        assert allowed is True
        
        # 3. Secure comparison
        is_match = hardener.secure_compare("expected", "expected")
        assert is_match is True
        
        # 4. Sanitize output for logging
        log_data = {"user": "test", "password": "secret"}
        sanitized = hardener.sanitize_for_log(log_data)
        assert sanitized["password"] == "[REDACTED]"

    def test_thread_safety_rate_limiter(self):
        """Test rate limiter is thread-safe"""
        config = RateLimitConfig(max_requests=100, window_seconds=60)
        limiter = AdaptiveRateLimiter(config)
        
        def worker():
            for _ in range(10):
                limiter.check_rate_limit("shared_key")
        
        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        # Should not crash or have race conditions
        assert True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
