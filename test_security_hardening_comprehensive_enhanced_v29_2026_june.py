"""
Test Suite for NeuralShield Security Hardening Module v29
DIMENSION B - Security Hardening
All tests verify security functionality without modifying core code.
"""

import pytest
import time
import threading
from neural_shield.security_hardening_comprehensive_enhanced_v29_2026_june import (
    SecurityLevel,
    ValidationSeverity,
    ValidationResult,
    RateLimitConfig,
    SecureMemory,
    ConstantTime,
    InputValidator,
    RateLimiter,
    SecurityHardener,
    SecurityError,
    secure_compare,
    zeroize_sensitive,
    get_security_hardener
)


class TestSecureMemory:
    """Tests for secure memory zeroization."""
    
    def test_zeroize_bytearray(self):
        """Test that bytearrays are properly zeroized."""
        sensitive = bytearray(b"secret_password_123")
        original = bytes(sensitive)
        
        SecureMemory.zeroize_bytes(sensitive)
        
        # After zeroization, should be all zeros
        assert all(b == 0 for b in sensitive)
        assert bytes(sensitive) != original
    
    def test_zeroize_empty_bytearray(self):
        """Test zeroization handles empty arrays."""
        empty = bytearray()
        SecureMemory.zeroize_bytes(empty)
        assert len(empty) == 0
    
    def test_zeroize_non_bytearray_no_error(self):
        """Test non-bytearray inputs don't cause errors."""
        SecureMemory.zeroize_bytes("not a bytearray")  # Should not raise
        SecureMemory.zeroize_bytes(None)  # Should not raise
    
    def test_secure_delete_list(self):
        """Test secure delete clears lists."""
        sensitive = ["secret1", "secret2", "secret3"]
        SecureMemory.secure_delete(sensitive)
        assert len(sensitive) == 0
    
    def test_secure_delete_dict(self):
        """Test secure delete clears dicts."""
        sensitive = {"key": "secret", "password": "12345"}
        SecureMemory.secure_delete(sensitive)
        assert len(sensitive) == 0
    
    def test_zeroize_sensitive_convenience(self):
        """Test convenience function works."""
        data = bytearray(b"test")
        zeroize_sensitive(data)
        assert all(b == 0 for b in data)


class TestConstantTime:
    """Tests for constant-time comparison utilities."""
    
    def test_compare_equal_strings(self):
        """Test equal strings compare correctly."""
        assert ConstantTime.compare_strings("hello", "hello") is True
    
    def test_compare_unequal_strings(self):
        """Test unequal strings compare correctly."""
        assert ConstantTime.compare_strings("hello", "world") is False
    
    def test_compare_strings_different_length(self):
        """Test different length strings compare correctly."""
        assert ConstantTime.compare_strings("hello", "hello world") is False
    
    def test_compare_equal_bytes(self):
        """Test equal bytes compare correctly."""
        assert ConstantTime.compare_bytes(b"test", b"test") is True
    
    def test_compare_unequal_bytes(self):
        """Test unequal bytes compare correctly."""
        assert ConstantTime.compare_bytes(b"test", b"TEST") is False
    
    def test_compare_digests(self):
        """Test digest comparison works."""
        digest1 = b"\x00" * 32
        digest2 = b"\x00" * 32
        digest3 = b"\x01" * 32
        assert ConstantTime.compare_digests(digest1, digest2) is True
        assert ConstantTime.compare_digests(digest1, digest3) is False
    
    def test_secure_equals_mixed_types(self):
        """Test type mismatch returns False."""
        assert ConstantTime.secure_equals("test", b"test") is False
    
    def test_secure_equals_strings(self):
        """Test secure_equals with strings."""
        assert ConstantTime.secure_equals("abc", "abc") is True
        assert ConstantTime.secure_equals("abc", "def") is False
    
    def test_secure_equals_bytes(self):
        """Test secure_equals with bytes."""
        assert ConstantTime.secure_equals(b"abc", b"abc") is True
        assert ConstantTime.secure_equals(b"abc", b"def") is False
    
    def test_secure_compare_convenience(self):
        """Test convenience function works."""
        assert secure_compare("test", "test") is True
        assert secure_compare("test", "wrong") is False


class TestInputValidator:
    """Tests for input validation utilities."""
    
    def test_validate_string_valid(self):
        """Test valid string passes validation."""
        validator = InputValidator()
        result = validator.validate_string("hello", min_length=1, max_length=100)
        assert result.is_valid is True
        assert len(result.violations) == 0
    
    def test_validate_string_empty_not_allowed(self):
        """Test empty string fails when not allowed."""
        validator = InputValidator()
        result = validator.validate_string("", allow_empty=False)
        assert result.is_valid is False
        assert "Empty" in result.message
    
    def test_validate_string_too_short(self):
        """Test string below minimum length fails."""
        validator = InputValidator()
        result = validator.validate_string("ab", min_length=5)
        assert result.is_valid is False
        assert any("minimum" in v.lower() for v in result.violations)
    
    def test_validate_string_too_long(self):
        """Test string exceeding maximum length fails."""
        validator = InputValidator()
        result = validator.validate_string("a" * 1000, max_length=100)
        assert result.is_valid is False
        assert any("maximum" in v.lower() for v in result.violations)
    
    def test_validate_string_pattern_alphanumeric(self):
        """Test alphanumeric pattern validation."""
        validator = InputValidator()
        result = validator.validate_string("abc123", pattern="alphanumeric")
        assert result.is_valid is True
        
        result = validator.validate_string("abc!@#", pattern="alphanumeric")
        assert result.is_valid is False
    
    def test_validate_string_pattern_hex(self):
        """Test hex pattern validation."""
        validator = InputValidator()
        result = validator.validate_string("deadBEEF1234", pattern="hex")
        assert result.is_valid is True
    
    def test_validate_string_dangerous_script(self):
        """Test dangerous script tags are detected."""
        validator = InputValidator()
        result = validator.validate_string("<script>alert('xss')</script>")
        assert result.is_valid is False
        assert result.severity == ValidationSeverity.CRITICAL
    
    def test_validate_string_path_traversal(self):
        """Test path traversal attempts are detected."""
        validator = InputValidator()
        result = validator.validate_string("../../../etc/passwd")
        assert result.is_valid is False
        assert result.severity == ValidationSeverity.CRITICAL
    
    def test_validate_string_null_byte(self):
        """Test null bytes are detected."""
        validator = InputValidator()
        result = validator.validate_string("hello\x00world")
        assert result.is_valid is False
        assert result.severity == ValidationSeverity.CRITICAL
    
    def test_validate_string_non_string(self):
        """Test non-string input fails gracefully."""
        validator = InputValidator()
        result = validator.validate_string(12345)  # type: ignore
        assert result.is_valid is False
    
    def test_validate_integer_valid(self):
        """Test valid integer passes."""
        validator = InputValidator()
        result = validator.validate_integer(42, min_val=0, max_val=100)
        assert result.is_valid is True
        assert result.sanitized_value == 42
    
    def test_validate_integer_coercion(self):
        """Test string integers are coerced."""
        validator = InputValidator()
        result = validator.validate_integer("42")
        assert result.is_valid is True
        assert result.sanitized_value == 42
    
    def test_validate_integer_invalid(self):
        """Test invalid integer fails."""
        validator = InputValidator()
        result = validator.validate_integer("not a number")
        assert result.is_valid is False
    
    def test_validate_integer_out_of_bounds(self):
        """Test out of bounds integers fail."""
        validator = InputValidator()
        result = validator.validate_integer(1000, max_val=100)
        assert result.is_valid is False
        
        result = validator.validate_integer(-5, allow_negative=False)
        assert result.is_valid is False
    
    def test_validate_integer_zero_not_allowed(self):
        """Test zero fails when not allowed."""
        validator = InputValidator()
        result = validator.validate_integer(0, allow_zero=False)
        assert result.is_valid is False
    
    def test_sanitize_string_removes_null_bytes(self):
        """Test sanitization removes null bytes."""
        validator = InputValidator()
        result = validator.validate_string("hello\x00world", allow_empty=True)
        # Note: validation fails but sanitization would remove null
        sanitized = validator._sanitize_string("hello\x00world")
        assert "\x00" not in sanitized
    
    def test_validation_result_post_init(self):
        """Test ValidationResult handles non-list violations."""
        result = ValidationResult(True, ValidationSeverity.INFO, "test")
        # This should work even if violations wasn't explicitly set
        assert isinstance(result.violations, list)


class TestRateLimiter:
    """Tests for rate limiting DoS protection."""
    
    def test_rate_limit_allows_initial_requests(self):
        """Test initial requests are allowed."""
        config = RateLimitConfig(max_requests=5, window_seconds=60)
        limiter = RateLimiter(config)
        
        for i in range(5):
            allowed, meta = limiter.is_allowed("user1")
            assert allowed is True
    
    def test_rate_limit_blocks_after_limit(self):
        """Test requests are blocked after exceeding limit."""
        config = RateLimitConfig(max_requests=3, window_seconds=60, block_duration_seconds=1)
        limiter = RateLimiter(config)
        
        # Exhaust limit
        for i in range(3):
            limiter.is_allowed("user1")
        
        # Next should be blocked
        allowed, meta = limiter.is_allowed("user1")
        assert allowed is False
        assert meta.get("blocked") is True
    
    def test_rate_limit_whitelist(self):
        """Test whitelisted identifiers bypass limits."""
        config = RateLimitConfig(
            max_requests=1,
            window_seconds=60,
            enable_whitelist=True,
            whitelisted_identifiers=["trusted_user"]
        )
        limiter = RateLimiter(config)
        
        # Whitelisted user can make unlimited requests
        for i in range(10):
            allowed, meta = limiter.is_allowed("trusted_user")
            assert allowed is True
            assert meta.get("whitelisted") is True
    
    def test_rate_limit_reset(self):
        """Test reset clears limits."""
        config = RateLimitConfig(max_requests=2, window_seconds=60)
        limiter = RateLimiter(config)
        
        limiter.is_allowed("user1")
        limiter.is_allowed("user1")
        
        limiter.reset_limits("user1")
        
        # Should be allowed again after reset
        allowed, _ = limiter.is_allowed("user1")
        assert allowed is True
    
    def test_rate_limit_reset_all(self):
        """Test reset all clears all limits."""
        config = RateLimitConfig(max_requests=1, window_seconds=60)
        limiter = RateLimiter(config)
        
        limiter.is_allowed("user1")
        limiter.is_allowed("user2")
        
        limiter.reset_limits()
        
        assert limiter.is_allowed("user1")[0] is True
        assert limiter.is_allowed("user2")[0] is True
    
    def test_rate_limit_thread_safety(self):
        """Test rate limiter works under concurrent access."""
        config = RateLimitConfig(max_requests=100, window_seconds=60)
        limiter = RateLimiter(config)
        
        def worker():
            for i in range(10):
                limiter.is_allowed(f"thread_{threading.get_ident()}")
        
        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        # No exceptions = success


class TestSecurityHardener:
    """Tests for main security hardener facade."""
    
    def test_get_security_hardener(self):
        """Test singleton getter works."""
        hardener = get_security_hardener()
        assert isinstance(hardener, SecurityHardener)
    
    def test_security_hardener_enable_disable(self):
        """Test enable/disable functionality."""
        hardener = SecurityHardener()
        assert hardener._enabled is True
        
        hardener.disable()
        assert hardener._enabled is False
        
        hardener.enable()
        assert hardener._enabled is True
    
    def test_secure_wrapper_basic(self):
        """Test function wrapping works."""
        hardener = SecurityHardener()
        
        def test_func(x, y):
            return x + y
        
        wrapped = hardener.secure_wrapper(test_func)
        assert wrapped(2, 3) == 5
    
    def test_secure_wrapper_disabled(self):
        """Test wrapper bypasses security when disabled."""
        hardener = SecurityHardener()
        hardener.disable()
        
        def test_func(x):
            return x * 2
        
        wrapped = hardener.secure_wrapper(test_func, rate_limit=True, rate_limit_identifier="test")
        assert wrapped(5) == 10  # Should work even without rate limit setup
    
    def test_validate_and_execute_success(self):
        """Test validate and execute with valid inputs."""
        hardener = SecurityHardener()
        
        def process(text):
            return text.upper()
        
        success, result, violations = hardener.validate_and_execute(
            process,
            {"text": {"min_length": 1, "max_length": 100}},
            text="hello"
        )
        
        assert success is True
        assert result == "HELLO"
        assert len(violations) == 0
    
    def test_validate_and_execute_failure(self):
        """Test validate and execute with invalid inputs."""
        hardener = SecurityHardener()
        
        def process(text):
            return text.upper()
        
        success, result, violations = hardener.validate_and_execute(
            process,
            {"text": {"max_length": 5}},
            text="way_too_long_string_here"
        )
        
        assert success is False
        assert result is None
        assert len(violations) > 0
    
    def test_validate_and_execute_disabled(self):
        """Test validate and execute bypasses validation when disabled."""
        hardener = SecurityHardener()
        hardener.disable()
        
        def process(text):
            return text
        
        success, result, violations = hardener.validate_and_execute(
            process,
            {"text": {"max_length": 1}},
            text="long_string"
        )
        
        assert success is True
        assert result == "long_string"


class TestSecurityError:
    """Tests for custom security exception."""
    
    def test_security_error_basic(self):
        """Test basic exception creation."""
        error = SecurityError("Test error")
        assert str(error) == "Test error"
        assert error.metadata == {}
    
    def test_security_error_with_metadata(self):
        """Test exception with metadata."""
        meta = {"code": 403, "reason": "unauthorized"}
        error = SecurityError("Access denied", metadata=meta)
        assert str(error) == "Access denied"
        assert error.metadata == meta


class TestSecurityLevel:
    """Tests for security level enumeration."""
    
    def test_security_level_values(self):
        """Test all security levels exist."""
        assert SecurityLevel.MINIMAL.value == "minimal"
        assert SecurityLevel.STANDARD.value == "standard"
        assert SecurityLevel.STRICT.value == "strict"
        assert SecurityLevel.PARANOID.value == "paranoid"


class TestValidationSeverity:
    """Tests for validation severity."""
    
    def test_validation_severity_values(self):
        """Test all severity levels exist with proper ordering."""
        assert ValidationSeverity.INFO.value == 0
        assert ValidationSeverity.WARNING.value == 1
        assert ValidationSeverity.ERROR.value == 2
        assert ValidationSeverity.CRITICAL.value == 3
        # Verify ordering works
        assert ValidationSeverity.INFO < ValidationSeverity.WARNING
        assert ValidationSeverity.WARNING < ValidationSeverity.ERROR
        assert ValidationSeverity.ERROR < ValidationSeverity.CRITICAL


class TestRateLimitConfig:
    """Tests for rate limit configuration."""
    
    def test_default_config(self):
        """Test default configuration values."""
        config = RateLimitConfig()
        assert config.max_requests == 100
        assert config.window_seconds == 60
        assert config.block_duration_seconds == 300
        assert config.enable_whitelist is False
        assert config.whitelisted_identifiers == []
    
    def test_custom_config(self):
        """Test custom configuration."""
        config = RateLimitConfig(
            max_requests=10,
            window_seconds=30,
            block_duration_seconds=60
        )
        assert config.max_requests == 10
        assert config.window_seconds == 30
        assert config.block_duration_seconds == 60


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
