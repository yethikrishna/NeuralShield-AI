"""
Test Suite for Security Hardening Comprehensive Protection V24
DIMENSION B: Security Hardening

Tests cover:
- Constant-time comparison utilities
- Secure memory zeroization
- Input validation wrappers
- Adaptive rate limiting
- Side-channel resistance
- Security facade integration

All tests are ADD-ONLY - no existing tests modified.
"""

import pytest
import time
import threading
import hmac
from typing import Dict, Any

from neural_shield.security_hardening_comprehensive_protection_v24_2026_june import (
    ConstantTimeComparer,
    SecureMemoryZeroizer,
    InputValidationWrapper,
    AdaptiveRateLimiter,
    SideChannelResistance,
    SecurityHardeningFacade,
    SecurityLevel,
    OverwritePattern,
    RateLimitConfig,
    ValidationConfig,
    MemorySecurityConfig,
    default_comparer,
    default_zeroizer,
    default_validator,
    default_rate_limiter,
    default_side_channel,
)


class TestConstantTimeComparer:
    """Tests for constant-time comparison utilities."""

    def test_compare_bytes_equal(self):
        """Test byte comparison with equal values."""
        a = b"secret_data_123"
        b = b"secret_data_123"
        assert ConstantTimeComparer.compare_bytes(a, b) is True

    def test_compare_bytes_not_equal(self):
        """Test byte comparison with different values."""
        a = b"secret_data_123"
        b = b"secret_data_456"
        assert ConstantTimeComparer.compare_bytes(a, b) is False

    def test_compare_strings_equal(self):
        """Test string comparison with equal values."""
        assert ConstantTimeComparer.compare_strings("password123", "password123") is True

    def test_compare_strings_not_equal(self):
        """Test string comparison with different values."""
        assert ConstantTimeComparer.compare_strings("password123", "password456") is False

    def test_compare_strings_different_length(self):
        """Test string comparison with different lengths."""
        assert ConstantTimeComparer.compare_strings("short", "longer_string") is False

    def test_secure_hash_compare(self):
        """Test hash comparison."""
        hash1 = hmac.new(b"key", b"msg", "sha256").hexdigest()
        hash2 = hmac.new(b"key", b"msg", "sha256").hexdigest()
        hash3 = hmac.new(b"key", b"different", "sha256").hexdigest()
        
        assert ConstantTimeComparer.secure_hash_compare(hash1, hash2) is True
        assert ConstantTimeComparer.secure_hash_compare(hash1, hash3) is False

    def test_arrays_equal_constant_time(self):
        """Test array comparison."""
        assert ConstantTimeComparer.arrays_equal_constant_time([1, 2, 3], [1, 2, 3]) is True
        assert ConstantTimeComparer.arrays_equal_constant_time([1, 2, 3], [1, 2, 4]) is False
        assert ConstantTimeComparer.arrays_equal_constant_time([1, 2], [1, 2, 3]) is False

    def test_default_comparer_instance(self):
        """Test default comparer instance works."""
        assert default_comparer.compare_bytes(b"test", b"test") is True


class TestSecureMemoryZeroizer:
    """Tests for secure memory zeroization."""

    def test_zeroize_bytearray(self):
        """Test bytearray zeroization."""
        data = bytearray(b"sensitive_password_12345")
        original = bytes(data)
        
        zeroizer = SecureMemoryZeroizer()
        zeroizer.zeroize_bytearray(data)
        
        assert all(b == 0 for b in data)
        assert bytes(data) != original

    def test_zeroize_bytearray_disabled(self):
        """Test zeroization can be disabled."""
        data = bytearray(b"test")
        original = bytes(data)
        
        config = MemorySecurityConfig(enabled=False)
        zeroizer = SecureMemoryZeroizer(config)
        zeroizer.zeroize_bytearray(data)
        
        assert bytes(data) == original

    def test_zeroize_bytes(self):
        """Test bytes zeroization (returns zeros)."""
        zeroizer = SecureMemoryZeroizer()
        result = zeroizer.zeroize_bytes(b"sensitive")
        assert result == b"\x00" * 9

    def test_zeroize_list(self):
        """Test list clearing."""
        data = ["secret1", "secret2", "secret3"]
        zeroizer = SecureMemoryZeroizer()
        zeroizer.zeroize_list(data)
        assert len(data) == 0

    def test_secure_delete_string(self):
        """Test string zeroization (best-effort)."""
        zeroizer = SecureMemoryZeroizer()
        result = zeroizer.secure_delete_string("password")
        assert len(result) == 8
        assert all(c == "\x00" for c in result)

    def test_multiple_overwrite_patterns(self):
        """Test multiple overwrite patterns."""
        data = bytearray(b"test")
        config = MemorySecurityConfig(
            overwrite_passes=2,
            overwrite_patterns=[
                OverwritePattern.ZEROS,
                OverwritePattern.ONES,
                OverwritePattern.RANDOM
            ]
        )
        zeroizer = SecureMemoryZeroizer(config)
        zeroizer.zeroize_bytearray(data)
        assert all(b == 0 for b in data)

    def test_default_zeroizer_instance(self):
        """Test default zeroizer instance works."""
        data = bytearray(b"test")
        default_zeroizer.zeroize_bytearray(data)
        assert all(b == 0 for b in data)


class TestInputValidationWrapper:
    """Tests for input validation wrappers."""

    def test_validate_string_normal(self):
        """Test normal string validation passes."""
        validator = InputValidationWrapper()
        result = validator.validate_string("Hello World")
        assert result == "Hello World"

    def test_validate_string_too_long(self):
        """Test string exceeding max length is rejected."""
        config = ValidationConfig(max_length=10)
        validator = InputValidationWrapper(config)
        
        with pytest.raises(ValueError, match="exceeds maximum length"):
            validator.validate_string("This string is way too long")

    def test_validate_string_dangerous_pattern(self):
        """Test dangerous patterns are rejected."""
        validator = InputValidationWrapper()
        
        with pytest.raises(ValueError):
            validator.validate_string("<script>alert('xss')</script>")
        
        with pytest.raises(ValueError):
            validator.validate_string("javascript:alert(1)")

    def test_validate_string_disabled(self):
        """Test validation can be disabled."""
        config = ValidationConfig(enabled=False)
        validator = InputValidationWrapper(config)
        result = validator.validate_string("<script>")
        assert result == "<script>"

    def test_validate_integer_normal(self):
        """Test normal integer validation."""
        validator = InputValidationWrapper()
        assert validator.validate_integer(5, 0, 10) == 5

    def test_validate_integer_out_of_bounds(self):
        """Test out of bounds integers are rejected."""
        validator = InputValidationWrapper()
        
        with pytest.raises(ValueError):
            validator.validate_integer(-1, 0, 10)
        
        with pytest.raises(ValueError):
            validator.validate_integer(11, 0, 10)

    def test_wrap_function_decorator(self):
        """Test function wrapping with validation."""
        validator = InputValidationWrapper()
        
        @validator.wrap_function
        def process_input(text: str) -> str:
            return f"Processed: {text}"
        
        # Normal input works
        assert process_input("hello") == "Processed: hello"
        
        # Dangerous input raises
        with pytest.raises(ValueError):
            process_input("<script>")

    def test_sanitize_html(self):
        """Test HTML sanitization."""
        validator = InputValidationWrapper()
        dirty = '<div onclick="alert(1)">Hello</div><script>bad</script>'
        clean = validator.sanitize_html(dirty)
        assert "<script>" not in clean
        assert "onclick" not in clean.lower() or "data-removed" in clean.lower()

    def test_strict_mode_validation(self):
        """Test strict security level."""
        config = ValidationConfig(
            security_level=SecurityLevel.STRICT,
            allow_special_chars=False
        )
        validator = InputValidationWrapper(config)
        
        with pytest.raises(ValueError):
            validator.validate_string('test<script>')

    def test_default_validator_instance(self):
        """Test default validator instance works."""
        assert default_validator.validate_string("test") == "test"


class TestAdaptiveRateLimiter:
    """Tests for adaptive rate limiting."""

    def test_rate_limit_allows_initial_requests(self):
        """Test initial requests are allowed."""
        config = RateLimitConfig(max_requests=5, window_seconds=60)
        limiter = AdaptiveRateLimiter(config)
        
        for _ in range(5):
            assert limiter.check_rate_limit("test") is True

    def test_rate_limit_blocks_over_limit(self):
        """Test requests over limit are blocked."""
        config = RateLimitConfig(max_requests=2, window_seconds=60, burst_allowance=0)
        limiter = AdaptiveRateLimiter(config)
        
        assert limiter.check_rate_limit("test") is True
        assert limiter.check_rate_limit("test") is True
        assert limiter.check_rate_limit("test") is False

    def test_burst_allowance(self):
        """Test burst allowance works."""
        config = RateLimitConfig(max_requests=2, window_seconds=60, burst_allowance=3)
        limiter = AdaptiveRateLimiter(config)
        
        # Burst + regular
        for _ in range(5):
            assert limiter.check_rate_limit("test") is True
        # Then blocked
        assert limiter.check_rate_limit("test") is False

    def test_rate_limit_disabled(self):
        """Test rate limiting can be disabled."""
        config = RateLimitConfig(enabled=False)
        limiter = AdaptiveRateLimiter(config)
        
        for _ in range(100):
            assert limiter.check_rate_limit() is True

    def test_get_remaining(self):
        """Test remaining tokens query."""
        config = RateLimitConfig(max_requests=10, window_seconds=60)
        limiter = AdaptiveRateLimiter(config)
        
        limiter.check_rate_limit("key")
        status = limiter.get_remaining("key")
        
        assert "remaining" in status
        assert "limit" in status
        assert "window" in status

    def test_rate_limit_decorator(self):
        """Test rate limit decorator."""
        config = RateLimitConfig(max_requests=2, window_seconds=60, burst_allowance=0)
        limiter = AdaptiveRateLimiter(config)
        
        @limiter.rate_limit_decorator()
        def protected_func() -> str:
            return "success"
        
        assert protected_func() == "success"
        assert protected_func() == "success"
        result = protected_func()
        assert isinstance(result, dict)
        assert result.get("error") == "rate_limited"

    def test_thread_safety(self):
        """Test rate limiter is thread-safe."""
        config = RateLimitConfig(max_requests=100, window_seconds=60)
        limiter = AdaptiveRateLimiter(config)
        
        results = []
        def worker():
            for _ in range(10):
                results.append(limiter.check_rate_limit("shared"))
        
        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert all(results)

    def test_default_rate_limiter_instance(self):
        """Test default rate limiter instance works."""
        assert default_rate_limiter.check_rate_limit() is True


class TestSideChannelResistance:
    """Tests for side-channel resistance utilities."""

    def test_constant_time_lookup_valid(self):
        """Test constant time lookup with valid index."""
        table = ["a", "b", "c", "d"]
        result = SideChannelResistance.constant_time_lookup(table, 2)
        assert result == "c"

    def test_constant_time_lookup_invalid(self):
        """Test constant time lookup with invalid index."""
        table = ["a", "b", "c"]
        assert SideChannelResistance.constant_time_lookup(table, -1) is None
        assert SideChannelResistance.constant_time_lookup(table, 10) is None

    def test_add_timing_noise(self):
        """Test timing noise injection (should not crash)."""
        # Should complete without error
        SideChannelResistance.add_timing_noise(base_delay_ms=0.1, jitter_ms=0.05)

    def test_blind_arithmetic_add(self):
        """Test blinded addition."""
        result = SideChannelResistance.blind_arithmetic(5, 3, "add")
        assert result == 8

    def test_blind_arithmetic_multiply(self):
        """Test blinded multiplication."""
        result = SideChannelResistance.blind_arithmetic(4, 5, "multiply")
        assert result == 20

    def test_default_side_channel_instance(self):
        """Test default side channel instance works."""
        assert default_side_channel.constant_time_lookup([1, 2], 0) == 1


class TestSecurityHardeningFacade:
    """Tests for unified security facade."""

    def test_facade_initialization(self):
        """Test facade initializes correctly."""
        facade = SecurityHardeningFacade()
        assert facade.validator is not None
        assert facade.memory_zeroizer is not None
        assert facade.rate_limiter is not None
        assert facade.constant_time is not None
        assert facade.side_channel is not None

    def test_facade_with_custom_configs(self):
        """Test facade with custom configurations."""
        val_config = ValidationConfig(max_length=100)
        mem_config = MemorySecurityConfig(overwrite_passes=2)
        rate_config = RateLimitConfig(max_requests=50)
        
        facade = SecurityHardeningFacade(val_config, mem_config, rate_config)
        
        assert facade.validator.config.max_length == 100
        assert facade.memory_zeroizer.config.overwrite_passes == 2
        assert facade.rate_limiter.config.max_requests == 50

    def test_secure_operation_wrapper(self):
        """Test secure operation wrapping."""
        facade = SecurityHardeningFacade()
        
        def sensitive_operation(data: str) -> str:
            return f"Processed: {data}"
        
        wrapped = facade.secure_operation(sensitive_operation)
        
        # Normal operation works
        assert wrapped("normal input") == "Processed: normal input"
        
        # Dangerous input is caught
        with pytest.raises(ValueError):
            wrapped("<script>")


class TestIntegrationWithExistingCode:
    """Integration tests - verify security layers don't break happy paths."""

    def test_all_modules_importable(self):
        """All security modules should import without errors."""
        from neural_shield.security_hardening_comprehensive_protection_v24_2026_june import (
            ConstantTimeComparer,
            SecureMemoryZeroizer,
            InputValidationWrapper,
            AdaptiveRateLimiter,
            SideChannelResistance,
            SecurityHardeningFacade,
        )
        assert True  # If we got here, imports worked

    def test_backward_compatibility(self):
        """Existing code patterns should work with security layers."""
        # This simulates wrapping existing functions without modification
        validator = InputValidationWrapper()
        
        @validator.wrap_function
        def existing_function(text: str, value: int) -> Dict[str, Any]:
            return {"text": text, "value": value}
        
        # Original behavior preserved
        result = existing_function("hello", 42)
        assert result == {"text": "hello", "value": 42}

    def test_security_is_opt_in(self):
        """Security is optional - can be disabled entirely."""
        disabled_config = ValidationConfig(enabled=False)
        validator = InputValidationWrapper(disabled_config)
        
        # Even dangerous patterns pass when disabled
        result = validator.validate_string("<script>alert(1)</script>")
        assert "<script>" in result


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
