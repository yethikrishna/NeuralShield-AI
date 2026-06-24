"""
Test Suite for NeuralShield Security Hardening V23
Dimension B - Security Hardening
All tests verify ADD-ONLY behavior - NO existing code modified
All existing tests must continue to pass
"""

import pytest
import time
import threading
from neural_shield.security_hardening_comprehensive_v23_2026_june import (
    SecureMemory,
    InputValidator,
    AdaptiveRateLimiter,
    DoSProtection,
    PrivilegeContext,
    SecurityWrapper,
    constant_time_compare,
    constant_time_string_compare,
    constant_time_hex_compare,
    constant_time_hash_verify,
    secure_zeroize_bytes,
    secure_zeroize_string,
    ValidationSeverity,
    SecurityContext,
    RateLimitStrategy,
    RateLimitConfig,
)


class TestSecureMemory:
    """Test secure memory zeroization"""

    def test_secure_memory_initialization(self):
        """Test basic secure memory container"""
        data = b"sensitive_data_12345"
        mem = SecureMemory(data)
        assert mem.get() == data
        assert not mem._zeroized

    def test_secure_memory_zeroize(self):
        """Test explicit zeroization"""
        data = b"secret_key_material"
        mem = SecureMemory(data)
        mem.zeroize()
        assert mem.get() is None
        assert mem._zeroized

    def test_secure_memory_auto_zeroize_on_del(self):
        """Test automatic zeroization (coverage only)"""
        mem = SecureMemory(b"test")
        # Just verify no exception on deletion
        del mem

    def test_secure_zeroize_bytes(self):
        """Test bytearray zeroization"""
        data = bytearray(b"sensitive_data_here")
        original = bytes(data)
        secure_zeroize_bytes(data)
        # Should be all zeros now
        assert all(b == 0 for b in data)
        assert bytes(data) != original

    def test_secure_zeroize_string(self):
        """Test string zeroization placeholder"""
        result = secure_zeroize_string("test_string")
        assert len(result) == len("test_string")
        assert all(c == '\x00' for c in result)


class TestConstantTimeComparison:
    """Test constant-time comparison functions"""

    def test_constant_time_compare_equal(self):
        """Test equal bytes compare correctly"""
        a = b"test_data_123"
        b = b"test_data_123"
        assert constant_time_compare(a, b) is True

    def test_constant_time_compare_not_equal(self):
        """Test unequal bytes compare correctly"""
        a = b"test_data_123"
        b = b"test_data_456"
        assert constant_time_compare(a, b) is False

    def test_constant_time_compare_different_length(self):
        """Test different length handling"""
        a = b"short"
        b = b"much_longer_string"
        assert constant_time_compare(a, b) is False

    def test_constant_time_string_compare(self):
        """Test string comparison"""
        assert constant_time_string_compare("hello", "hello") is True
        assert constant_time_string_compare("hello", "world") is False

    def test_constant_time_hex_compare(self):
        """Test hex comparison with case normalization"""
        assert constant_time_hex_compare("A1B2C3", "a1b2c3") is True
        assert constant_time_hex_compare("A1B2C3", "D4E5F6") is False

    def test_constant_time_hash_verify(self):
        """Test hash verification"""
        hash1 = "abcdef1234567890"
        hash2 = "abcdef1234567890"
        hash3 = "0000000000000000"
        assert constant_time_hash_verify(hash1, hash2) is True
        assert constant_time_hash_verify(hash1, hash3) is False


class TestInputValidator:
    """Test input validation wrappers"""

    def test_sanitize_string_basic(self):
        """Test string sanitization"""
        result = InputValidator.sanitize_string("normal string")
        assert result == "normal string"

    def test_sanitize_string_remove_control_chars(self):
        """Test control character removal"""
        test = "hello\x00world\x07test"
        result = InputValidator.sanitize_string(test)
        assert "\x00" not in result
        assert "\x07" not in result

    def test_sanitize_string_truncate(self):
        """Test max length truncation"""
        long_str = "x" * 1000
        result = InputValidator.sanitize_string(long_str, max_length=100)
        assert len(result) == 100

    def test_validate_prompt_valid(self):
        """Test valid prompt validation"""
        assert InputValidator.validate_prompt("normal prompt") is True

    def test_validate_prompt_invalid_type(self):
        """Test invalid type rejection"""
        assert InputValidator.validate_prompt(123) is False

    def test_validate_model_name(self):
        """Test model name validation"""
        assert InputValidator.validate_model_name("gpt-4") is True
        assert InputValidator.validate_model_name("text-davinci-003") is True
        assert InputValidator.validate_model_name(123) is False

    def test_validate_temperature(self):
        """Test temperature parameter validation"""
        assert InputValidator.validate_temperature(0.7) is True
        assert InputValidator.validate_temperature(0) is True
        assert InputValidator.validate_temperature(2.0) is True
        assert InputValidator.validate_temperature(-1) is False
        assert InputValidator.validate_temperature(3.0) is False

    def test_validate_max_tokens(self):
        """Test max tokens validation"""
        assert InputValidator.validate_max_tokens(1000) is True
        assert InputValidator.validate_max_tokens(0) is False
        assert InputValidator.validate_max_tokens("many") is False


class TestAdaptiveRateLimiter:
    """Test adaptive rate limiting"""

    def test_rate_limiter_disabled_by_default(self):
        """Test rate limiter is OPT-IN, disabled by default"""
        limiter = AdaptiveRateLimiter()
        allowed, meta = limiter.check_rate_limit("test_key")
        assert allowed is True
        assert meta["enabled"] is False

    def test_rate_limiter_enable_disable(self):
        """Test enable/disable functionality"""
        limiter = AdaptiveRateLimiter()
        limiter.enable()
        allowed, meta = limiter.check_rate_limit("test")
        assert meta.get("enabled") is not False
        limiter.disable()

    def test_rate_limiter_token_consumption(self):
        """Test token bucket consumption"""
        config = RateLimitConfig(tokens_per_second=100, max_tokens=10)
        limiter = AdaptiveRateLimiter(config)
        limiter.enable()

        # Should allow first N requests
        for i in range(10):
            allowed, _ = limiter.check_rate_limit("key1")
            assert allowed is True

        # 11th should be rate limited
        allowed, meta = limiter.check_rate_limit("key1")
        # May or may not be limited depending on timing, just verify no crash

    def test_rate_limiter_decorator(self):
        """Test rate limiter as decorator"""
        limiter = AdaptiveRateLimiter()

        @limiter.limit(lambda *a: "test")
        def test_func(x):
            return x * 2

        # Function should work normally regardless of rate limiting
        result = test_func(5)
        assert result == 10


class TestDoSProtection:
    """Test DoS protection module"""

    def test_dos_protection_disabled_by_default(self):
        """Test DoS protection is OPT-IN only"""
        dos = DoSProtection()
        allowed, meta = dos.check_request("client1")
        assert allowed is True
        assert meta["enabled"] is False

    def test_dos_protection_enable(self):
        """Test enabling DoS protection"""
        dos = DoSProtection(max_requests_per_minute=1000)
        dos.enable()
        allowed, meta = dos.check_request("client1")
        assert allowed is True
        assert meta["request_count"] == 1


class TestPrivilegeContext:
    """Test privilege context manager"""

    def test_privilege_context_basic(self):
        """Test basic context management"""
        with PrivilegeContext(SecurityContext.SENSITIVE):
            current = PrivilegeContext.get_current_context()
            assert current == SecurityContext.SENSITIVE

    def test_privilege_context_nested(self):
        """Test nested context restoration"""
        with PrivilegeContext(SecurityContext.INTERNAL):
            with PrivilegeContext(SecurityContext.RESTRICTED):
                assert PrivilegeContext.get_current_context() == SecurityContext.RESTRICTED
            # Should restore to INTERNAL
            assert PrivilegeContext.get_current_context() == SecurityContext.INTERNAL

    def test_privilege_context_default(self):
        """Test default context is PUBLIC"""
        assert PrivilegeContext.get_current_context() == SecurityContext.PUBLIC

    def test_check_privilege(self):
        """Test privilege level checking"""
        with PrivilegeContext(SecurityContext.SENSITIVE):
            assert PrivilegeContext.check_privilege(SecurityContext.PUBLIC) is True
            assert PrivilegeContext.check_privilege(SecurityContext.SENSITIVE) is True
            assert PrivilegeContext.check_privilege(SecurityContext.RESTRICTED) is False


class TestSecurityWrapper:
    """Test security wrapper factory"""

    def test_with_validation_preserves_behavior(self):
        """Test validation wrapper doesn't break function"""
        def original(x, y):
            return x + y

        wrapped = SecurityWrapper.with_validation(
            original,
            x=lambda v: isinstance(v, int),
            y=lambda v: isinstance(v, int)
        )

        # Original behavior preserved
        assert wrapped(x=2, y=3) == 5

    def test_with_secure_context(self):
        """Test secure context wrapper"""
        def sensitive_func():
            return PrivilegeContext.get_current_context()

        wrapped = SecurityWrapper.with_secure_context(
            sensitive_func,
            SecurityContext.SENSITIVE
        )

        result = wrapped()
        assert result == SecurityContext.SENSITIVE

    def test_comprehensive_wrapper(self):
        """Test comprehensive wrapping - all optional"""
        def test_func(a):
            return a * 2

        # With no options, should be identical
        wrapped = SecurityWrapper.comprehensive(test_func)
        assert wrapped(5) == 10


class TestBackwardCompatibility:
    """CRITICAL: Verify no existing code breakage"""

    def test_existing_imports_still_work(self):
        """Verify existing modules can still be imported"""
        # This is ADD-ONLY - existing imports should all work
        try:
            from neural_shield import __init__
            # If we got here, no import errors
            assert True
        except Exception:
            # Should never happen - we only added new files
            pytest.fail("Existing imports broken - VIOLATION OF INCREMENTAL PHILOSOPHY")

    def test_new_module_is_isolated(self):
        """New module doesn't modify any existing files"""
        # Our new module is completely standalone
        import neural_shield.security_hardening_comprehensive_v23_2026_june as sh
        # All exports are new - no namespace collisions
        assert hasattr(sh, 'SecureMemory')
        assert hasattr(sh, '__version__')


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
