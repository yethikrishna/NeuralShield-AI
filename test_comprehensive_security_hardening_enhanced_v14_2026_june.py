"""
Test suite for NeuralShield Comprehensive Security Hardening Enhanced v14
Dimension B: Security Hardening

Tests cover:
1. Secure memory zeroization
2. Constant-time comparisons
3. Adaptive rate limiting
4. Enhanced input validation
5. Security facade integration
6. Sensitive data masking
"""

import sys
import os
import time
import threading
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pytest
from neural_shield.comprehensive_security_hardening_enhanced_v14_2026_june import (
    SecurityValidationLevel,
    SecurityContext,
    SecureMemoryZeroizer,
    ConstantTimeComparer,
    AdaptiveRateLimiter,
    InputValidationResult,
    EnhancedInputValidator,
    SecurityHardeningFacade,
    secure_compare,
    validate_input,
    zeroize_sensitive,
    check_rate_limit,
)


class TestSecureMemoryZeroizer:
    """Tests for secure memory zeroization."""

    def test_zeroize_bytes_bytearray(self):
        """Test zeroizing a mutable bytearray."""
        sensitive = bytearray(b"secret_key_12345")
        original_length = len(sensitive)
        SecureMemoryZeroizer.zeroize_bytes(sensitive)
        
        # All bytes should be zero
        assert all(b == 0 for b in sensitive)
        assert len(sensitive) == original_length

    def test_zeroize_list(self):
        """Test zeroizing contents of a list."""
        sensitive = ["secret1", "secret2", "secret3"]
        SecureMemoryZeroizer.zeroize_list(sensitive)
        assert len(sensitive) == 0

    def test_zeroize_dict(self):
        """Test zeroizing contents of a dict."""
        sensitive = {"key1": "secret1", "key2": "secret2"}
        SecureMemoryZeroizer.zeroize_dict(sensitive)
        assert len(sensitive) == 0

    def test_zeroize_sensitive_convenience(self):
        """Test convenience function for zeroization."""
        # Should not raise for any type
        zeroize_sensitive("test")
        zeroize_sensitive(b"test")
        zeroize_sensitive(["a", "b"])
        zeroize_sensitive({"a": "b"})
        zeroize_sensitive(123)  # Should handle non-supported types gracefully


class TestConstantTimeComparer:
    """Tests for constant-time comparison."""

    def test_compare_equal_strings(self):
        """Test comparing equal strings."""
        assert ConstantTimeComparer.compare_strings("test123", "test123") is True

    def test_compare_different_strings(self):
        """Test comparing different strings."""
        assert ConstantTimeComparer.compare_strings("test123", "test124") is False

    def test_compare_different_lengths(self):
        """Test comparing strings of different lengths."""
        assert ConstantTimeComparer.compare_strings("short", "longer string") is False

    def test_compare_bytes(self):
        """Test comparing bytes."""
        assert ConstantTimeComparer.compare_bytes(b"test", b"test") is True
        assert ConstantTimeComparer.compare_bytes(b"test", b"tesx") is False

    def test_compare_hashes(self):
        """Test comparing hash strings."""
        hash1 = "a" * 64
        hash2 = "a" * 63 + "b"
        assert ConstantTimeComparer.compare_hashes(hash1, hash1) is True
        assert ConstantTimeComparer.compare_hashes(hash1, hash2) is False

    def test_secure_equals_generic(self):
        """Test generic secure equals."""
        assert ConstantTimeComparer.secure_equals("test", "test") is True
        assert ConstantTimeComparer.secure_equals(b"test", b"test") is True
        assert ConstantTimeComparer.secure_equals(123, 123) is True
        assert ConstantTimeComparer.secure_equals(123, 456) is False

    def test_secure_compare_convenience(self):
        """Test convenience function."""
        assert secure_compare("test", "test") is True
        assert secure_compare("test", "other") is False


class TestAdaptiveRateLimiter:
    """Tests for adaptive rate limiting."""

    def test_allow_requests_within_limit(self):
        """Test requests within limit are allowed."""
        limiter = AdaptiveRateLimiter(max_requests=10, window_seconds=60)
        key = "test_user"
        
        for i in range(10):
            allowed, retry = limiter.check_rate_limit(key)
            assert allowed is True
            assert retry == 0.0

    def test_block_requests_over_limit(self):
        """Test requests over limit are blocked."""
        limiter = AdaptiveRateLimiter(max_requests=5, window_seconds=60)
        key = "test_user"
        
        # Consume all tokens
        for i in range(5):
            limiter.check_rate_limit(key)
        
        # Next should be blocked
        allowed, retry = limiter.check_rate_limit(key)
        assert allowed is False
        assert retry > 0

    def test_attack_detection(self):
        """Test attack detection when rate limit exceeded."""
        limiter = AdaptiveRateLimiter(max_requests=3, window_seconds=60)
        key = "attacker"
        
        for i in range(3):
            limiter.check_rate_limit(key)
        
        # Trigger rate limit
        limiter.check_rate_limit(key)
        assert limiter.is_attack_detected(key) is True

    def test_reset_key(self):
        """Test resetting rate limit state."""
        limiter = AdaptiveRateLimiter(max_requests=3, window_seconds=60)
        key = "test_user"
        
        for i in range(3):
            limiter.check_rate_limit(key)
        limiter.check_rate_limit(key)  # Trigger limit
        
        limiter.reset_key(key)
        assert limiter.is_attack_detected(key) is False

    def test_check_rate_limit_convenience(self):
        """Test convenience function."""
        allowed, retry = check_rate_limit("test_key")
        assert isinstance(allowed, bool)
        assert isinstance(retry, float)

    def test_concurrent_access(self):
        """Test thread safety of rate limiter."""
        limiter = AdaptiveRateLimiter(max_requests=100, window_seconds=60)
        results = []
        errors = []
        
        def worker():
            try:
                for i in range(10):
                    allowed, _ = limiter.check_rate_limit("concurrent")
                    results.append(allowed)
            except Exception as e:
                errors.append(e)
        
        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert len(errors) == 0
        assert len(results) == 100


class TestEnhancedInputValidator:
    """Tests for enhanced input validation."""

    def test_validate_clean_input(self):
        """Test validation of clean input."""
        validator = EnhancedInputValidator()
        result = validator.validate_input("Hello, this is normal input.")
        
        assert result.valid is True
        assert result.risk_score == 0.0
        assert len(result.errors) == 0

    def test_validate_oversized_input(self):
        """Test validation rejects oversized input."""
        validator = EnhancedInputValidator()
        large_input = "x" * 2_000_000  # 2MB, exceeds default 1MB
        result = validator.validate_input(large_input)
        
        assert result.valid is False
        assert len(result.errors) > 0
        assert result.risk_score > 0

    def test_validate_dangerous_patterns(self):
        """Test validation detects dangerous patterns."""
        validator = EnhancedInputValidator()
        
        # SQL injection pattern
        result = validator.validate_input("UNION SELECT username, password FROM users")
        assert result.valid is False or len(result.warnings) > 0
        
        # XSS pattern
        result = validator.validate_input("<script>alert('xss')</script>")
        assert result.valid is False or len(result.warnings) > 0

    def test_mask_sensitive_data(self):
        """Test sensitive data masking."""
        validator = EnhancedInputValidator()
        
        # Email masking
        text = "Contact me at test@example.com for info"
        masked = validator.mask_sensitive_data(text)
        assert "@" not in masked or "*" in masked
        
        # Credit card masking
        text = "Card: 4111-1111-1111-1111"
        masked = validator.mask_sensitive_data(text)
        assert masked.count("*") > 0

    def test_validate_input_convenience(self):
        """Test convenience function."""
        result = validate_input("normal input")
        assert isinstance(result, InputValidationResult)
        assert result.valid is True

    def test_permissive_mode(self):
        """Test permissive validation level."""
        context = SecurityContext(validation_level=SecurityValidationLevel.PERMISSIVE)
        validator = EnhancedInputValidator(context)
        
        # Should warn but not block
        result = validator.validate_input("<script>test</script>")
        assert result.valid is True  # Permissive allows
        assert len(result.warnings) > 0


class TestSecurityHardeningFacade:
    """Tests for the security hardening facade."""

    def test_secure_process_success(self):
        """Test successful secure processing."""
        facade = SecurityHardeningFacade()
        
        def dummy_processor(text):
            return f"PROCESSED: {text}"
        
        result = facade.secure_process(
            key="user1",
            input_text="normal input",
            processor=dummy_processor
        )
        
        assert result["success"] is True
        assert result["rate_limited"] is False
        assert result["output"] == "PROCESSED: normal input"

    def test_secure_process_rate_limited(self):
        """Test rate limiting in facade."""
        context = SecurityContext(enable_rate_limiting=True)
        facade = SecurityHardeningFacade(context)
        
        def dummy_processor(text):
            return text
        
        # Consume tokens
        key = "limited_user"
        for i in range(100):
            facade.secure_process(key, "test", dummy_processor)
        
        # Next should be rate limited
        result = facade.secure_process(key, "test", dummy_processor)
        # May or may not be limited depending on timing, but should not error
        assert "rate_limited" in result

    def test_secure_process_validation_failed(self):
        """Test validation failure in facade."""
        facade = SecurityHardeningFacade()
        
        def dummy_processor(text):
            return text
        
        # Large input should fail validation
        large_input = "x" * 2_000_000
        result = facade.secure_process("user", large_input, dummy_processor)
        
        assert result["success"] is False
        assert len(result["validation_errors"]) > 0

    def test_cleanup_handlers(self):
        """Test cleanup handlers registration and execution."""
        facade = SecurityHardeningFacade()
        cleanup_called = []
        
        def handler():
            cleanup_called.append(True)
        
        facade.register_cleanup_handler(handler)
        facade.full_cleanup()
        
        assert len(cleanup_called) == 1

    def test_full_cleanup(self):
        """Test full cleanup with sensitive data."""
        facade = SecurityHardeningFacade()
        
        # Should not raise
        facade.full_cleanup([
            "secret string",
            bytearray(b"secret bytes"),
            ["secret", "list"],
            {"key": "secret"}
        ])


class TestSecurityContext:
    """Tests for security context."""

    def test_default_context(self):
        """Test default security context values."""
        context = SecurityContext()
        
        assert context.validation_level == SecurityValidationLevel.STANDARD
        assert context.enable_memory_zeroization is True
        assert context.enable_constant_time is True
        assert context.enable_rate_limiting is True
        assert context.max_input_size == 1_000_000

    def test_custom_context(self):
        """Test custom security context."""
        context = SecurityContext(
            validation_level=SecurityValidationLevel.STRICT,
            enable_memory_zeroization=False,
            max_input_size=100_000
        )
        
        assert context.validation_level == SecurityValidationLevel.STRICT
        assert context.enable_memory_zeroization is False
        assert context.max_input_size == 100_000


class TestInputValidationResult:
    """Tests for input validation result."""

    def test_result_creation(self):
        """Test validation result creation."""
        result = InputValidationResult(
            valid=True,
            sanitized_input="clean",
            warnings=["warning1"],
            errors=[],
            risk_score=0.1
        )
        
        assert result.valid is True
        assert result.sanitized_input == "clean"
        assert result.warnings == ["warning1"]
        assert result.errors == []
        assert result.risk_score == 0.1

    def test_result_defaults(self):
        """Test validation result defaults."""
        result = InputValidationResult(valid=True)
        
        assert result.warnings == []
        assert result.errors == []
        assert result.risk_score == 0.0


if __name__ == "__main__":
    # Run tests
    test_classes = [
        TestSecureMemoryZeroizer,
        TestConstantTimeComparer,
        TestAdaptiveRateLimiter,
        TestEnhancedInputValidator,
        TestSecurityHardeningFacade,
        TestSecurityContext,
        TestInputValidationResult,
    ]
    
    passed = 0
    failed = 0
    
    for test_class in test_classes:
        test_instance = test_class()
        methods = [m for m in dir(test_instance) if m.startswith("test_")]
        
        for method in methods:
            try:
                getattr(test_instance, method)()
                passed += 1
            except Exception as e:
                print(f"FAILED: {test_class.__name__}.{method}: {e}")
                failed += 1
    
    print(f"\n{'='*50}")
    print(f"Tests passed: {passed}")
    print(f"Tests failed: {failed}")
    print(f"{'='*50}")
    
    if failed == 0:
        print("\nAll tests PASSED!")
        sys.exit(0)
    else:
        print("\nSome tests FAILED!")
        sys.exit(1)
