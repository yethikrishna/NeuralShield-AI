"""
Test Suite for NeuralShield AI Security Hardening v23
Dimension B - Security Hardening
Tests for:
- Secure Memory Zeroization
- Constant-Time Comparisons
- Input Validation Wrappers
- Rate Limiting

All tests are ADD-ONLY - no modification to existing tests.
"""

import pytest
import time
import os
import sys

# Add module path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from security_hardening_secure_memory_zeroization_v23_2026_june import (
    SecureMemoryZeroizer,
    secure_zeroize,
    SensitiveDataContext
)

from security_hardening_constant_time_comparison_v23_2026_june import (
    ConstantTimeComparator,
    constant_time_compare,
    secure_api_key_validation,
    SecureCredentialValidator
)

from security_hardening_input_validation_wrapper_v23_2026_june import (
    InputValidator,
    ValidationResult,
    RateLimiter,
    validate_input,
    secure_input
)


class TestSecureMemoryZeroization:
    """Tests for secure memory zeroization utilities."""
    
    def test_zeroizer_initialization(self):
        """Test zeroizer initializes with correct defaults."""
        zeroizer = SecureMemoryZeroizer()
        assert zeroizer.overwrite_passes == 3
        stats = zeroizer.get_zeroization_stats()
        assert stats['total_zeroized'] == 0
    
    def test_zeroize_bytearray(self):
        """Test bytearray zeroization actually zeros data."""
        zeroizer = SecureMemoryZeroizer()
        data = bytearray(b"sensitive_api_key_12345")
        original = bytes(data)
        
        zeroizer.zeroize_bytes(data)
        
        # Verify all bytes are zero
        assert all(b == 0 for b in data)
        assert bytes(data) != original
        stats = zeroizer.get_zeroization_stats()
        assert stats['total_zeroized'] == 1
    
    def test_zeroize_string(self):
        """Test string zeroization returns empty string."""
        zeroizer = SecureMemoryZeroizer()
        result = zeroizer.zeroize_string("secret_password")
        assert result == ""
    
    def test_zeroize_list(self):
        """Test list items are zeroized."""
        zeroizer = SecureMemoryZeroizer()
        sensitive_list = [bytearray(b"secret1"), bytearray(b"secret2")]
        
        zeroizer.zeroize_list(sensitive_list)
        
        assert len(sensitive_list) == 0
    
    def test_zeroize_dict(self):
        """Test dict values are zeroized."""
        zeroizer = SecureMemoryZeroizer()
        sensitive_dict = {
            'api_key': bytearray(b"key123"),
            'token': bytearray(b"token456")
        }
        
        zeroizer.zeroize_dict(sensitive_dict)
        
        assert all(b == 0 for b in sensitive_dict['api_key'])
    
    def test_secure_zeroize_convenience(self):
        """Test convenience zeroize function."""
        data = bytearray(b"test_data")
        secure_zeroize(data)
        assert all(b == 0 for b in data)
    
    def test_sensitive_context_manager(self):
        """Test context manager auto-zeroizes data."""
        tracked_data = None
        
        with SensitiveDataContext() as ctx:
            data = ctx.track(bytearray(b"temporary_secret"))
            tracked_data = data
            assert len(data) > 0
        
        # Data should be zeroized after context exit
        assert all(b == 0 for b in tracked_data)
    
    def test_custom_overwrite_passes(self):
        """Test custom number of overwrite passes."""
        zeroizer = SecureMemoryZeroizer(overwrite_passes=5)
        assert zeroizer.overwrite_passes == 5


class TestConstantTimeComparison:
    """Tests for constant-time comparison utilities."""
    
    def test_comparator_initialization(self):
        """Test comparator initializes correctly."""
        comparator = ConstantTimeComparator()
        stats = comparator.get_comparison_stats()
        assert stats['total_comparisons'] == 0
    
    def test_compare_bytes_equal(self):
        """Test equal bytes compare correctly."""
        result = ConstantTimeComparator.compare_bytes(b"test123", b"test123")
        assert result is True
    
    def test_compare_bytes_not_equal(self):
        """Test unequal bytes compare correctly."""
        result = ConstantTimeComparator.compare_bytes(b"test123", b"test456")
        assert result is False
    
    def test_compare_strings_equal(self):
        """Test equal strings compare correctly."""
        result = ConstantTimeComparator.compare_strings("hello", "hello")
        assert result is True
    
    def test_compare_strings_not_equal(self):
        """Test unequal strings compare correctly."""
        result = ConstantTimeComparator.compare_strings("hello", "world")
        assert result is False
    
    def test_secure_api_key_comparison(self):
        """Test API key comparison with length check."""
        comparator = ConstantTimeComparator()
        
        # Matching keys
        assert comparator.secure_compare_api_key("abc123xyz789", "abc123xyz789") is True
        
        # Length mismatch (fails fast)
        assert comparator.secure_compare_api_key("short", "long_key_here") is False
        
        # Same length, different content
        assert comparator.secure_compare_api_key("aaaaaaaaaaaa", "bbbbbbbbbbbb") is False
    
    def test_secure_hash_comparison(self):
        """Test hash comparison."""
        comparator = ConstantTimeComparator()
        hash1 = "a1b2c3d4e5f6"
        hash2 = "a1b2c3d4e5f6"
        hash3 = "f6e5d4c3b2a1"
        
        assert comparator.secure_compare_hash(hash1, hash2) is True
        assert comparator.secure_compare_hash(hash1, hash3) is False
    
    def test_threat_signature_comparison(self):
        """Test threat signature matching."""
        comparator = ConstantTimeComparator()
        signature = "IGNORE_PREVIOUS_INSTRUCTIONS"
        
        assert comparator.secure_compare_threat_signature(signature, signature) is True
        assert comparator.secure_compare_threat_signature("SAFE_INPUT", signature) is False
    
    def test_constant_time_compare_convenience(self):
        """Test convenience function."""
        assert constant_time_compare("test", "test") is True
        assert constant_time_compare("test", "fail") is False
    
    def test_secure_api_key_validation_list(self):
        """Test validation against key list."""
        valid_keys = ["key_abc123", "key_xyz789", "key_pqrs45"]
        assert secure_api_key_validation("key_abc123", valid_keys) is True
        assert secure_api_key_validation("invalid_key", valid_keys) is False
    
    def test_credential_validator(self):
        """Test secure credential validator."""
        validator = SecureCredentialValidator()
        
        assert validator.validate_credentials(
            "admin", "secret123", "admin", "secret123"
        ) is True
        
        assert validator.validate_credentials(
            "admin", "wrong", "admin", "secret123"
        ) is False
    
    def test_token_validation(self):
        """Test token validation."""
        validator = SecureCredentialValidator()
        assert validator.validate_token("token_12345", "token_12345") is True


class TestInputValidation:
    """Tests for input validation wrappers."""
    
    def test_validator_initialization(self):
        """Test validator initializes correctly."""
        validator = InputValidator()
        assert validator.max_length == 100000
        assert validator.min_length == 1
    
    def test_validate_length_valid(self):
        """Test valid length passes validation."""
        validator = InputValidator()
        result = validator.validate_length("normal prompt text")
        assert result.is_valid is True
    
    def test_validate_length_too_short(self):
        """Test too short input fails validation."""
        validator = InputValidator(min_length=10)
        result = validator.validate_length("short")
        assert result.is_valid is False
        assert "too short" in result.error_message.lower()
    
    def test_validate_length_too_long(self):
        """Test too long input fails validation."""
        validator = InputValidator(max_length=10)
        result = validator.validate_length("this is way too long for the limit")
        assert result.is_valid is False
        assert "too long" in result.error_message.lower()
    
    def test_validate_encoding_valid(self):
        """Test valid UTF-8 passes."""
        validator = InputValidator()
        result = validator.validate_encoding("Hello World 123!")
        assert result.is_valid is True
    
    def test_validate_null_bytes(self):
        """Test null bytes are detected."""
        validator = InputValidator()
        result = validator.validate_encoding("hello\x00world")
        assert result.is_valid is False
    
    def test_sanitize_input(self):
        """Test input sanitization removes control characters."""
        validator = InputValidator()
        dirty = "hello\x00\x01\x02world"
        clean = validator.sanitize_input(dirty)
        assert '\x00' not in clean
        assert '\x01' not in clean
    
    def test_validate_all_valid(self):
        """Test complete validation for valid input."""
        validator = InputValidator()
        result = validator.validate_all("This is a normal user prompt.")
        assert result.is_valid is True
        assert result.sanitized_input is not None
    
    def test_excessive_special_chars(self):
        """Test excessive special characters detection."""
        validator = InputValidator()
        bad_input = "!" * 100
        result = validator.validate_special_chars(bad_input)
        assert result.is_valid is False
    
    def test_validation_stats(self):
        """Test validation statistics tracking."""
        validator = InputValidator()
        validator.validate_all("test1")
        validator.validate_all("test2")
        
        stats = validator.get_validation_stats()
        assert stats['total_validations'] == 2
        assert stats['total_rejections'] == 0
    
    def test_secure_input_convenience(self):
        """Test convenience validation function."""
        result = secure_input("normal input")
        assert result == "normal input"
    
    def test_validate_input_decorator(self):
        """Test validation decorator works."""
        @validate_input()
        def test_func(prompt: str, extra: str = "default"):
            return f"processed: {prompt}"
        
        result = test_func("valid prompt")
        assert "processed" in result


class TestRateLimiter:
    """Tests for rate limiting DoS protection."""
    
    def test_limiter_initialization(self):
        """Test rate limiter initializes."""
        limiter = RateLimiter(max_requests=10, window_seconds=60)
        assert limiter.max_requests == 10
    
    def test_check_rate_limit_allowed(self):
        """Test requests under limit are allowed."""
        limiter = RateLimiter(max_requests=5)
        
        for _ in range(5):
            assert limiter.check_rate_limit("client1") is True
    
    def test_check_rate_limit_blocked(self):
        """Test requests over limit are blocked."""
        limiter = RateLimiter(max_requests=2)
        
        limiter.check_rate_limit("client2")
        limiter.check_rate_limit("client2")
        # Third request should fail
        assert limiter.check_rate_limit("client2") is False
    
    def test_remaining_quota(self):
        """Test remaining quota calculation."""
        limiter = RateLimiter(max_requests=10)
        limiter.check_rate_limit("client3")
        limiter.check_rate_limit("client3")
        
        remaining = limiter.get_remaining_quota("client3")
        assert remaining == 8
    
    def test_rate_limited_decorator(self):
        """Test rate limiting decorator."""
        from security_hardening_input_validation_wrapper_v23_2026_june import rate_limited
        
        @rate_limited()
        def protected_api(client_id: str = "test"):
            return "success"
        
        result = protected_api(client_id="test_user")
        assert result == "success"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
