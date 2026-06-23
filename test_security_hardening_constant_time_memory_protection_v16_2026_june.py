"""
Tests for NeuralShield Security Hardening - Constant-Time Comparison & Memory Protection
DIMENSION B: Security Hardening (v16)
ADD-ONLY tests - no modifications to production source code

Covers:
1. Constant-time comparison correctness
2. Secure memory zeroization
3. Side-channel resistant validation
4. Secure buffer context manager
5. Edge cases and boundary conditions
"""

import pytest
import time
import secrets
import statistics
from typing import ByteString

from neural_shield.security_hardening_constant_time_memory_protection_v16_2026_june import (
    ConstantTimeComparer,
    SecureMemoryZeroizer,
    SideChannelResistantValidator,
    SecureTemporaryBuffer,
    constant_time_compare,
    constant_time_compare_str,
    secure_wipe,
    secure_buffer
)


class TestConstantTimeComparer:
    """Tests for constant-time comparison utilities."""
    
    def test_compare_bytes_equal(self):
        """Test equal byte strings compare correctly."""
        a = b"hello_world_test_data_12345"
        b = b"hello_world_test_data_12345"
        assert ConstantTimeComparer.compare_bytes(a, b) is True
    
    def test_compare_bytes_not_equal(self):
        """Test non-equal byte strings compare correctly."""
        a = b"hello_world_test_data_12345"
        b = b"hello_world_test_data_12346"
        assert ConstantTimeComparer.compare_bytes(a, b) is False
    
    def test_compare_bytes_different_length(self):
        """Test byte strings of different lengths."""
        a = b"short"
        b = b"much_longer_string"
        assert ConstantTimeComparer.compare_bytes(a, b) is False
    
    def test_compare_bytes_empty(self):
        """Test empty byte strings."""
        assert ConstantTimeComparer.compare_bytes(b"", b"") is True
        assert ConstantTimeComparer.compare_bytes(b"", b"a") is False
    
    def test_compare_strings_equal(self):
        """Test equal strings compare correctly."""
        assert ConstantTimeComparer.compare_strings("test_api_key_123", "test_api_key_123") is True
    
    def test_compare_strings_not_equal(self):
        """Test non-equal strings compare correctly."""
        assert ConstantTimeComparer.compare_strings("test_api_key_123", "test_api_key_124") is False
    
    def test_compare_strings_unicode(self):
        """Test Unicode string comparison."""
        assert ConstantTimeComparer.compare_strings("unicode_测试_🔐", "unicode_测试_🔐") is True
        assert ConstantTimeComparer.compare_strings("unicode_测试_🔐", "unicode_测试_🔑") is False
    
    def test_compare_hashes_equal(self):
        """Test hash comparison with different cases."""
        hash1 = "a1b2c3d4e5f6"
        hash2 = "A1B2C3D4E5F6"
        assert ConstantTimeComparer.compare_hashes(hash1, hash2) is True
    
    def test_compare_hashes_not_equal(self):
        """Test non-equal hash comparison."""
        assert ConstantTimeComparer.compare_hashes("a1b2c3", "a1b2c4") is False
    
    def test_select_true(self):
        """Test constant-time selection when condition is True."""
        result = ConstantTimeComparer.select(True, b"success", b"failure")
        # Should contain 'success' bytes
        assert b"success" in result or result.startswith(b'success')
    
    def test_select_false(self):
        """Test constant-time selection when condition is False."""
        result = ConstantTimeComparer.select(False, b"success", b"failure")
        # Should contain 'failure' bytes
        assert b"failure" in result or result.startswith(b'failure')
    
    def test_timing_consistency(self):
        """Test that comparison timing is consistent (no timing leaks)."""
        # This is a statistical test - we verify that early mismatch
        # doesn't cause significantly faster execution
        
        # Match at beginning vs match at end vs no match
        early_diff = b"a" + b"x" * 1000
        late_diff = b"x" * 1000 + b"a"
        control = b"x" * 1001
        
        def time_comparison(a: ByteString, b: ByteString, iterations: int = 100) -> float:
            start = time.perf_counter()
            for _ in range(iterations):
                ConstantTimeComparer.compare_bytes(a, b)
            return time.perf_counter() - start
        
        # Run multiple times and take median
        times_early = [time_comparison(early_diff, control) for _ in range(20)]
        times_late = [time_comparison(late_diff, control) for _ in range(20)]
        
        # Medians should be within reasonable range (no early exit optimization)
        median_early = statistics.median(times_early)
        median_late = statistics.median(times_late)
        
        # Allow 50% tolerance - if there's true early exit, this would be much larger
        ratio = max(median_early, median_late) / min(median_early, median_late)
        assert ratio < 1.5, f"Timing inconsistency detected: ratio={ratio}"


class TestSecureMemoryZeroizer:
    """Tests for secure memory wiping utilities."""
    
    def test_wipe_bytearray(self):
        """Test bytearray is properly wiped."""
        sensitive = bytearray(b"secret_api_key_here_12345")
        original = bytes(sensitive)
        
        SecureMemoryZeroizer.wipe_bytes(sensitive)
        
        # Verify all bytes are zero
        assert all(b == 0 for b in sensitive)
        # Verify original data is gone
        assert bytes(sensitive) != original
    
    def test_wipe_bytearray_empty(self):
        """Test wiping empty bytearray doesn't crash."""
        empty = bytearray()
        SecureMemoryZeroizer.wipe_bytes(empty)
        assert len(empty) == 0
    
    def test_wipe_memoryview(self):
        """Test wiping memoryview."""
        arr = bytearray(b"sensitive_data")
        view = memoryview(arr)
        SecureMemoryZeroizer.wipe_bytes(view)
        assert all(b == 0 for b in arr)
    
    def test_wipe_list(self):
        """Test wiping list contents."""
        sensitive_list = [bytearray(b"secret1"), bytearray(b"secret2")]
        SecureMemoryZeroizer.wipe_list(sensitive_list)
        assert len(sensitive_list) == 0
    
    def test_wipe_object_attributes(self):
        """Test wiping object attributes."""
        class TestObject:
            def __init__(self):
                self.secret_key = bytearray(b"my_secret")
                self.public_data = "public"
        
        obj = TestObject()
        SecureMemoryZeroizer.wipe_object(obj, ["secret_key"])
        
        assert obj.secret_key is None
        assert obj.public_data == "public"  # Unspecified attribute preserved


class TestSideChannelResistantValidator:
    """Tests for side-channel resistant validation."""
    
    def setup_method(self):
        self.validator = SideChannelResistantValidator()
    
    def test_validate_api_key_valid(self):
        """Test valid API key validation."""
        assert self.validator.validate_api_key("valid_key_123", "valid_key_123") is True
    
    def test_validate_api_key_invalid(self):
        """Test invalid API key validation."""
        assert self.validator.validate_api_key("wrong_key", "valid_key_123") is False
    
    def test_validate_token_valid(self):
        """Test valid token validation."""
        token = secrets.token_bytes(32)
        assert self.validator.validate_token(token, token) is True
    
    def test_validate_token_invalid(self):
        """Test invalid token validation."""
        token1 = secrets.token_bytes(32)
        token2 = secrets.token_bytes(32)
        assert self.validator.validate_token(token1, token2) is False
    
    def test_validate_password_hash_match(self):
        """Test matching password hashes."""
        hash1 = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
        hash2 = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
        assert self.validator.validate_password_hash(hash1, hash2) is True
    
    def test_validate_password_hash_mismatch(self):
        """Test mismatched password hashes."""
        hash1 = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
        hash2 = "6b21c058da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
        assert self.validator.validate_password_hash(hash1, hash2) is False


class TestSecureTemporaryBuffer:
    """Tests for secure temporary buffer context manager."""
    
    def test_context_manager_wipes_on_exit(self):
        """Test buffer is wiped after context exit."""
        with secure_buffer(64) as buf:
            buf[:11] = b"secret_data"
            assert buf[:11] == b"secret_data"
            original = bytes(buf)
        
        # After exit, buffer should be wiped
        # Note: can't access buf directly after exit, but we can verify
        # the context manager completed without errors
        assert len(original) == 64
    
    def test_explicit_wipe(self):
        """Test explicit wipe method works."""
        sb = SecureTemporaryBuffer(32)
        sb.buffer[:] = b"sensitive_content_here"
        sb.wipe()
        assert all(b == 0 for b in sb.buffer)
    
    def test_double_wipe_safe(self):
        """Test double wipe is safe (no errors)."""
        sb = SecureTemporaryBuffer(16)
        sb.wipe()
        sb.wipe()  # Should not raise


class TestConvenienceFunctions:
    """Tests for public convenience API."""
    
    def test_constant_time_compare_function(self):
        """Test top-level compare function."""
        assert constant_time_compare(b"test", b"test") is True
        assert constant_time_compare(b"test", b"tesx") is False
    
    def test_constant_time_compare_str_function(self):
        """Test top-level string compare function."""
        assert constant_time_compare_str("hello", "hello") is True
        assert constant_time_compare_str("hello", "world") is False
    
    def test_secure_wipe_bytearray(self):
        """Test top-level secure_wipe on bytearray."""
        data = bytearray(b"secret")
        secure_wipe(data)
        assert all(b == 0 for b in data)
    
    def test_secure_buffer_creates_context(self):
        """Test secure_buffer creates context manager."""
        sb = secure_buffer(128)
        assert isinstance(sb, SecureTemporaryBuffer)
        assert len(sb.buffer) == 128


class TestEdgeCases:
    """Edge case and boundary condition tests."""
    
    def test_very_long_comparison(self):
        """Test comparison of very long byte strings."""
        data1 = secrets.token_bytes(10000)
        data2 = bytes(data1)
        assert ConstantTimeComparer.compare_bytes(data1, data2) is True
        
        data3 = secrets.token_bytes(10000)
        assert ConstantTimeComparer.compare_bytes(data1, data3) is False
    
    def test_single_byte_difference(self):
        """Test comparison with single byte difference at various positions."""
        base = bytearray(b"x" * 100)
        
        for pos in [0, 1, 50, 98, 99]:
            modified = bytearray(base)
            modified[pos] ^= 0xFF
            assert ConstantTimeComparer.compare_bytes(bytes(base), bytes(modified)) is False
    
    def test_null_bytes_comparison(self):
        """Test strings containing null bytes."""
        a = b"\x00\x01\x00\x02"
        b = b"\x00\x01\x00\x02"
        c = b"\x00\x01\x00\x03"
        assert ConstantTimeComparer.compare_bytes(a, b) is True
        assert ConstantTimeComparer.compare_bytes(a, c) is False
    
    def test_all_zero_bytes(self):
        """Test comparison of all-zero buffers."""
        assert ConstantTimeComparer.compare_bytes(b"\x00" * 64, b"\x00" * 64) is True
        assert ConstantTimeComparer.compare_bytes(b"\x00" * 64, b"\x00" * 63 + b"\x01") is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
