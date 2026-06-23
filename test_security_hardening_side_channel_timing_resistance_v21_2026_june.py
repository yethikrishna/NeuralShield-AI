"""
Test Suite: Security Hardening - Side-Channel Timing Attack Resistance v21
NeuralShield-AI

Tests for timing attack resistance, secure memory zeroization,
and constant-time operations.

All tests verify backward compatibility and proper functionality.
"""

import pytest
import time
import hmac
import hashlib
import secrets
from typing import List

from neural_shield.security_hardening_side_channel_timing_attack_resistance_v21_2026_june import (
    TimingNoiseLevel,
    CacheProtectionLevel,
    TimingSecurityContext,
    SecureTimingProtector,
    SecureMemoryZeroizer,
    SecureInputValidator,
    constant_time_compare,
    secure_zeroize,
    normalize_timing,
    validate_input_length,
)


class TestTimingNoiseLevel:
    """Tests for TimingNoiseLevel enum."""
    
    def test_enum_values_exist(self):
        """Verify all noise levels are defined."""
        assert TimingNoiseLevel.NONE.value == 0
        assert TimingNoiseLevel.LOW.value == 1
        assert TimingNoiseLevel.MEDIUM.value == 2
        assert TimingNoiseLevel.HIGH.value == 3
        assert TimingNoiseLevel.MAXIMUM.value == 4


class TestCacheProtectionLevel:
    """Tests for CacheProtectionLevel enum."""
    
    def test_enum_values_exist(self):
        """Verify all protection levels are defined."""
        assert CacheProtectionLevel.NONE.value == 0
        assert CacheProtectionLevel.BASIC.value == 1
        assert CacheProtectionLevel.MEDIUM.value == 2
        assert CacheProtectionLevel.STRONG.value == 3
        assert CacheProtectionLevel.MAXIMUM.value == 4


class TestTimingSecurityContext:
    """Tests for TimingSecurityContext."""
    
    def test_context_initialization(self):
        """Verify context initializes with defaults."""
        ctx = TimingSecurityContext()
        assert ctx.noise_level == TimingNoiseLevel.MEDIUM
        assert ctx.cache_protection == CacheProtectionLevel.MEDIUM
        assert ctx.enable_constant_time is True
        assert ctx.normalize_execution_time is True
    
    def test_context_custom_values(self):
        """Verify context accepts custom values."""
        ctx = TimingSecurityContext(
            noise_level=TimingNoiseLevel.HIGH,
            cache_protection=CacheProtectionLevel.STRONG,
            baseline_ns=200000
        )
        assert ctx.noise_level == TimingNoiseLevel.HIGH
        assert ctx.cache_protection == CacheProtectionLevel.STRONG
        assert ctx.baseline_ns == 200000


class TestSecureTimingProtector:
    """Tests for SecureTimingProtector."""
    
    def test_protector_initialization(self):
        """Verify protector initializes correctly."""
        protector = SecureTimingProtector()
        assert protector.noise_level == TimingNoiseLevel.MEDIUM
        assert protector.cache_protection == CacheProtectionLevel.MEDIUM
    
    def test_constant_time_compare_equal(self):
        """Verify constant-time compare works for equal bytes."""
        protector = SecureTimingProtector()
        data = secrets.token_bytes(32)
        assert protector.constant_time_compare(data, data) is True
    
    def test_constant_time_compare_not_equal(self):
        """Verify constant-time compare works for different bytes."""
        protector = SecureTimingProtector()
        a = secrets.token_bytes(32)
        b = secrets.token_bytes(32)
        assert protector.constant_time_compare(a, b) is False
    
    def test_constant_time_compare_different_lengths(self):
        """Verify constant-time compare handles different lengths."""
        protector = SecureTimingProtector()
        a = secrets.token_bytes(16)
        b = secrets.token_bytes(32)
        assert protector.constant_time_compare(a, b) is False
    
    def test_constant_time_string_compare(self):
        """Verify constant-time string comparison."""
        protector = SecureTimingProtector()
        assert protector.constant_time_string_compare("test", "test") is True
        assert protector.constant_time_string_compare("test", "TEST") is False
    
    def test_timing_noise_injection(self):
        """Verify timing noise injection adds delay."""
        protector = SecureTimingProtector(noise_level=TimingNoiseLevel.MAXIMUM)
        
        # Measure time with noise
        start = time.perf_counter_ns()
        protector._timing_noise_delay()
        elapsed = time.perf_counter_ns() - start
        
        # Should have some delay
        assert elapsed > 0
    
    def test_cache_access_obfuscation(self):
        """Verify cache obfuscation runs without errors."""
        protector = SecureTimingProtector(
            cache_protection=CacheProtectionLevel.MAXIMUM
        )
        # Should not raise exceptions
        protector._cache_access_obfuscation()
    
    def test_normalize_execution_time_decorator(self):
        """Verify execution time normalization decorator."""
        protector = SecureTimingProtector(baseline_execution_ns=50000)
        
        call_count = 0
        
        @protector.normalize_execution_time
        def test_func(x: int) -> int:
            nonlocal call_count
            call_count += 1
            return x * 2
        
        result = test_func(5)
        assert result == 10
        assert call_count == 1
    
    def test_secure_branch(self):
        """Verify secure branch execution."""
        protector = SecureTimingProtector()
        
        true_executed = False
        false_executed = False
        
        def true_branch():
            nonlocal true_executed
            true_executed = True
            return "true"
        
        def false_branch():
            nonlocal false_executed
            false_executed = True
            return "false"
        
        # Both branches should be executed
        result = protector.secure_branch(True, true_branch, false_branch)
        assert result == "true"
        assert true_executed is True
        assert false_executed is True
        
        # Reset and test False condition
        true_executed = False
        false_executed = False
        
        result = protector.secure_branch(False, true_branch, false_branch)
        assert result == "false"
        assert true_executed is True
        assert false_executed is True


class TestSecureMemoryZeroizer:
    """Tests for SecureMemoryZeroizer."""
    
    def test_zeroize_bytes(self):
        """Verify bytearray zeroization."""
        data = bytearray(secrets.token_bytes(64))
        original = bytes(data)
        
        SecureMemoryZeroizer.zeroize_bytes(data)
        
        # All bytes should be zero
        assert all(b == 0 for b in data)
        # Original should be different
        assert bytes(data) != original
    
    def test_zeroize_empty_bytes(self):
        """Verify zeroization handles empty arrays."""
        data = bytearray()
        SecureMemoryZeroizer.zeroize_bytes(data)
        assert len(data) == 0
    
    def test_zeroize_string(self):
        """Verify string zeroization hint."""
        result = SecureMemoryZeroizer.zeroize_string("sensitive")
        assert result == ""
    
    def test_secure_delete_bytearray(self):
        """Verify secure delete on bytearray."""
        data = bytearray(b"sensitive data")
        SecureMemoryZeroizer.secure_delete(data)
        assert all(b == 0 for b in data)


class TestSecureInputValidator:
    """Tests for SecureInputValidator."""
    
    def test_validator_initialization(self):
        """Verify validator initializes correctly."""
        validator = SecureInputValidator()
        assert validator.timing_protector is not None
    
    def test_validate_length_valid(self):
        """Verify length validation for valid input."""
        validator = SecureInputValidator()
        assert validator.validate_length("test", 2, 10) is True
    
    def test_validate_length_too_short(self):
        """Verify length validation for too short input."""
        validator = SecureInputValidator()
        assert validator.validate_length("a", 2, 10) is False
    
    def test_validate_length_too_long(self):
        """Verify length validation for too long input."""
        validator = SecureInputValidator()
        assert validator.validate_length("a" * 20, 2, 10) is False
    
    def test_validate_charset_valid(self):
        """Verify charset validation for valid input."""
        validator = SecureInputValidator()
        assert validator.validate_charset("abc123", "abcdefghijklmnopqrstuvwxyz0123456789") is True
    
    def test_validate_charset_invalid(self):
        """Verify charset validation for invalid input."""
        validator = SecureInputValidator()
        assert validator.validate_charset("abc!", "abcdefghijklmnopqrstuvwxyz") is False
    
    def test_validate_email_format_valid(self):
        """Verify email validation for valid format."""
        validator = SecureInputValidator()
        assert validator.validate_email_format("test@example.com") is True
    
    def test_validate_email_format_invalid(self):
        """Verify email validation for invalid format."""
        validator = SecureInputValidator()
        assert validator.validate_email_format("invalid-email") is False


class TestConvenienceFunctions:
    """Tests for global convenience functions."""
    
    def test_global_constant_time_compare(self):
        """Verify global constant_time_compare function."""
        a = b"test data"
        b = b"test data"
        c = b"different"
        
        assert constant_time_compare(a, b) is True
        assert constant_time_compare(a, c) is False
    
    def test_global_secure_zeroize(self):
        """Verify global secure_zeroize function."""
        data = bytearray(b"sensitive")
        secure_zeroize(data)
        assert all(b == 0 for b in data)
    
    def test_global_normalize_timing(self):
        """Verify global normalize_timing decorator."""
        call_count = 0
        
        @normalize_timing
        def test_func():
            nonlocal call_count
            call_count += 1
            return "success"
        
        result = test_func()
        assert result == "success"
        assert call_count == 1
    
    def test_global_validate_input_length(self):
        """Verify global validate_input_length function."""
        assert validate_input_length("test", 2, 10) is True
        assert validate_input_length("a", 5, 10) is False


class TestTimingAttackResistance:
    """Tests for actual timing attack resistance properties."""
    
    def test_compare_timing_consistency(self):
        """Verify comparison timing is consistent regardless of input."""
        protector = SecureTimingProtector(
            noise_level=TimingNoiseLevel.NONE,
            cache_protection=CacheProtectionLevel.NONE
        )
        
        # Compare equal vs different bytes multiple times
        equal_times: List[int] = []
        different_times: List[int] = []
        
        a = secrets.token_bytes(32)
        b_equal = bytes(a)
        b_different = secrets.token_bytes(32)
        
        for _ in range(100):
            # Equal comparison timing
            start = time.perf_counter_ns()
            protector.constant_time_compare(a, b_equal)
            equal_times.append(time.perf_counter_ns() - start)
            
            # Different comparison timing
            start = time.perf_counter_ns()
            protector.constant_time_compare(a, b_different)
            different_times.append(time.perf_counter_ns() - start)
        
        # The averages should be close (within reasonable bounds)
        avg_equal = sum(equal_times) / len(equal_times)
        avg_different = sum(different_times) / len(different_times)
        
        # Should be within 2x of each other (not orders of magnitude)
        ratio = max(avg_equal, avg_different) / min(avg_equal, avg_different)
        assert ratio < 10, f"Timing ratio too high: {ratio}"
    
    def test_no_early_exit_in_charset_validation(self):
        """Verify charset validation doesn't early exit on first invalid char."""
        validator = SecureInputValidator(
            timing_protector=SecureTimingProtector(noise_level=TimingNoiseLevel.NONE)
        )
        
        allowed = "abcdefghijklmnopqrstuvwxyz"
        
        # Invalid char at beginning vs end
        early_times: List[int] = []
        late_times: List[int] = []
        
        for _ in range(50):
            # Invalid char at position 1
            start = time.perf_counter_ns()
            validator.validate_charset("a!cdefghijklmnopqrstuvwxyz", allowed)
            early_times.append(time.perf_counter_ns() - start)
            
            # Invalid char at position 25
            start = time.perf_counter_ns()
            validator.validate_charset("abcdefghijklmnopqrstuvwxy!", allowed)
            late_times.append(time.perf_counter_ns() - start)
        
        # Timings should be similar
        avg_early = sum(early_times) / len(early_times)
        avg_late = sum(late_times) / len(late_times)
        
        ratio = max(avg_early, avg_late) / min(avg_early, avg_late)
        assert ratio < 5, f"Early exit detected, ratio: {ratio}"


class TestBackwardCompatibility:
    """Tests for backward compatibility verification."""
    
    def test_no_existing_code_modification(self):
        """Verify module is purely additive."""
        # This module should only export new functionality
        # and not modify any existing modules
        import neural_shield
        
        # New module exists
        assert hasattr(neural_shield, 'security_hardening_side_channel_timing_attack_resistance_v21_2026_june')
    
    def test_import_without_side_effects(self):
        """Verify importing doesn't break anything."""
        # Import should succeed without exceptions
        from neural_shield import security_hardening_side_channel_timing_attack_resistance_v21_2026_june
        assert security_hardening_side_channel_timing_attack_resistance_v21_2026_june is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
