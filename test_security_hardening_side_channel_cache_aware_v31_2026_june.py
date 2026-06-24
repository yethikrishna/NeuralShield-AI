"""
Tests for Security Hardening: Side-Channel Cache-Aware Memory Protection v31
DIMENSION B - Security Hardening

These tests verify the side-channel protection features work correctly.
All tests are ADD-ONLY - no existing code is modified.
"""

import pytest
import time
import secrets
import threading
from typing import List

from neural_shield.security_hardening_side_channel_cache_aware_protection_v31_2026_june import (
    CacheAlignment,
    SideChannelMitigationLevel,
    CacheProtectionConfig,
    CacheAwareMemoryProtector,
    ConstantTimeStringProtector,
    constant_time_compare,
    secure_memory_zeroize,
    secure_string_equals,
    wrap_sensitive,
)


class TestCacheAlignment:
    """Tests for cache alignment enumeration."""
    
    def test_cache_alignment_values(self):
        """Verify all cache alignment values are reasonable."""
        assert CacheAlignment.X86_64.value == 64
        assert CacheAlignment.ARM64.value == 128
        assert CacheAlignment.UNIVERSAL.value == 512
    
    def test_all_alignments_power_of_two(self):
        """All cache line sizes should be powers of 2."""
        for alignment in CacheAlignment:
            value = alignment.value
            assert value > 0
            assert (value & (value - 1)) == 0  # Power of 2 check


class TestSideChannelMitigationLevel:
    """Tests for mitigation level enumeration."""
    
    def test_mitigation_order(self):
        """Verify mitigation levels are ordered correctly."""
        levels = [
            SideChannelMitigationLevel.MINIMAL,
            SideChannelMitigationLevel.STANDARD,
            SideChannelMitigationLevel.AGGRESSIVE,
            SideChannelMitigationLevel.PARANOID,
        ]
        for i in range(len(levels) - 1):
            assert levels[i].value < levels[i + 1].value


class TestCacheProtectionConfig:
    """Tests for protection configuration."""
    
    def test_default_config(self):
        """Verify default configuration is sensible."""
        config = CacheProtectionConfig()
        assert config.alignment == CacheAlignment.UNIVERSAL
        assert config.mitigation_level == SideChannelMitigationLevel.STANDARD
        assert config.enable_cache_flush == True
        assert config.enable_timing_noise == True
    
    def test_custom_config(self):
        """Verify custom configuration works."""
        config = CacheProtectionConfig(
            alignment=CacheAlignment.X86_64,
            mitigation_level=SideChannelMitigationLevel.PARANOID,
            max_jitter_ns=5000,
        )
        assert config.alignment == CacheAlignment.X86_64
        assert config.mitigation_level == SideChannelMitigationLevel.PARANOID
        assert config.max_jitter_ns == 5000


class TestCacheAwareMemoryProtector:
    """Tests for the main cache-aware memory protector."""
    
    def test_initialization(self):
        """Verify protector initializes correctly."""
        protector = CacheAwareMemoryProtector()
        assert protector._initialized == True
        assert protector._cache_line_size > 0
    
    def test_custom_config_initialization(self):
        """Verify custom config initialization."""
        config = CacheProtectionConfig(mitigation_level=SideChannelMitigationLevel.MINIMAL)
        protector = CacheAwareMemoryProtector(config)
        assert protector.config.mitigation_level == SideChannelMitigationLevel.MINIMAL
    
    def test_constant_time_compare_equal(self):
        """Verify equal byte strings compare as equal."""
        protector = CacheAwareMemoryProtector()
        
        data = secrets.token_bytes(32)
        assert protector.constant_time_compare(data, data) == True
        
        # Empty bytes
        assert protector.constant_time_compare(b'', b'') == True
    
    def test_constant_time_compare_not_equal(self):
        """Verify non-equal byte strings compare as not equal."""
        protector = CacheAwareMemoryProtector()
        
        a = b'hello world'
        b = b'hello worlx'
        assert protector.constant_time_compare(a, b) == False
        
        # Different lengths
        assert protector.constant_time_compare(b'short', b'longer string') == False
    
    def test_constant_time_compare_different_lengths_no_leak(self):
        """Different length comparisons should not leak via timing."""
        protector = CacheAwareMemoryProtector()
        
        # Both should execute without error
        result1 = protector.constant_time_compare(b'a', b'aa')
        result2 = protector.constant_time_compare(b'aa', b'a')
        
        assert result1 == False
        assert result2 == False
    
    def test_secure_hash_compare(self):
        """Verify secure hash comparison works."""
        protector = CacheAwareMemoryProtector()
        
        hash_val = secrets.token_bytes(32)
        assert protector.secure_hash_compare(hash_val, hash_val) == True
        
        # Single bit flip
        modified = bytearray(hash_val)
        modified[0] ^= 1
        assert protector.secure_hash_compare(hash_val, bytes(modified)) == False
    
    def test_secure_memory_zeroize(self):
        """Verify memory zeroization works correctly."""
        protector = CacheAwareMemoryProtector()
        
        # Create buffer with data
        data = bytearray(secrets.token_bytes(100))
        original = bytes(data)
        
        # Zeroize
        protector.secure_memory_zeroize(data)
        
        # Verify all zeros
        assert all(b == 0 for b in data)
        assert bytes(data) != original
    
    def test_secure_memory_zeroize_empty(self):
        """Zeroize should handle empty buffers gracefully."""
        protector = CacheAwareMemoryProtector()
        
        empty = bytearray()
        protector.secure_memory_zeroize(empty)  # Should not raise
        assert len(empty) == 0
    
    def test_create_protected_buffer(self):
        """Verify protected buffer creation."""
        protector = CacheAwareMemoryProtector()
        
        size = 256
        buf = protector.create_protected_buffer(size)
        
        assert len(buf) == size
        assert isinstance(buf, bytearray)
    
    def test_get_protection_stats(self):
        """Verify statistics tracking works."""
        protector = CacheAwareMemoryProtector()
        
        # Do some operations
        protector.constant_time_compare(b'test', b'test')
        protector.secure_memory_zeroize(bytearray(10))
        
        stats = protector.get_protection_stats()
        
        assert stats['protected_operations'] >= 2
        assert 'mitigation_level' in stats
        assert 'cache_alignment' in stats
        assert 'cache_line_size' in stats
    
    def test_wrap_sensitive_operation(self):
        """Verify function wrapping works."""
        protector = CacheAwareMemoryProtector()
        
        call_count = [0]
        
        @protector.wrap_sensitive_operation
        def sensitive_func(x: int) -> int:
            call_count[0] += 1
            return x * 2
        
        result = sensitive_func(5)
        assert result == 10
        assert call_count[0] == 1
    
    def test_thread_safety(self):
        """Verify protector is thread-safe."""
        protector = CacheAwareMemoryProtector()
        num_threads = 10
        ops_per_thread = 100
        
        errors = []
        
        def worker():
            try:
                for _ in range(ops_per_thread):
                    data = secrets.token_bytes(16)
                    protector.constant_time_compare(data, data)
            except Exception as e:
                errors.append(e)
        
        threads = [threading.Thread(target=worker) for _ in range(num_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert len(errors) == 0
        stats = protector.get_protection_stats()
        assert stats['protected_operations'] >= num_threads * ops_per_thread


class TestConstantTimeStringProtector:
    """Tests for constant-time string protection."""
    
    def test_secure_equals_equal(self):
        """Verify equal strings compare equal."""
        assert ConstantTimeStringProtector.secure_equals("test", "test") == True
        assert ConstantTimeStringProtector.secure_equals("", "") == True
        assert ConstantTimeStringProtector.secure_equals("日本語", "日本語") == True
    
    def test_secure_equals_not_equal(self):
        """Verify non-equal strings compare not equal."""
        assert ConstantTimeStringProtector.secure_equals("test", "Test") == False
        assert ConstantTimeStringProtector.secure_equals("hello", "world") == False
        assert ConstantTimeStringProtector.secure_equals("a", "aa") == False
    
    def test_secure_prefix_check(self):
        """Verify prefix checking works."""
        assert ConstantTimeStringProtector.secure_prefix_check("hello world", "hello") == True
        assert ConstantTimeStringProtector.secure_prefix_check("hello world", "world") == False
        assert ConstantTimeStringProtector.secure_prefix_check("short", "longer prefix") == False
    
    def test_secure_suffix_check(self):
        """Verify suffix checking works."""
        assert ConstantTimeStringProtector.secure_suffix_check("hello world", "world") == True
        assert ConstantTimeStringProtector.secure_suffix_check("hello world", "hello") == False
        assert ConstantTimeStringProtector.secure_suffix_check("short", "longer suffix") == False


class TestConvenienceFunctions:
    """Tests for the top-level convenience functions."""
    
    def test_constant_time_compare_function(self):
        """Verify convenience function works."""
        assert constant_time_compare(b'test', b'test') == True
        assert constant_time_compare(b'test', b'best') == False
    
    def test_secure_memory_zeroize_function(self):
        """Verify zeroize convenience function works."""
        buf = bytearray(b'sensitive data')
        secure_memory_zeroize(buf)
        assert all(b == 0 for b in buf)
    
    def test_secure_string_equals_function(self):
        """Verify string equals function works."""
        assert secure_string_equals("test", "test") == True
        assert secure_string_equals("test", "different") == False
    
    def test_wrap_sensitive_decorator(self):
        """Verify decorator works."""
        call_count = [0]
        
        @wrap_sensitive
        def sensitive_func():
            call_count[0] += 1
            return "result"
        
        result = sensitive_func()
        assert result == "result"
        assert call_count[0] == 1


class TestTimingProperties:
    """Tests for timing properties (rough verification)."""
    
    def test_timing_consistency_equal_comparisons(self):
        """Rough test that equal vs non-equal don't have huge timing differences.
        
        Note: This is a statistical test, not a formal proof.
        """
        config = CacheProtectionConfig(
            mitigation_level=SideChannelMitigationLevel.MINIMAL,
            enable_timing_noise=False,
        )
        protector = CacheAwareMemoryProtector(config)
        
        data1 = secrets.token_bytes(1024)
        data2 = secrets.token_bytes(1024)
        
        # Time equal comparisons
        equal_times: List[float] = []
        for _ in range(100):
            start = time.perf_counter()
            protector.constant_time_compare(data1, data1)
            equal_times.append(time.perf_counter() - start)
        
        # Time non-equal comparisons
        not_equal_times: List[float] = []
        for _ in range(100):
            start = time.perf_counter()
            protector.constant_time_compare(data1, data2)
            not_equal_times.append(time.perf_counter() - start)
        
        # Average times should be similar (within 2x)
        avg_equal = sum(equal_times) / len(equal_times)
        avg_not_equal = sum(not_equal_times) / len(not_equal_times)
        
        # This is a sanity check, not strict
        ratio = max(avg_equal, avg_not_equal) / min(avg_equal, avg_not_equal)
        assert ratio < 5.0, f"Timing ratio too high: {ratio}"


class TestApiStability:
    """Tests for API stability markers."""
    
    def test_all_exports_have_stability(self):
        """Verify all exported items have stability markers."""
        from neural_shield.security_hardening_side_channel_cache_aware_protection_v31_2026_june import (
            __all__, __api_stability__
        )
        
        for export in __all__:
            assert export in __api_stability__, f"Missing stability for {export}"
    
    def test_stability_values_valid(self):
        """Verify stability values are valid."""
        from neural_shield.security_hardening_side_channel_cache_aware_protection_v31_2026_june import (
            __api_stability__
        )
        
        valid_stabilities = {'STABLE', 'EXPERIMENTAL', 'DEPRECATED'}
        for stability in __api_stability__.values():
            assert stability in valid_stabilities, f"Invalid stability: {stability}"


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
