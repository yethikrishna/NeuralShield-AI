"""
Tests for Security Hardening: Side-Channel Resistant Memory Protection v19
NeuralShield-AI - June 2026

DIMENSION B - Security Hardening
Comprehensive test coverage for the new security module.
"""

import pytest
import secrets
import time
import gc

from neural_shield.security_hardening_side_channel_memory_protection_v19_2026_june import (
    MemoryProtectionLevel,
    MemoryProtectionResult,
    SideChannelResistantMemory,
    ProtectedSecret,
    constant_time_eq,
    secure_zeroize,
    protected_secret,
)


class TestMemoryProtectionLevel:
    """Tests for MemoryProtectionLevel enum."""
    
    def test_protection_levels_exist(self):
        """Test all protection levels are defined."""
        assert MemoryProtectionLevel.BASIC.value == "basic"
        assert MemoryProtectionLevel.STANDARD.value == "standard"
        assert MemoryProtectionLevel.ENHANCED.value == "enhanced"
        assert MemoryProtectionLevel.MAXIMUM.value == "maximum"


class TestSideChannelResistantMemory:
    """Tests for SideChannelResistantMemory class."""
    
    def test_initialization_default(self):
        """Test default initialization."""
        protector = SideChannelResistantMemory()
        assert protector.protection_level == MemoryProtectionLevel.STANDARD
    
    def test_initialization_custom_level(self):
        """Test initialization with custom protection level."""
        protector = SideChannelResistantMemory(MemoryProtectionLevel.MAXIMUM)
        assert protector.protection_level == MemoryProtectionLevel.MAXIMUM
    
    def test_constant_time_compare_equal(self):
        """Test constant time comparison with equal strings."""
        protector = SideChannelResistantMemory()
        a = b"test_data_12345"
        b = b"test_data_12345"
        assert protector.constant_time_compare(a, b) == True
    
    def test_constant_time_compare_not_equal(self):
        """Test constant time comparison with different strings."""
        protector = SideChannelResistantMemory()
        a = b"test_data_12345"
        b = b"test_data_54321"
        assert protector.constant_time_compare(a, b) == False
    
    def test_constant_time_compare_different_lengths(self):
        """Test constant time comparison with different lengths."""
        protector = SideChannelResistantMemory()
        a = b"short"
        b = b"much_longer_string"
        assert protector.constant_time_compare(a, b) == False
    
    def test_constant_time_compare_empty(self):
        """Test constant time comparison with empty strings."""
        protector = SideChannelResistantMemory()
        assert protector.constant_time_compare(b"", b"") == True
    
    def test_constant_time_hmac_compare(self):
        """Test HMAC-based constant time comparison."""
        protector = SideChannelResistantMemory()
        key = secrets.token_bytes(32)
        a = b"secret_data"
        b = b"secret_data"
        assert protector.constant_time_hmac_compare(a, b, key) == True
    
    def test_constant_time_hmac_compare_different(self):
        """Test HMAC-based comparison with different data."""
        protector = SideChannelResistantMemory()
        key = secrets.token_bytes(32)
        a = b"secret_data_1"
        b = b"secret_data_2"
        assert protector.constant_time_hmac_compare(a, b, key) == False
    
    def test_secure_zeroize_basic(self):
        """Test basic secure zeroization."""
        protector = SideChannelResistantMemory(MemoryProtectionLevel.BASIC)
        buffer = bytearray(b"sensitive_data_here")
        original = bytes(buffer)
        
        result = protector.secure_zeroize(buffer)
        
        assert result.success == True
        assert result.operation == "secure_zeroize"
        assert result.bytes_processed == len(original)
        assert bytes(buffer) == b"\x00" * len(original)
    
    def test_secure_zeroize_standard(self):
        """Test standard secure zeroization (3 passes)."""
        protector = SideChannelResistantMemory(MemoryProtectionLevel.STANDARD)
        buffer = bytearray(b"sensitive_data_here_12345")
        
        result = protector.secure_zeroize(buffer)
        
        assert result.success == True
        assert all(b == 0 for b in buffer)
    
    def test_secure_zeroize_enhanced(self):
        """Test enhanced secure zeroization (5 passes)."""
        protector = SideChannelResistantMemory(MemoryProtectionLevel.ENHANCED)
        buffer = bytearray(secrets.token_bytes(64))
        
        result = protector.secure_zeroize(buffer)
        
        assert result.success == True
        assert all(b == 0 for b in buffer)
    
    def test_secure_zeroize_maximum(self):
        """Test maximum secure zeroization (7 passes)."""
        protector = SideChannelResistantMemory(MemoryProtectionLevel.MAXIMUM)
        buffer = bytearray(secrets.token_bytes(128))
        
        result = protector.secure_zeroize(buffer)
        
        assert result.success == True
        assert all(b == 0 for b in buffer)
    
    def test_secure_zeroize_immutable_rejected(self):
        """Test that immutable bytes cannot be zeroized."""
        protector = SideChannelResistantMemory()
        buffer = b"immutable_data"  # bytes, not bytearray
        
        result = protector.secure_zeroize(buffer)  # type: ignore
        
        assert result.success == False
        assert "must be a mutable bytearray" in result.error_message
    
    def test_create_protected_buffer(self):
        """Test protected buffer creation."""
        protector = SideChannelResistantMemory()
        size = 32
        initial = b"test"
        
        buffer = protector.create_protected_buffer(size, initial)
        
        assert len(buffer) == size
        assert bytes(buffer[:4]) == initial
        # Remaining bytes should be random (not all zeros)
        assert not all(b == 0 for b in buffer[4:])
    
    def test_create_protected_buffer_no_initial(self):
        """Test protected buffer creation without initial data."""
        protector = SideChannelResistantMemory()
        size = 64
        
        buffer = protector.create_protected_buffer(size)
        
        assert len(buffer) == size
        # Should be initialized with random data
        assert not all(b == 0 for b in buffer)
    
    def test_secure_memcpy(self):
        """Test secure memory copy."""
        protector = SideChannelResistantMemory()
        dest = bytearray(32)
        src = b"hello_world_test_data"
        
        result = protector.secure_memcpy(dest, src)
        
        assert result.success == True
        assert bytes(dest[:len(src)]) == src
    
    def test_secure_memcpy_overflow(self):
        """Test secure memory copy with buffer overflow protection."""
        protector = SideChannelResistantMemory()
        dest = bytearray(10)  # Too small
        src = b"much_longer_than_10_bytes"
        
        result = protector.secure_memcpy(dest, src)
        
        assert result.success == False
        assert "overflow" in result.error_message


class TestProtectedSecret:
    """Tests for ProtectedSecret context manager."""
    
    def test_context_manager_basic(self):
        """Test basic context manager usage."""
        original = b"my_secret_key_12345"
        
        with ProtectedSecret(original) as secret:
            assert secret.data == original
            assert secret.is_destroyed == False
        
        assert secret.is_destroyed == True
    
    def test_destroy_explicit(self):
        """Test explicit destruction."""
        secret = ProtectedSecret(b"test_secret")
        assert secret.is_destroyed == False
        
        result = secret.destroy()
        
        assert result.success == True
        assert secret.is_destroyed == True
    
    def test_destroy_twice(self):
        """Test destroying already destroyed secret."""
        secret = ProtectedSecret(b"test_secret")
        secret.destroy()
        
        result = secret.destroy()
        
        assert result.success == True
        assert len(result.warnings) > 0
    
    def test_access_after_destroy_raises(self):
        """Test that accessing destroyed secret raises error."""
        secret = ProtectedSecret(b"test_secret")
        secret.destroy()
        
        with pytest.raises(ValueError, match="destroyed"):
            _ = secret.data
    
    def test_mutable_data_access(self):
        """Test mutable data access."""
        with ProtectedSecret(b"test_data") as secret:
            buf = secret.mutable_data
            assert bytes(buf) == b"test_data"
            # Modify in place
            buf[0] = ord('X')
            assert buf[0] == ord('X')
    
    def test_usage_count(self):
        """Test usage counting."""
        with ProtectedSecret(b"test") as secret:
            assert secret.usage_count == 0
            _ = secret.data
            assert secret.usage_count == 1
            _ = secret.data
            assert secret.usage_count == 2


class TestModuleLevelFunctions:
    """Tests for module-level convenience functions."""
    
    def test_constant_time_eq(self):
        """Test module-level constant time equality."""
        assert constant_time_eq(b"abc", b"abc") == True
        assert constant_time_eq(b"abc", b"def") == False
    
    def test_secure_zeroize_function(self):
        """Test module-level secure zeroize."""
        buffer = bytearray(b"sensitive")
        result = secure_zeroize(buffer)
        assert result.success == True
        assert all(b == 0 for b in buffer)
    
    def test_protected_secret_function(self):
        """Test module-level protected secret creation."""
        with protected_secret(b"test") as secret:
            assert secret.data == b"test"


class TestTimingAttackResistance:
    """Tests for timing attack resistance properties."""
    
    def test_constant_time_timing(self):
        """Test that comparison timing is consistent."""
        protector = SideChannelResistantMemory()
        
        # Compare strings that differ at first byte vs last byte
        a = b"a" * 1000
        b_first = b"b" + b"a" * 999
        b_last = b"a" * 999 + b"b"
        
        # Run multiple times and check timing variance is low
        times_first = []
        times_last = []
        
        for _ in range(100):
            start = time.perf_counter_ns()
            protector.constant_time_compare(a, b_first)
            times_first.append(time.perf_counter_ns() - start)
            
            start = time.perf_counter_ns()
            protector.constant_time_compare(a, b_last)
            times_last.append(time.perf_counter_ns() - start)
        
        # Average times should be similar (within 20%)
        avg_first = sum(times_first) / len(times_first)
        avg_last = sum(times_last) / len(times_last)
        ratio = max(avg_first, avg_last) / min(avg_first, avg_last)
        
        # This is a statistical test - should pass most of the time
        # We use a generous threshold
        assert ratio < 2.0, f"Timing variance too high: {ratio:.2f}x"


class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""
    
    def test_zero_length_buffer(self):
        """Test zeroization of zero-length buffer."""
        protector = SideChannelResistantMemory()
        buffer = bytearray()
        result = protector.secure_zeroize(buffer)
        assert result.success == True
        assert result.bytes_processed == 0
    
    def test_large_buffer(self):
        """Test zeroization of large buffer."""
        protector = SideChannelResistantMemory(MemoryProtectionLevel.BASIC)
        size = 10000
        buffer = bytearray(secrets.token_bytes(size))
        
        result = protector.secure_zeroize(buffer)
        
        assert result.success == True
        assert result.bytes_processed == size
        assert all(b == 0 for b in buffer)
    
    def test_protected_secret_empty(self):
        """Test protected secret with empty data."""
        with ProtectedSecret(b"") as secret:
            assert secret.data == b""
            assert secret.key_size == 0
    
    def test_protected_secret_garbage_collection(self):
        """Test that secrets are zeroized on GC."""
        secret = ProtectedSecret(b"will_be_gced")
        buffer_ref = secret._data  # Hold reference to internal buffer
        
        # Destroy reference
        del secret
        gc.collect()
        
        # Buffer should be zeroized
        assert all(b == 0 for b in buffer_ref)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
