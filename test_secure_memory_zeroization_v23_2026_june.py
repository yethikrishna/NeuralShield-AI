"""
Tests for Secure Memory Zeroization v23 - NeuralShield-AI
Security Hardening - Dimension B
"""

import pytest
import gc
from neural_shield.secure_memory_zeroization_v23_2026_june import (
    SecureMemoryZeroizer,
    SecureBuffer,
    secure_memcmp,
    secure_memset,
    generate_secure_random,
    scrub_memory,
    SecureMemoryError,
)


class TestSecureMemoryZeroizer:
    """Tests for SecureMemoryZeroizer class."""
    
    def setup_method(self):
        self.zeroizer = SecureMemoryZeroizer()
    
    def test_zeroize_bytes_basic(self):
        """Test basic bytearray zeroization."""
        data = bytearray(b'sensitive data here')
        original = bytes(data)
        
        self.zeroizer.zeroize_bytes(data)
        
        assert all(b == 0 for b in data)
        assert len(data) == len(original)
    
    def test_zeroize_bytes_empty(self):
        """Test zeroizing empty bytearray."""
        data = bytearray()
        self.zeroizer.zeroize_bytes(data)
        assert data == bytearray()
    
    def test_zeroize_bytes_type_check(self):
        """Test type checking for zeroize_bytes."""
        with pytest.raises(TypeError):
            self.zeroizer.zeroize_bytes(b'immutable bytes')  # Not bytearray
    
    def test_zeroize_string(self):
        """Test string zeroization (best effort)."""
        s = "secret password 123"
        result = self.zeroizer.zeroize_string(s)
        assert result == ''
    
    def test_zeroize_list(self):
        """Test zeroizing list elements."""
        sensitive = bytearray(b'secret')
        data = [sensitive, b'hello', 42, bytearray(b'another')]
        
        self.zeroizer.zeroize_list(data)
        
        assert all(b == 0 for b in sensitive)
        assert data == []
    
    def test_secure_wipe_object(self):
        """Test wiping object attributes."""
        class TestObj:
            def __init__(self):
                self.secret = bytearray(b'my secret')
                self.key = b'encryption key'
                self.count = 100
        
        obj = TestObj()
        self.zeroizer.secure_wipe_object(obj)
        
        assert all(b == 0 for b in obj.secret)
        assert obj.key == b''


class TestSecureBuffer:
    """Tests for SecureBuffer context manager."""
    
    def test_buffer_context_manager(self):
        """Test buffer as context manager."""
        with SecureBuffer(32) as buf:
            buf.data[:] = b'x' * 32
            assert len(buf.data) == 32
            assert buf.data[0] == ord('x')
        
        # After exit, should be zeroized
        assert all(b == 0 for b in buf.data)
        assert buf._is_zeroized
    
    def test_buffer_explicit_zeroize(self):
        """Test explicit zeroize call."""
        buf = SecureBuffer(16)
        buf.data[:] = b'test data'
        buf.zeroize()
        assert all(b == 0 for b in buf.data)
        assert buf._is_zeroized
    
    def test_buffer_double_zeroize_safe(self):
        """Test double zeroize is safe."""
        buf = SecureBuffer(8)
        buf.zeroize()
        buf.zeroize()  # Should not crash
        assert buf._is_zeroized


class TestSecureMemCmp:
    """Tests for constant-time memory comparison."""
    
    def test_memcmp_equal(self):
        """Test comparing equal buffers."""
        a = b'hello world'
        b = b'hello world'
        assert secure_memcmp(a, b) is True
    
    def test_memcmp_not_equal(self):
        """Test comparing different buffers."""
        a = b'hello world'
        b = b'hello xorld'
        assert secure_memcmp(a, b) is False
    
    def test_memcmp_different_lengths(self):
        """Test comparing buffers of different lengths."""
        a = b'short'
        b = b'much longer string'
        with pytest.raises(ValueError):
            secure_memcmp(a, b)
    
    def test_memcmp_empty(self):
        """Test comparing empty buffers."""
        assert secure_memcmp(b'', b'') is True


class TestSecureMemSet:
    """Tests for secure memset."""
    
    def test_memset_basic(self):
        """Test basic memset operation."""
        data = bytearray(10)
        secure_memset(data, 0xAA)
        assert all(b == 0xAA for b in data)
    
    def test_memset_zero(self):
        """Test memset to zero."""
        data = bytearray(b'hello')
        secure_memset(data, 0x00)
        assert all(b == 0 for b in data)
    
    def test_memset_partial(self):
        """Test partial memset."""
        data = bytearray(b'hello world')
        secure_memset(data, 0xFF, length=5)
        assert all(b == 0xFF for b in data[:5])
        assert data[5:] == b' world'


class TestSecureRandom:
    """Tests for secure random generation."""
    
    def test_generate_secure_random(self):
        """Test secure random generation."""
        rand1 = generate_secure_random(32)
        rand2 = generate_secure_random(32)
        
        assert len(rand1) == 32
        assert len(rand2) == 32
        assert rand1 != rand2  # Extremely unlikely to collide
    
    def test_generate_different_lengths(self):
        """Test different length random generation."""
        for length in [1, 16, 32, 64, 128]:
            result = generate_secure_random(length)
            assert len(result) == length


class TestScrubMemory:
    """Tests for memory scrubbing."""
    
    def test_scrub_memory_runs(self):
        """Test that scrub_memory executes without error."""
        # Should not raise exceptions
        scrub_memory()


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
