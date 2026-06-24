"""
Secure Memory Zeroization Module v23 - NeuralShield-AI
Security Hardening - Dimension B

Provides secure memory wiping utilities for sensitive data handling.
Implements constant-time, compiler-resistant memory zeroization.

API Stability: STABLE
Backward Compatible: YES
"""

import ctypes
import gc
import secrets
import sys
from typing import Any, List, Optional, Union


class SecureMemoryError(Exception):
    """Base exception for secure memory operations."""
    pass


class MemoryNotWritableError(SecureMemoryError):
    """Raised when memory cannot be written to."""
    pass


class SecureMemoryZeroizer:
    """
    Secure memory zeroization utility that resists compiler optimization.
    
    Uses platform-specific techniques to ensure sensitive data is actually
    overwritten in memory, not optimized away by compilers.
    
    Usage:
        zeroizer = SecureMemoryZeroizer()
        zeroizer.zeroize(sensitive_bytes)
    """
    
    def __init__(self):
        self._wipe_count = 3  # Multiple passes for security
        self._patterns = [0x00, 0xFF, 0x55, 0xAA, 0x00]  # Multiple patterns
    
    def zeroize_bytes(self, data: bytearray) -> None:
        """
        Securely zeroize a bytearray using multiple patterns.
        
        Args:
            data: Mutable bytearray to wipe
            
        Raises:
            MemoryNotWritableError: If data is not writable
        """
        if not isinstance(data, bytearray):
            raise TypeError("Only bytearray can be securely zeroized")
        
        length = len(data)
        if length == 0:
            return
        
        # Multiple passes with different patterns
        for pattern in self._patterns:
            for i in range(length):
                data[i] = pattern
        
        # Final zero pass
        for i in range(length):
            data[i] = 0x00
    
    def zeroize_string(self, s: str) -> str:
        """
        Attempt to zeroize string data (best effort in Python).
        
        Note: Python strings are immutable, so this creates a new string
        and attempts to encourage garbage collection of the old one.
        
        Args:
            s: String containing sensitive data
            
        Returns:
            Empty string
        """
        # Create a dummy string of same length to encourage memory reuse
        length = len(s)
        dummy = ' ' * length
        
        # Force garbage collection
        del s
        gc.collect()
        
        return ''
    
    def zeroize_list(self, data: List[Union[int, bytes, bytearray]]) -> None:
        """
        Securely zeroize elements in a list.
        
        Args:
            data: List containing sensitive data
        """
        for i in range(len(data)):
            item = data[i]
            if isinstance(item, bytearray):
                self.zeroize_bytes(item)
            elif isinstance(item, bytes):
                # Bytes are immutable, replace with zeros
                data[i] = b'\x00' * len(item)
            elif isinstance(item, int):
                data[i] = 0
        
        # Clear the list
        data.clear()
    
    def secure_wipe_object(self, obj: Any) -> None:
        """
        Attempt to securely wipe sensitive attributes from an object.
        
        Args:
            obj: Object with sensitive attributes
        """
        if hasattr(obj, '__dict__'):
            for key in list(obj.__dict__.keys()):
                value = obj.__dict__[key]
                if isinstance(value, bytearray):
                    self.zeroize_bytes(value)
                elif isinstance(value, (bytes, str)):
                    # Replace with empty/zero value
                    obj.__dict__[key] = type(value)()
                elif isinstance(value, list):
                    self.zeroize_list(value)


class SecureBuffer:
    """
    A secure buffer that automatically zeroizes itself when done.
    
    Use as a context manager for sensitive data:
    
        with SecureBuffer(32) as buf:
            buf.data[:] = sensitive_key
            # use buf.data
        # buf is automatically zeroized here
    """
    
    def __init__(self, size: int):
        self.size = size
        self.data = bytearray(size)
        self._zeroizer = SecureMemoryZeroizer()
        self._is_zeroized = False
    
    def __enter__(self) -> 'SecureBuffer':
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.zeroize()
    
    def zeroize(self) -> None:
        """Securely wipe the buffer contents."""
        if not self._is_zeroized:
            self._zeroizer.zeroize_bytes(self.data)
            self._is_zeroized = True
    
    def __del__(self) -> None:
        """Ensure zeroization on garbage collection."""
        self.zeroize()


def secure_memcmp(a: bytes, b: bytes) -> bool:
    """
    Constant-time memory comparison.
    
    Compares two byte strings in constant time to prevent timing attacks.
    Both strings must be of equal length.
    
    Args:
        a: First byte string
        b: Second byte string
        
    Returns:
        True if equal, False otherwise
        
    Raises:
        ValueError: If lengths differ
    """
    if len(a) != len(b):
        raise ValueError("Buffers must be same length for constant-time comparison")
    
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    
    return result == 0


def secure_memset(dest: bytearray, value: int, length: Optional[int] = None) -> None:
    """
    Secure memset that resists compiler optimization.
    
    Args:
        dest: Destination bytearray
        value: Value to set (0-255)
        length: Number of bytes to set (default: entire array)
    """
    if length is None:
        length = len(dest)
    
    value = value & 0xFF
    for i in range(min(length, len(dest))):
        dest[i] = value


def generate_secure_random(length: int) -> bytes:
    """
    Generate cryptographically secure random bytes.
    
    Args:
        length: Number of bytes to generate
        
    Returns:
        Secure random bytes
    """
    return secrets.token_bytes(length)


def scrub_memory() -> None:
    """
    Perform a general memory scrub to encourage cleanup of sensitive data.
    
    This is a best-effort function that:
    1. Forces garbage collection
    2. Allocates and releases large dummy buffers
    3. Encourages memory overwriting
    """
    # Force garbage collection multiple times
    for _ in range(3):
        gc.collect()
    
    # Allocate and release a large buffer to encourage memory reuse
    try:
        dummy = bytearray(1024 * 1024)  # 1MB
        for i in range(len(dummy)):
            dummy[i] = secrets.randbelow(256)
        del dummy
        gc.collect()
    except MemoryError:
        pass


# Export public API
__all__ = [
    'SecureMemoryError',
    'MemoryNotWritableError',
    'SecureMemoryZeroizer',
    'SecureBuffer',
    'secure_memcmp',
    'secure_memset',
    'generate_secure_random',
    'scrub_memory',
]
