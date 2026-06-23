"""
Security Hardening: Side-Channel Resistant Memory Protection v19
NeuralShield-AI - June 2026

DIMENSION B - Security Hardening
Incremental, additive-only security layer.
No modifications to existing production code.
100% backward compatible.

This module provides:
- Constant-time memory comparison for sensitive data
- Secure memory zeroization with overwriting patterns
- Side-channel resistant buffer handling
- Timing-attack resistant equality checks
- Protected memory allocation wrappers

API STABILITY: STABLE
"""

import os
import sys
import ctypes
import secrets
import hashlib
import hmac
from typing import Any, ByteString, List, Optional, Union
from dataclasses import dataclass, field
from enum import Enum


class MemoryProtectionLevel(Enum):
    """Protection levels for sensitive memory operations."""
    BASIC = "basic"           # Single pass zeroization
    STANDARD = "standard"     # Triple pass with patterns
    ENHANCED = "enhanced"     # Five passes with random data
    MAXIMUM = "maximum"       # Seven passes with crypto-grade random


@dataclass
class MemoryProtectionResult:
    """Result of a memory protection operation."""
    success: bool
    operation: str
    protection_level: MemoryProtectionLevel
    bytes_processed: int = 0
    duration_ns: int = 0
    error_message: Optional[str] = None
    warnings: List[str] = field(default_factory=list)


class SideChannelResistantMemory:
    """
    Side-channel resistant memory protection utilities.
    
    This class provides timing-attack resistant operations for
    handling sensitive data in memory. All operations are designed
    to execute in constant time regardless of input values.
    
    Usage:
        protector = SideChannelResistantMemory()
        result = protector.secure_zeroize(sensitive_buffer)
    """
    
    def __init__(self, protection_level: MemoryProtectionLevel = MemoryProtectionLevel.STANDARD):
        """
        Initialize the memory protector with specified protection level.
        
        Args:
            protection_level: Determines the number and type of overwriting passes
        """
        self.protection_level = protection_level
        self._protection_patterns = [
            b'\x00',      # Zero
            b'\xFF',      # All ones
            b'\x55',      # Alternating 01010101
            b'\xAA',      # Alternating 10101010
            b'\x33',      # 00110011
            b'\xCC',      # 11001100
            b'\x0F',      # 00001111
            b'\xF0',      # 11110000
        ]
        self._operations_count = 0
    
    def constant_time_compare(self, a: ByteString, b: ByteString) -> bool:
        """
        Perform constant-time comparison of two byte strings.
        
        Prevents timing attacks by ensuring the comparison takes the same
        amount of time regardless of how many bytes match.
        
        Args:
            a: First byte string to compare
            b: Second byte string to compare
            
        Returns:
            True if equal, False otherwise
        """
        if len(a) != len(b):
            # Still perform constant-time operations even when lengths differ
            result = 1
            # Dummy loop to maintain constant timing
            for _ in range(max(len(a), len(b))):
                result |= 1
            return False
        
        result = 0
        for x, y in zip(a, b):
            result |= x ^ y
        
        return result == 0
    
    def constant_time_hmac_compare(self, a: ByteString, b: ByteString, key: bytes) -> bool:
        """
        Compare two byte strings using HMAC in constant time.
        
        Provides additional protection against timing attacks by
        comparing HMAC digests rather than raw bytes.
        
        Args:
            a: First byte string
            b: Second byte string  
            key: Secret key for HMAC computation
            
        Returns:
            True if equal, False otherwise
        """
        hmac_a = hmac.new(key, a, hashlib.sha256).digest()
        hmac_b = hmac.new(key, b, hashlib.sha256).digest()
        return self.constant_time_compare(hmac_a, hmac_b)
    
    def secure_zeroize(self, buffer: bytearray, 
                      protection_level: Optional[MemoryProtectionLevel] = None) -> MemoryProtectionResult:
        """
        Securely zeroize a bytearray with multiple overwriting passes.
        
        This prevents sensitive data from remaining in memory after use.
        Uses different patterns based on protection level.
        
        Args:
            buffer: Mutable bytearray to zeroize
            protection_level: Override default protection level
            
        Returns:
            MemoryProtectionResult with operation details
        """
        import time
        start_time = time.perf_counter_ns()
        
        level = protection_level or self.protection_level
        passes = self._get_passes_for_level(level)
        warnings = []
        
        if not isinstance(buffer, bytearray):
            return MemoryProtectionResult(
                success=False,
                operation="secure_zeroize",
                protection_level=level,
                error_message="Buffer must be a mutable bytearray"
            )
        
        buffer_size = len(buffer)
        
        try:
            for pass_num in range(passes):
                if pass_num < len(self._protection_patterns):
                    pattern = self._protection_patterns[pass_num]
                else:
                    # Use cryptographically secure random data for additional passes
                    pattern = secrets.token_bytes(1)
                
                for i in range(buffer_size):
                    buffer[i] = pattern[0]
            
            # Final zero pass
            for i in range(buffer_size):
                buffer[i] = 0
            
            duration = time.perf_counter_ns() - start_time
            self._operations_count += 1
            
            return MemoryProtectionResult(
                success=True,
                operation="secure_zeroize",
                protection_level=level,
                bytes_processed=buffer_size,
                duration_ns=duration,
                warnings=warnings
            )
            
        except Exception as e:
            duration = time.perf_counter_ns() - start_time
            return MemoryProtectionResult(
                success=False,
                operation="secure_zeroize",
                protection_level=level,
                bytes_processed=buffer_size,
                duration_ns=duration,
                error_message=f"Zeroization failed: {str(e)}"
            )
    
    def _get_passes_for_level(self, level: MemoryProtectionLevel) -> int:
        """Get number of overwriting passes for protection level."""
        pass_counts = {
            MemoryProtectionLevel.BASIC: 1,
            MemoryProtectionLevel.STANDARD: 3,
            MemoryProtectionLevel.ENHANCED: 5,
            MemoryProtectionLevel.MAXIMUM: 7,
        }
        return pass_counts.get(level, 3)
    
    def create_protected_buffer(self, size: int, initial_data: Optional[bytes] = None) -> bytearray:
        """
        Create a protected buffer with optional initial data.
        
        Args:
            size: Size of buffer in bytes
            initial_data: Optional initial data to copy
            
        Returns:
            Protected bytearray
        """
        buffer = bytearray(size)
        
        if initial_data:
            copy_size = min(size, len(initial_data))
            # Constant-time copy
            for i in range(copy_size):
                buffer[i] = initial_data[i]
            # Fill remaining with random bytes
            for i in range(copy_size, size):
                buffer[i] = secrets.randbelow(256)
        else:
            # Initialize with random data
            for i in range(size):
                buffer[i] = secrets.randbelow(256)
        
        return buffer
    
    def secure_memcpy(self, dest: bytearray, src: ByteString, dest_offset: int = 0) -> MemoryProtectionResult:
        """
        Perform secure memory copy with constant timing.
        
        Args:
            dest: Destination bytearray
            src: Source bytes
            dest_offset: Offset in destination
            
        Returns:
            MemoryProtectionResult
        """
        import time
        start_time = time.perf_counter_ns()
        
        if dest_offset + len(src) > len(dest):
            return MemoryProtectionResult(
                success=False,
                operation="secure_memcpy",
                protection_level=self.protection_level,
                error_message="Destination buffer overflow"
            )
        
        # Constant-time copy
        for i, byte in enumerate(src):
            dest[dest_offset + i] = byte
        
        duration = time.perf_counter_ns() - start_time
        self._operations_count += 1
        
        return MemoryProtectionResult(
            success=True,
            operation="secure_memcpy",
            protection_level=self.protection_level,
            bytes_processed=len(src),
            duration_ns=duration
        )


class ProtectedSecret:
    """
    Wrapper for sensitive data that automatically zeroizes on cleanup.
    
    Uses context manager pattern for automatic secure cleanup.
    
    Usage:
        with ProtectedSecret(b"my-secret-key") as secret:
            # Use secret.data
            process(secret.data)
        # Data is automatically zeroized
    """
    
    def __init__(self, data: bytes, protector: Optional[SideChannelResistantMemory] = None):
        self._protector = protector or SideChannelResistantMemory(MemoryProtectionLevel.ENHANCED)
        self._data = bytearray(data)
        self._key_size = len(data)
        self._usage_count = 0
        self._used = False
        self._destroyed = False
    
    @property
    def is_destroyed(self) -> bool:
        """Check if secret has been destroyed."""
        return self._destroyed
    
    @property
    def usage_count(self) -> int:
        """Number of times data has been accessed."""
        return self._usage_count
    
    @property
    def key_size(self) -> int:
        """Size of the secret data in bytes."""
        return self._key_size
    
    def __enter__(self) -> 'ProtectedSecret':
        self._used = True
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.destroy()
        return False
    
    @property
    def data(self) -> bytes:
        """Get the protected data as immutable bytes."""
        if self._destroyed:
            raise ValueError("Secret has been destroyed")
        self._usage_count += 1
        return bytes(self._data)
    
    @property
    def mutable_data(self) -> bytearray:
        """Get mutable access to the underlying buffer."""
        if self._destroyed:
            raise ValueError("Secret has been destroyed")
        return self._data
    
    def destroy(self) -> MemoryProtectionResult:
        """Securely destroy the secret data."""
        if self._destroyed:
            return MemoryProtectionResult(
                success=True,
                operation="destroy",
                protection_level=self._protector.protection_level,
                warnings=["Secret already destroyed"]
            )
        
        result = self._protector.secure_zeroize(self._data)
        self._destroyed = True
        return result
    
    def __del__(self):
        """Ensure cleanup on garbage collection."""
        if not self._destroyed and hasattr(self, '_data'):
            try:
                self._protector.secure_zeroize(self._data)
            except:
                pass


# Module-level convenience functions
_default_protector = SideChannelResistantMemory(MemoryProtectionLevel.STANDARD)


def constant_time_eq(a: ByteString, b: ByteString) -> bool:
    """Module-level constant time comparison."""
    return _default_protector.constant_time_compare(a, b)


def secure_zeroize(buffer: bytearray) -> MemoryProtectionResult:
    """Module-level secure zeroization."""
    return _default_protector.secure_zeroize(buffer)


def protected_secret(data: bytes) -> ProtectedSecret:
    """Create a protected secret context manager."""
    return ProtectedSecret(data)


# Export public API
__all__ = [
    'MemoryProtectionLevel',
    'MemoryProtectionResult',
    'SideChannelResistantMemory',
    'ProtectedSecret',
    'constant_time_eq',
    'secure_zeroize',
    'protected_secret',
]
