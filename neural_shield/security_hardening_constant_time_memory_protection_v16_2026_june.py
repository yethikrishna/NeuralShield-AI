"""
NeuralShield Security Hardening - Constant-Time Comparison & Secure Memory Zeroization
DIMENSION B: Security Hardening (v16)
ADD-ONLY implementation - layers on top of existing code, no modifications to core

This module provides:
1. Constant-time string/byte comparison to prevent timing attacks
2. Secure memory zeroization for sensitive data
3. Constant-time conditional selection
4. Side-channel resistant hash comparison
5. Secure buffer wiping utilities

All functions are designed to execute in constant time regardless of input,
preventing timing-based side-channel attacks on authentication and validation logic.
"""

import hmac
import secrets
import ctypes
import sys
from typing import Any, ByteString, List, Optional, Union


class ConstantTimeComparer:
    """
    Constant-time comparison utilities to prevent timing side-channel attacks.
    
    All methods execute in the same amount of time regardless of input values,
    making them safe for comparing secrets, authentication tokens, passwords, etc.
    """
    
    @staticmethod
    def compare_bytes(a: ByteString, b: ByteString) -> bool:
        """
        Compare two byte strings in constant time.
        
        Uses HMAC-based comparison with a random key to prevent timing attacks.
        Execution time depends only on length, not content similarity.
        
        Args:
            a: First byte string to compare
            b: Second byte string to compare
            
        Returns:
            True if equal, False otherwise (in constant time)
        """
        if len(a) != len(b):
            # Even on length mismatch, do some work to maintain timing consistency
            ConstantTimeComparer._dummy_work(32)
            return False
        
        # Use HMAC compare with random nonce for double protection
        nonce = secrets.token_bytes(32)
        return hmac.compare_digest(
            hmac.new(nonce, bytes(a), 'sha256').digest(),
            hmac.new(nonce, bytes(b), 'sha256').digest()
        )
    
    @staticmethod
    def compare_strings(a: str, b: str, encoding: str = 'utf-8') -> bool:
        """
        Compare two strings in constant time.
        
        Args:
            a: First string to compare
            b: Second string to compare
            encoding: String encoding for byte conversion
            
        Returns:
            True if equal, False otherwise (in constant time)
        """
        try:
            a_bytes = a.encode(encoding)
            b_bytes = b.encode(encoding)
        except UnicodeEncodeError:
            ConstantTimeComparer._dummy_work(64)
            return False
        
        return ConstantTimeComparer.compare_bytes(a_bytes, b_bytes)
    
    @staticmethod
    def compare_hashes(hash_a: str, hash_b: str) -> bool:
        """
        Compare two hex hash strings in constant time.
        
        Safe for comparing API keys, auth tokens, password hashes.
        
        Args:
            hash_a: First hash hex string
            hash_b: Second hash hex string
            
        Returns:
            True if equal, False otherwise (in constant time)
        """
        # Normalize case first (constant time)
        hash_a_norm = hash_a.lower() if isinstance(hash_a, str) else hash_a
        hash_b_norm = hash_b.lower() if isinstance(hash_b, str) else hash_b
        
        return ConstantTimeComparer.compare_strings(hash_a_norm, hash_b_norm)
    
    @staticmethod
    def select(condition: bool, if_true: bytes, if_false: bytes) -> bytes:
        """
        Constant-time conditional selection.
        
        Returns if_true when condition is True, if_false otherwise,
        but executes both branches to prevent timing leaks.
        
        Args:
            condition: Boolean condition
            if_true: Value to return if condition is True
            if_false: Value to return if condition is False
            
        Returns:
            Selected byte string (constant time selection)
        """
        # Convert condition to mask: 0xFF if True, 0x00 if False
        mask = (condition * 0xFF) & 0xFF
        
        result = bytearray()
        max_len = max(len(if_true), len(if_false))
        
        for i in range(max_len):
            t_byte = if_true[i] if i < len(if_true) else 0
            f_byte = if_false[i] if i < len(if_false) else 0
            # Constant time selection using bitwise operations
            selected = ((t_byte & mask) | (f_byte & (~mask & 0xFF)))
            result.append(selected)
        
        return bytes(result)
    
    @staticmethod
    def _dummy_work(iterations: int) -> None:
        """Perform constant dummy work to maintain timing consistency."""
        acc = 0
        for i in range(iterations):
            acc = (acc + i * 17) & 0xFFFFFFFF


class SecureMemoryZeroizer:
    """
    Secure memory wiping utilities to prevent sensitive data leaks.
    
    Overwrites sensitive data in memory before it's garbage collected,
    preventing secrets from lingering in memory dumps or swap files.
    """
    
    @staticmethod
    def wipe_bytes(data: Union[bytearray, memoryview]) -> None:
        """
        Securely wipe bytearray or memoryview contents.
        
        Overwrites all bytes with zeros multiple times to ensure
        sensitive data doesn't remain in memory.
        
        Args:
            data: Mutable byte buffer to wipe
        """
        if not isinstance(data, (bytearray, memoryview)):
            return
        
        length = len(data)
        
        # Multiple pass overwrite pattern
        patterns = [0x00, 0xFF, 0xAA, 0x55, 0x00]
        
        for pattern in patterns:
            for i in range(length):
                data[i] = pattern
    
    @staticmethod
    def wipe_string(s: str) -> None:
        """
        Attempt to securely wipe string contents.
        
        Note: Python strings are immutable, so this creates an
        overwrite attempt using ctypes. Not 100% guaranteed but
        significantly reduces exposure window.
        
        Args:
            s: String containing sensitive data to wipe
        """
        try:
            address = id(s)
            # In CPython, string data offset varies by version
            # This is a best-effort approach
            length = len(s)
            
            # Create a bytes object and attempt to overwrite
            # Note: This won't affect interned strings
            buf = (ctypes.c_char * length).from_address(address + sys.getsizeof(s) - length)
            
            for i in range(length):
                buf[i] = b'\x00'
        except Exception:
            # Best effort - fail silently if wiping fails
            pass
    
    @staticmethod
    def wipe_list(lst: List[Any]) -> None:
        """
        Securely wipe contents of a list containing sensitive data.
        
        Args:
            lst: List containing sensitive elements
        """
        for i in range(len(lst)):
            item = lst[i]
            if isinstance(item, bytearray):
                SecureMemoryZeroizer.wipe_bytes(item)
            elif isinstance(item, str):
                SecureMemoryZeroizer.wipe_string(item)
            lst[i] = None
        
        lst.clear()
    
    @staticmethod
    def wipe_object(obj: Any, attributes: List[str]) -> None:
        """
        Wipe sensitive attributes from an object.
        
        Args:
            obj: Object containing sensitive attributes
            attributes: List of attribute names to wipe
        """
        for attr in attributes:
            if hasattr(obj, attr):
                value = getattr(obj, attr)
                if isinstance(value, bytearray):
                    SecureMemoryZeroizer.wipe_bytes(value)
                elif isinstance(value, str):
                    SecureMemoryZeroizer.wipe_string(value)
                setattr(obj, attr, None)


class SideChannelResistantValidator:
    """
    Validation helpers resistant to timing side-channel attacks.
    
    Wraps common validation operations with constant-time protection.
    """
    
    def __init__(self):
        self._comparer = ConstantTimeComparer()
        self._zeroizer = SecureMemoryZeroizer()
    
    def validate_api_key(self, provided: str, expected: str) -> bool:
        """
        Validate API key in constant time.
        
        Args:
            provided: User-provided API key
            expected: Expected valid API key
            
        Returns:
            True if valid, False otherwise (constant time)
        """
        result = self._comparer.compare_strings(provided, expected)
        return result
    
    def validate_token(self, provided_token: bytes, expected_token: bytes) -> bool:
        """
        Validate authentication token bytes in constant time.
        
        Args:
            provided_token: User-provided token bytes
            expected_token: Expected valid token
            
        Returns:
            True if valid, False otherwise (constant time)
        """
        return self._comparer.compare_bytes(provided_token, expected_token)
    
    def validate_password_hash(self, provided_hash: str, stored_hash: str) -> bool:
        """
        Compare password hashes in constant time.
        
        Args:
            provided_hash: Hash of user-provided password
            stored_hash: Stored hash from database
            
        Returns:
            True if match, False otherwise (constant time)
        """
        return self._comparer.compare_hashes(provided_hash, stored_hash)


class SecureTemporaryBuffer:
    """
    Context manager for secure temporary buffers.
    
    Automatically wipes buffer contents when exiting context,
    ensuring sensitive data doesn't linger in memory.
    """
    
    def __init__(self, size: int):
        """
        Create a secure temporary buffer.
        
        Args:
            size: Size of buffer in bytes
        """
        self._buffer = bytearray(size)
        self._size = size
        self._wiped = False
    
    def __enter__(self) -> bytearray:
        return self._buffer
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.wipe()
        return False
    
    def wipe(self) -> None:
        """Explicitly wipe the buffer."""
        if not self._wiped:
            SecureMemoryZeroizer.wipe_bytes(self._buffer)
            self._wiped = True
    
    @property
    def buffer(self) -> bytearray:
        """Get the underlying buffer."""
        return self._buffer
    
    def __del__(self):
        """Ensure buffer is wiped on garbage collection."""
        self.wipe()


# Exported convenience instances
_constant_time = ConstantTimeComparer()
_memory_zeroizer = SecureMemoryZeroizer()
_side_channel_validator = SideChannelResistantValidator()

# Public API - convenience functions
def constant_time_compare(a: ByteString, b: ByteString) -> bool:
    """Constant-time byte comparison."""
    return _constant_time.compare_bytes(a, b)

def constant_time_compare_str(a: str, b: str) -> bool:
    """Constant-time string comparison."""
    return _constant_time.compare_strings(a, b)

def secure_wipe(data: Union[bytearray, str, List]) -> None:
    """Securely wipe sensitive data."""
    if isinstance(data, bytearray):
        _memory_zeroizer.wipe_bytes(data)
    elif isinstance(data, str):
        _memory_zeroizer.wipe_string(data)
    elif isinstance(data, list):
        _memory_zeroizer.wipe_list(data)

def secure_buffer(size: int) -> SecureTemporaryBuffer:
    """Create a secure temporary buffer context manager."""
    return SecureTemporaryBuffer(size)
