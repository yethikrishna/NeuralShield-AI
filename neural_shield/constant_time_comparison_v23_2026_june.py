"""
Constant-Time Comparison Utilities v23 - NeuralShield-AI
Security Hardening - Dimension B

Provides constant-time comparison functions to prevent timing attacks.
All operations run in O(n) time regardless of input values.

API Stability: STABLE
Backward Compatible: YES
"""

import hmac
import secrets
from typing import Any, List, Optional, Sequence, Union


class ConstantTimeError(Exception):
    """Base exception for constant-time operations."""
    pass


class ConstantTimeComparer:
    """
    Collection of constant-time comparison utilities.
    
    All methods execute in constant time for inputs of equal length,
    preventing timing side-channel attacks.
    """
    
    @staticmethod
    def compare_bytes(a: bytes, b: bytes) -> bool:
        """
        Compare two byte strings in constant time.
        
        Args:
            a: First byte string
            b: Second byte string
            
        Returns:
            True if equal, False otherwise
        """
        if len(a) != len(b):
            return False
        return hmac.compare_digest(a, b)
    
    @staticmethod
    def compare_strings(a: str, b: str, encoding: str = 'utf-8') -> bool:
        """
        Compare two strings in constant time.
        
        Args:
            a: First string
            b: Second string
            encoding: String encoding for conversion to bytes
            
        Returns:
            True if equal, False otherwise
        """
        if len(a) != len(b):
            return False
        return hmac.compare_digest(a.encode(encoding), b.encode(encoding))
    
    @staticmethod
    def compare_ints(a: int, b: int, bits: int = 64) -> bool:
        """
        Compare two integers in constant time.
        
        Args:
            a: First integer
            b: Second integer
            bits: Maximum number of bits to compare
            
        Returns:
            True if equal, False otherwise
        """
        result = 0
        for i in range(bits):
            result |= ((a >> i) & 1) ^ ((b >> i) & 1)
        return result == 0
    
    @staticmethod
    def is_equal_length(a: Sequence, b: Sequence) -> bool:
        """
        Check if two sequences have equal length in constant-ish time.
        
        Note: True constant-time length check is difficult in Python.
        This provides best-effort protection.
        
        Args:
            a: First sequence
            b: Second sequence
            
        Returns:
            True if lengths equal
        """
        len_a = len(a)
        len_b = len(b)
        
        # XOR the lengths - non-zero result means different
        diff = len_a ^ len_b
        
        # Propagate any set bit to all bits
        diff |= diff >> 1
        diff |= diff >> 2
        diff |= diff >> 4
        diff |= diff >> 8
        diff |= diff >> 16
        
        return diff == 0
    
    @staticmethod
    def select(condition: bool, if_true: Any, if_false: Any) -> Any:
        """
        Constant-time conditional selection.
        
        Returns if_true when condition is True, if_false otherwise.
        Execution time is the same regardless of condition.
        
        Args:
            condition: Boolean condition
            if_true: Value if condition is True
            if_false: Value if condition is False
            
        Returns:
            Selected value
        """
        # Convert condition to 0 or 1
        mask = int(bool(condition))
        
        # Create all-1s mask if True, all-0s if False
        mask = -mask  # Two's complement: 0 -> 0, 1 -> -1 (all bits 1)
        
        # Return appropriate value
        # Note: This works for integers, for other types we branch
        if isinstance(if_true, int) and isinstance(if_false, int):
            return (if_true & mask) | (if_false & ~mask)
        
        # Fallback for non-integer types (not perfectly constant time)
        return if_true if condition else if_false
    
    @staticmethod
    def less_than(a: int, b: int, bits: int = 64) -> bool:
        """
        Constant-time a < b comparison for integers.
        
        Args:
            a: First integer
            b: Second integer
            bits: Number of bits to consider
            
        Returns:
            True if a < b, False otherwise
        """
        # Compute a - b. If result is negative, a < b.
        # In two's complement, negative numbers have the MSB set.
        diff = a - b
        # Check if sign bit is set (negative)
        return (diff >> (bits - 1)) & 1 == 1
    
    @staticmethod
    def greater_than(a: int, b: int, bits: int = 64) -> bool:
        """
        Constant-time a > b comparison for integers.
        
        Args:
            a: First integer
            b: Second integer
            bits: Number of bits to consider
            
        Returns:
            True if a > b, False otherwise
        """
        return ConstantTimeComparer.less_than(b, a, bits)


class ConstantTimeArray:
    """
    Array operations that execute in constant time.
    """
    
    @staticmethod
    def lookup(table: List[bytes], index: int) -> bytes:
        """
        Constant-time table lookup.
        
        Returns table[index] without leaking index through timing.
        
        Args:
            table: List of byte strings (all same length)
            index: Index to look up
            
        Returns:
            table[index]
        """
        if not table:
            raise ValueError("Empty table")
        
        entry_len = len(table[0])
        result = bytearray(entry_len)
        
        for i, entry in enumerate(table):
            mask = -int(i == index)  # All 1s if match, all 0s otherwise
            for j in range(entry_len):
                result[j] |= entry[j] & mask
        
        return bytes(result)
    
    @staticmethod
    def copy_if(dest: bytearray, src: bytes, condition: bool) -> None:
        """
        Copy src to dest only if condition is True, in constant time.
        
        Args:
            dest: Destination bytearray
            src: Source bytes
            condition: Whether to copy
        """
        mask = -int(bool(condition))
        
        for i in range(min(len(dest), len(src))):
            dest[i] = (dest[i] & ~mask) | (src[i] & mask)


class TimingAttackProtector:
    """
    Utilities to protect against timing attacks.
    """
    
    def __init__(self, jitter_range: tuple = (0.001, 0.010)):
        """
        Initialize timing attack protector.
        
        Args:
            jitter_range: (min, max) random delay in seconds
        """
        self.jitter_min, self.jitter_max = jitter_range
        self._operation_count = 0
    
    def random_delay(self) -> None:
        """
        Add a small random delay to make timing attacks harder.
        
        Note: This is a defense-in-depth measure. Always use constant-time
        comparisons as the primary defense.
        """
        import time
        delay = self.jitter_min + secrets.SystemRandom().random() * (
            self.jitter_max - self.jitter_min
        )
        time.sleep(delay)
    
    def normalize_execution_time(self, start_time: float, target_duration: float) -> None:
        """
        Ensure operation takes at least target_duration.
        
        Args:
            start_time: Operation start time (from time.time())
            target_duration: Minimum duration in seconds
        """
        import time
        elapsed = time.time() - start_time
        remaining = target_duration - elapsed
        if remaining > 0:
            time.sleep(remaining)
    
    def count_operation(self) -> None:
        """Count an operation for rate limiting."""
        self._operation_count += 1


def constant_time_all(conditions: List[bool]) -> bool:
    """
    Constant-time AND of all conditions.
    
    Evaluates all conditions even if one is False.
    
    Args:
        conditions: List of booleans
        
    Returns:
        True if all conditions are True
    """
    result = True
    for c in conditions:
        result = result and c  # Always evaluate c
    return result


def constant_time_any(conditions: List[bool]) -> bool:
    """
    Constant-time OR of all conditions.
    
    Evaluates all conditions even if one is True.
    
    Args:
        conditions: List of booleans
        
    Returns:
        True if any condition is True
    """
    result = False
    for c in conditions:
        result = result or c  # Always evaluate c
    return result


def secure_hash_compare(hash_a: bytes, hash_b: bytes) -> bool:
    """
    Securely compare two hash values in constant time.
    
    Args:
        hash_a: First hash
        hash_b: Second hash
        
    Returns:
        True if hashes match
    """
    return ConstantTimeComparer.compare_bytes(hash_a, hash_b)


def secure_password_compare(password_hash: bytes, attempt_hash: bytes) -> bool:
    """
    Secure password hash comparison.
    
    Args:
        password_hash: Stored password hash
        attempt_hash: Hash of password attempt
        
    Returns:
        True if match
    """
    return ConstantTimeComparer.compare_bytes(password_hash, attempt_hash)


# Export public API
__all__ = [
    'ConstantTimeError',
    'ConstantTimeComparer',
    'ConstantTimeArray',
    'TimingAttackProtector',
    'constant_time_all',
    'constant_time_any',
    'secure_hash_compare',
    'secure_password_compare',
]
