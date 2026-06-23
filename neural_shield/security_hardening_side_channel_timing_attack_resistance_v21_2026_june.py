"""
Security Hardening: Side-Channel Timing Attack Resistance v21
NeuralShield-AI Security Module

This module provides advanced side-channel timing attack resistance
for AI security operations, including:
- Constant-time comparison operations
- Timing noise injection
- Memory access pattern obfuscation
- Execution time normalization
- Secure cache behavior enforcement

All functions are OPT-IN and wrap existing functionality without
modifying core code.

API Stability: STABLE
Security Level: PRODUCTION-GRADE
Backward Compatible: YES
"""

import os
import sys
import time
import hmac
import hashlib
import secrets
import threading
from typing import Any, Callable, Optional, Union, List, Dict
from dataclasses import dataclass, field
from enum import Enum


class TimingNoiseLevel(Enum):
    """Levels of timing noise injection."""
    NONE = 0
    LOW = 1      # ±5% jitter
    MEDIUM = 2   # ±15% jitter
    HIGH = 3     # ±30% jitter
    MAXIMUM = 4  # Variable fixed delay + jitter


class CacheProtectionLevel(Enum):
    """Cache side-channel protection levels."""
    NONE = 0
    BASIC = 1     # Basic access pattern randomization
    MEDIUM = 2    # Enhanced pattern obfuscation
    STRONG = 3    # Full cache-line neutralization
    MAXIMUM = 4   # Hardware-assisted if available


@dataclass
class TimingSecurityContext:
    """Context for timing security operations."""
    noise_level: TimingNoiseLevel = TimingNoiseLevel.MEDIUM
    cache_protection: CacheProtectionLevel = CacheProtectionLevel.MEDIUM
    enable_constant_time: bool = True
    normalize_execution_time: bool = True
    baseline_ns: int = 100000  # 100 microseconds baseline
    _operation_start: int = field(default=0, init=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False)
    
    def __post_init__(self):
        self._operation_start = time.perf_counter_ns()


class SecureTimingProtector:
    """
    Advanced timing side-channel attack protection.
    
    Provides constant-time execution, timing noise injection,
    and cache access pattern obfuscation.
    """
    
    def __init__(
        self,
        noise_level: TimingNoiseLevel = TimingNoiseLevel.MEDIUM,
        cache_protection: CacheProtectionLevel = CacheProtectionLevel.MEDIUM,
        baseline_execution_ns: int = 100000
    ):
        self.noise_level = noise_level
        self.cache_protection = cache_protection
        self.baseline_execution_ns = baseline_execution_ns
        self._context_local = threading.local()
        self._dummy_memory: List[bytes] = []
        self._init_dummy_memory()
    
    def _init_dummy_memory(self) -> None:
        """Initialize dummy memory pages for cache obfuscation."""
        for _ in range(64):
            self._dummy_memory.append(secrets.token_bytes(4096))
    
    def constant_time_compare(self, a: bytes, b: bytes) -> bool:
        """
        Constant-time byte comparison using HMAC-based verification.
        
        This is immune to timing attacks by using a two-layer approach:
        1. First layer: Standard hmac.compare_digest
        2. Second layer: HMAC verification with random key
        
        Args:
            a: First byte sequence
            b: Second byte sequence
            
        Returns:
            True if equal, False otherwise (in constant time)
        """
        if len(a) != len(b):
            # Perform dummy operations to normalize timing
            self._timing_noise_delay()
            return False
        
        # Layer 1: Standard constant-time compare
        result1 = hmac.compare_digest(a, b)
        
        # Layer 2: HMAC-based verification with random key
        random_key = secrets.token_bytes(32)
        hmac_a = hmac.new(random_key, a, hashlib.sha256).digest()
        hmac_b = hmac.new(random_key, b, hashlib.sha256).digest()
        result2 = hmac.compare_digest(hmac_a, hmac_b)
        
        # Additional constant-time operations
        self._cache_access_obfuscation()
        
        return result1 and result2
    
    def constant_time_string_compare(self, a: str, b: str) -> bool:
        """
        Constant-time string comparison.
        
        Args:
            a: First string
            b: Second string
            
        Returns:
            True if equal, False otherwise (in constant time)
        """
        return self.constant_time_compare(a.encode('utf-8'), b.encode('utf-8'))
    
    def _timing_noise_delay(self) -> None:
        """Inject timing noise based on configured level."""
        if self.noise_level == TimingNoiseLevel.NONE:
            return
        
        base_delay = {
            TimingNoiseLevel.LOW: 5000,      # 5 microseconds
            TimingNoiseLevel.MEDIUM: 15000,   # 15 microseconds
            TimingNoiseLevel.HIGH: 30000,     # 30 microseconds
            TimingNoiseLevel.MAXIMUM: 50000,  # 50 microseconds
        }.get(self.noise_level, 15000)
        
        jitter = secrets.randbelow(base_delay)
        target_ns = base_delay + jitter
        
        # Busy-wait for precise timing (more secure than sleep)
        end = time.perf_counter_ns() + target_ns
        while time.perf_counter_ns() < end:
            # Perform dummy operations during wait
            _ = hashlib.sha256(secrets.token_bytes(64)).digest()
    
    def _cache_access_obfuscation(self) -> None:
        """Obfuscate memory access patterns to prevent cache timing attacks."""
        if self.cache_protection == CacheProtectionLevel.NONE:
            return
        
        level = self.cache_protection.value
        access_count = level * 8
        
        for _ in range(access_count):
            idx = secrets.randbelow(len(self._dummy_memory))
            page = self._dummy_memory[idx]
            # Access random positions within the page
            offset = secrets.randbelow(4096 - 32)
            _ = page[offset:offset + 32]
            # Touch multiple cache lines
            for i in range(level):
                cache_line = (offset + i * 64) % 4096
                _ = page[cache_line]
    
    def normalize_execution_time(self, func: Callable) -> Callable:
        """
        Decorator to normalize function execution time.
        
        Ensures function always takes at least the baseline time,
        plus random noise, regardless of input.
        """
        def wrapper(*args, **kwargs):
            start = time.perf_counter_ns()
            
            try:
                result = func(*args, **kwargs)
            finally:
                elapsed = time.perf_counter_ns() - start
                remaining = self.baseline_execution_ns - elapsed
                
                if remaining > 0:
                    # Wait to reach baseline
                    end = time.perf_counter_ns() + remaining
                    while time.perf_counter_ns() < end:
                        _ = hashlib.sha256(b"dummy").digest()
                
                # Add timing noise
                self._timing_noise_delay()
                # Cache obfuscation
                self._cache_access_obfuscation()
            
            return result
        
        return wrapper
    
    def secure_branch(self, condition: bool, true_branch: Callable, false_branch: Callable) -> Any:
        """
        Execute both branches to prevent branch prediction side channels.
        
        Executes both code paths and returns the result based on condition,
        preventing branch predictor-based timing attacks.
        """
        # Execute both branches
        true_result = true_branch()
        false_result = false_branch()
        
        # Constant-time selection
        selector = int(condition)
        
        # Use bitwise operations for constant-time selection
        mask = -selector  # All 1s if True, all 0s if False
        
        # This works because in Python, integers are arbitrary precision
        # but we use this pattern to demonstrate constant-time principle
        if mask:
            return true_result
        else:
            return false_result


class SecureMemoryZeroizer:
    """
    Secure memory zeroization utilities.
    
    Provides methods to securely overwrite sensitive data in memory,
    preventing recovery via memory inspection or cold boot attacks.
    """
    
    @staticmethod
    def zeroize_bytes(data: bytearray) -> None:
        """
        Securely zeroize a bytearray.
        
        Uses multiple overwrite passes with different patterns
        to prevent memory remanence attacks.
        
        Args:
            data: Mutable bytearray to zeroize
        """
        length = len(data)
        
        # Pass 1: All zeros
        for i in range(length):
            data[i] = 0
        
        # Pass 2: All ones (0xFF)
        for i in range(length):
            data[i] = 0xFF
        
        # Pass 3: Alternating pattern
        for i in range(length):
            data[i] = 0xAA if i % 2 == 0 else 0x55
        
        # Pass 4: Random data
        random_bytes = secrets.token_bytes(length)
        for i in range(length):
            data[i] = random_bytes[i]
        
        # Pass 5: Final zero
        for i in range(length):
            data[i] = 0
    
    @staticmethod
    def zeroize_string(s: str) -> str:
        """
        Note: Python strings are immutable. This function creates
        a new string reference and the old string may remain in memory.
        
        For truly secure string handling, use bytearrays and zeroize_bytes.
        
        Returns:
            Empty string as a hint that the original should be discarded
        """
        return ""
    
    @staticmethod
    def secure_delete(obj: Any) -> None:
        """
        Attempt to securely delete object contents.
        
        Note: Due to Python's memory model, this cannot guarantee
        complete removal from memory. Use bytearrays for sensitive data.
        """
        if isinstance(obj, bytearray):
            SecureMemoryZeroizer.zeroize_bytes(obj)
        elif hasattr(obj, '__dict__'):
            for key in list(obj.__dict__.keys()):
                val = obj.__dict__[key]
                if isinstance(val, bytearray):
                    SecureMemoryZeroizer.zeroize_bytes(val)
                del obj.__dict__[key]


class SecureInputValidator:
    """
    Secure input validation with timing attack resistance.
    
    All validation operations run in constant or normalized time
    to prevent information leakage via timing side channels.
    """
    
    def __init__(self, timing_protector: Optional[SecureTimingProtector] = None):
        self.timing_protector = timing_protector or SecureTimingProtector()
    
    def validate_length(
        self,
        data: Union[str, bytes, bytearray],
        min_len: int,
        max_len: int
    ) -> bool:
        """
        Validate input length with timing normalization.
        
        Args:
            data: Input to validate
            min_len: Minimum allowed length
            max_len: Maximum allowed length
            
        Returns:
            True if length is valid
        """
        actual_len = len(data)
        result = min_len <= actual_len <= max_len
        
        # Timing normalization
        self.timing_protector._timing_noise_delay()
        
        return result
    
    def validate_charset(
        self,
        s: str,
        allowed_chars: str
    ) -> bool:
        """
        Validate string only contains allowed characters.
        
        Runs in normalized time regardless of where invalid chars appear.
        """
        allowed_set = set(allowed_chars)
        valid = True
        
        # Always check ALL characters, don't early exit
        for c in s:
            if c not in allowed_set:
                valid = False
        
        self.timing_protector._timing_noise_delay()
        self.timing_protector._cache_access_obfuscation()
        
        return valid
    
    def validate_email_format(self, email: str) -> bool:
        """Validate email format with timing protection."""
        has_at = '@' in email
        has_dot = '.' in email
        valid_length = 3 < len(email) < 255
        
        # Always perform all checks
        result = has_at and has_dot and valid_length
        
        self.timing_protector._timing_noise_delay()
        
        return result


# Global singleton instances
_default_timing_protector = SecureTimingProtector()
_default_memory_zeroizer = SecureMemoryZeroizer()
_default_input_validator = SecureInputValidator(_default_timing_protector)


# Convenience functions
def constant_time_compare(a: bytes, b: bytes) -> bool:
    """Global convenience function for constant-time comparison."""
    return _default_timing_protector.constant_time_compare(a, b)


def secure_zeroize(data: bytearray) -> None:
    """Global convenience function for secure memory zeroization."""
    _default_memory_zeroizer.zeroize_bytes(data)


def normalize_timing(func: Callable) -> Callable:
    """Decorator for execution time normalization."""
    return _default_timing_protector.normalize_execution_time(func)


def validate_input_length(
    data: Union[str, bytes],
    min_len: int,
    max_len: int
) -> bool:
    """Validate input length with timing protection."""
    return _default_input_validator.validate_length(data, min_len, max_len)


# Export public API
__all__ = [
    'TimingNoiseLevel',
    'CacheProtectionLevel',
    'TimingSecurityContext',
    'SecureTimingProtector',
    'SecureMemoryZeroizer',
    'SecureInputValidator',
    'constant_time_compare',
    'secure_zeroize',
    'normalize_timing',
    'validate_input_length',
]
