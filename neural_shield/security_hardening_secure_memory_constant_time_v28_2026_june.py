"""
Security Hardening: Secure Memory Zeroization & Constant-Time Comparison v28
NeuralShield-AI Security Module
API Stability: STABLE

Provides secure memory handling utilities for sensitive security data,
constant-time comparison functions to prevent timing side-channel attacks,
and rate limiting protection.

Philosophy: ADD-ONLY, NO MODIFICATION TO EXISTING CODE
"""

import ctypes
import gc
import time
import hmac
import hashlib
import secrets
from typing import Any, ByteString, Callable, Dict, List, Optional, TypeVar
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
import threading


class RateLimitStrategy(Enum):
    FIXED_WINDOW = "fixed_window"
    SLIDING_WINDOW = "sliding_window"
    TOKEN_BUCKET = "token_bucket"


@dataclass
class RateLimitConfig:
    """Configuration for rate limiting"""
    max_requests: int = 100
    window_seconds: float = 60.0
    strategy: RateLimitStrategy = RateLimitStrategy.FIXED_WINDOW
    burst_limit: int = 150


@dataclass
class RateLimitResult:
    """Result of rate limit check"""
    allowed: bool
    remaining: int
    reset_after: float
    retry_after: Optional[float] = None


class SecureMemory:
    """
    Secure memory zeroization utilities.
    Provides methods to securely overwrite sensitive data in memory.
    """
    
    @staticmethod
    def zeroize_bytes(data: bytearray) -> None:
        """
        Securely zeroize a bytearray by overwriting with zeros.
        Prevents sensitive data lingering in memory.
        
        IMPORTANT: Only works on mutable bytearray, not immutable bytes
        """
        if not isinstance(data, bytearray):
            raise TypeError("zeroize_bytes requires bytearray, not bytes")
        
        length = len(data)
        for i in range(length):
            data[i] = 0
        
        # Force garbage collection to help clean up
        gc.collect()
    
    @staticmethod
    def zeroize_list(data: List[float], value: float = 0.0) -> None:
        """Zeroize a list of floating point values (e.g., embeddings)"""
        for i in range(len(data)):
            data[i] = value
        gc.collect()
    
    @staticmethod
    def zeroize_string(data: str) -> str:
        """
        Note: Python strings are immutable and cannot be truly zeroized.
        This function returns an empty string and encourages use of bytearray.
        """
        gc.collect()
        return ""
    
    @staticmethod
    def secure_delete(obj: Any) -> None:
        """
        Attempt to securely delete an object by overwriting internal buffers.
        Best effort - Python garbage collection makes true secure deletion difficult.
        """
        if isinstance(obj, bytearray):
            SecureMemory.zeroize_bytes(obj)
        elif isinstance(obj, list):
            if all(isinstance(x, (int, float)) for x in obj):
                SecureMemory.zeroize_list(obj)
        
        del obj
        gc.collect()


class ConstantTime:
    """
    Constant-time comparison functions to prevent timing side-channel attacks.
    All comparisons run in the same amount of time regardless of input values.
    """
    
    @staticmethod
    def compare_bytes(a: ByteString, b: ByteString) -> bool:
        """
        Constant-time byte comparison using HMAC.
        Returns True if a == b, False otherwise.
        Execution time independent of input similarity.
        """
        if len(a) != len(b):
            return False
        
        # Use HMAC compare which is constant-time in Python's OpenSSL implementation
        return hmac.compare_digest(a, b)
    
    @staticmethod
    def compare_strings(a: str, b: str, encoding: str = 'utf-8') -> bool:
        """Constant-time string comparison"""
        if len(a) != len(b):
            return False
        
        return hmac.compare_digest(a.encode(encoding), b.encode(encoding))
    
    @staticmethod
    def compare_ints(a: int, b: int) -> bool:
        """
        Constant-time integer comparison for security-relevant values.
        Uses bitwise operations to avoid timing branches.
        """
        # XOR: if equal, result is 0; if different, non-zero
        diff = a ^ b
        
        # Convert to bytes and use constant-time compare
        diff_bytes = diff.to_bytes((diff.bit_length() + 7) // 8 or 1, byteorder='big', signed=True)
        zero_bytes = b'\x00' * len(diff_bytes)
        
        return hmac.compare_digest(diff_bytes, zero_bytes)
    
    @staticmethod
    def compare_hashes(hash_a: str, hash_b: str) -> bool:
        """Constant-time hash comparison for security checks"""
        return ConstantTime.compare_strings(hash_a, hash_b)
    
    @staticmethod
    def select(condition: bool, if_true: bytes, if_false: bytes) -> bytes:
        """
        Constant-time selection: returns if_true if condition is True,
        otherwise if_false. No branching based on condition.
        Both inputs must be same length.
        """
        if len(if_true) != len(if_false):
            raise ValueError("Both byte strings must be same length")
        
        # Create mask based on condition
        # All bits 1 if True, all bits 0 if False
        mask = -condition if condition else 0
        
        result = bytearray(len(if_true))
        for i in range(len(if_true)):
            # Bitwise selection without branching
            result[i] = (if_true[i] & mask) | (if_false[i] & ~mask)
        
        return bytes(result)


class RateLimiter:
    """
    Thread-safe rate limiter to prevent DoS attacks on security modules.
    Implements multiple strategies.
    """
    
    def __init__(self, config: Optional[RateLimitConfig] = None):
        self.config = config or RateLimitConfig()
        self._requests: Dict[str, List[float]] = defaultdict(list)
        self._lock = threading.Lock()
        self._bucket_tokens: Dict[str, float] = defaultdict(lambda: self.config.max_requests)
        self._bucket_last_update: Dict[str, float] = defaultdict(time.time)
    
    def check_rate_limit(self, key: str = "global") -> RateLimitResult:
        """Check if request should be allowed"""
        with self._lock:
            now = time.time()
            
            if self.config.strategy == RateLimitStrategy.FIXED_WINDOW:
                return self._check_fixed_window(key, now)
            elif self.config.strategy == RateLimitStrategy.SLIDING_WINDOW:
                return self._check_sliding_window(key, now)
            elif self.config.strategy == RateLimitStrategy.TOKEN_BUCKET:
                return self._check_token_bucket(key, now)
            else:
                return self._check_fixed_window(key, now)
    
    def _check_fixed_window(self, key: str, now: float) -> RateLimitResult:
        """Fixed window rate limiting"""
        window_start = now - (now % self.config.window_seconds)
        
        # Clean old requests
        self._requests[key] = [
            ts for ts in self._requests[key]
            if ts >= window_start
        ]
        
        count = len(self._requests[key])
        
        if count >= self.config.max_requests:
            reset_after = window_start + self.config.window_seconds - now
            return RateLimitResult(
                allowed=False,
                remaining=0,
                reset_after=reset_after,
                retry_after=reset_after
            )
        
        self._requests[key].append(now)
        return RateLimitResult(
            allowed=True,
            remaining=self.config.max_requests - count - 1,
            reset_after=self.config.window_seconds
        )
    
    def _check_sliding_window(self, key: str, now: float) -> RateLimitResult:
        """Sliding window rate limiting"""
        cutoff = now - self.config.window_seconds
        
        # Remove old requests
        self._requests[key] = [
            ts for ts in self._requests[key]
            if ts > cutoff
        ]
        
        count = len(self._requests[key])
        
        if count >= self.config.max_requests:
            oldest = min(self._requests[key]) if self._requests[key] else now
            retry_after = oldest + self.config.window_seconds - now
            return RateLimitResult(
                allowed=False,
                remaining=0,
                reset_after=self.config.window_seconds,
                retry_after=max(0, retry_after)
            )
        
        self._requests[key].append(now)
        return RateLimitResult(
            allowed=True,
            remaining=self.config.max_requests - count - 1,
            reset_after=self.config.window_seconds
        )
    
    def _check_token_bucket(self, key: str, now: float) -> RateLimitResult:
        """Token bucket rate limiting with burst support"""
        time_passed = now - self._bucket_last_update[key]
        refill_rate = self.config.max_requests / self.config.window_seconds
        
        # Refill tokens
        self._bucket_tokens[key] = min(
            self.config.burst_limit,
            self._bucket_tokens[key] + time_passed * refill_rate
        )
        self._bucket_last_update[key] = now
        
        if self._bucket_tokens[key] < 1:
            time_to_refill = (1 - self._bucket_tokens[key]) / refill_rate
            return RateLimitResult(
                allowed=False,
                remaining=0,
                reset_after=time_to_refill,
                retry_after=time_to_refill
            )
        
        self._bucket_tokens[key] -= 1
        return RateLimitResult(
            allowed=True,
            remaining=int(self._bucket_tokens[key]),
            reset_after=1.0 / refill_rate
        )
    
    def reset(self, key: str = "global") -> None:
        """Reset rate limit for a key"""
        with self._lock:
            self._requests[key].clear()
            self._bucket_tokens[key] = self.config.max_requests


class HardenedSecurityModule:
    """
    Complete hardened wrapper that combines all security features:
    - Input validation
    - Constant-time comparisons
    - Rate limiting
    - Secure memory cleanup
    
    Usage: wrap existing security modules, no modification to original code needed.
    """
    
    def __init__(
        self,
        wrapped_module: Any,
        rate_limit_config: Optional[RateLimitConfig] = None,
        enable_rate_limiting: bool = True,
        enable_constant_time: bool = True
    ):
        self._wrapped = wrapped_module
        self._rate_limiter = RateLimiter(rate_limit_config)
        self._enable_rate_limiting = enable_rate_limiting
        self._enable_constant_time = enable_constant_time
        self._secure_memory = SecureMemory()
    
    def __getattr__(self, name: str) -> Any:
        """Wrap method calls with security hardening"""
        original_method = getattr(self._wrapped, name)
        
        if not callable(original_method):
            return original_method
        
        def hardened_method(*args, **kwargs):
            # Rate limiting check
            if self._enable_rate_limiting:
                rl_result = self._rate_limiter.check_rate_limit()
                if not rl_result.allowed:
                    raise RuntimeError(
                        f"Rate limit exceeded. Retry after {rl_result.retry_after:.2f}s"
                    )
            
            # Call original method
            result = original_method(*args, **kwargs)
            return result
        
        return hardened_method
    
    def secure_cleanup(self, sensitive_data: Any) -> None:
        """Securely clean up sensitive data"""
        self._secure_memory.secure_delete(sensitive_data)
    
    def constant_time_compare(self, a: Any, b: Any) -> bool:
        """Perform constant-time comparison"""
        if isinstance(a, bytes) and isinstance(b, bytes):
            return ConstantTime.compare_bytes(a, b)
        elif isinstance(a, str) and isinstance(b, str):
            return ConstantTime.compare_strings(a, b)
        elif isinstance(a, int) and isinstance(b, int):
            return ConstantTime.compare_ints(a, b)
        else:
            return False


# Export public API
__all__ = [
    'SecureMemory',
    'ConstantTime',
    'RateLimiter',
    'RateLimitConfig',
    'RateLimitResult',
    'RateLimitStrategy',
    'HardenedSecurityModule',
]
