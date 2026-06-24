"""
Security Hardening - Comprehensive Protection Layer V24
DIMENSION B: Security Hardening

Incremental security layer that wraps existing functionality
with enhanced protection without modifying core code.

Features added in V24:
- Enhanced input validation wrappers with type-safe sanitization
- Advanced secure memory zeroization with overwrite patterns
- Constant-time comparison helpers for sensitive data
- Adaptive rate limiting with token bucket algorithm
- Side-channel attack resistance utilities
- DoS protection with request throttling

All instrumentation is OPT-IN and layered on top.
Happy path behavior is 100% preserved.
"""

import hmac
import hashlib
import secrets
import time
import threading
from typing import Any, Callable, Dict, List, Optional, TypeVar, Union, cast
from dataclasses import dataclass, field
from enum import Enum
import re


class SecurityLevel(Enum):
    """Security level enumeration for granular control."""
    MINIMAL = "minimal"
    STANDARD = "standard"
    STRICT = "strict"
    MAXIMUM = "maximum"


class OverwritePattern(Enum):
    """Memory overwrite patterns for secure zeroization."""
    ZEROS = b"\x00"
    ONES = b"\xFF"
    ALTERNATING = b"\x55"
    RANDOM = None


T = TypeVar('T')


@dataclass
class RateLimitConfig:
    """Configuration for rate limiting."""
    max_requests: int = 100
    window_seconds: int = 60
    burst_allowance: int = 20
    enabled: bool = True


@dataclass
class ValidationConfig:
    """Configuration for input validation."""
    max_length: int = 10000
    allow_special_chars: bool = True
    reject_patterns: List[str] = field(default_factory=list)
    security_level: SecurityLevel = SecurityLevel.STANDARD
    enabled: bool = True


@dataclass
class MemorySecurityConfig:
    """Configuration for memory security."""
    overwrite_passes: int = 3
    overwrite_patterns: List[OverwritePattern] = field(default_factory=lambda: [
        OverwritePattern.ZEROS,
        OverwritePattern.ONES,
        OverwritePattern.ALTERNATING
    ])
    enabled: bool = True


class ConstantTimeComparer:
    """
    Constant-time comparison utilities to prevent timing attacks.
    All operations run in fixed time regardless of input values.
    """

    @staticmethod
    def compare_bytes(a: bytes, b: bytes) -> bool:
        """
        Compare two byte strings in constant time.
        Returns True if equal, False otherwise.
        Time is constant based on the longer input.
        """
        return hmac.compare_digest(a, b)

    @staticmethod
    def compare_strings(a: str, b: str) -> bool:
        """
        Compare two strings in constant time.
        Prevents timing attacks on secret comparisons.
        """
        max_len = max(len(a), len(b))
        a_padded = a.ljust(max_len, '\x00').encode('utf-8')
        b_padded = b.ljust(max_len, '\x00').encode('utf-8')
        return hmac.compare_digest(a_padded, b_padded)

    @staticmethod
    def secure_hash_compare(hash_a: str, hash_b: str) -> bool:
        """
        Compare two hash strings in constant time.
        Use for password hash verification, API keys, etc.
        """
        return hmac.compare_digest(hash_a, hash_b)

    @staticmethod
    def arrays_equal_constant_time(arr1: List[int], arr2: List[int]) -> bool:
        """
        Compare two integer arrays in constant time.
        """
        if len(arr1) != len(arr2):
            return False
        
        result = 0
        for x, y in zip(arr1, arr2):
            result |= x ^ y
        
        return result == 0


class SecureMemoryZeroizer:
    """
    Secure memory zeroization utilities.
    Overwrites sensitive data in memory with multiple patterns
    to prevent memory forensic recovery.
    """

    def __init__(self, config: Optional[MemorySecurityConfig] = None):
        self.config = config or MemorySecurityConfig()

    def zeroize_bytearray(self, data: bytearray) -> None:
        """
        Securely zeroize a bytearray.
        Overwrites with multiple patterns to prevent recovery.
        """
        if not self.config.enabled:
            return

        length = len(data)
        patterns = self.config.overwrite_patterns
        
        for _ in range(self.config.overwrite_passes):
            for pattern in patterns:
                if pattern == OverwritePattern.RANDOM:
                    overwrite = secrets.token_bytes(length)
                else:
                    overwrite = pattern.value * length
                
                for i in range(length):
                    data[i] = overwrite[i]
        
        # Final zero pass
        for i in range(length):
            data[i] = 0

    def zeroize_bytes(self, data: bytes) -> bytes:
        """
        Create a zeroized version of bytes.
        Note: Python strings/bytes are immutable, so this returns zeros.
        """
        if not self.config.enabled:
            return data
        return b"\x00" * len(data)

    def zeroize_list(self, data: List[Any]) -> None:
        """
        Securely clear a list of sensitive data.
        """
        if not self.config.enabled:
            data.clear()
            return
        
        # Overwrite elements before clearing
        for i in range(len(data)):
            data[i] = None
        
        data.clear()

    def secure_delete_string(self, s: str) -> str:
        """
        Return a zeroized string of the same length.
        Note: Python strings are immutable, this is best-effort.
        """
        return "\x00" * len(s)


class InputValidationWrapper:
    """
    Input validation wrappers that layer on top of existing functions.
    Sanitizes and validates inputs without modifying core logic.
    """

    COMMON_DANGEROUS_PATTERNS = [
        r"<script.*?>",
        r"javascript:",
        r"on\w+\s*=",
        r"eval\s*\(",
        r"exec\s*\(",
        r"__import__",
        r"system\s*\(",
        r"subprocess",
        r"UNION.*?SELECT",
        r"DROP.*?TABLE",
        r"INSERT.*?INTO",
        r"OR.*?1=1",
    ]

    def __init__(self, config: Optional[ValidationConfig] = None):
        self.config = config or ValidationConfig()
        self._compiled_patterns = [
            re.compile(p, re.IGNORECASE) 
            for p in self.config.reject_patterns or self.COMMON_DANGEROUS_PATTERNS
        ]

    def validate_string(self, value: str, context: str = "general") -> str:
        """
        Validate and sanitize string input.
        Returns sanitized string or raises ValueError on rejection.
        """
        if not self.config.enabled:
            return value

        if not isinstance(value, str):
            raise ValueError(f"Expected string, got {type(value)}")

        # Length validation
        if len(value) > self.config.max_length:
            raise ValueError(
                f"Input exceeds maximum length: {len(value)} > {self.config.max_length}"
            )

        # Pattern rejection
        for pattern in self._compiled_patterns:
            if pattern.search(value):
                raise ValueError(f"Dangerous pattern detected in {context} input")

        # Strict mode additional checks
        if self.config.security_level in (SecurityLevel.STRICT, SecurityLevel.MAXIMUM):
            if not self.config.allow_special_chars:
                if re.search(r'[<>\"\'\\&]', value):
                    raise ValueError(f"Special characters not allowed in strict mode")

        return value

    def validate_integer(self, value: int, min_val: Optional[int] = None, 
                        max_val: Optional[int] = None) -> int:
        """
        Validate integer is within bounds.
        """
        if not self.config.enabled:
            return value

        if not isinstance(value, int):
            raise ValueError(f"Expected integer, got {type(value)}")

        if min_val is not None and value < min_val:
            raise ValueError(f"Value {value} below minimum {min_val}")
        
        if max_val is not None and value > max_val:
            raise ValueError(f"Value {value} above maximum {max_val}")

        return value

    def wrap_function(self, func: Callable[..., T]) -> Callable[..., T]:
        """
        Decorator to wrap a function with input validation.
        """
        def wrapper(*args: Any, **kwargs: Any) -> T:
            # Validate string arguments
            for i, arg in enumerate(args):
                if isinstance(arg, str):
                    self.validate_string(arg, f"arg_{i}")
            
            for key, value in kwargs.items():
                if isinstance(value, str):
                    self.validate_string(value, key)
            
            return func(*args, **kwargs)
        
        return wrapper

    def sanitize_html(self, html: str) -> str:
        """
        Basic HTML sanitization to prevent XSS.
        """
        if not self.config.enabled:
            return html

        sanitized = html
        sanitized = re.sub(r'<script.*?>.*?</script>', '', sanitized, flags=re.DOTALL | re.IGNORECASE)
        sanitized = re.sub(r'on\w+\s*=', 'data-removed=', sanitized, flags=re.IGNORECASE)
        sanitized = re.sub(r'javascript:', 'data-blocked:', sanitized, flags=re.IGNORECASE)
        return sanitized


class AdaptiveRateLimiter:
    """
    Adaptive rate limiter with token bucket algorithm.
    Provides DoS protection and request throttling.
    Thread-safe implementation.
    """

    def __init__(self, config: Optional[RateLimitConfig] = None):
        self.config = config or RateLimitConfig()
        self._lock = threading.Lock()
        self._tokens: Dict[str, float] = {}
        self._last_update: Dict[str, float] = {}
        self._burst_remaining: Dict[str, int] = {}

    def _refill_tokens(self, key: str, current_time: float) -> None:
        """Refill tokens based on elapsed time."""
        if key not in self._last_update:
            self._tokens[key] = float(self.config.max_requests)
            self._last_update[key] = current_time
            self._burst_remaining[key] = self.config.burst_allowance
            return

        elapsed = current_time - self._last_update[key]
        refill_rate = self.config.max_requests / self.config.window_seconds
        new_tokens = elapsed * refill_rate
        
        self._tokens[key] = min(
            self.config.max_requests,
            self._tokens[key] + new_tokens
        )
        self._last_update[key] = current_time

    def check_rate_limit(self, key: str = "global") -> bool:
        """
        Check if request is within rate limits.
        Returns True if allowed, False if rate limited.
        """
        if not self.config.enabled:
            return True

        with self._lock:
            current_time = time.time()
            self._refill_tokens(key, current_time)

            # Check burst allowance first
            if self._burst_remaining.get(key, 0) > 0:
                self._burst_remaining[key] -= 1
                return True

            # Check regular tokens
            if self._tokens.get(key, 0) >= 1:
                self._tokens[key] -= 1
                return True

            return False

    def get_remaining(self, key: str = "global") -> Dict[str, Any]:
        """
        Get rate limit status for monitoring.
        """
        with self._lock:
            current_time = time.time()
            self._refill_tokens(key, current_time)
            
            return {
                "remaining": int(self._tokens.get(key, 0)),
                "burst_remaining": self._burst_remaining.get(key, 0),
                "limit": self.config.max_requests,
                "window": self.config.window_seconds,
                "reset_in": self.config.window_seconds - (current_time - self._last_update.get(key, current_time))
            }

    def rate_limit_decorator(self, key_func: Optional[Callable[..., str]] = None) -> Callable:
        """
        Decorator to apply rate limiting to functions.
        """
        def decorator(func: Callable[..., T]) -> Callable[..., Union[T, Dict[str, Any]]]:
            def wrapper(*args: Any, **kwargs: Any) -> Union[T, Dict[str, Any]]:
                key = key_func(*args, **kwargs) if key_func else "global"
                
                if not self.check_rate_limit(key):
                    return {
                        "error": "rate_limited",
                        "message": "Too many requests",
                        "retry_after": self.config.window_seconds // 10
                    }
                
                return func(*args, **kwargs)
            
            return wrapper
        return decorator


class SideChannelResistance:
    """
    Utilities to resist side-channel attacks.
    Provides constant-time operations and noise injection.
    """

    @staticmethod
    def constant_time_lookup(table: List[T], index: int) -> Optional[T]:
        """
        Perform array lookup in constant time.
        Prevents timing attacks on array indexing.
        """
        if not (0 <= index < len(table)):
            return None

        result = None
        for i in range(len(table)):
            # Constant time comparison
            match = (i ^ index) == 0
            if match:
                result = table[i]
        
        return result

    @staticmethod
    def add_timing_noise(base_delay_ms: float = 1.0, jitter_ms: float = 0.5) -> None:
        """
        Add random timing noise to make timing attacks harder.
        This is optional and adds a small random delay.
        """
        delay = (base_delay_ms + secrets.SystemRandom().uniform(-jitter_ms, jitter_ms)) / 1000
        if delay > 0:
            time.sleep(delay)

    @staticmethod
    def blind_arithmetic(a: int, b: int, operation: str = "add") -> int:
        """
        Perform arithmetic with blinding to resist power analysis.
        Uses secret sharing approach.
        """
        blind = secrets.randbits(32)
        
        if operation == "add":
            return (a + blind) + (b - blind)
        elif operation == "multiply":
            # Simple multiplicative blinding
            return ((a + blind) * (b + blind) - blind * (a + b) - blind * blind)
        else:
            return a + b


class SecurityHardeningFacade:
    """
    Unified facade for all security hardening features.
    Easy integration point for existing code.
    """

    def __init__(
        self,
        validation_config: Optional[ValidationConfig] = None,
        memory_config: Optional[MemorySecurityConfig] = None,
        rate_limit_config: Optional[RateLimitConfig] = None
    ):
        self.validator = InputValidationWrapper(validation_config)
        self.memory_zeroizer = SecureMemoryZeroizer(memory_config)
        self.rate_limiter = AdaptiveRateLimiter(rate_limit_config)
        self.constant_time = ConstantTimeComparer()
        self.side_channel = SideChannelResistance()

    def secure_operation(self, func: Callable[..., T], 
                        rate_limit_key: str = "global",
                        validate_inputs: bool = True) -> Callable[..., T]:
        """
        Wrap an operation with all security hardening layers.
        """
        def wrapper(*args: Any, **kwargs: Any) -> T:
            # Rate limiting check
            if not self.rate_limiter.check_rate_limit(rate_limit_key):
                raise RuntimeError("Rate limit exceeded")

            # Input validation
            if validate_inputs:
                for arg in args:
                    if isinstance(arg, str):
                        self.validator.validate_string(arg)
            
            # Execute operation
            result = func(*args, **kwargs)
            
            return result
        
        return cast(Callable[..., T], wrapper)


# Global instances for easy import
default_comparer = ConstantTimeComparer()
default_zeroizer = SecureMemoryZeroizer()
default_validator = InputValidationWrapper()
default_rate_limiter = AdaptiveRateLimiter()
default_side_channel = SideChannelResistance()
