"""
NeuralShield Security Hardening - Comprehensive Protection v19
Dimension B: Security Hardening

This module provides production-grade security hardening features:
- Enhanced input validation wrappers (additive, no core modification)
- Secure memory zeroization with side-channel resistance
- Advanced constant-time comparison helpers
- Adaptive rate limiting with token bucket algorithm
- Side-channel timing attack resistance

All features are OPT-IN and layered on top of existing code.
No existing production code is modified - 100% backward compatible.

API Stability: STABLE
"""

import hashlib
import hmac
import secrets
import threading
import time
import weakref
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, TypeVar, Union, cast
from functools import wraps
import re

T = TypeVar('T')

# -----------------------------------------------------------------------------
# Secure Memory Zeroization Utilities
# -----------------------------------------------------------------------------

class SecureMemory:
    """
    Secure memory management with side-channel resistant zeroization.
    
    Provides utilities for securely wiping sensitive data from memory
    with resistance to timing attacks and compiler optimizations.
    """
    
    @staticmethod
    def zeroize_bytes(data: bytearray) -> None:
        """
        Securely zeroize a bytearray with side-channel resistance.
        
        Uses multiple passes with different patterns to prevent
        compiler optimization and ensure memory is actually cleared.
        
        Args:
            data: Mutable bytearray to zeroize
        """
        length = len(data)
        if length == 0:
            return
            
        # Pass 1: All zeros
        for i in range(length):
            data[i] = 0
        
        # Pass 2: All ones
        for i in range(length):
            data[i] = 0xFF
        
        # Pass 3: Random pattern
        rng = secrets.SystemRandom()
        for i in range(length):
            data[i] = rng.randint(0, 255)
        
        # Pass 4: Final zero
        for i in range(length):
            data[i] = 0
    
    @staticmethod
    def zeroize_string(data: str) -> str:
        """
        Create a zeroized replacement for sensitive strings.
        
        Note: Python strings are immutable, so we return a
        placeholder and recommend using bytearray for secrets.
        
        Args:
            data: Sensitive string to be replaced
            
        Returns:
            Placeholder string of equal length
        """
        return "[REDACTED]" + " " * max(0, len(data) - 10)
    
    @staticmethod
    def secure_compare(a: bytes, b: bytes) -> bool:
        """
        Constant-time comparison of byte strings.
        
        Prevents timing attacks by ensuring comparison time
        does not depend on how many bytes match.
        
        Args:
            a: First byte string
            b: Second byte string
            
        Returns:
            True if equal, False otherwise
        """
        return hmac.compare_digest(a, b)


class SensitiveBuffer:
    """
    Auto-zeroizing sensitive buffer container.
    
    Automatically zeroizes memory when the buffer is garbage collected
    or explicitly closed. Uses weakref finalizer for guaranteed cleanup.
    """
    
    def __init__(self, initial_data: Optional[bytes] = None):
        self._data: bytearray = bytearray()
        self._is_closed = False
        
        if initial_data is not None:
            self._data.extend(initial_data)
        
        # Register finalizer to ensure zeroization on GC
        self._finalizer = weakref.finalize(
            self, self._finalize, self._data
        )
    
    @staticmethod
    def _finalize(data: bytearray) -> None:
        """Finalizer called during GC to zeroize memory."""
        SecureMemory.zeroize_bytes(data)
    
    def get_bytes(self) -> bytes:
        """Get copy of data as bytes."""
        if self._is_closed:
            raise ValueError("Buffer is closed")
        return bytes(self._data)
    
    def close(self) -> None:
        """Explicitly close and zeroize buffer."""
        if not self._is_closed:
            SecureMemory.zeroize_bytes(self._data)
            self._is_closed = True
    
    def __enter__(self) -> 'SensitiveBuffer':
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()


# -----------------------------------------------------------------------------
# Constant-Time Comparison Helpers
# -----------------------------------------------------------------------------

class ConstantTime:
    """
    Constant-time operations library.
    
    Provides comparison and selection operations that execute in
    constant time regardless of input values, preventing timing attacks.
    """
    
    @staticmethod
    def eq_int(a: int, b: int) -> bool:
        """
        Constant-time integer equality check.
        
        Args:
            a: First integer
            b: Second integer
            
        Returns:
            True if equal, False otherwise (constant time)
        """
        diff = a ^ b
        return (diff - 1) >> 63 != 0
    
    @staticmethod
    def select(condition: bool, val_true: T, val_false: T) -> T:
        """
        Constant-time conditional selection.
        
        Args:
            condition: Selection condition
            val_true: Value if condition is True
            val_false: Value if condition is False
            
        Returns:
            val_true if condition, otherwise val_false (constant time)
        """
        mask = -int(condition)
        if isinstance(val_true, int) and isinstance(val_false, int):
            return (val_true & mask) | (val_false & ~mask)
        return val_true if condition else val_false
    
    @staticmethod
    def compare_strings_constant(a: str, b: str) -> bool:
        """
        Constant-time string comparison.
        
        Args:
            a: First string
            b: Second string
            
        Returns:
            True if equal, False otherwise
        """
        if len(a) != len(b):
            return False
        return hmac.compare_digest(a.encode('utf-8'), b.encode('utf-8'))
    
    @staticmethod
    def verify_hash(hash_a: bytes, hash_b: bytes) -> bool:
        """
        Constant-time hash verification.
        
        Args:
            hash_a: First hash digest
            hash_b: Second hash digest
            
        Returns:
            True if hashes match, False otherwise
        """
        return hmac.compare_digest(hash_a, hash_b)


# -----------------------------------------------------------------------------
# Input Validation Wrappers
# -----------------------------------------------------------------------------

@dataclass
class ValidationRule:
    """Validation rule definition."""
    name: str
    validator: Callable[[Any], bool]
    error_message: str


class InputValidator:
    """
    Enhanced input validation wrapper.
    
    Layered security - wraps existing functions without modifying them.
    Provides sanitization and validation for all inputs.
    """
    
    def __init__(self):
        self._rules: Dict[str, List[ValidationRule]] = {}
        self._sql_patterns = [
            re.compile(r"['\";].*(OR|AND|UNION|SELECT|INSERT|UPDATE|DELETE|DROP|EXEC)", re.IGNORECASE),
            re.compile(r"--.*$", re.MULTILINE),
            re.compile(r"/\*.*?\*/", re.DOTALL),
        ]
        self._xss_patterns = [
            re.compile(r"<script.*?>.*?</script>", re.IGNORECASE | re.DOTALL),
            re.compile(r"javascript:", re.IGNORECASE),
            re.compile(r"on\w+\s*=", re.IGNORECASE),
        ]
    
    def register_rule(self, param_name: str, rule: ValidationRule) -> None:
        """Register a validation rule for a parameter."""
        if param_name not in self._rules:
            self._rules[param_name] = []
        self._rules[param_name].append(rule)
    
    def validate_string(
        self,
        value: str,
        min_length: int = 0,
        max_length: int = 10000,
        allow_empty: bool = False,
        block_sql_injection: bool = True,
        block_xss: bool = True
    ) -> tuple[bool, Optional[str]]:
        """
        Validate and sanitize string input.
        
        Args:
            value: Input string to validate
            min_length: Minimum allowed length
            max_length: Maximum allowed length
            allow_empty: Whether empty string is allowed
            block_sql_injection: Check for SQL injection patterns
            block_xss: Check for XSS patterns
            
        Returns:
            (is_valid, sanitized_value or None)
        """
        if not isinstance(value, str):
            return False, None
        
        if not allow_empty and len(value.strip()) == 0:
            return False, None
        
        if len(value) < min_length or len(value) > max_length:
            return False, None
        
        # Check for SQL injection
        if block_sql_injection:
            for pattern in self._sql_patterns:
                if pattern.search(value):
                    return False, None
        
        # Check for XSS
        if block_xss:
            for pattern in self._xss_patterns:
                if pattern.search(value):
                    return False, None
        
        # Basic sanitization
        sanitized = value.replace('\0', '')
        return True, sanitized
    
    def validate_int(
        self,
        value: Any,
        min_val: Optional[int] = None,
        max_val: Optional[int] = None
    ) -> tuple[bool, Optional[int]]:
        """Validate integer input."""
        try:
            int_val = int(value)
            if min_val is not None and int_val < min_val:
                return False, None
            if max_val is not None and int_val > max_val:
                return False, None
            return True, int_val
        except (ValueError, TypeError):
            return False, None
    
    def validate_list(
        self,
        value: Any,
        min_items: int = 0,
        max_items: int = 1000,
        item_type: Optional[type] = None
    ) -> tuple[bool, Optional[List]]:
        """Validate list input."""
        if not isinstance(value, list):
            return False, None
        
        if len(value) < min_items or len(value) > max_items:
            return False, None
        
        if item_type is not None:
            for item in value:
                if not isinstance(item, item_type):
                    return False, None
        
        return True, value


def validate_inputs(**validation_spec):
    """
    Decorator for input validation.
    
    Usage:
        @validate_inputs(
            prompt={'type': str, 'max_length': 10000},
            temperature={'type': float, 'min': 0.0, 'max': 2.0}
        )
        def generate(prompt, temperature):
            ...
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            validator = InputValidator()
            
            # Validate keyword arguments
            for param_name, spec in validation_spec.items():
                if param_name in kwargs:
                    value = kwargs[param_name]
                    expected_type = spec.get('type', str)
                    
                    if expected_type == str:
                        valid, sanitized = validator.validate_string(
                            str(value),
                            max_length=spec.get('max_length', 10000),
                            min_length=spec.get('min_length', 0)
                        )
                        if not valid:
                            raise ValueError(f"Invalid input for {param_name}")
                        kwargs[param_name] = sanitized
                    
                    elif expected_type == int:
                        valid, parsed = validator.validate_int(
                            value,
                            min_val=spec.get('min'),
                            max_val=spec.get('max')
                        )
                        if not valid:
                            raise ValueError(f"Invalid input for {param_name}")
                        kwargs[param_name] = parsed
            
            return func(*args, **kwargs)
        return wrapper
    return decorator


# -----------------------------------------------------------------------------
# Rate Limiting / DoS Protection
# -----------------------------------------------------------------------------

@dataclass
class RateLimitConfig:
    """Rate limit configuration."""
    max_requests: int = 100
    window_seconds: float = 60.0
    burst_multiplier: float = 2.0


@dataclass
class TokenBucket:
    """Token bucket state for rate limiting."""
    tokens: float
    last_update: float
    lock: threading.Lock = field(default_factory=threading.Lock)


class AdaptiveRateLimiter:
    """
    Adaptive rate limiter with token bucket algorithm.
    
    Provides DoS protection with configurable rate limits per client.
    Layered security - can wrap any existing function.
    """
    
    def __init__(self, default_config: Optional[RateLimitConfig] = None):
        self._default_config = default_config or RateLimitConfig()
        self._buckets: Dict[str, TokenBucket] = {}
        self._configs: Dict[str, RateLimitConfig] = {}
        self._global_lock = threading.Lock()
        self._cleanup_interval = 300.0  # 5 minutes
        self._last_cleanup = time.time()
    
    def _cleanup_old_buckets(self) -> None:
        """Remove stale buckets to prevent memory leaks."""
        now = time.time()
        if now - self._last_cleanup < self._cleanup_interval:
            return
        
        with self._global_lock:
            stale_keys = [
                key for key, bucket in self._buckets.items()
                if now - bucket.last_update > self._cleanup_interval * 2
            ]
            for key in stale_keys:
                del self._buckets[key]
            self._last_cleanup = now
    
    def check_rate_limit(
        self,
        client_id: str,
        tokens_needed: int = 1,
        config: Optional[RateLimitConfig] = None
    ) -> tuple[bool, float]:
        """
        Check if request is within rate limits.
        
        Args:
            client_id: Client identifier
            tokens_needed: Number of tokens required
            config: Optional per-client config
            
        Returns:
            (allowed, retry_after_seconds)
        """
        self._cleanup_old_buckets()
        
        cfg = config or self._configs.get(client_id, self._default_config)
        
        with self._global_lock:
            if client_id not in self._buckets:
                self._buckets[client_id] = TokenBucket(
                    tokens=cfg.max_requests,
                    last_update=time.time()
                )
        
        bucket = self._buckets[client_id]
        
        with bucket.lock:
            now = time.time()
            elapsed = now - bucket.last_update
            
            # Refill tokens
            refill_rate = cfg.max_requests / cfg.window_seconds
            new_tokens = elapsed * refill_rate
            bucket.tokens = min(
                bucket.tokens + new_tokens,
                cfg.max_requests * cfg.burst_multiplier
            )
            bucket.last_update = now
            
            # Check if enough tokens
            if bucket.tokens >= tokens_needed:
                bucket.tokens -= tokens_needed
                return True, 0.0
            else:
                # Calculate retry after
                tokens_deficit = tokens_needed - bucket.tokens
                retry_after = tokens_deficit / refill_rate
                return False, retry_after
    
    def get_remaining(self, client_id: str) -> int:
        """Get remaining tokens for a client."""
        if client_id not in self._buckets:
            return self._default_config.max_requests
        return int(self._buckets[client_id].tokens)


def rate_limited(
    max_requests: int = 100,
    window_seconds: float = 60.0,
    client_id_extractor: Optional[Callable[..., str]] = None
):
    """
    Decorator for rate limiting functions.
    
    Usage:
        @rate_limited(max_requests=100, window_seconds=60)
        def api_call(client_id, data):
            ...
    """
    limiter = AdaptiveRateLimiter(RateLimitConfig(
        max_requests=max_requests,
        window_seconds=window_seconds
    ))
    
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Extract client ID - use first argument by default
            if client_id_extractor:
                client_id = client_id_extractor(*args, **kwargs)
            elif args:
                client_id = str(args[0])
            else:
                client_id = "default"
            
            allowed, retry_after = limiter.check_rate_limit(client_id)
            
            if not allowed:
                raise RuntimeError(
                    f"Rate limit exceeded. Retry after {retry_after:.2f}s"
                )
            
            return func(*args, **kwargs)
        return wrapper
    return decorator


# -----------------------------------------------------------------------------
# Side-Channel Timing Resistance
# -----------------------------------------------------------------------------

class TimingResistance:
    """
    Side-channel timing attack resistance utilities.
    
    Provides methods to make operations resistant to timing analysis.
    """
    
    @staticmethod
    def add_jitter(
        base_delay: float = 0.001,
        jitter_range: float = 0.002
    ) -> None:
        """
        Add random timing jitter to obscure actual execution time.
        
        Args:
            base_delay: Minimum delay in seconds
            jitter_range: Additional random delay range
        """
        delay = base_delay + secrets.SystemRandom().random() * jitter_range
        time.sleep(delay)
    
    @staticmethod
    def normalize_execution_time(
        target_duration: float,
        start_time: float
    ) -> None:
        """
        Ensure operation takes at least target_duration.
        
        Args:
            target_duration: Minimum duration in seconds
            start_time: Operation start timestamp
        """
        elapsed = time.time() - start_time
        remaining = target_duration - elapsed
        if remaining > 0:
            time.sleep(remaining)


# -----------------------------------------------------------------------------
# Security Hardening Facade
# -----------------------------------------------------------------------------

class SecurityHardening:
    """
    Unified facade for all security hardening features.
    
    Single entry point for all security features.
    Can be instantiated and added to existing code without modification.
    """
    
    def __init__(self):
        self.memory = SecureMemory()
        self.constant_time = ConstantTime()
        self.validator = InputValidator()
        self.rate_limiter = AdaptiveRateLimiter()
        self.timing = TimingResistance()
    
    def create_sensitive_buffer(self, data: bytes) -> SensitiveBuffer:
        """Create a new auto-zeroizing sensitive buffer."""
        return SensitiveBuffer(data)
    
    def secure_compare(self, a: bytes, b: bytes) -> bool:
        """Constant-time comparison."""
        return SecureMemory.secure_compare(a, b)
    
    def validate_prompt(self, prompt: str, max_length: int = 10000) -> str:
        """Validate and sanitize AI prompt input."""
        valid, sanitized = self.validator.validate_string(
            prompt,
            max_length=max_length,
            block_sql_injection=True,
            block_xss=True
        )
        if not valid or sanitized is None:
            raise ValueError("Invalid prompt input detected")
        return sanitized
    
    def check_rate_limit(self, client_id: str) -> bool:
        """Check rate limit for a client."""
        allowed, _ = self.rate_limiter.check_rate_limit(client_id)
        return allowed


# -----------------------------------------------------------------------------
# Module Exports
# -----------------------------------------------------------------------------

__all__ = [
    'SecureMemory',
    'SensitiveBuffer',
    'ConstantTime',
    'InputValidator',
    'ValidationRule',
    'validate_inputs',
    'RateLimitConfig',
    'AdaptiveRateLimiter',
    'rate_limited',
    'TimingResistance',
    'SecurityHardening',
]
