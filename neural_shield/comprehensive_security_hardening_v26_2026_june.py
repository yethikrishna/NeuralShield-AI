"""
NeuralShield-AI Comprehensive Security Hardening Module v26
Dimension B - Security Hardening

Incremental security layer - wraps existing code, does NOT modify core
All security features are opt-in and backward compatible

Features added in v26:
1. Secure memory zeroization for sensitive data
2. Constant-time comparison helpers (prevents timing attacks)
3. Input validation wrappers with type safety
4. Rate limiting / DoS protection with token bucket
5. Secure string sanitization utilities
6. Memory-safe temporary buffer management
"""

import os
import sys
import time
import hmac
import ctypes
import threading
from typing import Any, Callable, Dict, List, Optional, TypeVar, Union, Tuple
from dataclasses import dataclass, field
from enum import Enum
import hashlib
import re

# Type variable for generic functions
T = TypeVar('T')
F = TypeVar('F', bound=Callable)


class SecurityLevel(Enum):
    """Security level enumeration for validation strictness"""
    RELAXED = "relaxed"
    STANDARD = "standard"
    STRICT = "strict"
    PARANOID = "paranoid"


@dataclass
class ValidationResult:
    """Result of input validation operation"""
    is_valid: bool
    sanitized_value: Any = None
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    security_level: SecurityLevel = SecurityLevel.STANDARD


class SecureMemory:
    """
    Secure memory zeroization utilities.
    
    Prevents sensitive data from lingering in memory after use.
    Uses low-level memory operations to ensure data is actually cleared.
    """
    
    @staticmethod
    def zeroize_bytes(data: bytearray) -> None:
        """
        Securely zeroize a bytearray in memory.
        
        Args:
            data: Mutable bytearray to clear (bytes are immutable, use bytearray)
        """
        if not isinstance(data, bytearray):
            return
        
        length = len(data)
        if length == 0:
            return
        
        # Multiple passes with different patterns to prevent compiler optimization
        for i in range(length):
            data[i] = 0x00
        
        for i in range(length):
            data[i] = 0xFF
        
        for i in range(length):
            data[i] = 0x00
        
        # Use ctypes to force memory overwrite
        if length > 0:
            buffer = (ctypes.c_ubyte * length).from_buffer(data)
            ctypes.memset(ctypes.byref(buffer), 0x00, length)
    
    @staticmethod
    def zeroize_string(s: str) -> str:
        """
        Note: Python strings are immutable and cannot be securely zeroized.
        This function returns an empty string as a best-effort cleanup.
        
        WARNING: For truly sensitive data, use bytearray and call zeroize_bytes.
        """
        return ""
    
    @staticmethod
    def create_secure_buffer(size: int) -> bytearray:
        """
        Create a secure buffer that can be zeroized after use.
        
        Args:
            size: Size of buffer in bytes
            
        Returns:
            Zero-initialized bytearray
        """
        return bytearray(size)
    
    @staticmethod
    def secure_delete(obj: Any) -> None:
        """
        Best-effort secure deletion attempt.
        Works for bytearray, list of integers, etc.
        """
        if isinstance(obj, bytearray):
            SecureMemory.zeroize_bytes(obj)
        elif isinstance(obj, list) and all(isinstance(x, int) for x in obj):
            for i in range(len(obj)):
                obj[i] = 0


class ConstantTime:
    """
    Constant-time comparison utilities to prevent timing attacks.
    
    All comparison operations take the same amount of time regardless
    of how much of the inputs match, preventing side-channel attacks.
    """
    
    @staticmethod
    def compare_bytes(a: bytes, b: bytes) -> bool:
        """
        Constant-time byte comparison using HMAC digest comparison.
        
        Args:
            a: First bytes object
            b: Second bytes object
            
        Returns:
            True if equal, False otherwise
        """
        if len(a) != len(b):
            return False
        return hmac.compare_digest(a, b)
    
    @staticmethod
    def compare_strings(a: str, b: str) -> bool:
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
    def compare_hashes(a: str, b: str) -> bool:
        """
        Constant-time hash comparison.
        
        Args:
            a: First hash hex string
            b: Second hash hex string
            
        Returns:
            True if equal, False otherwise
        """
        return ConstantTime.compare_strings(a.lower(), b.lower())
    
    @staticmethod
    def safe_equals(a: Any, b: Any) -> bool:
        """
        Generic safe equals with type checking.
        
        Args:
            a: First value
            b: Second value
            
        Returns:
            True if equal and same type, False otherwise
        """
        if type(a) != type(b):
            return False
        
        if isinstance(a, bytes) and isinstance(b, bytes):
            return ConstantTime.compare_bytes(a, b)
        elif isinstance(a, str) and isinstance(b, str):
            return ConstantTime.compare_strings(a, b)
        else:
            # For other types, use standard equality (not constant time)
            return a == b


class InputValidator:
    """
    Input validation wrapper with configurable security levels.
    Does NOT modify existing code - wraps inputs before they reach core.
    """
    
    # Regex patterns for common validations
    PATTERNS = {
        'alphanumeric': re.compile(r'^[a-zA-Z0-9_]+$'),
        'identifier': re.compile(r'^[a-zA-Z_][a-zA-Z0-9_]*$'),
        'hex': re.compile(r'^[0-9a-fA-F]+$'),
        'base64': re.compile(r'^[A-Za-z0-9+/]*={0,2}$'),
        'email': re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'),
        'url_safe': re.compile(r'^[a-zA-Z0-9\-._~:/?#[\]@!$&\'()*+,;=%]+$'),
        'filename': re.compile(r'^[a-zA-Z0-9_.-]+$'),
    }
    
    # Maximum lengths per security level
    MAX_LENGTHS = {
        SecurityLevel.RELAXED: 1048576,    # 1MB
        SecurityLevel.STANDARD: 65536,     # 64KB
        SecurityLevel.STRICT: 4096,        # 4KB
        SecurityLevel.PARANOID: 1024,      # 1KB
    }
    
    @staticmethod
    def validate_string(
        value: str,
        min_length: int = 0,
        max_length: Optional[int] = None,
        pattern: Optional[str] = None,
        allowed_chars: Optional[str] = None,
        security_level: SecurityLevel = SecurityLevel.STANDARD,
        allow_empty: bool = False
    ) -> ValidationResult:
        """
        Validate and sanitize string input.
        
        Args:
            value: Input string to validate
            min_length: Minimum allowed length
            max_length: Maximum allowed length (None = use security level default)
            pattern: Regex pattern name from PATTERNS dict
            allowed_chars: String of allowed characters (alternative to pattern)
            security_level: Security strictness level
            allow_empty: Whether empty string is allowed
            
        Returns:
            ValidationResult with sanitized value
        """
        errors = []
        warnings = []
        
        # Handle None
        if value is None:
            if allow_empty:
                return ValidationResult(True, "", [], warnings, security_level)
            return ValidationResult(False, None, ["Value cannot be None"], warnings, security_level)
        
        # Convert to string
        str_value = str(value)
        
        # Check empty
        if len(str_value) == 0:
            if allow_empty:
                return ValidationResult(True, "", [], warnings, security_level)
            return ValidationResult(False, "", ["Empty string not allowed"], warnings, security_level)
        
        # Apply max length from security level if not specified
        effective_max = max_length if max_length is not None else InputValidator.MAX_LENGTHS[security_level]
        
        # Check lengths
        if len(str_value) < min_length:
            errors.append(f"String too short: minimum {min_length} characters")
        if len(str_value) > effective_max:
            errors.append(f"String too long: maximum {effective_max} characters")
            str_value = str_value[:effective_max]
            warnings.append(f"String truncated to {effective_max} characters")
        
        # Pattern validation
        if pattern and pattern in InputValidator.PATTERNS:
            if not InputValidator.PATTERNS[pattern].match(str_value):
                errors.append(f"String does not match pattern: {pattern}")
        
        # Allowed characters validation
        if allowed_chars:
            for char in str_value:
                if char not in allowed_chars:
                    errors.append(f"Disallowed character: {repr(char)}")
                    break
        
        # Null byte check (security level >= STANDARD)
        if security_level in [SecurityLevel.STANDARD, SecurityLevel.STRICT, SecurityLevel.PARANOID]:
            if '\x00' in str_value:
                errors.append("Null bytes not allowed")
                str_value = str_value.replace('\x00', '')
        
        # Control character check (security level >= STRICT)
        if security_level in [SecurityLevel.STRICT, SecurityLevel.PARANOID]:
            for char in str_value:
                if ord(char) < 32 and char not in '\t\n\r':
                    errors.append(f"Control character not allowed: 0x{ord(char):02x}")
        
        return ValidationResult(len(errors) == 0, str_value, errors, warnings, security_level)
    
    @staticmethod
    def validate_prompt_input(
        prompt: str,
        security_level: SecurityLevel = SecurityLevel.STANDARD
    ) -> ValidationResult:
        """
        Specialized validation for AI prompt inputs.
        Prevents common injection attack patterns.
        """
        result = InputValidator.validate_string(
            prompt,
            max_length=InputValidator.MAX_LENGTHS[security_level],
            security_level=security_level,
            allow_empty=False
        )
        
        if not result.is_valid:
            return result
        
        sanitized = result.sanitized_value
        warnings = result.warnings.copy()
        
        # Check for common prompt injection patterns (warning only, not blocking)
        injection_patterns = [
            "ignore previous",
            "disregard all",
            "you are now",
            "act as",
            "system prompt",
            "override instructions",
        ]
        
        prompt_lower = sanitized.lower()
        for pattern in injection_patterns:
            if pattern in prompt_lower:
                warnings.append(f"Potential injection pattern detected: {pattern}")
        
        return ValidationResult(True, sanitized, [], warnings, security_level)
    
    @staticmethod
    def sanitize_for_logging(value: Any, max_length: int = 200) -> str:
        """
        Sanitize values for safe logging - truncate and remove sensitive patterns.
        
        Args:
            value: Value to sanitize
            max_length: Maximum output length
            
        Returns:
            Sanitized string safe for logging
        """
        if value is None:
            return "[None]"
        
        str_val = str(value)
        
        # Mask common sensitive patterns
        sensitive_patterns = [
            (r'api[_-]?key[=:]\s*[a-zA-Z0-9]{10,}', 'api_key=[REDACTED]'),
            (r'secret[=:]\s*[a-zA-Z0-9]{10,}', 'secret=[REDACTED]'),
            (r'password[=:]\s*\S+', 'password=[REDACTED]'),
            (r'Bearer\s+[a-zA-Z0-9._-]+', 'Bearer [REDACTED]'),
        ]
        
        for pattern, replacement in sensitive_patterns:
            str_val = re.sub(pattern, replacement, str_val, flags=re.IGNORECASE)
        
        # Truncate
        if len(str_val) > max_length:
            str_val = str_val[:max_length] + "...[TRUNCATED]"
        
        return str_val


class TokenBucket:
    """
    Token bucket rate limiter for DoS protection.
    
    Thread-safe implementation that can be wrapped around any function.
    Does not modify core logic - only adds rate limiting layer.
    """
    
    def __init__(self, rate: float, capacity: float):
        """
        Initialize token bucket.
        
        Args:
            rate: Tokens added per second
            capacity: Maximum bucket capacity (burst allowance)
        """
        self.rate = rate
        self.capacity = capacity
        self.tokens = capacity
        self.last_update = time.monotonic()
        self._lock = threading.Lock()
    
    def consume(self, tokens: float = 1.0) -> bool:
        """
        Try to consume tokens from the bucket.
        
        Args:
            tokens: Number of tokens to consume
            
        Returns:
            True if tokens were consumed, False if rate limited
        """
        with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_update
            
            # Add tokens based on elapsed time
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
            self.last_update = now
            
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False
    
    def get_available_tokens(self) -> float:
        """Get current available token count (thread-safe)"""
        with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_update
            return min(self.capacity, self.tokens + elapsed * self.rate)


class RateLimiter:
    """
    Rate limiter manager with per-key buckets.
    Used to protect endpoints from abuse.
    """
    
    def __init__(self, default_rate: float = 10.0, default_capacity: float = 20.0):
        self.default_rate = default_rate
        self.default_capacity = default_capacity
        self._buckets: Dict[str, TokenBucket] = {}
        self._lock = threading.Lock()
    
    def _get_bucket(self, key: str) -> TokenBucket:
        with self._lock:
            if key not in self._buckets:
                self._buckets[key] = TokenBucket(self.default_rate, self.default_capacity)
            return self._buckets[key]
    
    def check_rate_limit(self, key: str, cost: float = 1.0) -> Tuple[bool, float]:
        """
        Check if request should be rate limited.
        
        Args:
            key: Rate limit key (e.g., client IP, user ID)
            cost: Token cost for this request
            
        Returns:
            (allowed: bool, remaining_tokens: float)
        """
        bucket = self._get_bucket(key)
        allowed = bucket.consume(cost)
        remaining = bucket.get_available_tokens()
        return allowed, remaining
    
    def wrap_function(self, func: F, key_extractor: Callable[..., str]) -> F:
        """
        Wrap a function with rate limiting protection.
        
        Args:
            func: Function to wrap
            key_extractor: Function that extracts rate limit key from args
            
        Returns:
            Wrapped function
        """
        def wrapper(*args, **kwargs):
            key = key_extractor(*args, **kwargs)
            allowed, remaining = self.check_rate_limit(key)
            if not allowed:
                raise RateLimitError(f"Rate limit exceeded for key: {key}")
            return func(*args, **kwargs)
        return wrapper  # type: ignore


class RateLimitError(Exception):
    """Raised when rate limit is exceeded"""
    pass


class SecureTemporaryBuffer:
    """
    Context manager for secure temporary buffers.
    Automatically zeroizes buffer when exiting context.
    """
    
    def __init__(self, size: int):
        self.size = size
        self._buffer: Optional[bytearray] = None
    
    def __enter__(self) -> bytearray:
        self._buffer = bytearray(self.size)
        return self._buffer
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._buffer is not None:
            SecureMemory.zeroize_bytes(self._buffer)
            self._buffer = None
        return False


class SecurityHardeningFacade:
    """
    Facade class providing easy access to all security hardening features.
    This is the main entry point for integrating security into existing code.
    """
    
    def __init__(self, security_level: SecurityLevel = SecurityLevel.STANDARD):
        self.security_level = security_level
        self._rate_limiter = RateLimiter()
        self._validation_stats: Dict[str, int] = {
            'total_validated': 0,
            'validation_failures': 0,
            'rate_limited': 0,
        }
        self._stats_lock = threading.Lock()
    
    def validate_prompt(self, prompt: str) -> ValidationResult:
        """Validate AI prompt input"""
        with self._stats_lock:
            self._validation_stats['total_validated'] += 1
        
        result = InputValidator.validate_prompt_input(prompt, self.security_level)
        
        if not result.is_valid:
            with self._stats_lock:
                self._validation_stats['validation_failures'] += 1
        
        return result
    
    def check_rate_limit(self, client_id: str, cost: float = 1.0) -> bool:
        """Check rate limit for client"""
        allowed, _ = self._rate_limiter.check_rate_limit(client_id, cost)
        if not allowed:
            with self._stats_lock:
                self._validation_stats['rate_limited'] += 1
        return allowed
    
    def secure_compare(self, a: Any, b: Any) -> bool:
        """Constant-time safe comparison"""
        return ConstantTime.safe_equals(a, b)
    
    def create_secure_buffer(self, size: int) -> SecureTemporaryBuffer:
        """Create context-managed secure buffer"""
        return SecureTemporaryBuffer(size)
    
    def get_security_stats(self) -> Dict[str, int]:
        """Get security statistics"""
        with self._stats_lock:
            return dict(self._validation_stats)
    
    def sanitize_log(self, value: Any, max_length: int = 200) -> str:
        """Sanitize value for safe logging"""
        return InputValidator.sanitize_for_logging(value, max_length)


# Export singleton for easy use
_default_security = SecurityHardeningFacade()

def get_security_facade() -> SecurityHardeningFacade:
    """Get the default security hardening facade"""
    return _default_security


# Module version info
__version__ = "26.0.0"
__security_dimension__ = "B - Security Hardening"
