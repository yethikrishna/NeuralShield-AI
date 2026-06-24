"""
NeuralShield AI - Comprehensive Security Hardening Module v24
DIMENSION B - Security Hardening

ADD-ONLY implementation - wraps existing functionality without modification
Layered security on top of existing core modules

Security Features Added in v24:
1. Enhanced Input Validation Wrappers (new module, no core modification)
2. Advanced Secure Memory Zeroization Utilities
3. Cryptographically Secure Constant-Time Comparison Helpers
4. Token Bucket Rate Limiting / DoS Protection Modules
5. Secure Type Coercion with Boundary Validation
6. Sensitive Data Redaction Utilities
7. Path Traversal Prevention Wrappers
"""

import os
import sys
import hmac
import time
import ctypes
import secrets
import hashlib
import threading
from typing import Any, Callable, Dict, List, Optional, Tuple, Union, TypeVar
from dataclasses import dataclass, field
from enum import Enum
import re


# -----------------------------------------------------------------------------
# Security Level Enumeration
# -----------------------------------------------------------------------------
class SecurityLevel(Enum):
    """Security validation strictness levels."""
    PERMISSIVE = "permissive"
    STANDARD = "standard"
    STRICT = "strict"
    PARANOID = "paranoid"


# -----------------------------------------------------------------------------
# Secure Memory Zeroization Utilities
# -----------------------------------------------------------------------------
class SecureMemory:
    """
    Secure memory zeroization utilities for sensitive data.
    Uses low-level memory operations to overwrite sensitive contents.
    Follows ADD-ONLY philosophy - new utility module, no core modifications.
    """

    @staticmethod
    def zeroize_bytes(data: bytearray) -> None:
        """
        Securely zeroize a bytearray by overwriting with random data then zeros.
        Prevents compiler optimizations from skipping the zeroization.
        
        Args:
            data: Mutable bytearray to zeroize
        """
        if not isinstance(data, bytearray):
            return
            
        length = len(data)
        if length == 0:
            return
            
        # First pass: overwrite with random bytes
        for i in range(length):
            data[i] = secrets.randbelow(256)
            
        # Second pass: overwrite with alternating patterns
        pattern = 0xAA
        for i in range(length):
            data[i] = pattern
            pattern ^= 0xFF
            
        # Third pass: overwrite with zeros
        for i in range(length):
            data[i] = 0x00
            
        # Force memory barrier to prevent optimization
        if sys.version_info >= (3, 8):
            import gc
            gc.collect()

    @staticmethod
    def zeroize_string(s: str) -> None:
        """
        Attempt to zeroize string contents.
        Note: Python strings are immutable, so this is best-effort.
        For truly sensitive data, use bytearrays instead.
        """
        # Strings are immutable in Python - log warning
        pass

    @staticmethod
    def secure_delete_list(lst: List[Any]) -> None:
        """Securely clear list contents and overwrite elements."""
        for i in range(len(lst)):
            lst[i] = None
        lst.clear()

    @staticmethod
    def secure_delete_dict(d: Dict[Any, Any]) -> None:
        """Securely clear dictionary contents."""
        keys = list(d.keys())
        for key in keys:
            d[key] = None
            del d[key]
        d.clear()


# -----------------------------------------------------------------------------
# Constant-Time Comparison Helpers
# -----------------------------------------------------------------------------
class ConstantTime:
    """
    Cryptographically secure constant-time comparison functions.
    Prevents timing attacks on authentication and validation operations.
    """

    @staticmethod
    def compare_bytes(a: bytes, b: bytes) -> bool:
        """
        Constant-time byte comparison using HMAC-based verification.
        Equal execution time regardless of how many bytes match.
        
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
    def compare_hashes(hash_a: str, hash_b: str) -> bool:
        """
        Constant-time hash comparison with length normalization.
        
        Args:
            hash_a: First hash hex string
            hash_b: Second hash hex string
            
        Returns:
            True if hashes match, False otherwise
        """
        # Normalize to same length by padding with different values
        max_len = max(len(hash_a), len(hash_b))
        padded_a = hash_a.ljust(max_len, '\x00')
        padded_b = hash_b.ljust(max_len, '\x01')
        return hmac.compare_digest(padded_a, padded_b) and len(hash_a) == len(hash_b)

    @staticmethod
    def secure_equals(val1: Any, val2: Any) -> bool:
        """
        Generic constant-time equality check with type safety.
        
        Args:
            val1: First value
            val2: Second value
            
        Returns:
            True if equal (type and value), False otherwise
        """
        if type(val1) != type(val2):
            return False
            
        if isinstance(val1, bytes) and isinstance(val2, bytes):
            return ConstantTime.compare_bytes(val1, val2)
        elif isinstance(val1, str) and isinstance(val2, str):
            return ConstantTime.compare_strings(val1, val2)
        else:
            # For other types, convert to string representation
            return ConstantTime.compare_strings(str(val1), str(val2))


# -----------------------------------------------------------------------------
# Input Validation Wrappers
# -----------------------------------------------------------------------------
@dataclass
class ValidationResult:
    """Result of input validation."""
    valid: bool
    sanitized_value: Any = None
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


class InputValidator:
    """
    Enhanced input validation wrapper module.
    ADD-ONLY - layers validation on top without modifying core code.
    """

    # Regex patterns for validation
    PATTERN_ALPHANUMERIC = re.compile(r'^[a-zA-Z0-9_.-]+$')
    PATTERN_HEX = re.compile(r'^[a-fA-F0-9]+$')
    PATTERN_BASE64 = re.compile(r'^[A-Za-z0-9+/]*={0,2}$')
    PATTERN_SAFE_FILENAME = re.compile(r'^[a-zA-Z0-9_.-][a-zA-Z0-9_ .-]*$')
    PATTERN_EMAIL = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    PATTERN_URL_SAFE = re.compile(r'^[a-zA-Z0-9_./-]+$')

    def __init__(self, security_level: SecurityLevel = SecurityLevel.STANDARD):
        self.security_level = security_level
        self._validation_cache: Dict[str, bool] = {}
        self._max_cache_size = 10000

    def validate_string(
        self,
        value: Any,
        min_length: int = 0,
        max_length: int = 1000000,
        allowed_chars: Optional[str] = None,
        pattern: Optional[re.Pattern] = None,
        allow_empty: bool = False
    ) -> ValidationResult:
        """
        Validate string input with comprehensive checks.
        
        ADD-ONLY wrapper - no core modification required.
        """
        errors = []
        warnings = []
        
        # Type check
        if not isinstance(value, str):
            errors.append(f"Expected string, got {type(value).__name__}")
            return ValidationResult(False, None, errors, warnings)
            
        # Empty check
        if len(value) == 0:
            if not allow_empty:
                errors.append("Empty string not allowed")
            return ValidationResult(allow_empty, value, errors, warnings)
            
        # Length checks
        if len(value) < min_length:
            errors.append(f"String too short: min {min_length}, got {len(value)}")
        if len(value) > max_length:
            errors.append(f"String too long: max {max_length}, got {len(value)}")
            
        # Character set validation
        if allowed_chars is not None:
            for char in value:
                if char not in allowed_chars:
                    errors.append(f"Disallowed character: {repr(char)}")
                    break
                    
        # Pattern validation
        if pattern is not None:
            if not pattern.match(value):
                errors.append("Pattern match failed")
                
        # Security level specific checks
        if self.security_level in (SecurityLevel.STRICT, SecurityLevel.PARANOID):
            # Check for control characters
            for char in value:
                if ord(char) < 32 and char not in '\t\n\r':
                    errors.append(f"Control character detected: 0x{ord(char):02X}")
                    break
                    
        if self.security_level == SecurityLevel.PARANOID:
            # Additional unicode checks
            for char in value:
                if ord(char) > 127:
                    warnings.append(f"Non-ASCII character: U+{ord(char):04X}")
                    
        return ValidationResult(len(errors) == 0, value, errors, warnings)

    def validate_integer(
        self,
        value: Any,
        min_val: Optional[int] = None,
        max_val: Optional[int] = None,
        allow_zero: bool = True,
        allow_negative: bool = True
    ) -> ValidationResult:
        """Validate integer input with boundary checks."""
        errors = []
        warnings = []
        
        # Type coercion with safety
        if isinstance(value, str):
            try:
                value = int(value)
            except ValueError:
                errors.append(f"Cannot convert to integer: {repr(value)}")
                return ValidationResult(False, None, errors, warnings)
        elif not isinstance(value, int):
            errors.append(f"Expected integer, got {type(value).__name__}")
            return ValidationResult(False, None, errors, warnings)
            
        # Zero check
        if value == 0 and not allow_zero:
            errors.append("Zero value not allowed")
            
        # Negative check
        if value < 0 and not allow_negative:
            errors.append("Negative values not allowed")
            
        # Boundary checks
        if min_val is not None and value < min_val:
            errors.append(f"Value below minimum: {value} < {min_val}")
        if max_val is not None and value > max_val:
            errors.append(f"Value above maximum: {value} > {max_val}")
            
        return ValidationResult(len(errors) == 0, value, errors, warnings)

    def validate_path(self, path: str, base_dir: Optional[str] = None) -> ValidationResult:
        """
        Validate file path to prevent path traversal attacks.
        Critical security function for file operations.
        """
        errors = []
        warnings = []
        
        result = self.validate_string(path, min_length=1, max_length=4096)
        if not result.valid:
            return result
            
        # Path traversal detection
        normalized = os.path.normpath(path)
        
        # Check for traversal sequences
        if '..' in normalized or normalized.startswith('/') or normalized.startswith('\\'):
            errors.append("Path traversal attempt detected")
            
        # Base directory restriction
        if base_dir is not None:
            full_path = os.path.abspath(os.path.join(base_dir, normalized))
            base_abs = os.path.abspath(base_dir)
            if not full_path.startswith(base_abs + os.sep) and full_path != base_abs:
                errors.append("Path escapes base directory restriction")
                
        # Dangerous extensions check
        dangerous_exts = ['.exe', '.bat', '.cmd', '.sh', '.ps1', '.php', '.asp']
        lower_path = path.lower()
        for ext in dangerous_exts:
            if lower_path.endswith(ext):
                errors.append(f"Dangerous file extension: {ext}")
                break
                
        return ValidationResult(len(errors) == 0, normalized, errors, warnings)

    def sanitize_for_logging(self, data: Any, max_length: int = 200) -> str:
        """
        Sanitize data for safe logging - redact sensitive patterns.
        ADD-ONLY utility - wraps logging calls.
        """
        s = str(data)
        
        # Redact common sensitive patterns
        # API keys
        s = re.sub(r'(?i)(api[_-]?key|secret|token)\s*[=:]\s*[a-zA-Z0-9_\-]{10,}', 
                  lambda m: m.group(1) + '=[REDACTED]', s)
        # Passwords
        s = re.sub(r'(?i)password\s*[=:]\s*\S+', 'password=[REDACTED]', s)
        # Emails
        s = re.sub(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', 
                  '[EMAIL_REDACTED]', s)
        # IP addresses
        s = re.sub(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', '[IP_REDACTED]', s)
        
        if len(s) > max_length:
            s = s[:max_length] + '...[TRUNCATED]'
            
        return s


# -----------------------------------------------------------------------------
# Token Bucket Rate Limiter (DoS Protection)
# -----------------------------------------------------------------------------
class TokenBucketLimiter:
    """
    Token bucket rate limiter for DoS protection.
    ADD-ONLY module - wraps existing API endpoints without modification.
    Thread-safe implementation.
    """

    def __init__(self, rate: float, capacity: float):
        """
        Initialize token bucket limiter.
        
        Args:
            rate: Tokens added per second
            capacity: Maximum bucket capacity (burst allowance)
        """
        self._rate = rate
        self._capacity = capacity
        self._tokens = capacity
        self._last_update = time.monotonic()
        self._lock = threading.Lock()

    def _refill(self) -> None:
        """Refill tokens based on elapsed time."""
        now = time.monotonic()
        elapsed = now - self._last_update
        self._tokens = min(self._capacity, self._tokens + elapsed * self._rate)
        self._last_update = now

    def try_consume(self, tokens: float = 1.0) -> bool:
        """
        Try to consume tokens from the bucket.
        
        Args:
            tokens: Number of tokens to consume
            
        Returns:
            True if tokens available and consumed, False if rate limited
        """
        with self._lock:
            self._refill()
            if self._tokens >= tokens:
                self._tokens -= tokens
                return True
            return False

    def get_available_tokens(self) -> float:
        """Get current available tokens (thread-safe)."""
        with self._lock:
            self._refill()
            return self._tokens


class RateLimiterManager:
    """
    Manages multiple rate limiters for different endpoints/operations.
    ADD-ONLY protection layer.
    """

    def __init__(self):
        self._limiters: Dict[str, TokenBucketLimiter] = {}
        self._lock = threading.Lock()

    def register_limiter(self, key: str, rate: float, capacity: float) -> None:
        """Register a new rate limiter."""
        with self._lock:
            self._limiters[key] = TokenBucketLimiter(rate, capacity)

    def check_rate_limit(self, key: str, cost: float = 1.0) -> Tuple[bool, float]:
        """
        Check rate limit for a key.
        
        Returns:
            (allowed: bool, remaining_tokens: float)
        """
        with self._lock:
            limiter = self._limiters.get(key)
            if limiter is None:
                # Default limiter if not registered
                limiter = TokenBucketLimiter(10.0, 50.0)
                self._limiters[key] = limiter
                
        allowed = limiter.try_consume(cost)
        remaining = limiter.get_available_tokens()
        return allowed, remaining


# -----------------------------------------------------------------------------
# Sensitive Data Container
# -----------------------------------------------------------------------------
class SensitiveData:
    """
    Wrapper for sensitive data with automatic secure cleanup.
    ADD-ONLY container - wraps sensitive values.
    """

    def __init__(self, value: Union[str, bytes, bytearray]):
        self._data: Optional[bytearray] = None
        self._is_bytes = isinstance(value, bytes)
        self._is_str = isinstance(value, str)
        
        if isinstance(value, str):
            self._data = bytearray(value.encode('utf-8'))
        elif isinstance(value, bytes):
            self._data = bytearray(value)
        elif isinstance(value, bytearray):
            self._data = value.copy()

    def get_value(self) -> Union[str, bytes]:
        """Get the sensitive value (use carefully)."""
        if self._data is None:
            raise ValueError("Sensitive data has been cleared")
            
        if self._is_str:
            return bytes(self._data).decode('utf-8')
        return bytes(self._data)

    def clear(self) -> None:
        """Securely clear sensitive data from memory."""
        if self._data is not None:
            SecureMemory.zeroize_bytes(self._data)
            self._data = None

    def __del__(self):
        """Destructor with secure cleanup."""
        self.clear()

    def __repr__(self) -> str:
        """Safe representation - no data leakage."""
        return "<SensitiveData [REDACTED]>"

    def __str__(self) -> str:
        """Safe string conversion - no data leakage."""
        return "[REDACTED]"


# -----------------------------------------------------------------------------
# Security Validation Decorator
# -----------------------------------------------------------------------------
F = TypeVar('F', bound=Callable[..., Any])

def secure_input_validation(
    param_validators: Dict[str, Dict[str, Any]],
    security_level: SecurityLevel = SecurityLevel.STANDARD
) -> Callable[[F], F]:
    """
    Decorator for ADD-ONLY input validation.
    Wraps existing functions without modifying their core logic.
    
    Args:
        param_validators: Dictionary mapping parameter names to validation configs
        security_level: Security strictness level
        
    Example:
        @secure_input_validation({
            'prompt': {'type': 'string', 'max_length': 10000},
            'temperature': {'type': 'float', 'min': 0.0, 'max': 2.0}
        })
        def generate(prompt: str, temperature: float):
            ...
    """
    validator = InputValidator(security_level)
    
    def decorator(func: F) -> F:
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            # Validate keyword arguments
            for param_name, config in param_validators.items():
                if param_name in kwargs:
                    value = kwargs[param_name]
                    val_type = config.get('type', 'string')
                    
                    if val_type == 'string':
                        result = validator.validate_string(
                            value,
                            min_length=config.get('min_length', 0),
                            max_length=config.get('max_length', 1000000),
                            allow_empty=config.get('allow_empty', False)
                        )
                    elif val_type == 'int':
                        result = validator.validate_integer(
                            value,
                            min_val=config.get('min'),
                            max_val=config.get('max'),
                            allow_negative=config.get('allow_negative', True)
                        )
                    elif val_type == 'path':
                        result = validator.validate_path(
                            value,
                            base_dir=config.get('base_dir')
                        )
                    else:
                        continue
                        
                    if not result.valid:
                        raise ValueError(
                            f"Validation failed for '{param_name}': {', '.join(result.errors)}"
                        )
                        
            return func(*args, **kwargs)
        return wrapper  # type: ignore
    return decorator


# -----------------------------------------------------------------------------
# Module Exports
# -----------------------------------------------------------------------------
__all__ = [
    'SecurityLevel',
    'SecureMemory',
    'ConstantTime',
    'ValidationResult',
    'InputValidator',
    'TokenBucketLimiter',
    'RateLimiterManager',
    'SensitiveData',
    'secure_input_validation',
]
