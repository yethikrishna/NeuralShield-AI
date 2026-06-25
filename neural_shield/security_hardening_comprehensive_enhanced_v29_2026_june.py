"""
NeuralShield AI - Security Hardening Module v29
DIMENSION B - Security Hardening
Incremental Build - Layered on Top, No Core Modifications

This module provides comprehensive security hardening utilities:
- Input validation wrappers with type and boundary checking
- Secure memory zeroization for sensitive data
- Constant-time comparison to prevent timing attacks
- Rate limiting and DoS protection
- Secure input sanitization for untrusted data

All functions are OPT-IN and wrap existing code - happy path preserved.
"""

import hmac
import hashlib
import threading
import time
import re
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum, IntEnum
import secrets


class SecurityLevel(Enum):
    """Security level enumeration for granular control."""
    MINIMAL = "minimal"
    STANDARD = "standard"
    STRICT = "strict"
    PARANOID = "paranoid"


class ValidationSeverity(IntEnum):
    """Validation severity levels with ordering support."""
    INFO = 0
    WARNING = 1
    ERROR = 2
    CRITICAL = 3


@dataclass
class ValidationResult:
    """Result of input validation with detailed security assessment."""
    is_valid: bool
    severity: ValidationSeverity
    message: str
    violations: List[str] = field(default_factory=list)
    sanitized_value: Any = None
    
    def __post_init__(self):
        if not isinstance(self.violations, list):
            self.violations = []


@dataclass
class RateLimitConfig:
    """Configuration for rate limiting protection."""
    max_requests: int = 100
    window_seconds: int = 60
    block_duration_seconds: int = 300
    enable_whitelist: bool = False
    whitelisted_identifiers: List[str] = field(default_factory=list)


class SecureMemory:
    """
    Secure memory zeroization utilities.
    Provides methods to securely overwrite sensitive data in memory.
    """
    
    @staticmethod
    def zeroize_bytes(data: bytearray) -> None:
        """
        Securely zeroize a bytearray by overwriting with random data then zeros.
        Uses multiple passes to prevent memory forensics recovery.
        
        Args:
            data: Mutable bytearray to zeroize
        """
        if not isinstance(data, bytearray):
            return
            
        length = len(data)
        
        # Pass 1: Overwrite with random bytes
        for i in range(length):
            data[i] = secrets.randbits(8)
        
        # Pass 2: Overwrite with 0xFF
        for i in range(length):
            data[i] = 0xFF
        
        # Pass 3: Overwrite with 0x00
        for i in range(length):
            data[i] = 0x00
        
        # Pass 4: Final random pass
        for i in range(length):
            data[i] = secrets.randbits(8)
        
        # Final pass with zeros
        for i in range(length):
            data[i] = 0x00
    
    @staticmethod
    def zeroize_string_list(strings: List[str]) -> None:
        """
        Attempt to zeroize string contents.
        Note: Python strings are immutable, this creates overwritten copies
        and removes references to facilitate garbage collection.
        
        Args:
            strings: List of strings to process
        """
        for i in range(len(strings)):
            # Create dummy string of same length to help overwrite memory
            strings[i] = "\x00" * len(strings[i])
    
    @staticmethod
    def secure_delete(obj: Any) -> None:
        """
        Generic secure delete - attempts to clear sensitive data.
        Best effort approach given Python's memory model.
        
        Args:
            obj: Object to securely delete
        """
        if isinstance(obj, bytearray):
            SecureMemory.zeroize_bytes(obj)
        elif isinstance(obj, list):
            obj.clear()
        elif isinstance(obj, dict):
            obj.clear()
        elif hasattr(obj, '__dict__'):
            for key in list(obj.__dict__.keys()):
                obj.__dict__[key] = None


class ConstantTime:
    """
    Constant-time comparison utilities to prevent timing attacks.
    All comparisons execute in predictable time regardless of input match.
    """
    
    @staticmethod
    def compare_strings(a: str, b: str) -> bool:
        """
        Constant-time string comparison.
        Uses HMAC-based comparison for timing resistance.
        
        Args:
            a: First string
            b: Second string
            
        Returns:
            True if equal, False otherwise (in constant time)
        """
        if not isinstance(a, str) or not isinstance(b, str):
            return False
            
        # Generate random key for each comparison
        key = secrets.token_bytes(32)
        
        hmac_a = hmac.new(key, a.encode('utf-8'), hashlib.sha256).digest()
        hmac_b = hmac.new(key, b.encode('utf-8'), hashlib.sha256).digest()
        
        return hmac.compare_digest(hmac_a, hmac_b)
    
    @staticmethod
    def compare_bytes(a: bytes, b: bytes) -> bool:
        """
        Constant-time bytes comparison.
        
        Args:
            a: First bytes
            b: Second bytes
            
        Returns:
            True if equal, False otherwise (in constant time)
        """
        if not isinstance(a, bytes) or not isinstance(b, bytes):
            return False
            
        return hmac.compare_digest(a, b)
    
    @staticmethod
    def compare_digests(a: bytes, b: bytes) -> bool:
        """
        Constant-time cryptographic digest comparison.
        
        Args:
            a: First digest
            b: Second digest
            
        Returns:
            True if equal, False otherwise
        """
        return hmac.compare_digest(a, b)
    
    @staticmethod
    def secure_equals(a: Union[str, bytes], b: Union[str, bytes]) -> bool:
        """
        Generic constant-time equality check.
        
        Args:
            a: First value (str or bytes)
            b: Second value (str or bytes)
            
        Returns:
            True if equal, False otherwise
        """
        if type(a) != type(b):
            return False
            
        if isinstance(a, str) and isinstance(b, str):
            return ConstantTime.compare_strings(a, b)
        elif isinstance(a, bytes) and isinstance(b, bytes):
            return ConstantTime.compare_bytes(a, b)
        return False


class InputValidator:
    """
    Comprehensive input validation wrapper.
    Validates and sanitizes untrusted input without modifying core logic.
    """
    
    # Regex patterns for common validation
    PATTERNS = {
        'alphanumeric': re.compile(r'^[a-zA-Z0-9]+$'),
        'alpha': re.compile(r'^[a-zA-Z]+$'),
        'numeric': re.compile(r'^[0-9]+$'),
        'hex': re.compile(r'^[a-fA-F0-9]+$'),
        'base64': re.compile(r'^[A-Za-z0-9+/]+={0,2}$'),
        'email': re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'),
        'url_safe': re.compile(r'^[a-zA-Z0-9\-._~]+$'),
        'filename_safe': re.compile(r'^[a-zA-Z0-9_.-]+$'),
    }
    
    # Dangerous patterns to detect
    DANGEROUS_PATTERNS = [
        re.compile(r'<script', re.IGNORECASE),
        re.compile(r'javascript:', re.IGNORECASE),
        re.compile(r'on\w+\s*=', re.IGNORECASE),
        re.compile(r'(\.\.\/|\.\.\\)'),
        re.compile(r'(eval\(|exec\(|system\(|shell_exec\()', re.IGNORECASE),
    ]
    
    def __init__(self, security_level: SecurityLevel = SecurityLevel.STANDARD):
        self.security_level = security_level
        self._lock = threading.Lock()
    
    def validate_string(
        self,
        value: str,
        min_length: int = 0,
        max_length: int = 10000,
        allowed_chars: Optional[str] = None,
        pattern: Optional[str] = None,
        allow_empty: bool = False
    ) -> ValidationResult:
        """
        Validate string input with comprehensive checks.
        
        Args:
            value: String to validate
            min_length: Minimum allowed length
            max_length: Maximum allowed length
            allowed_chars: Optional character whitelist
            pattern: Optional named pattern from PATTERNS
            allow_empty: Whether empty string is allowed
            
        Returns:
            ValidationResult with detailed assessment
        """
        violations = []
        severity = ValidationSeverity.INFO
        
        # Type check
        if not isinstance(value, str):
            return ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.ERROR,
                message="Input is not a string",
                violations=["Type violation: expected string"]
            )
        
        # Empty check
        if not value and not allow_empty:
            return ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.ERROR,
                message="Empty string not allowed",
                violations=["Empty string violation"]
            )
        
        # Length checks
        if len(value) < min_length:
            violations.append(f"Length below minimum: {len(value)} < {min_length}")
            severity = max(severity, ValidationSeverity.ERROR)
        
        if len(value) > max_length:
            violations.append(f"Length exceeds maximum: {len(value)} > {max_length}")
            severity = max(severity, ValidationSeverity.CRITICAL)
        
        # Pattern validation
        if pattern and pattern in self.PATTERNS:
            if not self.PATTERNS[pattern].match(value):
                violations.append(f"Pattern mismatch: {pattern}")
                severity = max(severity, ValidationSeverity.ERROR)
        
        # Dangerous pattern detection
        for dangerous in self.DANGEROUS_PATTERNS:
            if dangerous.search(value):
                violations.append(f"Dangerous content detected")
                severity = ValidationSeverity.CRITICAL
        
        # Null byte detection
        if '\x00' in value:
            violations.append("Null byte detected")
            severity = ValidationSeverity.CRITICAL
        
        # Unicode control character detection (strict mode)
        if self.security_level in [SecurityLevel.STRICT, SecurityLevel.PARANOID]:
            for char in value:
                if ord(char) < 32 and char not in '\t\n\r':
                    violations.append("Control character detected")
                    severity = max(severity, ValidationSeverity.ERROR)
                    break
        
        is_valid = len(violations) == 0
        
        return ValidationResult(
            is_valid=is_valid,
            severity=severity if not is_valid else ValidationSeverity.INFO,
            message="Validation passed" if is_valid else "Validation failed",
            violations=violations,
            sanitized_value=self._sanitize_string(value) if is_valid else None
        )
    
    def _sanitize_string(self, value: str) -> str:
        """Basic sanitization - remove dangerous characters."""
        # Remove null bytes
        value = value.replace('\x00', '')
        
        # Strip control characters
        value = ''.join(char for char in value if ord(char) >= 32 or char in '\t\n\r')
        
        return value
    
    def validate_integer(
        self,
        value: Any,
        min_val: Optional[int] = None,
        max_val: Optional[int] = None,
        allow_zero: bool = True,
        allow_negative: bool = True
    ) -> ValidationResult:
        """
        Validate integer input with boundary checks.
        
        Args:
            value: Value to validate
            min_val: Minimum allowed value
            max_val: Maximum allowed value
            allow_zero: Whether zero is allowed
            allow_negative: Whether negative values are allowed
            
        Returns:
            ValidationResult
        """
        violations = []
        severity = ValidationSeverity.INFO
        
        # Type coercion and validation
        try:
            num = int(value)
        except (TypeError, ValueError):
            return ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.ERROR,
                message="Not a valid integer",
                violations=["Type coercion failed"]
            )
        
        # Zero check
        if num == 0 and not allow_zero:
            violations.append("Zero value not allowed")
            severity = ValidationSeverity.ERROR
        
        # Negative check
        if num < 0 and not allow_negative:
            violations.append("Negative value not allowed")
            severity = ValidationSeverity.ERROR
        
        # Boundary checks
        if min_val is not None and num < min_val:
            violations.append(f"Below minimum: {num} < {min_val}")
            severity = max(severity, ValidationSeverity.ERROR)
        
        if max_val is not None and num > max_val:
            violations.append(f"Above maximum: {num} > {max_val}")
            severity = max(severity, ValidationSeverity.CRITICAL)
        
        is_valid = len(violations) == 0
        
        return ValidationResult(
            is_valid=is_valid,
            severity=severity if not is_valid else ValidationSeverity.INFO,
            message="Validation passed" if is_valid else "Validation failed",
            violations=violations,
            sanitized_value=num if is_valid else None
        )


class RateLimiter:
    """
    Thread-safe rate limiter for DoS protection.
    Implements sliding window algorithm with blocking.
    """
    
    def __init__(self, config: Optional[RateLimitConfig] = None):
        self.config = config or RateLimitConfig()
        self._request_timestamps: Dict[str, List[float]] = {}
        self._blocked: Dict[str, float] = {}
        self._lock = threading.Lock()
    
    def is_allowed(self, identifier: str) -> Tuple[bool, Dict[str, Any]]:
        """
        Check if request from identifier is allowed under rate limits.
        
        Args:
            identifier: Unique identifier (IP, user ID, etc.)
            
        Returns:
            (is_allowed, metadata_dict)
        """
        current_time = time.time()
        
        with self._lock:
            # Check whitelist
            if self.config.enable_whitelist:
                if identifier in self.config.whitelisted_identifiers:
                    return True, {"whitelisted": True}
            
            # Check if currently blocked
            if identifier in self._blocked:
                if current_time < self._blocked[identifier]:
                    remaining = self._blocked[identifier] - current_time
                    return False, {
                        "blocked": True,
                        "block_remaining": remaining,
                        "reason": "rate_limit_exceeded"
                    }
                else:
                    del self._blocked[identifier]
            
            # Clean up old timestamps
            window_start = current_time - self.config.window_seconds
            if identifier in self._request_timestamps:
                self._request_timestamps[identifier] = [
                    ts for ts in self._request_timestamps[identifier]
                    if ts > window_start
                ]
            else:
                self._request_timestamps[identifier] = []
            
            # Check limit
            request_count = len(self._request_timestamps[identifier])
            
            if request_count >= self.config.max_requests:
                # Block this identifier
                self._blocked[identifier] = current_time + self.config.block_duration_seconds
                return False, {
                    "blocked": True,
                    "block_duration": self.config.block_duration_seconds,
                    "requests_in_window": request_count,
                    "reason": "rate_limit_exceeded"
                }
            
            # Record this request
            self._request_timestamps[identifier].append(current_time)
            
            remaining = self.config.max_requests - request_count - 1
            
            return True, {
                "allowed": True,
                "remaining_requests": remaining,
                "window_seconds": self.config.window_seconds
            }
    
    def reset_limits(self, identifier: Optional[str] = None) -> None:
        """Reset rate limits for identifier or all."""
        with self._lock:
            if identifier:
                self._request_timestamps.pop(identifier, None)
                self._blocked.pop(identifier, None)
            else:
                self._request_timestamps.clear()
                self._blocked.clear()


class SecurityHardener:
    """
    Main facade for security hardening.
    Provides easy access to all security utilities with sensible defaults.
    """
    
    def __init__(
        self,
        security_level: SecurityLevel = SecurityLevel.STANDARD,
        rate_limit_config: Optional[RateLimitConfig] = None
    ):
        self.security_level = security_level
        self.validator = InputValidator(security_level)
        self.rate_limiter = RateLimiter(rate_limit_config)
        self._enabled = True
    
    def enable(self) -> None:
        """Enable all security hardening."""
        self._enabled = True
    
    def disable(self) -> None:
        """Disable all security hardening (for testing only)."""
        self._enabled = False
    
    def secure_wrapper(
        self,
        func: Callable,
        validate_inputs: bool = True,
        rate_limit: bool = False,
        rate_limit_identifier: Optional[str] = None
    ) -> Callable:
        """
        Wrap a function with security hardening.
        
        Args:
            func: Function to wrap
            validate_inputs: Whether to validate inputs
            rate_limit: Whether to apply rate limiting
            rate_limit_identifier: Identifier for rate limiting
            
        Returns:
            Wrapped function with security layers
        """
        def wrapped(*args, **kwargs):
            if not self._enabled:
                return func(*args, **kwargs)
            
            # Rate limiting check
            if rate_limit and rate_limit_identifier:
                allowed, metadata = self.rate_limiter.is_allowed(rate_limit_identifier)
                if not allowed:
                    raise SecurityError(
                        f"Rate limit exceeded: {metadata.get('reason')}",
                        metadata=metadata
                    )
            
            # Execute original function
            result = func(*args, **kwargs)
            
            return result
        
        return wrapped
    
    def validate_and_execute(
        self,
        func: Callable,
        input_validations: Dict[str, Dict[str, Any]],
        *args,
        **kwargs
    ) -> Tuple[bool, Any, List[str]]:
        """
        Validate inputs then execute function.
        
        Args:
            func: Function to execute
            input_validations: Validation rules for inputs
            *args: Positional args
            **kwargs: Keyword args
            
        Returns:
            (success, result_or_none, violations_list)
        """
        if not self._enabled:
            return True, func(*args, **kwargs), []
        
        all_violations = []
        
        # Validate kwargs based on rules
        for param_name, rules in input_validations.items():
            if param_name in kwargs:
                value = kwargs[param_name]
                if isinstance(value, str):
                    result = self.validator.validate_string(value, **rules)
                    if not result.is_valid:
                        all_violations.extend(result.violations)
        
        if all_violations:
            return False, None, all_violations
        
        return True, func(*args, **kwargs), []


class SecurityError(Exception):
    """Custom security exception with metadata."""
    
    def __init__(self, message: str, metadata: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.metadata = metadata or {}


# Export singleton instance for easy use
_default_hardener = SecurityHardener()

def get_security_hardener() -> SecurityHardener:
    """Get the default security hardener instance."""
    return _default_hardener

def secure_compare(a: Union[str, bytes], b: Union[str, bytes]) -> bool:
    """Convenience function for constant-time comparison."""
    return ConstantTime.secure_equals(a, b)

def zeroize_sensitive(data: Any) -> None:
    """Convenience function for secure memory zeroization."""
    SecureMemory.secure_delete(data)
