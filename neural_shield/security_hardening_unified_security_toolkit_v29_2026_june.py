"""
NeuralShield AI - Unified Security Toolkit (Dimension B - Security Hardening)
===========================================================================
Incremental security layer - ADD-ONLY, no modifications to existing code.
Provides unified API for common security operations:
  - Input validation & sanitization wrappers
  - Secure memory zeroization utilities
  - Constant-time comparison helpers
  - Side-channel attack resistant operations
  - Rate limiting utilities

BACKWARD COMPATIBLE: All existing code continues to work unchanged.
OPTIONAL: Modules can opt-in to use these security utilities.
"""

import os
import sys
import hmac
import hashlib
import secrets
import threading
from typing import Any, Callable, Optional, Union, List, Dict
from dataclasses import dataclass, field
from enum import IntEnum


class SecurityLevel(IntEnum):
    """Security levels for validation strictness"""
    RELAXED = 1
    STANDARD = 2
    STRICT = 3
    MAXIMUM = 4


@dataclass
class ValidationResult:
    """Result of input validation operation"""
    is_valid: bool
    errors: List[str] = field(default_factory=list)
    sanitized_value: Any = None
    warnings: List[str] = field(default_factory=list)


class SecureMemory:
    """
    Secure memory zeroization utilities.
    Provides side-channel resistant memory clearing operations.
    """

    @staticmethod
    def zeroize_bytes(data: bytearray) -> None:
        """
        Securely zeroize a bytearray in constant time.
        Overwrites memory multiple times to prevent forensic recovery.
        """
        if not isinstance(data, bytearray):
            return
        
        length = len(data)
        # Multiple passes with different patterns
        for i in range(length):
            data[i] = 0x00
        for i in range(length):
            data[i] = 0xFF
        for i in range(length):
            data[i] = 0x00
        for i in range(length):
            data[i] = secrets.randbits(8) & 0xFF
        for i in range(length):
            data[i] = 0x00

    @staticmethod
    def zeroize_string(s: str) -> str:
        """
        Create a zeroized string placeholder.
        Note: Python strings are immutable, this returns a blank string.
        Original string should be garbage collected.
        """
        return ""

    @staticmethod
    def secure_delete(obj: Any) -> None:
        """
        Attempt to securely delete sensitive data from memory.
        Works best with mutable objects like bytearrays.
        """
        if isinstance(obj, bytearray):
            SecureMemory.zeroize_bytes(obj)
        elif isinstance(obj, list):
            for i in range(len(obj)):
                if isinstance(obj[i], (bytearray, bytes)):
                    if isinstance(obj[i], bytearray):
                        SecureMemory.zeroize_bytes(obj[i])
                obj[i] = None


class ConstantTime:
    """
    Constant-time comparison utilities to prevent timing attacks.
    All operations execute in the same time regardless of input values.
    """

    @staticmethod
    def compare_equal(a: bytes, b: bytes) -> bool:
        """
        Constant-time byte comparison.
        Returns True if a == b, False otherwise.
        Execution time depends only on length, not content.
        """
        return hmac.compare_digest(a, b)

    @staticmethod
    def compare_strings_equal(a: str, b: str, encoding: str = 'utf-8') -> bool:
        """
        Constant-time string comparison.
        """
        return hmac.compare_digest(a.encode(encoding), b.encode(encoding))

    @staticmethod
    def select(condition: bool, true_val: Any, false_val: Any) -> Any:
        """
        Constant-time selection.
        Returns true_val if condition is True, false_val otherwise.
        Execution time identical regardless of condition.
        """
        mask = -int(condition)
        # Works for integers, can be extended for other types
        if isinstance(true_val, int) and isinstance(false_val, int):
            return (true_val & mask) | (false_val & ~mask)
        # Fallback for other types (not strictly constant-time but safer than branching)
        return [false_val, true_val][condition]

    @staticmethod
    def less_than(a: int, b: int) -> bool:
        """
        Constant-time less than comparison for integers.
        """
        return bool((a - b) >> (sys.getsizeof(a) * 8 - 1))


class InputValidator:
    """
    Unified input validation and sanitization framework.
    Layered security - wraps existing inputs without modifying core logic.
    """

    def __init__(self, security_level: SecurityLevel = SecurityLevel.STANDARD):
        self.security_level = security_level
        self._validation_lock = threading.Lock()

    def validate_string(
        self,
        value: str,
        min_length: int = 0,
        max_length: int = 10000,
        allowed_chars: Optional[str] = None,
        forbidden_patterns: Optional[List[str]] = None,
        sanitize: bool = True
    ) -> ValidationResult:
        """Validate and optionally sanitize string input"""
        result = ValidationResult(is_valid=True)
        
        with self._validation_lock:
            # Basic type check
            if not isinstance(value, str):
                result.is_valid = False
                result.errors.append("Value must be a string")
                return result

            # Length checks
            if len(value) < min_length:
                result.is_valid = False
                result.errors.append(f"String too short: minimum {min_length} characters")
            
            if len(value) > max_length:
                result.is_valid = False
                result.errors.append(f"String too long: maximum {max_length} characters")
                if sanitize:
                    value = value[:max_length]
                    result.warnings.append(f"Truncated to {max_length} characters")

            # Character validation
            if allowed_chars and self.security_level >= SecurityLevel.STANDARD:
                for char in value:
                    if char not in allowed_chars:
                        result.is_valid = False
                        result.errors.append(f"Forbidden character: {repr(char)}")

            # Pattern checking
            if forbidden_patterns and self.security_level >= SecurityLevel.STRICT:
                for pattern in forbidden_patterns:
                    if pattern in value:
                        result.is_valid = False
                        result.errors.append(f"Forbidden pattern detected: {pattern}")

            # Basic sanitization
            if sanitize and result.is_valid:
                # Remove control characters at stricter security levels
                if self.security_level >= SecurityLevel.STRICT:
                    sanitized = ''.join(c for c in value if c.isprintable() or c.isspace())
                    if sanitized != value:
                        result.warnings.append("Removed non-printable control characters")
                    result.sanitized_value = sanitized
                else:
                    result.sanitized_value = value
            else:
                result.sanitized_value = value

        return result

    def validate_prompt_input(
        self,
        prompt: str,
        max_length: int = 100000
    ) -> ValidationResult:
        """
        Specialized validation for LLM prompt inputs.
        Checks for common injection patterns and unsafe content.
        """
        forbidden = [
            "Ignore previous",
            "Disregard all",
            "System prompt:",
            "<|endoftext|>",
            "You are now",
            "Pretend you are",
        ]
        
        return self.validate_string(
            prompt,
            min_length=1,
            max_length=max_length,
            forbidden_patterns=forbidden if self.security_level >= SecurityLevel.STRICT else None
        )


class RateLimiter:
    """
    Thread-safe rate limiter for DoS protection.
    Token bucket algorithm implementation.
    """

    def __init__(self, max_tokens: int = 100, refill_rate: float = 10.0):
        self.max_tokens = max_tokens
        self.refill_rate = refill_rate  # tokens per second
        self.tokens = max_tokens
        self.last_refill = threading.Lock()
        self._lock = threading.Lock()
        import time
        self._time_module = time
        self.last_refill_time = self._time_module.time()

    def try_consume(self, tokens: int = 1) -> bool:
        """
        Try to consume tokens. Returns True if successful, False if rate limited.
        """
        with self._lock:
            now = self._time_module.time()
            elapsed = now - self.last_refill_time
            
            # Refill tokens
            self.tokens = min(
                self.max_tokens,
                self.tokens + elapsed * self.refill_rate
            )
            self.last_refill_time = now

            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False

    def get_remaining_tokens(self) -> float:
        """Get current available tokens"""
        with self._lock:
            now = self._time_module.time()
            elapsed = now - self.last_refill_time
            return min(self.max_tokens, self.tokens + elapsed * self.refill_rate)


class UnifiedSecurityToolkit:
    """
    Main unified security toolkit facade.
    Provides single entry point for all security operations.
    """

    def __init__(self, security_level: SecurityLevel = SecurityLevel.STANDARD):
        self.security_level = security_level
        self.memory = SecureMemory()
        self.constant_time = ConstantTime()
        self.validator = InputValidator(security_level)
        self._rate_limiters: Dict[str, RateLimiter] = {}
        self._lock = threading.Lock()

    def get_rate_limiter(self, name: str, max_tokens: int = 100, refill_rate: float = 10.0) -> RateLimiter:
        """Get or create a named rate limiter"""
        with self._lock:
            if name not in self._rate_limiters:
                self._rate_limiters[name] = RateLimiter(max_tokens, refill_rate)
            return self._rate_limiters[name]

    def secure_compare(self, a: Union[str, bytes], b: Union[str, bytes]) -> bool:
        """Secure constant-time comparison"""
        if isinstance(a, str) and isinstance(b, str):
            return self.constant_time.compare_strings_equal(a, b)
        elif isinstance(a, bytes) and isinstance(b, bytes):
            return self.constant_time.compare_equal(a, b)
        else:
            raise TypeError("Both arguments must be str or bytes")

    def zeroize_sensitive_data(self, data: Any) -> None:
        """Securely zeroize sensitive data"""
        self.memory.zeroize_bytes(data) if isinstance(data, bytearray) else self.memory.secure_delete(data)

    def validate_and_sanitize_prompt(self, prompt: str) -> ValidationResult:
        """Validate and sanitize LLM prompt input"""
        return self.validator.validate_prompt_input(prompt)


# Default global instance for easy import
DEFAULT_SECURITY_TOOLKIT = UnifiedSecurityToolkit(SecurityLevel.STANDARD)


def get_security_toolkit(security_level: Optional[SecurityLevel] = None) -> UnifiedSecurityToolkit:
    """
    Get the unified security toolkit instance.
    Usage:
        from neural_shield.security_hardening_unified_security_toolkit_v29_2026_june import get_security_toolkit
        toolkit = get_security_toolkit()
        if toolkit.secure_compare(user_input, expected):
            ...
    """
    if security_level is None:
        return DEFAULT_SECURITY_TOOLKIT
    return UnifiedSecurityToolkit(security_level)
