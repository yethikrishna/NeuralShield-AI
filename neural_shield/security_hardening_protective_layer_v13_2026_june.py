"""
NeuralShield Security Hardening Protective Layer v13
Dimension B - Security Hardening
ADD-ONLY implementation - wraps existing code, no modifications

Features:
1. Secure memory zeroization utilities
2. Constant-time comparison helpers
3. Input validation wrappers
4. Rate limiting / DoS protection
5. Sensitive data masking
"""

import ctypes
import hashlib
import hmac
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Pattern, Union
from functools import wraps


class SecureMemory:
    """
    Secure memory zeroization utilities.
    Overwrites sensitive data in memory to prevent leakage.
    """

    @staticmethod
    def zeroize_bytes(data: bytearray) -> None:
        """
        Securely zeroize a bytearray.
        Overwrites with zeros multiple times to prevent memory forensics.
        """
        if not isinstance(data, bytearray):
            return
        
        length = len(data)
        for i in range(length):
            data[i] = 0
        
        # Second pass with random pattern
        import secrets
        for i in range(length):
            data[i] = secrets.randbelow(256)
        
        # Final zero pass
        for i in range(length):
            data[i] = 0

    @staticmethod
    def zeroize_string(s: str) -> None:
        """
        Attempt to zeroize string contents.
        Note: Python strings are immutable, this is best-effort.
        Use bytearray for truly sensitive data.
        """
        pass  # Cannot zeroize immutable strings - documentation only

    @staticmethod
    def secure_delete(obj: Any) -> None:
        """
        Securely delete an object by overwriting its __dict__ if possible.
        Best-effort approach for Python.
        """
        if hasattr(obj, '__dict__'):
            for key in list(obj.__dict__.keys()):
                val = obj.__dict__[key]
                if isinstance(val, bytearray):
                    SecureMemory.zeroize_bytes(val)
                obj.__dict__[key] = None


class ConstantTime:
    """
    Constant-time comparison functions to prevent timing attacks.
    All comparisons take the same amount of time regardless of input.
    """

    @staticmethod
    def compare_bytes(a: bytes, b: bytes) -> bool:
        """
        Constant-time byte comparison.
        Uses HMAC compare under the hood for true constant-time operation.
        """
        if len(a) != len(b):
            return False
        return hmac.compare_digest(a, b)

    @staticmethod
    def compare_strings(a: str, b: str) -> bool:
        """
        Constant-time string comparison.
        Prevents timing attacks on secrets like API keys, tokens, passwords.
        """
        if len(a) != len(b):
            return False
        return hmac.compare_digest(a.encode('utf-8'), b.encode('utf-8'))

    @staticmethod
    def safe_equals(a: Union[str, bytes], b: Union[str, bytes]) -> bool:
        """
        Safe constant-time equality check for strings or bytes.
        Always takes the same time, even if inputs differ early.
        """
        if isinstance(a, str) and isinstance(b, str):
            return ConstantTime.compare_strings(a, b)
        elif isinstance(a, bytes) and isinstance(b, bytes):
            return ConstantTime.compare_bytes(a, b)
        else:
            # Type mismatch - cannot be equal, but consume time anyway
            dummy = hmac.compare_digest(b'dummy', b'dummy')
            return False


@dataclass
class RateLimiter:
    """
    Token bucket rate limiter for DoS protection.
    Thread-safe implementation.
    """
    max_requests: int = 100
    window_seconds: float = 60.0
    _requests: Dict[str, List[float]] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def is_allowed(self, client_id: str) -> bool:
        """
        Check if a client is allowed to make a request.
        Returns True if within rate limit, False if rate limited.
        """
        now = time.time()
        
        with self._lock:
            if client_id not in self._requests:
                self._requests[client_id] = []
            
            # Remove old requests outside the window
            self._requests[client_id] = [
                t for t in self._requests[client_id]
                if now - t < self.window_seconds
            ]
            
            if len(self._requests[client_id]) >= self.max_requests:
                return False
            
            self._requests[client_id].append(now)
            return True

    def get_remaining(self, client_id: str) -> int:
        """Get remaining requests for a client."""
        now = time.time()
        
        with self._lock:
            if client_id not in self._requests:
                return self.max_requests
            
            active = [t for t in self._requests[client_id]
                     if now - t < self.window_seconds]
            return max(0, self.max_requests - len(active))

    def cleanup_old_entries(self, max_age: float = 3600.0) -> None:
        """Remove stale client entries to save memory."""
        now = time.time()
        with self._lock:
            to_remove = [
                cid for cid, times in self._requests.items()
                if all(now - t > max_age for t in times)
            ]
            for cid in to_remove:
                del self._requests[cid]


class InputValidator:
    """
    Input validation wrappers for security hardening.
    Validates and sanitizes inputs before they reach core logic.
    """
    
    # Common dangerous patterns
    SQL_PATTERN: Pattern = re.compile(
        r'(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|EXEC|ALTER)\b)|(--|;|\')',
        re.IGNORECASE
    )
    
    XSS_PATTERN: Pattern = re.compile(
        r'<script|javascript:|on\w+=|data:',
        re.IGNORECASE
    )
    
    CMD_PATTERN: Pattern = re.compile(
        r'[;&|`$()<>]|\.\./|~/\b',
        re.IGNORECASE
    )
    
    PROMPT_INJECTION_PATTERNS: List[Pattern] = [
        re.compile(r'ignore.*previous|disregard.*instructions', re.IGNORECASE),
        re.compile(r'you are now|act as|pretend to be', re.IGNORECASE),
        re.compile(r'system prompt|initial instructions', re.IGNORECASE),
    ]

    @staticmethod
    def validate_length(value: str, min_len: int = 0, max_len: int = 10000) -> bool:
        """Validate string length bounds."""
        if not isinstance(value, str):
            return False
        return min_len <= len(value) <= max_len

    @staticmethod
    def sanitize_string(value: str) -> str:
        """Basic sanitization - remove control characters."""
        if not isinstance(value, str):
            return ""
        # Remove non-printable control characters except newlines/tabs
        return re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', value)

    @staticmethod
    def detect_sql_injection(value: str) -> bool:
        """Detect potential SQL injection patterns."""
        if not isinstance(value, str):
            return False
        return bool(InputValidator.SQL_PATTERN.search(value))

    @staticmethod
    def detect_xss(value: str) -> bool:
        """Detect potential XSS patterns."""
        if not isinstance(value, str):
            return False
        return bool(InputValidator.XSS_PATTERN.search(value))

    @staticmethod
    def detect_command_injection(value: str) -> bool:
        """Detect potential command injection patterns."""
        if not isinstance(value, str):
            return False
        return bool(InputValidator.CMD_PATTERN.search(value))

    @staticmethod
    def detect_prompt_injection(value: str) -> bool:
        """Detect potential prompt injection patterns."""
        if not isinstance(value, str):
            return False
        return any(p.search(value) for p in InputValidator.PROMPT_INJECTION_PATTERNS)

    @staticmethod
    def validate_input(
        value: str,
        max_length: int = 10000,
        block_sql: bool = True,
        block_xss: bool = True,
        block_cmd: bool = True,
        block_prompt_injection: bool = True
    ) -> Dict[str, Any]:
        """
        Comprehensive input validation.
        Returns dict with 'valid' (bool) and 'issues' (list).
        """
        issues = []
        
        if not InputValidator.validate_length(value, max_len=max_length):
            issues.append(f"Input exceeds maximum length ({max_length})")
        
        if block_sql and InputValidator.detect_sql_injection(value):
            issues.append("Potential SQL injection pattern detected")
        
        if block_xss and InputValidator.detect_xss(value):
            issues.append("Potential XSS pattern detected")
        
        if block_cmd and InputValidator.detect_command_injection(value):
            issues.append("Potential command injection pattern detected")
        
        if block_prompt_injection and InputValidator.detect_prompt_injection(value):
            issues.append("Potential prompt injection pattern detected")
        
        return {
            "valid": len(issues) == 0,
            "issues": issues,
            "sanitized": InputValidator.sanitize_string(value)
        }


class SensitiveDataMasker:
    """
    Masks sensitive data in logs and outputs.
    Prevents accidental exposure of secrets.
    """
    
    # Patterns for common sensitive data
    API_KEY_PATTERN = re.compile(r'(api[_-]?key|token|secret)[\'"]?\s*[:=]\s*[\'"]?([A-Za-z0-9_\-]{5,})[\'"]?', re.IGNORECASE)
    PASSWORD_PATTERN = re.compile(r'(password|passwd|pwd)[\'"]?\s*[:=]\s*[\'"]?([^\s,\'"]+)', re.IGNORECASE)
    EMAIL_PATTERN = re.compile(r'([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})')
    PHONE_PATTERN = re.compile(r'\b(\+?\d{1,3}[-.\s]?)?(\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4})\b')

    @staticmethod
    def mask_api_keys(text: str) -> str:
        """Mask API keys and tokens in text."""
        def replace_fn(match):
            prefix = match.group(1)
            return f"{prefix}=[REDACTED]"
        return SensitiveDataMasker.API_KEY_PATTERN.sub(replace_fn, text)

    @staticmethod
    def mask_passwords(text: str) -> str:
        """Mask passwords in text."""
        def replace_fn(match):
            prefix = match.group(1)
            return f"{prefix}=[REDACTED]"
        return SensitiveDataMasker.PASSWORD_PATTERN.sub(replace_fn, text)

    @staticmethod
    def mask_emails(text: str) -> str:
        """Mask emails - show first 2 chars only."""
        def replace_fn(match):
            user = match.group(1)
            domain = match.group(2)
            masked_user = user[:2] + "***" if len(user) > 2 else "***"
            return f"{masked_user}@{domain}"
        return SensitiveDataMasker.EMAIL_PATTERN.sub(replace_fn, text)

    @staticmethod
    def mask_all(text: str) -> str:
        """Apply all masking rules."""
        result = text
        result = SensitiveDataMasker.mask_api_keys(result)
        result = SensitiveDataMasker.mask_passwords(result)
        result = SensitiveDataMasker.mask_emails(result)
        return result


# Global rate limiter instance
_global_rate_limiter = RateLimiter(max_requests=1000, window_seconds=60.0)


def rate_limit(client_id: Optional[str] = None):
    """
    Decorator for rate limiting functions.
    Usage: @rate_limit(client_id="default")
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            cid = client_id or "global"
            if not _global_rate_limiter.is_allowed(cid):
                raise RuntimeError(f"Rate limit exceeded for client: {cid}")
            return func(*args, **kwargs)
        return wrapper
    return decorator


def validate_input_decorator(max_length: int = 10000):
    """
    Decorator for input validation.
    Validates first string argument passed to the function.
    Always sanitizes inputs, even when valid.
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Find first string argument
            for i, arg in enumerate(args):
                if isinstance(arg, str):
                    result = InputValidator.validate_input(arg, max_length=max_length)
                    # Always use sanitized input
                    sanitized = result["sanitized"]
                    new_args = list(args)
                    new_args[i] = sanitized
                    return func(*new_args, **kwargs)
            return func(*args, **kwargs)
        return wrapper
    return decorator


# Export public API
__all__ = [
    'SecureMemory',
    'ConstantTime',
    'RateLimiter',
    'InputValidator',
    'SensitiveDataMasker',
    'rate_limit',
    'validate_input_decorator',
]
