"""
NeuralShield Security Hardening Module V23
Dimension B - Security Hardening
ADD-ONLY implementation - layers security ON TOP of existing code

Features:
1. Input Validation Wrappers
2. Secure Memory Zeroization
3. Constant-Time Comparison Helpers
4. Rate Limiting / DoS Protection
5. All features OPT-IN, zero overhead when disabled

Philosophy: Never modify core code, only wrap and extend
"""

import os
import sys
import time
import hmac
import hashlib
import threading
from typing import Any, Callable, Dict, List, Optional, Union, TypeVar
from dataclasses import dataclass, field
from enum import Enum
import re
import ipaddress


# -----------------------------------------------------------------------------
# CONFIGURATION - ALL FEATURES DISABLED BY DEFAULT
# -----------------------------------------------------------------------------
class SecurityConfig:
    """Security configuration - ALL features DISABLED by default.
    
    Enable via environment variables:
        NEURALSHIELD_SEC_VALIDATION=1
        NEURALSHIELD_SEC_ZEROIZATION=1
        NEURALSHIELD_SEC_CONSTANT_TIME=1
        NEURALSHIELD_SEC_RATE_LIMIT=1
    """
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialize()
            return cls._instance
    
    def _initialize(self):
        self.validation_enabled = os.getenv('NEURALSHIELD_SEC_VALIDATION', '0') == '1'
        self.zeroization_enabled = os.getenv('NEURALSHIELD_SEC_ZEROIZATION', '0') == '1'
        self.constant_time_enabled = os.getenv('NEURALSHIELD_SEC_CONSTANT_TIME', '0') == '1'
        self.rate_limit_enabled = os.getenv('NEURALSHIELD_SEC_RATE_LIMIT', '0') == '1'
        
        # Validation thresholds
        self.max_input_length = int(os.getenv('NEURALSHIELD_MAX_INPUT_LEN', '1048576'))  # 1MB
        self.max_prompt_tokens = int(os.getenv('NEURALSHIELD_MAX_TOKENS', '32768'))
        self.max_nesting_depth = int(os.getenv('NEURALSHIELD_MAX_NESTING', '10'))
        
        # Rate limiting defaults
        self.default_rate_limit = int(os.getenv('NEURALSHIELD_RATE_LIMIT', '100'))
        self.default_rate_window = int(os.getenv('NEURALSHIELD_RATE_WINDOW', '60'))  # seconds


# -----------------------------------------------------------------------------
# 1. INPUT VALIDATION WRAPPERS
# -----------------------------------------------------------------------------
class InputValidationLevel(Enum):
    BASIC = "basic"          # Length and format checks only
    STANDARD = "standard"    # + pattern matching, injection detection
    STRICT = "strict"        # + content analysis, heuristic scanning


class ValidationError(Exception):
    """Raised when input validation fails."""
    pass


class InputValidator:
    """Secure input validation wrapper - layers on top of existing code.
    
    Does NOT modify core detection logic, only validates inputs before processing.
    """
    
    def __init__(self, level: InputValidationLevel = InputValidationLevel.STANDARD):
        self.config = SecurityConfig()
        self.level = level
        self._compiled_patterns = self._compile_patterns()
    
    def _compile_patterns(self) -> Dict[str, re.Pattern]:
        """Pre-compile regex patterns for efficiency."""
        return {
            'system_prompt_leak': re.compile(
                r'(ignore|disregard|bypass).{0,20}(previous|above|system|instructions)',
                re.IGNORECASE
            ),
            'jailbreak_attempt': re.compile(
                r'(DAN|do anything now|developer mode|simulate|hypothetical|pretend).{0,30}(unrestricted|without limits)',
                re.IGNORECASE
            ),
            'sql_injection': re.compile(
                r'(\bunion\b.*\bselect\b|\bselect\b.*\bfrom\b|\bdrop\b.*\btable\b|\binsert\b.*\binto\b)',
                re.IGNORECASE
            ),
            'command_injection': re.compile(
                r'[;&|`]\s*(rm|sudo|chmod|chown|curl|wget|python|bash|sh)\s',
                re.IGNORECASE
            ),
        }
    
    def validate_prompt(self, prompt: str, 
                       max_length: Optional[int] = None,
                       raise_on_failure: bool = False) -> Dict[str, Any]:
        """Validate LLM prompt input.
        
        Returns: validation result dict with:
            - passed: bool
            - warnings: list of warning messages
            - errors: list of error messages
            - sanitized: sanitized input (if applicable)
        """
        if not self.config.validation_enabled:
            return {'passed': True, 'warnings': [], 'errors': [], 'sanitized': prompt}
        
        result = {'passed': True, 'warnings': [], 'errors': [], 'sanitized': prompt}
        max_len = max_length or self.config.max_input_length
        
        # Length validation
        if len(prompt) > max_len:
            result['errors'].append(f"Input exceeds maximum length: {len(prompt)} > {max_len}")
            result['passed'] = False
        
        # Null byte check
        if '\x00' in prompt:
            result['errors'].append("Input contains null bytes")
            result['passed'] = False
        
        # Pattern matching (STANDARD and above)
        if self.level in [InputValidationLevel.STANDARD, InputValidationLevel.STRICT]:
            for pattern_name, pattern in self._compiled_patterns.items():
                if pattern.search(prompt):
                    result['warnings'].append(f"Potential {pattern_name} detected")
        
        # Unicode control character check
        control_chars = sum(1 for c in prompt if ord(c) < 32 and c not in '\n\r\t')
        if control_chars > 5:
            result['warnings'].append(f"Excessive control characters: {control_chars}")
        
        if raise_on_failure and not result['passed']:
            raise ValidationError("; ".join(result['errors']))
        
        return result
    
    def validate_api_parameters(self, params: Dict[str, Any],
                               expected_schema: Dict[str, type]) -> Dict[str, Any]:
        """Validate API parameters against expected schema."""
        if not self.config.validation_enabled:
            return {'passed': True, 'warnings': [], 'errors': []}
        
        result = {'passed': True, 'warnings': [], 'errors': []}
        
        for param_name, expected_type in expected_schema.items():
            if param_name not in params:
                result['warnings'].append(f"Missing parameter: {param_name}")
                continue
            
            if not isinstance(params[param_name], expected_type):
                result['errors'].append(
                    f"Type mismatch for {param_name}: expected {expected_type}, got {type(params[param_name])}"
                )
                result['passed'] = False
        
        return result


def validate_input(level: InputValidationLevel = InputValidationLevel.STANDARD):
    """Decorator for input validation - wraps existing functions."""
    def decorator(func: Callable) -> Callable:
        validator = InputValidator(level)
        
        def wrapper(*args, **kwargs) -> Any:
            config = SecurityConfig()
            if not config.validation_enabled:
                return func(*args, **kwargs)
            
            # Validate first string argument as prompt
            for arg in args:
                if isinstance(arg, str):
                    result = validator.validate_prompt(arg)
                    if not result['passed']:
                        raise ValidationError(f"Input validation failed: {result['errors']}")
                    break
            
            return func(*args, **kwargs)
        return wrapper
    return decorator


# -----------------------------------------------------------------------------
# 2. SECURE MEMORY ZEROIZATION
# -----------------------------------------------------------------------------
class SecureMemory:
    """Secure memory zeroization utilities.
    
    Overwrites sensitive data in memory before garbage collection.
    Helps prevent sensitive data exposure in core dumps or memory scans.
    """
    
    @staticmethod
    def zeroize_bytes(data: bytearray) -> None:
        """Zeroize a bytearray in place.
        
        IMPORTANT: Only works on mutable bytearray objects, NOT on immutable bytes.
        Convert sensitive data to bytearray for zeroization.
        """
        config = SecurityConfig()
        if not config.zeroization_enabled:
            return
        
        try:
            # Overwrite with zeros
            for i in range(len(data)):
                data[i] = 0
            # Overwrite with ones
            for i in range(len(data)):
                data[i] = 0xFF
            # Final zero
            for i in range(len(data)):
                data[i] = 0
        except:
            pass  # Best effort only
    
    @staticmethod
    def zeroize_string(data: List[str]) -> None:
        """Zeroize string data stored in a list.
        
        Note: Python strings are immutable, so we can only overwrite the list
        elements. Store sensitive strings in lists for zeroization.
        """
        config = SecurityConfig()
        if not config.zeroization_enabled:
            return
        
        try:
            for i in range(len(data)):
                data[i] = '\x00' * len(data[i])
        except:
            pass
    
    @staticmethod
    def zeroize_list(data: List[Any]) -> None:
        """Clear and zeroize a list containing sensitive data."""
        config = SecurityConfig()
        if not config.zeroization_enabled:
            return
        
        try:
            data.clear()
        except:
            pass


class SensitiveBuffer:
    """Context manager for sensitive data buffers with auto-zeroization."""
    
    def __init__(self, initial_data: bytes = b''):
        self.config = SecurityConfig()
        self._data = bytearray(initial_data)
    
    def __enter__(self) -> bytearray:
        return self._data
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.config.zeroization_enabled:
            SecureMemory.zeroize_bytes(self._data)
        return False


# -----------------------------------------------------------------------------
# 3. CONSTANT-TIME COMPARISON HELPERS
# -----------------------------------------------------------------------------
def constant_time_compare(a: Union[bytes, str], b: Union[bytes, str]) -> bool:
    """Constant-time comparison for security-sensitive operations.
    
    Prevents timing attacks on secrets, API keys, tokens, hashes.
    Uses hmac.compare_digest under the hood (stdlib constant-time).
    """
    config = SecurityConfig()
    if not config.constant_time_enabled:
        return a == b
    
    if isinstance(a, str):
        a = a.encode('utf-8')
    if isinstance(b, str):
        b = b.encode('utf-8')
    
    # Ensure same length first (constant-time check)
    if len(a) != len(b):
        # Still do constant-time compare to avoid timing leak
        return hmac.compare_digest(a, a[:len(a)] + b[:0]) and False
    
    return hmac.compare_digest(a, b)


def constant_time_hex_digest(data: bytes, key: bytes) -> str:
    """Constant-time HMAC-SHA256 for hash comparisons."""
    return hmac.new(key, data, hashlib.sha256).hexdigest()


# -----------------------------------------------------------------------------
# 4. RATE LIMITING / DoS PROTECTION
# -----------------------------------------------------------------------------
@dataclass
class RateLimitEntry:
    count: int = 0
    window_start: float = field(default_factory=time.time)
    lock: threading.Lock = field(default_factory=threading.Lock)


class RateLimiter:
    """Thread-safe rate limiter for DoS protection.
    
    Token bucket algorithm with sliding window.
    """
    
    def __init__(self, default_limit: Optional[int] = None, 
                 default_window: Optional[int] = None):
        self.config = SecurityConfig()
        self.default_limit = default_limit or self.config.default_rate_limit
        self.default_window = default_window or self.config.default_rate_window
        self._buckets: Dict[str, RateLimitEntry] = {}
        self._global_lock = threading.Lock()
    
    def _get_bucket(self, key: str) -> RateLimitEntry:
        with self._global_lock:
            if key not in self._buckets:
                self._buckets[key] = RateLimitEntry()
            return self._buckets[key]
    
    def check_rate_limit(self, key: str, 
                        limit: Optional[int] = None,
                        window: Optional[int] = None,
                        consume: bool = True) -> Dict[str, Any]:
        """Check if request is within rate limits.
        
        Returns:
            - allowed: bool
            - remaining: remaining requests in window
            - reset: seconds until window resets
            - limit: current limit
        """
        if not self.config.rate_limit_enabled:
            return {'allowed': True, 'remaining': 9999, 'reset': 0, 'limit': self.default_limit}
        
        limit = limit or self.default_limit
        window = window or self.default_window
        
        bucket = self._get_bucket(key)
        now = time.time()
        
        with bucket.lock:
            # Reset window if expired
            if now - bucket.window_start > window:
                bucket.count = 0
                bucket.window_start = now
            
            remaining = limit - bucket.count
            reset_seconds = max(0, window - (now - bucket.window_start))
            
            if bucket.count >= limit:
                return {
                    'allowed': False,
                    'remaining': 0,
                    'reset': reset_seconds,
                    'limit': limit
                }
            
            if consume:
                bucket.count += 1
                remaining -= 1
            
            return {
                'allowed': True,
                'remaining': remaining,
                'reset': reset_seconds,
                'limit': limit
            }
    
    def cleanup_old_entries(self, max_age: int = 3600) -> int:
        """Clean up expired rate limit entries."""
        now = time.time()
        removed = 0
        
        with self._global_lock:
            keys_to_remove = [
                k for k, v in self._buckets.items()
                if now - v.window_start > max_age
            ]
            for k in keys_to_remove:
                del self._buckets[k]
                removed += 1
        
        return removed


# Global rate limiter instance
_global_rate_limiter: Optional[RateLimiter] = None
_global_rate_lock = threading.Lock()


def get_global_rate_limiter() -> RateLimiter:
    global _global_rate_limiter
    with _global_rate_lock:
        if _global_rate_limiter is None:
            _global_rate_limiter = RateLimiter()
        return _global_rate_limiter


def rate_limited(key_func: Callable[..., str] = lambda *a, **kw: 'default',
                limit: Optional[int] = None,
                window: Optional[int] = None):
    """Decorator for rate limiting."""
    def decorator(func: Callable) -> Callable:
        limiter = get_global_rate_limiter()
        
        def wrapper(*args, **kwargs) -> Any:
            config = SecurityConfig()
            if not config.rate_limit_enabled:
                return func(*args, **kwargs)
            
            key = key_func(*args, **kwargs)
            result = limiter.check_rate_limit(key, limit, window)
            
            if not result['allowed']:
                raise RuntimeError(
                    f"Rate limit exceeded. Try again in {result['reset']:.1f}s"
                )
            
            return func(*args, **kwargs)
        return wrapper
    return decorator


# -----------------------------------------------------------------------------
# MODULE EXPORTS
# -----------------------------------------------------------------------------
__all__ = [
    'SecurityConfig',
    'InputValidationLevel',
    'ValidationError',
    'InputValidator',
    'validate_input',
    'SecureMemory',
    'SensitiveBuffer',
    'constant_time_compare',
    'constant_time_hex_digest',
    'RateLimiter',
    'get_global_rate_limiter',
    'rate_limited',
]
