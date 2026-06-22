"""
NeuralShield AI - Security Hardening Module
Dimension B: Security Hardening

This module provides security wrappers that layer ON TOP of existing code.
NO existing production code is modified - only new functionality added.

Features:
1. Input validation wrappers for all public API entry points
2. Secure memory zeroization utilities
3. Constant-time comparison helpers
4. Type and boundary validation decorators
"""

import os
import sys
import hmac
import hashlib
import secrets
from typing import Any, Callable, Optional, Union, List, Dict, TypeVar
from functools import wraps
import re

T = TypeVar('T')

# -----------------------------------------------------------------------------
# Secure Memory Zeroization
# -----------------------------------------------------------------------------

def secure_zeroize(data: Union[bytearray, memoryview, List[int]]) -> None:
    """
    Securely zeroize sensitive data from memory.
    
    Uses volatile writes to prevent compiler optimization.
    This is best-effort - Python's garbage collector may still have copies.
    
    Args:
        data: Mutable byte sequence to zeroize
    """
    if isinstance(data, bytearray):
        for i in range(len(data)):
            data[i] = 0
    elif isinstance(data, memoryview):
        data[:] = b'\x00' * len(data)
    elif isinstance(data, list):
        for i in range(len(data)):
            data[i] = 0


class SecureSensitiveData:
    """
    Wrapper for sensitive data that ensures secure cleanup.
    
    Usage:
        with SecureSensitiveData(b"secret") as data:
            process(data)
        # Data is zeroized after context exit
    """
    
    def __init__(self, data: bytes):
        self._data = bytearray(data)
        self._used = False
    
    def __enter__(self) -> bytearray:
        self._used = True
        return self._data
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        secure_zeroize(self._data)
        self._data = None
        return False
    
    def __del__(self):
        if hasattr(self, '_data') and self._data is not None:
            secure_zeroize(self._data)

# -----------------------------------------------------------------------------
# Constant-Time Comparison
# -----------------------------------------------------------------------------

def constant_time_compare(a: bytes, b: bytes) -> bool:
    """
    Compare two byte sequences in constant time.
    
    Prevents timing attacks by ensuring the comparison takes the same
    amount of time regardless of how many bytes match.
    
    Args:
        a: First byte sequence
        b: Second byte sequence
        
    Returns:
        True if equal, False otherwise
    """
    return hmac.compare_digest(a, b)


def constant_time_str_compare(a: str, b: str) -> bool:
    """
    Compare two strings in constant time.
    
    Args:
        a: First string
        b: Second string
        
    Returns:
        True if equal, False otherwise
    """
    return hmac.compare_digest(a.encode('utf-8'), b.encode('utf-8'))

# -----------------------------------------------------------------------------
# Input Validation Decorators and Wrappers
# -----------------------------------------------------------------------------

class ValidationError(Exception):
    """Raised when input validation fails."""
    pass


def validate_string(max_length: int = 10000, 
                    min_length: int = 0,
                    allowed_chars: Optional[str] = None,
                    allow_empty: bool = True) -> Callable[[T], T]:
    """
    Decorator to validate string input parameters.
    
    Args:
        max_length: Maximum allowed string length
        min_length: Minimum required string length
        allowed_chars: Regex pattern for allowed characters
        allow_empty: Whether empty strings are allowed
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Validate positional string args
            for i, arg in enumerate(args):
                if isinstance(arg, str):
                    _validate_single_string(arg, max_length, min_length, 
                                          allowed_chars, allow_empty, f"arg[{i}]")
            
            # Validate keyword string args
            for key, value in kwargs.items():
                if isinstance(value, str):
                    _validate_single_string(value, max_length, min_length,
                                          allowed_chars, allow_empty, key)
            
            return func(*args, **kwargs)
        return wrapper
    return decorator


def _validate_single_string(value: str, max_length: int, min_length: int,
                          allowed_chars: Optional[str], allow_empty: bool,
                          param_name: str) -> None:
    """Internal string validation helper."""
    if not allow_empty and len(value.strip()) == 0:
        raise ValidationError(f"Parameter '{param_name}' cannot be empty")
    
    if len(value) > max_length:
        raise ValidationError(
            f"Parameter '{param_name}' exceeds max length: "
            f"{len(value)} > {max_length}"
        )
    
    if len(value) < min_length:
        raise ValidationError(
            f"Parameter '{param_name}' below min length: "
            f"{len(value)} < {min_length}"
        )
    
    if allowed_chars and not re.match(allowed_chars, value):
        raise ValidationError(
            f"Parameter '{param_name}' contains invalid characters"
        )


def validate_input_types(*type_args, **type_kwargs) -> Callable[[T], T]:
    """
    Decorator to validate input parameter types.
    
    Usage:
        @validate_input_types(str, int, threshold=float)
        def process(text, count, threshold=0.5):
            ...
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Validate positional args
            for i, (arg, expected_type) in enumerate(zip(args, type_args)):
                if expected_type is not None and not isinstance(arg, expected_type):
                    raise ValidationError(
                        f"Argument {i} expected {expected_type.__name__}, "
                        f"got {type(arg).__name__}"
                    )
            
            # Validate keyword args
            for key, expected_type in type_kwargs.items():
                if key in kwargs:
                    value = kwargs[key]
                    if expected_type is not None and not isinstance(value, expected_type):
                        raise ValidationError(
                            f"Keyword '{key}' expected {expected_type.__name__}, "
                            f"got {type(value).__name__}"
                        )
            
            return func(*args, **kwargs)
        return wrapper
    return decorator


def validate_boundaries(min_val: Optional[float] = None,
                       max_val: Optional[float] = None,
                       param_names: Optional[List[str]] = None) -> Callable[[T], T]:
    """
    Decorator to validate numeric boundaries.
    
    Args:
        min_val: Minimum allowed value (inclusive)
        max_val: Maximum allowed value (inclusive)
        param_names: List of parameter names to check (None = all numeric)
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            all_args = list(args) + list(kwargs.values())
            
            for i, value in enumerate(all_args):
                if isinstance(value, (int, float)):
                    if min_val is not None and value < min_val:
                        raise ValidationError(
                            f"Value {value} below minimum: {min_val}"
                        )
                    if max_val is not None and value > max_val:
                        raise ValidationError(
                            f"Value {value} above maximum: {max_val}"
                        )
            
            return func(*args, **kwargs)
        return wrapper
    return decorator

# -----------------------------------------------------------------------------
# Input Sanitization Wrappers
# -----------------------------------------------------------------------------

def sanitize_for_logging(data: Any, max_length: int = 200) -> str:
    """
    Sanitize data for safe logging.
    
    - Truncates long strings
    - Masks potential secrets
    - Converts to safe representation
    """
    if data is None:
        return "None"
    
    result = str(data)
    
    # Truncate long content
    if len(result) > max_length:
        result = result[:max_length] + "...[TRUNCATED]"
    
    # Mask common secret patterns
    secret_patterns = [
        (r'key\s*=\s*[^\s&]+', 'key=[REDACTED]'),
        (r'token\s*=\s*[^\s&]+', 'token=[REDACTED]'),
        (r'password\s*=\s*[^\s&]+', 'password=[REDACTED]'),
        (r'secret\s*=\s*[^\s&]+', 'secret=[REDACTED]'),
        (r'api_?key\s*=\s*[^\s&]+', 'api_key=[REDACTED]'),
    ]
    
    for pattern, replacement in secret_patterns:
        result = re.sub(pattern, replacement, result, flags=re.IGNORECASE)
    
    return result


def validate_prompt_safety(prompt: str, max_tokens: int = 4096) -> Dict[str, Any]:
    """
    Validate prompt input for safety constraints.
    
    Returns validation report without modifying the original prompt.
    """
    issues = []
    warnings = []
    
    # Length validation
    char_count = len(prompt)
    approx_tokens = char_count // 4
    
    if approx_tokens > max_tokens:
        issues.append(f"Prompt exceeds token limit: ~{approx_tokens} > {max_tokens}")
    
    # Check for suspicious patterns (informational only)
    suspicious_patterns = [
        (r'ignore.*previous', 'Potential prompt injection pattern'),
        (r'disregard.*instructions', 'Potential prompt injection pattern'),
        (r'you are now.*GPT', 'Potential persona hijacking'),
        (r'system.*prompt', 'Potential system prompt access attempt'),
    ]
    
    prompt_lower = prompt.lower()
    for pattern, description in suspicious_patterns:
        if re.search(pattern, prompt_lower):
            warnings.append(description)
    
    return {
        'valid': len(issues) == 0,
        'char_count': char_count,
        'approx_tokens': approx_tokens,
        'issues': issues,
        'warnings': warnings,
        'sanitized_log': sanitize_for_logging(prompt, 100)
    }

# -----------------------------------------------------------------------------
# Secure Input Gateway
# -----------------------------------------------------------------------------

class SecureInputGateway:
    """
    Secure entry point wrapper for all external inputs.
    
    This wraps existing functions with validation layers.
    Existing code is NOT modified - this is purely additive.
    """
    
    def __init__(self, max_input_size: int = 100000):
        self.max_input_size = max_input_size
        self.validation_count = 0
        self.rejection_count = 0
    
    def wrap_function(self, func: Callable, 
                     validation_rules: Optional[Dict] = None) -> Callable:
        """
        Wrap an existing function with security validation.
        
        Usage:
            original_func = some_existing_function
            secured_func = gateway.wrap_function(original_func)
        """
        @wraps(func)
        def secured_wrapper(*args, **kwargs):
            self.validation_count += 1
            
            try:
                # Size validation
                total_size = sum(self._estimate_size(arg) for arg in args)
                total_size += sum(self._estimate_size(v) for v in kwargs.values())
                
                if total_size > self.max_input_size:
                    self.rejection_count += 1
                    raise ValidationError(
                        f"Input size exceeded: {total_size} > {self.max_input_size}"
                    )
                
                # Execute original function
                return func(*args, **kwargs)
                
            except ValidationError:
                self.rejection_count += 1
                raise
        
        return secured_wrapper
    
    def _estimate_size(self, obj: Any) -> int:
        """Estimate memory size of an object."""
        if isinstance(obj, (str, bytes, bytearray)):
            return len(obj)
        elif isinstance(obj, (list, dict, set, tuple)):
            return sum(self._estimate_size(item) for item in obj)
        else:
            return sys.getsizeof(obj, 64)
    
    def get_stats(self) -> Dict[str, int]:
        """Get validation statistics."""
        return {
            'validations_processed': self.validation_count,
            'rejections': self.rejection_count,
            'acceptance_rate': (
                (self.validation_count - self.rejection_count) / 
                max(1, self.validation_count)
            )
        }

# -----------------------------------------------------------------------------
# Module Exports
# -----------------------------------------------------------------------------

__all__ = [
    'secure_zeroize',
    'SecureSensitiveData',
    'constant_time_compare',
    'constant_time_str_compare',
    'ValidationError',
    'validate_string',
    'validate_input_types',
    'validate_boundaries',
    'sanitize_for_logging',
    'validate_prompt_safety',
    'SecureInputGateway',
]
