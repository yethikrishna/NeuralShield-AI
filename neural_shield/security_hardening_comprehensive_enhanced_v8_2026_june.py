"""
NeuralShield Security Hardening Module v8 - Comprehensive Enhanced
DIMENSION B - Security Hardening

ADD-ONLY implementation - wraps existing code, no core modifications
Layered security approach: input validation, memory protection, constant-time ops, rate limiting

This module provides security wrappers that can be OPTIONALLY applied
to existing functions without modifying their core implementation.

Philosophy: Security in depth, defense in layers, zero trust
"""

import os
import sys
import time
import hmac
import hashlib
import threading
from typing import Any, Callable, Dict, List, Optional, Tuple, Union, TypeVar
from dataclasses import dataclass, field
from enum import Enum
import secrets
import re
from functools import wraps
from collections import defaultdict
from abc import ABC, abstractmethod

# Type variable for decorator
F = TypeVar('F', bound=Callable[..., Any])


class SecurityLevel(Enum):
    """Security levels for hardening"""
    MINIMAL = "minimal"
    STANDARD = "standard"
    ENHANCED = "enhanced"
    MAXIMUM = "maximum"


class ValidationSeverity(Enum):
    """Severity levels for validation failures"""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class SecurityContext:
    """Context for security operations"""
    security_level: SecurityLevel = SecurityLevel.STANDARD
    enable_logging: bool = False
    caller_identity: Optional[str] = None
    operation_id: str = field(default_factory=lambda: secrets.token_hex(16))
    timestamp: float = field(default_factory=time.time)


@dataclass
class ValidationResult:
    """Result of input validation"""
    valid: bool
    severity: ValidationSeverity
    message: str
    field_name: Optional[str] = None
    sanitized_value: Optional[Any] = None


class SecureMemoryZeroizer:
    """
    Secure memory zeroization with side-channel resistance.
    
    Overwrites sensitive data multiple times with different patterns
    to prevent forensic recovery and side-channel leaks.
    
    IMPORTANT: This is best-effort protection. Python's garbage collector
    may have already made copies of the data.
    """
    
    @staticmethod
    def zeroize_bytes(data: bytearray, passes: int = 3) -> None:
        """
        Securely zeroize a bytearray.
        
        Args:
            data: Mutable bytearray to zeroize
            passes: Number of overwrite passes (default: 3)
        """
        if not isinstance(data, bytearray):
            return
            
        length = len(data)
        if length == 0:
            return
            
        patterns = [
            b'\x00' * length,      # All zeros
            b'\xFF' * length,      # All ones
            b'\x55' * length,      # Alternating 01010101
            b'\xAA' * length,      # Alternating 10101010
        ]
        
        for i in range(min(passes, len(patterns))):
            data[:] = patterns[i]
            # Force memory barrier (best effort in Python)
            if hasattr(data, 'flush'):
                data.flush()
        
        # Final zero
        data[:] = b'\x00' * length
    
    @staticmethod
    def zeroize_string_list(strings: List[str]) -> None:
        """
        Best-effort zeroization of string list.
        
        Note: Python strings are immutable, so this cannot truly
        erase them from memory. This is for documentation purposes
        and to mark them for garbage collection.
        """
        for i in range(len(strings)):
            strings[i] = ""
    
    @staticmethod
    def clear_sensitive_dict(data: Dict[str, Any], sensitive_keys: List[str]) -> None:
        """Clear sensitive values from dictionary"""
        for key in sensitive_keys:
            if key in data:
                if isinstance(data[key], bytearray):
                    SecureMemoryZeroizer.zeroize_bytes(data[key])
                elif isinstance(data[key], str):
                    data[key] = ""
                elif isinstance(data[key], list):
                    data[key] = []
                else:
                    data[key] = None


class ConstantTimeOperations:
    """
    Constant-time comparison operations to prevent timing side-channel attacks.
    
    All comparisons run in O(n) time regardless of where the first mismatch occurs.
    """
    
    @staticmethod
    def compare_equal(a: bytes, b: bytes) -> bool:
        """
        Constant-time byte comparison.
        
        Uses hmac.compare_digest which is specifically designed
        to be timing-attack resistant.
        """
        if len(a) != len(b):
            return False
        return hmac.compare_digest(a, b)
    
    @staticmethod
    def compare_strings_constant_time(a: str, b: str) -> bool:
        """Constant-time string comparison"""
        if len(a) != len(b):
            return False
        return hmac.compare_digest(a.encode('utf-8'), b.encode('utf-8'))
    
    @staticmethod
    def secure_hash_compare(hash_a: str, hash_b: str) -> bool:
        """
        Compare two hash strings in constant time.
        
        Prevents timing attacks on hash comparisons.
        """
        # Normalize to same case first
        a_norm = hash_a.lower().strip()
        b_norm = hash_b.lower().strip()
        
        if len(a_norm) != len(b_norm):
            return False
            
        return hmac.compare_digest(a_norm.encode('utf-8'), b_norm.encode('utf-8'))
    
    @staticmethod
    def array_equals_constant_time(a: List[int], b: List[int]) -> bool:
        """Constant-time array comparison"""
        if len(a) != len(b):
            return False
            
        result = 0
        for x, y in zip(a, b):
            result |= x ^ y
            
        return result == 0


class InputType(Enum):
    """Types of input for validation"""
    PROMPT = "prompt"
    USER_INPUT = "user_input"
    API_KEY = "api_key"
    EMBEDDING = "embedding"
    JSON_DATA = "json_data"
    MODEL_NAME = "model_name"
    THRESHOLD = "threshold"


class InputValidator:
    """
    Comprehensive input validation with sanitization.
    
    Validates and optionally sanitizes inputs before they reach
    the core processing logic.
    """
    
    # Maximum safe lengths
    MAX_PROMPT_LENGTH = 100000
    MAX_USER_INPUT_LENGTH = 50000
    MAX_API_KEY_LENGTH = 200
    MAX_EMBEDDING_DIM = 4096
    
    # Suspicious patterns for prompt injection detection
    SUSPICIOUS_PATTERNS = [
        r'(?i)ignore.*previous.*instructions?',
        r'(?i)disregard.*above',
        r'(?i)forget.*everything',
        r'(?i)you.*are.*now.*in.*developer.*mode',
        r'(?i)system.*prompt',
        r'(?i)<\|endoftext\|>',
        r'(?i)repeat.*back',
        r'(?i)show.*your.*prompt',
    ]
    
    @staticmethod
    def validate_prompt(prompt: str, context: SecurityContext) -> ValidationResult:
        """Validate LLM prompt input"""
        if not isinstance(prompt, str):
            return ValidationResult(
                valid=False,
                severity=ValidationSeverity.ERROR,
                message="Prompt must be a string",
                field_name="prompt"
            )
        
        if len(prompt) == 0:
            return ValidationResult(
                valid=True,
                severity=ValidationSeverity.WARNING,
                message="Empty prompt provided",
                field_name="prompt",
                sanitized_value=prompt
            )
        
        if len(prompt) > InputValidator.MAX_PROMPT_LENGTH:
            return ValidationResult(
                valid=False,
                severity=ValidationSeverity.CRITICAL,
                message=f"Prompt exceeds maximum length of {InputValidator.MAX_PROMPT_LENGTH} chars",
                field_name="prompt"
            )
        
        # Check for suspicious patterns
        for pattern in InputValidator.SUSPICIOUS_PATTERNS:
            if re.search(pattern, prompt):
                return ValidationResult(
                    valid=False,
                    severity=ValidationSeverity.WARNING,
                    message=f"Suspicious pattern detected: {pattern[:50]}...",
                    field_name="prompt",
                    sanitized_value=prompt
                )
        
        return ValidationResult(
            valid=True,
            severity=ValidationSeverity.INFO,
            message="Prompt validation passed",
            field_name="prompt",
            sanitized_value=prompt
        )
    
    @staticmethod
    def validate_threshold(threshold: float, context: SecurityContext) -> ValidationResult:
        """Validate threshold value (0-1 range)"""
        if not isinstance(threshold, (int, float)):
            return ValidationResult(
                valid=False,
                severity=ValidationSeverity.ERROR,
                message="Threshold must be a number",
                field_name="threshold"
            )
        
        if threshold < 0.0 or threshold > 1.0:
            return ValidationResult(
                valid=False,
                severity=ValidationSeverity.ERROR,
                message="Threshold must be between 0 and 1",
                field_name="threshold"
            )
        
        return ValidationResult(
            valid=True,
            severity=ValidationSeverity.INFO,
            message="Threshold validation passed",
            field_name="threshold",
            sanitized_value=float(threshold)
        )
    
    @staticmethod
    def validate_embedding(embedding: List[float], context: SecurityContext) -> ValidationResult:
        """Validate embedding vector"""
        if not isinstance(embedding, list):
            return ValidationResult(
                valid=False,
                severity=ValidationSeverity.ERROR,
                message="Embedding must be a list",
                field_name="embedding"
            )
        
        if len(embedding) > InputValidator.MAX_EMBEDDING_DIM:
            return ValidationResult(
                valid=False,
                severity=ValidationSeverity.ERROR,
                message=f"Embedding dimension too large: {len(embedding)}",
                field_name="embedding"
            )
        
        return ValidationResult(
            valid=True,
            severity=ValidationSeverity.INFO,
            message="Embedding validation passed",
            field_name="embedding",
            sanitized_value=embedding
        )
    
    @staticmethod
    def sanitize_string(input_str: str) -> str:
        """
        Basic string sanitization - remove control characters.
        
        Preserves normal text while removing potentially dangerous
        control characters.
        """
        # Remove ASCII control characters except newline, tab
        sanitized = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', input_str)
        return sanitized


class TokenBucketRateLimiter:
    """
    Token bucket rate limiter for DoS protection.
    
    Each caller gets a bucket of tokens that refill over time.
    Prevents abuse while allowing legitimate burst traffic.
    """
    
    def __init__(self, rate: float = 10.0, capacity: int = 100):
        """
        Initialize rate limiter.
        
        Args:
            rate: Tokens added per second
            capacity: Maximum bucket capacity
        """
        self.rate = rate
        self.capacity = capacity
        self._buckets: Dict[str, Tuple[float, float]] = {}  # caller_id -> (tokens, last_update)
        self._lock = threading.Lock()
    
    def _refill(self, tokens: float, last_update: float) -> Tuple[float, float]:
        """Refill bucket based on elapsed time"""
        now = time.time()
        elapsed = now - last_update
        new_tokens = min(self.capacity, tokens + elapsed * self.rate)
        return new_tokens, now
    
    def consume(self, caller_id: str, tokens: int = 1) -> bool:
        """
        Try to consume tokens.
        
        Returns:
            True if tokens were consumed, False if rate limited
        """
        with self._lock:
            if caller_id not in self._buckets:
                self._buckets[caller_id] = (self.capacity, time.time())
            
            current_tokens, last_update = self._buckets[caller_id]
            current_tokens, last_update = self._refill(current_tokens, last_update)
            
            if current_tokens >= tokens:
                current_tokens -= tokens
                self._buckets[caller_id] = (current_tokens, last_update)
                return True
            
            self._buckets[caller_id] = (current_tokens, last_update)
            return False
    
    def get_remaining(self, caller_id: str) -> float:
        """Get remaining tokens for a caller"""
        with self._lock:
            if caller_id not in self._buckets:
                return self.capacity
            tokens, last_update = self._buckets[caller_id]
            tokens, _ = self._refill(tokens, last_update)
            return tokens


class SecurityHardeningWrapper:
    """
    Main wrapper class for applying security hardening.
    
    Provides decorators and wrapper functions that can be applied
    to existing code without modification.
    """
    
    def __init__(self, context: Optional[SecurityContext] = None):
        self.context = context or SecurityContext()
        self.rate_limiter = TokenBucketRateLimiter(rate=20.0, capacity=200)
        self._validation_failures: List[ValidationResult] = []
    
    def validate_inputs(self, validations: Dict[str, Tuple[Callable, Any]]) -> Dict[str, ValidationResult]:
        """
        Validate multiple inputs at once.
        
        Args:
            validations: Dict mapping field name -> (validator function, value)
        
        Returns:
            Dict of validation results
        """
        results = {}
        for field_name, (validator, value) in validations.items():
            result = validator(value, self.context)
            results[field_name] = result
            if not result.valid:
                self._validation_failures.append(result)
        return results
    
    def with_input_validation(self, validation_schema: Dict[str, Callable]) -> Callable[[F], F]:
        """
        Decorator: Apply input validation to function arguments.
        
        Usage:
            @wrapper.with_input_validation({
                'prompt': InputValidator.validate_prompt,
                'threshold': InputValidator.validate_threshold
            })
            def my_function(prompt, threshold=0.5):
                ...
        """
        def decorator(func: F) -> F:
            @wraps(func)
            def wrapped(*args, **kwargs):
                import inspect
                sig = inspect.signature(func)
                bound = sig.bind(*args, **kwargs)
                bound.apply_defaults()
                
                # Validate each parameter
                for param_name, validator in validation_schema.items():
                    if param_name in bound.arguments:
                        value = bound.arguments[param_name]
                        result = validator(value, self.context)
                        if not result.valid and result.severity in (ValidationSeverity.ERROR, ValidationSeverity.CRITICAL):
                            raise ValueError(f"Validation failed for {param_name}: {result.message}")
                
                return func(*args, **kwargs)
            return wrapped  # type: ignore
        return decorator
    
    def with_rate_limiting(self, tokens_per_call: int = 1) -> Callable[[F], F]:
        """
        Decorator: Apply rate limiting to a function.
        
        Uses caller identity from context or generates per-thread identity.
        """
        def decorator(func: F) -> F:
            @wraps(func)
            def wrapped(*args, **kwargs):
                caller_id = self.context.caller_identity or f"thread_{threading.get_ident()}"
                
                if not self.rate_limiter.consume(caller_id, tokens_per_call):
                    remaining = self.rate_limiter.get_remaining(caller_id)
                    raise RuntimeError(
                        f"Rate limit exceeded. Remaining tokens: {remaining:.1f}. "
                        f"Please wait before retrying."
                    )
                
                return func(*args, **kwargs)
            return wrapped  # type: ignore
        return decorator
    
    def with_secure_cleanup(self, sensitive_param_names: List[str]) -> Callable[[F], F]:
        """
        Decorator: Best-effort secure cleanup after function execution.
        
        Marks sensitive parameters for garbage collection after call.
        """
        def decorator(func: F) -> F:
            @wraps(func)
            def wrapped(*args, **kwargs):
                try:
                    return func(*args, **kwargs)
                finally:
                    # Best-effort cleanup - clear kwargs references
                    for param in sensitive_param_names:
                        if param in kwargs:
                            if isinstance(kwargs[param], bytearray):
                                SecureMemoryZeroizer.zeroize_bytes(kwargs[param])
                            elif isinstance(kwargs[param], str):
                                kwargs[param] = ""
            return wrapped  # type: ignore
        return decorator
    
    def get_validation_failures(self) -> List[ValidationResult]:
        """Get all validation failures encountered"""
        return self._validation_failures.copy()
    
    def clear_failures(self) -> None:
        """Clear validation failure history"""
        self._validation_failures.clear()


# Global default instances for easy import
_default_context = SecurityContext(security_level=SecurityLevel.STANDARD)
default_wrapper = SecurityHardeningWrapper(_default_context)
memory_zeroizer = SecureMemoryZeroizer()
constant_time = ConstantTimeOperations()
input_validator = InputValidator()


def create_secure_wrapper(
    security_level: SecurityLevel = SecurityLevel.STANDARD,
    enable_logging: bool = False
) -> SecurityHardeningWrapper:
    """
    Factory function to create a configured security wrapper.
    
    This is the main entry point for using this module.
    """
    context = SecurityContext(
        security_level=security_level,
        enable_logging=enable_logging
    )
    return SecurityHardeningWrapper(context)


# Export public interface
__all__ = [
    'SecurityLevel',
    'ValidationSeverity',
    'SecurityContext',
    'ValidationResult',
    'SecureMemoryZeroizer',
    'ConstantTimeOperations',
    'InputValidator',
    'InputType',
    'TokenBucketRateLimiter',
    'SecurityHardeningWrapper',
    'create_secure_wrapper',
    'default_wrapper',
    'memory_zeroizer',
    'constant_time',
    'input_validator',
]
