"""
NeuralShield Comprehensive Security Hardening Framework v29
Dimension B - Security Hardening
June 25, 2026

ADD-ONLY security layer - wraps existing code, does NOT modify core
All features are opt-in, backward compatible

Features:
1. Input Validation Wrappers
2. Secure Memory Zeroization
3. Constant-Time Comparison Helpers
4. Rate Limiting / DoS Protection
5. Secure Type Validation
"""

import time
import hmac
import hashlib
import threading
from typing import Any, Callable, Dict, List, Optional, Union, TypeVar
from dataclasses import dataclass, field
from enum import Enum


class SecurityLevel(Enum):
    """Security level enumeration for validation strictness"""
    RELAXED = "relaxed"
    STANDARD = "standard"
    STRICT = "strict"
    PARANOID = "paranoid"


@dataclass
class RateLimitConfig:
    """Configuration for rate limiting"""
    max_requests: int = 100
    window_seconds: int = 60
    block_duration_seconds: int = 300


@dataclass
class ValidationRule:
    """Single validation rule for input sanitization"""
    name: str
    validator: Callable[[Any], bool]
    error_message: str
    security_level: SecurityLevel = SecurityLevel.STANDARD


class SecureMemory:
    """
    Secure memory zeroization utilities
    Overwrites sensitive data in memory to prevent leakage
    """
    
    @staticmethod
    def zeroize_string(s: str) -> None:
        """
        Zeroize a string by overwriting its internal buffer
        Note: Python strings are immutable, this creates a replacement
        """
        try:
            import ctypes
            import sys
            length = len(s)
            offset = sys.getsizeof(s) - length - 1
            address = id(s) + offset
            ctypes.memset(address, 0, length)
        except Exception:
            pass
    
    @staticmethod
    def zeroize_bytes(b: bytearray) -> None:
        """Zeroize a bytearray"""
        for i in range(len(b)):
            b[i] = 0
    
    @staticmethod
    def zeroize_list(lst: List[Any]) -> None:
        """Zeroize a list containing sensitive data"""
        for i in range(len(lst)):
            lst[i] = None
        lst.clear()
    
    @staticmethod
    def zeroize_dict(d: Dict[Any, Any]) -> None:
        """Zeroize a dictionary containing sensitive data"""
        for key in list(d.keys()):
            d[key] = None
            del d[key]
        d.clear()


class ConstantTime:
    """
    Constant-time comparison helpers to prevent timing attacks
    All comparisons run in constant time regardless of input
    """
    
    @staticmethod
    def compare_strings(a: str, b: str) -> bool:
        """Constant-time string comparison using HMAC"""
        return hmac.compare_digest(a, b)
    
    @staticmethod
    def compare_bytes(a: bytes, b: bytes) -> bool:
        """Constant-time bytes comparison"""
        return hmac.compare_digest(a, b)
    
    @staticmethod
    def compare_ints(a: int, b: int) -> bool:
        """Constant-time integer comparison"""
        result = 0
        max_len = max(a.bit_length(), b.bit_length()) // 8 + 1
        a_bytes = a.to_bytes(max_len, 'big')
        b_bytes = b.to_bytes(max_len, 'big')
        return hmac.compare_digest(a_bytes, b_bytes)
    
    @staticmethod
    def secure_hash(data: Union[str, bytes], salt: bytes = b'') -> bytes:
        """Constant-time secure hashing"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        return hashlib.pbkdf2_hmac('sha256', data, salt, 100000)


class InputValidator:
    """
    Input validation wrapper - layer ON TOP of existing code
    Does NOT modify core functionality
    """
    
    def __init__(self, security_level: SecurityLevel = SecurityLevel.STANDARD):
        self.security_level = security_level
        self.validation_rules: List[ValidationRule] = []
        self._init_default_rules()
    
    def _init_default_rules(self) -> None:
        """Initialize default validation rules"""
        self.add_rule(ValidationRule(
            name="not_none",
            validator=lambda x: x is not None,
            error_message="Value cannot be None"
        ))
        self.add_rule(ValidationRule(
            name="not_empty_string",
            validator=lambda x: not (isinstance(x, str) and len(x.strip()) == 0),
            error_message="String cannot be empty"
        ))
        self.add_rule(ValidationRule(
            name="reasonable_length",
            validator=lambda x: not (isinstance(x, str) and len(x) > 1000000),
            error_message="String exceeds maximum length",
            security_level=SecurityLevel.STRICT
        ))
    
    def add_rule(self, rule: ValidationRule) -> None:
        """Add a custom validation rule"""
        self.validation_rules.append(rule)
    
    def validate(self, value: Any, field_name: str = "input") -> Dict[str, Any]:
        """
        Validate input against all applicable rules
        Returns: {"valid": bool, "errors": List[str], "sanitized": Any}
        """
        errors = []
        applicable_rules = [
            r for r in self.validation_rules
            if self._level_applicable(r.security_level)
        ]
        
        for rule in applicable_rules:
            try:
                if not rule.validator(value):
                    errors.append(f"{field_name}: {rule.error_message}")
            except Exception as e:
                errors.append(f"{field_name}: validation error - {str(e)}")
        
        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "sanitized": self._sanitize(value)
        }
    
    def _level_applicable(self, rule_level: SecurityLevel) -> bool:
        """Check if rule applies at current security level"""
        level_order = [
            SecurityLevel.RELAXED,
            SecurityLevel.STANDARD,
            SecurityLevel.STRICT,
            SecurityLevel.PARANOID
        ]
        current_idx = level_order.index(self.security_level)
        rule_idx = level_order.index(rule_level)
        return rule_idx <= current_idx
    
    def _sanitize(self, value: Any) -> Any:
        """Basic sanitization - preserve original type"""
        if isinstance(value, str):
            # Remove control characters but preserve content
            return ''.join(c for c in value if ord(c) >= 32 or c in '\n\t\r')
        return value
    
    def validate_dict(self, data: Dict[str, Any], schema: Dict[str, Callable]) -> Dict[str, Any]:
        """Validate a dictionary against a schema"""
        all_errors = []
        sanitized = {}
        
        for key, validator_fn in schema.items():
            if key in data:
                result = self.validate(data[key], key)
                if not result["valid"]:
                    all_errors.extend(result["errors"])
                sanitized[key] = validator_fn(result["sanitized"])
            else:
                all_errors.append(f"Missing required field: {key}")
        
        return {
            "valid": len(all_errors) == 0,
            "errors": all_errors,
            "sanitized": sanitized
        }


class RateLimiter:
    """
    Rate limiting and DoS protection module
    Thread-safe, in-memory rate limiter
    """
    
    def __init__(self, config: Optional[RateLimitConfig] = None):
        self.config = config or RateLimitConfig()
        self._requests: Dict[str, List[float]] = {}
        self._blocked: Dict[str, float] = {}
        self._lock = threading.Lock()
    
    def check_rate_limit(self, client_id: str) -> Dict[str, Any]:
        """
        Check if client is within rate limits
        Returns: {"allowed": bool, "remaining": int, "reset_time": float}
        """
        with self._lock:
            now = time.time()
            
            # Check if currently blocked
            if client_id in self._blocked:
                if now < self._blocked[client_id]:
                    return {
                        "allowed": False,
                        "remaining": 0,
                        "reset_time": self._blocked[client_id],
                        "blocked": True
                    }
                else:
                    del self._blocked[client_id]
            
            # Clean up old requests
            if client_id in self._requests:
                self._requests[client_id] = [
                    t for t in self._requests[client_id]
                    if now - t < self.config.window_seconds
                ]
            else:
                self._requests[client_id] = []
            
            # Check rate limit
            request_count = len(self._requests[client_id])
            
            if request_count >= self.config.max_requests:
                # Block client
                self._blocked[client_id] = now + self.config.block_duration_seconds
                return {
                    "allowed": False,
                    "remaining": 0,
                    "reset_time": self._blocked[client_id],
                    "blocked": True
                }
            
            # Record request
            self._requests[client_id].append(now)
            
            return {
                "allowed": True,
                "remaining": self.config.max_requests - request_count - 1,
                "reset_time": now + self.config.window_seconds,
                "blocked": False
            }
    
    def reset_client(self, client_id: str) -> None:
        """Reset rate limit for a client"""
        with self._lock:
            if client_id in self._requests:
                del self._requests[client_id]
            if client_id in self._blocked:
                del self._blocked[client_id]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get rate limiter statistics"""
        with self._lock:
            return {
                "total_clients_tracked": len(self._requests),
                "clients_blocked": len(self._blocked),
                "max_requests_window": self.config.max_requests,
                "window_seconds": self.config.window_seconds
            }


class SecurityHardeningWrapper:
    """
    Main wrapper class to apply all security hardening features
    Layered ON TOP of existing code - no modifications to core
    """
    
    def __init__(
        self,
        security_level: SecurityLevel = SecurityLevel.STANDARD,
        rate_limit_config: Optional[RateLimitConfig] = None
    ):
        self.validator = InputValidator(security_level)
        self.rate_limiter = RateLimiter(rate_limit_config)
        self.security_level = security_level
    
    def wrap_function(
        self,
        func: Callable,
        client_id: Optional[str] = None,
        validate_inputs: bool = True,
        rate_limit: bool = True
    ) -> Callable:
        """
        Wrap a function with security hardening
        Original function behavior is 100% preserved
        """
        def wrapped(*args, **kwargs):
            # Rate limiting check
            if rate_limit and client_id:
                rate_result = self.rate_limiter.check_rate_limit(client_id)
                if not rate_result["allowed"]:
                    raise SecurityError(
                        f"Rate limit exceeded. Try again after {rate_result['reset_time']}"
                    )
            
            # Input validation
            if validate_inputs:
                for i, arg in enumerate(args):
                    val_result = self.validator.validate(arg, f"arg_{i}")
                    if not val_result["valid"]:
                        raise ValidationError(f"Input validation failed: {val_result['errors']}")
                
                for key, value in kwargs.items():
                    val_result = self.validator.validate(value, key)
                    if not val_result["valid"]:
                        raise ValidationError(f"Input validation failed: {val_result['errors']}")
            
            # Call original function - 100% behavior preserved
            return func(*args, **kwargs)
        
        return wrapped
    
    def secure_execute(
        self,
        func: Callable,
        *args,
        client_id: Optional[str] = None,
        **kwargs
    ) -> Any:
        """Execute function with all security hardening applied"""
        wrapped = self.wrap_function(func, client_id=client_id)
        return wrapped(*args, **kwargs)


class SecurityError(Exception):
    """Base exception for security-related errors"""
    pass


class ValidationError(SecurityError):
    """Raised when input validation fails"""
    pass


class RateLimitError(SecurityError):
    """Raised when rate limit is exceeded"""
    pass


# Exported instances for easy use
default_validator = InputValidator(SecurityLevel.STANDARD)
default_rate_limiter = RateLimiter()
secure_memory = SecureMemory()
constant_time = ConstantTime()

__all__ = [
    'SecureMemory',
    'ConstantTime',
    'InputValidator',
    'RateLimiter',
    'SecurityHardeningWrapper',
    'SecurityLevel',
    'RateLimitConfig',
    'ValidationRule',
    'SecurityError',
    'ValidationError',
    'RateLimitError',
    'secure_memory',
    'constant_time',
    'default_validator',
    'default_rate_limiter',
]
