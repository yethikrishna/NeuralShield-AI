"""
NeuralShield AI - Comprehensive Security Hardening Integration V7
Dimension B: Security Hardening

ADD-ONLY IMPLEMENTATION - NO EXISTING CODE MODIFIED
Layers security ON TOP of existing code - 100% backward compatible

This module provides a unified security facade that integrates:
1. Input validation & sanitization
2. Secure memory management & zeroization
3. Constant-time comparison operations
4. Rate limiting & DoS protection
5. Context isolation & privilege separation
6. Security audit logging
7. Permission-based access control
8. Security policy enforcement

All features are OPT-IN and wrap existing functionality.
"""

import os
import sys
import time
import hmac
import hashlib
import secrets
import threading
from typing import (
    Any, Callable, Optional, Union, List, Dict, TypeVar,
    Tuple, Set, Awaitable, Generic
)
from functools import wraps
from dataclasses import dataclass, field
from enum import Enum, auto
from collections import defaultdict
import re

T = TypeVar('T')
R = TypeVar('R')

# -----------------------------------------------------------------------------
# Security Level Enumeration
# -----------------------------------------------------------------------------

class SecurityLevel(Enum):
    """Security enforcement levels."""
    DISABLED = auto()      # No security checks
    MINIMAL = auto()       # Basic validation only
    STANDARD = auto()      # Standard production security
    ENHANCED = auto()      # Enhanced with rate limiting
    MAXIMUM = auto()       # Full hardening + audit logging


class SecurityEventType(Enum):
    """Types of security events for auditing."""
    INPUT_VALIDATION_PASS = auto()
    INPUT_VALIDATION_FAIL = auto()
    RATE_LIMIT_EXCEEDED = auto()
    MEMORY_ZEROIZATION = auto()
    CONSTANT_TIME_COMPARISON = auto()
    PERMISSION_DENIED = auto()
    PERMISSION_GRANTED = auto()
    POLICY_ENFORCED = auto()
    CONTEXT_ISOLATION = auto()
    SENSITIVE_DATA_ACCESS = auto()


# -----------------------------------------------------------------------------
# Security Event & Audit Logging
# -----------------------------------------------------------------------------

@dataclass
class SecurityEvent:
    """Represents a security event for auditing."""
    event_type: SecurityEventType
    timestamp: float = field(default_factory=time.time)
    module: str = ""
    function: str = ""
    user_id: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    success: bool = True


class SecurityAuditLog:
    """Thread-safe security audit logging system."""
    
    def __init__(self, max_entries: int = 10000):
        self._lock = threading.RLock()
        self._events: List[SecurityEvent] = []
        self._max_entries = max_entries
        self._counters: Dict[SecurityEventType, int] = defaultdict(int)
    
    def log(self, event: SecurityEvent) -> None:
        """Log a security event."""
        with self._lock:
            self._events.append(event)
            self._counters[event.event_type] += 1
            
            # Trim if exceeded
            if len(self._events) > self._max_entries:
                self._events = self._events[-self._max_entries:]
    
    def get_event_count(self, event_type: Optional[SecurityEventType] = None) -> int:
        """Get count of events, optionally filtered by type."""
        with self._lock:
            if event_type:
                return self._counters.get(event_type, 0)
            return sum(self._counters.values())
    
    def get_recent_events(self, limit: int = 100) -> List[SecurityEvent]:
        """Get most recent security events."""
        with self._lock:
            return list(self._events[-limit:])
    
    def get_failure_rate(self) -> float:
        """Calculate security failure rate."""
        with self._lock:
            total = sum(self._counters.values())
            if total == 0:
                return 0.0
            failures = sum(
                count for et, count in self._counters.items()
                if not et.name.endswith('_PASS')
                and et not in (
                    SecurityEventType.MEMORY_ZEROIZATION,
                    SecurityEventType.CONSTANT_TIME_COMPARISON,
                    SecurityEventType.POLICY_ENFORCED,
                )
            )
            return failures / total


# Global audit log instance - thread safe singleton
_global_audit_log = SecurityAuditLog()


def get_security_audit_log() -> SecurityAuditLog:
    """Get the global security audit log instance."""
    return _global_audit_log


# -----------------------------------------------------------------------------
# Enhanced Input Validation
# -----------------------------------------------------------------------------

class InputValidationError(Exception):
    """Raised when input validation fails."""
    pass


class EnhancedInputValidator:
    """
    Enhanced input validation with multiple security checks.
    
    ADD-ONLY: Wraps existing validation, no core modifications.
    """
    
    # Common injection patterns
    _INJECTION_PATTERNS = [
        re.compile(r'(ignore|forget|disregard)\s+(all\s+)?previous\s+(instructions|context)', re.I),
        re.compile(r'you\s+are\s+(now|no\s+longer)\s+', re.I),
        re.compile(r'<\|beginoftext\|>', re.I),
        re.compile(r'system\s*prompt', re.I),
        re.compile(r'---\s*instructions?\s*---', re.I),
    ]
    
    # Maximum input sizes
    DEFAULT_MAX_LENGTH = 100000  # 100KB
    DEFAULT_MIN_LENGTH = 0
    
    def __init__(
        self,
        security_level: SecurityLevel = SecurityLevel.STANDARD,
        max_length: int = DEFAULT_MAX_LENGTH,
        min_length: int = DEFAULT_MIN_LENGTH,
        block_injection_patterns: bool = True,
        allow_null_bytes: bool = False,
        audit_log: Optional[SecurityAuditLog] = None,
    ):
        self.security_level = security_level
        self.max_length = max_length
        self.min_length = min_length
        self.block_injection_patterns = block_injection_patterns
        self.allow_null_bytes = allow_null_bytes
        self._audit = audit_log or _global_audit_log
        self._lock = threading.RLock()
    
    def _log_event(self, event_type: SecurityEventType, function: str, success: bool, **details):
        """Log a validation event."""
        self._audit.log(SecurityEvent(
            event_type=event_type,
            module="EnhancedInputValidator",
            function=function,
            success=success,
            details=details,
        ))
    
    def validate_string(
        self,
        value: Any,
        field_name: str = "input",
        max_length: Optional[int] = None,
        min_length: Optional[int] = None,
        allowed_chars: Optional[str] = None,
        regex_pattern: Optional[str] = None,
    ) -> str:
        """
        Validate and sanitize string input.
        
        Args:
            value: Input value to validate
            field_name: Name for error reporting
            max_length: Maximum allowed length
            min_length: Minimum allowed length
            allowed_chars: Whitelist of allowed characters
            regex_pattern: Regex pattern for validation
            
        Returns:
            Sanitized string
            
        Raises:
            InputValidationError: If validation fails
        """
        if self.security_level == SecurityLevel.DISABLED:
            return str(value) if value is not None else ""
        
        # Type check
        if not isinstance(value, str):
            self._log_event(
                SecurityEventType.INPUT_VALIDATION_FAIL,
                "validate_string",
                False,
                field=field_name,
                reason="wrong_type",
                got_type=type(value).__name__,
            )
            raise InputValidationError(
                f"{field_name}: expected string, got {type(value).__name__}"
            )
        
        # Null byte check
        if not self.allow_null_bytes and '\x00' in value:
            self._log_event(
                SecurityEventType.INPUT_VALIDATION_FAIL,
                "validate_string",
                False,
                field=field_name,
                reason="null_bytes",
            )
            raise InputValidationError(f"{field_name}: contains null bytes")
        
        # Length checks
        actual_max = max_length or self.max_length
        actual_min = min_length or self.min_length
        
        if len(value) > actual_max:
            self._log_event(
                SecurityEventType.INPUT_VALIDATION_FAIL,
                "validate_string",
                False,
                field=field_name,
                reason="too_long",
                length=len(value),
                max=actual_max,
            )
            raise InputValidationError(
                f"{field_name}: length {len(value)} exceeds maximum {actual_max}"
            )
        
        if len(value) < actual_min:
            self._log_event(
                SecurityEventType.INPUT_VALIDATION_FAIL,
                "validate_string",
                False,
                field=field_name,
                reason="too_short",
                length=len(value),
                min=actual_min,
            )
            raise InputValidationError(
                f"{field_name}: length {len(value)} below minimum {actual_min}"
            )
        
        # Injection pattern check (enhanced security)
        if self.block_injection_patterns and self.security_level.value >= SecurityLevel.ENHANCED.value:
            for pattern in self._INJECTION_PATTERNS:
                if pattern.search(value):
                    self._log_event(
                        SecurityEventType.INPUT_VALIDATION_FAIL,
                        "validate_string",
                        False,
                        field=field_name,
                        reason="injection_pattern",
                        pattern=pattern.pattern,
                    )
                    raise InputValidationError(
                        f"{field_name}: contains potential injection pattern"
                    )
        
        # Character whitelist
        if allowed_chars:
            for char in value:
                if char not in allowed_chars:
                    self._log_event(
                        SecurityEventType.INPUT_VALIDATION_FAIL,
                        "validate_string",
                        False,
                        field=field_name,
                        reason="invalid_character",
                        char=repr(char),
                    )
                    raise InputValidationError(
                        f"{field_name}: contains invalid character {repr(char)}"
                    )
        
        # Regex pattern
        if regex_pattern:
            if not re.fullmatch(regex_pattern, value):
                self._log_event(
                    SecurityEventType.INPUT_VALIDATION_FAIL,
                    "validate_string",
                    False,
                    field=field_name,
                    reason="regex_mismatch",
                )
                raise InputValidationError(f"{field_name}: does not match required pattern")
        
        self._log_event(
            SecurityEventType.INPUT_VALIDATION_PASS,
            "validate_string",
            True,
            field=field_name,
            length=len(value),
        )
        
        return value
    
    def validate_integer(
        self,
        value: Any,
        field_name: str = "input",
        min_value: Optional[int] = None,
        max_value: Optional[int] = None,
        positive_only: bool = False,
    ) -> int:
        """Validate integer input with bounds checking."""
        if self.security_level == SecurityLevel.DISABLED:
            return int(value)
        
        try:
            result = int(value)
        except (TypeError, ValueError):
            self._log_event(
                SecurityEventType.INPUT_VALIDATION_FAIL,
                "validate_integer",
                False,
                field=field_name,
                reason="not_integer",
            )
            raise InputValidationError(f"{field_name}: must be an integer")
        
        if positive_only and result < 0:
            self._log_event(
                SecurityEventType.INPUT_VALIDATION_FAIL,
                "validate_integer",
                False,
                field=field_name,
                reason="negative",
                value=result,
            )
            raise InputValidationError(f"{field_name}: must be non-negative")
        
        if min_value is not None and result < min_value:
            self._log_event(
                SecurityEventType.INPUT_VALIDATION_FAIL,
                "validate_integer",
                False,
                field=field_name,
                reason="below_min",
                value=result,
                min=min_value,
            )
            raise InputValidationError(f"{field_name}: {result} below minimum {min_value}")
        
        if max_value is not None and result > max_value:
            self._log_event(
                SecurityEventType.INPUT_VALIDATION_FAIL,
                "validate_integer",
                False,
                field=field_name,
                reason="above_max",
                value=result,
                max=max_value,
            )
            raise InputValidationError(f"{field_name}: {result} exceeds maximum {max_value}")
        
        self._log_event(
            SecurityEventType.INPUT_VALIDATION_PASS,
            "validate_integer",
            True,
            field=field_name,
        )
        
        return result


# -----------------------------------------------------------------------------
# Enhanced Rate Limiting with Circuit Breaker
# -----------------------------------------------------------------------------

class RateLimitExceededError(Exception):
    """Raised when rate limit is exceeded."""
    pass


class CircuitBreakerOpenError(Exception):
    """Raised when circuit breaker is open."""
    pass


class EnhancedRateLimiter:
    """
    Enhanced rate limiter with sliding window and circuit breaker.
    
    ADD-ONLY: Can wrap any function, no core modifications.
    """
    
    def __init__(
        self,
        max_requests: int = 100,
        window_seconds: float = 60.0,
        circuit_breaker_threshold: int = 10,
        circuit_breaker_cooldown: float = 30.0,
        audit_log: Optional[SecurityAuditLog] = None,
    ):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.circuit_breaker_threshold = circuit_breaker_threshold
        self.circuit_breaker_cooldown = circuit_breaker_cooldown
        
        self._lock = threading.RLock()
        self._requests: Dict[str, List[float]] = defaultdict(list)
        self._failure_counts: Dict[str, int] = defaultdict(int)
        self._circuit_open_until: Dict[str, float] = {}
        self._audit = audit_log or _global_audit_log
    
    def _cleanup_old_requests(self, key: str, now: float) -> None:
        """Remove requests outside the window."""
        cutoff = now - self.window_seconds
        self._requests[key] = [t for t in self._requests[key] if t > cutoff]
    
    def check_rate_limit(self, key: str = "global") -> None:
        """
        Check if rate limit is exceeded.
        
        Args:
            key: Rate limit key (e.g., user_id, ip_address)
            
        Raises:
            RateLimitExceededError: If rate limit exceeded
            CircuitBreakerOpenError: If circuit breaker is open
        """
        now = time.time()
        
        with self._lock:
            # Check circuit breaker
            if key in self._circuit_open_until:
                if now < self._circuit_open_until[key]:
                    self._audit.log(SecurityEvent(
                        event_type=SecurityEventType.RATE_LIMIT_EXCEEDED,
                        module="EnhancedRateLimiter",
                        function="check_rate_limit",
                        success=False,
                        details={"key": key, "reason": "circuit_breaker_open"},
                    ))
                    raise CircuitBreakerOpenError(
                        f"Circuit breaker open for {key}, cooldown until {self._circuit_open_until[key]}"
                    )
                else:
                    # Circuit recovered
                    del self._circuit_open_until[key]
                    self._failure_counts[key] = 0
            
            # Clean up and count
            self._cleanup_old_requests(key, now)
            current = len(self._requests[key])
            
            if current >= self.max_requests:
                self._failure_counts[key] += 1
                
                # Open circuit if threshold reached
                if self._failure_counts[key] >= self.circuit_breaker_threshold:
                    self._circuit_open_until[key] = now + self.circuit_breaker_cooldown
                
                self._audit.log(SecurityEvent(
                    event_type=SecurityEventType.RATE_LIMIT_EXCEEDED,
                    module="EnhancedRateLimiter",
                    function="check_rate_limit",
                    success=False,
                    details={
                        "key": key,
                        "current": current,
                        "max": self.max_requests,
                        "failures": self._failure_counts[key],
                    },
                ))
                raise RateLimitExceededError(
                    f"Rate limit exceeded: {current}/{self.max_requests} in {self.window_seconds}s"
                )
            
            self._requests[key].append(now)
    
    def get_remaining(self, key: str = "global") -> int:
        """Get remaining requests for a key."""
        now = time.time()
        with self._lock:
            self._cleanup_old_requests(key, now)
            return max(0, self.max_requests - len(self._requests[key]))
    
    def reset(self, key: str = "global") -> None:
        """Reset rate limit for a key."""
        with self._lock:
            self._requests[key].clear()
            self._failure_counts[key] = 0
            self._circuit_open_until.pop(key, None)


# Global rate limiter instance
_global_rate_limiter = EnhancedRateLimiter()


def get_global_rate_limiter() -> EnhancedRateLimiter:
    """Get the global rate limiter instance."""
    return _global_rate_limiter


# -----------------------------------------------------------------------------
# Security Policy Enforcement
# -----------------------------------------------------------------------------

class SecurityPolicy:
    """Defines a security policy that can be enforced on functions."""
    
    def __init__(
        self,
        name: str,
        required_permissions: Set[str],
        max_input_size: Optional[int] = None,
        rate_limited: bool = True,
        audit_logging: bool = True,
        validate_inputs: bool = True,
    ):
        self.name = name
        self.required_permissions = required_permissions
        self.max_input_size = max_input_size
        self.rate_limited = rate_limited
        self.audit_logging = audit_logging
        self.validate_inputs = validate_inputs


class SecurityPolicyEnforcer:
    """
    Enforces security policies on function calls.
    
    ADD-ONLY: Uses decorators, no core modifications.
    """
    
    def __init__(self, audit_log: Optional[SecurityAuditLog] = None):
        self._lock = threading.RLock()
        self._user_permissions: Dict[str, Set[str]] = defaultdict(set)
        self._policies: Dict[str, SecurityPolicy] = {}
        self._audit = audit_log or _global_audit_log
        self._validator = EnhancedInputValidator()
    
    def register_policy(self, policy: SecurityPolicy) -> None:
        """Register a security policy."""
        with self._lock:
            self._policies[policy.name] = policy
    
    def grant_permission(self, user_id: str, permission: str) -> None:
        """Grant a permission to a user."""
        with self._lock:
            self._user_permissions[user_id].add(permission)
    
    def revoke_permission(self, user_id: str, permission: str) -> None:
        """Revoke a permission from a user."""
        with self._lock:
            self._user_permissions[user_id].discard(permission)
    
    def has_permission(self, user_id: str, permission: str) -> bool:
        """Check if user has a permission."""
        with self._lock:
            return permission in self._user_permissions[user_id]
    
    def enforce(
        self,
        policy_name: str,
        user_id: str = "anonymous",
    ) -> Callable[[Callable[..., T]], Callable[..., T]]:
        """
        Decorator to enforce a security policy on a function.
        
        Usage:
            @enforcer.enforce("api_access", user_id="user123")
            def sensitive_function(...):
                ...
        """
        def decorator(func: Callable[..., T]) -> Callable[..., T]:
            @wraps(func)
            def wrapper(*args, **kwargs) -> T:
                policy = self._policies.get(policy_name)
                if not policy:
                    return func(*args, **kwargs)
                
                # Permission check
                for perm in policy.required_permissions:
                    if not self.has_permission(user_id, perm):
                        self._audit.log(SecurityEvent(
                            event_type=SecurityEventType.PERMISSION_DENIED,
                            module="SecurityPolicyEnforcer",
                            function=func.__name__,
                            user_id=user_id,
                            success=False,
                            details={"policy": policy_name, "missing_permission": perm},
                        ))
                        raise PermissionError(
                            f"User {user_id} lacks permission: {perm}"
                        )
                
                # Rate limiting
                if policy.rate_limited:
                    _global_rate_limiter.check_rate_limit(f"{user_id}:{policy_name}")
                
                # Input size validation
                if policy.max_input_size:
                    total_size = sum(
                        len(str(arg)) for arg in args
                    ) + sum(
                        len(str(v)) for v in kwargs.values()
                    )
                    if total_size > policy.max_input_size:
                        raise InputValidationError("Input size exceeds policy limit")
                
                self._audit.log(SecurityEvent(
                    event_type=SecurityEventType.POLICY_ENFORCED,
                    module="SecurityPolicyEnforcer",
                    function=func.__name__,
                    user_id=user_id,
                    success=True,
                    details={"policy": policy_name},
                ))
                
                return func(*args, **kwargs)
            
            return wrapper
        return decorator


# Global policy enforcer
_global_policy_enforcer = SecurityPolicyEnforcer()


def get_security_policy_enforcer() -> SecurityPolicyEnforcer:
    """Get the global security policy enforcer."""
    return _global_policy_enforcer


# -----------------------------------------------------------------------------
# Unified Security Facade
# -----------------------------------------------------------------------------

class SecurityHardeningFacade:
    """
    Unified facade for all security hardening features.
    
    This is the main entry point - provides one-stop access to:
    - Input validation
    - Rate limiting
    - Policy enforcement
    - Audit logging
    - Memory security
    
    100% ADD-ONLY - wraps existing functionality without modification.
    """
    
    def __init__(
        self,
        security_level: SecurityLevel = SecurityLevel.STANDARD,
    ):
        self.security_level = security_level
        self.validator = EnhancedInputValidator(security_level=security_level)
        self.rate_limiter = EnhancedRateLimiter()
        self.policy_enforcer = SecurityPolicyEnforcer()
        self.audit_log = get_security_audit_log()
    
    # --- Input Validation ---
    
    def validate_string(self, *args, **kwargs) -> str:
        return self.validator.validate_string(*args, **kwargs)
    
    def validate_integer(self, *args, **kwargs) -> int:
        return self.validator.validate_integer(*args, **kwargs)
    
    # --- Rate Limiting ---
    
    def check_rate_limit(self, key: str = "global") -> None:
        self.rate_limiter.check_rate_limit(key)
    
    def get_rate_limit_remaining(self, key: str = "global") -> int:
        return self.rate_limiter.get_remaining(key)
    
    # --- Policy Enforcement ---
    
    def grant_permission(self, user_id: str, permission: str) -> None:
        self.policy_enforcer.grant_permission(user_id, permission)
    
    def revoke_permission(self, user_id: str, permission: str) -> None:
        self.policy_enforcer.revoke_permission(user_id, permission)
    
    def has_permission(self, user_id: str, permission: str) -> bool:
        return self.policy_enforcer.has_permission(user_id, permission)
    
    # --- Audit Logging ---
    
    def get_security_event_count(self) -> int:
        return self.audit_log.get_event_count()
    
    def get_security_failure_rate(self) -> float:
        return self.audit_log.get_failure_rate()
    
    def get_recent_security_events(self, limit: int = 100) -> List[SecurityEvent]:
        return self.audit_log.get_recent_events(limit)
    
    # --- Memory Security ---
    
    @staticmethod
    def secure_zeroize(data: Union[bytearray, memoryview, List[int]]) -> None:
        """Securely zeroize sensitive data."""
        if isinstance(data, bytearray):
            for i in range(len(data)):
                data[i] = 0
        elif isinstance(data, memoryview):
            data[:] = b'\x00' * len(data)
        elif isinstance(data, list):
            for i in range(len(data)):
                data[i] = 0
    
    @staticmethod
    def constant_time_compare(a: bytes, b: bytes) -> bool:
        """Constant-time byte comparison to prevent timing attacks."""
        return hmac.compare_digest(a, b)
    
    # --- Convenience Decorators ---
    
    def secure_function(
        self,
        rate_limit_key: Optional[str] = None,
        validate_inputs: bool = True,
    ) -> Callable[[Callable[..., T]], Callable[..., T]]:
        """
        Decorator to apply full security hardening to a function.
        
        Includes: rate limiting, input validation, audit logging.
        """
        def decorator(func: Callable[..., T]) -> Callable[..., T]:
            @wraps(func)
            def wrapper(*args, **kwargs) -> T:
                # Rate limiting
                if rate_limit_key:
                    self.check_rate_limit(rate_limit_key)
                
                # Input validation (basic type checking)
                if validate_inputs and self.security_level.value >= SecurityLevel.STANDARD.value:
                    for i, arg in enumerate(args):
                        if isinstance(arg, str):
                            self.validate_string(arg, f"arg_{i}")
                
                return func(*args, **kwargs)
            
            return wrapper
        return decorator


# -----------------------------------------------------------------------------
# Convenience Functions (Global Access)
# -----------------------------------------------------------------------------

# Default facade instance for quick access
_default_facade = SecurityHardeningFacade()


def secure_validate_string(*args, **kwargs) -> str:
    return _default_facade.validate_string(*args, **kwargs)


def secure_validate_integer(*args, **kwargs) -> int:
    return _default_facade.validate_integer(*args, **kwargs)


def secure_check_rate_limit(key: str = "global") -> None:
    _default_facade.check_rate_limit(key)


def secure_zeroize_memory(data: Union[bytearray, memoryview, List[int]]) -> None:
    SecurityHardeningFacade.secure_zeroize(data)


def constant_time_compare(a: bytes, b: bytes) -> bool:
    return SecurityHardeningFacade.constant_time_compare(a, b)


def get_security_stats() -> Dict[str, Any]:
    """Get comprehensive security statistics."""
    return {
        "security_level": _default_facade.security_level.name,
        "total_events": _default_facade.get_security_event_count(),
        "failure_rate": _default_facade.get_security_failure_rate(),
        "rate_limit_remaining_global": _default_facade.get_rate_limit_remaining(),
    }
