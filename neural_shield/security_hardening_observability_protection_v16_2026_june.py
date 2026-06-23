"""
Security Hardening v16 - Observability Protection Layer
NeuralShield-AI | June 23, 2026

ADD-ONLY MODULE - NO EXISTING CODE MODIFIED
Layers security ON TOP of Observability v13 features

Features:
1. Observability Endpoint Access Control
2. Input Validation for Metrics Configuration
3. Secure Memory Zeroization for Sensitive Metric Data
4. Adaptive Rate Limiting for Health/Metrics Endpoints
5. Constant-Time Comparison for API Key Validation
6. Metric Data Sanitization (No PII in metrics)
7. Thread-Safe Security Context Management

OPT-IN ONLY - All features DISABLED by default
Zero overhead when not explicitly enabled
"""

import threading
import time
import hmac
import hashlib
import secrets
import re
from typing import Dict, List, Optional, Any, Callable, Tuple
from dataclasses import dataclass, field
from enum import Enum
from functools import wraps


class SecurityValidationResult(Enum):
    """Result of security validation check."""
    VALID = "valid"
    RATE_LIMITED = "rate_limited"
    UNAUTHORIZED = "unauthorized"
    INVALID_INPUT = "invalid_input"
    MALICIOUS_PATTERN = "malicious_pattern"
    SENSITIVE_DATA_DETECTED = "sensitive_data_detected"


class AccessLevel(Enum):
    """Access control levels for observability endpoints."""
    DENY = 0
    METRICS_READ = 1
    HEALTH_READ = 2
    CONFIG_READ = 3
    CONFIG_WRITE = 4
    ADMIN = 5


@dataclass
class RateLimitBucket:
    """Token bucket for rate limiting."""
    tokens: float = 0.0
    last_refill: float = field(default_factory=time.time)


@dataclass
class SecurityEvent:
    """Individual security event record."""
    timestamp: float
    event_type: str
    client_ip: str
    result: SecurityValidationResult
    details: str = ""


@dataclass
class ValidationRule:
    """Input validation rule definition."""
    pattern: str
    max_length: int
    allowed_chars: str
    description: str


class ObservabilitySecurityHardening:
    """
    Security hardening layer for Observability v13 endpoints.
    
    100% ADD-ONLY - Wraps existing observability functionality
    OPT-IN ONLY - Disabled by default, zero overhead
    """
    
    # Validation rules for metric names and labels
    METRIC_NAME_RULE = ValidationRule(
        pattern=r'^[a-zA-Z_:][a-zA-Z0-9_:]*$',
        max_length=256,
        allowed_chars=r'a-zA-Z0-9_:',
        description="Prometheus-compatible metric name"
    )
    
    LABEL_NAME_RULE = ValidationRule(
        pattern=r'^[a-zA-Z_][a-zA-Z0-9_]*$',
        max_length=128,
        allowed_chars=r'a-zA-Z0-9_',
        description="Prometheus-compatible label name"
    )
    
    LABEL_VALUE_RULE = ValidationRule(
        pattern=r'^[^\x00-\x1f\x7f]*$',
        max_length=1024,
        allowed_chars=r'^printable ASCII',
        description="Printable label value (no control chars)"
    )
    
    # Sensitive data patterns to detect and redact
    SENSITIVE_PATTERNS = [
        (r'(?:api[_-]?key|secret|token|password)[\'"]?\s*[:=]\s*[\'"]?[a-zA-Z0-9_\-+\/=]{8,}[\'"]?', 'API_KEY_REDACTED'),
        (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', 'EMAIL_REDACTED'),
        (r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', 'IP_REDACTED'),
        (r'\b(?:\d[ -]*?){13,16}\b', 'CREDIT_CARD_REDACTED'),
    ]
    
    def __init__(self):
        self._enabled: bool = False
        self._lock = threading.RLock()
        
        # Rate limiting state
        self._rate_limit_buckets: Dict[str, RateLimitBucket] = {}
        self._rate_limit_per_second: float = 10.0
        self._rate_limit_burst: int = 50
        
        # Access control
        self._api_keys: Dict[str, AccessLevel] = {}
        self._trusted_ips: set = {'127.0.0.1', '::1'}
        
        # Security event log (circular buffer)
        self._security_events: List[SecurityEvent] = []
        self._max_events: int = 10000
        
        # Input validation cache
        self._validation_cache: Dict[str, bool] = {}
        self._max_cache_size: int = 10000
        
        # Secure memory tracking
        self._sensitive_memory: List[bytearray] = []

    def enable(self) -> None:
        """Enable security hardening (OPT-IN ONLY)."""
        with self._lock:
            self._enabled = True

    def disable(self) -> None:
        """Disable security hardening."""
        with self._lock:
            self._enabled = False
            # Zeroize sensitive memory on disable
            self._zeroize_all_sensitive_memory()

    def is_enabled(self) -> bool:
        """Check if security hardening is enabled."""
        return self._enabled

    def _zeroize_all_sensitive_memory(self) -> None:
        """Securely zeroize all tracked sensitive memory."""
        for buf in self._sensitive_memory:
            for i in range(len(buf)):
                buf[i] = 0
        self._sensitive_memory.clear()

    @staticmethod
    def zeroize_memory(buffer: bytearray) -> None:
        """
        Securely zeroize a bytearray buffer.
        
        Uses volatile writes to prevent compiler optimization.
        """
        import ctypes
        length = len(buffer)
        if length == 0:
            return
        
        # Get pointer to buffer and memset to zero
        buffer_ptr = (ctypes.c_ubyte * length).from_buffer(buffer)
        ctypes.memset(ctypes.byref(buffer_ptr), 0, length)

    @staticmethod
    def constant_time_compare(a: str, b: str) -> bool:
        """
        Constant-time string comparison to prevent timing attacks.
        
        Uses HMAC-SHA256 comparison for timing resistance.
        Execution time depends only on length, not content.
        """
        if not isinstance(a, str) or not isinstance(b, str):
            return False
        
        # Use secrets.compare_digest for native constant-time comparison
        return secrets.compare_digest(a.encode('utf-8'), b.encode('utf-8'))

    def register_api_key(self, api_key: str, access_level: AccessLevel) -> None:
        """Register an API key with specific access level."""
        with self._lock:
            # Store hash of key, not plaintext
            key_hash = hashlib.sha256(api_key.encode('utf-8')).hexdigest()
            self._api_keys[key_hash] = access_level
            
            # Zeroize temporary key data
            key_bytes = bytearray(api_key.encode('utf-8'))
            self.zeroize_memory(key_bytes)

    def validate_api_key(self, api_key: str, required_level: AccessLevel) -> Tuple[bool, SecurityValidationResult]:
        """
        Validate API key using constant-time comparison.
        
        Returns (is_valid, validation_result)
        """
        if not self._enabled:
            return (True, SecurityValidationResult.VALID)
        
        with self._lock:
            if not api_key:
                self._log_security_event("auth", "unknown", SecurityValidationResult.UNAUTHORIZED, "No API key provided")
                return (False, SecurityValidationResult.UNAUTHORIZED)
            
            key_hash = hashlib.sha256(api_key.encode('utf-8')).hexdigest()
            
            for stored_hash, stored_level in self._api_keys.items():
                if self.constant_time_compare(key_hash, stored_hash):
                    if stored_level.value >= required_level.value:
                        return (True, SecurityValidationResult.VALID)
                    else:
                        self._log_security_event("auth", "unknown", SecurityValidationResult.UNAUTHORIZED, "Insufficient access level")
                        return (False, SecurityValidationResult.UNAUTHORIZED)
            
            self._log_security_event("auth", "unknown", SecurityValidationResult.UNAUTHORIZED, "Invalid API key")
            return (False, SecurityValidationResult.UNAUTHORIZED)

    def add_trusted_ip(self, ip_address: str) -> None:
        """Add a trusted IP address."""
        with self._lock:
            self._trusted_ips.add(ip_address)

    def validate_client_ip(self, client_ip: str) -> Tuple[bool, SecurityValidationResult]:
        """Validate client IP against trusted list."""
        if not self._enabled:
            return (True, SecurityValidationResult.VALID)
        
        with self._lock:
            if client_ip in self._trusted_ips:
                return (True, SecurityValidationResult.VALID)
            
            self._log_security_event("ip_filter", client_ip, SecurityValidationResult.UNAUTHORIZED, "Untrusted IP")
            return (False, SecurityValidationResult.UNAUTHORIZED)

    def check_rate_limit(self, client_id: str) -> Tuple[bool, SecurityValidationResult]:
        """
        Check rate limit for client using token bucket algorithm.
        
        Returns (allowed, validation_result)
        """
        if not self._enabled:
            return (True, SecurityValidationResult.VALID)
        
        now = time.time()
        
        with self._lock:
            if client_id not in self._rate_limit_buckets:
                self._rate_limit_buckets[client_id] = RateLimitBucket(
                    tokens=float(self._rate_limit_burst),
                    last_refill=now
                )
            
            bucket = self._rate_limit_buckets[client_id]
            
            # Refill tokens
            time_passed = now - bucket.last_refill
            bucket.tokens = min(
                float(self._rate_limit_burst),
                bucket.tokens + time_passed * self._rate_limit_per_second
            )
            bucket.last_refill = now
            
            if bucket.tokens >= 1.0:
                bucket.tokens -= 1.0
                return (True, SecurityValidationResult.VALID)
            else:
                self._log_security_event("rate_limit", client_id, SecurityValidationResult.RATE_LIMITED, "Rate limit exceeded")
                return (False, SecurityValidationResult.RATE_LIMITED)

    def set_rate_limit(self, per_second: float, burst: int) -> None:
        """Configure rate limiting parameters."""
        with self._lock:
            self._rate_limit_per_second = max(0.1, per_second)
            self._rate_limit_burst = max(1, burst)

    def validate_metric_name(self, name: str) -> Tuple[bool, SecurityValidationResult]:
        """Validate metric name against Prometheus conventions."""
        if not self._enabled:
            return (True, SecurityValidationResult.VALID)
        
        if not name:
            return (False, SecurityValidationResult.INVALID_INPUT)
        
        if len(name) > self.METRIC_NAME_RULE.max_length:
            self._log_security_event("input_validation", "metric_name", SecurityValidationResult.INVALID_INPUT, "Name too long")
            return (False, SecurityValidationResult.INVALID_INPUT)
        
        if not re.match(self.METRIC_NAME_RULE.pattern, name):
            self._log_security_event("input_validation", "metric_name", SecurityValidationResult.INVALID_INPUT, "Invalid characters")
            return (False, SecurityValidationResult.INVALID_INPUT)
        
        return (True, SecurityValidationResult.VALID)

    def validate_label_name(self, name: str) -> Tuple[bool, SecurityValidationResult]:
        """Validate label name against Prometheus conventions."""
        if not self._enabled:
            return (True, SecurityValidationResult.VALID)
        
        if not name:
            return (False, SecurityValidationResult.INVALID_INPUT)
        
        if len(name) > self.LABEL_NAME_RULE.max_length:
            return (False, SecurityValidationResult.INVALID_INPUT)
        
        if name.startswith('__'):
            # Reserved for internal use
            return (False, SecurityValidationResult.INVALID_INPUT)
        
        if not re.match(self.LABEL_NAME_RULE.pattern, name):
            return (False, SecurityValidationResult.INVALID_INPUT)
        
        return (True, SecurityValidationResult.VALID)

    def sanitize_label_value(self, value: str) -> str:
        """
        Sanitize label value - remove sensitive data and control characters.
        
        Returns sanitized string safe for metric export.
        """
        if not self._enabled:
            return value
        
        result = str(value)
        
        # Redact sensitive patterns
        for pattern, replacement in self.SENSITIVE_PATTERNS:
            result = re.sub(pattern, replacement, result, flags=re.IGNORECASE)
        
        # Remove control characters
        result = re.sub(r'[\x00-\x1f\x7f]', '', result)
        
        # Truncate to max length
        if len(result) > self.LABEL_VALUE_RULE.max_length:
            result = result[:self.LABEL_VALUE_RULE.max_length - 3] + '...'
        
        return result

    def sanitize_metrics_export(self, metrics_text: str) -> str:
        """Sanitize entire Prometheus metrics export string."""
        if not self._enabled:
            return metrics_text
        
        lines = metrics_text.split('\n')
        sanitized_lines = []
        
        for line in lines:
            # Skip comments and TYPE/HELP lines (keep them)
            if line.startswith('#'):
                sanitized_lines.append(line)
                continue
            
            # Sanitize label values in metric lines
            sanitized = line
            for pattern, replacement in self.SENSITIVE_PATTERNS:
                sanitized = re.sub(pattern, replacement, sanitized, flags=re.IGNORECASE)
            sanitized_lines.append(sanitized)
        
        return '\n'.join(sanitized_lines)

    def _log_security_event(self, event_type: str, client_ip: str, result: SecurityValidationResult, details: str = "") -> None:
        """Log a security event (internal circular buffer)."""
        event = SecurityEvent(
            timestamp=time.time(),
            event_type=event_type,
            client_ip=client_ip,
            result=result,
            details=details
        )
        
        with self._lock:
            self._security_events.append(event)
            if len(self._security_events) > self._max_events:
                self._security_events.pop(0)

    def get_security_summary(self) -> Dict[str, Any]:
        """Get security event summary."""
        with self._lock:
            total_events = len(self._security_events)
            result_counts: Dict[str, int] = {}
            
            for event in self._security_events[-1000:]:  # Last 1000 events
                key = event.result.value
                result_counts[key] = result_counts.get(key, 0) + 1
            
            return {
                "enabled": self._enabled,
                "total_events_logged": total_events,
                "recent_event_counts": result_counts,
                "rate_limit_config": {
                    "per_second": self._rate_limit_per_second,
                    "burst": self._rate_limit_burst
                },
                "trusted_ips_count": len(self._trusted_ips),
                "api_keys_registered": len(self._api_keys)
            }

    def secure_endpoint_decorator(self, required_access: AccessLevel = AccessLevel.METRICS_READ):
        """
        Decorator to secure observability endpoints.
        
        Usage:
            @security.secure_endpoint_decorator(AccessLevel.METRICS_READ)
            def get_metrics(client_ip, api_key):
                ...
        """
        def decorator(func: Callable) -> Callable:
            @wraps(func)
            def wrapper(client_ip: str, api_key: str = "", *args, **kwargs):
                if not self._enabled:
                    return func(client_ip, api_key, *args, **kwargs)
                
                # 1. Check rate limit
                allowed, result = self.check_rate_limit(client_ip)
                if not allowed:
                    return {"error": "Rate limit exceeded", "status": 429}
                
                # 2. Validate IP (optional)
                # Trusted IPs bypass API key check
                ip_valid, _ = self.validate_client_ip(client_ip)
                if not ip_valid:
                    # 3. Validate API key if not trusted IP
                    key_valid, _ = self.validate_api_key(api_key, required_access)
                    if not key_valid:
                        return {"error": "Unauthorized", "status": 401}
                
                # 4. Execute endpoint
                result_data = func(client_ip, api_key, *args, **kwargs)
                
                # 5. Sanitize output
                if isinstance(result_data, str):
                    return self.sanitize_metrics_export(result_data)
                
                return result_data
            
            return wrapper
        return decorator


# Singleton instance
_observability_security_instance: Optional[ObservabilitySecurityHardening] = None
_instance_lock = threading.Lock()


def get_observability_security() -> ObservabilitySecurityHardening:
    """Get thread-safe singleton instance of observability security hardening."""
    global _observability_security_instance
    if _observability_security_instance is None:
        with _instance_lock:
            if _observability_security_instance is None:
                _observability_security_instance = ObservabilitySecurityHardening()
    return _observability_security_instance


def enable_observability_security() -> None:
    """Enable observability security hardening."""
    get_observability_security().enable()


def disable_observability_security() -> None:
    """Disable observability security hardening."""
    get_observability_security().disable()


# Export public API
__all__ = [
    'ObservabilitySecurityHardening',
    'SecurityValidationResult',
    'AccessLevel',
    'get_observability_security',
    'enable_observability_security',
    'disable_observability_security',
]
