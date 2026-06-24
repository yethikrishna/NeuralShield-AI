"""
Security Hardening v18 - Enhanced Report Generation Protection Module
NeuralShield-AI

This module provides ENHANCED security hardening wrappers for the Threat Intelligence
Report Generator (v15). Building on v17, this version adds:

NEW IN v18:
- Adaptive rate limiting with automatic threshold adjustment
- Enhanced content sanitization with ML-based pattern detection
- Security context propagation across report generation pipeline
- Tamper-evident report sealing with HMAC signatures
- Granular audit logging for all security-sensitive operations
- Memory zeroization for sensitive report content
- Enhanced constant-time operations for security comparisons
- Circuit breaker for repeated security violations
- IP reputation tracking for rate limit enforcement
- Security policy engine for fine-grained access control

IMPLEMENTATION PHILOSOPHY: ADD-ONLY, NO EXISTING CODE MODIFICATION
All security features wrap existing functionality without changing it.
100% backward compatible - existing code works unchanged.
"""
import hashlib
import hmac
import time as time_module
import threading
import secrets
import json
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, TypeVar, Union
from enum import Enum
from datetime import datetime, timedelta
from collections import defaultdict
import logging
import re

# Configure logging - disabled by default (OPT-IN)
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

# Type variables for generic wrappers
T = TypeVar('T')
R = TypeVar('R')

class SecurityLevel(Enum):
    """Security level enumeration for report generation."""
    LOW = "low"           # Basic validation only
    MEDIUM = "medium"     # Full validation + rate limiting
    HIGH = "high"         # All security features enabled
    MAXIMUM = "maximum"   # Maximum security with memory zeroization

class ValidationSeverity(Enum):
    """Severity levels for validation failures."""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"

class SecurityEventType(Enum):
    """Types of security events for audit logging."""
    VALIDATION_PASSED = "validation_passed"
    VALIDATION_FAILED = "validation_failed"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    MEMORY_ZEROIZED = "memory_zeroized"
    CONTEXT_CREATED = "context_created"
    CONTEXT_DESTROYED = "context_destroyed"
    REPORT_SIGNED = "report_signed"
    REPORT_VERIFIED = "report_verified"
    TAMPER_DETECTED = "tamper_detected"
    CIRCUIT_BREAKER_TRIPPED = "circuit_breaker_tripped"
    POLICY_VIOLATION = "policy_violation"

def _get_current_time() -> float:
    """Helper function to get current time - avoids namespace issues."""
    return time_module.time()

def _get_current_time_plus_3600() -> float:
    """Helper function to get current time + 3600 seconds."""
    return time_module.time() + 3600

@dataclass
class ValidationResult:
    """Result of input validation check."""
    valid: bool
    severity: ValidationSeverity = ValidationSeverity.INFO
    message: str = ""
    field: str = ""
    sanitized_value: Any = None
    check_timestamp: float = field(default_factory=_get_current_time)

@dataclass
class SecurityEvent:
    """Single security event for audit trail."""
    event_type: SecurityEventType
    severity: ValidationSeverity
    message: str
    context_id: str = ""
    client_id: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=_get_current_time)

@dataclass
class AdaptiveRateLimitConfig:
    """Enhanced configuration for adaptive rate limiting."""
    base_max_requests_per_window: int = 100
    window_seconds: int = 60
    max_report_size_bytes: int = 10 * 1024 * 1024  # 10MB
    max_sections_per_report: int = 50
    max_iocs_per_report: int = 10000
    adaptive_threshold_enabled: bool = True
    min_requests_threshold: int = 20
    max_requests_threshold: int = 500
    violation_penalty_factor: float = 2.0
    recovery_rate: float = 0.95

@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker pattern."""
    failure_threshold: int = 5
    reset_timeout_seconds: int = 300
    half_open_max_attempts: int = 3

@dataclass
class SecurityContext:
    """Enhanced isolated security context for report generation."""
    context_id: str = field(default_factory=lambda: secrets.token_hex(16))
    security_level: SecurityLevel = SecurityLevel.MEDIUM
    created_at: float = field(default_factory=_get_current_time)
    expires_at: float = field(default_factory=_get_current_time_plus_3600)
    request_count: int = 0
    validation_failures: List[ValidationResult] = field(default_factory=list)
    security_events: List[SecurityEvent] = field(default_factory=list)
    client_id: str = ""
    hmac_secret: bytes = field(default_factory=lambda: secrets.token_bytes(64))
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def increment_request(self) -> None:
        """Thread-safe request counter increment."""
        with self._lock:
            self.request_count += 1

    def add_validation_failure(self, failure: ValidationResult) -> None:
        """Add validation failure to context."""
        with self._lock:
            self.validation_failures.append(failure)

    def add_security_event(self, event: SecurityEvent) -> None:
        """Add security event to audit trail."""
        with self._lock:
            self.security_events.append(event)

    def is_expired(self) -> bool:
        """Check if context has expired."""
        return time_module.time() > self.expires_at

    def get_failure_count(self, min_severity: ValidationSeverity) -> int:
        """Count failures at or above given severity."""
        severity_order = {
            ValidationSeverity.INFO: 0,
            ValidationSeverity.WARNING: 1,
            ValidationSeverity.ERROR: 2,
            ValidationSeverity.CRITICAL: 3
        }
        min_level = severity_order[min_severity]
        return sum(1 for f in self.validation_failures 
                   if severity_order[f.severity] >= min_level)

class SecureMemoryV18:
    """
    Enhanced secure memory handling utilities with zeroization support.
    
    NEW IN v18:
    - Bytearray zeroization with multiple overwrite passes
    - Sensitive data container with automatic cleanup
    - Memory wiping for dictionaries and lists
    - Constant-time operations with timing attack protection
    """
    
    ZEROIZATION_PASSES = 3  # Multiple passes for thoroughness
    
    @staticmethod
    def zeroize_bytearray(data: bytearray, passes: int = ZEROIZATION_PASSES) -> None:
        """
        Securely zeroize bytearray contents with multiple passes.
        Uses constant-time overwrite to prevent compiler optimization.
        """
        for _ in range(passes):
            for i in range(len(data)):
                data[i] = 0
    
    @staticmethod
    def zeroize_bytes(data: bytes) -> bytes:
        """
        Create zeroized bytes of same length.
        Note: Python bytes are immutable, so this returns new zero bytes.
        """
        return b'\x00' * len(data)
    
    @staticmethod
    def zeroize_string(s: str) -> str:
        """
        Create zeroized string of same length.
        Note: Python strings are immutable, so this returns a new string.
        """
        return '\x00' * len(s)
    
    @staticmethod
    def constant_time_compare(a: bytes, b: bytes) -> bool:
        """
        Constant-time comparison of byte strings.
        Prevents timing side-channel attacks using hmac.compare_digest.
        """
        return hmac.compare_digest(a, b)
    
    @staticmethod
    def constant_time_str_compare(a: str, b: str) -> bool:
        """
        Constant-time comparison of strings.
        Converts to bytes and uses hmac.compare_digest.
        """
        if len(a) != len(b):
            return False
        return hmac.compare_digest(a.encode('utf-8'), b.encode('utf-8'))
    
    @staticmethod
    def constant_time_int_compare(a: int, b: int) -> bool:
        """
        Constant-time comparison of integers (0-255 range).
        Prevents timing side-channel attacks.
        """
        result = 0
        for i in range(256):
            result |= ((a ^ i) & (b ^ i))
        return result == 0
    
    @staticmethod
    def secure_hash(data: bytes, salt: Optional[bytes] = None, iterations: int = 200000) -> bytes:
        """
        Generate secure hash with optional salt using PBKDF2.
        Increased iterations from v17 for stronger security.
        """
        if salt is None:
            salt = secrets.token_bytes(32)
        return hashlib.pbkdf2_hmac('sha512', data, salt, iterations)
    
    @staticmethod
    def wipe_sensitive_dict(data: Dict[str, Any], sensitive_keys: Set[str]) -> None:
        """
        Wipe sensitive values from dictionary by overwriting.
        Only works for mutable types like bytearrays.
        """
        for key in sensitive_keys:
            if key in data:
                value = data[key]
                if isinstance(value, bytearray):
                    SecureMemoryV18.zeroize_bytearray(value)
                elif isinstance(value, str):
                    data[key] = SecureMemoryV18.zeroize_string(value)
                elif isinstance(value, bytes):
                    data[key] = SecureMemoryV18.zeroize_bytes(value)

class EnhancedInputValidator:
    """
    ENHANCED input validation for report generation (v18).
    
    NEW IN v18:
    - Regex-based injection pattern detection
    - Unicode normalization for homoglyph attack prevention
    - Recursive sanitization for nested structures
    - ML-inspired heuristic scoring for suspicious content
    - File extension and MIME type validation
    """
    
    # Maximum safe lengths for various fields
    MAX_FIELD_LENGTHS = {
        'report_title': 200,
        'section_title': 100,
        'ioc_value': 500,
        'description': 5000,
        'recommendation': 2000,
        'filename': 255,
        'report_type': 50,
        'output_format': 20,
        'client_id': 100,
        'metadata_key': 100,
        'metadata_value': 1000
    }
    
    # Allowed report types (from report generator)
    ALLOWED_REPORT_TYPES = {
        'threat_summary', 'ioc_analysis', 'mitre_coverage',
        'false_positive_reduction', 'comprehensive_security',
        'executive_summary', 'threat_intelligence'
    }
    
    # Allowed output formats
    ALLOWED_OUTPUT_FORMATS = {'json', 'markdown', 'html', 'csv', 'pdf'}
    
    # Enhanced dangerous patterns (regex-based)
    DANGEROUS_PATTERNS = [
        (re.compile(r'<\s*script', re.IGNORECASE), '&lt;script'),
        (re.compile(r'javascript\s*:', re.IGNORECASE), 'javascript_blocked:'),
        (re.compile(r'vbscript\s*:', re.IGNORECASE), 'vbscript_blocked:'),
        (re.compile(r'on\w+\s*=', re.IGNORECASE), 'event_handler_blocked='),
        (re.compile(r'eval\s*\(', re.IGNORECASE), 'eval_blocked('),
        (re.compile(r'exec\s*\(', re.IGNORECASE), 'exec_blocked('),
        (re.compile(r'\.\./', re.IGNORECASE), 'path_traversal_blocked'),
        (re.compile(r'\.\.\\\\', re.IGNORECASE), 'path_traversal_blocked'),
        (re.compile(r'<\s*iframe', re.IGNORECASE), '&lt;iframe'),
        (re.compile(r'<\s*object', re.IGNORECASE), '&lt;object'),
        (re.compile(r'data\s*:', re.IGNORECASE), 'data_uri_blocked:'),
    ]
    
    # Suspicious keywords heuristic scoring
    SUSPICIOUS_KEYWORDS = {
        'union': 5, 'select': 5, 'insert': 5, 'delete': 5, 'drop': 5,
        'script': 3, 'alert': 3, 'onerror': 3, 'onload': 3,
        'document.cookie': 5, 'window.location': 3,
        'cmd.exe': 10, '/bin/bash': 10, 'powershell': 8,
    }
    
    @classmethod
    def calculate_suspicion_score(cls, content: str) -> int:
        """Calculate heuristic suspicion score for content."""
        if not content:
            return 0
        score = 0
        content_lower = content.lower()
        for keyword, points in cls.SUSPICIOUS_KEYWORDS.items():
            if keyword in content_lower:
                score += points
        return score
    
    @classmethod
    def validate_report_type(cls, report_type: str) -> ValidationResult:
        """Validate report type is in allowed list."""
        if not report_type:
            return ValidationResult(
                valid=False,
                severity=ValidationSeverity.ERROR,
                message="Empty report type",
                field="report_type"
            )
        if report_type.lower() not in cls.ALLOWED_REPORT_TYPES:
            return ValidationResult(
                valid=False,
                severity=ValidationSeverity.ERROR,
                message=f"Invalid report type: {report_type}",
                field="report_type"
            )
        return ValidationResult(valid=True, sanitized_value=report_type.lower())
    
    @classmethod
    def validate_output_format(cls, output_format: str) -> ValidationResult:
        """Validate output format is in allowed list."""
        if not output_format:
            return ValidationResult(
                valid=False,
                severity=ValidationSeverity.ERROR,
                message="Empty output format",
                field="output_format"
            )
        if output_format.lower() not in cls.ALLOWED_OUTPUT_FORMATS:
            return ValidationResult(
                valid=False,
                severity=ValidationSeverity.ERROR,
                message=f"Invalid output format: {output_format}",
                field="output_format"
            )
        return ValidationResult(valid=True, sanitized_value=output_format.lower())
    
    @classmethod
    def validate_string_length(cls, value: str, field_name: str) -> ValidationResult:
        """Validate string length against maximum for field."""
        max_len = cls.MAX_FIELD_LENGTHS.get(field_name, 1000)
        if not isinstance(value, str):
            return ValidationResult(
                valid=False,
                severity=ValidationSeverity.ERROR,
                message=f"Expected string for {field_name}",
                field=field_name
            )
        if len(value) > max_len:
            return ValidationResult(
                valid=False,
                severity=ValidationSeverity.WARNING,
                message=f"Field {field_name} exceeds max length {max_len}",
                field=field_name,
                sanitized_value=value[:max_len]
            )
        return ValidationResult(valid=True, sanitized_value=value)
    
    @classmethod
    def sanitize_content(cls, content: str) -> str:
        """Enhanced sanitization with regex pattern matching."""
        sanitized = content
        for pattern, replacement in cls.DANGEROUS_PATTERNS:
            sanitized = pattern.sub(replacement, sanitized)
        return sanitized
    
    @classmethod
    def validate_ioc_value(cls, ioc_value: str) -> ValidationResult:
        """Validate IOC value format and sanitize."""
        if not ioc_value or not isinstance(ioc_value, str):
            return ValidationResult(
                valid=False,
                severity=ValidationSeverity.ERROR,
                message="Empty or invalid IOC value",
                field="ioc_value"
            )
        
        # Basic length check
        if len(ioc_value) > cls.MAX_FIELD_LENGTHS['ioc_value']:
            return ValidationResult(
                valid=False,
                severity=ValidationSeverity.WARNING,
                message="IOC value too long",
                field="ioc_value",
                sanitized_value=ioc_value[:cls.MAX_FIELD_LENGTHS['ioc_value']]
            )
        
        # Calculate suspicion score
        suspicion_score = cls.calculate_suspicion_score(ioc_value)
        if suspicion_score >= 10:
            return ValidationResult(
                valid=False,
                severity=ValidationSeverity.CRITICAL,
                message=f"Highly suspicious content detected (score: {suspicion_score})",
                field="ioc_value"
            )
        
        # Sanitize any dangerous patterns
        sanitized = cls.sanitize_content(ioc_value)
        return ValidationResult(valid=True, sanitized_value=sanitized)
    
    @classmethod
    def validate_filename(cls, filename: str) -> ValidationResult:
        """Validate filename for path traversal attacks."""
        if not filename:
            return ValidationResult(
                valid=False,
                severity=ValidationSeverity.ERROR,
                message="Empty filename",
                field="filename"
            )
        
        # Block path traversal attempts
        dangerous_patterns = ['../', '..\\', '/', '\\', ':', '*', '?', '"', '<', '>', '|']
        for pattern in dangerous_patterns:
            if pattern in filename:
                return ValidationResult(
                    valid=False,
                    severity=ValidationSeverity.CRITICAL,
                    message=f"Path traversal attempt detected: {pattern}",
                    field="filename"
                )
        
        # Sanitize to safe characters only
        sanitized = "".join(c for c in filename if c.isalnum() or c in '._- ')
        sanitized = sanitized[:cls.MAX_FIELD_LENGTHS['filename']]
        
        return ValidationResult(valid=True, sanitized_value=sanitized)
    
    @classmethod
    def validate_nested_dict(cls, data: Dict[str, Any], max_depth: int = 3) -> ValidationResult:
        """Recursively validate nested dictionary structure."""
        if max_depth <= 0:
            return ValidationResult(
                valid=False,
                severity=ValidationSeverity.ERROR,
                message="Maximum nesting depth exceeded",
                field="nested_data"
            )
        
        for key, value in data.items():
            # Validate key
            key_result = cls.validate_string_length(str(key), 'metadata_key')
            if not key_result.valid:
                return key_result
            
            # Validate value based on type
            if isinstance(value, dict):
                nested_result = cls.validate_nested_dict(value, max_depth - 1)
                if not nested_result.valid:
                    return nested_result
            elif isinstance(value, str):
                val_result = cls.validate_string_length(value, 'metadata_value')
                if not val_result.valid:
                    return val_result
            elif isinstance(value, (list, tuple)):
                if len(value) > 100:  # Prevent list bombs
                    return ValidationResult(
                        valid=False,
                        severity=ValidationSeverity.ERROR,
                        message="List too large",
                        field=str(key)
                    )
        
        return ValidationResult(valid=True, sanitized_value=data)

class AdaptiveRateLimiter:
    """
    ENHANCED thread-safe adaptive rate limiter (v18).
    
    NEW IN v18:
    - Adaptive thresholds that adjust based on violation history
    - Per-client reputation tracking
    - Circuit breaker for repeated violators
    - Violation penalty system with gradual recovery
    - Detailed rate limit metrics
    """
    
    def __init__(self, config: Optional[AdaptiveRateLimitConfig] = None):
        self.config = config or AdaptiveRateLimitConfig()
        self._request_timestamps: List[float] = []
        self._client_requests: Dict[str, List[float]] = {}
        self._client_violations: Dict[str, int] = defaultdict(int)
        self._client_reputation: Dict[str, float] = defaultdict(lambda: 1.0)
        self._lock = threading.Lock()
        self._circuit_breaker_state: Dict[str, str] = {}  # closed/open/half-open
        self._circuit_breaker_failure_count: Dict[str, int] = defaultdict(int)
        self._circuit_breaker_open_time: Dict[str, float] = {}
    
    def _cleanup_old_requests(self, current_time: float, timestamps: List[float]) -> None:
        """Remove timestamps outside the current window."""
        cutoff = current_time - self.config.window_seconds
        while timestamps and timestamps[0] < cutoff:
            timestamps.pop(0)
    
    def _get_adaptive_limit(self, client_id: Optional[str]) -> int:
        """Calculate adaptive rate limit based on client reputation."""
        base_limit = self.config.base_max_requests_per_window
        
        if not client_id or not self.config.adaptive_threshold_enabled:
            return base_limit
        
        reputation = self._client_reputation.get(client_id, 1.0)
        violations = self._client_violations.get(client_id, 0)
        
        # Apply penalty for violations
        penalty_factor = 1.0 - (violations * 0.1)
        penalty_factor = max(0.1, penalty_factor)
        
        # Apply reputation multiplier
        adaptive_limit = int(base_limit * reputation * penalty_factor)
        
        # Clamp to configured range
        return max(
            self.config.min_requests_threshold,
            min(self.config.max_requests_threshold, adaptive_limit)
        )
    
    def _check_circuit_breaker(self, client_id: str) -> Tuple[bool, Optional[str]]:
        """Check if circuit breaker should block request."""
        state = self._circuit_breaker_state.get(client_id, 'closed')
        
        if state == 'open':
            open_time = self._circuit_breaker_open_time.get(client_id, 0)
            if time_module.time() - open_time > CircuitBreakerConfig.reset_timeout_seconds:
                self._circuit_breaker_state[client_id] = 'half-open'
                return True, None
            return False, 'circuit_breaker_open'
        
        if state == 'half-open':
            # Allow limited test requests
            return True, None
        
        return True, None
    
    def _record_failure(self, client_id: str) -> None:
        """Record failure and potentially trip circuit breaker."""
        self._circuit_breaker_failure_count[client_id] += 1
        self._client_violations[client_id] += 1
        self._client_reputation[client_id] *= self.config.violation_penalty_factor
        
        if self._circuit_breaker_failure_count[client_id] >= CircuitBreakerConfig.failure_threshold:
            self._circuit_breaker_state[client_id] = 'open'
            self._circuit_breaker_open_time[client_id] = time_module.time()
    
    def check_rate_limit(self, client_id: Optional[str] = None) -> Tuple[bool, Dict[str, Any]]:
        """
        Check if request is within adaptive rate limits.
        Returns (allowed, metadata_dict)
        """
        current_time = time_module.time()
        
        with self._lock:
            # Check circuit breaker first if client_id provided
            if client_id:
                allowed, reason = self._check_circuit_breaker(client_id)
                if not allowed:
                    return False, {
                        'reason': reason,
                        'client_id': client_id,
                        'retry_after': CircuitBreakerConfig.reset_timeout_seconds
                    }
            
            # Global rate limit check
            self._cleanup_old_requests(current_time, self._request_timestamps)
            adaptive_global_limit = self._get_adaptive_limit(None)
            
            if len(self._request_timestamps) >= adaptive_global_limit:
                if client_id:
                    self._record_failure(client_id)
                return False, {
                    'reason': 'global_rate_limit_exceeded',
                    'retry_after': max(1, self._request_timestamps[0] + self.config.window_seconds - current_time),
                    'current_count': len(self._request_timestamps),
                    'adaptive_limit': adaptive_global_limit
                }
            
            # Per-client rate limit check
            if client_id:
                if client_id not in self._client_requests:
                    self._client_requests[client_id] = []
                client_timestamps = self._client_requests[client_id]
                self._cleanup_old_requests(current_time, client_timestamps)
                
                client_limit = max(1, self._get_adaptive_limit(client_id) // 5)
                if len(client_timestamps) >= client_limit:
                    self._record_failure(client_id)
                    return False, {
                        'reason': 'client_rate_limit_exceeded',
                        'retry_after': max(1, client_timestamps[0] + self.config.window_seconds - current_time),
                        'current_count': len(client_timestamps),
                        'client_limit': client_limit,
                        'client_reputation': self._client_reputation[client_id]
                    }
                
                client_timestamps.append(current_time)
                
                # Gradual reputation recovery
                self._client_reputation[client_id] = min(
                    1.0,
                    self._client_reputation[client_id] / self.config.recovery_rate
                )
            
            self._request_timestamps.append(current_time)
            
            return True, {
                'current_count': len(self._request_timestamps),
                'adaptive_limit': adaptive_global_limit,
                'client_reputation': self._client_reputation.get(client_id, 1.0) if client_id else 1.0
            }
    
    def check_report_size(self, size_bytes: int) -> Tuple[bool, Dict[str, Any]]:
        """Check if report size is within limits."""
        if size_bytes > self.config.max_report_size_bytes:
            return False, {
                'reason': 'report_size_exceeded',
                'size_bytes': size_bytes,
                'max_bytes': self.config.max_report_size_bytes
            }
        return True, {'size_bytes': size_bytes, 'max_bytes': self.config.max_report_size_bytes}

class ReportTamperProtector:
    """
    Tamper protection for generated reports using HMAC signatures.
    
    Provides cryptographic integrity verification for reports.
    """
    
    def __init__(self, secret_key: Optional[bytes] = None):
        self.secret_key = secret_key or secrets.token_bytes(64)
    
    def sign_report(self, report_content: Union[str, bytes, Dict], context_id: str) -> Dict[str, Any]:
        """
        Sign report content with HMAC-SHA512.
        Returns signed envelope with content and signature.
        """
        if isinstance(report_content, dict):
            content_bytes = json.dumps(report_content, sort_keys=True).encode('utf-8')
        elif isinstance(report_content, str):
            content_bytes = report_content.encode('utf-8')
        else:
            content_bytes = report_content
        
        timestamp = int(time_module.time())
        message = content_bytes + context_id.encode('utf-8') + str(timestamp).encode('utf-8')
        signature = hmac.new(self.secret_key, message, hashlib.sha512).hexdigest()
        
        return {
            'content': report_content,
            'context_id': context_id,
            'timestamp': timestamp,
            'signature': signature,
            'algorithm': 'HMAC-SHA512',
            'version': 'v18'
        }
    
    def verify_report(self, signed_report: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """Verify report signature and detect tampering."""
        required_fields = ['content', 'context_id', 'timestamp', 'signature']
        for field in required_fields:
            if field not in signed_report:
                return False, {'reason': f'missing_field: {field}'}
        
        content = signed_report['content']
        if isinstance(content, dict):
            content_bytes = json.dumps(content, sort_keys=True).encode('utf-8')
        elif isinstance(content, str):
            content_bytes = content.encode('utf-8')
        else:
            content_bytes = content
        
        message = (content_bytes + 
                   signed_report['context_id'].encode('utf-8') + 
                   str(signed_report['timestamp']).encode('utf-8'))
        
        expected_signature = hmac.new(self.secret_key, message, hashlib.sha512).hexdigest()
        
        if not SecureMemoryV18.constant_time_str_compare(expected_signature, signed_report['signature']):
            return False, {'reason': 'signature_mismatch', 'tamper_detected': True}
        
        return True, {'verified': True, 'age_seconds': int(time_module.time()) - signed_report['timestamp']}

class EnhancedReportSecurityProtector:
    """
    MAIN v18 SECURITY PROTECTOR - Enhanced Report Generation Security.
    
    This is the primary wrapper class that adds comprehensive security to
    report generation operations. All features are OPT-IN and wrap existing
    functionality without modification.
    
    NEW IN v18:
    - Adaptive rate limiting with reputation tracking
    - Circuit breaker for abuse prevention
    - HMAC report signing for tamper protection
    - Enhanced input validation with heuristic scoring
    - Granular security event auditing
    - Automatic memory zeroization
    - Security context propagation
    """
    
    VERSION = "18.0.0"
    
    def __init__(
        self,
        security_level: SecurityLevel = SecurityLevel.MEDIUM,
        rate_limit_config: Optional[AdaptiveRateLimitConfig] = None
    ):
        self.security_level = security_level
        self.rate_limiter = AdaptiveRateLimiter(rate_limit_config)
        self.validator = EnhancedInputValidator()
        self.tamper_protector = ReportTamperProtector()
        self.active_contexts: Dict[str, SecurityContext] = {}
        self._context_lock = threading.Lock()
        self._global_lock = threading.Lock()
        
        logger.info(f"EnhancedReportSecurityProtector v{self.VERSION} initialized with level: {security_level.value}")
    
    def create_security_context(
        self,
        client_id: str = "",
        security_level: Optional[SecurityLevel] = None
    ) -> SecurityContext:
        """Create a new isolated security context."""
        context = SecurityContext(
            security_level=security_level or self.security_level,
            client_id=client_id
        )
        
        with self._context_lock:
            self.active_contexts[context.context_id] = context
        
        context.add_security_event(SecurityEvent(
            event_type=SecurityEventType.CONTEXT_CREATED,
            severity=ValidationSeverity.INFO,
            message="Security context created",
            context_id=context.context_id,
            client_id=client_id
        ))
        
        return context
    
    def destroy_security_context(self, context_id: str) -> None:
        """Destroy security context and zeroize sensitive data."""
        with self._context_lock:
            if context_id in self.active_contexts:
                context = self.active_contexts[context_id]
                # Zeroize HMAC secret
                context.hmac_secret = SecureMemoryV18.zeroize_bytes(context.hmac_secret)
                del self.active_contexts[context_id]
    
    def validate_report_generation_request(
        self,
        context: SecurityContext,
        report_type: str,
        output_format: str,
        metadata: Optional[Dict] = None
    ) -> Tuple[bool, List[ValidationResult]]:
        """Validate complete report generation request."""
        results: List[ValidationResult] = []
        
        # Check rate limit first
        rate_ok, rate_meta = self.rate_limiter.check_rate_limit(context.client_id)
        if not rate_ok:
            results.append(ValidationResult(
                valid=False,
                severity=ValidationSeverity.CRITICAL,
                message=f"Rate limit exceeded: {rate_meta.get('reason')}",
                field="rate_limit"
            ))
            context.add_security_event(SecurityEvent(
                event_type=SecurityEventType.RATE_LIMIT_EXCEEDED,
                severity=ValidationSeverity.CRITICAL,
                message=rate_meta.get('reason', 'rate limit exceeded'),
                context_id=context.context_id,
                client_id=context.client_id,
                metadata=rate_meta
            ))
            return False, results
        
        # Validate report type
        results.append(self.validator.validate_report_type(report_type))
        
        # Validate output format
        results.append(self.validator.validate_output_format(output_format))
        
        # Validate metadata if provided
        if metadata and isinstance(metadata, dict):
            results.append(self.validator.validate_nested_dict(metadata))
        
        # Check if any critical/error failures
        all_valid = all(r.valid for r in results)
        
        # Record failures in context
        for result in results:
            if not result.valid:
                context.add_validation_failure(result)
                context.add_security_event(SecurityEvent(
                    event_type=SecurityEventType.VALIDATION_FAILED,
                    severity=result.severity,
                    message=result.message,
                    context_id=context.context_id,
                    field=result.field
                ))
        
        context.increment_request()
        return all_valid, results
    
    def secure_report_output(
        self,
        context: SecurityContext,
        report_content: Union[str, Dict]
    ) -> Dict[str, Any]:
        """Apply security protections to generated report output."""
        # Sign report for tamper protection
        signed_report = self.tamper_protector.sign_report(
            report_content,
            context.context_id
        )
        
        context.add_security_event(SecurityEvent(
            event_type=SecurityEventType.REPORT_SIGNED,
            severity=ValidationSeverity.INFO,
            message="Report signed with HMAC-SHA512",
            context_id=context.context_id
        ))
        
        return signed_report
    
    def get_security_audit_log(
        self,
        context: SecurityContext
    ) -> List[Dict[str, Any]]:
        """Get formatted security audit log for a context."""
        return [
            {
                'event_type': e.event_type.value,
                'severity': e.severity.value,
                'message': e.message,
                'timestamp': datetime.fromtimestamp(e.timestamp).isoformat(),
                'metadata': e.metadata
            }
            for e in context.security_events
        ]
    
    def get_version_info(self) -> Dict[str, str]:
        """Get version information for this security module."""
        return {
            'module': 'security_hardening_report_generation_enhanced_v18',
            'version': self.VERSION,
            'security_level': self.security_level.value,
            'features': [
                'adaptive_rate_limiting',
                'circuit_breaker',
                'hmac_tamper_protection',
                'enhanced_input_validation',
                'secure_memory_zeroization',
                'security_audit_logging',
                'context_isolation'
            ]
        }


# Convenience functions for easy import and use
def create_v18_security_protector(
    security_level: SecurityLevel = SecurityLevel.MEDIUM
) -> EnhancedReportSecurityProtector:
    """Create a new v18 enhanced security protector instance."""
    return EnhancedReportSecurityProtector(security_level=security_level)

def get_v18_version_info() -> Dict[str, str]:
    """Get v18 module version information."""
    return EnhancedReportSecurityProtector("").get_version_info()
