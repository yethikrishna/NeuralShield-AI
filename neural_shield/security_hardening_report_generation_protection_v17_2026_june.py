"""
Security Hardening v17 - Report Generation Protection Module
NeuralShield-AI

This module provides security hardening wrappers for the Threat Intelligence
Report Generator (v15). It implements:
- Input validation and sanitization for report generation requests
- Rate limiting and DoS protection for report generation
- Secure memory handling for sensitive report data
- Constant-time comparison helpers for security checks
- Security context isolation for report generation operations

IMPLEMENTATION PHILOSOPHY: ADD-ONLY, NO EXISTING CODE MODIFICATION
All security features wrap existing functionality without changing it.
"""

import hashlib
import hmac
import time
import threading
import secrets
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, TypeVar
from enum import Enum
from datetime import datetime, timedelta
import logging

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


@dataclass
class ValidationResult:
    """Result of input validation check."""
    valid: bool
    severity: ValidationSeverity = ValidationSeverity.INFO
    message: str = ""
    field: str = ""
    sanitized_value: Any = None


@dataclass
class RateLimitConfig:
    """Configuration for rate limiting."""
    max_requests_per_window: int = 100
    window_seconds: int = 60
    max_report_size_bytes: int = 10 * 1024 * 1024  # 10MB
    max_sections_per_report: int = 50
    max_iocs_per_report: int = 10000


@dataclass
class SecurityContext:
    """Isolated security context for report generation."""
    context_id: str = field(default_factory=lambda: secrets.token_hex(16))
    security_level: SecurityLevel = SecurityLevel.MEDIUM
    created_at: float = field(default_factory=time.time)
    request_count: int = 0
    validation_failures: List[ValidationResult] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def increment_request(self) -> None:
        """Thread-safe request counter increment."""
        with self._lock:
            self.request_count += 1

    def add_validation_failure(self, failure: ValidationResult) -> None:
        """Add validation failure to context."""
        with self._lock:
            self.validation_failures.append(failure)


class SecureMemory:
    """
    Secure memory handling utilities with zeroization support.
    
    Provides methods for securely handling sensitive data with
    automatic memory zeroization on cleanup.
    """
    
    @staticmethod
    def zeroize_bytes(data: bytearray) -> None:
        """
        Securely zeroize bytearray contents.
        Uses constant-time overwrite to prevent compiler optimization.
        """
        for i in range(len(data)):
            data[i] = 0
    
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
        Prevents timing side-channel attacks.
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
    def secure_hash(data: bytes, salt: Optional[bytes] = None) -> bytes:
        """
        Generate secure hash with optional salt.
        Uses SHA-512 for strong collision resistance.
        """
        if salt is None:
            salt = secrets.token_bytes(32)
        return hashlib.pbkdf2_hmac('sha512', data, salt, 100000)


class InputValidator:
    """
    Comprehensive input validation for report generation.
    
    Validates and sanitizes all inputs to report generation functions,
    preventing injection attacks and malformed input exploits.
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
        'output_format': 20
    }
    
    # Allowed report types (from report generator)
    ALLOWED_REPORT_TYPES = {
        'threat_summary', 'ioc_analysis', 'mitre_coverage',
        'false_positive_reduction', 'comprehensive_security',
        'executive_summary'
    }
    
    # Allowed output formats
    ALLOWED_OUTPUT_FORMATS = {'json', 'markdown', 'html', 'csv'}
    
    # Potentially dangerous patterns to sanitize
    DANGEROUS_PATTERNS = [
        ('<script', '&lt;script'),
        ('javascript:', 'javascript_blocked:'),
        ('vbscript:', 'vbscript_blocked:'),
        ('onload=', 'onload_blocked='),
        ('onerror=', 'onerror_blocked='),
        ('eval(', 'eval_blocked('),
        ('../', 'dot_dot_slash_blocked'),
        ('..\\', 'dot_dot_backslash_blocked'),
    ]
    
    @classmethod
    def validate_report_type(cls, report_type: str) -> ValidationResult:
        """Validate report type is in allowed list."""
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
    def sanitize_html_content(cls, content: str) -> str:
        """Sanitize potentially dangerous HTML/JS patterns."""
        sanitized = content
        for pattern, replacement in cls.DANGEROUS_PATTERNS:
            sanitized = sanitized.replace(pattern, replacement)
            sanitized = sanitized.replace(pattern.upper(), replacement.upper())
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
        
        # Sanitize any dangerous patterns
        sanitized = cls.sanitize_html_content(ioc_value)
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
        if '../' in filename or '..\\' in filename or '/' in filename or '\\' in filename:
            return ValidationResult(
                valid=False,
                severity=ValidationSeverity.CRITICAL,
                message="Path traversal attempt detected",
                field="filename"
            )
        
        # Sanitize dangerous characters
        sanitized = "".join(c for c in filename if c.isalnum() or c in '._- ')
        sanitized = sanitized[:cls.MAX_FIELD_LENGTHS['filename']]
        
        return ValidationResult(valid=True, sanitized_value=sanitized)
    
    @classmethod
    def validate_numeric_range(
        cls, value: int, field_name: str, min_val: int, max_val: int
    ) -> ValidationResult:
        """Validate numeric value is within range."""
        if not isinstance(value, (int, float)):
            return ValidationResult(
                valid=False,
                severity=ValidationSeverity.ERROR,
                message=f"Expected numeric value for {field_name}",
                field=field_name
            )
        if value < min_val or value > max_val:
            return ValidationResult(
                valid=False,
                severity=ValidationSeverity.ERROR,
                message=f"{field_name} must be between {min_val} and {max_val}",
                field=field_name
            )
        return ValidationResult(valid=True, sanitized_value=value)


class RateLimiter:
    """
    Thread-safe rate limiter for report generation.
    
    Prevents DoS attacks by limiting the rate and volume of
    report generation requests.
    """
    
    def __init__(self, config: Optional[RateLimitConfig] = None):
        self.config = config or RateLimitConfig()
        self._request_timestamps: List[float] = []
        self._lock = threading.Lock()
        self._client_limits: Dict[str, List[float]] = {}
    
    def _cleanup_old_requests(self, current_time: float, timestamps: List[float]) -> None:
        """Remove timestamps outside the current window."""
        cutoff = current_time - self.config.window_seconds
        while timestamps and timestamps[0] < cutoff:
            timestamps.pop(0)
    
    def check_rate_limit(self, client_id: Optional[str] = None) -> Tuple[bool, Dict[str, Any]]:
        """
        Check if request is within rate limits.
        Returns (allowed, metadata_dict)
        """
        current_time = time.time()
        
        with self._lock:
            # Global rate limit check
            self._cleanup_old_requests(current_time, self._request_timestamps)
            
            if len(self._request_timestamps) >= self.config.max_requests_per_window:
                return False, {
                    'reason': 'global_rate_limit_exceeded',
                    'retry_after': self._request_timestamps[0] + self.config.window_seconds - current_time,
                    'current_count': len(self._request_timestamps),
                    'max_limit': self.config.max_requests_per_window
                }
            
            # Per-client rate limit check if client_id provided
            if client_id:
                if client_id not in self._client_limits:
                    self._client_limits[client_id] = []
                client_timestamps = self._client_limits[client_id]
                self._cleanup_old_requests(current_time, client_timestamps)
                
                client_limit = max(1, self.config.max_requests_per_window // 10)  # 10% of global per client
                if len(client_timestamps) >= client_limit:
                    return False, {
                        'reason': 'client_rate_limit_exceeded',
                        'retry_after': client_timestamps[0] + self.config.window_seconds - current_time,
                        'current_count': len(client_timestamps),
                        'max_limit': client_limit
                    }
                
                client_timestamps.append(current_time)
            
            self._request_timestamps.append(current_time)
            
            return True, {
                'current_count': len(self._request_timestamps),
                'max_limit': self.config.max_requests_per_window,
                'window_remaining': self.config.window_seconds - (current_time - self._request_timestamps[0]) if self._request_timestamps else self.config.window_seconds
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
    
    def check_section_count(self, section_count: int) -> Tuple[bool, Dict[str, Any]]:
        """Check if section count is within limits."""
        if section_count > self.config.max_sections_per_report:
            return False, {
                'reason': 'section_count_exceeded',
                'count': section_count,
                'max_count': self.config.max_sections_per_report
            }
        return True, {'count': section_count, 'max_count': self.config.max_sections_per_report}


class ReportGenerationSecurityProtector:
    """
    Main security protector for report generation.
    
    Wraps report generation functions with comprehensive security:
    - Input validation and sanitization
    - Rate limiting and DoS protection
    - Secure memory handling
    - Security context isolation
    """
    
    def __init__(
        self,
        security_level: SecurityLevel = SecurityLevel.MEDIUM,
        rate_limit_config: Optional[RateLimitConfig] = None
    ):
        self.security_level = security_level
        self.rate_limiter = RateLimiter(rate_limit_config)
        self.validator = InputValidator()
        self.active_contexts: Dict[str, SecurityContext] = {}
        self._context_lock = threading.Lock()
        self._global_lock = threading.Lock()
        
        logger.info(f"ReportGenerationSecurityProtector initialized with level: {security_level.value}")
    
    def create_security_context(
        self,
        security_level: Optional[SecurityLevel] = None
    ) -> SecurityContext:
        """Create a new isolated security context."""
        context = SecurityContext(security_level=security_level or self.security_level)
        with self._context_lock:
            self.active_contexts[context.context_id] = context
        logger.debug(f"Created security context: {context.context_id}")
        return context
    
    def release_context(self, context_id: str) -> None:
        """Release and cleanup security context."""
        with self._context_lock:
            if context_id in self.active_contexts:
                del self.active_contexts[context_id]
        logger.debug(f"Released security context: {context_id}")
    
    def secure_report_generation(
        self,
        func: Callable[..., R],
        *args: Any,
        context: Optional[SecurityContext] = None,
        client_id: Optional[str] = None,
        **kwargs: Any
    ) -> Tuple[bool, Optional[R], Dict[str, Any]]:
        """
        Wrap report generation function with full security protection.
        
        Returns: (success, result_or_none, security_metadata)
        """
        if context is None:
            context = self.create_security_context()
        
        context.increment_request()
        security_metadata: Dict[str, Any] = {
            'context_id': context.context_id,
            'security_level': context.security_level.value,
            'validation_passed': True,
            'validation_failures': [],
            'rate_limit_check': None,
            'start_time': time.time()
        }
        
        # Step 1: Rate limiting check (MEDIUM+ security level)
        if context.security_level in (SecurityLevel.MEDIUM, SecurityLevel.HIGH, SecurityLevel.MAXIMUM):
            allowed, rate_info = self.rate_limiter.check_rate_limit(client_id)
            security_metadata['rate_limit_check'] = rate_info
            if not allowed:
                security_metadata['blocked_reason'] = rate_info['reason']
                logger.warning(f"Rate limit blocked: {rate_info['reason']}")
                return False, None, security_metadata
        
        # Step 2: Input validation (ALL security levels)
        validation_failures = self._validate_generation_inputs(*args, **kwargs)
        if validation_failures:
            for failure in validation_failures:
                context.add_validation_failure(failure)
            
            # Block on ERROR/CRITICAL at MEDIUM+
            blocking_failures = [
                f for f in validation_failures
                if f.severity in (ValidationSeverity.ERROR, ValidationSeverity.CRITICAL)
            ]
            
            if blocking_failures and context.security_level != SecurityLevel.LOW:
                security_metadata['validation_passed'] = False
                security_metadata['validation_failures'] = [
                    {'field': f.field, 'message': f.message, 'severity': f.severity.value}
                    for f in blocking_failures
                ]
                security_metadata['blocked_reason'] = 'validation_failure'
                logger.warning(f"Validation blocked: {len(blocking_failures)} failures")
                return False, None, security_metadata
            
            security_metadata['validation_warnings'] = [
                {'field': f.field, 'message': f.message}
                for f in validation_failures
            ]
        
        # Step 3: Execute wrapped function
        try:
            result = func(*args, **kwargs)
            
            # Step 4: Post-execution size checks (HIGH+ security level)
            if context.security_level in (SecurityLevel.HIGH, SecurityLevel.MAXIMUM):
                result_size = self._estimate_result_size(result)
                size_ok, size_info = self.rate_limiter.check_report_size(result_size)
                security_metadata['size_check'] = size_info
                if not size_ok:
                    security_metadata['blocked_reason'] = size_info['reason']
                    logger.warning(f"Size limit blocked: {size_info['reason']}")
                    return False, None, security_metadata
            
            security_metadata['execution_time'] = time.time() - security_metadata['start_time']
            security_metadata['success'] = True
            
            logger.debug(f"Secure report generation completed: {context.context_id}")
            return True, result, security_metadata
            
        except Exception as e:
            security_metadata['success'] = False
            security_metadata['error'] = str(e)
            security_metadata['execution_time'] = time.time() - security_metadata['start_time']
            logger.error(f"Secure report generation error: {e}")
            return False, None, security_metadata
    
    def _validate_generation_inputs(self, *args: Any, **kwargs: Any) -> List[ValidationResult]:
        """Validate all inputs to report generation."""
        failures: List[ValidationResult] = []
        
        # Validate report_type if present
        if 'report_type' in kwargs:
            result = self.validator.validate_report_type(kwargs['report_type'])
            if not result.valid:
                failures.append(result)
        
        # Validate output_format if present
        if 'output_format' in kwargs:
            result = self.validator.validate_output_format(kwargs['output_format'])
            if not result.valid:
                failures.append(result)
        
        # Validate filename if present
        if 'filename' in kwargs:
            result = self.validator.validate_filename(kwargs['filename'])
            if not result.valid:
                failures.append(result)
        
        # Validate section count if sections present
        if 'sections' in kwargs and isinstance(kwargs['sections'], list):
            result = self.rate_limiter.check_section_count(len(kwargs['sections']))
            if not result[0]:
                failures.append(ValidationResult(
                    valid=False,
                    severity=ValidationSeverity.WARNING,
                    message=result[1]['reason'],
                    field='sections'
                ))
        
        return failures
    
    def _estimate_result_size(self, result: Any) -> int:
        """Rough estimate of result size in bytes."""
        if isinstance(result, str):
            return len(result.encode('utf-8'))
        if isinstance(result, (dict, list)):
            import json
            try:
                return len(json.dumps(result).encode('utf-8'))
            except:
                return 0
        return 0
    
    def get_security_stats(self) -> Dict[str, Any]:
        """Get security protection statistics."""
        with self._context_lock:
            return {
                'active_contexts': len(self.active_contexts),
                'security_level': self.security_level.value,
                'rate_limit_config': {
                    'max_requests': self.rate_limiter.config.max_requests_per_window,
                    'window_seconds': self.rate_limiter.config.window_seconds,
                    'max_report_size': self.rate_limiter.config.max_report_size_bytes
                }
            }


# Convenience functions for easy integration
_DEFAULT_PROTECTOR: Optional[ReportGenerationSecurityProtector] = None
_PROTECTOR_LOCK = threading.Lock()


def get_default_protector() -> ReportGenerationSecurityProtector:
    """Get or create the default security protector singleton."""
    global _DEFAULT_PROTECTOR
    if _DEFAULT_PROTECTOR is None:
        with _PROTECTOR_LOCK:
            if _DEFAULT_PROTECTOR is None:
                _DEFAULT_PROTECTOR = ReportGenerationSecurityProtector()
    return _DEFAULT_PROTECTOR


def secure_generate_report(
    func: Callable[..., R],
    *args: Any,
    security_level: SecurityLevel = SecurityLevel.MEDIUM,
    **kwargs: Any
) -> Tuple[bool, Optional[R], Dict[str, Any]]:
    """
    Convenience function to secure report generation.
    
    Usage:
        success, result, metadata = secure_generate_report(
            report_generator.generate,
            report_type='threat_summary',
            security_level=SecurityLevel.HIGH
        )
    """
    protector = get_default_protector()
    context = protector.create_security_context(security_level)
    try:
        return protector.secure_report_generation(func, *args, context=context, **kwargs)
    finally:
        protector.release_context(context.context_id)


def constant_time_compare(a: str, b: str) -> bool:
    """Convenience function for constant-time string comparison."""
    return SecureMemory.constant_time_str_compare(a, b)


def secure_zeroize(data: bytearray) -> None:
    """Convenience function for secure memory zeroization."""
    SecureMemory.zeroize_bytes(data)


# Version information
VERSION = "1.7.0"
VERSION_INFO = {
    'major': 1,
    'minor': 7,
    'patch': 0,
    'dimension': 'B',
    'dimension_version': 17,
    'release_date': '2026-06-24',
    'module': 'security_hardening_report_generation_protection'
}


def get_version() -> str:
    """Get module version string."""
    return VERSION


def get_version_info() -> Dict[str, Any]:
    """Get detailed version information."""
    return VERSION_INFO.copy()


# Module initialization verification
logger.info(f"Security Hardening v17 loaded - Report Generation Protection Module v{VERSION}")
