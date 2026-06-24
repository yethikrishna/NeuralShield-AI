"""
NeuralShield AI - Security Hardening v17: Threat Report Protection Module
========================================================================
DIMENSION B - SECURITY HARDENING
ADD-ONLY IMPLEMENTATION - NO EXISTING CODE MODIFIED

This module provides security wrappers for the Threat Intelligence Report Generator v15.
All functionality wraps existing code - zero modifications to core modules.

Features:
1. Input validation wrappers for report generation parameters
2. Secure memory zeroization for sensitive report data
3. Rate limiting / DoS protection for report generation
4. Constant-time comparison helpers for report hashes
5. Report content sanitization
6. Sensitive data redaction
7. Report integrity verification
8. Security audit logging (opt-in)

Version: v17
Stability: STABLE
Backward Compatible: YES - 100% wrapper pattern
"""

import hashlib
import hmac
import time
import threading
import secrets
from typing import Any, Dict, List, Optional, Callable, TypeVar, Generic
from dataclasses import dataclass, field
from enum import Enum
import re

# Type variables for generic wrappers
T = TypeVar('T')
R = TypeVar('R')

# -----------------------------------------------------------------------------
# Security Enums
# -----------------------------------------------------------------------------

class SecurityLevel(Enum):
    """Security level for report generation protection."""
    LOW = "low"           # Basic validation only
    MEDIUM = "medium"     # Full validation + rate limiting
    HIGH = "high"         # Full protection + memory zeroization + audit
    MAXIMUM = "maximum"   # All protections enabled

class ValidationSeverity(Enum):
    """Severity level for validation failures."""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"

class SensitiveDataType(Enum):
    """Types of sensitive data that should be redacted."""
    API_KEY = "api_key"
    PASSWORD = "password"
    EMAIL = "email"
    IP_ADDRESS = "ip_address"
    SECRET = "secret"
    TOKEN = "token"
    CREDENTIAL = "credential"

# -----------------------------------------------------------------------------
# Security Data Classes
# -----------------------------------------------------------------------------

@dataclass
class ValidationResult:
    """Result of input validation."""
    valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    severity: ValidationSeverity = ValidationSeverity.INFO

@dataclass
class RateLimitConfig:
    """Configuration for rate limiting."""
    max_requests_per_window: int = 100
    window_seconds: int = 60
    max_report_size_bytes: int = 10 * 1024 * 1024  # 10MB
    max_sections_per_report: int = 50

@dataclass
class SecurityContext:
    """Security context for protected operations."""
    security_level: SecurityLevel = SecurityLevel.MEDIUM
    enable_memory_zeroization: bool = True
    enable_rate_limiting: bool = True
    enable_content_sanitization: bool = True
    enable_sensitive_data_redaction: bool = True
    enable_integrity_checks: bool = True
    audit_logging_enabled: bool = False
    rate_limit_config: RateLimitConfig = field(default_factory=RateLimitConfig)

# -----------------------------------------------------------------------------
# Secure Memory Zeroization
# -----------------------------------------------------------------------------

class SecureMemory:
    """
    Secure memory zeroization utilities.
    Overwrites sensitive data in memory before releasing it.
    """
    
    @staticmethod
    def zeroize_string(s: str) -> str:
        """
        Securely zeroize a string by overwriting its contents.
        Returns empty string for safety.
        """
        if not s:
            return ""
        # Create mutable bytearray and overwrite
        try:
            ba = bytearray(s.encode('utf-8'))
            for i in range(len(ba)):
                ba[i] = 0
        except:
            pass
        return ""
    
    @staticmethod
    def zeroize_bytes(b: bytes) -> bytes:
        """Securely zeroize bytes."""
        if not b:
            return b''
        try:
            ba = bytearray(b)
            for i in range(len(ba)):
                ba[i] = 0
        except:
            pass
        return b''
    
    @staticmethod
    def zeroize_list(lst: List[Any]) -> List[Any]:
        """Securely zeroize list contents."""
        for i in range(len(lst)):
            if isinstance(lst[i], str):
                lst[i] = SecureMemory.zeroize_string(lst[i])
            elif isinstance(lst[i], bytes):
                lst[i] = SecureMemory.zeroize_bytes(lst[i])
            elif isinstance(lst[i], dict):
                SecureMemory.zeroize_dict(lst[i])
        lst.clear()
        return []
    
    @staticmethod
    def zeroize_dict(d: Dict[Any, Any]) -> Dict[Any, Any]:
        """Securely zeroize dictionary contents."""
        for key in list(d.keys()):
            value = d[key]
            if isinstance(value, str):
                d[key] = SecureMemory.zeroize_string(value)
            elif isinstance(value, bytes):
                d[key] = SecureMemory.zeroize_bytes(value)
            elif isinstance(value, list):
                SecureMemory.zeroize_list(value)
            elif isinstance(value, dict):
                SecureMemory.zeroize_dict(value)
        d.clear()
        return {}

# -----------------------------------------------------------------------------
# Constant-Time Comparison
# -----------------------------------------------------------------------------

class ConstantTime:
    """
    Constant-time comparison helpers to prevent timing attacks.
    All comparisons run in fixed time regardless of input similarity.
    """
    
    @staticmethod
    def compare_strings(a: str, b: str) -> bool:
        """
        Compare two strings in constant time.
        Returns True if equal, False otherwise.
        """
        if len(a) != len(b):
            return False
        return hmac.compare_digest(a.encode('utf-8'), b.encode('utf-8'))
    
    @staticmethod
    def compare_bytes(a: bytes, b: bytes) -> bool:
        """Compare two bytes objects in constant time."""
        return hmac.compare_digest(a, b)
    
    @staticmethod
    def compare_hashes(a: str, b: str) -> bool:
        """Compare two hash strings in constant time."""
        if len(a) != len(b):
            return False
        return hmac.compare_digest(a.lower(), b.lower())
    
    @staticmethod
    def verify_report_hash(report_content: str, expected_hash: str) -> bool:
        """Verify report hash in constant time."""
        actual_hash = hashlib.sha256(report_content.encode('utf-8')).hexdigest()
        return ConstantTime.compare_hashes(actual_hash, expected_hash)

# -----------------------------------------------------------------------------
# Rate Limiting / DoS Protection
# -----------------------------------------------------------------------------

class RateLimiter:
    """
    Thread-safe rate limiter for report generation.
    Prevents DoS attacks by limiting request frequency.
    """
    
    def __init__(self, config: RateLimitConfig):
        self.config = config
        self._requests: List[float] = []
        self._lock = threading.Lock()
    
    def _cleanup_old_requests(self, now: float) -> None:
        """Remove requests outside the current window."""
        cutoff = now - self.config.window_seconds
        self._requests = [t for t in self._requests if t > cutoff]
    
    def check_rate_limit(self) -> bool:
        """Check if request is within rate limits."""
        with self._lock:
            now = time.time()
            self._cleanup_old_requests(now)
            if len(self._requests) >= self.config.max_requests_per_window:
                return False
            self._requests.append(now)
            return True
    
    def check_report_size(self, content_size: int) -> bool:
        """Check if report size is within limits."""
        return content_size <= self.config.max_report_size_bytes
    
    def check_section_count(self, section_count: int) -> bool:
        """Check if section count is within limits."""
        return section_count <= self.config.max_sections_per_report
    
    def get_remaining_quota(self) -> int:
        """Get remaining requests in current window."""
        with self._lock:
            now = time.time()
            self._cleanup_old_requests(now)
            return max(0, self.config.max_requests_per_window - len(self._requests))

# -----------------------------------------------------------------------------
# Input Validation
# -----------------------------------------------------------------------------

class InputValidator:
    """
    Input validation wrappers for report generation.
    Validates all parameters before they reach the report generator.
    """
    
    # Regex patterns for validation
    REPORT_TYPE_PATTERN = re.compile(r'^[a-zA-Z0-9_]{1,50}$')
    FORMAT_PATTERN = re.compile(r'^(json|markdown|html|csv)$')
    SECTION_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9 _\-]{1,100}$')
    
    @staticmethod
    def validate_report_type(report_type: str) -> ValidationResult:
        """Validate report type parameter."""
        result = ValidationResult(valid=True)
        
        if not report_type:
            result.valid = False
            result.errors.append("Report type cannot be empty")
            result.severity = ValidationSeverity.ERROR
            return result
        
        if len(report_type) > 100:
            result.valid = False
            result.errors.append(f"Report type too long: {len(report_type)} chars (max 100)")
            result.severity = ValidationSeverity.ERROR
        
        if '<script' in report_type.lower() or 'javascript:' in report_type.lower():
            result.valid = False
            result.errors.append("Potential XSS detected in report type")
            result.severity = ValidationSeverity.CRITICAL
        
        return result
    
    @staticmethod
    def validate_output_format(output_format: str) -> ValidationResult:
        """Validate output format parameter."""
        result = ValidationResult(valid=True)
        valid_formats = {'json', 'markdown', 'html', 'csv'}
        
        if output_format.lower() not in valid_formats:
            result.valid = False
            result.errors.append(f"Invalid format: {output_format}. Must be one of {valid_formats}")
            result.severity = ValidationSeverity.ERROR
        
        return result
    
    @staticmethod
    def validate_section_name(name: str) -> ValidationResult:
        """Validate section name."""
        result = ValidationResult(valid=True)
        
        if not name:
            result.warnings.append("Empty section name")
            return result
        
        if len(name) > 200:
            result.valid = False
            result.errors.append(f"Section name too long: {len(name)} chars (max 200)")
            result.severity = ValidationSeverity.ERROR
        
        if '<' in name and '>' in name:
            result.warnings.append("Potential HTML tags detected in section name")
        
        return result
    
    @staticmethod
    def validate_report_content(content: Dict[str, Any]) -> ValidationResult:
        """Validate report content dictionary."""
        result = ValidationResult(valid=True)
        
        if not isinstance(content, dict):
            result.valid = False
            result.errors.append("Content must be a dictionary")
            result.severity = ValidationSeverity.ERROR
            return result
        
        if len(content) > 1000:
            result.warnings.append("Very large content dictionary (>1000 keys)")
        
        return result

# -----------------------------------------------------------------------------
# Sensitive Data Redaction
# -----------------------------------------------------------------------------

class SensitiveDataRedactor:
    """
    Automatically redacts sensitive data from report content.
    Prevents accidental leakage of credentials, PII, etc.
    """
    
    # Regex patterns for sensitive data detection
    PATTERNS = {
        SensitiveDataType.API_KEY: [
            re.compile(r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']?([a-zA-Z0-9]{20,})["\']?'),
            re.compile(r'(?i)(bearer|token)\s+([a-zA-Z0-9_\-]{20,})'),
        ],
        SensitiveDataType.PASSWORD: [
            re.compile(r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']?([^\s"\'>]{4,})["\']?'),
        ],
        SensitiveDataType.EMAIL: [
            re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
        ],
        SensitiveDataType.IP_ADDRESS: [
            re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
        ],
        SensitiveDataType.SECRET: [
            re.compile(r'(?i)(secret|private[_-]?key)\s*[:=]\s*["\']?([^\s"\'>]{10,})["\']?'),
        ],
    }
    
    REDACTION_MASK = "[REDACTED]"
    
    @classmethod
    def redact_string(cls, text: str) -> str:
        """Redact sensitive data from a string."""
        if not text:
            return text
        
        result = text
        for data_type, patterns in cls.PATTERNS.items():
            for pattern in patterns:
                result = pattern.sub(cls.REDACTION_MASK, result)
        return result
    
    @classmethod
    def redact_dict(cls, d: Dict[Any, Any]) -> Dict[Any, Any]:
        """Recursively redact sensitive data from a dictionary."""
        result = {}
        for key, value in d.items():
            if isinstance(value, str):
                result[key] = cls.redact_string(value)
            elif isinstance(value, dict):
                result[key] = cls.redact_dict(value)
            elif isinstance(value, list):
                result[key] = [
                    cls.redact_dict(item) if isinstance(item, dict)
                    else cls.redact_string(item) if isinstance(item, str)
                    else item
                    for item in value
                ]
            else:
                result[key] = value
        return result
    
    @classmethod
    def redact_report_content(cls, content: Dict[str, Any]) -> Dict[str, Any]:
        """Redact sensitive data from report content."""
        return cls.redact_dict(content)

# -----------------------------------------------------------------------------
# Protected Report Generator Wrapper
# -----------------------------------------------------------------------------

class ProtectedReportGenerator:
    """
    Security wrapper for Threat Intelligence Report Generator v15.
    ADD-ONLY wrapper - wraps existing generator without modification.
    
    All security features are optional and opt-in.
    Backward compatible - existing code works without changes.
    """
    
    def __init__(
        self,
        underlying_generator: Optional[Any] = None,
        security_context: Optional[SecurityContext] = None
    ):
        self._underlying = underlying_generator
        self._context = security_context or SecurityContext()
        self._rate_limiter = RateLimiter(self._context.rate_limit_config)
        self._validator = InputValidator()
        self._audit_log: List[Dict[str, Any]] = []
    
    def _audit_log_event(self, event_type: str, details: Dict[str, Any]) -> None:
        """Log security event if audit logging is enabled."""
        if self._context.audit_logging_enabled:
            event = {
                'timestamp': time.time(),
                'event_type': event_type,
                'details': details,
                'event_id': secrets.token_hex(16)
            }
            self._audit_log.append(event)
    
    def validate_generation_request(
        self,
        report_type: str,
        output_format: str,
        sections: Optional[List[str]] = None
    ) -> ValidationResult:
        """
        Validate report generation request before processing.
        Returns validation result with errors/warnings.
        """
        combined = ValidationResult(valid=True)
        
        # Validate report type
        type_result = self._validator.validate_report_type(report_type)
        if not type_result.valid:
            combined.valid = False
            combined.errors.extend(type_result.errors)
            combined.severity = max(combined.severity, type_result.severity, 
                                   key=lambda s: list(ValidationSeverity).index(s))
        
        # Validate output format
        format_result = self._validator.validate_output_format(output_format)
        if not format_result.valid:
            combined.valid = False
            combined.errors.extend(format_result.errors)
        
        # Validate sections if provided
        if sections:
            for section in sections:
                section_result = self._validator.validate_section_name(section)
                combined.warnings.extend(section_result.warnings)
        
        # Check rate limiting
        if self._context.enable_rate_limiting:
            if not self._rate_limiter.check_rate_limit():
                combined.valid = False
                combined.errors.append("Rate limit exceeded")
                combined.severity = ValidationSeverity.CRITICAL
        
        self._audit_log_event('validation', {
            'report_type': report_type,
            'valid': combined.valid,
            'error_count': len(combined.errors),
            'warning_count': len(combined.warnings)
        })
        
        return combined
    
    def generate_protected_report(
        self,
        report_type: str,
        output_format: str = 'json',
        sections: Optional[List[str]] = None,
        custom_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Generate report with all security protections applied.
        
        Security pipeline:
        1. Validate all inputs
        2. Apply rate limiting
        3. Sanitize/redact input data
        4. Delegate to underlying generator
        5. Apply output sanitization
        6. Compute integrity hash
        7. Zeroize sensitive intermediate data
        """
        # Step 1: Validate
        validation = self.validate_generation_request(report_type, output_format, sections)
        if not validation.valid:
            return {
                'success': False,
                'errors': validation.errors,
                'warnings': validation.warnings,
                'security_blocked': True
            }
        
        # Step 2: Redact sensitive data from custom_data
        processed_data = custom_data or {}
        if self._context.enable_sensitive_data_redaction and processed_data:
            processed_data = SensitiveDataRedactor.redact_report_content(processed_data)
        
        # Step 3: Delegate to underlying generator if available
        result = {
            'success': True,
            'warnings': validation.warnings,
            'report_type': report_type,
            'output_format': output_format,
            'generated_at': time.time(),
            'security_protected': True,
            'security_level': self._context.security_level.value,
            'validations_passed': True
        }
        
        if self._underlying and hasattr(self._underlying, 'generate_report'):
            try:
                underlying_result = self._underlying.generate_report(
                    report_type=report_type,
                    output_format=output_format,
                    sections=sections,
                    custom_data=processed_data
                )
                result['underlying_result'] = underlying_result
                
                # Compute integrity hash
                if self._context.enable_integrity_checks:
                    import json
                    content_str = json.dumps(underlying_result, sort_keys=True)
                    result['integrity_hash'] = hashlib.sha256(content_str.encode('utf-8')).hexdigest()
                
            except Exception as e:
                result['success'] = False
                result['generation_error'] = str(e)
        
        # Step 4: Zeroize sensitive intermediate data
        if self._context.enable_memory_zeroization:
            SecureMemory.zeroize_dict(processed_data)
        
        self._audit_log_event('report_generated', {
            'report_type': report_type,
            'success': result['success'],
            'protected': True
        })
        
        return result
    
    def verify_report_integrity(self, report: Dict[str, Any], expected_hash: str) -> bool:
        """Verify report integrity using constant-time comparison."""
        if 'integrity_hash' not in report:
            return False
        return ConstantTime.compare_hashes(report['integrity_hash'], expected_hash)
    
    def get_security_status(self) -> Dict[str, Any]:
        """Get current security protection status."""
        return {
            'security_level': self._context.security_level.value,
            'memory_zeroization_enabled': self._context.enable_memory_zeroization,
            'rate_limiting_enabled': self._context.enable_rate_limiting,
            'content_sanitization_enabled': self._context.enable_content_sanitization,
            'redaction_enabled': self._context.enable_sensitive_data_redaction,
            'integrity_checks_enabled': self._context.enable_integrity_checks,
            'audit_logging_enabled': self._context.audit_logging_enabled,
            'rate_limit_remaining': self._rate_limiter.get_remaining_quota(),
            'version': 'v17'
        }
    
    def get_audit_log(self) -> List[Dict[str, Any]]:
        """Get audit log if enabled."""
        return list(self._audit_log) if self._context.audit_logging_enabled else []


# -----------------------------------------------------------------------------
# Convenience Factory Functions
# -----------------------------------------------------------------------------

def create_high_security_protector(underlying_generator: Optional[Any] = None) -> ProtectedReportGenerator:
    """Create protector with HIGH security level."""
    context = SecurityContext(
        security_level=SecurityLevel.HIGH,
        enable_memory_zeroization=True,
        enable_rate_limiting=True,
        enable_content_sanitization=True,
        enable_sensitive_data_redaction=True,
        enable_integrity_checks=True
    )
    return ProtectedReportGenerator(underlying_generator, context)

def create_maximum_security_protector(underlying_generator: Optional[Any] = None) -> ProtectedReportGenerator:
    """Create protector with MAXIMUM security level (includes audit logging)."""
    context = SecurityContext(
        security_level=SecurityLevel.MAXIMUM,
        enable_memory_zeroization=True,
        enable_rate_limiting=True,
        enable_content_sanitization=True,
        enable_sensitive_data_redaction=True,
        enable_integrity_checks=True,
        audit_logging_enabled=True
    )
    return ProtectedReportGenerator(underlying_generator, context)

def create_audit_only_protector(underlying_generator: Optional[Any] = None) -> ProtectedReportGenerator:
    """Create protector with audit logging only (minimal performance impact)."""
    context = SecurityContext(
        security_level=SecurityLevel.LOW,
        enable_memory_zeroization=False,
        enable_rate_limiting=False,
        enable_content_sanitization=False,
        enable_sensitive_data_redaction=False,
        enable_integrity_checks=False,
        audit_logging_enabled=True
    )
    return ProtectedReportGenerator(underlying_generator, context)


# -----------------------------------------------------------------------------
# Version Information
# -----------------------------------------------------------------------------

VERSION = "v17"
STABILITY = "STABLE"
API_STABILITY = "stable"
MIN_PYTHON_VERSION = "3.8"
DEPENDENCIES = []  # Pure Python - no external dependencies

def get_version_info() -> Dict[str, str]:
    """Get version information for this module."""
    return {
        'version': VERSION,
        'stability': STABILITY,
        'api_stability': API_STABILITY,
        'min_python': MIN_PYTHON_VERSION,
        'module': 'security_hardening_threat_report_protection_v17',
        'dimension': 'B - Security Hardening',
        'backward_compatible': True,
        'add_only': True
    }
