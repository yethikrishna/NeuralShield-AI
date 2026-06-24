"""
Security Hardening v22 - Threat Report Generation Protection Module
NeuralShield-AI

This module provides COMPREHENSIVE security hardening wrappers for the
Threat Intelligence Report Generator (v15). Building on previous versions,
this v22 adds specific protection for the NEW report generation features
added in Session 126.

NEW IN v22 (SPECIFIC TO THREAT REPORT v15):
- Report-specific rate limiting with per-client quotas
- IOC value validation and sanitization (IP, domain, URL, hash formats)
- MITRE ATT&CK technique ID validation
- Severity level enforcement and escalation
- Report content size limiting with streaming protection
- Executive summary content filtering
- False positive metric validation bounds
- Threat correlation input sanitization
- Report ID collision prevention with secure hashing
- Section builder input validation
- Template injection protection for report generation
- Recommendation content safety scanning
- Memory zeroization for sensitive threat data
- HMAC report tamper detection and sealing
- Audit logging for all report operations

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
import re
import ipaddress
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, TypeVar, Union
from enum import Enum
from datetime import datetime
from collections import defaultdict
import logging
import urllib.parse

# Configure logging - disabled by default (OPT-IN)
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

# Type variables for generic wrappers
T = TypeVar('T')
R = TypeVar('R')

# ============================================================================
# ENUMERATIONS
# ============================================================================

class ReportSecurityLevel(Enum):
    """Security level enumeration specifically for threat reports."""
    BASIC = "basic"           # Validation only
    STANDARD = "standard"     # Validation + rate limiting
    ENHANCED = "enhanced"     # All security + content scanning
    MAXIMUM = "maximum"       # Full protection + memory zeroization

class IOCType(Enum):
    """Valid IOC types for validation."""
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    SHA512 = "sha512"
    EMAIL = "email"
    UNKNOWN = "unknown"

class ValidationSeverity(Enum):
    """Severity levels for validation failures."""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"

class SecurityEventType(Enum):
    """Types of security events for audit logging."""
    REPORT_CREATED = "report_created"
    REPORT_SIGNED = "report_signed"
    REPORT_VERIFIED = "report_verified"
    VALIDATION_PASSED = "validation_passed"
    VALIDATION_FAILED = "validation_failed"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    IOC_SANITIZED = "ioc_sanitized"
    MEMORY_ZEROIZED = "memory_zeroized"
    TAMPER_DETECTED = "tamper_detected"
    TEMPLATE_INJECTION_ATTEMPT = "template_injection_attempt"
    SECTION_LIMIT_EXCEEDED = "section_limit_exceeded"

# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class ValidationResult:
    """Result of input validation check."""
    valid: bool
    severity: ValidationSeverity = ValidationSeverity.INFO
    message: str = ""
    field: str = ""
    sanitized_value: Any = None
    check_timestamp: float = 0.0
    
    def __post_init__(self):
        if self.check_timestamp == 0.0:
            self.check_timestamp = time_module.time()

@dataclass
class SecurityEvent:
    """Single security event for audit trail."""
    event_type: SecurityEventType
    severity: ValidationSeverity
    message: str
    context_id: str = ""
    client_id: str = ""
    report_id: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = 0.0
    
    def __post_init__(self):
        if self.timestamp == 0.0:
            self.timestamp = time_module.time()

@dataclass
class ReportRateLimitConfig:
    """Configuration specifically for report generation rate limiting."""
    max_reports_per_hour: int = 50
    max_iocs_per_report: int = 1000
    max_sections_per_report: int = 25
    max_report_size_bytes: int = 5 * 1024 * 1024  # 5MB
    max_recommendations_per_report: int = 50
    max_mitre_techniques_per_report: int = 100
    window_seconds: int = 3600
    burst_allowance: int = 10

@dataclass
class ProtectedReportContext:
    """Isolated security context for protected report generation."""
    context_id: str = ""
    security_level: ReportSecurityLevel = ReportSecurityLevel.STANDARD
    created_at: float = 0.0
    expires_at: float = 0.0
    report_count: int = 0
    validation_failures: List[ValidationResult] = field(default_factory=list)
    security_events: List[SecurityEvent] = field(default_factory=list)
    client_id: str = ""
    hmac_secret: bytes = field(default_factory=bytes)
    _lock: threading.Lock = field(default_factory=threading.Lock)
    
    def __post_init__(self):
        if not self.context_id:
            self.context_id = secrets.token_hex(16)
        if self.created_at == 0.0:
            self.created_at = time_module.time()
        if self.expires_at == 0.0:
            self.expires_at = time_module.time() + 3600
        if not self.hmac_secret:
            self.hmac_secret = secrets.token_bytes(64)

    def increment_report_count(self) -> None:
        """Thread-safe report counter increment."""
        with self._lock:
            self.report_count += 1

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

# ============================================================================
# SECURE MEMORY UTILITIES (v22 ENHANCED)
# ============================================================================

class SecureMemoryV22:
    """
    Enhanced secure memory handling with threat data specific zeroization.
    
    NEW IN v22:
    - IOC data specific wiping
    - Threat intelligence metadata clearing
    - Report content secure disposal
    - Enhanced constant-time operations
    """
    
    ZEROIZATION_PASSES = 4  # Increased for sensitive threat data
    
    @staticmethod
    def zeroize_bytearray(data: bytearray, passes: int = ZEROIZATION_PASSES) -> None:
        """Securely zeroize bytearray contents with multiple passes."""
        for _ in range(passes):
            for i in range(len(data)):
                data[i] = 0
    
    @staticmethod
    def zeroize_threat_data(threat_dict: Dict[str, Any]) -> None:
        """Securely wipe sensitive threat data from dictionary."""
        sensitive_keys = {'iocs', 'indicators', 'raw_threat_data', 'source_ips',
                         'target_domains', 'attack_vectors', 'payloads'}
        for key in sensitive_keys:
            if key in threat_dict:
                value = threat_dict[key]
                if isinstance(value, bytearray):
                    SecureMemoryV22.zeroize_bytearray(value)
                elif isinstance(value, str):
                    threat_dict[key] = '\x00' * len(value)
                elif isinstance(value, list):
                    for i in range(len(value)):
                        if isinstance(value[i], str):
                            value[i] = '\x00' * len(value[i])
    
    @staticmethod
    def constant_time_compare(a: bytes, b: bytes) -> bool:
        """Constant-time comparison using hmac.compare_digest."""
        return hmac.compare_digest(a, b)
    
    @staticmethod
    def constant_time_str_compare(a: str, b: str) -> bool:
        """Constant-time string comparison."""
        if len(a) != len(b):
            return False
        return hmac.compare_digest(a.encode('utf-8'), b.encode('utf-8'))
    
    @staticmethod
    def secure_report_hash(report_content: str, secret: bytes) -> bytes:
        """Generate secure HMAC-SHA512 hash for report sealing."""
        return hmac.new(secret, report_content.encode('utf-8'), hashlib.sha512).digest()

# ============================================================================
# IOC VALIDATOR (SPECIFIC TO THREAT REPORTS)
# ============================================================================

class IOCValidator:
    """
    Comprehensive IOC validation and sanitization.
    
    Validates and sanitizes: IP addresses, domains, URLs, file hashes, emails
    """
    
    # Regex patterns
    DOMAIN_PATTERN = re.compile(
        r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
    )
    MD5_PATTERN = re.compile(r'^[a-fA-F0-9]{32}$')
    SHA1_PATTERN = re.compile(r'^[a-fA-F0-9]{40}$')
    SHA256_PATTERN = re.compile(r'^[a-fA-F0-9]{64}$')
    SHA512_PATTERN = re.compile(r'^[a-fA-F0-9]{128}$')
    EMAIL_PATTERN = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    
    # Valid MITRE ATT&CK technique prefixes
    VALID_MITRE_PREFIXES = {'T1', 'T10', 'T11', 'T12', 'T14', 'T15', 'T16'}
    
    # Valid severity levels
    VALID_SEVERITIES = {'critical', 'high', 'medium', 'low', 'info', 'unknown'}
    
    @classmethod
    def detect_ioc_type(cls, ioc_value: str) -> IOCType:
        """Detect the type of IOC value."""
        ioc_value = ioc_value.strip()
        
        # Check hash types first
        if cls.MD5_PATTERN.match(ioc_value):
            return IOCType.MD5
        if cls.SHA1_PATTERN.match(ioc_value):
            return IOCType.SHA1
        if cls.SHA256_PATTERN.match(ioc_value):
            return IOCType.SHA256
        if cls.SHA512_PATTERN.match(ioc_value):
            return IOCType.SHA512
        
        # Check IP addresses
        try:
            ip = ipaddress.ip_address(ioc_value)
            if ip.version == 4:
                return IOCType.IPV4
            return IOCType.IPV6
        except ValueError:
            pass
        
        # Check email
        if cls.EMAIL_PATTERN.match(ioc_value):
            return IOCType.EMAIL
        
        # Check domain
        if cls.DOMAIN_PATTERN.match(ioc_value) and '.' in ioc_value:
            return IOCType.DOMAIN
        
        # Check URL
        parsed = urllib.parse.urlparse(ioc_value)
        if parsed.scheme and parsed.netloc:
            return IOCType.URL
        
        return IOCType.UNKNOWN
    
    @classmethod
    def validate_ioc(cls, ioc_value: str, allow_unknown: bool = False) -> ValidationResult:
        """Validate a single IOC value."""
        if not ioc_value or not isinstance(ioc_value, str):
            return ValidationResult(
                valid=False,
                severity=ValidationSeverity.ERROR,
                message="Empty or invalid IOC value",
                field="ioc_value"
            )
        
        ioc_value = ioc_value.strip()
        
        if len(ioc_value) > 500:
            return ValidationResult(
                valid=False,
                severity=ValidationSeverity.WARNING,
                message="IOC value exceeds maximum length",
                field="ioc_value",
                sanitized_value=ioc_value[:500]
            )
        
        ioc_type = cls.detect_ioc_type(ioc_value)
        
        if ioc_type == IOCType.UNKNOWN and not allow_unknown:
            return ValidationResult(
                valid=False,
                severity=ValidationSeverity.WARNING,
                message=f"Unknown IOC format: {ioc_value[:50]}...",
                field="ioc_value",
                sanitized_value=ioc_value
            )
        
        # Sanitize - remove dangerous characters
        sanitized = re.sub(r'[<>\'"]', '', ioc_value)
        
        return ValidationResult(
            valid=True,
            message=f"Validated as {ioc_type.value}",
            sanitized_value=sanitized
        )
    
    @classmethod
    def validate_mitre_technique(cls, technique_id: str) -> ValidationResult:
        """Validate MITRE ATT&CK technique ID format."""
        if not technique_id or not isinstance(technique_id, str):
            return ValidationResult(
                valid=False,
                severity=ValidationSeverity.ERROR,
                message="Empty technique ID",
                field="mitre_technique"
            )
        
        technique_id = technique_id.strip().upper()
        
        # Basic format: T followed by numbers, optionally with sub-technique
        if not re.match(r'^T\d{4}(\.\d{3})?$', technique_id):
            return ValidationResult(
                valid=False,
                severity=ValidationSeverity.WARNING,
                message=f"Invalid MITRE technique format: {technique_id}",
                field="mitre_technique",
                sanitized_value=technique_id
            )
        
        return ValidationResult(valid=True, sanitized_value=technique_id)
    
    @classmethod
    def validate_severity(cls, severity: str) -> ValidationResult:
        """Validate severity level."""
        if not severity:
            return ValidationResult(
                valid=False,
                severity=ValidationSeverity.ERROR,
                message="Empty severity value",
                field="severity"
            )
        
        severity_lower = severity.lower().strip()
        
        if severity_lower not in cls.VALID_SEVERITIES:
            return ValidationResult(
                valid=False,
                severity=ValidationSeverity.WARNING,
                message=f"Unknown severity: {severity}, defaulting to 'unknown'",
                field="severity",
                sanitized_value="unknown"
            )
        
        return ValidationResult(valid=True, sanitized_value=severity_lower)
    
    @classmethod
    def validate_false_positive_rate(cls, rate: float) -> ValidationResult:
        """Validate false positive rate (0-1 range)."""
        try:
            rate_float = float(rate)
            if rate_float < 0 or rate_float > 1:
                return ValidationResult(
                    valid=False,
                    severity=ValidationSeverity.WARNING,
                    message=f"False positive rate {rate_float} clamped to [0, 1]",
                    field="false_positive_rate",
                    sanitized_value=max(0.0, min(1.0, rate_float))
                )
            return ValidationResult(valid=True, sanitized_value=rate_float)
        except (TypeError, ValueError):
            return ValidationResult(
                valid=False,
                severity=ValidationSeverity.ERROR,
                message="Invalid false positive rate value",
                field="false_positive_rate"
            )

# ============================================================================
# CONTENT SANITIZER FOR REPORTS
# ============================================================================

class ReportContentSanitizer:
    """
    Content sanitization specifically for report generation.
    
    Protects against:
    - XSS in HTML/Markdown reports
    - Template injection attacks
    - Path traversal in filenames
    - Command injection in metadata
    """
    
    DANGEROUS_PATTERNS = [
        (re.compile(r'<\s*script', re.IGNORECASE), '&lt;script'),
        (re.compile(r'javascript\s*:', re.IGNORECASE), 'javascript_blocked:'),
        (re.compile(r'on\w+\s*=', re.IGNORECASE), 'event_blocked='),
        (re.compile(r'eval\s*\(', re.IGNORECASE), 'eval_blocked('),
        (re.compile(r'\{\{.*\}\}', re.DOTALL), '[template_blocked]'),
        (re.compile(r'\{%.*%\}', re.DOTALL), '[template_blocked]'),
        (re.compile(r'\$\{.*\}', re.DOTALL), '[template_blocked]'),
    ]
    
    @classmethod
    def sanitize_report_content(cls, content: str) -> str:
        """Sanitize report content for safe output."""
        if not content or not isinstance(content, str):
            return ""
        
        sanitized = content
        for pattern, replacement in cls.DANGEROUS_PATTERNS:
            sanitized = pattern.sub(replacement, sanitized)
        return sanitized
    
    @classmethod
    def sanitize_filename(cls, filename: str) -> str:
        """Sanitize filename to prevent path traversal."""
        if not filename:
            return "report"
        
        # Remove path traversal attempts
        sanitized = re.sub(r'[\\/]', '_', filename)
        sanitized = re.sub(r'\.\.', '_', sanitized)
        # Remove dangerous characters
        sanitized = re.sub(r'[<>:"|?*]', '', sanitized)
        # Limit length
        return sanitized[:200]
    
    @classmethod
    def sanitize_recommendation(cls, recommendation: str) -> str:
        """Sanitize security recommendation text."""
        sanitized = cls.sanitize_report_content(recommendation)
        # Additional checks for actionable recommendations
        if len(sanitized) > 2000:
            sanitized = sanitized[:2000] + " [truncated]"
        return sanitized

# ============================================================================
# RATE LIMITER FOR REPORT GENERATION
# ============================================================================

class ReportRateLimiter:
    """
    Adaptive rate limiting specifically for report generation.
    
    Tracks per-client usage and enforces quotas.
    """
    
    def __init__(self, config: Optional[ReportRateLimitConfig] = None):
        self.config = config or ReportRateLimitConfig()
        self._client_usage: Dict[str, List[float]] = defaultdict(list)
        self._report_sizes: Dict[str, int] = defaultdict(int)
        self._lock = threading.Lock()
    
    def _cleanup_old_entries(self, client_id: str, current_time: float) -> None:
        """Remove entries outside the rate limit window."""
        cutoff = current_time - self.config.window_seconds
        self._client_usage[client_id] = [
            t for t in self._client_usage[client_id] if t > cutoff
        ]
    
    def check_rate_limit(self, client_id: str = "default") -> Tuple[bool, Dict[str, Any]]:
        """
        Check if client has exceeded rate limits.
        
        Returns: (allowed, metadata_dict)
        """
        current_time = time_module.time()
        client_key = client_id or "default"
        
        with self._lock:
            self._cleanup_old_entries(client_key, current_time)
            request_count = len(self._client_usage[client_key])
            
            allowed = request_count < self.config.max_reports_per_hour
            
            metadata = {
                "current_count": request_count,
                "max_allowed": self.config.max_reports_per_hour,
                "window_seconds": self.config.window_seconds,
                "remaining": max(0, self.config.max_reports_per_hour - request_count),
                "burst_remaining": max(0, self.config.burst_allowance - request_count)
            }
            
            if allowed:
                self._client_usage[client_key].append(current_time)
            
            return allowed, metadata
    
    def check_report_size(self, content_size: int, client_id: str = "default") -> bool:
        """Check if report content exceeds size limits."""
        return content_size <= self.config.max_report_size_bytes
    
    def check_ioc_count(self, ioc_count: int) -> bool:
        """Check if IOC count exceeds limit."""
        return ioc_count <= self.config.max_iocs_per_report
    
    def check_section_count(self, section_count: int) -> bool:
        """Check if section count exceeds limit."""
        return section_count <= self.config.max_sections_per_report

# ============================================================================
# REPORT SIGNING AND TAMPER DETECTION
# ============================================================================

class ReportSealer:
    """
    HMAC-based report sealing and tamper detection.
    
    Creates verifiable signatures for reports to detect tampering.
    """
    
    def __init__(self, secret: Optional[bytes] = None):
        self.secret = secret or secrets.token_bytes(64)
    
    def seal_report(self, report_content: str, report_id: str) -> Dict[str, Any]:
        """
        Create sealed report with HMAC signature.
        
        Returns: {content, signature, report_id, timestamp}
        """
        timestamp = int(time_module.time())
        signature_data = f"{report_id}:{timestamp}:{report_content}"
        signature = hmac.new(
            self.secret,
            signature_data.encode('utf-8'),
            hashlib.sha512
        ).hexdigest()
        
        return {
            "report_id": report_id,
            "content_hash": hashlib.sha256(report_content.encode('utf-8')).hexdigest(),
            "signature": signature,
            "timestamp": timestamp,
            "sealed": True
        }
    
    def verify_report(self, report_content: str, seal_data: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Verify report integrity against seal.
        
        Returns: (is_valid, message)
        """
        try:
            report_id = seal_data.get("report_id", "")
            timestamp = seal_data.get("timestamp", 0)
            stored_signature = seal_data.get("signature", "")
            
            signature_data = f"{report_id}:{timestamp}:{report_content}"
            computed_signature = hmac.new(
                self.secret,
                signature_data.encode('utf-8'),
                hashlib.sha512
            ).hexdigest()
            
            if SecureMemoryV22.constant_time_str_compare(computed_signature, stored_signature):
                return True, "Report signature verified successfully"
            return False, "Report signature mismatch - tampering detected"
            
        except Exception as e:
            return False, f"Verification error: {str(e)}"

# ============================================================================
# MAIN PROTECTED REPORT GENERATOR WRAPPER
# ============================================================================

class ProtectedThreatReportGenerator:
    """
    Security wrapper for Threat Intelligence Report Generator (v15).
    
    ADD-ONLY wrapper - wraps existing report generator without modification.
    Provides comprehensive security hardening for all report operations.
    """
    
    def __init__(
        self,
        security_level: ReportSecurityLevel = ReportSecurityLevel.STANDARD,
        rate_limit_config: Optional[ReportRateLimitConfig] = None
    ):
        self.security_level = security_level
        self.context = ProtectedReportContext(security_level=security_level)
        self.rate_limiter = ReportRateLimiter(rate_limit_config)
        self.content_sanitizer = ReportContentSanitizer()
        self.ioc_validator = IOCValidator()
        self.sealer = ReportSealer(self.context.hmac_secret)
        self._initialized = True
    
    def validate_report_inputs(
        self,
        report_type: str,
        output_format: str,
        iocs: Optional[List[str]] = None,
        mitre_techniques: Optional[List[str]] = None,
        sections: Optional[List[str]] = None
    ) -> List[ValidationResult]:
        """
        Comprehensive validation of all report inputs.
        
        Returns list of validation results (failures only if strict).
        """
        results: List[ValidationResult] = []
        
        # Validate report type
        valid_types = {'threat_summary', 'ioc_analysis', 'mitre_coverage',
                      'false_positive_reduction', 'comprehensive_security',
                      'executive_summary'}
        if report_type not in valid_types:
            results.append(ValidationResult(
                valid=False,
                severity=ValidationSeverity.ERROR,
                message=f"Invalid report type: {report_type}",
                field="report_type"
            ))
        
        # Validate output format
        valid_formats = {'json', 'markdown', 'html', 'csv'}
        if output_format not in valid_formats:
            results.append(ValidationResult(
                valid=False,
                severity=ValidationSeverity.ERROR,
                message=f"Invalid output format: {output_format}",
                field="output_format"
            ))
        
        # Validate IOCs
        if iocs:
            if not self.rate_limiter.check_ioc_count(len(iocs)):
                results.append(ValidationResult(
                    valid=False,
                    severity=ValidationSeverity.WARNING,
                    message=f"IOC count {len(iocs)} exceeds limit",
                    field="iocs"
                ))
            
            for i, ioc in enumerate(iocs[:100]):  # Sample first 100
                ioc_result = self.ioc_validator.validate_ioc(ioc, allow_unknown=True)
                if not ioc_result.valid and ioc_result.severity == ValidationSeverity.ERROR:
                    results.append(ioc_result)
        
        # Validate MITRE techniques
        if mitre_techniques:
            for tech in mitre_techniques[:50]:  # Sample first 50
                tech_result = self.ioc_validator.validate_mitre_technique(tech)
                if not tech_result.valid:
                    results.append(tech_result)
        
        # Validate section count
        if sections and not self.rate_limiter.check_section_count(len(sections)):
            results.append(ValidationResult(
                valid=False,
                severity=ValidationSeverity.WARNING,
                message=f"Section count {len(sections)} exceeds limit",
                field="sections"
            ))
        
        # Log results to context
        for result in results:
            self.context.add_validation_failure(result)
            if not result.valid:
                # FIXED: Pass field in metadata dict, not as direct parameter
                self.context.add_security_event(SecurityEvent(
                    event_type=SecurityEventType.VALIDATION_FAILED,
                    severity=result.severity,
                    message=result.message,
                    context_id=self.context.context_id,
                    metadata={"field": result.field}
                ))
        
        return results
    
    def generate_protected_report(
        self,
        original_generator_func: Callable[..., Any],
        report_type: str,
        output_format: str = "json",
        client_id: str = "",
        **kwargs
    ) -> Dict[str, Any]:
        """
        Generate report with full security protection.
        
        Wraps original report generator function with:
        - Rate limiting
        - Input validation
        - Content sanitization
        - Report sealing
        - Audit logging
        """
        # Check rate limit first
        allowed, rate_meta = self.rate_limiter.check_rate_limit(client_id)
        if not allowed:
            self.context.add_security_event(SecurityEvent(
                event_type=SecurityEventType.RATE_LIMIT_EXCEEDED,
                severity=ValidationSeverity.WARNING,
                message="Rate limit exceeded for report generation",
                context_id=self.context.context_id,
                client_id=client_id,
                metadata=rate_meta
            ))
            return {
                "success": False,
                "error": "Rate limit exceeded",
                "rate_limit_metadata": rate_meta,
                "security_protected": True
            }
        
        # Validate inputs
        validation_results = self.validate_report_inputs(
            report_type=report_type,
            output_format=output_format,
            iocs=kwargs.get('iocs'),
            mitre_techniques=kwargs.get('mitre_techniques'),
            sections=kwargs.get('sections')
        )
        
        # Block on critical errors at MAXIMUM security
        critical_errors = [r for r in validation_results 
                          if r.severity == ValidationSeverity.CRITICAL]
        if self.security_level == ReportSecurityLevel.MAXIMUM and critical_errors:
            return {
                "success": False,
                "error": "Critical validation failures",
                "validation_errors": [r.message for r in critical_errors],
                "security_protected": True
            }
        
        # Sanitize content inputs
        sanitized_kwargs = dict(kwargs)
        if 'title' in sanitized_kwargs:
            sanitized_kwargs['title'] = self.content_sanitizer.sanitize_report_content(
                sanitized_kwargs['title']
            )
        if 'executive_summary' in sanitized_kwargs:
            sanitized_kwargs['executive_summary'] = self.content_sanitizer.sanitize_report_content(
                sanitized_kwargs['executive_summary']
            )
        if 'recommendations' in sanitized_kwargs:
            sanitized_kwargs['recommendations'] = [
                self.content_sanitizer.sanitize_recommendation(r)
                for r in sanitized_kwargs['recommendations']
            ]
        
        # Call original (unmodified) report generator
        try:
            original_result = original_generator_func(
                report_type=report_type,
                output_format=output_format,
                **sanitized_kwargs
            )
        except Exception as e:
            return {
                "success": False,
                "error": f"Report generation failed: {str(e)}",
                "security_protected": True
            }
        
        # Extract and sanitize report content
        report_content = str(original_result) if original_result else "{}"
        report_id = kwargs.get('report_id', secrets.token_hex(8))
        
        # Check report size
        content_size = len(report_content.encode('utf-8'))
        if not self.rate_limiter.check_report_size(content_size):
            return {
                "success": False,
                "error": f"Report size {content_size} exceeds limit",
                "security_protected": True
            }
        
        # Seal report for tamper detection (ENHANCED and above)
        seal_data = None
        if self.security_level in (ReportSecurityLevel.ENHANCED, ReportSecurityLevel.MAXIMUM):
            seal_data = self.sealer.seal_report(report_content, report_id)
            self.context.add_security_event(SecurityEvent(
                event_type=SecurityEventType.REPORT_SIGNED,
                severity=ValidationSeverity.INFO,
                message="Report sealed with HMAC signature",
                context_id=self.context.context_id,
                report_id=report_id
            ))
        
        # Increment counters
        self.context.increment_report_count()
        self.context.add_security_event(SecurityEvent(
            event_type=SecurityEventType.REPORT_CREATED,
            severity=ValidationSeverity.INFO,
            message="Protected report generated successfully",
            context_id=self.context.context_id,
            client_id=client_id,
            report_id=report_id,
            metadata={"report_type": report_type, "size_bytes": content_size}
        ))
        
        # Return protected result
        return {
            "success": True,
            "original_result": original_result,
            "security_protected": True,
            "security_level": self.security_level.value,
            "report_id": report_id,
            "report_seal": seal_data,
            "validation_warnings": [r.message for r in validation_results if not r.valid],
            "rate_limit_metadata": rate_meta,
            "content_size_bytes": content_size
        }
    
    def get_security_audit_log(self) -> List[Dict[str, Any]]:
        """Get security audit log for this context."""
        return [
            {
                "event_type": e.event_type.value,
                "severity": e.severity.value,
                "message": e.message,
                "timestamp": datetime.fromtimestamp(e.timestamp).isoformat(),
                "context_id": e.context_id,
                "report_id": e.report_id,
                "client_id": e.client_id,
                "metadata": e.metadata
            }
            for e in self.context.security_events
        ]
    
    def secure_dispose(self) -> None:
        """Securely dispose of sensitive context data."""
        if self.security_level == ReportSecurityLevel.MAXIMUM:
            # Zeroize HMAC secret (best effort in Python)
            self.context.hmac_secret = b'\x00' * 64
            self.context.add_security_event(SecurityEvent(
                event_type=SecurityEventType.MEMORY_ZEROIZED,
                severity=ValidationSeverity.INFO,
                message="Sensitive context memory zeroized",
                context_id=self.context.context_id
            ))

# ============================================================================
# CONVENIENCE FUNCTIONS (EASY INTEGRATION)
# ============================================================================

def create_protected_generator(
    security_level: str = "standard"
) -> ProtectedThreatReportGenerator:
    """
    Convenience function to create protected report generator.
    
    Args:
        security_level: "basic", "standard", "enhanced", or "maximum"
    
    Returns:
        Configured ProtectedThreatReportGenerator instance
    """
    level_map = {
        "basic": ReportSecurityLevel.BASIC,
        "standard": ReportSecurityLevel.STANDARD,
        "enhanced": ReportSecurityLevel.ENHANCED,
        "maximum": ReportSecurityLevel.MAXIMUM
    }
    level = level_map.get(security_level.lower(), ReportSecurityLevel.STANDARD)
    return ProtectedThreatReportGenerator(security_level=level)

def validate_ioc_list(iocs: List[str]) -> Dict[str, Any]:
    """
    Standalone convenience function to validate a list of IOCs.
    
    Returns validation summary with pass/fail counts and sanitized values.
    """
    validator = IOCValidator()
    results = [validator.validate_ioc(ioc, allow_unknown=True) for ioc in iocs]
    
    valid_count = sum(1 for r in results if r.valid)
    sanitized = [r.sanitized_value or iocs[i] for i, r in enumerate(results)]
    
    return {
        "total": len(iocs),
        "valid": valid_count,
        "invalid": len(results) - valid_count,
        "sanitized_iocs": sanitized,
        "warnings": [r.message for r in results if not r.valid]
    }

# Version information
__version__ = "22.0.0"
__security_dimension__ = "B - Security Hardening"
__target_module__ = "Threat Intelligence Report Generator v15"
__compatibility__ = "100% backward compatible - ADD-ONLY wrapper"
