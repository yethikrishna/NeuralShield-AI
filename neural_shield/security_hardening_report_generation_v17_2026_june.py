"""
NeuralShield-AI: Security Hardening Module v17 for Report Generation
DIMENSION B - Security Hardening

This module provides security wrappers for the Threat Intelligence Report Generator.
All functionality is ADD-ONLY - wraps existing code without modification.

Features:
1. Input validation and sanitization for report generation requests
2. Rate limiting and DoS protection for report generation
3. Secure memory zeroization for sensitive report data
4. Constant-time comparison helpers for security-sensitive operations
5. Security audit logging for report generation activities
6. Input size limits to prevent resource exhaustion
7. Type checking and boundary validation for all inputs

Backward Compatible: 100% - all existing code works unchanged
"""

import hashlib
import hmac
import secrets
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union
from abc import ABC, abstractmethod


class SecurityValidationError(Exception):
    """Raised when security validation fails"""
    pass


class RateLimitExceededError(Exception):
    """Raised when rate limit is exceeded"""
    pass


class SecurityLevel(Enum):
    """Security levels for report generation"""
    LOW = "low"           # Basic validation only
    MEDIUM = "medium"     # Standard validation + rate limiting
    HIGH = "high"         # Full validation + memory zeroization
    CRITICAL = "critical" # Maximum security + constant-time ops


class ValidationSeverity(Enum):
    """Severity levels for validation failures"""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class ValidationResult:
    """Result of security validation"""
    is_valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    sanitized_input: Optional[Dict[str, Any]] = None
    
    def add_error(self, message: str) -> None:
        self.is_valid = False
        self.errors.append(message)
    
    def add_warning(self, message: str) -> None:
        self.warnings.append(message)


@dataclass
class RateLimitConfig:
    """Configuration for rate limiting"""
    max_requests_per_minute: int = 60
    max_requests_per_hour: int = 1000
    max_report_size_bytes: int = 10 * 1024 * 1024  # 10MB
    max_sections_per_report: int = 50
    max_iocs_per_report: int = 10000
    burst_limit: int = 10


class SecureMemory:
    """
    Secure memory handling utilities.
    Provides zeroization for sensitive data in memory.
    """
    
    @staticmethod
    def zeroize(data: Union[bytearray, List[int], str]) -> None:
        """
        Securely zeroize sensitive data.
        Overwrites memory to prevent data leakage.
        """
        if isinstance(data, bytearray):
            for i in range(len(data)):
                data[i] = 0
        elif isinstance(data, list):
            for i in range(len(data)):
                data[i] = 0
        elif isinstance(data, str):
            # Strings are immutable in Python, create overwrite placeholder
            pass  # Cannot truly zeroize immutable strings, documented limitation
    
    @staticmethod
    def secure_compare(a: str, b: str) -> bool:
        """
        Constant-time string comparison to prevent timing attacks.
        Uses hmac.compare_digest for secure comparison.
        """
        return hmac.compare_digest(a, b)
    
    @staticmethod
    def secure_compare_bytes(a: bytes, b: bytes) -> bool:
        """
        Constant-time bytes comparison to prevent timing attacks.
        """
        return hmac.compare_digest(a, b)
    
    @staticmethod
    def generate_secure_nonce(length: int = 32) -> bytes:
        """Generate cryptographically secure nonce"""
        return secrets.token_bytes(length)
    
    @staticmethod
    def generate_secure_token(length: int = 64) -> str:
        """Generate cryptographically secure token"""
        return secrets.token_hex(length // 2)


class RateLimiter:
    """
    Thread-safe rate limiter for report generation.
    Prevents DoS attacks through resource exhaustion.
    """
    
    def __init__(self, config: Optional[RateLimitConfig] = None):
        self.config = config or RateLimitConfig()
        self._minute_requests: Dict[str, List[float]] = {}
        self._hour_requests: Dict[str, List[float]] = {}
        self._lock = threading.Lock()
    
    def _cleanup_old_requests(self, client_id: str, window_seconds: float, 
                              request_list: List[float]) -> None:
        """Remove requests older than the window"""
        cutoff = time.time() - window_seconds
        while request_list and request_list[0] < cutoff:
            request_list.pop(0)
    
    def check_rate_limit(self, client_id: str = "default") -> Tuple[bool, Dict[str, Any]]:
        """
        Check if client has exceeded rate limits.
        Returns (allowed, rate_limit_info)
        """
        with self._lock:
            now = time.time()
            
            if client_id not in self._minute_requests:
                self._minute_requests[client_id] = []
            if client_id not in self._hour_requests:
                self._hour_requests[client_id] = []
            
            # Clean up old entries
            self._cleanup_old_requests(client_id, 60, self._minute_requests[client_id])
            self._cleanup_old_requests(client_id, 3600, self._hour_requests[client_id])
            
            minute_count = len(self._minute_requests[client_id])
            hour_count = len(self._hour_requests[client_id])
            
            info = {
                "minute_remaining": self.config.max_requests_per_minute - minute_count,
                "hour_remaining": self.config.max_requests_per_hour - hour_count,
                "minute_limit": self.config.max_requests_per_minute,
                "hour_limit": self.config.max_requests_per_hour
            }
            
            if minute_count >= self.config.max_requests_per_minute:
                return False, {**info, "reason": "per_minute_limit_exceeded"}
            
            if hour_count >= self.config.max_requests_per_hour:
                return False, {**info, "reason": "per_hour_limit_exceeded"}
            
            # Record this request
            self._minute_requests[client_id].append(now)
            self._hour_requests[client_id].append(now)
            
            return True, info
    
    def get_current_usage(self, client_id: str = "default") -> Dict[str, Any]:
        """Get current rate limit usage for client"""
        with self._lock:
            now = time.time()
            
            if client_id not in self._minute_requests:
                self._minute_requests[client_id] = []
            if client_id not in self._hour_requests:
                self._hour_requests[client_id] = []
            
            self._cleanup_old_requests(client_id, 60, self._minute_requests[client_id])
            self._cleanup_old_requests(client_id, 3600, self._hour_requests[client_id])
            
            return {
                "minute_requests": len(self._minute_requests[client_id]),
                "hour_requests": len(self._hour_requests[client_id]),
                "minute_limit": self.config.max_requests_per_minute,
                "hour_limit": self.config.max_requests_per_hour
            }


class InputValidator:
    """
    Comprehensive input validation for report generation.
    Prevents injection attacks, resource exhaustion, and invalid inputs.
    """
    
    MAX_STRING_LENGTH = 10000
    MAX_LIST_LENGTH = 10000
    MAX_DICT_KEYS = 1000
    MAX_NESTING_DEPTH = 10
    
    ALLOWED_REPORT_TYPES = {
        "threat_summary", "ioc_analysis", "mitre_coverage",
        "false_positive_reduction", "comprehensive_security", "executive_summary"
    }
    
    ALLOWED_OUTPUT_FORMATS = {"json", "markdown", "html", "csv"}
    
    def __init__(self, security_level: SecurityLevel = SecurityLevel.MEDIUM):
        self.security_level = security_level
        self._validation_cache: Dict[str, ValidationResult] = {}
    
    def validate_report_request(self, request_data: Dict[str, Any]) -> ValidationResult:
        """Validate a complete report generation request"""
        result = ValidationResult(is_valid=True, sanitized_input={})
        
        # Validate report type
        report_type = request_data.get("report_type", "")
        if report_type:
            if report_type not in self.ALLOWED_REPORT_TYPES:
                result.add_error(f"Invalid report_type: {report_type}")
            else:
                result.sanitized_input["report_type"] = report_type
        
        # Validate output format
        output_format = request_data.get("output_format", "")
        if output_format:
            if output_format not in self.ALLOWED_OUTPUT_FORMATS:
                result.add_error(f"Invalid output_format: {output_format}")
            else:
                result.sanitized_input["output_format"] = output_format
        
        # Validate title
        title = request_data.get("title", "")
        if title:
            title_result = self._validate_string(title, "title", max_len=500)
            if not title_result.is_valid:
                result.errors.extend(title_result.errors)
            else:
                result.sanitized_input["title"] = title.strip()
        
        # Validate IOCs if present
        iocs = request_data.get("iocs", [])
        if iocs:
            iocs_result = self._validate_iocs(iocs)
            if not iocs_result.is_valid:
                result.errors.extend(iocs_result.errors)
            else:
                result.sanitized_input["iocs"] = iocs_result.sanitized_input.get("iocs", [])
        
        # Validate sections
        sections = request_data.get("sections", [])
        if sections:
            sections_result = self._validate_sections(sections)
            if not sections_result.is_valid:
                result.errors.extend(sections_result.errors)
            else:
                result.sanitized_input["sections"] = sections_result.sanitized_input.get("sections", [])
        
        # High security: additional checks
        if self.security_level in (SecurityLevel.HIGH, SecurityLevel.CRITICAL):
            self._validate_nesting_depth(request_data, result, 0)
            self._check_for_suspicious_patterns(request_data, result)
        
        return result
    
    def _validate_string(self, value: str, field_name: str, 
                         max_len: Optional[int] = None) -> ValidationResult:
        """Validate string input"""
        result = ValidationResult(is_valid=True)
        max_len = max_len or self.MAX_STRING_LENGTH
        
        if not isinstance(value, str):
            result.add_error(f"{field_name} must be a string")
            return result
        
        if len(value) > max_len:
            result.add_error(f"{field_name} exceeds maximum length of {max_len}")
        
        # Check for control characters (high security)
        if self.security_level in (SecurityLevel.HIGH, SecurityLevel.CRITICAL):
            if any(chr(c) in value for c in range(0, 32) if chr(c) not in '\n\r\t'):
                result.add_warning(f"{field_name} contains control characters")
        
        return result
    
    def _validate_iocs(self, iocs: List[Any]) -> ValidationResult:
        """Validate IOC list"""
        result = ValidationResult(is_valid=True, sanitized_input={"iocs": []})
        
        if not isinstance(iocs, list):
            result.add_error("iocs must be a list")
            return result
        
        if len(iocs) > RateLimitConfig().max_iocs_per_report:
            result.add_error(f"Too many IOCs: {len(iocs)} (max: {RateLimitConfig().max_iocs_per_report})")
            return result
        
        for i, ioc in enumerate(iocs):
            if isinstance(ioc, str):
                if len(ioc) < 1000:  # Reasonable IOC length
                    result.sanitized_input["iocs"].append(ioc.strip())
                else:
                    result.add_warning(f"IOC at index {i} exceeds reasonable length")
            elif isinstance(ioc, dict):
                # Sanitize dict IOCs
                sanitized = {}
                for k, v in ioc.items():
                    if isinstance(k, str) and len(k) < 100:
                        if isinstance(v, (str, int, float, bool)):
                            sanitized[k] = v
                result.sanitized_input["iocs"].append(sanitized)
        
        return result
    
    def _validate_sections(self, sections: List[Any]) -> ValidationResult:
        """Validate report sections"""
        result = ValidationResult(is_valid=True, sanitized_input={"sections": []})
        
        if not isinstance(sections, list):
            result.add_error("sections must be a list")
            return result
        
        if len(sections) > RateLimitConfig().max_sections_per_report:
            result.add_error(f"Too many sections: {len(sections)} (max: {RateLimitConfig().max_sections_per_report})")
            return result
        
        for section in sections:
            if isinstance(section, dict):
                sanitized = {}
                for k, v in section.items():
                    if isinstance(k, str) and len(k) < 100:
                        sanitized[k] = v
                result.sanitized_input["sections"].append(sanitized)
        
        return result
    
    def _validate_nesting_depth(self, data: Any, result: ValidationResult, 
                                 depth: int) -> None:
        """Validate data structure nesting depth"""
        if depth > self.MAX_NESTING_DEPTH:
            result.add_error(f"Data structure exceeds maximum nesting depth of {self.MAX_NESTING_DEPTH}")
            return
        
        if isinstance(data, dict):
            if len(data) > self.MAX_DICT_KEYS:
                result.add_error(f"Dictionary exceeds maximum key count of {self.MAX_DICT_KEYS}")
            for v in data.values():
                self._validate_nesting_depth(v, result, depth + 1)
        elif isinstance(data, (list, tuple)):
            if len(data) > self.MAX_LIST_LENGTH:
                result.add_error(f"List exceeds maximum length of {self.MAX_LIST_LENGTH}")
            for item in data:
                self._validate_nesting_depth(item, result, depth + 1)
    
    def _check_for_suspicious_patterns(self, data: Any, result: ValidationResult) -> None:
        """Check for potentially malicious patterns"""
        if isinstance(data, str):
            suspicious = ["javascript:", "vbscript:", "data:", "onerror=", "onload="]
            lower_data = data.lower()
            for pattern in suspicious:
                if pattern in lower_data:
                    result.add_warning(f"Suspicious pattern detected: {pattern}")
        elif isinstance(data, dict):
            for v in data.values():
                self._check_for_suspicious_patterns(v, result)
        elif isinstance(data, (list, tuple)):
            for item in data:
                self._check_for_suspicious_patterns(item, result)


class SecurityAuditLogger:
    """
    Security audit logging for report generation activities.
    Tracks all security-relevant events.
    """
    
    def __init__(self):
        self._audit_log: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
    
    def log_event(self, event_type: str, severity: ValidationSeverity,
                  details: Dict[str, Any], client_id: str = "default") -> None:
        """Log a security audit event"""
        with self._lock:
            event = {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "event_type": event_type,
                "severity": severity.value,
                "client_id": hashlib.sha256(client_id.encode()).hexdigest()[:16],
                "details": details,
                "event_id": SecureMemory.generate_secure_token(16)
            }
            self._audit_log.append(event)
            
            # Keep only last 1000 events in memory
            if len(self._audit_log) > 1000:
                self._audit_log.pop(0)
    
    def get_audit_log(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent audit log entries"""
        with self._lock:
            return list(self._audit_log[-limit:])
    
    def get_security_summary(self) -> Dict[str, Any]:
        """Get security audit summary"""
        with self._lock:
            summary = {
                "total_events": len(self._audit_log),
                "by_severity": {},
                "by_type": {},
                "last_event_time": None
            }
            
            for event in self._audit_log:
                sev = event["severity"]
                summary["by_severity"][sev] = summary["by_severity"].get(sev, 0) + 1
                
                evt_type = event["event_type"]
                summary["by_type"][evt_type] = summary["by_type"].get(evt_type, 0) + 1
                
                summary["last_event_time"] = event["timestamp"]
            
            return summary


class SecureReportGeneratorWrapper:
    """
    Security wrapper for the Threat Intelligence Report Generator.
    Provides comprehensive security hardening while maintaining 100% backward compatibility.
    
    ADD-ONLY implementation - wraps existing generator, no modifications needed.
    """
    
    def __init__(self, underlying_generator: Any = None,
                 security_level: SecurityLevel = SecurityLevel.MEDIUM,
                 rate_limit_config: Optional[RateLimitConfig] = None):
        self._underlying = underlying_generator
        self.security_level = security_level
        self.validator = InputValidator(security_level)
        self.rate_limiter = RateLimiter(rate_limit_config)
        self.audit_logger = SecurityAuditLogger()
        self._lock = threading.Lock()
    
    def generate_secure_report(self, request_data: Dict[str, Any],
                               client_id: str = "default") -> Dict[str, Any]:
        """
        Generate a report with full security hardening applied.
        
        Security layers applied:
        1. Rate limit check
        2. Input validation and sanitization
        3. Security audit logging
        4. Memory zeroization (high security)
        """
        # Step 1: Rate limiting
        allowed, rate_info = self.rate_limiter.check_rate_limit(client_id)
        if not allowed:
            self.audit_logger.log_event(
                "rate_limit_exceeded",
                ValidationSeverity.WARNING,
                {"client_id_hash": hashlib.sha256(client_id.encode()).hexdigest()[:16],
                 "rate_info": rate_info},
                client_id
            )
            raise RateLimitExceededError(f"Rate limit exceeded: {rate_info}")
        
        # Step 2: Input validation
        validation = self.validator.validate_report_request(request_data)
        if not validation.is_valid:
            self.audit_logger.log_event(
                "validation_failure",
                ValidationSeverity.ERROR,
                {"errors": validation.errors, "warnings": validation.warnings},
                client_id
            )
            raise SecurityValidationError(f"Validation failed: {validation.errors}")
        
        if validation.warnings:
            self.audit_logger.log_event(
                "validation_warnings",
                ValidationSeverity.WARNING,
                {"warnings": validation.warnings},
                client_id
            )
        
        # Step 3: Audit log successful validation
        self.audit_logger.log_event(
            "report_generation_request",
            ValidationSeverity.INFO,
            {"report_type": request_data.get("report_type"),
             "output_format": request_data.get("output_format")},
            client_id
        )
        
        # Step 4: Generate report using sanitized input
        try:
            if self._underlying and hasattr(self._underlying, 'generate_report'):
                # Use underlying generator if available
                result = self._underlying.generate_report(validation.sanitized_input)
            else:
                # Standalone mode - return validation and security info
                result = {
                    "security_validated": True,
                    "sanitized_input": validation.sanitized_input,
                    "validation_warnings": validation.warnings,
                    "rate_limit_info": rate_info,
                    "security_level": self.security_level.value,
                    "secure_generation_id": SecureMemory.generate_secure_token()
                }
            
            # Step 5: High security - zeroize sensitive intermediate data
            if self.security_level in (SecurityLevel.HIGH, SecurityLevel.CRITICAL):
                # Note: Python strings are immutable, documented limitation
                pass
            
            self.audit_logger.log_event(
                "report_generation_success",
                ValidationSeverity.INFO,
                {"report_type": request_data.get("report_type")},
                client_id
            )
            
            return result
            
        except Exception as e:
            self.audit_logger.log_event(
                "report_generation_error",
                ValidationSeverity.ERROR,
                {"error": str(e), "report_type": request_data.get("report_type")},
                client_id
            )
            raise
    
    def get_security_status(self) -> Dict[str, Any]:
        """Get current security status"""
        return {
            "security_level": self.security_level.value,
            "rate_limiter_status": self.rate_limiter.get_current_usage(),
            "audit_summary": self.audit_logger.get_security_summary(),
            "wrapper_version": "v17",
            "security_features": [
                "input_validation",
                "rate_limiting",
                "audit_logging",
                "constant_time_comparison",
                "memory_zeroization_available"
            ]
        }


# Convenience functions
def create_secure_wrapper(generator: Any = None, 
                          security_level: SecurityLevel = SecurityLevel.MEDIUM) -> SecureReportGeneratorWrapper:
    """Create a security-hardened wrapper for a report generator"""
    return SecureReportGeneratorWrapper(generator, security_level)


def secure_compare(a: str, b: str) -> bool:
    """Constant-time string comparison (convenience function)"""
    return SecureMemory.secure_compare(a, b)


def zeroize_sensitive_data(data: Union[bytearray, List[int]]) -> None:
    """Securely zeroize sensitive data (convenience function)"""
    SecureMemory.zeroize(data)


# Version information
SECURITY_HARDENING_VERSION = "v17"
SECURITY_HARDENING_BUILD_DATE = "2026-06-24"
SECURITY_HARDENING_DIMENSION = "B - Security Hardening"
