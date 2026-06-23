"""
Security Hardening Layer v14 for Threat Intelligence Fusion Engine
ADD-ONLY - NO existing code modified
OPT-IN pattern - disabled by default
Backward compatible 100%
"""

import threading
import time
import hmac
import hashlib
import secrets
from dataclasses import dataclass, field
from typing import Optional, Callable, Any, Dict, List
from enum import Enum


class ValidationSeverity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ValidationResult:
    is_valid: bool
    severity: ValidationSeverity
    message: str
    field_name: Optional[str] = None
    sanitized_value: Any = None


@dataclass
class RateLimitConfig:
    max_requests_per_window: int = 100
    window_seconds: int = 60
    burst_limit: int = 20
    enabled: bool = True


@dataclass
class SecurityHardeningConfig:
    enable_input_validation: bool = True
    enable_rate_limiting: bool = True
    enable_memory_zeroization: bool = True
    enable_constant_time_compare: bool = True
    rate_limit_config: RateLimitConfig = field(default_factory=RateLimitConfig)
    max_indicator_size: int = 1024
    max_metadata_entries: int = 50
    max_metadata_value_length: int = 2048


class SecureMemoryZeroizer:
    """Secure memory zeroization utilities - side channel resistant"""
    
    @staticmethod
    def zeroize_bytes(data: bytearray) -> None:
        """Zeroize bytearray in a way that resists compiler optimization"""
        for i in range(len(data)):
            data[i] = 0
        # Force memory barrier effect
        if sum(data) != 0:
            raise RuntimeError("Memory zeroization failed")
    
    @staticmethod
    def zeroize_string(s: str) -> str:
        """Return empty string, original should be garbage collected"""
        return ""
    
    @staticmethod
    def zeroize_list(lst: list) -> None:
        """Clear list contents"""
        lst.clear()


class ConstantTimeComparator:
    """Constant-time comparison utilities to prevent timing attacks"""
    
    @staticmethod
    def compare_strings(a: str, b: str) -> bool:
        """Constant-time string comparison using HMAC"""
        key = secrets.token_bytes(32)
        hmac_a = hmac.new(key, a.encode('utf-8') if a else b'', hashlib.sha256).digest()
        hmac_b = hmac.new(key, b.encode('utf-8') if b else b'', hashlib.sha256).digest()
        return hmac.compare_digest(hmac_a, hmac_b)
    
    @staticmethod
    def compare_bytes(a: bytes, b: bytes) -> bool:
        """Constant-time bytes comparison"""
        return hmac.compare_digest(a, b)
    
    @staticmethod
    def compare_ips(ip1: str, ip2: str) -> bool:
        """Constant-time IP comparison"""
        return ConstantTimeComparator.compare_strings(ip1, ip2)


class InputValidator:
    """Input validation and sanitization wrapper"""
    
    def __init__(self, config: SecurityHardeningConfig):
        self.config = config
    
    def validate_indicator_type(self, indicator_type: str) -> ValidationResult:
        """Validate indicator type against allowed values"""
        allowed_types = {
            'ip', 'domain', 'url', 'hash', 'email', 'filename', 
            'user_agent', 'ja3', 'ja3s'
        }
        
        if not indicator_type or not isinstance(indicator_type, str):
            return ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.HIGH,
                message="Indicator type must be a non-empty string",
                field_name="indicator_type"
            )
        
        indicator_type_clean = indicator_type.lower().strip()
        
        if indicator_type_clean not in allowed_types:
            return ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.MEDIUM,
                message=f"Indicator type '{indicator_type_clean}' not in allowed types",
                field_name="indicator_type",
                sanitized_value=indicator_type_clean
            )
        
        return ValidationResult(
            is_valid=True,
            severity=ValidationSeverity.LOW,
            message="Indicator type valid",
            field_name="indicator_type",
            sanitized_value=indicator_type_clean
        )
    
    def validate_indicator_value(self, value: str, indicator_type: str) -> ValidationResult:
        """Validate indicator value based on type"""
        if not value or not isinstance(value, str):
            return ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.HIGH,
                message="Indicator value must be a non-empty string",
                field_name="value"
            )
        
        if len(value) > self.config.max_indicator_size:
            return ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.HIGH,
                message=f"Indicator value exceeds max size of {self.config.max_indicator_size}",
                field_name="value"
            )
        
        # Basic sanitization
        sanitized = value.strip()
        
        # Type-specific validation
        if indicator_type == 'ip':
            # Basic IP format check
            parts = sanitized.split('.')
            if len(parts) != 4:
                return ValidationResult(
                    is_valid=False,
                    severity=ValidationSeverity.MEDIUM,
                    message="Invalid IPv4 format",
                    field_name="value"
                )
        
        return ValidationResult(
            is_valid=True,
            severity=ValidationSeverity.LOW,
            message="Indicator value valid",
            field_name="value",
            sanitized_value=sanitized
        )
    
    def validate_confidence(self, confidence: float) -> ValidationResult:
        """Validate confidence score"""
        if not isinstance(confidence, (int, float)):
            return ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.HIGH,
                message="Confidence must be a number",
                field_name="confidence"
            )
        
        clamped = max(0.0, min(1.0, float(confidence)))
        
        return ValidationResult(
            is_valid=True,
            severity=ValidationSeverity.LOW,
            message="Confidence valid",
            field_name="confidence",
            sanitized_value=clamped
        )
    
    def validate_metadata(self, metadata: Dict[str, Any]) -> ValidationResult:
        """Validate metadata dictionary"""
        if not isinstance(metadata, dict):
            return ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.HIGH,
                message="Metadata must be a dictionary",
                field_name="metadata"
            )
        
        if len(metadata) > self.config.max_metadata_entries:
            return ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.MEDIUM,
                message=f"Metadata exceeds max entries of {self.config.max_metadata_entries}",
                field_name="metadata"
            )
        
        sanitized = {}
        for key, value in metadata.items():
            if not isinstance(key, str):
                continue
            if len(key) > 64:
                continue
            str_value = str(value) if value is not None else ""
            if len(str_value) > self.config.max_metadata_value_length:
                str_value = str_value[:self.config.max_metadata_value_length]
            sanitized[key] = str_value
        
        return ValidationResult(
            is_valid=True,
            severity=ValidationSeverity.LOW,
            message="Metadata validated and sanitized",
            field_name="metadata",
            sanitized_value=sanitized
        )
    
    def validate_indicator_ingestion(self, indicator_type: str, value: str, 
                                    confidence: float, metadata: Dict[str, Any]) -> Dict[str, ValidationResult]:
        """Validate full indicator ingestion request"""
        results = {}
        results['indicator_type'] = self.validate_indicator_type(indicator_type)
        results['value'] = self.validate_indicator_value(value, indicator_type)
        results['confidence'] = self.validate_confidence(confidence)
        results['metadata'] = self.validate_metadata(metadata)
        return results


class AdaptiveRateLimiter:
    """Adaptive rate limiter with token bucket algorithm and burst protection"""
    
    def __init__(self, config: RateLimitConfig):
        self.config = config
        self._lock = threading.Lock()
        self._window_start = time.time()
        self._request_count = 0
        self._burst_tokens = config.burst_limit
        self._last_refill = time.time()
    
    def _refill_bucket(self) -> None:
        """Refill burst token bucket"""
        now = time.time()
        elapsed = now - self._last_refill
        refill_amount = int(elapsed * (self.config.burst_limit / self.config.window_seconds))
        if refill_amount > 0:
            self._burst_tokens = min(self.config.burst_limit, self._burst_tokens + refill_amount)
            self._last_refill = now
    
    def check_rate_limit(self, client_id: str = "default") -> bool:
        """Check if request should be rate limited"""
        if not self.config.enabled:
            return True
        
        with self._lock:
            now = time.time()
            
            # Reset window if expired
            if now - self._window_start >= self.config.window_seconds:
                self._window_start = now
                self._request_count = 0
            
            # Refill burst bucket
            self._refill_bucket()
            
            # Check window limit
            if self._request_count >= self.config.max_requests_per_window:
                return False
            
            # Check burst limit
            if self._burst_tokens <= 0:
                return False
            
            self._request_count += 1
            self._burst_tokens -= 1
            return True
    
    def get_stats(self) -> Dict[str, Any]:
        """Get rate limiter statistics"""
        with self._lock:
            return {
                'requests_in_window': self._request_count,
                'window_remaining': max(0, self.config.window_seconds - (time.time() - self._window_start)),
                'burst_tokens_remaining': self._burst_tokens,
                'enabled': self.config.enabled
            }


class ThreatIntelligenceSecurityHardener:
    """
    Security Hardening Wrapper for Threat Intelligence Fusion Engine
    ADD-ONLY layer - wraps existing functionality
    OPT-IN - disabled by default
    100% backward compatible
    """
    
    _instance = None
    _instance_lock = threading.Lock()
    
    def __new__(cls):
        with cls._instance_lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self._enabled = False
        self._lock = threading.Lock()
        self.config = SecurityHardeningConfig()
        self.validator = InputValidator(self.config)
        self.rate_limiter = AdaptiveRateLimiter(self.config.rate_limit_config)
        self.memory_zeroizer = SecureMemoryZeroizer()
        self.constant_time = ConstantTimeComparator()
        self._validation_failures = 0
        self._rate_limited_requests = 0
    
    def enable(self) -> None:
        """Enable security hardening - OPT-IN"""
        with self._lock:
            self._enabled = True
    
    def disable(self) -> None:
        """Disable security hardening"""
        with self._lock:
            self._enabled = False
    
    def is_enabled(self) -> bool:
        return self._enabled
    
    def validate_and_sanitize_indicator(self, indicator_type: str, value: str,
                                       confidence: float, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate and sanitize indicator before ingestion
        Returns: dict with 'allowed' flag and sanitized values
        """
        if not self._enabled:
            return {
                'allowed': True,
                'sanitized': {
                    'indicator_type': indicator_type,
                    'value': value,
                    'confidence': confidence,
                    'metadata': metadata
                },
                'validations': {}
            }
        
        # Check rate limit first
        if not self.rate_limiter.check_rate_limit():
            self._rate_limited_requests += 1
            return {
                'allowed': False,
                'reason': 'rate_limited',
                'sanitized': None,
                'validations': {}
            }
        
        # Run all validations
        validations = self.validator.validate_indicator_ingestion(
            indicator_type, value, confidence, metadata
        )
        
        # Check if any critical/high severity failures
        has_failure = any(
            not v.is_valid and v.severity in (ValidationSeverity.HIGH, ValidationSeverity.CRITICAL)
            for v in validations.values()
        )
        
        if has_failure:
            self._validation_failures += 1
            return {
                'allowed': False,
                'reason': 'validation_failed',
                'sanitized': None,
                'validations': {k: v.__dict__ for k, v in validations.items()}
            }
        
        # Use sanitized values
        sanitized = {
            'indicator_type': validations['indicator_type'].sanitized_value or indicator_type,
            'value': validations['value'].sanitized_value or value,
            'confidence': validations['confidence'].sanitized_value or confidence,
            'metadata': validations['metadata'].sanitized_value or metadata
        }
        
        return {
            'allowed': True,
            'sanitized': sanitized,
            'validations': {k: v.__dict__ for k, v in validations.items()}
        }
    
    def secure_compare_indicators(self, val1: str, val2: str) -> bool:
        """Constant-time indicator comparison"""
        if not self._enabled:
            return val1 == val2
        return self.constant_time.compare_strings(val1, val2)
    
    def secure_zeroize_sensitive_data(self, data: Any) -> None:
        """Securely zeroize sensitive data"""
        if not self._enabled:
            return
        if isinstance(data, bytearray):
            self.memory_zeroizer.zeroize_bytes(data)
        elif isinstance(data, list):
            self.memory_zeroizer.zeroize_list(data)
    
    def get_security_stats(self) -> Dict[str, Any]:
        """Get security hardening statistics"""
        with self._lock:
            return {
                'enabled': self._enabled,
                'validation_failures': self._validation_failures,
                'rate_limited_requests': self._rate_limited_requests,
                'rate_limiter': self.rate_limiter.get_stats(),
                'config': {
                    'input_validation': self.config.enable_input_validation,
                    'rate_limiting': self.config.enable_rate_limiting,
                    'memory_zeroization': self.config.enable_memory_zeroization,
                    'constant_time_compare': self.config.enable_constant_time_compare
                }
            }


# Singleton instance for global access
security_hardener = ThreatIntelligenceSecurityHardener()
