"""
Error Resilience: Enhanced Exception Hierarchy
Dimension E - Error Resilience
Stability: BETA
Last Updated: June 24, 2026

Custom exception hierarchy for NeuralShield-AI providing:
- Granular exception types for specific failure modes
- Context-rich error information
- Chainable exceptions for root cause analysis
- Error categorization for automated handling
"""

from typing import Optional, Dict, Any, List
from enum import Enum
import traceback
import uuid


class ErrorSeverity(Enum):
    """Severity levels for error classification."""
    DEBUG = 0
    INFO = 1
    WARNING = 2
    ERROR = 3
    CRITICAL = 4
    FATAL = 5


class ErrorCategory(Enum):
    """Categories for error classification and routing."""
    VALIDATION_ERROR = "validation_error"
    AUTHENTICATION_ERROR = "authentication_error"
    AUTHORIZATION_ERROR = "authorization_error"
    RESOURCE_ERROR = "resource_error"
    NETWORK_ERROR = "network_error"
    TIMEOUT_ERROR = "timeout_error"
    THROTTLING_ERROR = "throttling_error"
    CONFIGURATION_ERROR = "configuration_error"
    INTEGRATION_ERROR = "integration_error"
    PROCESSING_ERROR = "processing_error"
    SECURITY_ERROR = "security_error"
    UNKNOWN_ERROR = "unknown_error"


class NeuralShieldBaseException(Exception):
    """
    Base exception for all NeuralShield-AI exceptions.
    
    Provides:
    - Unique error ID for tracing
    - Timestamp of error occurrence
    - Structured context information
    - Severity and category classification
    - Chainable exception support
    """
    
    def __init__(
        self,
        message: str,
        error_code: str = "NS_ERR_001",
        severity: ErrorSeverity = ErrorSeverity.ERROR,
        category: ErrorCategory = ErrorCategory.UNKNOWN_ERROR,
        context: Optional[Dict[str, Any]] = None,
        retryable: bool = False,
        cause: Optional[Exception] = None
    ):
        super().__init__(message)
        self.error_id = str(uuid.uuid4())
        self.error_code = error_code
        self.message = message
        self.severity = severity
        self.category = category
        self.context = context or {}
        self.retryable = retryable
        self.cause = cause
        self.traceback = traceback.format_exc() if cause else None
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to structured dictionary for logging."""
        return {
            "error_id": self.error_id,
            "error_code": self.error_code,
            "message": self.message,
            "severity": self.severity.name,
            "category": self.category.value,
            "context": self.context,
            "retryable": self.retryable,
            "cause": str(self.cause) if self.cause else None
        }
    
    def __str__(self) -> str:
        return f"[{self.error_code}] {self.message} (ID: {self.error_id})"


# =============================================================================
# Validation Exceptions
# =============================================================================

class ValidationError(NeuralShieldBaseException):
    """Raised when input validation fails."""
    
    def __init__(
        self,
        message: str = "Input validation failed",
        field: Optional[str] = None,
        value: Any = None,
        context: Optional[Dict[str, Any]] = None
    ):
        ctx = context or {}
        if field:
            ctx["field"] = field
        if value is not None:
            ctx["value_repr"] = repr(value)[:100]
            
        super().__init__(
            message=message,
            error_code="NS_VAL_001",
            severity=ErrorSeverity.WARNING,
            category=ErrorCategory.VALIDATION_ERROR,
            context=ctx,
            retryable=False
        )


class EmptyInputError(ValidationError):
    """Raised when required input is empty."""
    
    def __init__(self, field_name: str, context: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=f"Required field '{field_name}' cannot be empty",
            field=field_name,
            context=context
        )
        self.error_code = "NS_VAL_002"


class InputTooLongError(ValidationError):
    """Raised when input exceeds maximum length."""
    
    def __init__(
        self,
        field_name: str,
        max_length: int,
        actual_length: int,
        context: Optional[Dict[str, Any]] = None
    ):
        ctx = context or {}
        ctx["max_length"] = max_length
        ctx["actual_length"] = actual_length
        
        super().__init__(
            message=f"Field '{field_name}' exceeds maximum length of {max_length} (got {actual_length})",
            field=field_name,
            context=ctx
        )
        self.error_code = "NS_VAL_003"


class InvalidFormatError(ValidationError):
    """Raised when input format is invalid."""
    
    def __init__(
        self,
        field_name: str,
        expected_format: str,
        context: Optional[Dict[str, Any]] = None
    ):
        ctx = context or {}
        ctx["expected_format"] = expected_format
        
        super().__init__(
            message=f"Field '{field_name}' has invalid format (expected: {expected_format})",
            field=field_name,
            context=ctx
        )
        self.error_code = "NS_VAL_004"


# =============================================================================
# Security Exceptions
# =============================================================================

class SecurityError(NeuralShieldBaseException):
    """Raised when a security violation is detected."""
    
    def __init__(
        self,
        message: str = "Security violation detected",
        threat_type: Optional[str] = None,
        confidence: Optional[float] = None,
        context: Optional[Dict[str, Any]] = None
    ):
        ctx = context or {}
        if threat_type:
            ctx["threat_type"] = threat_type
        if confidence is not None:
            ctx["confidence"] = confidence
            
        super().__init__(
            message=message,
            error_code="NS_SEC_001",
            severity=ErrorSeverity.CRITICAL,
            category=ErrorCategory.SECURITY_ERROR,
            context=ctx,
            retryable=False
        )


class ThreatDetectedError(SecurityError):
    """Raised when a threat is positively detected."""
    
    def __init__(
        self,
        threat_type: str,
        confidence: float,
        message: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            message=message or f"Threat detected: {threat_type} (confidence: {confidence:.2%})",
            threat_type=threat_type,
            confidence=confidence,
            context=context
        )
        self.error_code = "NS_SEC_002"


class PromptInjectionDetectedError(ThreatDetectedError):
    """Raised when prompt injection is detected."""
    
    def __init__(
        self,
        confidence: float,
        injection_type: str = "unknown",
        context: Optional[Dict[str, Any]] = None
    ):
        ctx = context or {}
        ctx["injection_type"] = injection_type
        
        super().__init__(
            threat_type="prompt_injection",
            confidence=confidence,
            message=f"Prompt injection detected (type: {injection_type}, confidence: {confidence:.2%})",
            context=ctx
        )
        self.error_code = "NS_SEC_003"


class JailbreakDetectedError(ThreatDetectedError):
    """Raised when jailbreak attempt is detected."""
    
    def __init__(
        self,
        confidence: float,
        attack_pattern: str = "unknown",
        context: Optional[Dict[str, Any]] = None
    ):
        ctx = context or {}
        ctx["attack_pattern"] = attack_pattern
        
        super().__init__(
            threat_type="jailbreak_attempt",
            confidence=confidence,
            message=f"Jailbreak attempt detected (pattern: {attack_pattern}, confidence: {confidence:.2%})",
            context=ctx
        )
        self.error_code = "NS_SEC_004"


# =============================================================================
# Processing Exceptions
# =============================================================================

class ProcessingError(NeuralShieldBaseException):
    """Raised when processing fails for any reason."""
    
    def __init__(
        self,
        message: str = "Processing failed",
        component: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
        retryable: bool = True
    ):
        ctx = context or {}
        if component:
            ctx["component"] = component
            
        super().__init__(
            message=message,
            error_code="NS_PROC_001",
            severity=ErrorSeverity.ERROR,
            category=ErrorCategory.PROCESSING_ERROR,
            context=ctx,
            retryable=retryable
        )


class ModelInferenceError(ProcessingError):
    """Raised when model inference fails."""
    
    def __init__(
        self,
        model_name: str,
        message: str = "Model inference failed",
        context: Optional[Dict[str, Any]] = None
    ):
        ctx = context or {}
        ctx["model_name"] = model_name
        
        super().__init__(
            message=f"Model '{model_name}' inference failed: {message}",
            component=model_name,
            context=ctx,
            retryable=True
        )
        self.error_code = "NS_PROC_002"


class ExternalServiceError(ProcessingError):
    """Raised when an external service call fails."""
    
    def __init__(
        self,
        service_name: str,
        status_code: Optional[int] = None,
        message: str = "External service call failed",
        context: Optional[Dict[str, Any]] = None,
        retryable: bool = True
    ):
        ctx = context or {}
        ctx["service_name"] = service_name
        if status_code:
            ctx["status_code"] = status_code
            
        super().__init__(
            message=f"Service '{service_name}' failed: {message}",
            component=service_name,
            context=ctx,
            retryable=retryable
        )
        self.error_code = "NS_PROC_003"


# =============================================================================
# Resource & Timeout Exceptions
# =============================================================================

class ResourceExhaustedError(NeuralShieldBaseException):
    """Raised when system resources are exhausted."""
    
    def __init__(
        self,
        resource_type: str,
        current_usage: float,
        limit: float,
        context: Optional[Dict[str, Any]] = None
    ):
        ctx = context or {}
        ctx["resource_type"] = resource_type
        ctx["current_usage"] = current_usage
        ctx["limit"] = limit
        
        super().__init__(
            message=f"Resource '{resource_type}' exhausted: {current_usage}/{limit}",
            error_code="NS_RES_001",
            severity=ErrorSeverity.ERROR,
            category=ErrorCategory.RESOURCE_ERROR,
            context=ctx,
            retryable=True
        )


class TimeoutError(NeuralShieldBaseException):
    """Raised when an operation times out."""
    
    def __init__(
        self,
        operation: str,
        timeout_seconds: float,
        context: Optional[Dict[str, Any]] = None
    ):
        ctx = context or {}
        ctx["operation"] = operation
        ctx["timeout_seconds"] = timeout_seconds
        
        super().__init__(
            message=f"Operation '{operation}' timed out after {timeout_seconds}s",
            error_code="NS_TO_001",
            severity=ErrorSeverity.WARNING,
            category=ErrorCategory.TIMEOUT_ERROR,
            context=ctx,
            retryable=True
        )


class RateLimitExceededError(NeuralShieldBaseException):
    """Raised when rate limit is exceeded."""
    
    def __init__(
        self,
        limit_key: str,
        retry_after_seconds: Optional[float] = None,
        context: Optional[Dict[str, Any]] = None
    ):
        ctx = context or {}
        ctx["limit_key"] = limit_key
        if retry_after_seconds:
            ctx["retry_after_seconds"] = retry_after_seconds
            
        super().__init__(
            message=f"Rate limit exceeded for '{limit_key}'",
            error_code="NS_RL_001",
            severity=ErrorSeverity.WARNING,
            category=ErrorCategory.THROTTLING_ERROR,
            context=ctx,
            retryable=True
        )


# =============================================================================
# Configuration Exceptions
# =============================================================================

class ConfigurationError(NeuralShieldBaseException):
    """Raised when configuration is invalid or missing."""
    
    def __init__(
        self,
        message: str = "Invalid configuration",
        config_key: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ):
        ctx = context or {}
        if config_key:
            ctx["config_key"] = config_key
            
        super().__init__(
            message=message,
            error_code="NS_CFG_001",
            severity=ErrorSeverity.ERROR,
            category=ErrorCategory.CONFIGURATION_ERROR,
            context=ctx,
            retryable=False
        )


class MissingConfigurationError(ConfigurationError):
    """Raised when required configuration is missing."""
    
    def __init__(
        self,
        config_key: str,
        context: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            message=f"Required configuration '{config_key}' is missing",
            config_key=config_key,
            context=context
        )
        self.error_code = "NS_CFG_002"


# =============================================================================
# Fallback & Degradation Exceptions
# =============================================================================

class GracefulDegradationActivated(Exception):
    """
    Non-error exception to signal graceful degradation.
    
    This is NOT an error condition - it signals that the system
    has fallen back to a degraded but functional mode.
    """
    
    def __init__(
        self,
        feature: str,
        fallback_mode: str,
        reason: str,
        context: Optional[Dict[str, Any]] = None
    ):
        super().__init__(f"Graceful degradation activated for {feature}: {reason}")
        self.feature = feature
        self.fallback_mode = fallback_mode
        self.reason = reason
        self.context = context or {}
