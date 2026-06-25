"""
Security Hardening: Input Validation Wrappers v28
NeuralShield-AI Security Module
API Stability: STABLE

Layered input validation wrappers that wrap existing security modules
without modifying core implementation. Provides defense-in-depth
against malformed inputs, injection attacks, and DoS vectors.

Philosophy: ADD-ONLY, NO MODIFICATION TO EXISTING CODE
"""

import re
import json
import logging
from typing import Any, Callable, Dict, List, Optional, Union, Tuple
from dataclasses import dataclass, field
from enum import Enum
import hashlib
import secrets

# Configure logging - OPT-IN only
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


class ValidationSeverity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ValidationFailureCode(Enum):
    INPUT_TOO_LARGE = "input_too_large"
    INPUT_TOO_SMALL = "input_too_small"
    INVALID_CHARACTERS = "invalid_characters"
    INVALID_JSON = "invalid_json"
    INVALID_PATTERN = "invalid_pattern"
    SUSPICIOUS_CONTENT = "suspicious_content"
    NULL_BYTE_DETECTED = "null_byte_detected"
    ENCODING_ISSUE = "encoding_issue"
    TYPE_MISMATCH = "type_mismatch"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"


@dataclass
class ValidationResult:
    """Result of input validation check"""
    passed: bool
    severity: ValidationSeverity
    failure_code: Optional[ValidationFailureCode] = None
    message: str = ""
    sanitized_input: Optional[Any] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class InputSizeLimiter:
    """
    Enforces maximum input size limits to prevent DoS via oversized inputs.
    Wraps existing functions without modifying them.
    """
    
    DEFAULT_MAX_PROMPT_LENGTH = 16384  # 16KB
    DEFAULT_MAX_EMBEDDING_SIZE = 1024
    DEFAULT_MAX_JSON_DEPTH = 32
    
    def __init__(
        self,
        max_prompt_length: int = DEFAULT_MAX_PROMPT_LENGTH,
        max_embedding_size: int = DEFAULT_MAX_EMBEDDING_SIZE,
        max_json_depth: int = DEFAULT_MAX_JSON_DEPTH
    ):
        self.max_prompt_length = max_prompt_length
        self.max_embedding_size = max_embedding_size
        self.max_json_depth = max_json_depth
    
    def validate_prompt(self, prompt: str) -> ValidationResult:
        """Validate prompt input size"""
        if not isinstance(prompt, str):
            return ValidationResult(
                passed=False,
                severity=ValidationSeverity.HIGH,
                failure_code=ValidationFailureCode.TYPE_MISMATCH,
                message=f"Expected string, got {type(prompt).__name__}"
            )
        
        if len(prompt) > self.max_prompt_length:
            return ValidationResult(
                passed=False,
                severity=ValidationSeverity.CRITICAL,
                failure_code=ValidationFailureCode.INPUT_TOO_LARGE,
                message=f"Prompt exceeds max length: {len(prompt)} > {self.max_prompt_length}",
                metadata={"actual_length": len(prompt), "max_length": self.max_prompt_length}
            )
        
        if len(prompt) == 0:
            return ValidationResult(
                passed=False,
                severity=ValidationSeverity.MEDIUM,
                failure_code=ValidationFailureCode.INPUT_TOO_SMALL,
                message="Empty prompt provided"
            )
        
        return ValidationResult(passed=True, severity=ValidationSeverity.LOW, message="Size validation passed")
    
    def validate_embedding(self, embedding: List[float]) -> ValidationResult:
        """Validate embedding vector size"""
        if not isinstance(embedding, list):
            return ValidationResult(
                passed=False,
                severity=ValidationSeverity.HIGH,
                failure_code=ValidationFailureCode.TYPE_MISMATCH,
                message=f"Expected list, got {type(embedding).__name__}"
            )
        
        if len(embedding) > self.max_embedding_size:
            return ValidationResult(
                passed=False,
                severity=ValidationSeverity.CRITICAL,
                failure_code=ValidationFailureCode.INPUT_TOO_LARGE,
                message=f"Embedding exceeds max size"
            )
        
        return ValidationResult(passed=True, severity=ValidationSeverity.LOW, message="Embedding size OK")


class ContentSanitizer:
    """
    Sanitizes potentially dangerous content patterns.
    Detects null bytes, control characters, and injection patterns.
    """
    
    # Suspicious patterns commonly used in prompt injection
    SUSPICIOUS_PATTERNS = [
        (r'\x00', ValidationFailureCode.NULL_BYTE_DETECTED),
        (r'ignore.*previous', ValidationFailureCode.SUSPICIOUS_CONTENT),
        (r'disregard.*instructions', ValidationFailureCode.SUSPICIOUS_CONTENT),
        (r'you are now.*', ValidationFailureCode.SUSPICIOUS_CONTENT),
        (r'system.*prompt', ValidationFailureCode.SUSPICIOUS_CONTENT),
        (r'<script', ValidationFailureCode.SUSPICIOUS_CONTENT),
        (r'javascript:', ValidationFailureCode.SUSPICIOUS_CONTENT),
        (r'on\w+=', ValidationFailureCode.SUSPICIOUS_CONTENT),
    ]
    
    # Control characters except newline, tab, carriage return
    CONTROL_CHAR_PATTERN = r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]'
    
    def __init__(self, aggressive: bool = False):
        self.aggressive = aggressive
        self._compiled_patterns = [
            (re.compile(pattern, re.IGNORECASE), code)
            for pattern, code in self.SUSPICIOUS_PATTERNS
        ]
        self._control_chars = re.compile(self.CONTROL_CHAR_PATTERN)
    
    def sanitize(self, content: str) -> ValidationResult:
        """Sanitize input content"""
        if not isinstance(content, str):
            return ValidationResult(
                passed=False,
                severity=ValidationSeverity.HIGH,
                failure_code=ValidationFailureCode.TYPE_MISMATCH,
                message="Content must be string"
            )
        
        # Check for suspicious patterns
        for pattern, failure_code in self._compiled_patterns:
            if pattern.search(content):
                return ValidationResult(
                    passed=False,
                    severity=ValidationSeverity.HIGH,
                    failure_code=failure_code,
                    message=f"Suspicious pattern detected: {failure_code.value}",
                    sanitized_input=self._remove_control_chars(content)
                )
        
        # Remove control characters
        sanitized = self._remove_control_chars(content)
        
        return ValidationResult(
            passed=True,
            severity=ValidationSeverity.LOW,
            message="Content sanitized",
            sanitized_input=sanitized
        )
    
    def _remove_control_chars(self, content: str) -> str:
        """Remove dangerous control characters"""
        return self._control_chars.sub('', content)


class JsonInputValidator:
    """
    Validates JSON inputs with depth and structure checks.
    Prevents JSON bombs and deeply nested structures.
    """
    
    def __init__(self, max_depth: int = 32, max_size: int = 1048576):
        self.max_depth = max_depth
        self.max_size = max_size
    
    def _get_json_depth(self, obj: Any, current_depth: int = 0) -> int:
        """Recursively calculate JSON structure depth"""
        if current_depth > self.max_depth:
            return current_depth
        
        if isinstance(obj, dict):
            if not obj:
                return current_depth + 1
            return max(self._get_json_depth(v, current_depth + 1) for v in obj.values())
        elif isinstance(obj, list):
            if not obj:
                return current_depth + 1
            return max(self._get_json_depth(item, current_depth + 1) for item in obj)
        else:
            return current_depth + 1
    
    def validate(self, json_str: str) -> ValidationResult:
        """Validate JSON input"""
        if len(json_str) > self.max_size:
            return ValidationResult(
                passed=False,
                severity=ValidationSeverity.CRITICAL,
                failure_code=ValidationFailureCode.INPUT_TOO_LARGE,
                message="JSON input too large"
            )
        
        try:
            parsed = json.loads(json_str)
        except json.JSONDecodeError as e:
            return ValidationResult(
                passed=False,
                severity=ValidationSeverity.HIGH,
                failure_code=ValidationFailureCode.INVALID_JSON,
                message=f"Invalid JSON: {str(e)}"
            )
        
        depth = self._get_json_depth(parsed)
        if depth > self.max_depth:
            return ValidationResult(
                passed=False,
                severity=ValidationSeverity.CRITICAL,
                failure_code=ValidationFailureCode.INPUT_TOO_LARGE,
                message=f"JSON depth exceeds limit: {depth} > {self.max_depth}"
            )
        
        return ValidationResult(
            passed=True,
            severity=ValidationSeverity.LOW,
            message=f"JSON valid, depth {depth}",
            metadata={"depth": depth}
        )


class ValidatedSecurityWrapper:
    """
    Wrapper class that adds input validation to existing security modules.
    Does NOT modify original module code - layers security on top.
    """
    
    def __init__(
        self,
        wrapped_object: Any,
        enable_validation: bool = True,
        enable_logging: bool = False
    ):
        self._wrapped = wrapped_object
        self._enable_validation = enable_validation
        self._enable_logging = enable_logging
        self._size_limiter = InputSizeLimiter()
        self._sanitizer = ContentSanitizer()
        self._json_validator = JsonInputValidator()
    
    def __getattr__(self, name: str) -> Any:
        """Wrap method calls with validation"""
        original_attr = getattr(self._wrapped, name)
        
        if not callable(original_attr):
            return original_attr
        
        def wrapped_method(*args, **kwargs):
            # Validate first positional argument if it's a string prompt
            if args and isinstance(args[0], str) and self._enable_validation:
                size_result = self._size_limiter.validate_prompt(args[0])
                if not size_result.passed:
                    if self._enable_logging:
                        logger.warning(f"Validation failed: {size_result.message}")
                    # Return safe default or raise - let caller decide
                    raise ValueError(f"Input validation failed: {size_result.message}")
                
                sanitize_result = self._sanitizer.sanitize(args[0])
                if sanitize_result.sanitized_input:
                    args = (sanitize_result.sanitized_input,) + args[1:]
            
            return original_attr(*args, **kwargs)
        
        return wrapped_method
    
    def get_original(self) -> Any:
        """Get the unwrapped original object"""
        return self._wrapped


# Export public API
__all__ = [
    'InputSizeLimiter',
    'ContentSanitizer',
    'JsonInputValidator',
    'ValidatedSecurityWrapper',
    'ValidationResult',
    'ValidationSeverity',
    'ValidationFailureCode',
]
