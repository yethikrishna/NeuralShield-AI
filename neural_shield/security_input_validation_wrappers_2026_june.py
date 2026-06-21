"""
Security Input Validation Wrappers - NeuralShield AI Security
DIMENSION B: Security Hardening

Layered security ON TOP of existing code - NO modifications to core modules.
All validation is OPT-IN via decorators and wrapper functions.

Purpose: Prevent injection attacks, malformed input, boundary violations,
and type confusion attacks through declarative validation wrappers.

API Stability: STABLE
Thread Safety: Thread-safe
Backward Compatible: 100% - no existing code modified
"""

import re
import json
import logging
import functools
import threading
from typing import Any, Callable, Dict, List, Optional, Set, Type, Union, Pattern
from dataclasses import dataclass, field
from enum import Enum, auto

# Configure null logger - opt-in only
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


class ValidationSeverity(Enum):
    """Severity levels for validation failures."""
    INFO = auto()
    WARNING = auto()
    ERROR = auto()
    FATAL = auto()


class ValidationErrorCode(Enum):
    """Standard validation error codes."""
    TYPE_MISMATCH = "TYPE_MISMATCH"
    VALUE_OUT_OF_RANGE = "VALUE_OUT_OF_RANGE"
    LENGTH_VIOLATION = "LENGTH_VIOLATION"
    PATTERN_MISMATCH = "PATTERN_MISMATCH"
    FORBIDDEN_VALUE = "FORBIDDEN_VALUE"
    MISSING_REQUIRED = "MISSING_REQUIRED"
    INVALID_JSON = "INVALID_JSON"
    SCHEMA_VIOLATION = "SCHEMA_VIOLATION"
    SANITIZATION_FAILED = "SANITIZATION_FAILED"
    UNKNOWN_VALIDATION = "UNKNOWN_VALIDATION"


@dataclass
class ValidationResult:
    """Result of a validation check."""
    passed: bool
    error_code: Optional[ValidationErrorCode] = None
    message: str = ""
    severity: ValidationSeverity = ValidationSeverity.ERROR
    field_name: Optional[str] = None
    original_value: Any = None
    sanitized_value: Any = None


@dataclass
class ValidationContext:
    """Shared context for validation operations."""
    strict_mode: bool = False
    fail_fast: bool = True
    auto_sanitize: bool = False
    log_violations: bool = False
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    
    def __post_init__(self):
        """Initialize context lock."""
        self._lock = threading.Lock()


class InputSanitizer:
    """Safe input sanitization utilities - opt-in only."""
    
    @staticmethod
    def _is_control_char(c: str) -> bool:
        """Check if character is a control character (Python 3.10 compatible)."""
        code = ord(c)
        return code < 32 or code == 127
    
    @staticmethod
    def sanitize_string(value: str, 
                       allow_newlines: bool = False,
                       max_length: Optional[int] = None,
                       strip_control: bool = True) -> str:
        """
        Sanitize string input safely.
        
        Args:
            value: Input string to sanitize
            allow_newlines: Whether to preserve newlines
            max_length: Maximum allowed length
            strip_control: Whether to strip control characters
            
        Returns:
            Sanitized string
        """
        if not isinstance(value, str):
            return str(value) if value is not None else ""
        
        result = value
        
        # Strip dangerous control characters except optionally newlines
        if strip_control:
            if allow_newlines:
                # Keep newlines, remove other control chars
                result = "".join(
                    c for c in result 
                    if c in ('\n', '\r') or not InputSanitizer._is_control_char(c)
                )
            else:
                result = "".join(
                    c for c in result 
                    if not InputSanitizer._is_control_char(c)
                )
        
        # Enforce length limit
        if max_length is not None and len(result) > max_length:
            result = result[:max_length]
        
        return result
    
    @staticmethod
    def sanitize_filename(filename: str, max_length: int = 255) -> str:
        """
        Sanitize filename to prevent path traversal attacks.
        
        Args:
            filename: Input filename
            max_length: Maximum filename length
            
        Returns:
            Sanitized safe filename
        """
        if not isinstance(filename, str):
            filename = str(filename) if filename is not None else "unnamed_file"
        
        result = filename
        
        # Remove leading dots FIRST to prevent hidden files
        while result.startswith('.'):
            result = result[1:]
        
        # Remove path separators and dangerous characters
        unsafe_chars = ['/', '\\', '<', '>', ':', '"', '|', '?', '*', '\0']
        for char in unsafe_chars:
            result = result.replace(char, '_')
        
        # Also handle .. sequences
        while '..' in result:
            result = result.replace('..', '_')
        
        # Enforce length
        if len(result) > max_length:
            name, ext = result.rsplit('.', 1) if '.' in result else (result, '')
            result = name[:max_length - len(ext) - 1] + ('.' + ext if ext else '')
        
        return result or "safe_file"
    
    @staticmethod
    def sanitize_json_input(json_str: str, max_depth: int = 10) -> Optional[Any]:
        """
        Safely parse and validate JSON input.
        
        Args:
            json_str: JSON string to parse
            max_depth: Maximum allowed nesting depth
            
        Returns:
            Parsed JSON or None if invalid
        """
        try:
            # Quick depth check before parsing
            depth = 0
            max_seen = 0
            for c in json_str:
                if c in '{[':
                    depth += 1
                    max_seen = max(max_seen, depth)
                elif c in '}]':
                    depth -= 1
                if max_seen > max_depth:
                    return None
            
            return json.loads(json_str)
        except (json.JSONDecodeError, TypeError, MemoryError):
            return None


class InputValidator:
    """Composable input validation rules."""
    
    def __init__(self, context: Optional[ValidationContext] = None):
        self.context = context or ValidationContext()
        self._sanitizer = InputSanitizer()
    
    def validate_type(self, value: Any, expected_type: Union[Type, tuple], 
                     field_name: str = "value") -> ValidationResult:
        """Validate value type."""
        if isinstance(value, expected_type):
            return ValidationResult(passed=True, field_name=field_name, original_value=value)
        
        return ValidationResult(
            passed=False,
            error_code=ValidationErrorCode.TYPE_MISMATCH,
            message=f"Expected {expected_type}, got {type(value)}",
            field_name=field_name,
            original_value=value
        )
    
    def validate_range(self, value: Union[int, float], 
                      min_val: Optional[Union[int, float]] = None,
                      max_val: Optional[Union[int, float]] = None,
                      field_name: str = "value") -> ValidationResult:
        """Validate numeric range."""
        if not isinstance(value, (int, float)):
            return ValidationResult(
                passed=False,
                error_code=ValidationErrorCode.TYPE_MISMATCH,
                message=f"Expected numeric value, got {type(value)}",
                field_name=field_name,
                original_value=value
            )
        
        if min_val is not None and value < min_val:
            return ValidationResult(
                passed=False,
                error_code=ValidationErrorCode.VALUE_OUT_OF_RANGE,
                message=f"Value {value} below minimum {min_val}",
                field_name=field_name,
                original_value=value
            )
        
        if max_val is not None and value > max_val:
            return ValidationResult(
                passed=False,
                error_code=ValidationErrorCode.VALUE_OUT_OF_RANGE,
                message=f"Value {value} above maximum {max_val}",
                field_name=field_name,
                original_value=value
            )
        
        return ValidationResult(passed=True, field_name=field_name, original_value=value)
    
    def validate_length(self, value: str, 
                       min_len: Optional[int] = None,
                       max_len: Optional[int] = None,
                       field_name: str = "value") -> ValidationResult:
        """Validate string/sequence length."""
        if not hasattr(value, '__len__'):
            return ValidationResult(
                passed=False,
                error_code=ValidationErrorCode.TYPE_MISMATCH,
                message="Value has no length attribute",
                field_name=field_name,
                original_value=value
            )
        
        length = len(value)
        
        if min_len is not None and length < min_len:
            return ValidationResult(
                passed=False,
                error_code=ValidationErrorCode.LENGTH_VIOLATION,
                message=f"Length {length} below minimum {min_len}",
                field_name=field_name,
                original_value=value
            )
        
        if max_len is not None and length > max_len:
            return ValidationResult(
                passed=False,
                error_code=ValidationErrorCode.LENGTH_VIOLATION,
                message=f"Length {length} above maximum {max_len}",
                field_name=field_name,
                original_value=value
            )
        
        return ValidationResult(passed=True, field_name=field_name, original_value=value)
    
    def validate_pattern(self, value: str, pattern: Union[str, Pattern],
                        field_name: str = "value") -> ValidationResult:
        """Validate against regex pattern."""
        if not isinstance(value, str):
            return ValidationResult(
                passed=False,
                error_code=ValidationErrorCode.TYPE_MISMATCH,
                message=f"Expected string, got {type(value)}",
                field_name=field_name,
                original_value=value
            )
        
        compiled_pattern = re.compile(pattern) if isinstance(pattern, str) else pattern
        
        if not compiled_pattern.match(value):
            return ValidationResult(
                passed=False,
                error_code=ValidationErrorCode.PATTERN_MISMATCH,
                message=f"Value does not match required pattern",
                field_name=field_name,
                original_value=value
            )
        
        return ValidationResult(passed=True, field_name=field_name, original_value=value)
    
    def validate_allowed_values(self, value: Any, allowed: Set[Any],
                               field_name: str = "value") -> ValidationResult:
        """Validate value is in allowed set."""
        if value not in allowed:
            return ValidationResult(
                passed=False,
                error_code=ValidationErrorCode.FORBIDDEN_VALUE,
                message=f"Value not in allowed set",
                field_name=field_name,
                original_value=value
            )
        
        return ValidationResult(passed=True, field_name=field_name, original_value=value)
    
    def validate_forbidden_values(self, value: Any, forbidden: Set[Any],
                                 field_name: str = "value") -> ValidationResult:
        """Validate value is NOT in forbidden set."""
        if value in forbidden:
            return ValidationResult(
                passed=False,
                error_code=ValidationErrorCode.FORBIDDEN_VALUE,
                message=f"Value is in forbidden set",
                field_name=field_name,
                original_value=value
            )
        
        return ValidationResult(passed=True, field_name=field_name, original_value=value)
    
    def validate_not_empty(self, value: Any, field_name: str = "value") -> ValidationResult:
        """Validate value is not empty/None."""
        if value is None:
            return ValidationResult(
                passed=False,
                error_code=ValidationErrorCode.MISSING_REQUIRED,
                message="Value is None",
                field_name=field_name,
                original_value=value
            )
        
        if isinstance(value, (str, list, dict, set, tuple)) and len(value) == 0:
            return ValidationResult(
                passed=False,
                error_code=ValidationErrorCode.MISSING_REQUIRED,
                message="Value is empty",
                field_name=field_name,
                original_value=value
            )
        
        return ValidationResult(passed=True, field_name=field_name, original_value=value)


class ValidationError(Exception):
    """Exception raised when validation fails in strict mode."""
    
    def __init__(self, result: ValidationResult):
        self.result = result
        super().__init__(f"{result.error_code.value}: {result.message}")


def validate_input(**rules: Dict[str, Any]):
    """
    Decorator to validate function inputs.
    
    Usage:
        @validate_input(
            prompt={'type': str, 'max_len': 10000, 'not_empty': True},
            temperature={'type': (int, float), 'min': 0, 'max': 2},
            user_id={'pattern': r'^[a-zA-Z0-9_-]{1,64}$'}
        )
        def process_prompt(prompt: str, temperature: float, user_id: str):
            ...
    
    Args:
        **rules: Validation rules per parameter name
        
    Returns:
        Decorated function with input validation
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            import inspect
            sig = inspect.signature(func)
            bound = sig.bind(*args, **kwargs)
            bound.apply_defaults()
            
            validator = InputValidator()
            
            for param_name, param_rules in rules.items():
                if param_name not in bound.arguments:
                    if param_rules.get('required', True):
                        raise ValidationError(ValidationResult(
                            passed=False,
                            error_code=ValidationErrorCode.MISSING_REQUIRED,
                            message=f"Missing required parameter: {param_name}",
                            field_name=param_name
                        ))
                    continue
                
                value = bound.arguments[param_name]
                
                # Type validation
                if 'type' in param_rules:
                    result = validator.validate_type(value, param_rules['type'], param_name)
                    if not result.passed:
                        raise ValidationError(result)
                
                # Not empty validation
                if param_rules.get('not_empty', False):
                    result = validator.validate_not_empty(value, param_name)
                    if not result.passed:
                        raise ValidationError(result)
                
                # Range validation
                if 'min' in param_rules or 'max' in param_rules:
                    result = validator.validate_range(
                        value, 
                        param_rules.get('min'), 
                        param_rules.get('max'),
                        param_name
                    )
                    if not result.passed:
                        raise ValidationError(result)
                
                # Length validation
                if 'min_len' in param_rules or 'max_len' in param_rules:
                    result = validator.validate_length(
                        value,
                        param_rules.get('min_len'),
                        param_rules.get('max_len'),
                        param_name
                    )
                    if not result.passed:
                        raise ValidationError(result)
                
                # Pattern validation
                if 'pattern' in param_rules:
                    result = validator.validate_pattern(value, param_rules['pattern'], param_name)
                    if not result.passed:
                        raise ValidationError(result)
                
                # Allowed values
                if 'allowed' in param_rules:
                    result = validator.validate_allowed_values(value, set(param_rules['allowed']), param_name)
                    if not result.passed:
                        raise ValidationError(result)
                
                # Forbidden values
                if 'forbidden' in param_rules:
                    result = validator.validate_forbidden_values(value, set(param_rules['forbidden']), param_name)
                    if not result.passed:
                        raise ValidationError(result)
            
            return func(*args, **kwargs)
        return wrapper
    return decorator


def sanitize_input(**sanitize_rules: Dict[str, Any]):
    """
    Decorator to sanitize function inputs before processing.
    
    Usage:
        @sanitize_input(
            prompt={'max_length': 10000, 'strip_control': True},
            filename={'sanitize_filename': True}
        )
        def process_input(prompt: str, filename: str):
            ...
    
    Args:
        **sanitize_rules: Sanitization rules per parameter
        
    Returns:
        Decorated function with automatic input sanitization
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            import inspect
            sig = inspect.signature(func)
            bound = sig.bind(*args, **kwargs)
            bound.apply_defaults()
            
            sanitizer = InputSanitizer()
            
            for param_name, rules in sanitize_rules.items():
                if param_name not in bound.arguments:
                    continue
                
                value = bound.arguments[param_name]
                
                if isinstance(value, str):
                    if rules.get('sanitize_filename', False):
                        bound.arguments[param_name] = sanitizer.sanitize_filename(
                            value, 
                            max_length=rules.get('max_length', 255)
                        )
                    else:
                        bound.arguments[param_name] = sanitizer.sanitize_string(
                            value,
                            allow_newlines=rules.get('allow_newlines', False),
                            max_length=rules.get('max_length'),
                            strip_control=rules.get('strip_control', True)
                        )
            
            return func(*bound.args, **bound.kwargs)
        return wrapper
    return decorator


# Global shared instances - thread-safe
_default_validator = InputValidator()
_default_sanitizer = InputSanitizer()
_global_lock = threading.Lock()


def get_validator() -> InputValidator:
    """Get shared validator instance."""
    with _global_lock:
        return _default_validator


def get_sanitizer() -> InputSanitizer:
    """Get shared sanitizer instance."""
    with _global_lock:
        return _default_sanitizer


# Export public API
__all__ = [
    # Classes
    'InputValidator',
    'InputSanitizer',
    'ValidationContext',
    'ValidationResult',
    'ValidationError',
    'ValidationSeverity',
    'ValidationErrorCode',
    
    # Decorators
    'validate_input',
    'sanitize_input',
    
    # Factory functions
    'get_validator',
    'get_sanitizer',
]
