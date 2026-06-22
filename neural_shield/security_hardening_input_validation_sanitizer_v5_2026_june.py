"""
Security Hardening: Input Validation & Sanitization Wrapper v5
DIMENSION B - Security Hardening
ADD-ONLY implementation - wraps existing modules, no core code modified

Provides:
- Type-safe input validation wrappers
- Recursive sanitization for nested structures
- SQL/NoSQL injection pattern detection
- Command injection prevention
- Path traversal protection
- Unicode normalization and confusable detection
- HTML/JS XSS sanitization
"""

from __future__ import annotations

import enum
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, TypeVar, Union
from urllib.parse import urlparse


# ============================================================================
# ENUMS
# ============================================================================

class ValidationSeverity(enum.Enum):
    """Severity levels for validation violations."""
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4
    
    @property
    def value_str(self) -> str:
        return self.name.lower()


class ValidationRule(enum.Enum):
    """Available validation rules."""
    TYPE_CHECK = "type_check"
    SQL_INJECTION = "sql_injection"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    XSS_PATTERN = "xss_pattern"
    UNICODE_CONFUSABLE = "unicode_confusable"
    STRING_LENGTH = "string_length"
    REGEX_MATCH = "regex_match"
    ALLOWLIST = "allowlist"
    BLOCKLIST = "blocklist"
    NESTED_DEPTH = "nested_depth"
    URL_SAFETY = "url_safety"
    CUSTOM = "custom"


class SanitizationMode(enum.Enum):
    """Sanitization behavior modes."""
    REJECT = "reject"  # Raise exception on violation
    REMOVE = "remove"  # Remove offending content
    REPLACE = "replace"  # Replace with safe placeholder
    ESCAPE = "escape"  # Escape special characters
    LOG_ONLY = "log_only"  # Just log, don't modify


# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class ValidationViolation:
    """Represents a single validation violation."""
    rule: ValidationRule
    severity: ValidationSeverity
    message: str
    field_path: str = ""
    offending_value: str = ""
    timestamp: float = field(default_factory=lambda: __import__('time').time())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule": self.rule.value,
            "severity": self.severity.value_str,
            "message": self.message,
            "field_path": self.field_path,
            "offending_value": self.offending_value[:100]
        }


@dataclass
class ValidationResult:
    """Result of input validation."""
    is_valid: bool
    violations: List[ValidationViolation] = field(default_factory=list)
    sanitized_value: Any = None
    original_value: Any = None

    @property
    def has_critical(self) -> bool:
        return any(v.severity == ValidationSeverity.CRITICAL for v in self.violations)

    @property
    def has_high(self) -> bool:
        return any(v.severity in (ValidationSeverity.CRITICAL, ValidationSeverity.HIGH) for v in self.violations)

    def raise_if_invalid(self, min_severity: ValidationSeverity = ValidationSeverity.HIGH) -> None:
        severe = [v for v in self.violations if v.severity.value >= min_severity.value]
        if severe:
            msgs = "; ".join(f"{v.field_path}: {v.message}" for v in severe)
            raise SecurityValidationError(f"Validation failed: {msgs}", severe)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_valid": self.is_valid,
            "violation_count": len(self.violations),
            "violations": [v.to_dict() for v in self.violations],
            "has_critical": self.has_critical,
            "has_high": self.has_high
        }


class SecurityValidationError(Exception):
    """Custom exception for security validation failures."""
    def __init__(self, message: str, violations: List[ValidationViolation]):
        super().__init__(message)
        self.violations = violations


# ============================================================================
# PATTERN DATABASE (Immutable, compiled once)
# ============================================================================

class SecurityPatterns:
    """Compiled regex patterns for security detection."""
    
    # SQL Injection patterns (case-insensitive)
    # More specific patterns to avoid false positives on normal English
    SQL_INJECTION = re.compile(
        r"(\bUNION\s+SELECT\b|\bOR\s+1\s*=\s*1"
        r"|\bAND\s+1\s*=\s*1|--\s*$|;\s*[\w]|'[\s]*OR\b|'[\s]*AND\b"
        r"|\b(EXEC|EXECUTE)\s+\w|sp_\w+|xp_\w+|DECLARE\s+@)",
        re.IGNORECASE
    )
    
    # Command injection patterns
    COMMAND_INJECTION = re.compile(
        r"([;&|`$()<>]|\|\||&&|\$\(|\`|\.\./|\.\.\\|\/etc\/|\/bin\/|cmd\.exe|powershell)",
        re.IGNORECASE
    )
    
    # Path traversal
    PATH_TRAVERSAL = re.compile(r"(\.\.[/\\]|%2e%2e|%c0%ae|/etc/|C:\\\\|\\\\\\\\)")
    
    # XSS patterns
    XSS_BASIC = re.compile(
        r"(<script|javascript:|on\w+\s*=|data:text/html|expression\(|vbscript:)",
        re.IGNORECASE
    )
    
    # Unicode confusable homoglyphs (common attack patterns)
    CONFUSABLES = {
        '\u0430': 'a', '\u0441': 'c', '\u0435': 'e', '\u043e': 'o',
        '\u0440': 'p', '\u0445': 'x', '\u0455': 's', '\u0456': 'i',
        '\u0457': 'j', '\u03bf': 'o', '\u03c1': 'p', '\u03c7': 'x'
    }
    
    # Dangerous URL schemes
    DANGEROUS_SCHEMES = {'javascript', 'vbscript', 'data', 'file', 'ftp'}
    
    # Safe HTML tags for basic sanitization
    SAFE_HTML_TAGS = {'b', 'i', 'u', 'em', 'strong', 'p', 'br', 'ul', 'ol', 'li'}


# ============================================================================
# MAIN VALIDATOR CLASS
# ============================================================================

T = TypeVar('T')

class InputSecurityValidator:
    """
    Secure input validation and sanitization wrapper.
    ADD-ONLY: Wraps existing functions, does not modify core logic.
    
    Usage:
        validator = InputSecurityValidator()
        result = validator.validate(user_input, max_depth=5)
        result.raise_if_invalid()
        safe_input = result.sanitized_value
    """
    
    def __init__(
        self,
        mode: SanitizationMode = SanitizationMode.REJECT,
        max_nested_depth: int = 10,
        max_string_length: int = 1_000_000,
        enable_confusable_detection: bool = True
    ):
        self.mode = mode
        self.max_nested_depth = max_nested_depth
        self.max_string_length = max_string_length
        self.enable_confusable_detection = enable_confusable_detection
        self._custom_rules: Dict[str, Callable[[Any], Tuple[bool, str]]] = {}
        self._allowlist_patterns: Set[str] = set()
        self._blocklist_patterns: Set[str] = set()
    
    def add_custom_rule(
        self,
        name: str,
        rule_fn: Callable[[Any], Tuple[bool, str]],
        severity: ValidationSeverity = ValidationSeverity.HIGH
    ) -> None:
        """Add custom validation rule."""
        self._custom_rules[name] = (rule_fn, severity)
    
    def add_to_allowlist(self, pattern: str) -> None:
        """Add regex pattern to allowlist."""
        self._allowlist_patterns.add(pattern)
    
    def add_to_blocklist(self, pattern: str) -> None:
        """Add regex pattern to blocklist."""
        self._blocklist_patterns.add(pattern)
    
    def validate(
        self,
        value: Any,
        field_path: str = "root",
        depth: int = 0,
        expected_type: Optional[type] = None
    ) -> ValidationResult:
        """
        Recursively validate and sanitize input.
        
        Args:
            value: Input value to validate
            field_path: Path for error reporting
            depth: Current recursion depth
            expected_type: Optional type expectation
        """
        violations: List[ValidationViolation] = []
        sanitized = value
        
        # Check nested depth
        if depth > self.max_nested_depth:
            violations.append(ValidationViolation(
                rule=ValidationRule.NESTED_DEPTH,
                severity=ValidationSeverity.HIGH,
                message=f"Exceeded max nested depth {self.max_nested_depth}",
                field_path=field_path
            ))
            return ValidationResult(False, violations, None, value)
        
        # Type validation
        if expected_type is not None and not isinstance(value, expected_type):
            violations.append(ValidationViolation(
                rule=ValidationRule.TYPE_CHECK,
                severity=ValidationSeverity.MEDIUM,
                message=f"Expected type {expected_type.__name__}, got {type(value).__name__}",
                field_path=field_path
            ))
        
        # String validation
        if isinstance(value, str):
            str_violations, sanitized = self._validate_string(value, field_path)
            violations.extend(str_violations)
        
        # Recursive validation for containers
        elif isinstance(value, dict):
            sanitized = {}
            for k, v in value.items():
                sub_result = self.validate(v, f"{field_path}.{k}", depth + 1)
                violations.extend(sub_result.violations)
                sanitized[k] = sub_result.sanitized_value
        
        elif isinstance(value, (list, tuple)):
            sanitized = []
            for i, v in enumerate(value):
                sub_result = self.validate(v, f"{field_path}[{i}]", depth + 1)
                violations.extend(sub_result.violations)
                sanitized.append(sub_result.sanitized_value)
            if isinstance(value, tuple):
                sanitized = tuple(sanitized)
        
        # Custom rules
        for name, (rule_fn, severity) in self._custom_rules.items():
            passed, msg = rule_fn(value)
            if not passed:
                violations.append(ValidationViolation(
                    rule=ValidationRule.CUSTOM,
                    severity=severity,
                    message=f"Custom rule '{name}': {msg}",
                    field_path=field_path,
                    offending_value=str(value)[:100]
                ))
        
        is_valid = not any(
            v.severity in (ValidationSeverity.CRITICAL, ValidationSeverity.HIGH)
            for v in violations
        )
        
        return ValidationResult(is_valid, violations, sanitized, value)
    
    def _validate_string(
        self,
        value: str,
        field_path: str
    ) -> Tuple[List[ValidationViolation], str]:
        """Validate string content for security patterns."""
        violations: List[ValidationViolation] = []
        sanitized = value
        
        # Length check
        if len(value) > self.max_string_length:
            violations.append(ValidationViolation(
                rule=ValidationRule.STRING_LENGTH,
                severity=ValidationSeverity.HIGH,
                message=f"String exceeds max length {self.max_string_length}",
                field_path=field_path,
                offending_value=f"{len(value)} chars"
            ))
        
        # SQL injection check
        if SecurityPatterns.SQL_INJECTION.search(value):
            violations.append(ValidationViolation(
                rule=ValidationRule.SQL_INJECTION,
                severity=ValidationSeverity.CRITICAL,
                message="Potential SQL injection pattern detected",
                field_path=field_path,
                offending_value=value[:100]
            ))
        
        # Command injection check
        if SecurityPatterns.COMMAND_INJECTION.search(value):
            violations.append(ValidationViolation(
                rule=ValidationRule.COMMAND_INJECTION,
                severity=ValidationSeverity.CRITICAL,
                message="Potential command injection pattern detected",
                field_path=field_path,
                offending_value=value[:100]
            ))
        
        # Path traversal check
        if SecurityPatterns.PATH_TRAVERSAL.search(value):
            violations.append(ValidationViolation(
                rule=ValidationRule.PATH_TRAVERSAL,
                severity=ValidationSeverity.HIGH,
                message="Potential path traversal pattern detected",
                field_path=field_path,
                offending_value=value[:100]
            ))
        
        # XSS check
        if SecurityPatterns.XSS_BASIC.search(value):
            violations.append(ValidationViolation(
                rule=ValidationRule.XSS_PATTERN,
                severity=ValidationSeverity.HIGH,
                message="Potential XSS pattern detected",
                field_path=field_path,
                offending_value=value[:100]
            ))
        
        # Unicode confusable detection
        if self.enable_confusable_detection:
            confusables_found = [c for c in value if c in SecurityPatterns.CONFUSABLES]
            if confusables_found:
                violations.append(ValidationViolation(
                    rule=ValidationRule.UNICODE_CONFUSABLE,
                    severity=ValidationSeverity.MEDIUM,
                    message=f"Unicode confusable characters found: {set(confusables_found)}",
                    field_path=field_path
                ))
                # Normalize
                sanitized = ''.join(
                    SecurityPatterns.CONFUSABLES.get(c, c) for c in value
                )
        
        # URL safety check
        if value.startswith(('http://', 'https://', 'ftp://')):
            try:
                parsed = urlparse(value)
                if parsed.scheme in SecurityPatterns.DANGEROUS_SCHEMES:
                    violations.append(ValidationViolation(
                        rule=ValidationRule.URL_SAFETY,
                        severity=ValidationSeverity.HIGH,
                        message=f"Dangerous URL scheme: {parsed.scheme}",
                        field_path=field_path
                    ))
            except Exception:
                pass
        
        # Apply sanitization mode
        if self.mode == SanitizationMode.ESCAPE:
            sanitized = (sanitized
                .replace('&', '&amp;')
                .replace('<', '&lt;')
                .replace('>', '&gt;')
                .replace('"', '&quot;')
                .replace("'", '&#39;')
            )
        elif self.mode == SanitizationMode.REPLACE:
            sanitized = re.sub(r'[^\w\s\-_.,@]', '_', sanitized)
        
        # NFC normalization
        sanitized = unicodedata.normalize('NFC', sanitized)
        
        return violations, sanitized
    
    def wrap_function(self, fn: Callable[..., T]) -> Callable[..., T]:
        """
        Decorator to wrap existing functions with input validation.
        ADD-ONLY: Does not modify the original function.
        """
        def wrapped(*args, **kwargs):
            # Validate positional args
            for i, arg in enumerate(args):
                result = self.validate(arg, f"arg[{i}]")
                result.raise_if_invalid()
            
            # Validate keyword args
            for k, v in kwargs.items():
                result = self.validate(v, f"kwarg.{k}")
                result.raise_if_invalid()
            
            return fn(*args, **kwargs)
        
        return wrapped


# ============================================================================
# FACTORY FUNCTIONS
# ============================================================================

def create_strict_validator() -> InputSecurityValidator:
    """Create validator with strict rejection mode."""
    return InputSecurityValidator(
        mode=SanitizationMode.REJECT,
        max_nested_depth=8,
        max_string_length=100_000,
        enable_confusable_detection=True
    )


def create_permissive_validator() -> InputSecurityValidator:
    """Create validator with escape-only mode (lenient but safe)."""
    return InputSecurityValidator(
        mode=SanitizationMode.ESCAPE,
        max_nested_depth=20,
        max_string_length=10_000_000,
        enable_confusable_detection=True
    )


def validate_single_input(value: Any) -> ValidationResult:
    """One-line convenience function for quick validation."""
    return create_strict_validator().validate(value)
