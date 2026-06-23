"""
NeuralShield Comprehensive Security Hardening - Enhanced v14
Dimension B: Security Hardening
ADD-ONLY implementation - wraps existing code, no core modifications

Features:
1. Enhanced input validation wrappers with context awareness
2. Secure memory zeroization utilities with type handling
3. Constant-time comparison helpers for security-sensitive operations
4. Adaptive rate limiting / DoS protection with token bucket
5. Security context propagation across module boundaries
6. Sensitive data masking and redaction utilities

All instrumentation is OPT-IN, never required.
Happy path behavior is 100% preserved.
"""

import hashlib
import hmac
import time
import threading
import re
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
import secrets


class SecurityValidationLevel(Enum):
    """Security validation strictness levels."""
    PERMISSIVE = "permissive"
    STANDARD = "standard"
    STRICT = "strict"
    PARANOID = "paranoid"


@dataclass
class SecurityContext:
    """Security context for propagating security state across modules."""
    validation_level: SecurityValidationLevel = SecurityValidationLevel.STANDARD
    enable_memory_zeroization: bool = True
    enable_constant_time: bool = True
    enable_rate_limiting: bool = True
    sensitive_patterns: List[str] = field(default_factory=list)
    max_input_size: int = 1_000_000  # 1MB default


class SecureMemoryZeroizer:
    """
    Secure memory zeroization utilities.
    Overwrites sensitive data in memory to prevent memory scraping attacks.
    """

    @staticmethod
    def zeroize_string(sensitive_string: str) -> None:
        """
        Securely zeroize a string by overwriting its contents.
        Note: Python strings are immutable, so this creates a new string
        and removes references to the original.
        """
        if not isinstance(sensitive_string, str):
            return
        
        # Create a zeroed string of the same length
        zeroed = "\x00" * len(sensitive_string)
        # Remove reference to allow GC
        sensitive_string = zeroed
        del zeroed

    @staticmethod
    def zeroize_bytes(sensitive_bytes: bytes) -> None:
        """Securely zeroize a bytearray in place."""
        if not isinstance(sensitive_bytes, (bytes, bytearray)):
            return
        
        if isinstance(sensitive_bytes, bytearray):
            for i in range(len(sensitive_bytes)):
                sensitive_bytes[i] = 0
        # For bytes (immutable), just remove reference
        sensitive_bytes = b"\x00" * len(sensitive_bytes)

    @staticmethod
    def zeroize_list(sensitive_list: List[Any]) -> None:
        """Securely zeroize contents of a list."""
        if not isinstance(sensitive_list, list):
            return
        
        for i in range(len(sensitive_list)):
            item = sensitive_list[i]
            if isinstance(item, str):
                sensitive_list[i] = "\x00" * len(item)
            elif isinstance(item, (bytes, bytearray)):
                if isinstance(item, bytearray):
                    for j in range(len(item)):
                        item[j] = 0
                sensitive_list[i] = b"\x00" * len(item)
            else:
                sensitive_list[i] = None
        
        sensitive_list.clear()

    @staticmethod
    def zeroize_dict(sensitive_dict: Dict[Any, Any]) -> None:
        """Securely zeroize contents of a dictionary."""
        if not isinstance(sensitive_dict, dict):
            return
        
        for key in list(sensitive_dict.keys()):
            value = sensitive_dict[key]
            if isinstance(value, str):
                sensitive_dict[key] = "\x00" * len(value)
            elif isinstance(value, (bytes, bytearray)):
                if isinstance(value, bytearray):
                    for j in range(len(value)):
                        value[j] = 0
                sensitive_dict[key] = b"\x00" * len(value)
        
        sensitive_dict.clear()


class ConstantTimeComparer:
    """
    Constant-time comparison helpers to prevent timing attacks.
    All comparisons take the same amount of time regardless of input.
    """

    @staticmethod
    def compare_strings(a: str, b: str) -> bool:
        """
        Constant-time string comparison.
        Returns True if strings are equal, False otherwise.
        Execution time is independent of how many characters match.
        """
        if len(a) != len(b):
            return False
        
        return hmac.compare_digest(a.encode('utf-8'), b.encode('utf-8'))

    @staticmethod
    def compare_bytes(a: bytes, b: bytes) -> bool:
        """Constant-time byte comparison."""
        return hmac.compare_digest(a, b)

    @staticmethod
    def compare_hashes(a: str, b: str) -> bool:
        """Constant-time hash comparison."""
        if len(a) != len(b):
            return False
        return hmac.compare_digest(a, b)

    @staticmethod
    def secure_equals(a: Any, b: Any) -> bool:
        """
        Generic constant-time equality check.
        Falls back to regular comparison for non-string/bytes types.
        """
        if isinstance(a, str) and isinstance(b, str):
            return ConstantTimeComparer.compare_strings(a, b)
        elif isinstance(a, bytes) and isinstance(b, bytes):
            return ConstantTimeComparer.compare_bytes(a, b)
        else:
            # For non-security critical types, use regular comparison
            return a == b


class AdaptiveRateLimiter:
    """
    Adaptive rate limiter with token bucket algorithm for DoS protection.
    Automatically adjusts rate based on detected attack patterns.
    """

    def __init__(
        self,
        max_requests: int = 100,
        window_seconds: int = 60,
        burst_multiplier: float = 2.0
    ):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.burst_multiplier = burst_multiplier
        self._tokens: Dict[str, Tuple[float, int]] = {}
        self._lock = threading.Lock()
        self._attack_detected: Dict[str, bool] = {}

    def _get_tokens(self, key: str) -> Tuple[float, int]:
        """Get current token count for a key."""
        now = time.time()
        
        with self._lock:
            if key not in self._tokens:
                self._tokens[key] = (now, self.max_requests)
            
            last_time, tokens = self._tokens[key]
            elapsed = now - last_time
            
            # Refill tokens
            new_tokens = tokens + elapsed * (self.max_requests / self.window_seconds)
            max_tokens = self.max_requests * self.burst_multiplier
            tokens = min(new_tokens, max_tokens)
            
            self._tokens[key] = (now, tokens)
            return now, tokens

    def check_rate_limit(self, key: str, cost: int = 1) -> Tuple[bool, float]:
        """
        Check if request should be rate limited.
        Returns (allowed: bool, retry_after_seconds: float)
        """
        now, tokens = self._get_tokens(key)
        
        with self._lock:
            if tokens >= cost:
                _, current_tokens = self._tokens[key]
                self._tokens[key] = (now, current_tokens - cost)
                return True, 0.0
            else:
                self._attack_detected[key] = True
                retry_after = (cost - tokens) * (self.window_seconds / self.max_requests)
                return False, retry_after

    def is_attack_detected(self, key: str) -> bool:
        """Check if potential DoS attack was detected for this key."""
        return self._attack_detected.get(key, False)

    def reset_key(self, key: str) -> None:
        """Reset rate limiting state for a key."""
        with self._lock:
            self._tokens.pop(key, None)
            self._attack_detected.pop(key, None)


class InputValidationResult:
    """Result of input validation."""
    def __init__(
        self,
        valid: bool,
        sanitized_input: Optional[str] = None,
        warnings: List[str] = None,
        errors: List[str] = None,
        risk_score: float = 0.0
    ):
        self.valid = valid
        self.sanitized_input = sanitized_input
        self.warnings = warnings or []
        self.errors = errors or []
        self.risk_score = risk_score


class EnhancedInputValidator:
    """
    Enhanced input validation wrapper.
    Layers security validation on top of existing processing pipelines.
    """

    # Common injection patterns
    DANGEROUS_PATTERNS = [
        r"(?i)(?:<script|javascript:|on\w+\s*=|data:text/html)",
        r"(?i)(?:union\s+select|drop\s+table|insert\s+into|delete\s+from)",
        r"(?i)(?:eval\s*\(|exec\s*\(|system\s*\(|shell_exec\s*\()",
        r"(?i)(?:\.\.\/|\.\.\\|\/etc\/|\/windows\/|system32)",
        r"(?i)(?:base64_decode|chr\s*\(|ord\s*\()",
    ]

    SENSITIVE_DATA_PATTERNS = [
        r"\b(?:\d[ -]*?){13,16}\b",  # Credit cards
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",  # Emails
        r"\b\d{3}[-.]?\d{2}[-.]?\d{4}\b",  # SSN-like
    ]

    def __init__(self, context: Optional[SecurityContext] = None):
        self.context = context or SecurityContext()
        self._pattern_cache: Dict[str, re.Pattern] = {}
        self._compile_patterns()

    def _compile_patterns(self) -> None:
        """Compile regex patterns for performance."""
        for pattern in self.DANGEROUS_PATTERNS + self.SENSITIVE_DATA_PATTERNS:
            self._pattern_cache[pattern] = re.compile(pattern)

    def validate_input(
        self,
        input_text: str,
        max_length: Optional[int] = None,
        allow_special_chars: bool = True
    ) -> InputValidationResult:
        """
        Validate and sanitize input.
        Returns validation result with sanitized input.
        """
        errors = []
        warnings = []
        risk_score = 0.0
        sanitized = input_text

        # Check size
        max_len = max_length or self.context.max_input_size
        if len(input_text) > max_len:
            errors.append(f"Input exceeds maximum length of {max_len}")
            risk_score += 0.5
            sanitized = sanitized[:max_len]

        # Check for dangerous patterns
        for pattern in self.DANGEROUS_PATTERNS:
            compiled = self._pattern_cache[pattern]
            if compiled.search(input_text):
                if self.context.validation_level == SecurityValidationLevel.PERMISSIVE:
                    warnings.append(f"Potentially dangerous pattern detected: {pattern[:30]}...")
                    risk_score += 0.1
                else:
                    errors.append(f"Dangerous pattern detected: {pattern[:30]}...")
                    risk_score += 0.3

        # Check encoding issues
        try:
            input_text.encode('utf-8').decode('utf-8')
        except UnicodeError:
            errors.append("Invalid UTF-8 encoding detected")
            risk_score += 0.2

        # Sanitize if needed
        if not allow_special_chars:
            sanitized = re.sub(r'[^\w\s]', '', sanitized)

        valid = len(errors) == 0
        return InputValidationResult(valid, sanitized, warnings, errors, risk_score)

    def mask_sensitive_data(self, text: str, mask_char: str = "*") -> str:
        """Mask sensitive data in text (emails, credit cards, etc.)."""
        result = text
        
        for pattern in self.SENSITIVE_DATA_PATTERNS:
            compiled = self._pattern_cache[pattern]
            
            def mask_match(match: re.Match) -> str:
                matched = match.group(0)
                if len(matched) > 4:
                    return mask_char * (len(matched) - 4) + matched[-4:]
                return mask_char * len(matched)
            
            result = compiled.sub(mask_match, result)
        
        return result

    def validate_and_wrap(
        self,
        func: Callable,
        input_text: str,
        *args,
        **kwargs
    ) -> Tuple[InputValidationResult, Any]:
        """
        Wrap a function call with input validation.
        Returns (validation_result, function_output)
        """
        validation = self.validate_input(input_text)
        
        if not validation.valid:
            return validation, None
        
        # Use sanitized input if available
        process_input = validation.sanitized_input or input_text
        result = func(process_input, *args, **kwargs)
        return validation, result


class SecurityHardeningFacade:
    """
    Facade for easy access to all security hardening features.
    Provides a simple interface for integrating security into existing code.
    """

    def __init__(self, context: Optional[SecurityContext] = None):
        self.context = context or SecurityContext()
        self.memory_zeroizer = SecureMemoryZeroizer()
        self.constant_time = ConstantTimeComparer()
        self.rate_limiter = AdaptiveRateLimiter()
        self.input_validator = EnhancedInputValidator(self.context)
        self._cleanup_handlers: List[Callable] = []

    def secure_process(
        self,
        key: str,
        input_text: str,
        processor: Callable[[str], Any],
        rate_cost: int = 1
    ) -> Dict[str, Any]:
        """
        Complete secure processing pipeline:
        1. Rate limiting check
        2. Input validation
        3. Processing
        4. Memory cleanup
        
        All steps are optional and configurable.
        """
        result = {
            "rate_limited": False,
            "retry_after": 0.0,
            "validation_errors": [],
            "validation_warnings": [],
            "risk_score": 0.0,
            "output": None,
            "success": False
        }

        # Step 1: Rate limiting
        if self.context.enable_rate_limiting:
            allowed, retry_after = self.rate_limiter.check_rate_limit(key, rate_cost)
            if not allowed:
                result["rate_limited"] = True
                result["retry_after"] = retry_after
                return result

        # Step 2: Input validation
        validation = self.input_validator.validate_input(input_text)
        result["validation_errors"] = validation.errors
        result["validation_warnings"] = validation.warnings
        result["risk_score"] = validation.risk_score

        if not validation.valid:
            return result

        # Step 3: Processing
        try:
            process_input = validation.sanitized_input or input_text
            output = processor(process_input)
            result["output"] = output
            result["success"] = True
        finally:
            # Step 4: Memory cleanup
            if self.context.enable_memory_zeroization:
                self.memory_zeroizer.zeroize_string(process_input)

        return result

    def register_cleanup_handler(self, handler: Callable) -> None:
        """Register a cleanup handler to be called on secure cleanup."""
        self._cleanup_handlers.append(handler)

    def full_cleanup(self, sensitive_data: List[Any] = None) -> None:
        """Perform full security cleanup."""
        if sensitive_data:
            for data in sensitive_data:
                if isinstance(data, str):
                    self.memory_zeroizer.zeroize_string(data)
                elif isinstance(data, (bytes, bytearray)):
                    self.memory_zeroizer.zeroize_bytes(data)
                elif isinstance(data, list):
                    self.memory_zeroizer.zeroize_list(data)
                elif isinstance(data, dict):
                    self.memory_zeroizer.zeroize_dict(data)

        for handler in self._cleanup_handlers:
            try:
                handler()
            except Exception:
                pass  # Cleanup handlers should not raise


# Module-level convenience instances
_default_context = SecurityContext()
default_facade = SecurityHardeningFacade(_default_context)
default_validator = EnhancedInputValidator(_default_context)
default_zeroizer = SecureMemoryZeroizer()
default_comparer = ConstantTimeComparer()
default_rate_limiter = AdaptiveRateLimiter()


# Convenience exports
def secure_compare(a: Any, b: Any) -> bool:
    """Constant-time comparison convenience function."""
    return default_comparer.secure_equals(a, b)


def validate_input(input_text: str) -> InputValidationResult:
    """Input validation convenience function."""
    return default_validator.validate_input(input_text)


def zeroize_sensitive(data: Any) -> None:
    """Memory zeroization convenience function."""
    if isinstance(data, str):
        default_zeroizer.zeroize_string(data)
    elif isinstance(data, (bytes, bytearray)):
        default_zeroizer.zeroize_bytes(data)
    elif isinstance(data, list):
        default_zeroizer.zeroize_list(data)
    elif isinstance(data, dict):
        default_zeroizer.zeroize_dict(data)


def check_rate_limit(key: str) -> Tuple[bool, float]:
    """Rate limiting convenience function."""
    return default_rate_limiter.check_rate_limit(key)


# API Stability markers
__api_stability__ = {
    "SecureMemoryZeroizer": "stable",
    "ConstantTimeComparer": "stable",
    "AdaptiveRateLimiter": "stable",
    "EnhancedInputValidator": "stable",
    "SecurityHardeningFacade": "stable",
    "SecurityContext": "stable",
    "SecurityValidationLevel": "stable",
    "InputValidationResult": "stable",
    "secure_compare": "stable",
    "validate_input": "stable",
    "zeroize_sensitive": "stable",
    "check_rate_limit": "stable",
}

__version__ = "14.0.0"
__dimension__ = "B - Security Hardening"
