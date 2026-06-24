"""
NeuralShield AI - Input Validation Wrappers v23
Dimension B - Security Hardening
Incremental build - ADD-ONLY module, wraps existing functionality

Provides input validation wrappers that layer ON TOP of existing
threat detection modules without modifying core code.

Validates:
- Prompt length and content bounds
- Character encoding safety
- Malicious input patterns
- Rate limiting per client
"""

import re
import time
from dataclasses import dataclass
from typing import Callable, Any, Dict, Optional, List
from functools import wraps
import logging

# Configure logging (opt-in only)
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


@dataclass
class ValidationResult:
    """Result of input validation."""
    is_valid: bool
    error_message: Optional[str] = None
    sanitized_input: Optional[str] = None
    validation_type: str = "general"


class InputValidator:
    """
    Input validation wrapper for security hardening.
    
    Layers ON TOP of existing threat detection - validates input format,
    bounds, and encoding before passing to core detectors.
    
    API Stability: STABLE
    """
    
    # Default validation bounds
    DEFAULT_MAX_PROMPT_LENGTH = 100000  # 100KB
    DEFAULT_MIN_PROMPT_LENGTH = 1
    MAX_CONSECUTIVE_SPECIAL_CHARS = 50
    
    # Suspicious patterns to flag (not block - just validate)
    SUSPICIOUS_PATTERNS = [
        (r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', 'control_characters'),
        (r'%[0-9A-Fa-f]{2}', 'url_encoding'),
        (r'&#[0-9]+;', 'html_entities'),
    ]
    
    def __init__(self, 
                 max_length: Optional[int] = None,
                 min_length: Optional[int] = None,
                 enable_logging: bool = False):
        """
        Initialize input validator.
        
        Args:
            max_length: Maximum allowed input length
            min_length: Minimum allowed input length
            enable_logging: Whether to enable operation logging (opt-in)
        """
        self.max_length = max_length or self.DEFAULT_MAX_PROMPT_LENGTH
        self.min_length = min_length or self.DEFAULT_MIN_PROMPT_LENGTH
        self._logging_enabled = enable_logging
        self._validation_count = 0
        self._rejection_count = 0
    
    def _log(self, message: str) -> None:
        """Conditional logging - only if explicitly enabled."""
        if self._logging_enabled:
            logger.debug(message)
    
    def validate_length(self, prompt: str) -> ValidationResult:
        """Validate prompt length bounds."""
        if not isinstance(prompt, str):
            return ValidationResult(
                is_valid=False,
                error_message="Input must be a string",
                validation_type="type_check"
            )
        
        length = len(prompt)
        
        if length < self.min_length:
            self._rejection_count += 1
            return ValidationResult(
                is_valid=False,
                error_message=f"Input too short: {length} < {self.min_length}",
                validation_type="length_min"
            )
        
        if length > self.max_length:
            self._rejection_count += 1
            return ValidationResult(
                is_valid=False,
                error_message=f"Input too long: {length} > {self.max_length}",
                validation_type="length_max"
            )
        
        return ValidationResult(is_valid=True, validation_type="length")
    
    def validate_encoding(self, prompt: str) -> ValidationResult:
        """Validate character encoding safety."""
        try:
            # Verify valid UTF-8
            prompt.encode('utf-8').decode('utf-8')
            
            # Check for null bytes
            if '\x00' in prompt:
                return ValidationResult(
                    is_valid=False,
                    error_message="Null bytes detected in input",
                    validation_type="encoding"
                )
            
            return ValidationResult(is_valid=True, validation_type="encoding")
            
        except UnicodeError:
            self._rejection_count += 1
            return ValidationResult(
                is_valid=False,
                error_message="Invalid UTF-8 encoding",
                validation_type="encoding"
            )
    
    def validate_special_chars(self, prompt: str) -> ValidationResult:
        """Validate against excessive special characters."""
        # Check for consecutive special characters
        special_count = 0
        max_run = 0
        
        for char in prompt:
            if not char.isalnum() and not char.isspace():
                special_count += 1
                max_run = max(max_run, special_count)
            else:
                special_count = 0
        
        if max_run > self.MAX_CONSECUTIVE_SPECIAL_CHARS:
            self._rejection_count += 1
            return ValidationResult(
                is_valid=False,
                error_message=f"Excessive consecutive special characters: {max_run}",
                validation_type="special_chars"
            )
        
        return ValidationResult(is_valid=True, validation_type="special_chars")
    
    def sanitize_input(self, prompt: str) -> str:
        """Basic input sanitization (preserves content, removes dangerous control chars)."""
        # Remove control characters but preserve printable
        sanitized = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F]', '', prompt)
        return sanitized
    
    def validate_all(self, prompt: str) -> ValidationResult:
        """Run all validations."""
        self._validation_count += 1
        
        # Length check
        length_result = self.validate_length(prompt)
        if not length_result.is_valid:
            return length_result
        
        # Encoding check
        encoding_result = self.validate_encoding(prompt)
        if not encoding_result.is_valid:
            return encoding_result
        
        # Special characters check
        special_result = self.validate_special_chars(prompt)
        if not special_result.is_valid:
            return special_result
        
        # Sanitize
        sanitized = self.sanitize_input(prompt)
        
        self._log(f"Validation passed for input ({len(prompt)} chars)")
        
        return ValidationResult(
            is_valid=True,
            sanitized_input=sanitized,
            validation_type="complete"
        )
    
    def get_validation_stats(self) -> dict:
        """Get validation statistics."""
        return {
            "total_validations": self._validation_count,
            "total_rejections": self._rejection_count,
            "rejection_rate": self._rejection_count / max(1, self._validation_count)
        }


class RateLimiter:
    """
    Token bucket rate limiter for DoS protection.
    
    Prevents abuse by limiting request rate per client identifier.
    Layered ON TOP of existing API endpoints.
    
    API Stability: STABLE
    """
    
    def __init__(self, 
                 max_requests: int = 100,
                 window_seconds: int = 60,
                 enable_logging: bool = False):
        """
        Initialize rate limiter.
        
        Args:
            max_requests: Maximum requests per window
            window_seconds: Time window in seconds
            enable_logging: Whether to enable logging (opt-in)
        """
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._logging_enabled = enable_logging
        
        # Client tracking: {client_id: [timestamps]}
        self._client_requests: Dict[str, List[float]] = {}
    
    def _log(self, message: str) -> None:
        if self._logging_enabled:
            logger.debug(message)
    
    def _cleanup_old_requests(self, client_id: str, current_time: float) -> None:
        """Remove requests outside the current window."""
        cutoff = current_time - self.window_seconds
        if client_id in self._client_requests:
            self._client_requests[client_id] = [
                ts for ts in self._client_requests[client_id]
                if ts > cutoff
            ]
    
    def check_rate_limit(self, client_id: str = "global") -> bool:
        """
        Check if client is within rate limits.
        
        Args:
            client_id: Client identifier (IP, user ID, etc.)
            
        Returns:
            True if allowed, False if rate limited
        """
        now = time.time()
        self._cleanup_old_requests(client_id, now)
        
        if client_id not in self._client_requests:
            self._client_requests[client_id] = []
        
        request_count = len(self._client_requests[client_id])
        
        if request_count >= self.max_requests:
            self._log(f"Rate limit exceeded for {client_id}: {request_count}/{self.max_requests}")
            return False
        
        self._client_requests[client_id].append(now)
        self._log(f"Request allowed for {client_id}: {request_count + 1}/{self.max_requests}")
        return True
    
    def get_remaining_quota(self, client_id: str = "global") -> int:
        """Get remaining requests for client."""
        now = time.time()
        self._cleanup_old_requests(client_id, now)
        count = len(self._client_requests.get(client_id, []))
        return max(0, self.max_requests - count)


def validate_input(validator: Optional[InputValidator] = None):
    """
    Decorator to validate function inputs.
    
    Usage:
        @validate_input()
        def detect_threat(prompt: str, **kwargs):
            ...
    """
    val = validator or InputValidator()
    
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(prompt: str, *args, **kwargs):
            result = val.validate_all(prompt)
            if not result.is_valid:
                raise ValueError(f"Input validation failed: {result.error_message}")
            
            # Use sanitized input if available
            if result.sanitized_input is not None:
                prompt = result.sanitized_input
            
            return func(prompt, *args, **kwargs)
        return wrapper
    return decorator


def rate_limited(limiter: Optional[RateLimiter] = None):
    """
    Decorator to apply rate limiting.
    
    Usage:
        @rate_limited()
        def api_endpoint(request, **kwargs):
            ...
    """
    lim = limiter or RateLimiter()
    
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            client_id = kwargs.get('client_id', 'global')
            if not lim.check_rate_limit(client_id):
                raise RuntimeError("Rate limit exceeded")
            return func(*args, **kwargs)
        return wrapper
    return decorator


# Global instances for easy use
default_validator = InputValidator()
default_rate_limiter = RateLimiter()


def secure_input(prompt: str) -> str:
    """Convenience function for one-shot input validation."""
    result = default_validator.validate_all(prompt)
    if not result.is_valid:
        raise ValueError(f"Input validation failed: {result.error_message}")
    return result.sanitized_input or prompt
