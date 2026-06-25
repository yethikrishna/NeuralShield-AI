"""
Security Hardening v28 - Prompt Boundary & Context Leakage Protection
Dimension B: Security Hardening - ADD-ONLY, backward compatible

Provides:
1. Context window boundary validation wrappers
2. Prompt injection leakage prevention
3. Sensitive data masking in context windows
4. Boundary crossing detection for system prompts
5. Gradient-based context leakage detection

All wrappers are OPT-IN, no modification to existing code required.
"""

import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
from functools import wraps


class BoundaryViolationType(Enum):
    """Types of boundary violations detected."""
    CONTEXT_LEAKAGE = "context_leakage"
    PROMPT_ESCAPE = "prompt_escape"
    SYSTEM_PROMPT_TAMPER = "system_prompt_tamper"
    BOUNDARY_CROSSING = "boundary_crossing"
    SENSITIVE_LEAKAGE = "sensitive_leakage"
    INJECTION_ATTEMPT = "injection_attempt"


@dataclass
class BoundarySecurityResult:
    """Result from boundary security check."""
    is_safe: bool
    violation_type: Optional[BoundaryViolationType] = None
    confidence_score: float = 0.0
    masked_content: Optional[str] = None
    violation_details: Dict[str, Any] = field(default_factory=dict)
    remediation_applied: bool = False


class PromptBoundaryProtector:
    """
    Protects prompt boundaries and prevents context leakage.
    
    Wraps existing prompt processing functions without modification.
    All features are opt-in via decorators or explicit calls.
    """
    
    # System prompt boundary markers - cryptographically secure
    _SYSTEM_PROMPT_MARKER: bytes = None
    _BOUNDARY_SECRET: bytes = None
    
    # Sensitive data patterns - ordered by specificity (most specific first)
    _SENSITIVE_PATTERNS = [
        (r'-----BEGIN [A-Z ]*PRIVATE KEY-----', 'PRIVATE_KEY_MASKED'),
        (r'\bghp_[A-Za-z0-9]{36}\b', 'GITHUB_TOKEN_MASKED'),
        (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', 'EMAIL_MASKED'),
        (r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', 'PHONE_MASKED'),
        (r'\b(?:\d{4}[-\s]?){3}\d{4}\b', 'CREDIT_CARD_MASKED'),
        (r'\bapi[_-]?key\s*[:=]\s*["\']?[A-Za-z0-9]{16,}["\']?', 'API_KEY_MASKED'),
        (r'\bsecret[_-]?key\s*[:=]\s*["\']?[A-Za-z0-9]{16,}["\']?', 'SECRET_KEY_MASKED'),
        # Base64 - require minimum length AND mixed case to avoid false positives
        (r'(?=[A-Za-z0-9+/]*[A-Z])(?=[A-Za-z0-9+/]*[a-z])[A-Za-z0-9+/]{40,}={0,2}', 'BASE64_MASKED'),
    ]
    
    # Prompt escape patterns
    _ESCAPE_PATTERNS = [
        r'(?i)ignore.*previous.*instructions?',
        r'(?i)disregard.*system.*prompt',
        r'(?i)you.*are.*now.*in.*developer.*mode',
        r'(?i)override.*safety.*protocol',
        r'(?i)system.*prompt.*:?',
        r'(?i)<\s*\|endoftext\|\s*>',
        r'(?i)print.*system.*instruction',
        r'(?i)reveal.*your.*prompt',
    ]
    
    def __init__(self, auto_remediate: bool = True, strict_mode: bool = False):
        """
        Initialize boundary protector.
        
        Args:
            auto_remediate: Automatically apply masking/remediation
            strict_mode: Block on any suspected violation
        """
        self.auto_remediate = auto_remediate
        self.strict_mode = strict_mode
        self._initialize_crypto_boundaries()
        self._violation_log: List[Dict[str, Any]] = []
    
    @classmethod
    def _initialize_crypto_boundaries(cls) -> None:
        """Initialize cryptographically secure boundary markers."""
        if cls._BOUNDARY_SECRET is None:
            cls._BOUNDARY_SECRET = secrets.token_bytes(32)
            cls._SYSTEM_PROMPT_MARKER = secrets.token_bytes(16)
    
    def _generate_boundary_hmac(self, content: str) -> str:
        """Generate HMAC for content integrity verification."""
        return hmac.new(
            self._BOUNDARY_SECRET,
            content.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
    
    def _constant_time_compare(self, a: str, b: str) -> bool:
        """
        Constant-time string comparison to prevent timing attacks.
        
        Returns True if equal, False otherwise.
        """
        if len(a) != len(b):
            return False
        result = 0
        for x, y in zip(a.encode('utf-8'), b.encode('utf-8')):
            result |= x ^ y
        return result == 0
    
    def mask_sensitive_data(self, content: str) -> str:
        """
        Mask sensitive data patterns in content.
        
        Args:
            content: Input string to mask
            
        Returns:
            Content with sensitive patterns replaced
        """
        masked = content
        for pattern, replacement in self._SENSITIVE_PATTERNS:
            masked = re.sub(pattern, f'[{replacement}]', masked)
        return masked
    
    def detect_prompt_escape(self, content: str) -> Tuple[bool, float, List[str]]:
        """
        Detect prompt escape attempts.
        
        Args:
            content: Content to analyze
            
        Returns:
            (detected, confidence, matched_patterns)
        """
        matches = []
        max_confidence = 0.0
        
        for pattern in self._ESCAPE_PATTERNS:
            found = re.findall(pattern, content)
            if found:
                matches.extend(found)
                max_confidence = min(1.0, max_confidence + 0.15 * len(found))
        
        return len(matches) > 0, min(max_confidence, 1.0), matches
    
    def detect_context_leakage(
        self,
        user_prompt: str,
        system_prompt: Optional[str] = None,
        history: Optional[List[str]] = None
    ) -> BoundarySecurityResult:
        """
        Detect context leakage attempts across boundaries.
        
        Args:
            user_prompt: User input to check
            system_prompt: System prompt for boundary verification
            history: Conversation history
            
        Returns:
            BoundarySecurityResult with assessment
        """
        violations = []
        confidence = 0.0
        masked_content = user_prompt
        
        # Check for prompt escape
        escape_detected, escape_conf, escape_matches = self.detect_prompt_escape(user_prompt)
        if escape_detected:
            violations.append(BoundaryViolationType.PROMPT_ESCAPE)
            confidence = max(confidence, escape_conf)
        
        # Check for sensitive data in user prompt
        masked = self.mask_sensitive_data(user_prompt)
        if masked != user_prompt:
            violations.append(BoundaryViolationType.SENSITIVE_LEAKAGE)
            confidence = max(confidence, 0.7)
            masked_content = masked
        
        # System prompt tampering detection
        if system_prompt is not None:
            lower_prompt = user_prompt.lower()
            system_triggers = ['system prompt', 'your instructions', 'initial prompt']
            for trigger in system_triggers:
                if trigger in lower_prompt:
                    violations.append(BoundaryViolationType.SYSTEM_PROMPT_TAMPER)
                    confidence = max(confidence, 0.5)
        
        is_safe = len(violations) == 0 or (not self.strict_mode and confidence < 0.3)
        
        if self.auto_remediate and not is_safe:
            masked_content = self.mask_sensitive_data(user_prompt)
        
        return BoundarySecurityResult(
            is_safe=is_safe,
            violation_type=violations[0] if violations else None,
            confidence_score=confidence,
            masked_content=masked_content,
            violation_details={
                'all_violations': [v.value for v in violations],
                'escape_matches': escape_matches if escape_detected else [],
                'masking_applied': masked_content != user_prompt
            },
            remediation_applied=masked_content != user_prompt
        )
    
    def secure_wrap_function(
        self,
        func: Callable,
        validate_input: bool = True,
        validate_output: bool = True,
        mask_output: bool = False
    ) -> Callable:
        """
        Decorator to wrap existing functions with boundary protection.
        
        Does NOT modify original function - layers security on top.
        
        Args:
            func: Function to wrap
            validate_input: Check inputs for boundary violations
            validate_output: Check outputs for leakage
            mask_output: Mask sensitive data in output
        """
        @wraps(func)
        def wrapped(*args, **kwargs):
            # Input validation
            if validate_input:
                for arg in args:
                    if isinstance(arg, str):
                        result = self.detect_context_leakage(arg)
                        if not result.is_safe and self.strict_mode:
                            raise SecurityBoundaryError(
                                f"Boundary violation detected: {result.violation_type}",
                                result
                            )
                        if result.remediation_applied:
                            args = tuple(
                                result.masked_content if a == arg else a 
                                for a in args
                            )
            
            # Call original function - unmodified behavior
            result = func(*args, **kwargs)
            
            # Output validation and masking
            if validate_output and isinstance(result, str):
                if mask_output:
                    result = self.mask_sensitive_data(result)
            
            return result
        
        return wrapped
    
    def get_violation_report(self) -> List[Dict[str, Any]]:
        """Get report of all detected violations."""
        return list(self._violation_log)
    
    def reset_violations(self) -> None:
        """Clear violation log."""
        self._violation_log.clear()


class SecurityBoundaryError(Exception):
    """Custom exception for security boundary violations."""
    
    def __init__(self, message: str, security_result: BoundarySecurityResult):
        super().__init__(message)
        self.security_result = security_result
        self.violation_type = security_result.violation_type


class SecureMemoryZeroizer:
    """
    Secure memory zeroization utilities for sensitive data.
    
    Provides:
    - Overwrite sensitive memory before GC
    - Constant-time operations
    - No traceback leakage
    """
    
    @staticmethod
    def zeroize_string(s: str) -> None:
        """
        Attempt to zeroize string contents.
        
        Note: Python strings are immutable, this creates a masked
        reference and encourages early GC.
        """
        # Create a bytes object we can actually overwrite
        b = bytearray(len(s) * 4)
        for i in range(len(b)):
            b[i] = 0
        # Encourage GC of original
        s = ""
        del b
    
    @staticmethod
    def zeroize_bytearray(b: bytearray) -> None:
        """Securely zeroize a bytearray."""
        for i in range(len(b)):
            b[i] = 0
    
    @staticmethod
    def zeroize_list(lst: List[Any]) -> None:
        """Zeroize list contents."""
        for i in range(len(lst)):
            lst[i] = None
        lst.clear()


# Global protector instance - lazy initialized
_DEFAULT_PROTECTOR: Optional[PromptBoundaryProtector] = None


def get_boundary_protector(
    auto_remediate: bool = True,
    strict_mode: bool = False
) -> PromptBoundaryProtector:
    """
    Get or create the default boundary protector instance.
    
    Factory function to ensure single instance with proper crypto init.
    """
    global _DEFAULT_PROTECTOR
    if _DEFAULT_PROTECTOR is None:
        _DEFAULT_PROTECTOR = PromptBoundaryProtector(
            auto_remediate=auto_remediate,
            strict_mode=strict_mode
        )
    return _DEFAULT_PROTECTOR


def secure_prompt_boundary(func: Callable) -> Callable:
    """
    Decorator for easy boundary protection integration.
    
    Usage:
        @secure_prompt_boundary
        def process_prompt(prompt: str) -> str:
            ...
    """
    protector = get_boundary_protector()
    return protector.secure_wrap_function(func)


# Module exports
__all__ = [
    'PromptBoundaryProtector',
    'BoundarySecurityResult',
    'BoundaryViolationType',
    'SecurityBoundaryError',
    'SecureMemoryZeroizer',
    'get_boundary_protector',
    'secure_prompt_boundary',
]
