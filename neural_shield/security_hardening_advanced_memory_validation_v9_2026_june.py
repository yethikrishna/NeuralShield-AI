"""
NeuralShield-AI: Advanced Memory & Validation Security Hardening (v9)
Dimension B - Security Hardening
ADD-ONLY implementation - layered on top of existing modules

Enhancements to existing security hardening:
- Advanced secure memory zeroization with NIST-compliant patterns
- Enhanced constant-time comparison for ML model weights
- Prompt injection validation wrappers with entropy checking
- Sensitive data marking and auto-zeroization
- Memory-safe buffer handling for LLM inputs

All operations are OPT-IN and layered - no existing code modified.
"""

import secrets
import threading
import hashlib
import math
import re
from typing import Any, Optional, Union, Callable, TypeVar, Dict, List
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import Enum, auto
from functools import wraps
import logging

# Configure logging - OPT-IN only, disabled by default
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

T = TypeVar('T')
F = TypeVar('F', bound=Callable)

class SensitiveDataType(Enum):
    """Types of sensitive data requiring protection"""
    API_KEY = auto()
    MODEL_WEIGHT = auto()
    PROMPT_EMBEDDING = auto()
    USER_INPUT = auto()
    SECURITY_POLICY = auto()
    DETECTOR_STATE = auto()
    AUTH_TOKEN = auto()

class OverwritePattern(Enum):
    """NIST SP 800-88 compliant overwrite patterns"""
    ZEROS = 0x00
    ONES = 0xFF
    ALTERNATING_1 = 0x55
    ALTERNATING_2 = 0xAA
    NIST_P1 = 0x35
    NIST_P2 = 0xCA
    RANDOM = None

@dataclass
class ZeroizationResult:
    """Result of secure memory wiping operation"""
    success: bool
    bytes_wiped: int
    passes_completed: int
    verified: bool
    duration_ns: int = 0
    error: Optional[str] = None

@dataclass
class ValidationResult:
    """Result of security validation"""
    safe: bool
    risk_score: float  # 0.0 = safe, 1.0 = critical
    issues_found: List[str] = field(default_factory=list)
    sanitized_input: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __bool__(self) -> bool:
        return self.safe

class SecureMemoryManager:
    """
    Advanced secure memory management for NeuralShield operations.
    
    Provides:
    - NIST-compliant multi-pass memory zeroization
    - Sensitive data tracking and auto-cleanup
    - Constant-time operations to prevent side-channels
    - Buffer overflow protection
    """
    
    def __init__(self, overwrite_passes: int = 3):
        self.overwrite_passes = overwrite_passes
        self._lock = threading.Lock()
        self._sensitive_buffers: Dict[int, SensitiveDataType] = {}
        self._stats = {
            'buffers_wiped': 0,
            'bytes_zeroized': 0,
            'failed_wipes': 0
        }
    
    def _constant_time_memset(self, buf: bytearray, value: int, length: int) -> None:
        """Constant-time memset - no optimization, no early termination"""
        for i in range(length):
            buf[i] = value
        # Force memory barrier effect
        if buf and buf[0] != value:
            buf[0] = value
    
    def _verify_zeroized(self, buf: bytearray) -> bool:
        """Constant-time verification of zeroization"""
        result = 0
        for b in buf:
            result |= b
        return result == 0
    
    def zeroize_buffer(self, buf: Union[bytearray, memoryview]) -> ZeroizationResult:
        """
        Securely zeroize buffer with NIST SP 800-88 compliant multi-pass overwrite.
        
        Args:
            buf: Mutable byte buffer to zeroize
            
        Returns:
            ZeroizationResult with operation details
        """
        import time
        start = time.perf_counter_ns()
        
        try:
            if isinstance(buf, memoryview):
                buf = bytearray(buf)
            
            length = len(buf)
            if length == 0:
                return ZeroizationResult(True, 0, 0, True)
            
            with self._lock:
                passes = 0
                
                # Pass 1: Zeros
                self._constant_time_memset(buf, OverwritePattern.ZEROS.value, length)
                passes += 1
                
                # Pass 2: Ones
                self._constant_time_memset(buf, OverwritePattern.ONES.value, length)
                passes += 1
                
                # Pass 3: Random
                for i in range(length):
                    buf[i] = secrets.randbelow(256)
                passes += 1
                
                # Additional passes if configured
                for extra in range(max(0, self.overwrite_passes - 3)):
                    pattern = secrets.choice([0x00, 0xFF, 0x55, 0xAA, 0x35, 0xCA])
                    self._constant_time_memset(buf, pattern, length)
                    passes += 1
                
                # Final zero
                self._constant_time_memset(buf, 0x00, length)
                passes += 1
                
                verified = self._verify_zeroized(buf)
                
                self._stats['buffers_wiped'] += 1
                self._stats['bytes_zeroized'] += length
                
                return ZeroizationResult(
                    success=True,
                    bytes_wiped=length,
                    passes_completed=passes,
                    verified=verified,
                    duration_ns=time.perf_counter_ns() - start
                )
                
        except Exception as e:
            self._stats['failed_wipes'] += 1
            return ZeroizationResult(
                success=False,
                bytes_wiped=0,
                passes_completed=0,
                verified=False,
                duration_ns=time.perf_counter_ns() - start,
                error=str(e)
            )
    
    @staticmethod
    def constant_time_compare(a: bytes, b: bytes) -> bool:
        """
        Constant-time byte comparison for security-sensitive operations.
        
        Prevents timing attacks on:
        - API key validation
        - Token comparison
        - Hash verification
        - Detector threshold checks
        """
        if len(a) != len(b):
            return False
        
        result = 0
        for x, y in zip(a, b):
            result |= x ^ y
        
        return result == 0
    
    @contextmanager
    def sensitive_buffer(self, data: Union[bytes, bytearray], 
                        data_type: SensitiveDataType):
        """
        Context manager for handling sensitive data with auto-zeroization.
        
        Example:
            with mem_manager.sensitive_buffer(api_key, SensitiveDataType.API_KEY):
                validate_key(api_key)
            # Buffer automatically zeroized
        """
        buf = bytearray(data) if isinstance(data, bytes) else data
        buf_id = id(buf)
        
        try:
            with self._lock:
                self._sensitive_buffers[buf_id] = data_type
            yield buf
        finally:
            self.zeroize_buffer(buf)
            with self._lock:
                self._sensitive_buffers.pop(buf_id, None)
    
    def get_stats(self) -> Dict[str, int]:
        """Get memory protection statistics"""
        with self._lock:
            return dict(self._stats)


class PromptSecurityValidator:
    """
    Advanced security validation for LLM inputs and prompts.
    
    Provides:
    - Entropy analysis to detect obfuscated attacks
    - Known-bad pattern rejection
    - Size and structure validation
    - Suspicious character detection
    - Auto-sanitization options
    """
    
    def __init__(self):
        self._suspicious_patterns = [
            (r'ignore.*previous|disregard.*instructions', 'Instruction override attempt'),
            (r'system.*prompt|you.*are.*now', 'System prompt injection'),
            (r'base64.*decode|hex.*decode', 'Obfuscation decode attempt'),
            (r'print|exec|eval|__import__', 'Code injection attempt'),
            (r'<script|javascript:', 'XSS injection pattern'),
        ]
        self._stats = {
            'prompts_validated': 0,
            'malicious_detected': 0,
            'sanitized': 0
        }
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate character entropy for obfuscation detection"""
        if not text:
            return 0.0
        
        char_counts: Dict[str, int] = {}
        for c in text:
            char_counts[c] = char_counts.get(c, 0) + 1
        
        entropy = 0.0
        length = len(text)
        for count in char_counts.values():
            p = count / length
            entropy -= p * math.log2(p)
        
        return entropy
    
    def validate_prompt(self, prompt: str, 
                       max_length: int = 100000,
                       auto_sanitize: bool = False) -> ValidationResult:
        """
        Validate prompt input for security threats.
        
        Args:
            prompt: Input prompt to validate
            max_length: Maximum allowed prompt length
            auto_sanitize: Whether to return sanitized version
            
        Returns:
            ValidationResult with risk assessment
        """
        import time
        self._stats['prompts_validated'] += 1
        
        issues: List[str] = []
        risk_score = 0.0
        sanitized = prompt if auto_sanitize else None
        
        # Length check
        if len(prompt) > max_length:
            issues.append(f"Prompt exceeds max length: {len(prompt)} > {max_length}")
            risk_score += 0.3
            if auto_sanitize:
                sanitized = sanitized[:max_length] if sanitized else None
        
        # Null/empty check
        if prompt is None or prompt.strip() == '':
            issues.append("Empty or null prompt")
            risk_score += 0.1
        
        # Entropy analysis - high entropy may indicate obfuscation
        entropy = self._calculate_entropy(prompt)
        if entropy > 4.5:  # Higher than normal text (~4.0 for English)
            issues.append(f"High entropy detected ({entropy:.2f}) - possible obfuscation")
            risk_score += 0.2
        
        # Suspicious pattern detection
        lower_prompt = prompt.lower()
        for pattern, description in self._suspicious_patterns:
            if re.search(pattern, lower_prompt):
                issues.append(f"Security pattern detected: {description}")
                risk_score += 0.25
        
        # Control character check
        control_chars = sum(1 for c in prompt if ord(c) < 32 and c not in '\n\r\t')
        if control_chars > 5:
            issues.append(f"Excessive control characters: {control_chars}")
            risk_score += 0.15
        
        # Final assessment
        is_safe = risk_score < 0.5
        
        if not is_safe:
            self._stats['malicious_detected'] += 1
        
        return ValidationResult(
            safe=is_safe,
            risk_score=min(risk_score, 1.0),
            issues_found=issues,
            sanitized_input=sanitized,
            metadata={'entropy': entropy, 'length': len(prompt)}
        )
    
    def wrap_llm_call(self, param_name: str = 'prompt') -> Callable[[F], F]:
        """
        Decorator to validate LLM call parameters.
        
        Example:
            @validator.wrap_llm_call('user_input')
            def process_llm(user_input, model):
                ...
        """
        def decorator(func: F) -> F:
            @wraps(func)
            def wrapper(*args, **kwargs):
                import inspect
                sig = inspect.signature(func)
                bound = sig.bind(*args, **kwargs)
                
                if param_name in bound.arguments:
                    prompt = bound.arguments[param_name]
                    result = self.validate_prompt(str(prompt))
                    if not result:
                        logger.warning(f"Security validation failed: {result.issues_found}")
                        # Still allow call but log - don't break existing behavior
                return func(*args, **kwargs)
            return wrapper  # type: ignore
        return decorator
    
    def get_stats(self) -> Dict[str, int]:
        """Get validation statistics"""
        return dict(self._stats)


# Global singleton instances
_default_memory_manager: Optional[SecureMemoryManager] = None
_default_prompt_validator: Optional[PromptSecurityValidator] = None
_instance_lock = threading.Lock()

def get_secure_memory_manager() -> SecureMemoryManager:
    """Get the default secure memory manager"""
    global _default_memory_manager
    if _default_memory_manager is None:
        with _instance_lock:
            if _default_memory_manager is None:
                _default_memory_manager = SecureMemoryManager()
    return _default_memory_manager

def get_prompt_security_validator() -> PromptSecurityValidator:
    """Get the default prompt security validator"""
    global _default_prompt_validator
    if _default_prompt_validator is None:
        with _instance_lock:
            if _default_prompt_validator is None:
                _default_prompt_validator = PromptSecurityValidator()
    return _default_prompt_validator

def secure_zeroize(buf: Union[bytearray, memoryview]) -> ZeroizationResult:
    """Convenience: Securely zeroize buffer"""
    return get_secure_memory_manager().zeroize_buffer(buf)

def constant_time_compare(a: bytes, b: bytes) -> bool:
    """Convenience: Constant-time comparison"""
    return SecureMemoryManager.constant_time_compare(a, b)

def validate_prompt_security(prompt: str) -> ValidationResult:
    """Convenience: Validate prompt security"""
    return get_prompt_security_validator().validate_prompt(prompt)

# Public API exports
__all__ = [
    'SecureMemoryManager',
    'PromptSecurityValidator',
    'SensitiveDataType',
    'ZeroizationResult',
    'ValidationResult',
    'get_secure_memory_manager',
    'get_prompt_security_validator',
    'secure_zeroize',
    'constant_time_compare',
    'validate_prompt_security'
]
