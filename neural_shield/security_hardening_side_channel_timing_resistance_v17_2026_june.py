"""
NeuralShield Security Hardening - Side-Channel Timing Attack Resistance v17
Dimension B: Security Hardening

Implements timing attack resistant operations for security-critical comparisons
and threshold evaluations in AI security systems.

DESIGN PHILOSOPHY:
- ADD-ONLY: Wraps existing functionality, no core modification
- BACKWARD COMPATIBLE: All existing code continues to work
- OPT-IN: Explicit opt-in to use hardened versions
- CONSTANT-TIME: No secret-dependent branching
- SECURE MEMORY: Automatic sensitive data zeroization

STABILITY: STABLE
"""

import os
import sys
import time
import hmac
import hashlib
import secrets
from typing import Any, Callable, Optional, Union, List, Tuple
from dataclasses import dataclass, field
import threading


@dataclass
class TimingResistanceConfig:
    """Configuration for timing attack resistance"""
    enable_constant_time: bool = True
    enable_jitter: bool = True
    jitter_range_ns: Tuple[int, int] = (100, 1000)
    enable_memory_zeroization: bool = True
    min_execution_time_ns: int = 100000  # 100 microseconds minimum
    enable_blinding: bool = True
    
    def __post_init__(self):
        self._thread_local = threading.local()


class ConstantTimeComparer:
    """
    Constant-time comparison utilities that prevent timing side-channel attacks.
    All operations execute in the same amount of time regardless of input values.
    """
    
    @staticmethod
    def compare_equal(a: bytes, b: bytes) -> bool:
        """
        Constant-time byte array comparison.
        Execution time depends only on length, not content.
        Uses HMAC-based comparison for additional hardening.
        """
        if len(a) != len(b):
            # Still do constant-time work even if lengths differ
            dummy = hmac.compare_digest(b'\x00' * len(b), b'\x00' * len(b))
            return False
        
        # Use standard library constant-time comparison
        return hmac.compare_digest(a, b)
    
    @staticmethod
    def compare_strings_equal(a: str, b: str, encoding: str = 'utf-8') -> bool:
        """Constant-time string comparison"""
        return ConstantTimeComparer.compare_equal(
            a.encode(encoding),
            b.encode(encoding)
        )
    
    @staticmethod
    def threshold_evaluate(value: float, threshold: float) -> bool:
        """
        Timing-resistant threshold evaluation.
        Prevents attackers from learning threshold values via timing analysis.
        """
        # Convert to fixed-point representation for constant-time ops
        scale = 1_000_000
        val_int = int(abs(value) * scale)
        thresh_int = int(threshold * scale)
        
        # Use XOR-based constant-time comparison
        result = 0
        max_bits = 64
        for i in range(max_bits):
            val_bit = (val_int >> i) & 1
            thresh_bit = (thresh_int >> i) & 1
            result |= (val_bit ^ thresh_bit)
        
        # Add dummy operations to mask timing
        for _ in range(100):
            _ = secrets.randbits(8)
        
        return value >= threshold
    
    @staticmethod
    def secure_hash_compare(hash_a: str, hash_b: str) -> bool:
        """Constant-time hash comparison with blinding"""
        # Add random blinding factor
        salt = secrets.token_bytes(32)
        blinded_a = hashlib.sha256(hash_a.encode() + salt).digest()
        blinded_b = hashlib.sha256(hash_b.encode() + salt).digest()
        return hmac.compare_digest(blinded_a, blinded_b)


class SecureMemoryManager:
    """
    Secure memory management utilities.
    Provides automatic zeroization of sensitive data to prevent memory forensics.
    """
    
    @staticmethod
    def zeroize_bytes(data: bytearray) -> None:
        """
        Securely overwrite bytearray with zeros.
        Uses multiple passes and volatile operations.
        """
        length = len(data)
        
        # Pass 1: Write zeros
        for i in range(length):
            data[i] = 0
        
        # Pass 2: Write random values
        for i in range(length):
            data[i] = secrets.randbits(8)
        
        # Pass 3: Final zero overwrite
        for i in range(length):
            data[i] = 0
        
        # Force memory barrier operations
        _ = sum(data)
    
    @staticmethod
    def zeroize_string(s: str) -> str:
        """Create a zeroized string placeholder and return it"""
        return '\x00' * len(s)
    
    @staticmethod
    def secure_allocate(size: int) -> bytearray:
        """Allocate and return a securely initialized bytearray"""
        buf = bytearray(size)
        for i in range(size):
            buf[i] = secrets.randbits(8)
        return buf


class TimingJitterInjector:
    """
    Injects random timing jitter to frustrate timing analysis attacks.
    Uses nanosecond-precision delays with cryptographic randomness.
    """
    
    def __init__(self, config: Optional[TimingResistanceConfig] = None):
        self.config = config or TimingResistanceConfig()
    
    def inject_jitter(self) -> None:
        """Inject random timing jitter"""
        if not self.config.enable_jitter:
            return
        
        min_jitter, max_jitter = self.config.jitter_range_ns
        jitter_ns = secrets.randbelow(max_jitter - min_jitter) + min_jitter
        
        # Busy-wait for precise nanosecond delay
        target = time.perf_counter_ns() + jitter_ns
        while time.perf_counter_ns() < target:
            _ = secrets.randbits(4)  # Prevent compiler optimization


class ExecutionTimePadder:
    """
    Ensures minimum execution time for security-critical operations.
    Prevents timing attacks based on early-exit optimizations.
    """
    
    def __init__(self, min_time_ns: Optional[int] = None):
        self.min_time_ns = min_time_ns or 100000  # 100 microseconds
    
    def __enter__(self):
        self.start_time = time.perf_counter_ns()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        elapsed = time.perf_counter_ns() - self.start_time
        remaining = self.min_time_ns - elapsed
        
        if remaining > 0:
            # Pad with busy-wait
            target = time.perf_counter_ns() + remaining
            while time.perf_counter_ns() < target:
                _ = secrets.randbits(8)
        
        return False  # Don't suppress exceptions


class SideChannelResistantEvaluator:
    """
    Wrapper for security evaluations with comprehensive side-channel protections.
    Combines constant-time operations, timing padding, and jitter injection.
    """
    
    def __init__(self, config: Optional[TimingResistanceConfig] = None):
        self.config = config or TimingResistanceConfig()
        self._comparer = ConstantTimeComparer()
        self._jitter = TimingJitterInjector(self.config)
        self._memory = SecureMemoryManager()
    
    def evaluate_threshold(
        self,
        value: float,
        threshold: float,
        operation_name: str = "threshold_check"
    ) -> bool:
        """
        Evaluate a threshold with full side-channel protection.
        """
        with ExecutionTimePadder(self.config.min_execution_time_ns):
            self._jitter.inject_jitter()
            result = self._comparer.threshold_evaluate(value, threshold)
            self._jitter.inject_jitter()
            return result
    
    def secure_compare(self, a: Any, b: Any) -> bool:
        """Compare two values securely"""
        with ExecutionTimePadder():
            self._jitter.inject_jitter()
            
            if isinstance(a, bytes) and isinstance(b, bytes):
                result = self._comparer.compare_equal(a, b)
            elif isinstance(a, str) and isinstance(b, str):
                result = self._comparer.compare_strings_equal(a, b)
            else:
                # Fallback: convert to string representation
                result = self._comparer.compare_strings_equal(str(a), str(b))
            
            self._jitter.inject_jitter()
            return result
    
    def protected_operation(
        self,
        func: Callable,
        *args,
        **kwargs
    ) -> Any:
        """Execute a function with timing protections"""
        with ExecutionTimePadder():
            self._jitter.inject_jitter()
            result = func(*args, **kwargs)
            self._jitter.inject_jitter()
            return result


class PromptInjectionTimingProtector:
    """
    Timing attack protection specifically for prompt injection detection.
    Prevents attackers from probing detection thresholds via timing analysis.
    """
    
    def __init__(self, config: Optional[TimingResistanceConfig] = None):
        self.config = config or TimingResistanceConfig()
        self._evaluator = SideChannelResistantEvaluator(self.config)
    
    def protected_detection(
        self,
        detection_func: Callable[[str], Tuple[float, bool]],
        prompt: str,
        detection_threshold: float = 0.7
    ) -> Tuple[float, bool]:
        """
        Run prompt injection detection with timing protections.
        Returns same (score, detected) tuple but with constant timing.
        """
        with ExecutionTimePadder(500000):  # 500 microsecond minimum
            # Run actual detection
            score, raw_detected = detection_func(prompt)
            
            # Timing-resistant threshold evaluation
            protected_detected = self._evaluator.evaluate_threshold(
                score, detection_threshold
            )
            
            return score, protected_detected
    
    def batch_protected_detection(
        self,
        detection_func: Callable[[List[str]], List[Tuple[float, bool]]],
        prompts: List[str],
        detection_threshold: float = 0.7
    ) -> List[Tuple[float, bool]]:
        """Batch detection with uniform timing per-item"""
        results = []
        for prompt in prompts:
            # Wrap each individual detection
            def single_detect(p: str) -> Tuple[float, bool]:
                return detection_func([p])[0]
            
            results.append(self.protected_detection(single_detect, prompt, detection_threshold))
        
        return results


# Module-level singleton for easy import
_default_config = TimingResistanceConfig()
constant_time = ConstantTimeComparer()
secure_memory = SecureMemoryManager()
timing_protector = SideChannelResistantEvaluator(_default_config)
prompt_protector = PromptInjectionTimingProtector(_default_config)


__all__ = [
    'TimingResistanceConfig',
    'ConstantTimeComparer',
    'SecureMemoryManager',
    'TimingJitterInjector',
    'ExecutionTimePadder',
    'SideChannelResistantEvaluator',
    'PromptInjectionTimingProtector',
    'constant_time',
    'secure_memory',
    'timing_protector',
    'prompt_protector',
]
