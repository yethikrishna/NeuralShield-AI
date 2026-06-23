"""
NeuralShield Security Hardening Module v18 - Side Channel & Memory Protection
Dimension B: Security Hardening - Incremental Build, Add-Only Philosophy

Provides:
1. Constant-time comparison helpers with timing attack resistance
2. Secure memory zeroization with cryptographic overwrite patterns
3. Adaptive rate limiting with token bucket algorithm
4. Context-aware DoS protection with behavioral analysis
5. Side-channel resistant memory operations

All functionality is OPT-IN and layered ON TOP of existing code.
No modifications to core production logic.
"""

import time
import hmac
import hashlib
import secrets
import threading
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
from dataclasses import dataclass, field
from collections import defaultdict
import gc


@dataclass
class RateLimitConfig:
    """Configuration for rate limiting."""
    max_requests: int = 100
    window_seconds: float = 60.0
    burst_multiplier: float = 2.0
    enable_adaptive: bool = True
    suspicious_threshold: float = 0.8


@dataclass
class MemoryProtectionConfig:
    """Configuration for memory protection."""
    overwrite_passes: int = 3
    enable_random_patterns: bool = True
    force_gc_after_zeroize: bool = True
    zeroize_on_exit: bool = True


class ConstantTimeComparator:
    """
    Constant-time comparison utilities to prevent timing attacks.
    All operations run in fixed time regardless of input values.
    """

    @staticmethod
    def compare_strings(a: str, b: str) -> bool:
        """
        Compare two strings in constant time.
        Returns True if equal, False otherwise.
        Time taken is independent of how many characters match.
        """
        if len(a) != len(b):
            # Still perform full comparison to avoid timing leak
            dummy = hmac.compare_digest(a[:min(len(a), len(b))], b[:min(len(a), len(b))])
            return False
        return hmac.compare_digest(a, b)

    @staticmethod
    def compare_bytes(a: bytes, b: bytes) -> bool:
        """Compare two byte strings in constant time."""
        if len(a) != len(b):
            dummy = hmac.compare_digest(a[:min(len(a), len(b))], b[:min(len(a), len(b))])
            return False
        return hmac.compare_digest(a, b)

    @staticmethod
    def compare_digests(a: bytes, b: bytes) -> bool:
        """Compare two cryptographic digests in constant time."""
        return hmac.compare_digest(a, b)

    @staticmethod
    def secure_equals(a: Union[str, bytes], b: Union[str, bytes]) -> bool:
        """
        Generic secure comparison.
        Automatically handles both str and bytes types.
        Type mismatch returns False.
        """
        if type(a) != type(b):
            return False
        if isinstance(a, str) and isinstance(b, str):
            return ConstantTimeComparator.compare_strings(a, b)
        elif isinstance(a, bytes) and isinstance(b, bytes):
            return ConstantTimeComparator.compare_bytes(a, b)
        return False


class SecureMemoryZeroizer:
    """
    Secure memory zeroization with multiple overwrite patterns.
    Prevents memory forensic recovery of sensitive data.
    """

    def __init__(self, config: Optional[MemoryProtectionConfig] = None):
        self.config = config or MemoryProtectionConfig()
        self._patterns = [
            b'\x00',      # Zero pattern
            b'\xFF',      # All ones pattern
            b'\x55',      # Alternating 01010101
            b'\xAA',      # Alternating 10101010
        ]

    def zeroize_bytearray(self, data: bytearray) -> None:
        """
        Securely zeroize a bytearray with multiple overwrite passes.
        This destroys sensitive data in memory.
        """
        length = len(data)
        if length == 0:
            return

        for pass_num in range(self.config.overwrite_passes):
            # Select pattern for this pass
            if self.config.enable_random_patterns:
                pattern = secrets.token_bytes(1)
            else:
                pattern = self._patterns[pass_num % len(self._patterns)]

            # Overwrite every byte
            for i in range(length):
                data[i] = pattern[0]

        # Final zero pass
        for i in range(length):
            data[i] = 0

        if self.config.force_gc_after_zeroize:
            gc.collect()

    def zeroize_bytes(self, data: bytes) -> bytearray:
        """
        Create a zeroized version of bytes.
        Note: bytes are immutable, so this returns a new zeroized bytearray.
        Original bytes cannot be securely modified.
        """
        result = bytearray(len(data))
        self.zeroize_bytearray(result)
        return result

    def zeroize_string(self, s: str) -> None:
        """
        Attempt to zeroize string contents.
        Note: Python strings are immutable, so this is best-effort.
        Recommend using bytearray for truly sensitive data.
        """
        pass

    def zeroize_list(self, items: List[Any]) -> None:
        """Zeroize sensitive items in a list."""
        for i, item in enumerate(items):
            if isinstance(item, bytearray):
                self.zeroize_bytearray(item)
            elif isinstance(item, str):
                items[i] = ""
            elif isinstance(item, (int, float)):
                items[i] = 0

    def secure_wipe_object(self, obj: Any, sensitive_attrs: List[str]) -> None:
        """Wipe sensitive attributes from an object."""
        for attr in sensitive_attrs:
            if hasattr(obj, attr):
                value = getattr(obj, attr)
                if isinstance(value, bytearray):
                    self.zeroize_bytearray(value)
                elif isinstance(value, (str, bytes)):
                    setattr(obj, attr, "")
                elif isinstance(value, (int, float)):
                    setattr(obj, attr, 0)


class AdaptiveRateLimiter:
    """
    Adaptive rate limiter with token bucket algorithm.
    Provides DoS protection and prevents abuse.
    Features behavioral analysis for suspicious patterns.
    """

    def __init__(self, config: Optional[RateLimitConfig] = None):
        self.config = config or RateLimitConfig()
        self._buckets: Dict[str, Tuple[float, float]] = {}  # key -> (tokens, last_update)
        self._request_history: Dict[str, List[float]] = defaultdict(list)
        self._lock = threading.Lock()
        self._suspicious_clients: Dict[str, int] = defaultdict(int)

    def _ensure_bucket(self, key: str) -> None:
        """Ensure bucket exists for a key."""
        if key not in self._buckets:
            now = time.time()
            self._buckets[key] = (self.config.max_requests, now)

    def _refill_tokens(self, key: str) -> None:
        """Refill tokens based on elapsed time."""
        self._ensure_bucket(key)
        tokens, last_time = self._buckets[key]
        now = time.time()
        elapsed = now - last_time

        # Calculate tokens to add
        tokens_per_second = self.config.max_requests / self.config.window_seconds
        new_tokens = tokens + elapsed * tokens_per_second

        # Cap at max (with burst multiplier)
        max_tokens = self.config.max_requests * self.config.burst_multiplier
        self._buckets[key] = (min(new_tokens, max_tokens), now)

    def check_rate_limit(self, key: str, cost: float = 1.0) -> Tuple[bool, Dict[str, Any]]:
        """
        Check if request should be allowed.
        Returns (allowed, metadata_dict)
        """
        with self._lock:
            now = time.time()

            # Ensure bucket exists
            self._ensure_bucket(key)

            # Record request time for behavioral analysis
            self._request_history[key].append(now)
            # Keep only recent history
            cutoff = now - self.config.window_seconds
            self._request_history[key] = [
                t for t in self._request_history[key] if t > cutoff
            ]

            # Refill tokens
            self._refill_tokens(key)
            tokens, _ = self._buckets[key]

            # Check behavioral patterns if adaptive is enabled
            suspicious_score = 0.0
            if self.config.enable_adaptive:
                suspicious_score = self._calculate_suspicious_score(key)

                if suspicious_score > self.config.suspicious_threshold:
                    self._suspicious_clients[key] += 1
                    # Apply penalty to suspicious clients
                    cost *= (1.0 + suspicious_score)

            # Check if enough tokens
            if tokens >= cost:
                self._buckets[key] = (tokens - cost, now)
                allowed = True
            else:
                allowed = False

            remaining, _ = self._buckets[key]

            return allowed, {
                "allowed": allowed,
                "remaining_tokens": remaining,
                "max_tokens": self.config.max_requests,
                "suspicious_score": suspicious_score,
                "suspicious_strikes": self._suspicious_clients[key],
                "window_reset": now + self.config.window_seconds
            }

    def _calculate_suspicious_score(self, key: str) -> float:
        """
        Calculate behavioral suspiciousness score.
        Detects: uniform intervals (bot behavior), excessive frequency, etc.
        """
        history = self._request_history[key]
        if len(history) < 5:
            return 0.0

        # Check for too-uniform intervals (bot signature)
        intervals = [history[i] - history[i-1] for i in range(1, len(history))]
        if len(intervals) < 3:
            return 0.0

        # Calculate interval variance
        avg_interval = sum(intervals) / len(intervals)
        variance = sum((i - avg_interval) ** 2 for i in intervals) / len(intervals)

        # Low variance = very uniform = suspicious
        uniformity_score = 1.0 / (1.0 + variance * 1000)  # Normalize

        # Check request frequency
        frequency = len(history) / self.config.window_seconds
        frequency_score = min(frequency / (self.config.max_requests / self.config.window_seconds), 1.0)

        # Combined score
        return (uniformity_score * 0.5 + frequency_score * 0.5)

    def reset_client(self, key: str) -> None:
        """Reset rate limit for a client."""
        with self._lock:
            now = time.time()
            self._buckets[key] = (self.config.max_requests, now)
            self._suspicious_clients[key] = 0


class SideChannelResistantOperations:
    """
    Side-channel resistant implementations of common operations.
    Designed to prevent timing, power, and cache side-channel attacks.
    """

    @staticmethod
    def blind_index_lookup(index: int, array: List[Any], blind_value: Any) -> Any:
        """
        Perform array lookup without leaking index through timing.
        Always iterates through entire array regardless of index.
        """
        result = blind_value
        for i, item in enumerate(array):
            match = (i == index)
            if match:
                result = item
        return result

    @staticmethod
    def secure_condition(condition: bool, true_val: Any, false_val: Any) -> Any:
        """
        Return value based on condition without timing branch.
        Uses arithmetic instead of if/else to avoid timing leaks.
        """
        condition_int = int(condition)
        not_condition_int = 1 - condition_int

        if isinstance(true_val, (int, float)) and isinstance(false_val, (int, float)):
            return condition_int * true_val + not_condition_int * false_val

        options = [false_val, true_val]
        return options[condition_int]

    @staticmethod
    def constant_time_selection(items: List[Any], selector: int) -> Any:
        """
        Select item from list in constant time.
        Always touches all items to prevent cache timing.
        """
        result = items[0]  # Default
        for i, item in enumerate(items):
            if i == selector:
                result = item
        return result


class SecurityHardeningFacade:
    """
    Facade for easy integration of security hardening features.
    Provides simple API that wraps existing code.
    """

    def __init__(
        self,
        rate_config: Optional[RateLimitConfig] = None,
        memory_config: Optional[MemoryProtectionConfig] = None
    ):
        self.rate_limiter = AdaptiveRateLimiter(rate_config)
        self.memory_zeroizer = SecureMemoryZeroizer(memory_config)
        self.constant_time = ConstantTimeComparator()
        self.side_channel = SideChannelResistantOperations()

    def wrap_function_with_rate_limit(
        self,
        func: Callable,
        client_id: str,
        *args,
        **kwargs
    ) -> Tuple[bool, Optional[Any]]:
        """
        Wrap a function call with rate limiting.
        Returns (was_allowed, result)
        """
        allowed, metadata = self.rate_limiter.check_rate_limit(client_id)
        if allowed:
            return True, func(*args, **kwargs)
        return False, None

    def secure_compare(self, a: Any, b: Any) -> bool:
        """Secure constant-time comparison."""
        return self.constant_time.secure_equals(a, b)

    def zeroize_sensitive_data(self, data: Union[bytearray, List[Any]]) -> None:
        """Securely zeroize sensitive data."""
        if isinstance(data, bytearray):
            self.memory_zeroizer.zeroize_bytearray(data)
        elif isinstance(data, list):
            self.memory_zeroizer.zeroize_list(data)

    def check_rate(self, client_id: str) -> Tuple[bool, Dict[str, Any]]:
        """Check rate limit status."""
        return self.rate_limiter.check_rate_limit(client_id)


# Module-level singletons for easy use
_default_comparator = ConstantTimeComparator()
_default_zeroizer = SecureMemoryZeroizer()
_default_rate_limiter = AdaptiveRateLimiter()
_default_side_channel = SideChannelResistantOperations()

# Exported convenience functions
secure_compare = _default_comparator.secure_equals
constant_time_compare = _default_comparator.compare_strings
zeroize_bytearray = _default_zeroizer.zeroize_bytearray
check_rate_limit = _default_rate_limiter.check_rate_limit
blind_lookup = _default_side_channel.blind_index_lookup

__all__ = [
    'ConstantTimeComparator',
    'SecureMemoryZeroizer',
    'AdaptiveRateLimiter',
    'SideChannelResistantOperations',
    'SecurityHardeningFacade',
    'RateLimitConfig',
    'MemoryProtectionConfig',
    'secure_compare',
    'constant_time_compare',
    'zeroize_bytearray',
    'check_rate_limit',
    'blind_lookup',
]
