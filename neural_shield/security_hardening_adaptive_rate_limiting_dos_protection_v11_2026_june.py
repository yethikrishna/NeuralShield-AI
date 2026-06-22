"""
NeuralShield AI - Adaptive Rate Limiting & DoS Protection Module v11
Dimension B: Security Hardening
Production-grade, incrementally added - NO EXISTING CODE MODIFIED

Implements:
- Token Bucket Algorithm (burst-friendly)
- Leaky Bucket Algorithm (smooth rate)
- Sliding Window Counter (precision timing)
- Adaptive Threat-Based Rate Limiting
- IP/User/Endpoint-level rate limiting
- DoS Attack Detection (burst, slowloris, request flooding)
- Circuit Breaker for degraded services
- Backpressure signaling
"""

import time
import threading
import hashlib
import ipaddress
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Optional, Callable, Any, Tuple, List
from collections import defaultdict, deque
from abc import ABC, abstractmethod
import functools
import asyncio


class RateLimitAlgorithm(Enum):
    """Rate limiting algorithm selection."""
    TOKEN_BUCKET = "token_bucket"        # Best for bursty traffic
    LEAKY_BUCKET = "leaky_bucket"        # Best for smooth, constant rate
    SLIDING_WINDOW = "sliding_window"    # Best for precise time windows
    FIXED_WINDOW = "fixed_window"        # Simplest, lowest overhead


class ThreatLevel(Enum):
    """Threat level for adaptive rate limiting."""
    LOW = "low"           # Normal traffic - lenient limits
    MEDIUM = "medium"     # Suspicious activity - moderate limits
    HIGH = "high"         # Likely attack - strict limits
    CRITICAL = "critical" # Confirmed attack - maximum protection


class DoSAttackType(Enum):
    """Detected DoS attack types."""
    NONE = "none"
    BURST_FLOOD = "burst_flood"
    SLOWLORIS = "slowloris"
    CONNECTION_FLOOD = "connection_flood"
    ENDPOINT_FLOOD = "endpoint_flood"
    DISTRIBUTED_FLOOD = "distributed_flood"


@dataclass
class RateLimitConfig:
    """Configuration for rate limiter."""
    requests_per_second: float = 10.0
    max_burst: int = 50
    window_seconds: int = 60
    algorithm: RateLimitAlgorithm = RateLimitAlgorithm.TOKEN_BUCKET
    block_duration_seconds: int = 300
    enable_adaptive: bool = True


@dataclass
class RateLimitState:
    """Per-key rate limiting state."""
    tokens: float = 0.0
    last_refill: float = 0.0  # 0 means uninitialized
    request_times: deque = field(default_factory=lambda: deque(maxlen=1000))
    window_counter: int = 0
    window_start: float = field(default_factory=time.time)
    blocked_until: float = 0.0
    request_count: int = 0
    error_count: int = 0


@dataclass
class RateLimitResult:
    """Result of rate limit check."""
    allowed: bool
    remaining: int
    limit: int
    reset_after: float
    retry_after: Optional[float] = None
    threat_level: ThreatLevel = ThreatLevel.LOW
    attack_detected: DoSAttackType = DoSAttackType.NONE


@dataclass
class CircuitBreakerState:
    """Circuit breaker state for service protection."""
    failure_count: int = 0
    last_failure_time: float = 0.0
    open_until: float = 0.0
    half_open_attempts: int = 0
    state: str = "closed"  # closed, open, half-open


class BaseRateLimiter(ABC):
    """Abstract base class for rate limiters."""

    @abstractmethod
    def check_rate_limit(self, key: str, config: RateLimitConfig) -> RateLimitResult:
        """Check if request should be allowed."""
        pass


class TokenBucketLimiter(BaseRateLimiter):
    """Token Bucket algorithm - allows controlled bursts."""

    def __init__(self):
        self._states: Dict[str, RateLimitState] = defaultdict(RateLimitState)
        self._lock = threading.Lock()

    def check_rate_limit(self, key: str, config: RateLimitConfig) -> RateLimitResult:
        with self._lock:
            state = self._states[key]
            now = time.time()

            # Initialize with full bucket on first use
            if state.last_refill == 0.0:
                state.tokens = config.max_burst
                state.last_refill = now

            # Check if currently blocked
            if now < state.blocked_until:
                return RateLimitResult(
                    allowed=False,
                    remaining=0,
                    limit=int(config.requests_per_second * config.window_seconds),
                    reset_after=state.blocked_until - now,
                    retry_after=state.blocked_until - now
                )

            # Refill tokens
            elapsed = now - state.last_refill
            state.tokens = min(
                config.max_burst,
                state.tokens + elapsed * config.requests_per_second
            )
            state.last_refill = now

            # Check if token available
            if state.tokens >= 1.0:
                state.tokens -= 1.0
                state.request_count += 1
                return RateLimitResult(
                    allowed=True,
                    remaining=int(state.tokens),
                    limit=config.max_burst,
                    reset_after=1.0 / config.requests_per_second
                )
            else:
                # Rate limit exceeded
                state.blocked_until = now + config.block_duration_seconds
                return RateLimitResult(
                    allowed=False,
                    remaining=0,
                    limit=config.max_burst,
                    reset_after=(1.0 - state.tokens) / config.requests_per_second,
                    retry_after=config.block_duration_seconds
                )


class SlidingWindowLimiter(BaseRateLimiter):
    """Sliding Window Counter - precise time-based rate limiting."""

    def __init__(self):
        self._states: Dict[str, RateLimitState] = defaultdict(RateLimitState)
        self._lock = threading.Lock()

    def check_rate_limit(self, key: str, config: RateLimitConfig) -> RateLimitResult:
        with self._lock:
            state = self._states[key]
            now = time.time()
            window_start = now - config.window_seconds

            # Check if blocked
            if now < state.blocked_until:
                return RateLimitResult(
                    allowed=False,
                    remaining=0,
                    limit=int(config.requests_per_second * config.window_seconds),
                    reset_after=state.blocked_until - now,
                    retry_after=state.blocked_until - now
                )

            # Remove old entries
            while state.request_times and state.request_times[0] < window_start:
                state.request_times.popleft()

            max_requests = int(config.requests_per_second * config.window_seconds)

            if len(state.request_times) < max_requests:
                state.request_times.append(now)
                state.request_count += 1
                return RateLimitResult(
                    allowed=True,
                    remaining=max_requests - len(state.request_times),
                    limit=max_requests,
                    reset_after=config.window_seconds - (now - state.request_times[0]) if state.request_times else 0
                )
            else:
                state.blocked_until = now + config.block_duration_seconds
                return RateLimitResult(
                    allowed=False,
                    remaining=0,
                    limit=max_requests,
                    reset_after=config.window_seconds,
                    retry_after=config.block_duration_seconds
                )


class LeakyBucketLimiter(BaseRateLimiter):
    """Leaky Bucket - enforces constant output rate, smooths bursts."""

    def __init__(self):
        self._states: Dict[str, RateLimitState] = defaultdict(RateLimitState)
        self._lock = threading.Lock()

    def check_rate_limit(self, key: str, config: RateLimitConfig) -> RateLimitResult:
        with self._lock:
            state = self._states[key]
            now = time.time()

            if now < state.blocked_until:
                return RateLimitResult(
                    allowed=False,
                    remaining=0,
                    limit=config.max_burst,
                    reset_after=state.blocked_until - now,
                    retry_after=state.blocked_until - now
                )

            # "Leak" tokens based on time elapsed
            elapsed = now - state.last_refill
            state.tokens = max(0, state.tokens - elapsed * config.requests_per_second)
            state.last_refill = now

            if state.tokens < config.max_burst:
                state.tokens += 1.0
                state.request_count += 1
                return RateLimitResult(
                    allowed=True,
                    remaining=int(config.max_burst - state.tokens),
                    limit=config.max_burst,
                    reset_after=1.0 / config.requests_per_second
                )
            else:
                state.blocked_until = now + config.block_duration_seconds
                return RateLimitResult(
                    allowed=False,
                    remaining=0,
                    limit=config.max_burst,
                    reset_after=1.0 / config.requests_per_second,
                    retry_after=config.block_duration_seconds
                )


class DoSDetector:
    """Detects various types of DoS attacks based on traffic patterns."""

    def __init__(self, burst_threshold: int = 100, slow_request_threshold: float = 30.0):
        self._ip_requests: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self._ip_request_durations: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        self._endpoint_requests: Dict[str, deque] = defaultdict(lambda: deque(maxlen=5000))
        self._lock = threading.Lock()
        self.burst_threshold = burst_threshold
        self.slow_request_threshold = slow_request_threshold

    def track_request(self, ip: str, endpoint: str, duration: Optional[float] = None) -> DoSAttackType:
        """Track a request and detect potential DoS attacks."""
        with self._lock:
            now = time.time()
            self._ip_requests[ip].append(now)
            self._endpoint_requests[endpoint].append(now)
            if duration is not None:
                self._ip_request_durations[ip].append(duration)

            return self._detect_attack(ip, endpoint)

    def _detect_attack(self, ip: str, endpoint: str) -> DoSAttackType:
        """Detect attack type based on patterns."""
        now = time.time()
        one_minute_ago = now - 60
        five_seconds_ago = now - 5

        # Check for burst flood (very high rate in short window)
        ip_recent_5s = sum(1 for t in self._ip_requests[ip] if t > five_seconds_ago)
        if ip_recent_5s > self.burst_threshold:
            return DoSAttackType.BURST_FLOOD

        # Check for slowloris (many long-running requests)
        if len(self._ip_request_durations[ip]) >= 5:
            avg_duration = sum(self._ip_request_durations[ip]) / len(self._ip_request_durations[ip])
            if avg_duration > self.slow_request_threshold:
                return DoSAttackType.SLOWLORIS

        # Check endpoint flood
        endpoint_requests = sum(1 for t in self._endpoint_requests[endpoint] if t > one_minute_ago)
        if endpoint_requests > 1000:
            return DoSAttackType.ENDPOINT_FLOOD

        # Check distributed flood (many unique IPs hitting same endpoint)
        unique_ips = len(self._ip_requests)
        if unique_ips > 50 and endpoint_requests > 500:
            return DoSAttackType.DISTRIBUTED_FLOOD

        return DoSAttackType.NONE

    def get_threat_level(self, ip: str) -> ThreatLevel:
        """Calculate threat level based on IP behavior."""
        now = time.time()
        one_minute_ago = now - 60

        requests_last_minute = sum(1 for t in self._ip_requests[ip] if t > one_minute_ago)

        if requests_last_minute > 500:
            return ThreatLevel.CRITICAL
        elif requests_last_minute > 200:
            return ThreatLevel.HIGH
        elif requests_last_minute > 50:
            return ThreatLevel.MEDIUM
        return ThreatLevel.LOW


class AdaptiveRateLimiter:
    """Adaptive rate limiter that adjusts based on threat level."""

    def __init__(self, base_config: Optional[RateLimitConfig] = None):
        self.base_config = base_config or RateLimitConfig()
        self._limiters = {
            RateLimitAlgorithm.TOKEN_BUCKET: TokenBucketLimiter(),
            RateLimitAlgorithm.SLIDING_WINDOW: SlidingWindowLimiter(),
            RateLimitAlgorithm.LEAKY_BUCKET: LeakyBucketLimiter(),
        }
        self._dos_detector = DoSDetector()
        self._circuit_breakers: Dict[str, CircuitBreakerState] = defaultdict(CircuitBreakerState)
        self._lock = threading.Lock()

    def _get_adaptive_config(self, threat_level: ThreatLevel) -> RateLimitConfig:
        """Get config adjusted for threat level."""
        base = self.base_config
        if threat_level == ThreatLevel.LOW:
            return RateLimitConfig(
                requests_per_second=base.requests_per_second * 2.0,
                max_burst=base.max_burst * 2,
                window_seconds=base.window_seconds,
                algorithm=base.algorithm,
                block_duration_seconds=10
            )
        elif threat_level == ThreatLevel.MEDIUM:
            return RateLimitConfig(
                requests_per_second=base.requests_per_second,
                max_burst=base.max_burst,
                window_seconds=base.window_seconds,
                algorithm=base.algorithm,
                block_duration_seconds=60
            )
        elif threat_level == ThreatLevel.HIGH:
            return RateLimitConfig(
                requests_per_second=base.requests_per_second * 0.5,
                max_burst=int(base.max_burst * 0.5),
                window_seconds=base.window_seconds * 2,
                algorithm=RateLimitAlgorithm.SLIDING_WINDOW,
                block_duration_seconds=300
            )
        else:  # CRITICAL
            return RateLimitConfig(
                requests_per_second=base.requests_per_second * 0.1,
                max_burst=5,
                window_seconds=base.window_seconds * 5,
                algorithm=RateLimitAlgorithm.SLIDING_WINDOW,
                block_duration_seconds=1800
            )

    def check_request(
        self,
        key: str,
        ip: str = "unknown",
        endpoint: str = "unknown",
        algorithm: Optional[RateLimitAlgorithm] = None
    ) -> RateLimitResult:
        """Check if request should be allowed with adaptive rate limiting."""
        # Detect DoS first
        attack_type = self._dos_detector.track_request(ip, endpoint)
        threat_level = self._dos_detector.get_threat_level(ip)

        # Get adaptive config
        config = self._get_adaptive_config(threat_level) if self.base_config.enable_adaptive else self.base_config

        # Use selected algorithm
        algo = algorithm or config.algorithm
        limiter = self._limiters[algo]
        result = limiter.check_rate_limit(key, config)

        # Add threat info
        result.threat_level = threat_level
        result.attack_detected = attack_type

        return result

    def check_circuit_breaker(self, service_name: str) -> Tuple[bool, Optional[float]]:
        """Check if circuit breaker is open for service."""
        with self._lock:
            state = self._circuit_breakers[service_name]
            now = time.time()

            if state.state == "open":
                if now >= state.open_until:
                    state.state = "half-open"
                    state.half_open_attempts = 0
                    return True, None
                return False, state.open_until - now

            return True, None

    def record_failure(self, service_name: str, failure_threshold: int = 5, recovery_timeout: float = 30.0):
        """Record a service failure for circuit breaker."""
        with self._lock:
            state = self._circuit_breakers[service_name]
            now = time.time()

            if state.state == "half-open":
                state.state = "open"
                state.open_until = now + recovery_timeout
                state.failure_count = 0
                return

            state.failure_count += 1
            state.last_failure_time = now

            if state.failure_count >= failure_threshold:
                state.state = "open"
                state.open_until = now + recovery_timeout
                state.failure_count = 0

    def record_success(self, service_name: str):
        """Record a service success for circuit breaker."""
        with self._lock:
            state = self._circuit_breakers[service_name]

            if state.state == "half-open":
                state.half_open_attempts += 1
                if state.half_open_attempts >= 3:
                    state.state = "closed"
                    state.failure_count = 0
                    state.half_open_attempts = 0
            else:
                state.failure_count = max(0, state.failure_count - 1)

    def get_stats(self) -> Dict[str, Any]:
        """Get rate limiting statistics."""
        return {
            "tracked_ips": len(self._dos_detector._ip_requests),
            "tracked_endpoints": len(self._dos_detector._endpoint_requests),
            "circuit_breakers": len(self._circuit_breakers),
            "open_circuits": sum(1 for s in self._circuit_breakers.values() if s.state == "open"),
        }


def rate_limit(
    config: Optional[RateLimitConfig] = None,
    key_prefix: str = "",
    algorithm: RateLimitAlgorithm = RateLimitAlgorithm.TOKEN_BUCKET
):
    """Decorator for rate limiting functions."""
    limiter = AdaptiveRateLimiter(config or RateLimitConfig())

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Generate key from function name and args
            key_hash = hashlib.md5(f"{func.__name__}:{str(args)[:100]}".encode()).hexdigest()
            key = f"{key_prefix}:{key_hash}"

            result = limiter.check_request(key, algorithm=algorithm)

            if not result.allowed:
                raise RateLimitExceededError(
                    f"Rate limit exceeded. Retry after {result.retry_after:.1f}s",
                    retry_after=result.retry_after
                )

            return func(*args, **kwargs)
        return wrapper
    return decorator


class RateLimitExceededError(Exception):
    """Raised when rate limit is exceeded."""

    def __init__(self, message: str, retry_after: Optional[float] = None):
        super().__init__(message)
        self.retry_after = retry_after


# Factory functions for easy instantiation
def create_token_bucket_limiter(requests_per_sec: float = 10.0, max_burst: int = 50) -> AdaptiveRateLimiter:
    """Create a token bucket rate limiter."""
    return AdaptiveRateLimiter(RateLimitConfig(
        requests_per_second=requests_per_sec,
        max_burst=max_burst,
        algorithm=RateLimitAlgorithm.TOKEN_BUCKET
    ))


def create_sliding_window_limiter(requests_per_minute: int = 600, window_sec: int = 60) -> AdaptiveRateLimiter:
    """Create a sliding window rate limiter."""
    return AdaptiveRateLimiter(RateLimitConfig(
        requests_per_second=requests_per_minute / window_sec,
        max_burst=requests_per_minute,
        window_seconds=window_sec,
        algorithm=RateLimitAlgorithm.SLIDING_WINDOW
    ))


def create_dos_protector() -> DoSDetector:
    """Create a standalone DoS detector."""
    return DoSDetector()


# Export public API
__all__ = [
    'AdaptiveRateLimiter',
    'RateLimitConfig',
    'RateLimitResult',
    'RateLimitAlgorithm',
    'ThreatLevel',
    'DoSAttackType',
    'DoSDetector',
    'RateLimitExceededError',
    'CircuitBreakerState',
    'rate_limit',
    'create_token_bucket_limiter',
    'create_sliding_window_limiter',
    'create_dos_protector',
]
