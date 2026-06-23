"""
Error Resilience v25 - TLS Connection Protection Layer
=======================================================
Pure wrapper layer for Security v17 TLS/HTTPS Endpoint Protection

ADD-ONLY: 100% new module, zero modifications to existing code
OPT-IN: Disabled by default, zero performance impact when not used
BACKWARD COMPATIBLE: All existing code continues to work unchanged

Purpose:
- Timeout protection for TLS handshakes
- Circuit breaker for repeated TLS failures
- Retry with exponential backoff for transient errors
- Graceful degradation fallback to HTTP
- Connection pool health monitoring

Integrates with:
- security_hardening_tls_https_endpoint_protection_v17
- feature_expansion_http_metrics_server_v14
"""

import time
import ssl
import socket
import logging
import threading
from typing import Optional, Callable, Any, Dict, List, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import deque
from functools import wraps
import random


# Configure logging - OPTIONAL, disabled by default
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


class CircuitState(Enum):
    """Circuit breaker states."""
    CLOSED = "closed"           # Normal operation - allow requests
    OPEN = "open"               # Circuit tripped - reject requests
    HALF_OPEN = "half_open"     # Testing recovery - allow limited requests


class DegradationMode(Enum):
    """Graceful degradation modes."""
    FAIL_FAST = "fail_fast"                     # Raise exception immediately
    FALLBACK_TO_HTTP = "fallback_to_http"       # Fall back to unencrypted HTTP
    FALLBACK_TO_CACHE = "fallback_to_cache"     # Return cached response
    FALLBACK_TO_DEFAULT = "fallback_to_default" # Return default value


@dataclass
class TLSConnectionStats:
    """Statistics for TLS connection resilience."""
    total_attempts: int = 0
    successful_connections: int = 0
    failed_connections: int = 0
    timeout_failures: int = 0
    certificate_failures: int = 0
    handshake_failures: int = 0
    retry_attempts: int = 0
    circuit_breaker_trips: int = 0
    graceful_degradations: int = 0
    fallback_to_http: int = 0
    avg_handshake_time_ms: float = 0.0
    _handshake_times: deque = field(default_factory=lambda: deque(maxlen=100))
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def record_handshake_time(self, duration_ms: float) -> None:
        """Record TLS handshake duration."""
        with self._lock:
            self._handshake_times.append(duration_ms)
            if self._handshake_times:
                self.avg_handshake_time_ms = sum(self._handshake_times) / len(self._handshake_times)

    def record_success(self, handshake_time_ms: float) -> None:
        """Record successful connection."""
        with self._lock:
            self.total_attempts += 1
            self.successful_connections += 1
            self.record_handshake_time(handshake_time_ms)

    def record_failure(self, failure_type: str) -> None:
        """Record failed connection."""
        with self._lock:
            self.total_attempts += 1
            self.failed_connections += 1
            if failure_type == "timeout":
                self.timeout_failures += 1
            elif failure_type == "certificate":
                self.certificate_failures += 1
            elif failure_type == "handshake":
                self.handshake_failures += 1

    def record_retry(self) -> None:
        """Record retry attempt."""
        with self._lock:
            self.retry_attempts += 1

    def record_circuit_trip(self) -> None:
        """Record circuit breaker trip."""
        with self._lock:
            self.circuit_breaker_trips += 1

    def record_degradation(self, mode: str) -> None:
        """Record graceful degradation."""
        with self._lock:
            self.graceful_degradations += 1
            if mode == "http":
                self.fallback_to_http += 1

    def get_summary(self) -> Dict[str, Any]:
        """Get statistics summary."""
        with self._lock:
            success_rate = (
                self.successful_connections / self.total_attempts * 100
                if self.total_attempts > 0 else 100.0
            )
            return {
                "total_attempts": self.total_attempts,
                "successful_connections": self.successful_connections,
                "failed_connections": self.failed_connections,
                "success_rate_pct": round(success_rate, 2),
                "timeout_failures": self.timeout_failures,
                "certificate_failures": self.certificate_failures,
                "handshake_failures": self.handshake_failures,
                "retry_attempts": self.retry_attempts,
                "circuit_breaker_trips": self.circuit_breaker_trips,
                "graceful_degradations": self.graceful_degradations,
                "fallback_to_http": self.fallback_to_http,
                "avg_handshake_time_ms": round(self.avg_handshake_time_ms, 2),
            }


class CircuitBreaker:
    """
    Circuit breaker for TLS connection failures.
    
    Prevents cascading failures when TLS endpoints are unhealthy.
    Trips open after failure threshold, allows test requests after recovery timeout.
    """

    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: float = 30.0,
        half_open_max_attempts: int = 3,
    ):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.half_open_max_attempts = half_open_max_attempts
        
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._half_open_attempts = 0
        self._open_timestamp = 0.0
        self._lock = threading.Lock()

    @property
    def state(self) -> CircuitState:
        """Get current circuit state."""
        with self._lock:
            if self._state == CircuitState.OPEN:
                if time.time() - self._open_timestamp >= self.recovery_timeout:
                    self._state = CircuitState.HALF_OPEN
                    self._half_open_attempts = 0
            return self._state

    def allow_request(self) -> bool:
        """Check if request should be allowed."""
        current_state = self.state
        if current_state == CircuitState.OPEN:
            return False
        if current_state == CircuitState.HALF_OPEN:
            with self._lock:
                if self._half_open_attempts >= self.half_open_max_attempts:
                    return False
                self._half_open_attempts += 1
        return True

    def record_success(self) -> None:
        """Record successful request - reset circuit."""
        with self._lock:
            self._failure_count = 0
            self._half_open_attempts = 0
            self._state = CircuitState.CLOSED

    def record_failure(self) -> None:
        """Record failed request - may trip circuit."""
        with self._lock:
            self._failure_count += 1
            if self._state == CircuitState.HALF_OPEN:
                # Any failure in half-open trips back to open
                self._state = CircuitState.OPEN
                self._open_timestamp = time.time()
            elif self._failure_count >= self.failure_threshold:
                self._state = CircuitState.OPEN
                self._open_timestamp = time.time()

    def reset(self) -> None:
        """Reset circuit breaker to closed state."""
        with self._lock:
            self._state = CircuitState.CLOSED
            self._failure_count = 0
            self._half_open_attempts = 0
            self._open_timestamp = 0.0


class ExponentialBackoff:
    """
    Exponential backoff with jitter for retry logic.
    
    Formula: base_delay * (multiplier ^ attempt) + random_jitter
    Prevents thundering herd during recovery.
    """

    def __init__(
        self,
        base_delay: float = 0.1,
        max_delay: float = 10.0,
        multiplier: float = 2.0,
        jitter_factor: float = 0.1,
    ):
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.multiplier = multiplier
        self.jitter_factor = jitter_factor

    def get_delay(self, attempt: int) -> float:
        """Calculate delay for given attempt number (0-indexed)."""
        delay = min(self.base_delay * (self.multiplier ** attempt), self.max_delay)
        jitter = random.uniform(-delay * self.jitter_factor, delay * self.jitter_factor)
        return max(0.0, delay + jitter)


class TLSTimeoutProtector:
    """
    Timeout protection for TLS handshakes.
    
    Wraps SSL socket operations with timeout enforcement.
    Prevents hanging on misconfigured or unresponsive TLS endpoints.
    """

    def __init__(
        self,
        handshake_timeout: float = 10.0,
        connection_timeout: float = 5.0,
        read_timeout: float = 30.0,
        write_timeout: float = 30.0,
    ):
        self.handshake_timeout = handshake_timeout
        self.connection_timeout = connection_timeout
        self.read_timeout = read_timeout
        self.write_timeout = write_timeout

    def wrap_socket(
        self,
        sock: socket.socket,
        ssl_context: ssl.SSLContext,
        server_hostname: Optional[str] = None,
    ) -> ssl.SSLSocket:
        """
        Wrap socket with SSL and apply timeout protections.
        
        ADD-ONLY: Pure wrapper, doesn't modify original socket behavior
        """
        sock.settimeout(self.connection_timeout)
        
        start_time = time.time()
        try:
            ssl_sock = ssl_context.wrap_socket(
                sock,
                server_hostname=server_hostname,
                do_handshake_on_connect=False,
            )
            
            # Enforce handshake timeout
            ssl_sock.settimeout(self.handshake_timeout)
            handshake_start = time.time()
            ssl_sock.do_handshake()
            handshake_time = (time.time() - handshake_start) * 1000
            
            # Apply post-handshake timeouts
            ssl_sock.settimeout(self.read_timeout)
            
            logger.debug(
                f"TLS handshake completed in {handshake_time:.1f}ms "
                f"(timeout={self.handshake_timeout}s)"
            )
            
            return ssl_sock
            
        except ssl.SSLError as e:
            if "timed out" in str(e).lower():
                raise TLSTimeoutError(
                    f"TLS handshake timed out after {time.time() - start_time:.1f}s"
                ) from e
            raise TLSHandshakeError(f"TLS handshake failed: {e}") from e
        except socket.timeout as e:
            raise TLSTimeoutError(
                f"Connection timed out after {self.connection_timeout}s"
            ) from e


class TLSError(Exception):
    """Base exception for TLS resilience errors."""
    pass


class TLSTimeoutError(TLSError):
    """Raised when TLS operation times out."""
    pass


class TLSHandshakeError(TLSError):
    """Raised when TLS handshake fails."""
    pass


class TLSCircuitOpenError(TLSError):
    """Raised when circuit breaker is open."""
    pass


class TLSResilienceWrapper:
    """
    Main wrapper class combining all error resilience features.
    
    Features:
    1. Timeout protection for all TLS operations
    2. Circuit breaker for cascading failure prevention
    3. Retry with exponential backoff and jitter
    4. Graceful degradation with multiple fallback modes
    5. Comprehensive statistics collection
    """

    def __init__(
        self,
        # Timeout settings
        handshake_timeout: float = 10.0,
        connection_timeout: float = 5.0,
        # Circuit breaker settings
        circuit_failure_threshold: int = 5,
        circuit_recovery_timeout: float = 30.0,
        # Retry settings
        max_retries: int = 3,
        base_retry_delay: float = 0.1,
        max_retry_delay: float = 5.0,
        # Degradation settings
        degradation_mode: DegradationMode = DegradationMode.FALLBACK_TO_HTTP,
        fallback_value: Any = None,
        # Statistics
        enable_stats: bool = True,
    ):
        self.timeout_protector = TLSTimeoutProtector(
            handshake_timeout=handshake_timeout,
            connection_timeout=connection_timeout,
        )
        self.circuit_breaker = CircuitBreaker(
            failure_threshold=circuit_failure_threshold,
            recovery_timeout=circuit_recovery_timeout,
        )
        self.backoff = ExponentialBackoff(
            base_delay=base_retry_delay,
            max_delay=max_retry_delay,
        )
        self.max_retries = max_retries
        self.degradation_mode = degradation_mode
        self.fallback_value = fallback_value
        self.stats = TLSConnectionStats() if enable_stats else None
        self._fallback_handler: Optional[Callable] = None

    def set_fallback_handler(self, handler: Callable) -> None:
        """Set custom fallback handler for graceful degradation."""
        self._fallback_handler = handler

    def execute_with_resilience(
        self,
        operation: Callable,
        *args,
        **kwargs,
    ) -> Any:
        """
        Execute TLS operation with full resilience protection.
        
        Flow:
        1. Check circuit breaker
        2. Try operation with retries
        3. Apply exponential backoff between retries
        4. Apply graceful degradation on final failure
        """
        if not self.circuit_breaker.allow_request():
            if self.stats:
                self.stats.record_circuit_trip()
            return self._handle_degradation("circuit_open")

        for attempt in range(self.max_retries + 1):
            try:
                start_time = time.time()
                result = operation(*args, **kwargs)
                handshake_time = (time.time() - start_time) * 1000
                
                self.circuit_breaker.record_success()
                if self.stats:
                    self.stats.record_success(handshake_time)
                
                return result

            except (TLSTimeoutError, TLSHandshakeError, ssl.SSLError, socket.timeout) as e:
                failure_type = "timeout" if isinstance(e, (TLSTimeoutError, socket.timeout)) else "handshake"
                
                if self.stats:
                    self.stats.record_failure(failure_type)
                
                if attempt < self.max_retries:
                    if self.stats:
                        self.stats.record_retry()
                    delay = self.backoff.get_delay(attempt)
                    logger.debug(f"Retry {attempt + 1}/{self.max_retries} after {delay:.2f}s delay")
                    time.sleep(delay)
                    continue
                
                # Final failure - record and degrade
                self.circuit_breaker.record_failure()
                return self._handle_degradation(failure_type, error=e)

        return self._handle_degradation("max_retries")

    def _handle_degradation(self, reason: str, error: Optional[Exception] = None) -> Any:
        """Handle graceful degradation based on configured mode."""
        if self.stats:
            self.stats.record_degradation(self.degradation_mode.value)

        logger.warning(f"Graceful degradation triggered: {reason}", exc_info=error)

        if self.degradation_mode == DegradationMode.FAIL_FAST:
            if error:
                raise error
            raise TLSError(f"Operation failed: {reason}")

        elif self.degradation_mode == DegradationMode.FALLBACK_TO_HTTP:
            logger.info("Falling back to unencrypted HTTP")
            if self._fallback_handler:
                return self._fallback_handler("http")
            return self.fallback_value

        elif self.degradation_mode == DegradationMode.FALLBACK_TO_CACHE:
            logger.info("Falling back to cached response")
            if self._fallback_handler:
                return self._fallback_handler("cache")
            return self.fallback_value

        elif self.degradation_mode == DegradationMode.FALLBACK_TO_DEFAULT:
            return self.fallback_value

        return self.fallback_value

    def get_stats(self) -> Optional[Dict[str, Any]]:
        """Get resilience statistics."""
        return self.stats.get_summary() if self.stats else None

    def reset_stats(self) -> None:
        """Reset statistics counters."""
        if self.stats:
            self.stats = TLSConnectionStats()

    def reset_circuit(self) -> None:
        """Reset circuit breaker to closed state."""
        self.circuit_breaker.reset()


# Global convenience instances - OPT-IN, must be explicitly used
_default_resilience = TLSResilienceWrapper()


def wrap_tls_operation_with_resilience(
    operation: Callable,
    *args,
    max_retries: int = 3,
    handshake_timeout: float = 10.0,
    **kwargs,
) -> Any:
    """
    Convenience function to wrap any TLS operation with resilience.
    
    ADD-ONLY: Pure wrapper, no changes to operation itself
    """
    wrapper = TLSResilienceWrapper(
        max_retries=max_retries,
        handshake_timeout=handshake_timeout,
    )
    return wrapper.execute_with_resilience(operation, *args, **kwargs)


def tls_resilience_decorator(
    max_retries: int = 3,
    circuit_failure_threshold: int = 5,
    degradation_mode: DegradationMode = DegradationMode.FALLBACK_TO_HTTP,
):
    """
    Decorator for adding TLS resilience to any function.
    
    Usage:
        @tls_resilience_decorator()
        def my_tls_function(...):
            ...
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            resilience = TLSResilienceWrapper(
                max_retries=max_retries,
                circuit_failure_threshold=circuit_failure_threshold,
                degradation_mode=degradation_mode,
            )
            return resilience.execute_with_resilience(func, *args, **kwargs)
        return wrapper
    return decorator


# Backward compatibility - ensure existing code doesn't break
__all__ = [
    "CircuitState",
    "DegradationMode",
    "TLSConnectionStats",
    "CircuitBreaker",
    "ExponentialBackoff",
    "TLSTimeoutProtector",
    "TLSError",
    "TLSTimeoutError",
    "TLSHandshakeError",
    "TLSCircuitOpenError",
    "TLSResilienceWrapper",
    "wrap_tls_operation_with_resilience",
    "tls_resilience_decorator",
]
