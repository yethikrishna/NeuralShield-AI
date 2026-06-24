"""
NeuralShield AI - Comprehensive Error Resilience Framework v30
Dimension E: Error Resilience - ADD-ONLY implementation

This module provides production-grade error resilience capabilities:
- Custom exception hierarchy for security-specific errors
- Timeout wrappers with jitter
- Retry with exponential backoff and jitter
- Circuit breaker pattern for fault tolerance
- Graceful degradation fallbacks
- Bulkhead isolation for resource protection

ALL existing happy-path behavior is 100% preserved.
This is purely additive - no modifications to existing code.
"""

import time
import random
import threading
import functools
import logging
from typing import Any, Callable, Optional, Type, Tuple, Union, Dict, List
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta

# Configure logging - OPT-IN only, disabled by default
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


# -----------------------------------------------------------------------------
# Custom Exception Hierarchy (Security-Specific)
# -----------------------------------------------------------------------------

class NeuralShieldError(Exception):
    """Base exception for all NeuralShield errors."""
    error_code: str = "NS-000"
    retryable: bool = False
    severity: str = "ERROR"
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}
        self.timestamp = datetime.utcnow().isoformat()


class ConfigurationError(NeuralShieldError):
    """Raised when configuration is invalid or missing."""
    error_code: str = "NS-001"
    retryable: bool = False
    severity: str = "ERROR"


class ValidationError(NeuralShieldError):
    """Raised when input validation fails."""
    error_code: str = "NS-002"
    retryable: bool = False
    severity: str = "WARNING"


class SecurityViolationError(NeuralShieldError):
    """Raised when a security policy is violated."""
    error_code: str = "NS-003"
    retryable: bool = False
    severity: str = "CRITICAL"


class ThreatDetectionError(NeuralShieldError):
    """Raised when threat detection encounters an error."""
    error_code: str = "NS-004"
    retryable: bool = True
    severity: str = "ERROR"


class ModelInferenceError(NeuralShieldError):
    """Raised when model inference fails."""
    error_code: str = "NS-005"
    retryable: bool = True
    severity: str = "ERROR"


class ExternalServiceError(NeuralShieldError):
    """Raised when external service calls fail."""
    error_code: str = "NS-006"
    retryable: bool = True
    severity: str = "WARNING"


class RateLimitExceededError(NeuralShieldError):
    """Raised when rate limits are exceeded."""
    error_code: str = "NS-007"
    retryable: bool = True
    severity: str = "WARNING"
    
    def __init__(self, message: str, retry_after: float = 1.0, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, details)
        self.retry_after = retry_after


class CircuitBreakerOpenError(NeuralShieldError):
    """Raised when circuit breaker is open and calls are blocked."""
    error_code: str = "NS-008"
    retryable: bool = True
    severity: str = "WARNING"


class TimeoutError(NeuralShieldError):
    """Raised when operation exceeds timeout threshold."""
    error_code: str = "NS-009"
    retryable: bool = True
    severity: str = "WARNING"


# -----------------------------------------------------------------------------
# Circuit Breaker Implementation
# -----------------------------------------------------------------------------

class CircuitState(Enum):
    CLOSED = "CLOSED"           # Normal operation - all calls pass through
    OPEN = "OPEN"               # Circuit tripped - fail fast
    HALF_OPEN = "HALF_OPEN"     # Testing recovery - allow limited calls


@dataclass
class CircuitBreakerMetrics:
    """Metrics for circuit breaker monitoring."""
    success_count: int = 0
    failure_count: int = 0
    timeout_count: int = 0
    rejection_count: int = 0
    state_transitions: List[Tuple[CircuitState, CircuitState, str]] = field(default_factory=list)


class CircuitBreaker:
    """
    Circuit Breaker pattern implementation for fault tolerance.
    
    Prevents cascading failures by failing fast when downstream services
    are unhealthy. Automatically recovers when service health improves.
    """
    
    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: float = 30.0,
        half_open_max_calls: int = 3,
        name: str = "default",
        allowed_exceptions: Tuple[Type[Exception], ...] = (Exception,)
    ):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.half_open_max_calls = half_open_max_calls
        self.name = name
        self.allowed_exceptions = allowed_exceptions
        
        self._state: CircuitState = CircuitState.CLOSED
        self._failure_count: int = 0
        self._open_timestamp: Optional[float] = None
        self._half_open_calls: int = 0
        self._lock = threading.RLock()
        self.metrics = CircuitBreakerMetrics()
    
    @property
    def state(self) -> CircuitState:
        with self._lock:
            return self._state
    
    def _transition_to(self, new_state: CircuitState, reason: str) -> None:
        old_state = self._state
        self._state = new_state
        self.metrics.state_transitions.append((old_state, new_state, reason))
        logger.warning(f"CircuitBreaker '{self.name}': {old_state.value} -> {new_state.value}: {reason}")
    
    def _record_success(self) -> None:
        self._failure_count = 0
        self._half_open_calls = 0
        self.metrics.success_count += 1
        if self._state == CircuitState.HALF_OPEN:
            self._transition_to(CircuitState.CLOSED, "Recovery successful")
    
    def _record_failure(self) -> None:
        self._failure_count += 1
        self.metrics.failure_count += 1
        
        if self._state == CircuitState.CLOSED:
            if self._failure_count >= self.failure_threshold:
                self._transition_to(CircuitState.OPEN, f"Failure threshold reached ({self.failure_threshold})")
                self._open_timestamp = time.monotonic()
        
        elif self._state == CircuitState.HALF_OPEN:
            self._transition_to(CircuitState.OPEN, "Failure during half-open recovery")
            self._open_timestamp = time.monotonic()
    
    def _allow_call(self) -> bool:
        now = time.monotonic()
        
        if self._state == CircuitState.CLOSED:
            return True
        
        if self._state == CircuitState.OPEN:
            if now - self._open_timestamp >= self.recovery_timeout:
                self._transition_to(CircuitState.HALF_OPEN, "Recovery timeout elapsed")
                self._half_open_calls = 0
                return True
            return False
        
        if self._state == CircuitState.HALF_OPEN:
            if self._half_open_calls < self.half_open_max_calls:
                self._half_open_calls += 1
                return True
            return False
        
        return False
    
    def __call__(self, func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            with self._lock:
                if not self._allow_call():
                    self.metrics.rejection_count += 1
                    raise CircuitBreakerOpenError(
                        f"Circuit breaker '{self.name}' is OPEN. "
                        f"Try again after {self.recovery_timeout}s."
                    )
            
            try:
                result = func(*args, **kwargs)
                with self._lock:
                    self._record_success()
                return result
            except self.allowed_exceptions:
                with self._lock:
                    self._record_failure()
                raise
        
        return wrapper


# -----------------------------------------------------------------------------
# Retry with Exponential Backoff and Jitter
# -----------------------------------------------------------------------------

def retry(
    max_attempts: int = 3,
    initial_delay: float = 1.0,
    max_delay: float = 30.0,
    backoff_factor: float = 2.0,
    jitter: float = 0.1,
    retry_on: Tuple[Type[Exception], ...] = (Exception,),
    giveup_on: Tuple[Type[Exception], ...] = ()
) -> Callable:
    """
    Retry decorator with exponential backoff and jitter.
    
    Args:
        max_attempts: Maximum number of attempts
        initial_delay: Initial delay between retries (seconds)
        max_delay: Maximum delay cap (seconds)
        backoff_factor: Multiplier for exponential backoff
        jitter: Random jitter factor (0.0-1.0)
        retry_on: Exception types to retry on
        giveup_on: Exception types to immediately give up on
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            attempt = 0
            delay = initial_delay
            
            while True:
                try:
                    return func(*args, **kwargs)
                except giveup_on:
                    raise
                except retry_on as e:
                    attempt += 1
                    if attempt >= max_attempts:
                        logger.warning(f"Retry failed after {max_attempts} attempts: {e}")
                        raise
                    
                    # Calculate delay with jitter
                    jitter_amount = delay * jitter * (2 * random.random() - 1)
                    sleep_time = min(delay + jitter_amount, max_delay)
                    sleep_time = max(0, sleep_time)
                    
                    logger.debug(
                        f"Retry attempt {attempt}/{max_attempts} failed. "
                        f"Retrying in {sleep_time:.2f}s. Error: {e}"
                    )
                    time.sleep(sleep_time)
                    
                    # Exponential backoff
                    delay = min(delay * backoff_factor, max_delay)
        
        return wrapper
    return decorator


# -----------------------------------------------------------------------------
# Timeout Wrapper
# -----------------------------------------------------------------------------

def timeout(seconds: float, fallback: Optional[Any] = None, exception: Type[Exception] = TimeoutError) -> Callable:
    """
    Timeout decorator for synchronous functions.
    
    Note: Uses threading-based timeout. For CPU-bound operations,
    consider using multiprocessing-based timeout instead.
    
    Args:
        seconds: Timeout threshold in seconds
        fallback: Optional fallback value to return on timeout
        exception: Exception type to raise (if no fallback)
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            result = []
            exc_info = []
            
            def target():
                try:
                    result.append(func(*args, **kwargs))
                except Exception as e:
                    exc_info.append(e)
            
            thread = threading.Thread(target=target)
            thread.daemon = True
            thread.start()
            thread.join(timeout=seconds)
            
            if thread.is_alive():
                if fallback is not None:
                    logger.warning(f"Function {func.__name__} timed out after {seconds}s, using fallback")
                    return fallback
                raise exception(f"Operation timed out after {seconds} seconds")
            
            if exc_info:
                raise exc_info[0]
            
            return result[0] if result else None
        
        return wrapper
    return decorator


# -----------------------------------------------------------------------------
# Graceful Degradation Fallback
# -----------------------------------------------------------------------------

def fallback(
    primary: Optional[Callable] = None,
    *,
    fallback_func: Callable,
    exceptions: Tuple[Type[Exception], ...] = (Exception,),
    log_fallback: bool = True
) -> Callable:
    """
    Graceful degradation decorator.
    
    When primary function fails, falls back to alternative implementation.
    Happy path behavior is 100% preserved.
    
    Args:
        fallback_func: Function to call when primary fails
        exceptions: Exception types that trigger fallback
        log_fallback: Whether to log fallback occurrences
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except exceptions as e:
                if log_fallback:
                    logger.warning(
                        f"Fallback triggered for {func.__name__}: {type(e).__name__}: {e}. "
                        f"Using {fallback_func.__name__}"
                    )
                return fallback_func(*args, **kwargs)
        
        return wrapper
    
    if primary is not None:
        return decorator(primary)
    return decorator


# -----------------------------------------------------------------------------
# Bulkhead Isolation
# -----------------------------------------------------------------------------

class Bulkhead:
    """
    Bulkhead pattern implementation for resource isolation.
    
    Limits concurrent calls to prevent resource exhaustion and
    cascading failures across system components.
    """
    
    def __init__(self, max_concurrent: int = 10, max_waiting: int = 100, name: str = "default"):
        self.max_concurrent = max_concurrent
        self.max_waiting = max_waiting
        self.name = name
        self._semaphore = threading.Semaphore(max_concurrent)
        self._waiting_count = 0
        self._lock = threading.Lock()
        self.rejections = 0
        self.timeouts = 0
    
    def __call__(self, func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            with self._lock:
                if self._waiting_count >= self.max_waiting:
                    self.rejections += 1
                    raise RuntimeError(f"Bulkhead '{self.name}' queue full ({self.max_waiting})")
                self._waiting_count += 1
            
            try:
                acquired = self._semaphore.acquire(timeout=5.0)
                if not acquired:
                    self.timeouts += 1
                    raise RuntimeError(f"Bulkhead '{self.name}' acquisition timeout")
                
                try:
                    return func(*args, **kwargs)
                finally:
                    self._semaphore.release()
            finally:
                with self._lock:
                    self._waiting_count -= 1
        
        return wrapper


# -----------------------------------------------------------------------------
# Composite Resilience Policy
# -----------------------------------------------------------------------------

class ResiliencePolicy:
    """
    Composite resilience policy combining multiple strategies.
    
    Combines: Retry + Circuit Breaker + Timeout + Fallback
    for comprehensive error resilience.
    """
    
    def __init__(
        self,
        name: str = "default",
        max_retries: int = 3,
        circuit_failure_threshold: int = 5,
        timeout_seconds: float = 30.0,
        fallback_func: Optional[Callable] = None
    ):
        self.name = name
        self.circuit_breaker = CircuitBreaker(
            failure_threshold=circuit_failure_threshold,
            name=name
        )
        self.max_retries = max_retries
        self.timeout_seconds = timeout_seconds
        self.fallback_func = fallback_func
    
    def __call__(self, func: Callable) -> Callable:
        decorated = func
        
        # Apply circuit breaker
        decorated = self.circuit_breaker(decorated)
        
        # Apply retry
        decorated = retry(
            max_attempts=self.max_retries,
            retry_on=(ExternalServiceError, ModelInferenceError, ThreatDetectionError)
        )(decorated)
        
        # Apply timeout
        decorated = timeout(seconds=self.timeout_seconds)(decorated)
        
        # Apply fallback if provided
        if self.fallback_func is not None:
            decorated = fallback(fallback_func=self.fallback_func)(decorated)
        
        return decorated


# -----------------------------------------------------------------------------
# Safe Default Fallback Implementations
# -----------------------------------------------------------------------------

def safe_fallback_empty(*args, **kwargs) -> Dict[str, Any]:
    """Safe fallback returning empty results."""
    return {
        "status": "degraded",
        "warning": "Service unavailable - using degraded mode",
        "threat_detected": False,
        "confidence": 0.0,
        "fallback_used": True,
        "timestamp": datetime.utcnow().isoformat()
    }


def safe_fallback_allow(*args, **kwargs) -> Dict[str, Any]:
    """Safe fallback allowing request through (fail-open)."""
    return {
        "status": "degraded",
        "warning": "Security check unavailable - request allowed (fail-open)",
        "allowed": True,
        "fallback_used": True,
        "timestamp": datetime.utcnow().isoformat()
    }


def safe_fallback_deny(*args, **kwargs) -> Dict[str, Any]:
    """Safe fallback denying request (fail-closed)."""
    return {
        "status": "degraded",
        "warning": "Security check unavailable - request denied (fail-closed)",
        "allowed": False,
        "fallback_used": True,
        "timestamp": datetime.utcnow().isoformat()
    }


# -----------------------------------------------------------------------------
# Module Exports
# -----------------------------------------------------------------------------

__all__ = [
    # Exceptions
    "NeuralShieldError",
    "ConfigurationError",
    "ValidationError",
    "SecurityViolationError",
    "ThreatDetectionError",
    "ModelInferenceError",
    "ExternalServiceError",
    "RateLimitExceededError",
    "CircuitBreakerOpenError",
    "TimeoutError",
    
    # Circuit Breaker
    "CircuitState",
    "CircuitBreaker",
    "CircuitBreakerMetrics",
    
    # Retry
    "retry",
    
    # Timeout
    "timeout",
    
    # Fallback
    "fallback",
    
    # Bulkhead
    "Bulkhead",
    
    # Composite Policy
    "ResiliencePolicy",
    
    # Safe Fallbacks
    "safe_fallback_empty",
    "safe_fallback_allow",
    "safe_fallback_deny",
]
