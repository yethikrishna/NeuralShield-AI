"""
Error Resilience Module - Retry, Backoff, Circuit Breaker, and Timeout Utilities
Dimension E: Error Resilience

This module provides production-grade error resilience utilities that wrap
existing functionality without modifying core logic. All features are opt-in
and preserve 100% backward compatibility.

API Stability: STABLE
"""

import time
import random
import functools
import threading
from typing import Callable, Any, Optional, Type, Tuple, List, Dict, Union
from dataclasses import dataclass, field
from enum import Enum
import logging

# Configure null logger - opt-in only
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


class CircuitState(Enum):
    """Circuit breaker states."""
    CLOSED = "closed"           # Normal operation - allow requests
    OPEN = "open"               # Circuit tripped - reject requests
    HALF_OPEN = "half_open"     # Testing recovery - allow limited requests


class ResilienceError(Exception):
    """Base exception for all resilience errors."""
    pass


class CircuitBreakerError(ResilienceError):
    """Raised when circuit breaker is open."""
    pass


class TimeoutError(ResilienceError):
    """Raised when operation times out."""
    pass


class MaxRetriesExceededError(ResilienceError):
    """Raised when maximum retries exceeded."""
    pass


class FallbackNotAvailableError(ResilienceError):
    """Raised when fallback is not available."""
    pass


@dataclass
class RetryConfig:
    """Configuration for retry behavior."""
    max_attempts: int = 3
    initial_delay: float = 0.1
    max_delay: float = 10.0
    backoff_factor: float = 2.0
    jitter: bool = True
    retry_exceptions: Tuple[Type[Exception], ...] = (Exception,)
    stop_on_exceptions: Tuple[Type[Exception], ...] = ()


@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker behavior."""
    failure_threshold: int = 5
    recovery_timeout: float = 30.0
    half_open_max_calls: int = 3
    success_threshold: int = 2
    tracked_exceptions: Tuple[Type[Exception], ...] = (Exception,)


@dataclass
class CircuitBreakerState:
    """Internal state for circuit breaker."""
    state: CircuitState = CircuitState.CLOSED
    failure_count: int = 0
    success_count: int = 0
    last_failure_time: float = 0.0
    half_open_call_count: int = 0
    lock: threading.Lock = field(default_factory=threading.Lock)


class ExponentialBackoff:
    """
    Exponential backoff strategy with optional jitter.
    
    Calculates delay times for retry operations using exponential backoff.
    """
    
    def __init__(
        self,
        initial_delay: float = 0.1,
        max_delay: float = 10.0,
        factor: float = 2.0,
        jitter: bool = True
    ):
        self.initial_delay = initial_delay
        self.max_delay = max_delay
        self.factor = factor
        self.jitter = jitter
    
    def calculate_delay(self, attempt: int) -> float:
        """Calculate delay for the given attempt number (0-based)."""
        delay = min(
            self.initial_delay * (self.factor ** attempt),
            self.max_delay
        )
        
        if self.jitter:
            delay = delay * (0.5 + random.random() * 0.5)
        
        return delay


class CircuitBreaker:
    """
    Circuit Breaker pattern implementation.
    
    Prevents cascading failures by stopping requests to a failing service
    and allowing periodic recovery attempts.
    """
    
    def __init__(self, config: Optional[CircuitBreakerConfig] = None):
        self.config = config or CircuitBreakerConfig()
        self._state = CircuitBreakerState()
    
    def _transition_to_open(self) -> None:
        """Transition to OPEN state - reject all requests."""
        self._state.state = CircuitState.OPEN
        self._state.failure_count = 0
        self._state.last_failure_time = time.time()
        logger.warning("Circuit breaker OPEN - rejecting requests")
    
    def _transition_to_half_open(self) -> None:
        """Transition to HALF_OPEN state - test recovery."""
        self._state.state = CircuitState.HALF_OPEN
        self._state.half_open_call_count = 0
        self._state.success_count = 0
        logger.info("Circuit breaker HALF_OPEN - testing recovery")
    
    def _transition_to_closed(self) -> None:
        """Transition to CLOSED state - normal operation."""
        self._state.state = CircuitState.CLOSED
        self._state.failure_count = 0
        self._state.success_count = 0
        logger.info("Circuit breaker CLOSED - normal operation resumed")
    
    def _check_state_transition(self) -> None:
        """Check and perform state transitions based on timing."""
        if self._state.state == CircuitState.OPEN:
            elapsed = time.time() - self._state.last_failure_time
            if elapsed >= self.config.recovery_timeout:
                self._transition_to_half_open()
    
    def record_success(self) -> None:
        """Record a successful call."""
        with self._state.lock:
            if self._state.state == CircuitState.HALF_OPEN:
                self._state.success_count += 1
                if self._state.success_count >= self.config.success_threshold:
                    self._transition_to_closed()
            elif self._state.state == CircuitState.CLOSED:
                self._state.failure_count = 0
    
    def record_failure(self) -> None:
        """Record a failed call."""
        with self._state.lock:
            if self._state.state == CircuitState.CLOSED:
                self._state.failure_count += 1
                if self._state.failure_count >= self.config.failure_threshold:
                    self._transition_to_open()
            elif self._state.state == CircuitState.HALF_OPEN:
                self._transition_to_open()
    
    def allow_request(self) -> bool:
        """Check if request should be allowed."""
        with self._state.lock:
            self._check_state_transition()
            
            if self._state.state == CircuitState.OPEN:
                return False
            
            if self._state.state == CircuitState.HALF_OPEN:
                if self._state.half_open_call_count >= self.config.half_open_max_calls:
                    return False
                self._state.half_open_call_count += 1
            
            return True
    
    def get_state(self) -> CircuitState:
        """Get current circuit state."""
        with self._state.lock:
            self._check_state_transition()
            return self._state.state
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get circuit breaker metrics."""
        with self._state.lock:
            return {
                "state": self._state.state.value,
                "failure_count": self._state.failure_count,
                "success_count": self._state.success_count,
                "last_failure_seconds_ago": time.time() - self._state.last_failure_time,
                "half_open_call_count": self._state.half_open_call_count
            }


def with_retry(
    config: Optional[RetryConfig] = None,
    on_retry: Optional[Callable[[int, Exception], None]] = None
) -> Callable:
    """
    Decorator: Add retry with exponential backoff to a function.
    
    Usage:
        @with_retry()
        def unreliable_function():
            ...
    """
    config = config or RetryConfig()
    backoff = ExponentialBackoff(
        initial_delay=config.initial_delay,
        max_delay=config.max_delay,
        factor=config.backoff_factor,
        jitter=config.jitter
    )
    
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            last_exception: Optional[Exception] = None
            
            for attempt in range(config.max_attempts):
                try:
                    result = func(*args, **kwargs)
                    if attempt > 0:
                        logger.debug(f"Success on attempt {attempt + 1}")
                    return result
                except config.stop_on_exceptions:
                    raise
                except Exception as e:
                    last_exception = e
                    if on_retry:
                        on_retry(attempt, e)
                    
                    if attempt == config.max_attempts - 1:
                        break
                    
                    delay = backoff.calculate_delay(attempt)
                    logger.debug(
                        f"Attempt {attempt + 1} failed: {e}, "
                        f"retrying in {delay:.2f}s"
                    )
                    time.sleep(delay)
            
            raise MaxRetriesExceededError(
                f"Failed after {config.max_attempts} attempts. "
                f"Last error: {last_exception}"
            ) from last_exception
        
        return wrapper
    return decorator


def with_timeout(
    timeout_seconds: float,
    fallback: Optional[Callable] = None
) -> Callable:
    """
    Decorator: Add timeout to a function.
    
    Note: Uses threading for timeout. For CPU-bound operations,
    consider using multiprocessing instead.
    
    Usage:
        @with_timeout(5.0)
        def slow_function():
            ...
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            result: List[Any] = []
            exception: List[Optional[Exception]] = [None]
            
            def target():
                try:
                    result.append(func(*args, **kwargs))
                except Exception as e:
                    exception[0] = e
            
            thread = threading.Thread(target=target)
            thread.daemon = True
            thread.start()
            thread.join(timeout=timeout_seconds)
            
            if thread.is_alive():
                if fallback is not None:
                    logger.warning(f"Operation timed out after {timeout_seconds}s, using fallback")
                    return fallback(*args, **kwargs)
                raise TimeoutError(
                    f"Operation timed out after {timeout_seconds} seconds"
                )
            
            if exception[0] is not None:
                raise exception[0]
            
            return result[0]
        
        return wrapper
    return decorator


def with_circuit_breaker(
    circuit_breaker: CircuitBreaker,
    fallback: Optional[Callable] = None
) -> Callable:
    """
    Decorator: Add circuit breaker protection to a function.
    
    Usage:
        breaker = CircuitBreaker()
        @with_circuit_breaker(breaker)
        def external_service_call():
            ...
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            if not circuit_breaker.allow_request():
                if fallback is not None:
                    return fallback(*args, **kwargs)
                raise CircuitBreakerError("Circuit breaker is OPEN")
            
            try:
                result = func(*args, **kwargs)
                circuit_breaker.record_success()
                return result
            except Exception as e:
                circuit_breaker.record_failure()
                raise
        
        return wrapper
    return decorator


def with_graceful_degradation(
    fallback: Callable,
    fallback_exceptions: Tuple[Type[Exception], ...] = (Exception,)
) -> Callable:
    """
    Decorator: Gracefully degrade functionality when primary fails.
    
    Usage:
        def fallback_response():
            return cached_or_default_value
        
        @with_graceful_degradation(fallback_response)
        def primary_operation():
            ...
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            try:
                return func(*args, **kwargs)
            except fallback_exceptions as e:
                logger.warning(f"Primary failed, degrading gracefully: {e}")
                return fallback(*args, **kwargs)
        
        return wrapper
    return decorator


class Bulkhead:
    """
    Bulkhead pattern - limit concurrent calls to prevent resource exhaustion.
    
    Isolates failures to one part of the system by limiting concurrency.
    """
    
    def __init__(self, max_concurrent: int = 10):
        self.max_concurrent = max_concurrent
        self._semaphore = threading.Semaphore(max_concurrent)
        self._active_count = 0
        self._lock = threading.Lock()
    
    def acquire(self, timeout: Optional[float] = None) -> bool:
        """Acquire a slot. Returns False if timeout."""
        if timeout is not None:
            acquired = self._semaphore.acquire(timeout=timeout)
        else:
            acquired = self._semaphore.acquire()
        if acquired:
            with self._lock:
                self._active_count += 1
        return acquired
    
    def release(self) -> None:
        """Release a slot."""
        with self._lock:
            self._active_count -= 1
        self._semaphore.release()
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get bulkhead metrics."""
        with self._lock:
            return {
                "max_concurrent": self.max_concurrent,
                "active_count": self._active_count,
                "available": self.max_concurrent - self._active_count
            }


def with_bulkhead(
    bulkhead: Bulkhead,
    timeout: Optional[float] = None,
    fallback: Optional[Callable] = None
) -> Callable:
    """
    Decorator: Apply bulkhead pattern to limit concurrency.
    
    Usage:
        bulkhead = Bulkhead(max_concurrent=5)
        @with_bulkhead(bulkhead)
        def resource_intensive_operation():
            ...
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            if not bulkhead.acquire(timeout=timeout):
                if fallback is not None:
                    return fallback(*args, **kwargs)
                raise ResilienceError("Bulkhead capacity exhausted - too many concurrent calls")
            
            try:
                return func(*args, **kwargs)
            finally:
                bulkhead.release()
        
        return wrapper
    return decorator


class FallbackChain:
    """
    Chain multiple fallback strategies.
    
    Tries primary, then each fallback in order until one succeeds.
    """
    
    def __init__(self, primary: Callable, *fallbacks: Callable):
        self.primary = primary
        self.fallbacks = list(fallbacks)
    
    def __call__(self, *args, **kwargs) -> Any:
        """Execute with fallback chain."""
        try:
            return self.primary(*args, **kwargs)
        except Exception as primary_error:
            for i, fallback in enumerate(self.fallbacks):
                try:
                    logger.debug(f"Trying fallback {i + 1}")
                    return fallback(*args, **kwargs)
                except Exception:
                    continue
            
            raise FallbackNotAvailableError(
                "All fallbacks exhausted"
            ) from primary_error


# Global shared instances for convenience
_shared_circuit_breakers: Dict[str, CircuitBreaker] = {}
_shared_bulkheads: Dict[str, Bulkhead] = {}


def get_circuit_breaker(name: str, config: Optional[CircuitBreakerConfig] = None) -> CircuitBreaker:
    """Get or create a named shared circuit breaker."""
    if name not in _shared_circuit_breakers:
        _shared_circuit_breakers[name] = CircuitBreaker(config)
    return _shared_circuit_breakers[name]


def get_bulkhead(name: str, max_concurrent: int = 10) -> Bulkhead:
    """Get or create a named shared bulkhead."""
    if name not in _shared_bulkheads:
        _shared_bulkheads[name] = Bulkhead(max_concurrent)
    return _shared_bulkheads[name]


def get_all_resilience_metrics() -> Dict[str, Any]:
    """Get metrics from all shared resilience components."""
    return {
        "circuit_breakers": {
            name: cb.get_metrics()
            for name, cb in _shared_circuit_breakers.items()
        },
        "bulkheads": {
            name: bh.get_metrics()
            for name, bh in _shared_bulkheads.items()
        }
    }
