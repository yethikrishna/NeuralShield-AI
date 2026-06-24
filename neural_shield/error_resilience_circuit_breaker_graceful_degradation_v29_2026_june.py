"""
Error Resilience: Circuit Breaker and Graceful Degradation
Dimension E - Error Resilience
Stability: BETA
Last Updated: June 24, 2026

Circuit breaker pattern implementation providing:
- Automatic failure detection and circuit opening
- Half-open state for recovery testing
- Configurable failure thresholds and recovery windows
- Graceful degradation fallbacks
- Bulkhead isolation for resource protection
"""

import time
import threading
import logging
import functools
from typing import (
    Callable, Any, Optional, Dict, List,
    Type, Tuple, Union
)
from dataclasses import dataclass, field
from enum import Enum
from collections import deque


class CircuitState(Enum):
    """States for the circuit breaker."""
    CLOSED = "closed"           # Normal operation, requests flow through
    OPEN = "open"               # Failure threshold exceeded, fail fast
    HALF_OPEN = "half_open"     # Testing recovery, allow limited requests


@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker behavior."""
    failure_threshold: int = 5
    success_threshold: int = 3
    recovery_timeout_seconds: float = 30.0
    window_size_seconds: float = 60.0
    allowed_exceptions: Tuple[Type[Exception], ...] = (Exception,)
    ignored_exceptions: Tuple[Type[Exception], ...] = ()
    fallback_function: Optional[Callable] = None
    half_open_max_requests: int = 1


@dataclass
class CircuitMetrics:
    """Metrics for circuit breaker monitoring."""
    state: CircuitState = CircuitState.CLOSED
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    rejected_requests: int = 0
    last_state_change: float = field(default_factory=time.time)
    consecutive_failures: int = 0
    consecutive_successes: int = 0
    recent_failures: deque = field(default_factory=lambda: deque(maxlen=100))
    recent_successes: deque = field(default_factory=lambda: deque(maxlen=100))


class CircuitBreaker:
    """
    Circuit Breaker implementation based on Michael Nygard's pattern.
    
    Prevents cascading failures by:
    1. Monitoring for failures
    2. Opening circuit when threshold exceeded
    3. Allowing recovery after timeout
    4. Closing circuit when healthy again
    """
    
    def __init__(
        self,
        config: Optional[CircuitBreakerConfig] = None,
        name: str = "default"
    ):
        self.config = config or CircuitBreakerConfig()
        self.name = name
        self._state = CircuitState.CLOSED
        self._metrics = CircuitMetrics()
        self._lock = threading.RLock()
        self._logger = logging.getLogger(__name__)
        
    @property
    def state(self) -> CircuitState:
        """Get current circuit state."""
        with self._lock:
            return self._state
            
    @property
    def metrics(self) -> CircuitMetrics:
        """Get circuit metrics snapshot."""
        with self._lock:
            from dataclasses import replace
            return replace(self._metrics)
            
    def _should_count_failure(self, exc: Exception) -> bool:
        """Check if exception should count as a failure."""
        # Check ignored exceptions first
        for exc_type in self.config.ignored_exceptions:
            if isinstance(exc, exc_type):
                return False
                
        # Check allowed exceptions
        for exc_type in self.config.allowed_exceptions:
            if isinstance(exc, exc_type):
                return True
                
        return False
        
    def _record_success(self) -> None:
        """Record a successful request."""
        self._metrics.total_requests += 1
        self._metrics.successful_requests += 1
        self._metrics.consecutive_failures = 0
        self._metrics.consecutive_successes += 1
        self._metrics.recent_successes.append(time.time())
        
        # Transition from HALF_OPEN to CLOSED if threshold met
        if self._state == CircuitState.HALF_OPEN:
            if self._metrics.consecutive_successes >= self.config.success_threshold:
                self._transition_to(CircuitState.CLOSED)
                
    def _record_failure(self, exc: Exception) -> None:
        """Record a failed request."""
        if not self._should_count_failure(exc):
            return
            
        self._metrics.total_requests += 1
        self._metrics.failed_requests += 1
        self._metrics.consecutive_successes = 0
        self._metrics.consecutive_failures += 1
        self._metrics.recent_failures.append(time.time())
        
        # Transition to OPEN if threshold exceeded
        if self._state in (CircuitState.CLOSED, CircuitState.HALF_OPEN):
            if self._metrics.consecutive_failures >= self.config.failure_threshold:
                self._transition_to(CircuitState.OPEN)
                
    def _record_rejected(self) -> None:
        """Record a rejected request (circuit open)."""
        self._metrics.rejected_requests += 1
        
    def _transition_to(self, new_state: CircuitState) -> None:
        """Transition to a new state."""
        old_state = self._state
        self._state = new_state
        self._metrics.state = new_state
        self._metrics.last_state_change = time.time()
        self._metrics.consecutive_failures = 0
        self._metrics.consecutive_successes = 0
        
        self._logger.info(
            f"Circuit '{self.name}' transitioned: {old_state.value} -> {new_state.value}"
        )
        
    def _can_attempt_execution(self) -> bool:
        """Check if execution should be attempted."""
        if self._state == CircuitState.CLOSED:
            return True
            
        if self._state == CircuitState.OPEN:
            # Check if recovery timeout has elapsed
            elapsed = time.time() - self._metrics.last_state_change
            if elapsed >= self.config.recovery_timeout_seconds:
                self._transition_to(CircuitState.HALF_OPEN)
                return True
            return False
            
        if self._state == CircuitState.HALF_OPEN:
            # Allow limited requests in half-open state
            recent_half_open_attempts = sum(
                1 for t in self._metrics.recent_successes
                if t > self._metrics.last_state_change
            ) + sum(
                1 for t in self._metrics.recent_failures
                if t > self._metrics.last_state_change
            )
            return recent_half_open_attempts < self.config.half_open_max_requests
            
        return False
        
    def execute(
        self,
        func: Callable,
        *args,
        fallback: Optional[Callable] = None,
        **kwargs
    ) -> Any:
        """
        Execute function with circuit breaker protection.
        
        Args:
            func: Function to execute
            *args: Positional arguments
            fallback: Fallback function if circuit is open
            **kwargs: Keyword arguments
            
        Returns:
            Function result or fallback result
        """
        with self._lock:
            if not self._can_attempt_execution():
                self._record_rejected()
                
                # Use configured fallback or provided fallback
                fallback_func = fallback or self.config.fallback_function
                if fallback_func:
                    return fallback_func(*args, **kwargs)
                    
                raise CircuitOpenError(
                    circuit_name=self.name,
                    state=self._state,
                    remaining_timeout=max(
                        0,
                        self.config.recovery_timeout_seconds - 
                        (time.time() - self._metrics.last_state_change)
                    )
                )
        
        try:
            result = func(*args, **kwargs)
            with self._lock:
                self._record_success()
            return result
            
        except Exception as e:
            with self._lock:
                self._record_failure(e)
            raise
            
    def reset(self) -> None:
        """Reset circuit to initial CLOSED state."""
        with self._lock:
            self._transition_to(CircuitState.CLOSED)
            self._metrics = CircuitMetrics()
            self._logger.info(f"Circuit '{self.name}' manually reset")
            
    def force_open(self) -> None:
        """Force circuit into OPEN state."""
        with self._lock:
            self._transition_to(CircuitState.OPEN)
            
    def force_closed(self) -> None:
        """Force circuit into CLOSED state."""
        with self._lock:
            self._transition_to(CircuitState.CLOSED)


class CircuitOpenError(Exception):
    """Raised when circuit is open and execution is rejected."""
    
    def __init__(
        self,
        circuit_name: str,
        state: CircuitState,
        remaining_timeout: float
    ):
        super().__init__(
            f"Circuit '{circuit_name}' is {state.value}. "
            f"Retry in {remaining_timeout:.1f}s"
        )
        self.circuit_name = circuit_name
        self.state = state
        self.remaining_timeout = remaining_timeout


def circuit_breaker(
    failure_threshold: int = 5,
    success_threshold: int = 3,
    recovery_timeout_seconds: float = 30.0,
    fallback: Optional[Callable] = None,
    name: Optional[str] = None
):
    """
    Decorator for circuit breaker protection.
    
    Usage:
        @circuit_breaker(failure_threshold=3, recovery_timeout_seconds=10)
        def unreliable_external_call():
            ...
    """
    def decorator(func: Callable) -> Callable:
        cb_name = name or func.__name__
        cb = CircuitBreaker(
            CircuitBreakerConfig(
                failure_threshold=failure_threshold,
                success_threshold=success_threshold,
                recovery_timeout_seconds=recovery_timeout_seconds,
                fallback_function=fallback
            ),
            name=cb_name
        )
        
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            return cb.execute(func, *args, **kwargs)
            
        # Expose circuit breaker for monitoring
        wrapper.circuit_breaker = cb
        return wrapper
    return decorator


class GracefulDegradation:
    """
    Graceful degradation manager for feature-level fallback.
    
    Allows features to degrade gracefully when dependencies fail,
    maintaining partial functionality rather than total failure.
    """
    
    def __init__(self):
        self._feature_states: Dict[str, bool] = {}
        self._fallbacks: Dict[str, Callable] = {}
        self._lock = threading.Lock()
        self._logger = logging.getLogger(__name__)
        
    def register_feature(
        self,
        feature_name: str,
        primary_function: Callable,
        fallback_function: Callable,
        enabled: bool = True
    ) -> None:
        """Register a feature with its fallback."""
        with self._lock:
            self._feature_states[feature_name] = enabled
            self._fallbacks[feature_name] = fallback_function
            
    def execute(
        self,
        feature_name: str,
        primary_function: Callable,
        *args,
        **kwargs
    ) -> Any:
        """
        Execute feature with graceful degradation.
        
        If primary function fails, falls back to degraded mode.
        """
        fallback = self._fallbacks.get(feature_name)
        
        try:
            return primary_function(*args, **kwargs)
        except Exception as e:
            self._logger.warning(
                f"Feature '{feature_name}' failed, activating fallback: {e}"
            )
            if fallback:
                return fallback(*args, **kwargs)
            raise
            
    def get_degraded_features(self) -> List[str]:
        """Get list of features currently in degraded mode."""
        with self._lock:
            return [
                name for name, enabled in self._feature_states.items()
                if not enabled
            ]


class Bulkhead:
    """
    Bulkhead pattern implementation for resource isolation.
    
    Prevents one failing component from consuming all resources.
    """
    
    def __init__(
        self,
        max_concurrent_requests: int = 10,
        max_queue_size: int = 100,
        name: str = "default"
    ):
        self.max_concurrent_requests = max_concurrent_requests
        self.max_queue_size = max_queue_size
        self.name = name
        self._active_requests = 0
        self._queued_requests = 0
        self._lock = threading.Lock()
        self._condition = threading.Condition(self._lock)
        self._logger = logging.getLogger(__name__)
        
    @property
    def active_requests(self) -> int:
        with self._lock:
            return self._active_requests
            
    @property
    def utilization(self) -> float:
        with self._lock:
            return self._active_requests / self.max_concurrent_requests
            
    def acquire(self, timeout: Optional[float] = None) -> bool:
        """Acquire a bulkhead slot."""
        with self._condition:
            if self._active_requests >= self.max_concurrent_requests:
                if self._queued_requests >= self.max_queue_size:
                    self._logger.warning(
                        f"Bulkhead '{self.name}' queue full, rejecting request"
                    )
                    return False
                    
                self._queued_requests += 1
                acquired = self._condition.wait_for(
                    lambda: self._active_requests < self.max_concurrent_requests,
                    timeout=timeout
                )
                self._queued_requests -= 1
                
                if not acquired:
                    return False
                    
            self._active_requests += 1
            return True
            
    def release(self) -> None:
        """Release a bulkhead slot."""
        with self._condition:
            self._active_requests = max(0, self._active_requests - 1)
            self._condition.notify()
            
    def __call__(self, timeout: Optional[float] = None):
        """Use as context manager."""
        class BulkheadContext:
            def __init__(self, bulkhead: Bulkhead, timeout: Optional[float]):
                self.bulkhead = bulkhead
                self.timeout = timeout
                self.acquired = False
                
            def __enter__(self):
                self.acquired = self.bulkhead.acquire(self.timeout)
                if not self.acquired:
                    raise BulkheadExhaustedError(
                        bulkhead_name=self.bulkhead.name,
                        active=self.bulkhead.active_requests,
                        max=self.bulkhead.max_concurrent_requests
                    )
                return self
                
            def __exit__(self, *args):
                if self.acquired:
                    self.bulkhead.release()
                    
        return BulkheadContext(self, timeout)


class BulkheadExhaustedError(Exception):
    """Raised when bulkhead capacity is exhausted."""
    
    def __init__(
        self,
        bulkhead_name: str,
        active: int,
        max: int
    ):
        super().__init__(
            f"Bulkhead '{bulkhead_name}' exhausted: {active}/{max} slots in use"
        )
        self.bulkhead_name = bulkhead_name
        self.active = active
        self.max = max


# Global registry for circuit breakers
_circuit_breakers: Dict[str, CircuitBreaker] = {}
_bulkheads: Dict[str, Bulkhead] = {}
_graceful_degradation = GracefulDegradation()


def get_circuit_breaker(name: str, config: Optional[CircuitBreakerConfig] = None) -> CircuitBreaker:
    """Get or create a named circuit breaker."""
    if name not in _circuit_breakers:
        _circuit_breakers[name] = CircuitBreaker(config or CircuitBreakerConfig(), name=name)
    return _circuit_breakers[name]


def get_bulkhead(name: str, max_concurrent: int = 10) -> Bulkhead:
    """Get or create a named bulkhead."""
    if name not in _bulkheads:
        _bulkheads[name] = Bulkhead(max_concurrent_requests=max_concurrent, name=name)
    return _bulkheads[name]


def get_graceful_degradation() -> GracefulDegradation:
    """Get global graceful degradation manager."""
    return _graceful_degradation
