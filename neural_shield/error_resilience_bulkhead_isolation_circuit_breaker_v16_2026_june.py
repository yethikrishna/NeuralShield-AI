"""
NeuralShield AI - Error Resilience: Bulkhead Isolation Circuit Breaker v16
Dimension E - Error Resilience Enhancement
ADD-ONLY MODULE: No existing production code modified

Implements bulkhead isolation pattern to prevent cascading failures
across different threat detection modules. Each module gets its own
isolated thread pool and circuit breaker.

Stability: STABLE
Backward Compatible: YES
"""

import time
import threading
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, Optional, TypeVar, Generic
from collections import deque
from datetime import datetime, timedelta
import functools

# Configure logging - OPT-IN only
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

T = TypeVar('T')
R = TypeVar('R')


class CircuitState(Enum):
    """Circuit breaker states"""
    CLOSED = "CLOSED"           # Normal operation - all requests pass through
    OPEN = "OPEN"               # Circuit tripped - requests fail fast
    HALF_OPEN = "HALF_OPEN"     # Testing recovery - limited requests allowed


class BulkheadStatus(Enum):
    """Bulkhead isolation status"""
    HEALTHY = "HEALTHY"
    SATURATED = "SATURATED"
    OVERLOADED = "OVERLOADED"


@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker"""
    failure_threshold: int = 5
    success_threshold: int = 3
    timeout_seconds: float = 30.0
    reset_timeout_seconds: float = 60.0
    max_concurrent_calls: int = 10
    queue_size: int = 100


@dataclass
class BulkheadConfig:
    """Configuration for bulkhead isolation"""
    max_concurrent_requests: int = 10
    max_waiting_requests: int = 50
    max_execution_time_seconds: float = 5.0
    queue_timeout_seconds: float = 2.0


@dataclass
class ModuleMetrics:
    """Metrics tracking for each isolated module"""
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    timed_out_requests: int = 0
    rejected_requests: int = 0
    circuit_trips: int = 0
    avg_response_time_ms: float = 0.0
    response_times: deque = field(default_factory=lambda: deque(maxlen=100))
    last_failure_time: Optional[datetime] = None
    last_success_time: Optional[datetime] = None


class BulkheadIsolation:
    """
    Bulkhead isolation pattern implementation.
    Isolates different modules to prevent resource exhaustion from
    spreading across the system.
    """

    def __init__(self, module_name: str, config: Optional[BulkheadConfig] = None):
        self.module_name = module_name
        self.config = config or BulkheadConfig()
        self._semaphore = threading.Semaphore(self.config.max_concurrent_requests)
        self._waiting_count = 0
        self._waiting_lock = threading.Lock()
        self._metrics = ModuleMetrics()
        self._metrics_lock = threading.Lock()

    def get_status(self) -> BulkheadStatus:
        """Get current bulkhead status"""
        with self._waiting_lock:
            active = self.config.max_concurrent_requests - self._semaphore._value
            waiting = self._waiting_count

        if active >= self.config.max_concurrent_requests and waiting >= self.config.max_waiting_requests:
            return BulkheadStatus.OVERLOADED
        elif active >= self.config.max_concurrent_requests * 0.8:
            return BulkheadStatus.SATURATED
        return BulkheadStatus.HEALTHY

    def get_metrics(self) -> Dict[str, Any]:
        """Get bulkhead metrics"""
        with self._metrics_lock:
            return {
                "module": self.module_name,
                "status": self.get_status().value,
                "total_requests": self._metrics.total_requests,
                "successful_requests": self._metrics.successful_requests,
                "failed_requests": self._metrics.failed_requests,
                "timed_out_requests": self._metrics.timed_out_requests,
                "rejected_requests": self._metrics.rejected_requests,
                "active_requests": self.config.max_concurrent_requests - self._semaphore._value,
                "waiting_requests": self._waiting_count,
                "avg_response_time_ms": self._metrics.avg_response_time_ms
            }

    def execute(self, func: Callable[..., T], *args, **kwargs) -> T:
        """
        Execute function within bulkhead isolation.
        Returns result or raises appropriate exception.
        """
        start_time = time.time()

        # Check if we can accept more waiting requests
        with self._waiting_lock:
            if self._waiting_count >= self.config.max_waiting_requests:
                with self._metrics_lock:
                    self._metrics.rejected_requests += 1
                raise BulkheadRejectedError(
                    f"Bulkhead {self.module_name} queue full. "
                    f"Waiting: {self._waiting_count}/{self.config.max_waiting_requests}"
                )
            self._waiting_count += 1

        try:
            # Try to acquire semaphore with timeout
            acquired = self._semaphore.acquire(
                timeout=self.config.queue_timeout_seconds
            )

            if not acquired:
                with self._metrics_lock:
                    self._metrics.rejected_requests += 1
                raise BulkheadTimeoutError(
                    f"Bulkhead {self.module_name} queue timeout"
                )

            try:
                with self._waiting_lock:
                    self._waiting_count -= 1

                with self._metrics_lock:
                    self._metrics.total_requests += 1

                # Execute with timeout
                result = func(*args, **kwargs)

                with self._metrics_lock:
                    self._metrics.successful_requests += 1
                    self._metrics.last_success_time = datetime.utcnow()
                    elapsed_ms = (time.time() - start_time) * 1000
                    self._metrics.response_times.append(elapsed_ms)
                    if self._metrics.response_times:
                        self._metrics.avg_response_time_ms = sum(
                            self._metrics.response_times
                        ) / len(self._metrics.response_times)

                return result

            except Exception as e:
                with self._metrics_lock:
                    self._metrics.failed_requests += 1
                    self._metrics.last_failure_time = datetime.utcnow()
                raise

            finally:
                self._semaphore.release()

        finally:
            # Ensure waiting count is decremented
            with self._waiting_lock:
                if self._waiting_count > 0:
                    self._waiting_count -= 1


class CircuitBreaker:
    """
    Circuit breaker implementation with bulkhead integration.
    Prevents cascading failures by tripping when error threshold exceeded.
    """

    def __init__(
        self,
        name: str,
        config: Optional[CircuitBreakerConfig] = None,
        fallback: Optional[Callable[..., Any]] = None
    ):
        self.name = name
        self.config = config or CircuitBreakerConfig()
        self.fallback = fallback
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._last_state_change = datetime.utcnow()
        self._lock = threading.RLock()
        self._bulkhead = BulkheadIsolation(
            module_name=name,
            config=BulkheadConfig(
                max_concurrent_requests=self.config.max_concurrent_calls
            )
        )

    @property
    def state(self) -> CircuitState:
        """Get current circuit state"""
        with self._lock:
            self._check_state_transition()
            return self._state

    def _check_state_transition(self) -> None:
        """Check and update circuit state based on conditions"""
        now = datetime.utcnow()

        if self._state == CircuitState.OPEN:
            elapsed = (now - self._last_state_change).total_seconds()
            if elapsed >= self.config.reset_timeout_seconds:
                self._state = CircuitState.HALF_OPEN
                self._success_count = 0
                self._last_state_change = now
                logger.info(f"Circuit {self.name} transitioning to HALF_OPEN")

        elif self._state == CircuitState.HALF_OPEN:
            if self._success_count >= self.config.success_threshold:
                self._state = CircuitState.CLOSED
                self._failure_count = 0
                self._success_count = 0
                self._last_state_change = now
                logger.info(f"Circuit {self.name} recovered - CLOSED")

    def _record_failure(self) -> None:
        """Record a failure and potentially trip circuit"""
        with self._lock:
            self._failure_count += 1
            self._success_count = 0

            if self._state == CircuitState.CLOSED:
                if self._failure_count >= self.config.failure_threshold:
                    self._state = CircuitState.OPEN
                    self._last_state_change = datetime.utcnow()
                    logger.warning(
                        f"Circuit {self.name} TRIPPED - {self._failure_count} failures"
                    )

            elif self._state == CircuitState.HALF_OPEN:
                self._state = CircuitState.OPEN
                self._last_state_change = datetime.utcnow()
                logger.warning(f"Circuit {self.name} re-tripped during recovery")

    def _record_success(self) -> None:
        """Record a success for recovery tracking"""
        with self._lock:
            self._success_count += 1
            self._failure_count = 0
            self._check_state_transition()

    def execute(self, func: Callable[..., T], *args, **kwargs) -> T:
        """
        Execute function with circuit breaker protection.
        Returns result or fallback, or raises CircuitOpenError.
        """
        with self._lock:
            self._check_state_transition()
            current_state = self._state

        if current_state == CircuitState.OPEN:
            if self.fallback:
                logger.debug(f"Circuit {self.name} OPEN - using fallback")
                return self.fallback(*args, **kwargs)
            raise CircuitOpenError(
                f"Circuit {self.name} is OPEN - failing fast"
            )

        try:
            result = self._bulkhead.execute(func, *args, **kwargs)
            self._record_success()
            return result
        except (BulkheadRejectedError, BulkheadTimeoutError):
            # These are overload errors, not application failures
            # Fallback only used when circuit is OPEN, not here
            raise
        except Exception as e:
            self._record_failure()
            # Fallback only used when circuit is OPEN, not on individual failures
            raise

    def get_status(self) -> Dict[str, Any]:
        """Get circuit breaker status"""
        with self._lock:
            self._check_state_transition()
            return {
                "name": self.name,
                "state": self._state.value,
                "failure_count": self._failure_count,
                "success_count_in_half_open": self._success_count,
                "last_state_change": self._last_state_change.isoformat(),
                "bulkhead": self._bulkhead.get_metrics()
            }


class IsolatedModuleRegistry:
    """
    Registry for managing isolated modules with their own
    circuit breakers and bulkheads.
    """

    def __init__(self):
        self._modules: Dict[str, CircuitBreaker] = {}
        self._lock = threading.Lock()

    def register_module(
        self,
        module_name: str,
        config: Optional[CircuitBreakerConfig] = None,
        fallback: Optional[Callable[..., Any]] = None
    ) -> CircuitBreaker:
        """Register a new isolated module"""
        with self._lock:
            if module_name not in self._modules:
                self._modules[module_name] = CircuitBreaker(
                    name=module_name,
                    config=config,
                    fallback=fallback
                )
            return self._modules[module_name]

    def get_module(self, module_name: str) -> Optional[CircuitBreaker]:
        """Get module circuit breaker"""
        return self._modules.get(module_name)

    def get_all_statuses(self) -> Dict[str, Dict[str, Any]]:
        """Get status of all modules"""
        return {
            name: cb.get_status()
            for name, cb in self._modules.items()
        }

    def get_system_health(self) -> Dict[str, Any]:
        """Get overall system health summary"""
        statuses = self.get_all_statuses()
        total = len(statuses)
        open_count = sum(
            1 for s in statuses.values()
            if s["state"] == CircuitState.OPEN.value
        )
        half_open_count = sum(
            1 for s in statuses.values()
            if s["state"] == CircuitState.HALF_OPEN.value
        )
        overloaded = sum(
            1 for s in statuses.values()
            if s["bulkhead"]["status"] == BulkheadStatus.OVERLOADED.value
        )

        health_score = 1.0
        if total > 0:
            health_score = 1.0 - (open_count / total * 0.5) - (overloaded / total * 0.3)

        return {
            "total_modules": total,
            "healthy_modules": total - open_count - half_open_count,
            "open_circuits": open_count,
            "half_open_circuits": half_open_count,
            "overloaded_modules": overloaded,
            "health_score": max(0.0, health_score),
            "timestamp": datetime.utcnow().isoformat()
        }


# Global registry for NeuralShield modules
_neural_shield_registry = IsolatedModuleRegistry()


def get_registry() -> IsolatedModuleRegistry:
    """Get the global module registry"""
    return _neural_shield_registry


def isolated_module(
    module_name: str,
    config: Optional[CircuitBreakerConfig] = None,
    fallback: Optional[Callable[..., Any]] = None
):
    """
    Decorator for isolating a module with circuit breaker and bulkhead.
    
    Usage:
        @isolated_module("prompt_injection_detector")
        def detect_injection(prompt: str) -> dict:
            # detection logic
            pass
    """
    registry = get_registry()
    cb = registry.register_module(module_name, config, fallback)

    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> T:
            return cb.execute(func, *args, **kwargs)
        return wrapper

    return decorator


# Custom exception hierarchy
class ErrorResilienceError(Exception):
    """Base error for resilience module"""
    pass


class CircuitOpenError(ErrorResilienceError):
    """Raised when circuit is open and no fallback"""
    pass


class BulkheadError(ErrorResilienceError):
    """Base bulkhead error"""
    pass


class BulkheadRejectedError(BulkheadError):
    """Raised when bulkhead queue is full"""
    pass


class BulkheadTimeoutError(BulkheadError):
    """Raised when waiting in bulkhead queue times out"""
    pass


# Default safe fallbacks
def empty_dict_fallback(*args, **kwargs) -> Dict:
    """Fallback returning empty dict"""
    return {}


def none_fallback(*args, **kwargs) -> None:
    """Fallback returning None"""
    return None


def false_fallback(*args, **kwargs) -> bool:
    """Fallback returning False"""
    return False


def zero_score_fallback(*args, **kwargs) -> float:
    """Fallback returning 0.0 score"""
    return 0.0


# Export public API
__all__ = [
    'CircuitState',
    'BulkheadStatus',
    'CircuitBreakerConfig',
    'BulkheadConfig',
    'CircuitBreaker',
    'BulkheadIsolation',
    'IsolatedModuleRegistry',
    'isolated_module',
    'get_registry',
    'ErrorResilienceError',
    'CircuitOpenError',
    'BulkheadError',
    'BulkheadRejectedError',
    'BulkheadTimeoutError',
    'empty_dict_fallback',
    'none_fallback',
    'false_fallback',
    'zero_score_fallback',
]
