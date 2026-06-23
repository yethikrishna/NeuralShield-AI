"""
NeuralShield AI - Error Resilience Module v20
Adaptive Timeout with Jitter + Configurable Backoff Strategies + Circuit Breaker Integration

DIMENSION E - Error Resilience
- Custom exception hierarchies
- Adaptive timeout wrappers with jitter (prevents thundering herd)
- Multiple retry + backoff strategies (exponential, linear, fixed, fibonacci)
- Circuit breaker state management
- Bulkhead resource isolation
- Graceful degradation fallbacks

ADD-ONLY implementation - wraps existing code, no modifications
Happy path behavior 100% preserved
"""

import time
import random
import threading
import functools
import logging
from typing import Any, Callable, Dict, List, Optional, Type, Union, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
import asyncio


# Configure logging (disabled by default - OPT-IN)
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


class BackoffStrategy(Enum):
    """Supported backoff strategies for retry logic."""
    EXPONENTIAL = "exponential"
    LINEAR = "linear"
    FIXED = "fixed"
    FIBONACCI = "fibonacci"
    EXPONENTIAL_WITH_JITTER = "exponential_with_jitter"


class CircuitState(Enum):
    """Circuit breaker states."""
    CLOSED = "closed"           # Normal operation
    OPEN = "open"               # Tripped, reject requests
    HALF_OPEN = "half_open"     # Testing recovery


class ErrorResilienceError(Exception):
    """Base exception for all error resilience errors."""
    pass


class TimeoutError(ErrorResilienceError):
    """Raised when operation exceeds timeout threshold."""
    pass


class CircuitBreakerOpenError(ErrorResilienceError):
    """Raised when circuit breaker is in OPEN state."""
    pass


class MaxRetriesExceededError(ErrorResilienceError):
    """Raised when maximum retry attempts exhausted."""
    pass


class BulkheadCapacityExceededError(ErrorResilienceError):
    """Raised when bulkhead capacity is exceeded."""
    pass


@dataclass
class RetryConfig:
    """Configuration for retry behavior."""
    max_attempts: int = 3
    initial_delay: float = 0.1
    max_delay: float = 10.0
    strategy: BackoffStrategy = BackoffStrategy.EXPONENTIAL_WITH_JITTER
    jitter_factor: float = 0.5
    retry_on_exceptions: Tuple[Type[Exception], ...] = (Exception,)
    stop_on_exceptions: Tuple[Type[Exception], ...] = ()
    backoff_multiplier: float = 2.0


@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker behavior."""
    failure_threshold: int = 5
    success_threshold: int = 2
    reset_timeout: float = 30.0
    timeout_window: float = 60.0


@dataclass
class BulkheadConfig:
    """Configuration for bulkhead isolation."""
    max_concurrent: int = 10
    max_queue_size: int = 100
    queue_timeout: float = 5.0


@dataclass
class TimeoutConfig:
    """Configuration for timeout behavior."""
    timeout_seconds: float = 30.0
    jitter_percentage: float = 0.1
    adaptive: bool = True
    history_window: int = 100


class BackoffCalculator:
    """Calculates backoff delays using various strategies."""

    @staticmethod
    def calculate(attempt: int, config: RetryConfig) -> float:
        """Calculate backoff delay for given attempt number."""
        if config.strategy == BackoffStrategy.FIXED:
            delay = config.initial_delay
        
        elif config.strategy == BackoffStrategy.LINEAR:
            delay = config.initial_delay * attempt
        
        elif config.strategy == BackoffStrategy.EXPONENTIAL:
            delay = config.initial_delay * (config.backoff_multiplier ** (attempt - 1))
        
        elif config.strategy == BackoffStrategy.FIBONACCI:
            a, b = 0, config.initial_delay
            for _ in range(attempt):
                a, b = b, a + b
            delay = a
        
        elif config.strategy == BackoffStrategy.EXPONENTIAL_WITH_JITTER:
            base_delay = config.initial_delay * (config.backoff_multiplier ** (attempt - 1))
            jitter = random.uniform(
                -config.jitter_factor * base_delay,
                config.jitter_factor * base_delay
            )
            delay = max(0, base_delay + jitter)
        
        else:
            delay = config.initial_delay

        return min(delay, config.max_delay)


class AdaptiveTimeout:
    """Adaptive timeout with jitter to prevent thundering herd."""

    def __init__(self, config: Optional[TimeoutConfig] = None):
        self.config = config or TimeoutConfig()
        self._history: List[float] = []
        self._lock = threading.Lock()

    def record_success(self, duration: float) -> None:
        """Record successful operation duration for adaptive calculation."""
        with self._lock:
            self._history.append(duration)
            if len(self._history) > self.config.history_window:
                self._history.pop(0)

    def get_timeout(self) -> float:
        """Get current timeout value with optional jitter."""
        base_timeout = self.config.timeout_seconds

        if self.config.adaptive and self._history:
            with self._lock:
                avg_duration = sum(self._history) / len(self._history)
                std_dev = (sum((x - avg_duration) ** 2 for x in self._history) / len(self._history)) ** 0.5
                base_timeout = avg_duration + (3 * std_dev)

        if self.config.jitter_percentage > 0:
            jitter = random.uniform(
                -self.config.jitter_percentage * base_timeout,
                self.config.jitter_percentage * base_timeout
            )
            base_timeout = max(0.1, base_timeout + jitter)

        return base_timeout


class CircuitBreaker:
    """Circuit breaker implementation with state management."""

    def __init__(self, config: Optional[CircuitBreakerConfig] = None, name: str = "default"):
        self.config = config or CircuitBreakerConfig()
        self.name = name
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._last_failure_time = 0.0
        self._lock = threading.Lock()

    @property
    def state(self) -> CircuitState:
        """Get current circuit state."""
        return self._state

    def record_success(self) -> None:
        """Record successful operation."""
        with self._lock:
            if self._state == CircuitState.HALF_OPEN:
                self._success_count += 1
                if self._success_count >= self.config.success_threshold:
                    self._state = CircuitState.CLOSED
                    self._failure_count = 0
                    self._success_count = 0
                    logger.info(f"Circuit '{self.name}' closed - recovery successful")
            elif self._state == CircuitState.CLOSED:
                self._failure_count = 0

    def record_failure(self) -> None:
        """Record failed operation."""
        with self._lock:
            self._last_failure_time = time.time()
            
            if self._state == CircuitState.CLOSED:
                self._failure_count += 1
                if self._failure_count >= self.config.failure_threshold:
                    self._state = CircuitState.OPEN
                    logger.warning(f"Circuit '{self.name}' opened - threshold exceeded")
            
            elif self._state == CircuitState.HALF_OPEN:
                self._state = CircuitState.OPEN
                self._success_count = 0
                logger.warning(f"Circuit '{self.name}' reopened - recovery failed")

    def allow_request(self) -> bool:
        """Check if request should be allowed through."""
        with self._lock:
            if self._state == CircuitState.CLOSED:
                return True
            
            if self._state == CircuitState.OPEN:
                elapsed = time.time() - self._last_failure_time
                if elapsed >= self.config.reset_timeout:
                    self._state = CircuitState.HALF_OPEN
                    self._success_count = 0
                    logger.info(f"Circuit '{self.name}' half-open - testing recovery")
                    return True
                return False
            
            # HALF_OPEN - allow limited requests
            return True


class Bulkhead:
    """Bulkhead pattern for resource isolation."""

    def __init__(self, config: Optional[BulkheadConfig] = None, name: str = "default"):
        self.config = config or BulkheadConfig()
        self.name = name
        self._active_count = 0
        self._lock = threading.Lock()
        self._semaphore = threading.Semaphore(self.config.max_concurrent)

    @property
    def active_count(self) -> int:
        """Get current active operation count."""
        with self._lock:
            return self._active_count

    def acquire(self, timeout: Optional[float] = None) -> bool:
        """Acquire bulkhead slot."""
        acquire_timeout = timeout if timeout is not None else self.config.queue_timeout
        acquired = self._semaphore.acquire(timeout=acquire_timeout)
        
        if acquired:
            with self._lock:
                self._active_count += 1
        
        return acquired

    def release(self) -> None:
        """Release bulkhead slot."""
        with self._lock:
            if self._active_count > 0:
                self._active_count -= 1
        self._semaphore.release()


class ErrorResilienceOrchestrator:
    """Orchestrates all error resilience mechanisms."""

    _instance: Optional['ErrorResilienceOrchestrator'] = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._circuit_breakers: Dict[str, CircuitBreaker] = {}
        self._bulkheads: Dict[str, Bulkhead] = {}
        self._timeouts: Dict[str, AdaptiveTimeout] = {}
        self._global_lock = threading.Lock()
        self._initialized = True

    def get_circuit_breaker(self, name: str, config: Optional[CircuitBreakerConfig] = None) -> CircuitBreaker:
        """Get or create circuit breaker by name."""
        with self._global_lock:
            if name not in self._circuit_breakers:
                self._circuit_breakers[name] = CircuitBreaker(config, name)
            return self._circuit_breakers[name]

    def get_bulkhead(self, name: str, config: Optional[BulkheadConfig] = None) -> Bulkhead:
        """Get or create bulkhead by name."""
        with self._global_lock:
            if name not in self._bulkheads:
                self._bulkheads[name] = Bulkhead(config, name)
            return self._bulkheads[name]

    def get_timeout(self, name: str, config: Optional[TimeoutConfig] = None) -> AdaptiveTimeout:
        """Get or create adaptive timeout by name."""
        with self._global_lock:
            if name not in self._timeouts:
                self._timeouts[name] = AdaptiveTimeout(config)
            return self._timeouts[name]

    def get_status(self) -> Dict[str, Any]:
        """Get comprehensive status of all resilience components."""
        return {
            "circuit_breakers": {
                name: {
                    "state": cb.state.value,
                    "failure_count": cb._failure_count,
                    "success_count": cb._success_count
                }
                for name, cb in self._circuit_breakers.items()
            },
            "bulkheads": {
                name: {
                    "active_count": bh.active_count,
                    "max_concurrent": bh.config.max_concurrent
                }
                for name, bh in self._bulkheads.items()
            },
            "timeouts": list(self._timeouts.keys())
        }


def with_retry(
    config: Optional[RetryConfig] = None,
    fallback: Optional[Callable] = None,
    circuit_breaker_name: Optional[str] = None
):
    """
    Decorator for retry logic with configurable backoff strategies.
    
    Usage:
        @with_retry(config=RetryConfig(max_attempts=5))
        def my_function():
            ...
    """
    retry_config = config or RetryConfig()
    orchestrator = ErrorResilienceOrchestrator()

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            circuit_breaker = None
            if circuit_breaker_name:
                circuit_breaker = orchestrator.get_circuit_breaker(circuit_breaker_name)
                if not circuit_breaker.allow_request():
                    if fallback:
                        logger.warning(f"Circuit open, using fallback for {func.__name__}")
                        return fallback(*args, **kwargs)
                    raise CircuitBreakerOpenError(f"Circuit '{circuit_breaker_name}' is open")

            last_exception = None
            
            for attempt in range(1, retry_config.max_attempts + 1):
                try:
                    result = func(*args, **kwargs)
                    if circuit_breaker:
                        circuit_breaker.record_success()
                    return result
                
                except retry_config.stop_on_exceptions as e:
                    if circuit_breaker:
                        circuit_breaker.record_failure()
                    raise
                
                except retry_config.retry_on_exceptions as e:
                    last_exception = e
                    if circuit_breaker:
                        circuit_breaker.record_failure()
                    
                    if attempt < retry_config.max_attempts:
                        delay = BackoffCalculator.calculate(attempt, retry_config)
                        logger.debug(f"Retry {attempt}/{retry_config.max_attempts} for {func.__name__} in {delay:.3f}s")
                        time.sleep(delay)
                    continue

            if fallback:
                logger.warning(f"Max retries exceeded, using fallback for {func.__name__}")
                return fallback(*args, **kwargs)
            
            raise MaxRetriesExceededError(
                f"Max retries ({retry_config.max_attempts}) exceeded for {func.__name__}"
            ) from last_exception

        return wrapper
    return decorator


def with_timeout(
    timeout_seconds: float = 30.0,
    timeout_name: Optional[str] = None,
    fallback: Optional[Callable] = None
):
    """
    Decorator for timeout enforcement.
    
    Usage:
        @with_timeout(timeout_seconds=5.0)
        def my_function():
            ...
    """
    orchestrator = ErrorResilienceOrchestrator()

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            timeout = timeout_seconds
            if timeout_name:
                adaptive_timeout = orchestrator.get_timeout(timeout_name)
                timeout = adaptive_timeout.get_timeout()

            result = [None]
            exception = [None]

            def target():
                try:
                    start_time = time.time()
                    result[0] = func(*args, **kwargs)
                    duration = time.time() - start_time
                    if timeout_name:
                        adaptive_timeout.record_success(duration)
                except Exception as e:
                    exception[0] = e

            thread = threading.Thread(target=target)
            thread.daemon = True
            thread.start()
            thread.join(timeout=timeout)

            if thread.is_alive():
                if fallback:
                    logger.warning(f"Timeout exceeded, using fallback for {func.__name__}")
                    return fallback(*args, **kwargs)
                raise TimeoutError(f"Operation timed out after {timeout:.2f}s")

            if exception[0]:
                raise exception[0]

            return result[0]

        return wrapper
    return decorator


def with_bulkhead(
    bulkhead_name: str,
    config: Optional[BulkheadConfig] = None,
    fallback: Optional[Callable] = None
):
    """
    Decorator for bulkhead resource isolation.
    
    Usage:
        @with_bulkhead("database_operations")
        def my_function():
            ...
    """
    orchestrator = ErrorResilienceOrchestrator()

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            bulkhead = orchestrator.get_bulkhead(bulkhead_name, config)
            
            if not bulkhead.acquire():
                if fallback:
                    logger.warning(f"Bulkhead capacity exceeded, using fallback for {func.__name__}")
                    return fallback(*args, **kwargs)
                raise BulkheadCapacityExceededError(
                    f"Bulkhead '{bulkhead_name}' capacity exceeded"
                )

            try:
                return func(*args, **kwargs)
            finally:
                bulkhead.release()

        return wrapper
    return decorator


def with_resilience(
    retry_config: Optional[RetryConfig] = None,
    timeout_config: Optional[TimeoutConfig] = None,
    circuit_breaker_name: Optional[str] = None,
    bulkhead_name: Optional[str] = None,
    fallback: Optional[Callable] = None
):
    """
    Combined decorator applying all resilience mechanisms.
    
    Usage:
        @with_resilience(
            retry_config=RetryConfig(max_attempts=3),
            circuit_breaker_name="my_service",
            bulkhead_name="my_service"
        )
        def my_function():
            ...
    """
    def decorator(func: Callable) -> Callable:
        decorated = func
        
        if bulkhead_name:
            decorated = with_bulkhead(bulkhead_name, fallback=fallback)(decorated)
        
        if timeout_config:
            decorated = with_timeout(
                timeout_config.timeout_seconds,
                fallback=fallback
            )(decorated)
        
        if retry_config or circuit_breaker_name:
            decorated = with_retry(
                config=retry_config,
                fallback=fallback,
                circuit_breaker_name=circuit_breaker_name
            )(decorated)
        
        return decorated
    return decorator


# Async versions for asyncio compatibility
async def with_retry_async(
    func: Callable,
    config: Optional[RetryConfig] = None,
    *args, **kwargs
):
    """Async version of retry logic."""
    retry_config = config or RetryConfig()
    last_exception = None

    for attempt in range(1, retry_config.max_attempts + 1):
        try:
            return await func(*args, **kwargs)
        except retry_config.stop_on_exceptions:
            raise
        except retry_config.retry_on_exceptions as e:
            last_exception = e
            if attempt < retry_config.max_attempts:
                delay = BackoffCalculator.calculate(attempt, retry_config)
                await asyncio.sleep(delay)
            continue

    raise MaxRetriesExceededError(f"Max retries exceeded") from last_exception


# Export public API
__all__ = [
    'BackoffStrategy',
    'CircuitState',
    'ErrorResilienceError',
    'TimeoutError',
    'CircuitBreakerOpenError',
    'MaxRetriesExceededError',
    'BulkheadCapacityExceededError',
    'RetryConfig',
    'CircuitBreakerConfig',
    'BulkheadConfig',
    'TimeoutConfig',
    'BackoffCalculator',
    'AdaptiveTimeout',
    'CircuitBreaker',
    'Bulkhead',
    'ErrorResilienceOrchestrator',
    'with_retry',
    'with_timeout',
    'with_bulkhead',
    'with_resilience',
    'with_retry_async',
]
