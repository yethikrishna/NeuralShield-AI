"""
NeuralShield Error Resilience Framework v13 - June 22, 2026
Comprehensive error handling, retry logic, circuit breakers, and graceful degradation

DIMENSION E - Error Resilience Implementation
- Custom exception hierarchies
- Timeout wrappers (sync + async)
- Retry + exponential backoff + jitter
- Circuit breaker pattern
- Graceful degradation fallbacks
- Bulkhead pattern for resource isolation
- 100% backward compatible - wrap existing code, no modifications
"""

import asyncio
import functools
import time
import random
import logging
import threading
from typing import Any, Callable, Optional, TypeVar, Tuple, Dict, List, Union
from dataclasses import dataclass, field
from enum import Enum
from collections import deque
from datetime import datetime, timedelta

# Configure logging - OPT-IN only, disabled by default
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

# Type variables for decorators
T = TypeVar('T')
R = TypeVar('R')

# ============================================================================
# CUSTOM EXCEPTION HIERARCHY
# ============================================================================

class NeuralShieldError(Exception):
    """Base exception for all NeuralShield errors"""
    def __init__(self, message: str, code: str = "NS_ERR_UNKNOWN", details: Dict = None):
        super().__init__(message)
        self.message = message
        self.code = code
        self.details = details or {}
        self.timestamp = datetime.utcnow().isoformat()

class SecurityError(NeuralShieldError):
    """Security-related errors"""
    pass

class ThreatDetectionError(SecurityError):
    """Errors during threat detection"""
    pass

class ModelInferenceError(NeuralShieldError):
    """Errors during model inference"""
    pass

class ValidationError(NeuralShieldError):
    """Input validation errors"""
    pass

class RateLimitError(NeuralShieldError):
    """Rate limiting errors"""
    pass

class TimeoutError(NeuralShieldError):
    """Operation timeout errors"""
    pass

class CircuitBreakerOpenError(NeuralShieldError):
    """Circuit breaker is open"""
    pass

class ResourceExhaustedError(NeuralShieldError):
    """Resource exhaustion errors"""
    pass

class ConfigurationError(NeuralShieldError):
    """Configuration errors"""
    pass

class DependencyError(NeuralShieldError):
    """External dependency errors"""
    pass

# ============================================================================
# RETRY STRATEGY ENUM
# ============================================================================

class RetryStrategy(Enum):
    EXPONENTIAL = "exponential"
    LINEAR = "linear"
    FIXED = "fixed"
    RANDOM = "random"

# ============================================================================
# CIRCUIT BREAKER STATE
# ============================================================================

class CircuitState(Enum):
    CLOSED = "closed"      # Normal operation
    OPEN = "open"          # Tripped, fail fast
    HALF_OPEN = "half_open"  # Testing recovery

# ============================================================================
# BACKOFF UTILITIES
# ============================================================================

@dataclass
class RetryConfig:
    max_attempts: int = 3
    initial_delay: float = 0.1
    max_delay: float = 10.0
    strategy: RetryStrategy = RetryStrategy.EXPONENTIAL
    jitter: bool = True
    retry_on_exceptions: Tuple[Exception, ...] = field(default_factory=lambda: (Exception,))
    fallback_value: Optional[Any] = None

def calculate_backoff(attempt: int, config: RetryConfig) -> float:
    """Calculate backoff delay based on strategy"""
    if config.strategy == RetryStrategy.EXPONENTIAL:
        delay = config.initial_delay * (2 ** attempt)
    elif config.strategy == RetryStrategy.LINEAR:
        delay = config.initial_delay * (attempt + 1)
    elif config.strategy == RetryStrategy.FIXED:
        delay = config.initial_delay
    elif config.strategy == RetryStrategy.RANDOM:
        delay = config.initial_delay * random.random()
    else:
        delay = config.initial_delay
    
    delay = min(delay, config.max_delay)
    
    if config.jitter:
        delay = delay * (0.5 + random.random())
    
    return delay

# ============================================================================
# SYNCHRONOUS RETRY DECORATOR
# ============================================================================

def retry(config: Optional[RetryConfig] = None) -> Callable:
    """
    Retry decorator with exponential backoff
    
    Usage:
        @retry(RetryConfig(max_attempts=3))
        def my_function():
            ...
    """
    if config is None:
        config = RetryConfig()
    
    def decorator(func: Callable[[Any], T]) -> Callable[[Any], T]:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> T:
            last_exception = None
            
            for attempt in range(config.max_attempts):
                try:
                    return func(*args, **kwargs)
                except config.retry_on_exceptions as e:
                    last_exception = e
                    if attempt < config.max_attempts - 1:
                        delay = calculate_backoff(attempt, config)
                        logger.warning(f"Attempt {attempt + 1} failed, retrying in {delay:.2f}s: {e}")
                        time.sleep(delay)
                    continue
            
            if config.fallback_value is not None:
                logger.warning(f"All {config.max_attempts} attempts failed, using fallback")
                return config.fallback_value
            
            raise last_exception
        
        return wrapper
    return decorator

# ============================================================================
# ASYNCHRONOUS RETRY DECORATOR
# ============================================================================

def async_retry(config: Optional[RetryConfig] = None) -> Callable:
    """Async version of retry decorator"""
    if config is None:
        config = RetryConfig()
    
    def decorator(func: Callable[[Any], T]) -> Callable[[Any], T]:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs) -> T:
            last_exception = None
            
            for attempt in range(config.max_attempts):
                try:
                    return await func(*args, **kwargs)
                except config.retry_on_exceptions as e:
                    last_exception = e
                    if attempt < config.max_attempts - 1:
                        delay = calculate_backoff(attempt, config)
                        logger.warning(f"Attempt {attempt + 1} failed, retrying in {delay:.2f}s: {e}")
                        await asyncio.sleep(delay)
                    continue
            
            if config.fallback_value is not None:
                logger.warning(f"All {config.max_attempts} attempts failed, using fallback")
                return config.fallback_value
            
            raise last_exception
        
        return wrapper
    return decorator

# ============================================================================
# SYNCHRONOUS TIMEOUT DECORATOR
# ============================================================================

def timeout(seconds: float, fallback: Optional[Any] = None) -> Callable:
    """
    Timeout decorator for synchronous functions
    
    Usage:
        @timeout(5.0, fallback=default_value)
        def my_function():
            ...
    """
    def decorator(func: Callable[[Any], T]) -> Callable[[Any], T]:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> T:
            result = [None]
            exception = [None]
            
            def target():
                try:
                    result[0] = func(*args, **kwargs)
                except Exception as e:
                    exception[0] = e
            
            thread = threading.Thread(target=target)
            thread.daemon = True
            thread.start()
            thread.join(timeout=seconds)
            
            if thread.is_alive():
                logger.warning(f"Function {func.__name__} timed out after {seconds}s")
                if fallback is not None:
                    return fallback
                raise TimeoutError(
                    f"Operation timed out after {seconds} seconds",
                    code="NS_ERR_TIMEOUT"
                )
            
            if exception[0] is not None:
                raise exception[0]
            
            return result[0]
        
        return wrapper
    return decorator

# ============================================================================
# ASYNCHRONOUS TIMEOUT DECORATOR
# ============================================================================

def async_timeout(seconds: float, fallback: Optional[Any] = None) -> Callable:
    """Async version of timeout decorator"""
    def decorator(func: Callable[[Any], T]) -> Callable[[Any], T]:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs) -> T:
            try:
                return await asyncio.wait_for(func(*args, **kwargs), timeout=seconds)
            except asyncio.TimeoutError:
                logger.warning(f"Function {func.__name__} timed out after {seconds}s")
                if fallback is not None:
                    return fallback
                raise TimeoutError(
                    f"Operation timed out after {seconds} seconds",
                    code="NS_ERR_TIMEOUT"
                )
        
        return wrapper
    return decorator

# ============================================================================
# CIRCUIT BREAKER IMPLEMENTATION
# ============================================================================

@dataclass
class CircuitBreakerConfig:
    failure_threshold: int = 5
    recovery_timeout: float = 30.0
    half_open_max_calls: int = 3
    reset_timeout: float = 60.0

class CircuitBreaker:
    """
    Circuit Breaker pattern implementation
    
    Prevents cascading failures by failing fast when a dependency is unhealthy
    """
    
    def __init__(self, config: Optional[CircuitBreakerConfig] = None, name: str = "default"):
        self.config = config or CircuitBreakerConfig()
        self.name = name
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._last_failure_time: Optional[float] = None
        self._lock = threading.RLock()
    
    @property
    def state(self) -> CircuitState:
        with self._lock:
            self._check_state_transition()
            return self._state
    
    def _check_state_transition(self):
        """Check if we should transition states"""
        now = time.time()
        
        if self._state == CircuitState.OPEN:
            if (self._last_failure_time and 
                now - self._last_failure_time > self.config.recovery_timeout):
                self._state = CircuitState.HALF_OPEN
                self._success_count = 0
                logger.info(f"Circuit breaker '{self.name}' transitioning to HALF_OPEN")
        
        elif self._state == CircuitState.CLOSED:
            if (self._last_failure_time and 
                now - self._last_failure_time > self.config.reset_timeout):
                self._failure_count = 0
    
    def record_success(self):
        """Record a successful call"""
        with self._lock:
            if self._state == CircuitState.HALF_OPEN:
                self._success_count += 1
                if self._success_count >= self.config.half_open_max_calls:
                    self._state = CircuitState.CLOSED
                    self._failure_count = 0
                    self._success_count = 0
                    logger.info(f"Circuit breaker '{self.name}' recovered, transitioning to CLOSED")
            else:
                self._failure_count = max(0, self._failure_count - 1)
    
    def record_failure(self):
        """Record a failed call"""
        with self._lock:
            self._failure_count += 1
            self._last_failure_time = time.time()
            
            if self._state == CircuitState.CLOSED:
                if self._failure_count >= self.config.failure_threshold:
                    self._state = CircuitState.OPEN
                    logger.warning(f"Circuit breaker '{self.name}' tripped, transitioning to OPEN")
            
            elif self._state == CircuitState.HALF_OPEN:
                self._state = CircuitState.OPEN
                logger.warning(f"Circuit breaker '{self.name}' failed in HALF_OPEN, returning to OPEN")
    
    def can_execute(self) -> bool:
        """Check if execution is allowed"""
        with self._lock:
            self._check_state_transition()
            return self._state != CircuitState.OPEN
    
    def __call__(self, fallback: Optional[Any] = None) -> Callable:
        """Decorator factory"""
        def decorator(func: Callable[[Any], T]) -> Callable[[Any], T]:
            @functools.wraps(func)
            def wrapper(*args, **kwargs) -> T:
                if not self.can_execute():
                    if fallback is not None:
                        return fallback
                    raise CircuitBreakerOpenError(
                        f"Circuit breaker '{self.name}' is open",
                        code="NS_ERR_CIRCUIT_OPEN"
                    )
                
                try:
                    result = func(*args, **kwargs)
                    self.record_success()
                    return result
                except Exception as e:
                    self.record_failure()
                    raise e
            
            return wrapper
        return decorator

# ============================================================================
# GRACEFUL DEGRADATION
# ============================================================================

@dataclass
class FallbackStrategy:
    primary: Callable
    fallbacks: List[Tuple[Callable, Optional[List[Exception]]]]
    default_value: Optional[Any] = None

def graceful_degradation(strategy: FallbackStrategy) -> Callable:
    """
    Graceful degradation decorator - try primary, then fallbacks in order
    
    Usage:
        @graceful_degradation(FallbackStrategy(
            primary=primary_function,
            fallbacks=[
                (simplified_fallback, [ConnectionError, TimeoutError]),
                (cache_fallback, None),
            ],
            default_value=default_result
        ))
        def my_function():
            ...
    """
    def decorator(func: Callable[[Any], T]) -> Callable[[Any], T]:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> T:
            # Try primary first
            try:
                return func(*args, **kwargs)
            except Exception as e:
                logger.warning(f"Primary function failed: {e}")
            
            # Try each fallback
            for fallback_func, catch_exceptions in strategy.fallbacks:
                try:
                    result = fallback_func(*args, **kwargs)
                    logger.info(f"Used fallback: {fallback_func.__name__}")
                    return result
                except Exception as e:
                    if catch_exceptions is None or isinstance(e, tuple(catch_exceptions)):
                        logger.warning(f"Fallback {fallback_func.__name__} failed: {e}")
                        continue
                    raise
            
            # Return default value if all else fails
            if strategy.default_value is not None:
                logger.warning("All fallbacks failed, using default value")
                return strategy.default_value
            
            raise NeuralShieldError(
                "All fallbacks exhausted and no default value provided",
                code="NS_ERR_ALL_FALLBACKS_EXHAUSTED"
            )
        
        return wrapper
    return decorator

# ============================================================================
# BULKHEAD PATTERN - RESOURCE ISOLATION
# ============================================================================

class Bulkhead:
    """
    Bulkhead pattern - isolate resources to prevent cascading failures
    
    Limits concurrent calls to a resource
    """
    
    def __init__(self, max_concurrent: int = 10, name: str = "default"):
        self.max_concurrent = max_concurrent
        self.name = name
        self._semaphore = threading.Semaphore(max_concurrent)
        self._active_count = 0
        self._lock = threading.Lock()
    
    @property
    def active_count(self) -> int:
        with self._lock:
            return self._active_count
    
    @property
    def available(self) -> int:
        return self.max_concurrent - self.active_count
    
    def __call__(self, timeout: float = 5.0, fallback: Optional[Any] = None) -> Callable:
        def decorator(func: Callable[[Any], T]) -> Callable[[Any], T]:
            @functools.wraps(func)
            def wrapper(*args, **kwargs) -> T:
                acquired = self._semaphore.acquire(timeout=timeout)
                
                if not acquired:
                    if fallback is not None:
                        return fallback
                    raise ResourceExhaustedError(
                        f"Bulkhead '{self.name}' capacity exceeded ({self.max_concurrent} concurrent)",
                        code="NS_ERR_BULKHEAD_FULL"
                    )
                
                try:
                    with self._lock:
                        self._active_count += 1
                    return func(*args, **kwargs)
                finally:
                    with self._lock:
                        self._active_count -= 1
                    self._semaphore.release()
            
            return wrapper
        return decorator

# ============================================================================
# ERROR WRAPPER - SAFE EXECUTION
# ============================================================================

class SafeExecutor:
    """
    Safe execution wrapper - catches all exceptions and returns structured results
    
    Usage:
        result = SafeExecutor.execute(risky_function, arg1, arg2)
        if result.success:
            process(result.value)
        else:
            handle_error(result.error)
    """
    
    @dataclass
    class Result:
        success: bool
        value: Any = None
        error: Optional[Exception] = None
        execution_time: float = 0.0
    
    @staticmethod
    def execute(func: Callable[[Any], T], *args, **kwargs) -> Result:
        """Execute function safely and return structured result"""
        start = time.perf_counter()
        try:
            value = func(*args, **kwargs)
            elapsed = time.perf_counter() - start
            return SafeExecutor.Result(True, value=value, execution_time=elapsed)
        except Exception as e:
            elapsed = time.perf_counter() - start
            return SafeExecutor.Result(False, error=e, execution_time=elapsed)
    
    @staticmethod
    async def execute_async(func: Callable[[Any], T], *args, **kwargs) -> Result:
        """Async version of safe execute"""
        start = time.perf_counter()
        try:
            value = await func(*args, **kwargs)
            elapsed = time.perf_counter() - start
            return SafeExecutor.Result(True, value=value, execution_time=elapsed)
        except Exception as e:
            elapsed = time.perf_counter() - start
            return SafeExecutor.Result(False, error=e, execution_time=elapsed)

# ============================================================================
# CONVENIENCE FACTORY METHODS
# ============================================================================

def create_robust_executor(
    max_retries: int = 3,
    timeout_seconds: float = 10.0,
    circuit_failure_threshold: int = 5,
    bulkhead_capacity: int = 10,
    name: str = "default"
) -> Tuple[CircuitBreaker, Bulkhead]:
    """
    Create a complete robustness suite
    
    Returns circuit breaker and bulkhead ready to use
    """
    cb = CircuitBreaker(
        CircuitBreakerConfig(failure_threshold=circuit_failure_threshold),
        name=name
    )
    bh = Bulkhead(max_concurrent=bulkhead_capacity, name=name)
    return cb, bh

# ============================================================================
# MODULE EXPORTS
# ============================================================================

__all__ = [
    # Exceptions
    'NeuralShieldError',
    'SecurityError',
    'ThreatDetectionError',
    'ModelInferenceError',
    'ValidationError',
    'RateLimitError',
    'TimeoutError',
    'CircuitBreakerOpenError',
    'ResourceExhaustedError',
    'ConfigurationError',
    'DependencyError',
    
    # Strategies
    'RetryStrategy',
    'CircuitState',
    
    # Configs
    'RetryConfig',
    'CircuitBreakerConfig',
    'FallbackStrategy',
    
    # Decorators
    'retry',
    'async_retry',
    'timeout',
    'async_timeout',
    'graceful_degradation',
    
    # Classes
    'CircuitBreaker',
    'Bulkhead',
    'SafeExecutor',
    
    # Utilities
    'calculate_backoff',
    'create_robust_executor',
]
