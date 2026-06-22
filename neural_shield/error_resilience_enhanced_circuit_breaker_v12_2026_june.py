"""
NeuralShield AI - Enhanced Error Resilience Engine v12
DIMENSION E: Error Resilience - ADD-ONLY, Backward Compatible
================================================================
Custom Exception Hierarchies, Timeout Wrappers, Retry + Backoff,
Graceful Degradation Fallbacks, Circuit Breaker Pattern

All existing code behavior is 100% preserved.
This module layers ON TOP - wrap existing functions, don't replace.
"""

import time
import random
import logging
import functools
import threading
from typing import Any, Callable, Dict, List, Optional, Type, Union, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta

# -----------------------------------------------------------------------------
# CUSTOM EXCEPTION HIERARCHY
# -----------------------------------------------------------------------------

class NeuralShieldError(Exception):
    """Base exception for all NeuralShield errors"""
    error_code: str = "NS_E001"
    retryable: bool = False
    severity: str = "ERROR"
    
    def __init__(self, message: str, details: Optional[Dict] = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}
        self.timestamp = datetime.utcnow().isoformat()

class ThreatDetectionError(NeuralShieldError):
    """Threat detection subsystem errors"""
    error_code = "NS_T001"
    retryable = True

class PromptInjectionDetectionError(ThreatDetectionError):
    """Prompt injection detection specific errors"""
    error_code = "NS_T002"
    retryable = True

class ModelInferenceError(NeuralShieldError):
    """Model inference errors"""
    error_code = "NS_M001"
    retryable = True

class ModelTimeoutError(ModelInferenceError):
    """Model inference timeout"""
    error_code = "NS_M002"
    retryable = True

class ConfigurationError(NeuralShieldError):
    """Configuration errors - NOT retryable"""
    error_code = "NS_C001"
    retryable = False
    severity = "CRITICAL"

class ValidationError(NeuralShieldError):
    """Input validation errors - NOT retryable"""
    error_code = "NS_V001"
    retryable = False

class RateLimitExceededError(NeuralShieldError):
    """Rate limit exceeded - retryable with backoff"""
    error_code = "NS_R001"
    retryable = True
    severity = "WARNING"

class CircuitBreakerOpenError(NeuralShieldError):
    """Circuit breaker is open - fail fast"""
    error_code = "NS_CB001"
    retryable = False
    severity = "WARNING"

class GracefulDegradationError(NeuralShieldError):
    """Graceful degradation activated - informational"""
    error_code = "NS_GD001"
    retryable = False
    severity = "INFO"

# -----------------------------------------------------------------------------
# CIRCUIT BREAKER IMPLEMENTATION
# -----------------------------------------------------------------------------

class CircuitState(Enum):
    CLOSED = "CLOSED"           # Normal operation
    OPEN = "OPEN"               # Fail fast
    HALF_OPEN = "HALF_OPEN"     # Test recovery

@dataclass
class CircuitBreakerStats:
    success_count: int = 0
    failure_count: int = 0
    timeout_count: int = 0
    rejection_count: int = 0
    last_failure_time: Optional[datetime] = None
    last_success_time: Optional[datetime] = None
    state_transitions: List[Tuple[CircuitState, CircuitState, datetime]] = field(default_factory=list)

class CircuitBreaker:
    """
    Circuit Breaker Pattern - prevents cascading failures
    ADD-ONLY wrapper - wrap existing functions
    """
    
    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: float = 30.0,
        half_open_max_calls: int = 3,
        allowed_exceptions: Tuple[Type[Exception], ...] = (Exception,),
        name: str = "default"
    ):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.half_open_max_calls = half_open_max_calls
        self.allowed_exceptions = allowed_exceptions
        self.name = name
        
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._half_open_calls = 0
        self._open_time: Optional[datetime] = None
        self._lock = threading.RLock()
        self.stats = CircuitBreakerStats()
    
    @property
    def state(self) -> CircuitState:
        with self._lock:
            self._check_transition()
            return self._state
    
    def _check_transition(self) -> None:
        """Check if we should transition from OPEN to HALF_OPEN"""
        if self._state == CircuitState.OPEN and self._open_time:
            elapsed = (datetime.utcnow() - self._open_time).total_seconds()
            if elapsed >= self.recovery_timeout:
                self._transition_to(CircuitState.HALF_OPEN)
    
    def _transition_to(self, new_state: CircuitState) -> None:
        old_state = self._state
        self._state = new_state
        self.stats.state_transitions.append((old_state, new_state, datetime.utcnow()))
        
        if new_state == CircuitState.OPEN:
            self._open_time = datetime.utcnow()
        elif new_state == CircuitState.CLOSED:
            self._failure_count = 0
            self._half_open_calls = 0
            self._open_time = None
        elif new_state == CircuitState.HALF_OPEN:
            self._half_open_calls = 0
    
    def _on_success(self) -> None:
        self.stats.success_count += 1
        self.stats.last_success_time = datetime.utcnow()
        
        if self._state == CircuitState.HALF_OPEN:
            self._half_open_calls += 1
            if self._half_open_calls >= self.half_open_max_calls:
                self._transition_to(CircuitState.CLOSED)
        elif self._state == CircuitState.CLOSED:
            self._failure_count = 0
    
    def _on_failure(self) -> None:
        self.stats.failure_count += 1
        self.stats.last_failure_time = datetime.utcnow()
        
        if self._state == CircuitState.HALF_OPEN:
            self._transition_to(CircuitState.OPEN)
        elif self._state == CircuitState.CLOSED:
            self._failure_count += 1
            if self._failure_count >= self.failure_threshold:
                self._transition_to(CircuitState.OPEN)
    
    def can_execute(self) -> bool:
        with self._lock:
            self._check_transition()
            if self._state == CircuitState.OPEN:
                self.stats.rejection_count += 1
                return False
            return True
    
    def __call__(self, func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            with self._lock:
                if not self.can_execute():
                    raise CircuitBreakerOpenError(
                        f"Circuit breaker '{self.name}' is OPEN - failing fast",
                        {"recovery_in": self.recovery_timeout - (datetime.utcnow() - self._open_time).total_seconds() 
                         if self._open_time else 0}
                    )
            
            try:
                result = func(*args, **kwargs)
                with self._lock:
                    self._on_success()
                return result
            except self.allowed_exceptions:
                with self._lock:
                    self._on_failure()
                raise
        
        return wrapper
    
    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "name": self.name,
                "state": self._state.value,
                "failure_count": self._failure_count,
                "failure_threshold": self.failure_threshold,
                "stats": {
                    "successes": self.stats.success_count,
                    "failures": self.stats.failure_count,
                    "timeouts": self.stats.timeout_count,
                    "rejections": self.stats.rejection_count
                }
            }

# -----------------------------------------------------------------------------
# RETRY WITH EXPONENTIAL BACKOFF
# -----------------------------------------------------------------------------

class RetryStrategy(Enum):
    EXPONENTIAL = "exponential"
    FIXED = "fixed"
    LINEAR = "linear"
    RANDOM_JITTER = "random_jitter"

def retry(
    max_attempts: int = 3,
    initial_delay: float = 1.0,
    max_delay: float = 30.0,
    strategy: RetryStrategy = RetryStrategy.EXPONENTIAL,
    jitter: bool = True,
    retry_on: Tuple[Type[Exception], ...] = (Exception,),
    fallback: Optional[Callable] = None
):
    """
    Retry decorator with multiple backoff strategies
    ADD-ONLY - wrap existing functions
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None
            
            for attempt in range(max_attempts):
                try:
                    return func(*args, **kwargs)
                except retry_on as e:
                    last_exception = e
                    
                    if attempt == max_attempts - 1:
                        break
                    
                    # Calculate delay
                    if strategy == RetryStrategy.EXPONENTIAL:
                        delay = min(initial_delay * (2 ** attempt), max_delay)
                    elif strategy == RetryStrategy.LINEAR:
                        delay = min(initial_delay * (attempt + 1), max_delay)
                    elif strategy == RetryStrategy.RANDOM_JITTER:
                        delay = min(initial_delay * random.uniform(0.5, 1.5) * (2 ** attempt), max_delay)
                    else:  # FIXED
                        delay = initial_delay
                    
                    if jitter and strategy != RetryStrategy.RANDOM_JITTER:
                        delay = delay * random.uniform(0.8, 1.2)
                    
                    time.sleep(delay)
            
            # All attempts failed - use fallback if provided
            if fallback is not None:
                return fallback(*args, **kwargs)
            
            raise last_exception
        
        return wrapper
    return decorator

# -----------------------------------------------------------------------------
# TIMEOUT WRAPPER
# -----------------------------------------------------------------------------

def timeout(seconds: float, fallback: Optional[Callable] = None, exception_class: Type[Exception] = TimeoutError):
    """
    Timeout decorator using threading
    ADD-ONLY - wrap existing functions
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            result = []
            exception = []
            
            def target():
                try:
                    result.append(func(*args, **kwargs))
                except Exception as e:
                    exception.append(e)
            
            thread = threading.Thread(target=target)
            thread.daemon = True
            thread.start()
            thread.join(timeout=seconds)
            
            if thread.is_alive():
                if fallback is not None:
                    return fallback(*args, **kwargs)
                raise exception_class(f"Function timed out after {seconds}s")
            
            if exception:
                raise exception[0]
            
            return result[0] if result else None
        
        return wrapper
    return decorator

# -----------------------------------------------------------------------------
# GRACEFUL DEGRADATION FALLBACKS
# -----------------------------------------------------------------------------

class FallbackStrategy(Enum):
    RETURN_NONE = "return_none"
    RETURN_DEFAULT = "return_default"
    RETURN_CACHED = "return_cached"
    RETURN_SIMPLIFIED = "return_simplified"
    RAISE_INFO = "raise_info"

class GracefulDegradation:
    """
    Graceful Degradation Manager
    Provides fallbacks when primary systems fail
    ADD-ONLY - no changes to core logic
    """
    
    def __init__(self):
        self._fallbacks: Dict[str, Callable] = {}
        self._cache: Dict[str, Tuple[Any, datetime]] = {}
        self._cache_ttl: float = 300.0  # 5 minutes
        self._degradation_count: Dict[str, int] = {}
    
    def register_fallback(self, operation_name: str, fallback: Callable) -> None:
        self._fallbacks[operation_name] = fallback
    
    def get_cached_or_fallback(
        self,
        operation_name: str,
        primary_func: Callable,
        *args,
        default: Any = None,
        **kwargs
    ) -> Any:
        """Try primary, fall back to cache, then default"""
        try:
            result = primary_func(*args, **kwargs)
            self._cache[operation_name] = (result, datetime.utcnow())
            return result
        except Exception:
            # Try cache first
            if operation_name in self._cache:
                cached_result, cached_time = self._cache[operation_name]
                age = (datetime.utcnow() - cached_time).total_seconds()
                if age < self._cache_ttl:
                    self._increment_degradation(operation_name)
                    return cached_result
            
            # Try registered fallback
            if operation_name in self._fallbacks:
                self._increment_degradation(operation_name)
                return self._fallbacks[operation_name](*args, **kwargs)
            
            # Return default
            self._increment_degradation(operation_name)
            return default
    
    def _increment_degradation(self, operation_name: str) -> None:
        self._degradation_count[operation_name] = self._degradation_count.get(operation_name, 0) + 1
    
    def get_degradation_stats(self) -> Dict[str, Any]:
        return {
            "total_degradations": sum(self._degradation_count.values()),
            "by_operation": dict(self._degradation_count),
            "cached_items": len(self._cache)
        }

# -----------------------------------------------------------------------------
# BULKHEAD PATTERN - ISOLATE FAILURES
# -----------------------------------------------------------------------------

class Bulkhead:
    """
    Bulkhead Pattern - Isolate thread pools to prevent cascading failures
    Limits concurrent executions per operation
    ADD-ONLY wrapper
    """
    
    def __init__(self, max_concurrent: int = 10, name: str = "default"):
        self.max_concurrent = max_concurrent
        self.name = name
        self._semaphore = threading.Semaphore(max_concurrent)
        self._active_count = 0
        self._rejected_count = 0
        self._lock = threading.Lock()
    
    def __call__(self, func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            acquired = self._semaphore.acquire(blocking=False)
            
            if not acquired:
                with self._lock:
                    self._rejected_count += 1
                raise RateLimitExceededError(
                    f"Bulkhead '{self.name}' capacity exceeded ({self.max_concurrent})",
                    {"max_concurrent": self.max_concurrent}
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
    
    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "name": self.name,
                "max_concurrent": self.max_concurrent,
                "active": self._active_count,
                "rejected": self._rejected_count
            }

# -----------------------------------------------------------------------------
# GLOBAL CONVENIENCE FUNCTIONS
# -----------------------------------------------------------------------------

_DEFAULT_CIRCUIT_BREAKERS: Dict[str, CircuitBreaker] = {}
_DEFAULT_GRACEFUL = GracefulDegradation()
_DEFAULT_BULKHEADS: Dict[str, Bulkhead] = {}

def get_circuit_breaker(name: str, **kwargs) -> CircuitBreaker:
    """Get or create a named circuit breaker"""
    if name not in _DEFAULT_CIRCUIT_BREAKERS:
        _DEFAULT_CIRCUIT_BREAKERS[name] = CircuitBreaker(name=name, **kwargs)
    return _DEFAULT_CIRCUIT_BREAKERS[name]

def get_bulkhead(name: str, **kwargs) -> Bulkhead:
    """Get or create a named bulkhead"""
    if name not in _DEFAULT_BULKHEADS:
        _DEFAULT_BULKHEADS[name] = Bulkhead(name=name, **kwargs)
    return _DEFAULT_BULKHEADS[name]

def get_graceful_degradation() -> GracefulDegradation:
    """Get the global graceful degradation manager"""
    return _DEFAULT_GRACEFUL

def safe_execute(
    func: Callable,
    *args,
    timeout_sec: Optional[float] = None,
    max_retries: int = 0,
    circuit_breaker: Optional[str] = None,
    fallback: Optional[Callable] = None,
    default: Any = None,
    **kwargs
) -> Any:
    """
    One-shot safe execution with all resilience features
    ADD-ONLY convenience wrapper
    """
    @functools.wraps(func)
    def wrapped():
        return func(*args, **kwargs)
    
    if circuit_breaker:
        cb = get_circuit_breaker(circuit_breaker)
        wrapped = cb(wrapped)
    
    if max_retries > 0:
        wrapped = retry(max_attempts=max_retries + 1)(wrapped)
    
    if timeout_sec:
        wrapped = timeout(timeout_sec)(wrapped)
    
    try:
        return wrapped()
    except Exception:
        if fallback:
            return fallback(*args, **kwargs)
        return default

def get_all_resilience_stats() -> Dict[str, Any]:
    """Get combined statistics from all resilience components"""
    return {
        "circuit_breakers": {
            name: cb.get_stats()
            for name, cb in _DEFAULT_CIRCUIT_BREAKERS.items()
        },
        "bulkheads": {
            name: bh.get_stats()
            for name, bh in _DEFAULT_BULKHEADS.items()
        },
        "graceful_degradation": _DEFAULT_GRACEFUL.get_degradation_stats(),
        "timestamp": datetime.utcnow().isoformat()
    }
