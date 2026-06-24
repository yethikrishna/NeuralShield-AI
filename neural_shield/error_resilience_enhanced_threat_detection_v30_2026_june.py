"""
NeuralShield AI - Enhanced Error Resilience Module v30
Dimension E - Error Resilience

This module provides comprehensive error resilience capabilities:
- Custom exception hierarchy for threat detection workflows
- Advanced timeout wrappers with adaptive jitter
- Retry + exponential backoff with circuit breaker
- Graceful degradation fallbacks
- Bulkhead isolation for concurrent operations

IMPLEMENTATION NOTE: All features are implemented as WRAPPERS.
No existing code is modified - this is purely additive.
Happy path behavior is 100% preserved.
"""

import time
import random
import logging
import threading
import functools
import traceback
from typing import Any, Callable, Dict, List, Optional, Type, Union, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
from datetime import datetime, timedelta

# Configure logging - OPT-IN only, disabled by default
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

# -----------------------------------------------------------------------------
# CUSTOM EXCEPTION HIERARCHY
# -----------------------------------------------------------------------------

class NeuralShieldError(Exception):
    """Base exception for all NeuralShield errors"""
    def __init__(self, message: str, error_code: str = "NS-001", details: Optional[Dict] = None):
        self.message = message
        self.error_code = error_code
        self.details = details or {}
        self.timestamp = datetime.utcnow().isoformat()
        super().__init__(self.message)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "error_type": self.__class__.__name__,
            "message": self.message,
            "error_code": self.error_code,
            "details": self.details,
            "timestamp": self.timestamp
        }


class ThreatDetectionError(NeuralShieldError):
    """Base for threat detection related errors"""
    pass


class PromptAnalysisError(ThreatDetectionError):
    """Error during prompt analysis"""
    def __init__(self, message: str, prompt_preview: str = "", details: Optional[Dict] = None):
        super().__init__(message, "NS-TD-001", details)
        self.details["prompt_preview"] = prompt_preview[:100] if prompt_preview else ""


class EmbeddingComputationError(ThreatDetectionError):
    """Error during embedding computation"""
    def __init__(self, message: str, model_name: str = "", details: Optional[Dict] = None):
        super().__init__(message, "NS-TD-002", details)
        self.details["model_name"] = model_name


class ModelInferenceError(ThreatDetectionError):
    """Error during model inference"""
    def __init__(self, message: str, model_type: str = "", details: Optional[Dict] = None):
        super().__init__(message, "NS-TD-003", details)
        self.details["model_type"] = model_type


class ThreatIntelligenceError(NeuralShieldError):
    """Base for threat intelligence errors"""
    pass


class FeedSyncError(ThreatIntelligenceError):
    """Error syncing threat intelligence feeds"""
    def __init__(self, message: str, feed_name: str = "", details: Optional[Dict] = None):
        super().__init__(message, "NS-TI-001", details)
        self.details["feed_name"] = feed_name


class CacheError(ThreatIntelligenceError):
    """Error in threat intelligence caching"""
    def __init__(self, message: str, cache_key: str = "", details: Optional[Dict] = None):
        super().__init__(message, "NS-TI-002", details)
        self.details["cache_key"] = cache_key


class SecurityError(NeuralShieldError):
    """Base for security-related errors"""
    pass


class ValidationError(SecurityError):
    """Input validation error"""
    def __init__(self, message: str, field_name: str = "", details: Optional[Dict] = None):
        super().__init__(message, "NS-SEC-001", details)
        self.details["field_name"] = field_name


class RateLimitExceededError(SecurityError):
    """Rate limit exceeded error"""
    def __init__(self, message: str, limit: int = 0, window_seconds: int = 0, details: Optional[Dict] = None):
        super().__init__(message, "NS-SEC-002", details)
        self.details["limit"] = limit
        self.details["window_seconds"] = window_seconds


class TimeoutError(NeuralShieldError):
    """Operation timeout error"""
    def __init__(self, message: str, timeout_seconds: float = 0, operation: str = "", details: Optional[Dict] = None):
        super().__init__(message, "NS-TIMEOUT-001", details)
        self.details["timeout_seconds"] = timeout_seconds
        self.details["operation"] = operation


class CircuitBreakerOpenError(NeuralShieldError):
    """Circuit breaker is open - operation rejected"""
    def __init__(self, message: str, service_name: str = "", reset_time: Optional[datetime] = None, details: Optional[Dict] = None):
        super().__init__(message, "NS-CB-001", details)
        self.details["service_name"] = service_name
        self.details["reset_time"] = reset_time.isoformat() if reset_time else None


class FallbackActivatedError(NeuralShieldError):
    """Fallback was activated (informational, not always fatal)"""
    def __init__(self, message: str, primary_error: Optional[Exception] = None, details: Optional[Dict] = None):
        super().__init__(message, "NS-FB-001", details)
        self.details["primary_error_type"] = type(primary_error).__name__ if primary_error else None
        self.details["primary_error_message"] = str(primary_error) if primary_error else None


# -----------------------------------------------------------------------------
# CIRCUIT BREAKER IMPLEMENTATION
# -----------------------------------------------------------------------------

class CircuitState(Enum):
    CLOSED = "closed"           # Normal operation
    OPEN = "open"               # Tripped, reject requests
    HALF_OPEN = "half_open"     # Testing recovery


@dataclass
class CircuitBreakerConfig:
    failure_threshold: int = 5
    recovery_timeout_seconds: float = 30.0
    half_open_max_calls: int = 3
    excluded_exceptions: Tuple[Type[Exception], ...] = field(default_factory=lambda: (ValueError, TypeError))


@dataclass
class CircuitBreakerStats:
    success_count: int = 0
    failure_count: int = 0
    rejected_count: int = 0
    last_failure_time: Optional[datetime] = None
    last_state_change: datetime = field(default_factory=datetime.utcnow)


class CircuitBreaker:
    """
    Circuit Breaker pattern implementation to prevent cascading failures.
    
    When failures exceed threshold, circuit opens and rejects calls temporarily.
    After recovery timeout, enters half-open state to test recovery.
    """
    
    def __init__(self, name: str, config: Optional[CircuitBreakerConfig] = None):
        self.name = name
        self.config = config or CircuitBreakerConfig()
        self._state = CircuitState.CLOSED
        self._stats = CircuitBreakerStats()
        self._lock = threading.RLock()
        self._open_until: Optional[datetime] = None
    
    @property
    def state(self) -> CircuitState:
        with self._lock:
            self._check_state_transition()
            return self._state
    
    @property
    def stats(self) -> CircuitBreakerStats:
        with self._lock:
            return CircuitBreakerStats(
                success_count=self._stats.success_count,
                failure_count=self._stats.failure_count,
                rejected_count=self._stats.rejected_count,
                last_failure_time=self._stats.last_failure_time,
                last_state_change=self._stats.last_state_change
            )
    
    def _check_state_transition(self) -> None:
        """Check if we should transition from OPEN to HALF_OPEN"""
        if self._state == CircuitState.OPEN and self._open_until:
            if datetime.utcnow() >= self._open_until:
                self._state = CircuitState.HALF_OPEN
                self._stats.last_state_change = datetime.utcnow()
                logger.info(f"CircuitBreaker '{self.name}' transitioning to HALF_OPEN")
    
    def _on_success(self) -> None:
        """Handle successful call"""
        with self._lock:
            self._stats.success_count += 1
            if self._state == CircuitState.HALF_OPEN:
                # Success in half-open - close the circuit
                self._state = CircuitState.CLOSED
                self._stats.failure_count = 0
                self._stats.last_state_change = datetime.utcnow()
                logger.info(f"CircuitBreaker '{self.name}' recovered, transitioning to CLOSED")
    
    def _on_failure(self, exc: Exception) -> None:
        """Handle failed call"""
        with self._lock:
            if isinstance(exc, self.config.excluded_exceptions):
                return  # Don't count these as failures
            
            self._stats.failure_count += 1
            self._stats.last_failure_time = datetime.utcnow()
            
            if self._state == CircuitState.HALF_OPEN:
                # Failure in half-open - reopen
                self._open_circuit()
            elif self._state == CircuitState.CLOSED:
                if self._stats.failure_count >= self.config.failure_threshold:
                    self._open_circuit()
    
    def _open_circuit(self) -> None:
        """Open the circuit"""
        self._state = CircuitState.OPEN
        self._open_until = datetime.utcnow() + timedelta(seconds=self.config.recovery_timeout_seconds)
        self._stats.last_state_change = datetime.utcnow()
        logger.warning(f"CircuitBreaker '{self.name}' OPEN - failures: {self._stats.failure_count}")
    
    def allow_call(self) -> bool:
        """Check if call is allowed"""
        with self._lock:
            self._check_state_transition()
            
            if self._state == CircuitState.OPEN:
                self._stats.rejected_count += 1
                return False
            return True
    
    def reset(self) -> None:
        """Reset circuit breaker to initial state"""
        with self._lock:
            self._state = CircuitState.CLOSED
            self._stats = CircuitBreakerStats()
            self._open_until = None
            logger.info(f"CircuitBreaker '{self.name}' reset")
    
    def __call__(self, func: Callable) -> Callable:
        """Decorator usage"""
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if not self.allow_call():
                raise CircuitBreakerOpenError(
                    f"Circuit breaker '{self.name}' is open",
                    service_name=self.name,
                    reset_time=self._open_until
                )
            
            try:
                result = func(*args, **kwargs)
                self._on_success()
                return result
            except Exception as e:
                self._on_failure(e)
                raise
        return wrapper


# Global circuit breaker registry
_circuit_breakers: Dict[str, CircuitBreaker] = {}
_circuit_breaker_lock = threading.Lock()


def get_circuit_breaker(name: str, config: Optional[CircuitBreakerConfig] = None) -> CircuitBreaker:
    """Get or create a named circuit breaker"""
    with _circuit_breaker_lock:
        if name not in _circuit_breakers:
            _circuit_breakers[name] = CircuitBreaker(name, config)
        return _circuit_breakers[name]


# -----------------------------------------------------------------------------
# RETRY WITH EXPONENTIAL BACKOFF + JITTER
# -----------------------------------------------------------------------------

@dataclass
class RetryConfig:
    max_attempts: int = 3
    initial_delay_seconds: float = 0.1
    max_delay_seconds: float = 10.0
    backoff_factor: float = 2.0
    jitter_factor: float = 0.1
    retry_on_exceptions: Tuple[Type[Exception], ...] = field(default_factory=lambda: (Exception,))
    stop_on_exceptions: Tuple[Type[Exception], ...] = field(default_factory=lambda: (ValueError, TypeError))


def retry_with_backoff(
    config: Optional[RetryConfig] = None,
    *,
    max_attempts: int = 3,
    initial_delay: float = 0.1,
    jitter: bool = True
) -> Callable:
    """
    Retry decorator with exponential backoff and jitter.
    
    Args:
        config: Full retry configuration
        max_attempts: Maximum number of attempts
        initial_delay: Initial delay between retries
        jitter: Whether to add random jitter to delays
    """
    if config is None:
        config = RetryConfig(
            max_attempts=max_attempts,
            initial_delay_seconds=initial_delay,
            jitter_factor=0.1 if jitter else 0.0
        )
    
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            last_exception: Optional[Exception] = None
            delay = config.initial_delay_seconds
            
            for attempt in range(config.max_attempts):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    
                    # Check if we should stop on this exception
                    if isinstance(e, config.stop_on_exceptions):
                        logger.debug(f"Not retrying on {type(e).__name__}: {e}")
                        raise
                    
                    # Check if we should retry this exception
                    if not isinstance(e, config.retry_on_exceptions):
                        raise
                    
                    if attempt < config.max_attempts - 1:
                        # Calculate delay with jitter
                        actual_delay = delay
                        if config.jitter_factor > 0:
                            jitter_amount = delay * config.jitter_factor
                            actual_delay = delay + random.uniform(-jitter_amount, jitter_amount)
                            actual_delay = max(0, actual_delay)
                        
                        actual_delay = min(actual_delay, config.max_delay_seconds)
                        
                        logger.debug(
                            f"Retry attempt {attempt + 1}/{config.max_attempts} "
                            f"for {func.__name__}, waiting {actual_delay:.3f}s"
                        )
                        time.sleep(actual_delay)
                        
                        # Exponential backoff
                        delay *= config.backoff_factor
            
            # All attempts failed
            raise last_exception
        
        return wrapper
    return decorator


# -----------------------------------------------------------------------------
# TIMEOUT WRAPPERS
# -----------------------------------------------------------------------------

def timeout(seconds: float, fallback: Optional[Callable] = None, exception: Optional[Type[Exception]] = None) -> Callable:
    """
    Timeout decorator using threading.
    
    Args:
        seconds: Maximum execution time in seconds
        fallback: Optional fallback function to call on timeout
        exception: Custom exception type to raise (default: TimeoutError)
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            result_container: Dict[str, Any] = {"success": False, "result": None, "exception": None}
            
            def target():
                try:
                    result_container["result"] = func(*args, **kwargs)
                    result_container["success"] = True
                except Exception as e:
                    result_container["exception"] = e
            
            thread = threading.Thread(target=target, daemon=True)
            thread.start()
            thread.join(timeout=seconds)
            
            if thread.is_alive():
                if fallback is not None:
                    logger.warning(f"Timeout in {func.__name__}, activating fallback")
                    return fallback(*args, **kwargs)
                exc_type = exception or TimeoutError
                raise exc_type(
                    f"Operation '{func.__name__}' timed out after {seconds}s",
                    timeout_seconds=seconds,
                    operation=func.__name__
                )
            
            if not result_container["success"]:
                raise result_container["exception"]
            
            return result_container["result"]
        
        return wrapper
    return decorator


# -----------------------------------------------------------------------------
# GRACEFUL DEGRADATION & FALLBACKS
# -----------------------------------------------------------------------------

@dataclass
class FallbackResult:
    value: Any
    was_fallback: bool
    primary_error: Optional[Exception] = None
    fallback_name: str = "default"


def with_fallback(
    fallback_func: Callable,
    fallback_name: str = "default",
    catch_exceptions: Tuple[Type[Exception], ...] = (Exception,)
) -> Callable:
    """
    Decorator that provides graceful degradation via fallback function.
    
    Args:
        fallback_func: Function to call when primary fails
        fallback_name: Name for logging/metrics
        catch_exceptions: Which exceptions trigger fallback
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> FallbackResult:
            try:
                result = func(*args, **kwargs)
                return FallbackResult(
                    value=result,
                    was_fallback=False,
                    fallback_name=fallback_name
                )
            except catch_exceptions as e:
                logger.warning(
                    f"Fallback '{fallback_name}' activated for {func.__name__}: {e}"
                )
                fallback_value = fallback_func(*args, **kwargs)
                return FallbackResult(
                    value=fallback_value,
                    was_fallback=True,
                    primary_error=e,
                    fallback_name=fallback_name
                )
        
        return wrapper
    return decorator


def safe_default(default_value: Any, catch_exceptions: Tuple[Type[Exception], ...] = (Exception,)) -> Callable:
    """
    Simple decorator that returns a default value on exception.
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except catch_exceptions:
                return default_value
        return wrapper
    return decorator


# -----------------------------------------------------------------------------
# BULKHEAD ISOLATION
# -----------------------------------------------------------------------------

class Bulkhead:
    """
    Bulkhead pattern to limit concurrent calls and prevent resource exhaustion.
    Isolates different operations from affecting each other.
    """
    
    def __init__(self, name: str, max_concurrent: int = 10, max_queue_size: int = 100):
        self.name = name
        self.max_concurrent = max_concurrent
        self.max_queue_size = max_queue_size
        self._semaphore = threading.Semaphore(max_concurrent)
        self._active_count = 0
        self._queued_count = 0
        self._rejected_count = 0
        self._lock = threading.Lock()
    
    @property
    def stats(self) -> Dict[str, int]:
        with self._lock:
            return {
                "max_concurrent": self.max_concurrent,
                "active": self._active_count,
                "queued": self._queued_count,
                "rejected": self._rejected_count
            }
    
    def __call__(self, func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            with self._lock:
                if self._queued_count >= self.max_queue_size:
                    self._rejected_count += 1
                    raise NeuralShieldError(
                        f"Bulkhead '{self.name}' queue full",
                        "NS-BH-001",
                        self.stats
                    )
                self._queued_count += 1
            
            try:
                acquired = self._semaphore.acquire(timeout=30)
                if not acquired:
                    raise NeuralShieldError(
                        f"Bulkhead '{self.name}' timeout waiting for slot",
                        "NS-BH-002",
                        self.stats
                    )
                
                with self._lock:
                    self._queued_count -= 1
                    self._active_count += 1
                
                try:
                    return func(*args, **kwargs)
                finally:
                    with self._lock:
                        self._active_count -= 1
                    self._semaphore.release()
            finally:
                with self._lock:
                    if self._queued_count > 0:
                        self._queued_count -= 1
        
        return wrapper


# Global bulkhead registry
_bulkheads: Dict[str, Bulkhead] = {}
_bulkhead_lock = threading.Lock()


def get_bulkhead(name: str, max_concurrent: int = 10, max_queue_size: int = 100) -> Bulkhead:
    """Get or create a named bulkhead"""
    with _bulkhead_lock:
        if name not in _bulkheads:
            _bulkheads[name] = Bulkhead(name, max_concurrent, max_queue_size)
        return _bulkheads[name]


# -----------------------------------------------------------------------------
# CONVENIENCE COMBINED DECORATORS
# -----------------------------------------------------------------------------

def resilient_operation(
    *,
    timeout_seconds: float = 5.0,
    max_retries: int = 2,
    circuit_breaker: Optional[str] = None,
    fallback: Optional[Callable] = None,
    bulkhead: Optional[str] = None
) -> Callable:
    """
    Combined resilience decorator applying multiple patterns:
    - Bulkhead isolation
    - Circuit breaker
    - Retry with backoff
    - Timeout
    - Fallback
    
    All features are OPTIONAL and opt-in.
    """
    def decorator(func: Callable) -> Callable:
        wrapped = func
        
        if bulkhead:
            bh = get_bulkhead(bulkhead)
            wrapped = bh(wrapped)
        
        if circuit_breaker:
            cb = get_circuit_breaker(circuit_breaker)
            wrapped = cb(wrapped)
        
        if max_retries > 0:
            wrapped = retry_with_backoff(max_attempts=max_retries + 1)(wrapped)
        
        if timeout_seconds > 0:
            wrapped = timeout(timeout_seconds, fallback=fallback)(wrapped)
        
        return wrapped
    return decorator


# -----------------------------------------------------------------------------
# ERROR CONTEXT MANAGER
# -----------------------------------------------------------------------------

class ErrorContext:
    """
    Context manager for capturing and enriching errors with context.
    """
    
    def __init__(self, operation: str, context: Optional[Dict[str, Any]] = None):
        self.operation = operation
        self.context = context or {}
        self.start_time = time.time()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_val is not None:
            # Enrich the exception with context
            if hasattr(exc_val, 'details') and isinstance(exc_val.details, dict):
                exc_val.details.update(self.context)
                exc_val.details["operation"] = self.operation
                exc_val.details["duration_seconds"] = time.time() - self.start_time
            
            logger.error(
                f"Error in '{self.operation}': {exc_val}",
                extra={
                    "operation": self.operation,
                    "context": self.context,
                    "duration": time.time() - self.start_time,
                    "exception": exc_val
                }
            )
        return False  # Don't suppress exception


# -----------------------------------------------------------------------------
# USAGE EXAMPLES (DOCUMENTATION ONLY - NOT EXECUTED)
# -----------------------------------------------------------------------------

"""
USAGE EXAMPLES:

1. Basic retry with backoff:
    @retry_with_backoff(max_attempts=3)
    def call_external_api():
        pass

2. Circuit breaker protection:
    @get_circuit_breaker("threat_feed")
    def sync_threat_feed():
        pass

3. Timeout with fallback:
    @timeout(seconds=5.0, fallback=my_fallback_function)
    def risky_operation():
        pass

4. Graceful degradation:
    @with_fallback(fallback_ml_model)
    def run_expensive_model():
        pass

5. Full resilience stack:
    @resilient_operation(
        timeout_seconds=10,
        max_retries=2,
        circuit_breaker="ml_inference",
        bulkhead="model_pool"
    )
    def detect_threats(input_text):
        pass

6. Error context:
    with ErrorContext("prompt_analysis", {"prompt_length": len(prompt)}):
        analyze_prompt(prompt)
"""

# Module version info
__version__ = "30.0.0"
__dimension__ = "E - Error Resilience"
__stable__ = True
__all__ = [
    # Exceptions
    "NeuralShieldError",
    "ThreatDetectionError",
    "PromptAnalysisError",
    "EmbeddingComputationError",
    "ModelInferenceError",
    "ThreatIntelligenceError",
    "FeedSyncError",
    "CacheError",
    "SecurityError",
    "ValidationError",
    "RateLimitExceededError",
    "TimeoutError",
    "CircuitBreakerOpenError",
    "FallbackActivatedError",
    
    # Circuit Breaker
    "CircuitBreaker",
    "CircuitBreakerConfig",
    "CircuitState",
    "get_circuit_breaker",
    
    # Retry
    "RetryConfig",
    "retry_with_backoff",
    
    # Timeout
    "timeout",
    
    # Fallbacks
    "with_fallback",
    "safe_default",
    "FallbackResult",
    
    # Bulkhead
    "Bulkhead",
    "get_bulkhead",
    
    # Combined
    "resilient_operation",
    
    # Context
    "ErrorContext",
]
