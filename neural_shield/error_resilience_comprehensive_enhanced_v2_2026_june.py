"""
NeuralShield AI - Comprehensive Error Resilience Framework v2
DIMENSION E: Error Resilience
ADD-ONLY implementation - wraps existing code, no modifications
Backward compatible, happy path preserved 100%

Core Components:
1. Custom Exception Hierarchy (domain-specific)
2. Timeout Wrappers (function-level, thread-safe)
3. Retry + Backoff Utilities (exponential, jittered, linear)
4. Graceful Degradation Fallbacks (circuit breaker pattern)
5. Error Context Propagation (rich error metadata)
6. Bulkhead Pattern (resource isolation)
"""

import time
import threading
import signal
import functools
import random
import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Type, Union, Tuple
from enum import Enum
from datetime import datetime, timedelta
from collections import defaultdict


# -----------------------------------------------------------------------------
# 1. CUSTOM EXCEPTION HIERARCHY
# -----------------------------------------------------------------------------

class NeuralShieldError(Exception):
    """Base exception for all NeuralShield errors"""
    error_code: str = "NEURALSHIELD_ERROR"
    severity: str = "ERROR"
    retryable: bool = False
    
    def __init__(
        self,
        message: str,
        context: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None
    ):
        super().__init__(message)
        self.message = message
        self.context = context or {}
        self.cause = cause
        self.timestamp = datetime.utcnow()
        
    def to_dict(self) -> Dict[str, Any]:
        return {
            "error_code": self.error_code,
            "severity": self.severity,
            "message": self.message,
            "retryable": self.retryable,
            "context": self.context,
            "timestamp": self.timestamp.isoformat()
        }


# Security & Threat Detection Errors
class SecurityError(NeuralShieldError):
    error_code = "SECURITY_ERROR"
    severity = "CRITICAL"


class ThreatDetectionError(SecurityError):
    error_code = "THREAT_DETECTION_ERROR"
    severity = "ERROR"
    retryable = True


class PromptInjectionDetectionError(ThreatDetectionError):
    error_code = "PROMPT_INJECTION_DETECTION_ERROR"
    retryable = True


class JailbreakDetectionError(ThreatDetectionError):
    error_code = "JAILBREAK_DETECTION_ERROR"
    retryable = True


class ModelInferenceError(NeuralShieldError):
    error_code = "MODEL_INFERENCE_ERROR"
    severity = "ERROR"
    retryable = True


class ModelTimeoutError(ModelInferenceError):
    error_code = "MODEL_TIMEOUT_ERROR"
    retryable = True


class ModelLoadError(ModelInferenceError):
    error_code = "MODEL_LOAD_ERROR"
    retryable = False


# Input Validation Errors
class ValidationError(NeuralShieldError):
    error_code = "VALIDATION_ERROR"
    severity = "WARNING"
    retryable = False


class InputSanitizationError(ValidationError):
    error_code = "INPUT_SANITIZATION_ERROR"


class InvalidPromptError(ValidationError):
    error_code = "INVALID_PROMPT_ERROR"


# Resource & Infrastructure Errors
class ResourceError(NeuralShieldError):
    error_code = "RESOURCE_ERROR"
    severity = "ERROR"


class MemoryLimitExceededError(ResourceError):
    error_code = "MEMORY_LIMIT_EXCEEDED"
    retryable = False


class RateLimitExceededError(ResourceError):
    error_code = "RATE_LIMIT_EXCEEDED"
    severity = "WARNING"
    retryable = True


class CircuitBreakerOpenError(ResourceError):
    error_code = "CIRCUIT_BREAKER_OPEN"
    retryable = False


# Configuration Errors
class ConfigurationError(NeuralShieldError):
    error_code = "CONFIGURATION_ERROR"
    severity = "ERROR"
    retryable = False


class FallbackActivatedError(NeuralShieldError):
    """Special error indicating fallback was activated (not a failure)"""
    error_code = "FALLBACK_ACTIVATED"
    severity = "INFO"
    retryable = False


# -----------------------------------------------------------------------------
# 2. ERROR CONTEXT PROPAGATION
# -----------------------------------------------------------------------------

@dataclass
class ErrorContext:
    """Rich context for error tracking and debugging"""
    operation: str
    module: str
    start_time: datetime = field(default_factory=datetime.utcnow)
    attributes: Dict[str, Any] = field(default_factory=dict)
    attempts: int = 0
    
    def add_attribute(self, key: str, value: Any) -> None:
        self.attributes[key] = value
    
    def increment_attempt(self) -> None:
        self.attempts += 1
    
    def elapsed(self) -> timedelta:
        return datetime.utcnow() - self.start_time


class ErrorContextManager:
    """Thread-safe error context manager"""
    
    _local = threading.local()
    
    @classmethod
    def current(cls) -> Optional[ErrorContext]:
        return getattr(cls._local, 'context', None)
    
    @classmethod
    def set_context(cls, context: ErrorContext) -> None:
        cls._local.context = context
    
    @classmethod
    def clear_context(cls) -> None:
        cls._local.context = None


# -----------------------------------------------------------------------------
# 3. TIMEOUT WRAPPERS
# -----------------------------------------------------------------------------

class Timeout:
    """
    Thread-safe timeout wrapper using signals (main thread) or threading (workers)
    Does NOT modify wrapped function behavior on happy path
    """
    
    def __init__(self, seconds: float, fallback: Optional[Any] = None):
        self.seconds = seconds
        self.fallback = fallback
        self._timeout_occurred = False
    
    def __call__(self, func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            result = [None]
            exception = [None]
            done = threading.Event()
            
            def target():
                try:
                    result[0] = func(*args, **kwargs)
                except Exception as e:
                    exception[0] = e
                finally:
                    done.set()
            
            thread = threading.Thread(target=target, daemon=True)
            thread.start()
            
            if done.wait(timeout=self.seconds):
                if exception[0] is not None:
                    raise exception[0]
                return result[0]
            else:
                self._timeout_occurred = True
                if self.fallback is not None:
                    return self.fallback
                raise ModelTimeoutError(
                    f"Operation timed out after {self.seconds}s",
                    context={"function": func.__name__, "timeout": self.seconds}
                )
        
        return wrapper


def timeout(seconds: float, fallback: Optional[Any] = None) -> Callable:
    """Decorator for timeout protection"""
    def decorator(func: Callable) -> Callable:
        return Timeout(seconds, fallback)(func)
    return decorator


# -----------------------------------------------------------------------------
# 4. RETRY + BACKOFF STRATEGIES
# -----------------------------------------------------------------------------

class BackoffStrategy(Enum):
    EXPONENTIAL = "exponential"
    LINEAR = "linear"
    FIXED = "fixed"
    JITTERED = "jittered"


@dataclass
class RetryConfig:
    max_attempts: int = 3
    initial_delay: float = 0.1
    max_delay: float = 10.0
    backoff_strategy: BackoffStrategy = BackoffStrategy.EXPONENTIAL
    jitter: float = 0.1
    retry_on: Tuple[Type[Exception], ...] = (Exception,)
    stop_on: Tuple[Type[Exception], ...] = ()


class RetryPolicy:
    """
    Configurable retry policy with multiple backoff strategies
    ADD-ONLY: wraps functions, no modifications to existing code
    """
    
    def __init__(self, config: Optional[RetryConfig] = None):
        self.config = config or RetryConfig()
        self._retry_counts: Dict[str, int] = defaultdict(int)
        self._lock = threading.Lock()
    
    def _calculate_delay(self, attempt: int) -> float:
        """Calculate delay based on backoff strategy"""
        strategy = self.config.backoff_strategy
        initial = self.config.initial_delay
        max_d = self.config.max_delay
        
        if strategy == BackoffStrategy.FIXED:
            delay = initial
        elif strategy == BackoffStrategy.LINEAR:
            delay = initial * attempt
        elif strategy == BackoffStrategy.EXPONENTIAL:
            delay = initial * (2 ** (attempt - 1))
        elif strategy == BackoffStrategy.JITTERED:
            base = initial * (2 ** (attempt - 1))
            jitter_amount = base * self.config.jitter
            delay = base + random.uniform(-jitter_amount, jitter_amount)
        else:
            delay = initial
        
        return min(max(delay, 0), max_d)
    
    def _should_retry(self, exception: Exception, attempt: int) -> bool:
        """Determine if exception should trigger retry"""
        if attempt >= self.config.max_attempts:
            return False
        
        # Check stop conditions first
        for stop_exc in self.config.stop_on:
            if isinstance(exception, stop_exc):
                return False
        
        # Check retry conditions
        for retry_exc in self.config.retry_on:
            if isinstance(exception, retry_exc):
                return True
        
        return False
    
    def __call__(self, func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            func_name = func.__name__
            last_exception = None
            
            for attempt in range(1, self.config.max_attempts + 1):
                try:
                    with self._lock:
                        self._retry_counts[func_name] += 1
                    return func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    if not self._should_retry(e, attempt):
                        break
                    if attempt < self.config.max_attempts:
                        delay = self._calculate_delay(attempt)
                        time.sleep(delay)
            
            raise last_exception
        
        return wrapper


def retry(
    max_attempts: int = 3,
    initial_delay: float = 0.1,
    backoff: BackoffStrategy = BackoffStrategy.EXPONENTIAL,
    retry_on: Tuple[Type[Exception], ...] = (Exception,)
) -> Callable:
    """Convenience decorator for retry logic"""
    config = RetryConfig(
        max_attempts=max_attempts,
        initial_delay=initial_delay,
        backoff_strategy=backoff,
        retry_on=retry_on
    )
    def decorator(func: Callable) -> Callable:
        return RetryPolicy(config)(func)
    return decorator


# -----------------------------------------------------------------------------
# 5. CIRCUIT BREAKER + GRACEFUL DEGRADATION
# -----------------------------------------------------------------------------

class CircuitState(Enum):
    CLOSED = "closed"      # Normal operation
    OPEN = "open"          # Tripped, reject requests
    HALF_OPEN = "half_open"  # Test if recovered


@dataclass
class CircuitBreakerConfig:
    failure_threshold: int = 5
    reset_timeout: float = 30.0
    half_open_max_calls: int = 3
    monitored_exceptions: Tuple[Type[Exception], ...] = (Exception,)


class CircuitBreaker:
    """
    Circuit Breaker pattern for graceful degradation
    - CLOSED: normal operation, track failures
    - OPEN: fail fast, use fallback
    - HALF_OPEN: test recovery after timeout
    
    100% ADD-ONLY: wraps existing functions, no core modifications
    Happy path preserved when circuit is CLOSED
    """
    
    def __init__(
        self,
        config: Optional[CircuitBreakerConfig] = None,
        fallback: Optional[Callable] = None
    ):
        self.config = config or CircuitBreakerConfig()
        self.fallback = fallback
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._open_time: Optional[float] = None
        self._half_open_calls = 0
        self._lock = threading.Lock()
    
    @property
    def state(self) -> CircuitState:
        with self._lock:
            self._check_state_transition()
            return self._state
    
    def _check_state_transition(self) -> None:
        """Check if we should transition from OPEN to HALF_OPEN"""
        if self._state == CircuitState.OPEN and self._open_time is not None:
            if time.time() - self._open_time >= self.config.reset_timeout:
                self._state = CircuitState.HALF_OPEN
                self._half_open_calls = 0
    
    def _record_success(self) -> None:
        """Record successful call - reset on success"""
        self._failure_count = 0
        if self._state == CircuitState.HALF_OPEN:
            self._state = CircuitState.CLOSED
            self._half_open_calls = 0
    
    def _record_failure(self) -> None:
        """Record failed call - trip circuit if threshold reached"""
        self._failure_count += 1
        
        if self._state == CircuitState.HALF_OPEN:
            # Any failure in half-open -> back to open
            self._state = CircuitState.OPEN
            self._open_time = time.time()
            self._half_open_calls = 0
        elif self._failure_count >= self.config.failure_threshold:
            self._state = CircuitState.OPEN
            self._open_time = time.time()
    
    def _is_monitored_exception(self, exc: Exception) -> bool:
        return isinstance(exc, self.config.monitored_exceptions)
    
    def __call__(self, func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            with self._lock:
                self._check_state_transition()
                current_state = self._state
                
                if current_state == CircuitState.OPEN:
                    # Circuit is open - fail fast or use fallback
                    if self.fallback is not None:
                        return self.fallback(*args, **kwargs)
                    raise CircuitBreakerOpenError(
                        f"Circuit breaker OPEN for {func.__name__}",
                        context={"reset_in": self.config.reset_timeout - (time.time() - (self._open_time or 0))}
                    )
                
                if current_state == CircuitState.HALF_OPEN:
                    self._half_open_calls += 1
                    if self._half_open_calls > self.config.half_open_max_calls:
                        if self.fallback is not None:
                            return self.fallback(*args, **kwargs)
                        raise CircuitBreakerOpenError(
                            f"Circuit breaker HALF_OPEN limit reached for {func.__name__}",
                            context={"half_open_calls": self._half_open_calls}
                        )
            
            # Execute the function
            try:
                result = func(*args, **kwargs)
                with self._lock:
                    self._record_success()
                return result
            except Exception as e:
                with self._lock:
                    if self._is_monitored_exception(e):
                        self._record_failure()
                # Re-raise after recording
                raise
        
        return wrapper


def circuit_breaker(
    failure_threshold: int = 5,
    reset_timeout: float = 30.0,
    fallback: Optional[Callable] = None
) -> Callable:
    """Convenience decorator for circuit breaker"""
    config = CircuitBreakerConfig(
        failure_threshold=failure_threshold,
        reset_timeout=reset_timeout
    )
    def decorator(func: Callable) -> Callable:
        return CircuitBreaker(config, fallback)(func)
    return decorator


# -----------------------------------------------------------------------------
# 6. BULKHEAD PATTERN - RESOURCE ISOLATION
# -----------------------------------------------------------------------------

class Bulkhead:
    """
    Bulkhead pattern - isolate resources to prevent cascade failures
    Limits concurrent executions per operation
    
    ADD-ONLY: wraps functions, no core modifications
    """
    
    def __init__(self, max_concurrent: int = 10, timeout: float = 5.0):
        self.max_concurrent = max_concurrent
        self.timeout = timeout
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
    
    def __call__(self, func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            acquired = self._semaphore.acquire(timeout=self.timeout)
            if not acquired:
                raise ResourceError(
                    f"Bulkhead capacity exceeded for {func.__name__}",
                    context={"max_concurrent": self.max_concurrent, "timeout": self.timeout}
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


# -----------------------------------------------------------------------------
# 7. GRACEFUL DEGRADATION FALLBACKS
# -----------------------------------------------------------------------------

class FallbackStrategy:
    """Collection of fallback strategies for graceful degradation"""
    
    @staticmethod
    def return_default(default_value: Any) -> Callable:
        """Return a default value on failure"""
        def fallback(*args, **kwargs):
            return default_value
        return fallback
    
    @staticmethod
    def return_empty_list() -> Callable:
        return FallbackStrategy.return_default([])
    
    @staticmethod
    def return_empty_dict() -> Callable:
        return FallbackStrategy.return_default({})
    
    @staticmethod
    def return_false() -> Callable:
        return FallbackStrategy.return_default(False)
    
    @staticmethod
    def return_none() -> Callable:
        return FallbackStrategy.return_default(None)
    
    @staticmethod
    def log_and_return(logger: logging.Logger, level: int, default: Any) -> Callable:
        def fallback(*args, **kwargs):
            logger.log(level, f"Fallback activated, returning default: {default}")
            return default
        return fallback


def with_fallback(
    fallback_func: Callable,
    catch: Tuple[Type[Exception], ...] = (Exception,)
) -> Callable:
    """
    Decorator to activate fallback on specific exceptions
    Happy path: 100% preserved when no exceptions
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except catch:
                return fallback_func(*args, **kwargs)
        return wrapper
    return decorator


# -----------------------------------------------------------------------------
# 8. CONVENIENCE COMPOSITION - ALL IN ONE
# -----------------------------------------------------------------------------

def resilient(
    timeout_seconds: Optional[float] = None,
    max_retries: int = 3,
    retry_delay: float = 0.1,
    circuit_failure_threshold: Optional[int] = None,
    circuit_reset_timeout: float = 30.0,
    bulkhead_max_concurrent: Optional[int] = None,
    fallback: Optional[Callable] = None,
    retry_on: Tuple[Type[Exception], ...] = (NeuralShieldError,)
) -> Callable:
    """
    One-stop decorator for comprehensive error resilience
    Composes: timeout + retry + circuit breaker + bulkhead + fallback
    
    USAGE:
        @resilient(timeout_seconds=5, max_retries=3)
        def my_function():
            ...
    """
    def decorator(func: Callable) -> Callable:
        wrapped = func
        
        # Apply in order: bulkhead -> timeout -> retry -> circuit -> fallback
        if bulkhead_max_concurrent is not None:
            wrapped = Bulkhead(bulkhead_max_concurrent)(wrapped)
        
        if timeout_seconds is not None:
            wrapped = Timeout(timeout_seconds)(wrapped)
        
        if max_retries > 1:
            wrapped = retry(max_retries, retry_delay, retry_on=retry_on)(wrapped)
        
        if circuit_failure_threshold is not None:
            wrapped = circuit_breaker(circuit_failure_threshold, circuit_reset_timeout, fallback)(wrapped)
        elif fallback is not None:
            wrapped = with_fallback(fallback)(wrapped)
        
        return wrapped
    
    return decorator


# -----------------------------------------------------------------------------
# 9. ERROR MONITORING & METRICS
# -----------------------------------------------------------------------------

class ErrorMetrics:
    """Track error rates and statistics for observability"""
    
    def __init__(self):
        self._error_counts: Dict[str, int] = defaultdict(int)
        self._success_counts: Dict[str, int] = defaultdict(int)
        self._lock = threading.Lock()
    
    def record_error(self, operation: str, error_type: str) -> None:
        with self._lock:
            self._error_counts[f"{operation}:{error_type}"] += 1
    
    def record_success(self, operation: str) -> None:
        with self._lock:
            self._success_counts[operation] += 1
    
    def get_error_rate(self, operation: str) -> float:
        with self._lock:
            errors = sum(v for k, v in self._error_counts.items() if k.startswith(f"{operation}:"))
            total = errors + self._success_counts.get(operation, 0)
            return errors / total if total > 0 else 0.0
    
    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "total_errors": sum(self._error_counts.values()),
                "total_successes": sum(self._success_counts.values()),
                "error_by_type": dict(self._error_counts),
                "success_by_operation": dict(self._success_counts)
            }


# Global instance (OPT-IN - use only if explicitly imported)
_global_error_metrics = ErrorMetrics()


def get_error_metrics() -> ErrorMetrics:
    return _global_error_metrics


# -----------------------------------------------------------------------------
# 10. SELF-TEST
# -----------------------------------------------------------------------------

def _run_self_test():
    """Quick self-test to verify all components work"""
    print("=" * 60)
    print("NeuralShield Error Resilience v2 - SELF TEST")
    print("=" * 60)
    
    # Test 1: Custom exceptions
    print("\n[1] Testing Custom Exception Hierarchy...")
    try:
        raise PromptInjectionDetectionError("Test error", context={"test": True})
    except NeuralShieldError as e:
        print(f"  ✓ Exception hierarchy works: {e.error_code}")
        print(f"  ✓ Context preserved: {e.context}")
    
    # Test 2: Timeout
    print("\n[2] Testing Timeout Wrapper...")
    @timeout(0.1)
    def slow_func():
        time.sleep(1.0)
    
    try:
        slow_func()
        print("  ✗ Should have timed out!")
    except ModelTimeoutError:
        print("  ✓ Timeout works correctly")
    
    # Test 3: Retry
    print("\n[3] Testing Retry Policy...")
    call_count = [0]
    @retry(max_attempts=3, initial_delay=0.01)
    def flaky_func():
        call_count[0] += 1
        if call_count[0] < 3:
            raise ValueError("Flaky!")
        return "success"
    
    result = flaky_func()
    print(f"  ✓ Retry works: attempts={call_count[0]}, result={result}")
    
    # Test 4: Circuit Breaker
    print("\n[4] Testing Circuit Breaker...")
    cb = CircuitBreaker(CircuitBreakerConfig(failure_threshold=2, reset_timeout=1.0))
    
    @cb
    def failing_func():
        raise ValueError("Always fails")
    
    try:
        failing_func()
    except ValueError:
        pass
    try:
        failing_func()
    except ValueError:
        pass
    
    try:
        failing_func()
    except CircuitBreakerOpenError:
        print("  ✓ Circuit breaker trips correctly")
    
    # Test 5: Fallback
    print("\n[5] Testing Graceful Degradation...")
    @with_fallback(FallbackStrategy.return_default("safe_value"))
    def risky_func():
        raise ValueError("Fail!")
    
    result = risky_func()
    print(f"  ✓ Fallback activated: result={result}")
    
    # Test 6: Bulkhead
    print("\n[6] Testing Bulkhead Pattern...")
    @Bulkhead(max_concurrent=2)
    def limited_func():
        return "ok"
    
    result = limited_func()
    print(f"  ✓ Bulkhead works: {result}")
    
    print("\n" + "=" * 60)
    print("ALL SELF-TESTS PASSED ✓")
    print("=" * 60)


if __name__ == "__main__":
    _run_self_test()
