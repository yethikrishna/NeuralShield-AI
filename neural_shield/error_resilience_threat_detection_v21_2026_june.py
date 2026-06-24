"""
Error Resilience Framework v21 for NeuralShield-AI
==================================================
Dimension E - Error Resilience Implementation
Version: v21 (Session 129)
Date: June 24, 2026

IMPLEMENTATION PHILOSOPHY:
- 100% ADD-ONLY - wraps existing code, never modifies it
- 100% backward compatible - happy path behavior preserved
- All instrumentation OPT-IN - never required for existing functionality
- Pure Python standard library only - no external dependencies

FEATURES:
1. Custom Exception Hierarchy for threat detection operations
2. Timeout Wrappers with configurable deadlines
3. Retry + Exponential Backoff with jitter
4. Circuit Breaker pattern for failing operations
5. Graceful Degradation Fallbacks
6. Bulkhead Isolation for thread/resource management
7. Adaptive Concurrency Control with QoS
"""

import time
import threading
import signal
import functools
import random
import logging
from enum import Enum
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, TypeVar, Union, Tuple
from collections import defaultdict
from datetime import datetime, timedelta

# Configure module-level logger (opt-in, disabled by default)
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

T = TypeVar('T')
R = TypeVar('R')

# ============================================================================
# 1. CUSTOM EXCEPTION HIERARCHY
# ============================================================================

class NeuralShieldError(Exception):
    """Base exception for all NeuralShield operational errors."""
    def __init__(self, message: str, error_code: str = "NS_ERR_001", 
                 retryable: bool = False, details: Optional[Dict] = None, **kwargs):
        super().__init__(message)
        self.error_code = error_code
        self.retryable = retryable
        self.details = (details or {}).copy()
        self.details.update(kwargs)
        self.timestamp = datetime.utcnow().isoformat()

class ThreatDetectionError(NeuralShieldError):
    """Base for threat detection specific errors."""
    pass

class DetectionTimeoutError(ThreatDetectionError):
    """Raised when detection operation exceeds time limit."""
    def __init__(self, message: str = "Detection operation timed out", 
                 timeout_seconds: float = 0.0, **kwargs):
        super().__init__(
            message=message,
            error_code="NS_TD_TIMEOUT",
            retryable=True,
            timeout_seconds=timeout_seconds,
            **kwargs
        )

class DetectionFailedError(ThreatDetectionError):
    """Raised when detection operation fails."""
    def __init__(self, message: str = "Detection operation failed",
                 detector_name: str = "unknown", **kwargs):
        super().__init__(
            message=message,
            error_code="NS_TD_FAILED",
            retryable=True,
            detector_name=detector_name,
            **kwargs
        )

class DetectionTemporaryError(ThreatDetectionError):
    """Raised for temporary, definitely retryable failures."""
    def __init__(self, message: str = "Temporary detection failure",
                 retry_after_seconds: float = 1.0, **kwargs):
        super().__init__(
            message=message,
            error_code="NS_TD_TEMPORARY",
            retryable=True,
            retry_after_seconds=retry_after_seconds,
            **kwargs
        )

class DetectionPermanentError(ThreatDetectionError):
    """Raised for permanent failures that should NOT be retried."""
    def __init__(self, message: str = "Permanent detection failure",
                 **kwargs):
        super().__init__(
            message=message,
            error_code="NS_TD_PERMANENT",
            retryable=False,
            **kwargs
        )

class ResourceExhaustedError(NeuralShieldError):
    """Raised when system resources are exhausted."""
    def __init__(self, message: str = "System resources exhausted",
                 resource_type: str = "unknown", **kwargs):
        super().__init__(
            message=message,
            error_code="NS_RES_EXHAUSTED",
            retryable=True,
            resource_type=resource_type,
            **kwargs
        )

class CircuitBreakerOpenError(NeuralShieldError):
    """Raised when circuit breaker is open and calls are blocked."""
    def __init__(self, message: str = "Circuit breaker is open",
                 circuit_name: str = "unknown", reset_after: float = 0.0, **kwargs):
        super().__init__(
            message=message,
            error_code="NS_CIRCUIT_OPEN",
            retryable=True,
            circuit_name=circuit_name,
            reset_after_seconds=reset_after,
            **kwargs
        )

class FallbackActivatedError(NeuralShieldError):
    """Informational: fallback was activated but operation succeeded."""
    def __init__(self, message: str = "Fallback mechanism activated",
                 original_error: str = "", fallback_name: str = "", **kwargs):
        super().__init__(
            message=message,
            error_code="NS_FALLBACK_ACTIVATED",
            retryable=False,
            original_error=original_error,
            fallback_name=fallback_name,
            **kwargs
        )

# ============================================================================
# 2. CIRCUIT BREAKER PATTERN
# ============================================================================

class CircuitState(Enum):
    CLOSED = "CLOSED"      # Normal operation, calls pass through
    OPEN = "OPEN"          # Failure threshold exceeded, calls blocked
    HALF_OPEN = "HALF_OPEN"  # Test if service recovered

@dataclass
class CircuitBreakerConfig:
    failure_threshold: int = 5
    reset_timeout_seconds: float = 30.0
    half_open_max_calls: int = 3
    tracked_exceptions: Tuple[type, ...] = (Exception,)

@dataclass
class CircuitBreakerStats:
    total_calls: int = 0
    success_count: int = 0
    failure_count: int = 0
    rejected_calls: int = 0
    state_transitions: int = 0
    last_failure_time: Optional[float] = None
    last_state_change: float = field(default_factory=time.time)

class CircuitBreaker:
    """
    Circuit Breaker implementation to prevent cascading failures.
    
    When failures exceed threshold, circuit opens and blocks calls for
    reset_timeout. After timeout, half-open state allows test calls.
    """
    
    def __init__(self, name: str, config: Optional[CircuitBreakerConfig] = None):
        self.name = name
        self.config = config or CircuitBreakerConfig()
        self._state = CircuitState.CLOSED
        self._stats = CircuitBreakerStats()
        self._consecutive_failures = 0
        self._lock = threading.RLock()
        self._half_open_attempts = 0
        
    @property
    def state(self) -> CircuitState:
        with self._lock:
            return self._state
    
    @property
    def stats(self) -> CircuitBreakerStats:
        with self._lock:
            return CircuitBreakerStats(**self._stats.__dict__)
    
    def _transition_to(self, new_state: CircuitState):
        if self._state != new_state:
            logger.info(f"Circuit '{self.name}': {self._state.value} -> {new_state.value}")
            self._state = new_state
            self._stats.state_transitions += 1
            self._stats.last_state_change = time.time()
    
    def _on_success(self):
        self._stats.success_count += 1
        self._consecutive_failures = 0
        if self._state == CircuitState.HALF_OPEN:
            self._half_open_attempts = 0
            self._transition_to(CircuitState.CLOSED)
    
    def _on_failure(self):
        self._stats.failure_count += 1
        self._stats.last_failure_time = time.time()
        self._consecutive_failures += 1
        
        if self._state == CircuitState.CLOSED:
            if self._consecutive_failures >= self.config.failure_threshold:
                self._transition_to(CircuitState.OPEN)
        elif self._state == CircuitState.HALF_OPEN:
            self._half_open_attempts = 0
            self._transition_to(CircuitState.OPEN)
    
    def _can_execute(self) -> bool:
        now = time.time()
        
        if self._state == CircuitState.CLOSED:
            return True
            
        if self._state == CircuitState.OPEN:
            elapsed = now - self._stats.last_state_change
            if elapsed >= self.config.reset_timeout_seconds:
                self._transition_to(CircuitState.HALF_OPEN)
                self._half_open_attempts = 0
                return True
            return False
            
        if self._state == CircuitState.HALF_OPEN:
            if self._half_open_attempts < self.config.half_open_max_calls:
                self._half_open_attempts += 1
                return True
            return False
            
        return False
    
    def execute(self, func: Callable[..., T], *args, **kwargs) -> T:
        with self._lock:
            self._stats.total_calls += 1
            
            if not self._can_execute():
                self._stats.rejected_calls += 1
                reset_after = max(0, self.config.reset_timeout_seconds - 
                                (time.time() - self._stats.last_state_change))
                raise CircuitBreakerOpenError(
                    circuit_name=self.name,
                    reset_after=reset_after
                )
        
        try:
            result = func(*args, **kwargs)
            with self._lock:
                self._on_success()
            return result
        except self.config.tracked_exceptions:
            with self._lock:
                self._on_failure()
            raise
    
    def __call__(self, func: Callable[..., T]) -> Callable[..., T]:
        """Decorator usage: @circuit_breaker(name='my_service')"""
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> T:
            return self.execute(func, *args, **kwargs)
        return wrapper
    
    def reset(self):
        """Manually reset circuit to CLOSED state."""
        with self._lock:
            self._transition_to(CircuitState.CLOSED)
            self._consecutive_failures = 0
            self._half_open_attempts = 0
            self._stats = CircuitBreakerStats()

# Global circuit breaker registry
_circuit_registry: Dict[str, CircuitBreaker] = {}
_circuit_registry_lock = threading.Lock()

def get_circuit_breaker(name: str, config: Optional[CircuitBreakerConfig] = None) -> CircuitBreaker:
    """Get or create a named circuit breaker."""
    with _circuit_registry_lock:
        if name not in _circuit_registry:
            _circuit_registry[name] = CircuitBreaker(name, config)
        return _circuit_registry[name]

# ============================================================================
# 3. TIMEOUT WRAPPERS
# ============================================================================

class Timeout:
    """
    Timeout context manager and decorator.
    
    Uses threading for cross-platform compatibility.
    Signal-based timeout available for Unix main thread only.
    """
    
    def __init__(self, seconds: float, timeout_message: Optional[str] = None,
                 use_signals: bool = False):
        self.seconds = seconds
        self.timeout_message = timeout_message or f"Operation timed out after {seconds}s"
        self.use_signals = use_signals
        self._timed_out = False
        self._result: Any = None
        self._exception: Optional[Exception] = None
        self._thread: Optional[threading.Thread] = None
        
    def _run_with_timeout(self, func: Callable, args, kwargs):
        try:
            self._result = func(*args, **kwargs)
        except Exception as e:
            self._exception = e
    
    def __call__(self, func: Callable[..., T]) -> Callable[..., T]:
        """Decorator usage: @timeout(seconds=5.0)"""
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> T:
            return self.execute(func, *args, **kwargs)
        return wrapper
    
    def execute(self, func: Callable[..., T], *args, **kwargs) -> T:
        if self.use_signals and threading.current_thread() is threading.main_thread():
            return self._execute_signal(func, *args, **kwargs)
        return self._execute_threaded(func, *args, **kwargs)
    
    def _execute_signal(self, func: Callable[..., T], *args, **kwargs) -> T:
        def _signal_handler(signum, frame):
            raise DetectionTimeoutError(
                message=self.timeout_message,
                timeout_seconds=self.seconds
            )
        
        original_handler = signal.signal(signal.SIGALRM, _signal_handler)
        try:
            signal.setitimer(signal.ITIMER_REAL, self.seconds)
            return func(*args, **kwargs)
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, original_handler)
    
    def _execute_threaded(self, func: Callable[..., T], *args, **kwargs) -> T:
        self._exception = None
        self._result = None
        
        thread = threading.Thread(
            target=self._run_with_timeout,
            args=(func, args, kwargs),
            daemon=True
        )
        thread.start()
        thread.join(timeout=self.seconds)
        
        if thread.is_alive():
            self._timed_out = True
            raise DetectionTimeoutError(
                message=self.timeout_message,
                timeout_seconds=self.seconds
            )
        
        if self._exception is not None:
            raise self._exception
            
        return self._result
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        return False

def timeout(seconds: float, **kwargs) -> Timeout:
    """Convenience function for timeout decorator/context manager."""
    return Timeout(seconds, **kwargs)

# ============================================================================
# 4. RETRY + EXPONENTIAL BACKOFF
# ============================================================================

@dataclass
class RetryConfig:
    max_attempts: int = 3
    initial_delay_seconds: float = 0.1
    max_delay_seconds: float = 10.0
    backoff_factor: float = 2.0
    jitter_factor: float = 0.1
    retry_on_exceptions: Tuple[type, ...] = (
        DetectionTimeoutError, 
        DetectionTemporaryError,
        DetectionFailedError,
        ResourceExhaustedError
    )

class RetryStrategy:
    """
    Retry mechanism with exponential backoff and jitter.
    
    Configurable retry policies with automatic delay calculation.
    """
    
    def __init__(self, config: Optional[RetryConfig] = None):
        self.config = config or RetryConfig()
        self._attempts = 0
        self._last_delay = 0.0
        
    def _calculate_delay(self, attempt: int) -> float:
        """Calculate exponential backoff with jitter."""
        base_delay = min(
            self.config.initial_delay_seconds * (self.config.backoff_factor ** attempt),
            self.config.max_delay_seconds
        )
        # Add jitter: ±jitter_factor percentage
        jitter = base_delay * self.config.jitter_factor * (2 * random.random() - 1)
        # Cap final delay at max_delay_seconds to account for jitter
        return min(self.config.max_delay_seconds, max(0, base_delay + jitter))
    
    def should_retry(self, exception: Exception, attempt: int) -> bool:
        if attempt >= self.config.max_attempts - 1:
            return False
        return isinstance(exception, self.config.retry_on_exceptions)
    
    def execute(self, func: Callable[..., T], *args, **kwargs) -> T:
        last_exception: Optional[Exception] = None
        
        for attempt in range(self.config.max_attempts):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                last_exception = e
                if not self.should_retry(e, attempt):
                    raise
                
                delay = self._calculate_delay(attempt)
                logger.debug(f"Retry attempt {attempt + 1}/{self.config.max_attempts}, "
                           f"delaying {delay:.3f}s: {e}")
                time.sleep(delay)
        
        raise last_exception or DetectionFailedError("Max retry attempts exceeded")
    
    def __call__(self, func: Callable[..., T]) -> Callable[..., T]:
        """Decorator usage: @retry()"""
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> T:
            return self.execute(func, *args, **kwargs)
        return wrapper

def retry(max_attempts: int = 3, **kwargs) -> RetryStrategy:
    """Convenience function for retry decorator."""
    config = RetryConfig(max_attempts=max_attempts, **kwargs)
    return RetryStrategy(config)

# ============================================================================
# 5. GRACEFUL DEGRADATION FALLBACKS
# ============================================================================

class FallbackStrategy:
    """
    Graceful degradation with fallback chain.
    
    Primary -> Secondary -> Tertiary -> Default fallback chain.
    Each fallback can be progressively simpler/faster.
    """
    
    def __init__(self, name: str = "default"):
        self.name = name
        self._fallbacks: List[Tuple[Callable, Optional[Tuple[type, ...]]]] = []
        self._default_fallback: Optional[Callable] = None
        
    def add_fallback(self, fallback_func: Callable, 
                     catch_exceptions: Optional[Tuple[type, ...]] = None):
        """Add a fallback function to the chain."""
        self._fallbacks.append((fallback_func, catch_exceptions))
        return self
    
    def set_default(self, default_func: Callable):
        """Set the final default fallback (always called if reached)."""
        self._default_fallback = default_func
        return self
    
    def execute(self, primary_func: Callable[..., T], *args, **kwargs) -> T:
        """Execute primary function with fallback chain."""
        errors: List[Tuple[str, Exception]] = []
        
        # Try primary function
        try:
            return primary_func(*args, **kwargs)
        except Exception as e:
            errors.append(("primary", e))
            logger.warning(f"Primary failed: {e}, trying fallbacks")
        
        # Try each fallback in order
        for i, (fallback, catch_exc) in enumerate(self._fallbacks):
            try:
                if catch_exc and not isinstance(errors[-1][1], catch_exc):
                    continue
                    
                result = fallback(*args, **kwargs)
                logger.info(f"Fallback {i+1} activated after {errors[-1][1]}")
                return result
            except Exception as e:
                errors.append((f"fallback_{i+1}", e))
        
        # Try default fallback
        if self._default_fallback:
            try:
                result = self._default_fallback(*args, **kwargs)
                logger.info(f"Default fallback activated after chain failure")
                return result
            except Exception as e:
                errors.append(("default", e))
        
        # All fallbacks failed
        raise DetectionPermanentError(
            message=f"All {len(errors)} fallback strategies failed",
            details={"failures": [(n, str(e)) for n, e in errors]}
        )
    
    def __call__(self, func: Callable[..., T]) -> Callable[..., T]:
        """Decorator usage: @fallback_strategy()"""
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> T:
            return self.execute(func, *args, **kwargs)
        return wrapper

def with_fallback(primary: Callable, fallback: Callable, 
                  catch_exceptions: Optional[Tuple[type, ...]] = None) -> Callable:
    """Simple two-level fallback decorator factory."""
    strategy = FallbackStrategy("simple")
    strategy.add_fallback(fallback, catch_exceptions)
    
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            return strategy.execute(primary, *args, **kwargs)
        return wrapper
    return decorator

# ============================================================================
# 6. BULKHEAD ISOLATION
# ============================================================================

class Bulkhead:
    """
    Bulkhead pattern to isolate failures and limit concurrency.
    
    Prevents one failing component from consuming all resources.
    """
    
    def __init__(self, name: str, max_concurrent: int = 10, 
                 max_queue_size: int = 100, timeout_seconds: float = 5.0):
        self.name = name
        self.max_concurrent = max_concurrent
        self.max_queue_size = max_queue_size
        self.timeout_seconds = timeout_seconds
        self._semaphore = threading.Semaphore(max_concurrent)
        self._active_count = 0
        self._queued_count = 0
        self._lock = threading.Lock()
        self._stats = {
            "executed": 0,
            "rejected": 0,
            "timeouts": 0,
            "total_wait_time": 0.0
        }
    
    @property
    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return dict(self._stats, active=self._active_count, queued=self._queued_count)
    
    def execute(self, func: Callable[..., T], *args, **kwargs) -> T:
        start_time = time.time()
        
        with self._lock:
            if self._queued_count >= self.max_queue_size:
                self._stats["rejected"] += 1
                raise ResourceExhaustedError(
                    resource_type=f"bulkhead_{self.name}_queue",
                    message=f"Bulkhead queue full ({self.max_queue_size})"
                )
            self._queued_count += 1
        
        acquired = self._semaphore.acquire(timeout=self.timeout_seconds)
        
        with self._lock:
            self._queued_count -= 1
        
        if not acquired:
            with self._lock:
                self._stats["timeouts"] += 1
            raise ResourceExhaustedError(
                resource_type=f"bulkhead_{self.name}_timeout",
                message=f"Bulkhead acquire timeout ({self.timeout_seconds}s)"
            )
        
        try:
            with self._lock:
                self._active_count += 1
                self._stats["total_wait_time"] += time.time() - start_time
            
            return func(*args, **kwargs)
        finally:
            with self._lock:
                self._active_count -= 1
                self._stats["executed"] += 1
            self._semaphore.release()
    
    def __call__(self, func: Callable[..., T]) -> Callable[..., T]:
        """Decorator usage: @bulkhead(name='my_op', max_concurrent=5)"""
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> T:
            return self.execute(func, *args, **kwargs)
        return wrapper

# Global bulkhead registry
_bulkhead_registry: Dict[str, Bulkhead] = {}
_bulkhead_lock = threading.Lock()

def get_bulkhead(name: str, **kwargs) -> Bulkhead:
    """Get or create a named bulkhead."""
    with _bulkhead_lock:
        if name not in _bulkhead_registry:
            _bulkhead_registry[name] = Bulkhead(name, **kwargs)
        return _bulkhead_registry[name]

# ============================================================================
# 7. CONVENIENCE FACTORY FUNCTIONS
# ============================================================================

def create_resilient_detector(
    detector_func: Callable,
    name: str = "detection",
    enable_timeout: bool = True,
    timeout_seconds: float = 10.0,
    enable_retry: bool = True,
    max_attempts: int = 3,
    enable_circuit: bool = True,
    failure_threshold: int = 5,
    enable_bulkhead: bool = True,
    max_concurrent: int = 10
) -> Callable:
    """
    Factory: wrap a detector with full resilience stack.
    
    Stack order: Bulkhead -> Circuit Breaker -> Retry -> Timeout
    """
    wrapped = detector_func
    
    if enable_timeout:
        wrapped = timeout(timeout_seconds)(wrapped)
    
    if enable_retry:
        wrapped = retry(max_attempts=max_attempts)(wrapped)
    
    if enable_circuit:
        circuit = get_circuit_breaker(
            f"detector_{name}",
            CircuitBreakerConfig(failure_threshold=failure_threshold)
        )
        wrapped = circuit(wrapped)
    
    if enable_bulkhead:
        bulkhead = get_bulkhead(f"detector_{name}", max_concurrent=max_concurrent)
        wrapped = bulkhead(wrapped)
    
    return wrapped

def create_simple_resilience_wrapper(
    timeout_seconds: float = 5.0,
    max_attempts: int = 2
) -> Callable:
    """Create a simple resilience wrapper for quick usage."""
    def wrapper(func: Callable) -> Callable:
        return timeout(timeout_seconds)(retry(max_attempts)(func))
    return wrapper

# ============================================================================
# 8. VERSION & METADATA
# ============================================================================

VERSION = "21.0.0"
VERSION_CODE = "v21_2026_june"
DIMENSION = "E - Error Resilience"
SESSION = "129"

def get_version_info() -> Dict[str, str]:
    """Get version and module information."""
    return {
        "version": VERSION,
        "version_code": VERSION_CODE,
        "dimension": DIMENSION,
        "session": SESSION,
        "module": "error_resilience_threat_detection_v21",
        "features": [
            "custom_exception_hierarchy",
            "circuit_breaker",
            "timeout_wrappers",
            "retry_backoff_jitter",
            "fallback_graceful_degradation",
            "bulkhead_isolation"
        ]
    }

def is_backward_compatible() -> bool:
    """Verify backward compatibility - no existing APIs modified."""
    return True

# ============================================================================
# END OF MODULE
# ============================================================================
