"""
NeuralShield AI - Comprehensive Error Resilience Exception Hierarchy (v21)
DIMENSION E - Error Resilience
June 2026 Production Release

PHILOSOPHY: ADD-ONLY, wrap, extend, layer on top
- 100% backward compatible
- Happy path behavior preserved
- Graceful degradation enabled
- Layered ON TOP of existing code

Custom exception hierarchy for NeuralShield AI security modules
with retry, backoff, timeout, and graceful degradation capabilities.
"""

import time
import random
import logging
import functools
import threading
from typing import Any, Callable, Optional, TypeVar, Union, Dict, List, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta

# Type variables for decorators
T = TypeVar('T')
F = TypeVar('F', bound=Callable[..., Any])

# Configure module logger (OPT-IN, disabled by default)
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

# ============================================================================
# EXCEPTION SEVERITY ENUM
# ============================================================================

class ExceptionSeverity(Enum):
    """Severity levels for structured exception handling."""
    DEBUG = 0
    INFO = 1
    WARNING = 2
    ERROR = 3
    CRITICAL = 4
    FATAL = 5

# ============================================================================
# EXCEPTION CATEGORY ENUM
# ============================================================================

class ExceptionCategory(Enum):
    """Category classification for error handling routing."""
    TRANSIENT = "transient"          # Retry-eligible
    CONFIGURATION = "configuration"  # User-fixable
    VALIDATION = "validation"        # Input-related
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    RESOURCE = "resource"           # Resource exhaustion
    NETWORK = "network"             # Network-related
    CRYPTOGRAPHIC = "cryptographic" # Security failures
    THREAT_DETECTION = "threat_detection"
    INTEGRITY = "integrity"         # Data integrity
    TIMEOUT = "timeout"
    UNKNOWN = "unknown"

# ============================================================================
# BASE EXCEPTION HIERARCHY
# ============================================================================

class NeuralShieldBaseError(Exception):
    """
    Base exception for all NeuralShield AI errors.
    
    All custom exceptions inherit from this, providing:
    - Structured error codes
    - Severity levels
    - Category classification
    - Retry eligibility
    - User-friendly messages
    - Graceful degradation hints
    """
    
    def __init__(
        self,
        message: str,
        error_code: str = "NS-0001",
        severity: ExceptionSeverity = ExceptionSeverity.ERROR,
        category: ExceptionCategory = ExceptionCategory.UNKNOWN,
        retry_eligible: bool = False,
        graceful_fallback: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None
    ):
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.severity = severity
        self.category = category
        self.retry_eligible = retry_eligible
        self.graceful_fallback = graceful_fallback
        self.details = details or {}
        self.cause = cause
        self.timestamp = datetime.utcnow()
        
    def __str__(self) -> str:
        base = f"[{self.error_code}] {self.message}"
        if self.graceful_fallback:
            base += f" | FALLBACK: {self.graceful_fallback}"
        return base
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to structured dictionary for logging."""
        return {
            "error_code": self.error_code,
            "message": self.message,
            "severity": self.severity.name,
            "category": self.category.value,
            "retry_eligible": self.retry_eligible,
            "graceful_fallback": self.graceful_fallback,
            "details": self.details,
            "timestamp": self.timestamp.isoformat()
        }

# ----------------------------------------------------------------------------
# TRANSIENT ERRORS (Retry-eligible)
# ----------------------------------------------------------------------------

class NeuralShieldTransientError(NeuralShieldBaseError):
    """Base for transient, retry-eligible errors."""
    def __init__(self, message: str, error_code: str = "NS-T001", **kwargs):
        kwargs.pop("category", None)  # Avoid duplicate - we explicitly set it
        kwargs.pop("retry_eligible", None)  # Avoid duplicate - we explicitly set it
        super().__init__(
            message,
            error_code=error_code,
            category=ExceptionCategory.TRANSIENT,
            retry_eligible=True,
            **kwargs
        )

class NeuralShieldTimeoutError(NeuralShieldTransientError):
    """Operation timed out - safe to retry."""
    def __init__(self, message: str = "Operation timed out", timeout_seconds: Optional[float] = None, **kwargs):
        details = kwargs.pop("details", {})
        if timeout_seconds is not None:
            details["timeout_seconds"] = timeout_seconds
        kwargs.pop("category", None)  # Avoid duplicate
        kwargs.pop("error_code", None)  # Avoid duplicate
        super().__init__(
            message,
            error_code="NS-T002",
            category=ExceptionCategory.TIMEOUT,
            details=details,
            **kwargs
        )

class NeuralShieldRateLimitError(NeuralShieldTransientError):
    """Rate limit exceeded - retry with backoff."""
    def __init__(self, message: str = "Rate limit exceeded", retry_after: Optional[int] = None, **kwargs):
        details = kwargs.pop("details", {})
        if retry_after is not None:
            details["retry_after_seconds"] = retry_after
        super().__init__(
            message,
            error_code="NS-T003",
            details=details,
            **kwargs
        )

class NeuralShieldNetworkError(NeuralShieldTransientError):
    """Network connectivity issue - retry eligible."""
    def __init__(self, message: str = "Network connectivity error", **kwargs):
        super().__init__(
            message,
            error_code="NS-T004",
            category=ExceptionCategory.NETWORK,
            **kwargs
        )

class NeuralShieldResourceTemporarilyUnavailableError(NeuralShieldTransientError):
    """Resource temporarily busy - retry later."""
    def __init__(self, message: str = "Resource temporarily unavailable", **kwargs):
        super().__init__(
            message,
            error_code="NS-T005",
            category=ExceptionCategory.RESOURCE,
            **kwargs
        )

# ----------------------------------------------------------------------------
# VALIDATION ERRORS (NOT retry-eligible)
# ----------------------------------------------------------------------------

class NeuralShieldValidationError(NeuralShieldBaseError):
    """Input validation failed - NOT retry eligible."""
    def __init__(self, message: str = "Validation failed", field: Optional[str] = None, **kwargs):
        details = kwargs.pop("details", {})
        if field is not None:
            details["field"] = field
        # Allow child classes to override these values
        category = kwargs.pop("category", ExceptionCategory.VALIDATION)
        severity = kwargs.pop("severity", ExceptionSeverity.WARNING)
        error_code = kwargs.pop("error_code", "NS-V001")
        super().__init__(
            message,
            error_code=error_code,
            category=category,
            severity=severity,
            retry_eligible=False,
            details=details,
            **kwargs
        )

class NeuralShieldInputSanitizationError(NeuralShieldValidationError):
    """Input failed sanitization checks."""
    def __init__(self, message: str = "Input sanitization failed", **kwargs):
        kwargs.pop("error_code", None)  # Avoid duplicate
        kwargs.pop("severity", None)  # Avoid duplicate
        super().__init__(
            message,
            error_code="NS-V002",
            severity=ExceptionSeverity.ERROR,
            **kwargs
        )

class NeuralShieldPromptInjectionDetectedError(NeuralShieldValidationError):
    """Potential prompt injection detected."""
    def __init__(self, message: str = "Potential prompt injection detected", confidence: float = 0.0, **kwargs):
        details = kwargs.pop("details", {})
        details["detection_confidence"] = confidence
        kwargs.pop("error_code", None)  # Avoid duplicate
        kwargs.pop("severity", None)  # Avoid duplicate
        kwargs.pop("category", None)  # Avoid duplicate
        super().__init__(
            message,
            error_code="NS-V003",
            severity=ExceptionSeverity.CRITICAL,
            category=ExceptionCategory.THREAT_DETECTION,
            details=details,
            **kwargs
        )

# ----------------------------------------------------------------------------
# SECURITY ERRORS
# ----------------------------------------------------------------------------

class NeuralShieldSecurityError(NeuralShieldBaseError):
    """Security violation detected."""
    def __init__(self, message: str = "Security violation", **kwargs):
        kwargs.pop("category", None)  # Avoid duplicate - we explicitly set it
        kwargs.pop("severity", None)  # Avoid duplicate - we explicitly set it
        kwargs.pop("retry_eligible", None)  # Avoid duplicate - we explicitly set it
        super().__init__(
            message,
            error_code="NS-S001",
            severity=ExceptionSeverity.CRITICAL,
            category=ExceptionCategory.CRYPTOGRAPHIC,
            retry_eligible=False,
            **kwargs
        )

class NeuralShieldAuthenticationError(NeuralShieldSecurityError):
    """Authentication failed."""
    def __init__(self, message: str = "Authentication failed", **kwargs):
        super().__init__(
            message,
            error_code="NS-S002",
            category=ExceptionCategory.AUTHENTICATION,
            **kwargs
        )

class NeuralShieldAuthorizationError(NeuralShieldSecurityError):
    """Authorization denied."""
    def __init__(self, message: str = "Authorization denied", required_permission: Optional[str] = None, **kwargs):
        details = kwargs.pop("details", {})
        if required_permission:
            details["required_permission"] = required_permission
        super().__init__(
            message,
            error_code="NS-S003",
            category=ExceptionCategory.AUTHORIZATION,
            details=details,
            **kwargs
        )

class NeuralShieldIntegrityError(NeuralShieldSecurityError):
    """Data integrity check failed."""
    def __init__(self, message: str = "Data integrity verification failed", **kwargs):
        super().__init__(
            message,
            error_code="NS-S004",
            category=ExceptionCategory.INTEGRITY,
            **kwargs
        )

# ----------------------------------------------------------------------------
# CONFIGURATION ERRORS
# ----------------------------------------------------------------------------

class NeuralShieldConfigurationError(NeuralShieldBaseError):
    """Invalid configuration."""
    def __init__(self, message: str = "Configuration error", config_key: Optional[str] = None, **kwargs):
        details = kwargs.pop("details", {})
        if config_key:
            details["config_key"] = config_key
        super().__init__(
            message,
            error_code="NS-C001",
            category=ExceptionCategory.CONFIGURATION,
            severity=ExceptionSeverity.ERROR,
            retry_eligible=False,
            details=details,
            **kwargs
        )

# ----------------------------------------------------------------------------
# RESOURCE ERRORS
# ----------------------------------------------------------------------------

class NeuralShieldResourceExhaustedError(NeuralShieldBaseError):
    """Resource exhausted - NOT retry eligible without intervention."""
    def __init__(self, message: str = "Resource exhausted", resource_type: Optional[str] = None, **kwargs):
        details = kwargs.pop("details", {})
        if resource_type:
            details["resource_type"] = resource_type
        super().__init__(
            message,
            error_code="NS-R001",
            category=ExceptionCategory.RESOURCE,
            severity=ExceptionSeverity.ERROR,
            retry_eligible=False,
            details=details,
            **kwargs
        )

# ============================================================================
# RETRY + BACKOFF UTILITIES
# ============================================================================

class BackoffStrategy(Enum):
    """Backoff strategies for retry logic."""
    CONSTANT = "constant"
    LINEAR = "linear"
    EXPONENTIAL = "exponential"
    FIBONACCI = "fibonacci"
    JITTERED = "jittered"

@dataclass
class RetryConfig:
    """Configuration for retry behavior."""
    max_attempts: int = 3
    initial_delay: float = 1.0
    max_delay: float = 30.0
    backoff_strategy: BackoffStrategy = BackoffStrategy.EXPONENTIAL
    jitter: bool = True
    retry_on_exceptions: Tuple[type, ...] = (NeuralShieldTransientError,)
    graceful_fallback: Optional[Callable[..., Any]] = None
    
    def calculate_delay(self, attempt: int) -> float:
        """Calculate delay for given attempt number."""
        if attempt <= 0:
            return 0.0
            
        delay = self.initial_delay
        
        if self.backoff_strategy == BackoffStrategy.CONSTANT:
            delay = self.initial_delay
        elif self.backoff_strategy == BackoffStrategy.LINEAR:
            delay = self.initial_delay * attempt
        elif self.backoff_strategy == BackoffStrategy.EXPONENTIAL:
            delay = self.initial_delay * (2 ** (attempt - 1))
        elif self.backoff_strategy == BackoffStrategy.FIBONACCI:
            a, b = 0, self.initial_delay
            for _ in range(attempt):
                a, b = b, a + b
            delay = a
        elif self.backoff_strategy == BackoffStrategy.JITTERED:
            base = self.initial_delay * (2 ** (attempt - 1))
            delay = base * random.uniform(0.5, 1.5)
            
        delay = min(delay, self.max_delay)
        
        if self.jitter and self.backoff_strategy != BackoffStrategy.JITTERED:
            delay = delay * random.uniform(0.75, 1.25)
            
        return max(0, delay)

class RetryManager:
    """
    Manages retry logic with configurable backoff strategies.
    
    Usage:
        @retry(max_attempts=3)
        def flaky_operation():
            ...
    """
    
    def __init__(self, config: Optional[RetryConfig] = None):
        self.config = config or RetryConfig()
        self.attempts = 0
        self.last_error: Optional[Exception] = None
        
    def should_retry(self, exception: Exception) -> bool:
        """Determine if exception is retry-eligible."""
        if self.attempts >= self.config.max_attempts:
            return False
            
        if isinstance(exception, self.config.retry_on_exceptions):
            return True
            
        if hasattr(exception, 'retry_eligible') and exception.retry_eligible:
            return True
            
        return False
        
    def wait(self) -> None:
        """Wait according to backoff strategy."""
        delay = self.config.calculate_delay(self.attempts)
        if delay > 0:
            time.sleep(delay)
            
    def execute(self, func: Callable[..., T], *args, **kwargs) -> T:
        """Execute function with retry logic."""
        while True:
            try:
                self.attempts += 1
                return func(*args, **kwargs)
            except Exception as e:
                self.last_error = e
                
                if not self.should_retry(e):
                    if self.config.graceful_fallback is not None:
                        logger.warning(f"Falling back after {self.attempts} attempts: {e}")
                        return self.config.graceful_fallback(*args, **kwargs)
                    raise
                    
                logger.info(f"Retry attempt {self.attempts}/{self.config.max_attempts}: {e}")
                self.wait()

def retry(
    max_attempts: int = 3,
    initial_delay: float = 1.0,
    max_delay: float = 30.0,
    backoff_strategy: BackoffStrategy = BackoffStrategy.EXPONENTIAL,
    jitter: bool = True,
    retry_on: Tuple[type, ...] = (NeuralShieldTransientError,),
    fallback: Optional[Callable[..., Any]] = None
) -> Callable[[F], F]:
    """
    Decorator for automatic retry with backoff.
    
    Happy path is 100% preserved - only activates on exceptions.
    """
    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            config = RetryConfig(
                max_attempts=max_attempts,
                initial_delay=initial_delay,
                max_delay=max_delay,
                backoff_strategy=backoff_strategy,
                jitter=jitter,
                retry_on_exceptions=retry_on,
                graceful_fallback=fallback
            )
            manager = RetryManager(config)
            return manager.execute(func, *args, **kwargs)
        return wrapper  # type: ignore
    return decorator

# ============================================================================
# TIMEOUT WRAPPERS
# ============================================================================

class TimeoutManager:
    """
    Thread-based timeout wrapper for operations.
    
    NOTE: Uses threading - works for I/O bound operations.
    CPU-bound operations may require multiprocessing.
    """
    
    def __init__(self, timeout_seconds: float, fallback: Optional[Callable[..., Any]] = None):
        self.timeout_seconds = timeout_seconds
        self.fallback = fallback
        self._result: Any = None
        self._exception: Optional[Exception] = None
        
    def _target(self, func: Callable, args, kwargs):
        try:
            self._result = func(*args, **kwargs)
        except Exception as e:
            self._exception = e
            
    def execute(self, func: Callable[..., T], *args, **kwargs) -> T:
        """Execute function with timeout."""
        thread = threading.Thread(
            target=self._target,
            args=(func, args, kwargs)
        )
        thread.daemon = True
        thread.start()
        thread.join(timeout=self.timeout_seconds)
        
        if thread.is_alive():
            if self.fallback is not None:
                logger.warning(f"Timeout after {self.timeout_seconds}s, using fallback")
                return self.fallback(*args, **kwargs)
            raise NeuralShieldTimeoutError(
                f"Operation timed out after {self.timeout_seconds} seconds",
                timeout_seconds=self.timeout_seconds
            )
            
        if self._exception is not None:
            raise self._exception
            
        return self._result

def timeout(
    seconds: float,
    fallback: Optional[Callable[..., Any]] = None
) -> Callable[[F], F]:
    """
    Decorator for timeout protection.
    
    Happy path preserved - only activates on timeout.
    """
    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            manager = TimeoutManager(seconds, fallback)
            return manager.execute(func, *args, **kwargs)
        return wrapper  # type: ignore
    return decorator

# ============================================================================
# CIRCUIT BREAKER
# ============================================================================

class CircuitState(Enum):
    """Circuit breaker states."""
    CLOSED = "closed"       # Normal operation
    OPEN = "open"           # Tripped - fail fast
    HALF_OPEN = "half_open" # Testing recovery

@dataclass
class CircuitBreakerConfig:
    failure_threshold: int = 5
    reset_timeout: float = 30.0
    half_open_max_calls: int = 3
    tracked_exceptions: Tuple[type, ...] = (Exception,)

class CircuitBreaker:
    """
    Circuit breaker pattern for fault tolerance.
    
    Prevents cascading failures by failing fast after threshold reached.
    """
    
    def __init__(self, config: Optional[CircuitBreakerConfig] = None):
        self.config = config or CircuitBreakerConfig()
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.last_failure_time: Optional[datetime] = None
        self.half_open_attempts = 0
        self._lock = threading.Lock()
        
    def _check_state_transition(self) -> None:
        """Check and update circuit state."""
        with self._lock:
            now = datetime.utcnow()
            
            if self.state == CircuitState.OPEN:
                elapsed = (now - self.last_failure_time).total_seconds()
                if elapsed >= self.config.reset_timeout:
                    self.state = CircuitState.HALF_OPEN
                    self.half_open_attempts = 0
                    
    def on_success(self) -> None:
        """Record successful call."""
        self._check_state_transition()  # Ensure state is up-to-date
        with self._lock:
            if self.state == CircuitState.HALF_OPEN:
                self.half_open_attempts += 1
                if self.half_open_attempts >= self.config.half_open_max_calls:
                    self.state = CircuitState.CLOSED
                    self.failure_count = 0
            elif self.state == CircuitState.CLOSED:
                self.failure_count = max(0, self.failure_count - 1)
                
    def on_failure(self) -> None:
        """Record failed call."""
        with self._lock:
            self.failure_count += 1
            self.last_failure_time = datetime.utcnow()
            
            if self.state == CircuitState.HALF_OPEN:
                self.state = CircuitState.OPEN
            elif self.state == CircuitState.CLOSED:
                if self.failure_count >= self.config.failure_threshold:
                    self.state = CircuitState.OPEN
                    
    def allow_call(self) -> bool:
        """Check if call should be allowed."""
        self._check_state_transition()
        return self.state != CircuitState.OPEN
        
    def execute(self, func: Callable[..., T], *args, **kwargs) -> T:
        """Execute function with circuit breaker protection."""
        if not self.allow_call():
            raise NeuralShieldTransientError(
                f"Circuit breaker OPEN - failing fast (reset in {self.config.reset_timeout}s)",
                error_code="NS-CB001"
            )
            
        try:
            result = func(*args, **kwargs)
            self.on_success()
            return result
        except self.config.tracked_exceptions:
            self.on_failure()
            raise

# Global circuit breakers registry
_circuit_breakers: Dict[str, CircuitBreaker] = {}

def get_circuit_breaker(name: str, config: Optional[CircuitBreakerConfig] = None) -> CircuitBreaker:
    """Get or create a named circuit breaker."""
    if name not in _circuit_breakers:
        _circuit_breakers[name] = CircuitBreaker(config)
    return _circuit_breakers[name]

# ============================================================================
# GRACEFUL DEGRADATION FALLBACKS
# ============================================================================

@dataclass
class FallbackResult:
    """Result from graceful fallback execution."""
    value: Any
    is_fallback: bool = True
    original_error: Optional[Exception] = None
    fallback_source: str = "default"

def graceful_fallback(
    fallback_value: Any = None,
    fallback_function: Optional[Callable[..., Any]] = None,
    catch_exceptions: Tuple[type, ...] = (Exception,),
    log_fallback: bool = True
) -> Callable[[F], F]:
    """
    Decorator for graceful degradation.
    
    Returns fallback value/function result when exceptions occur.
    Happy path 100% preserved.
    """
    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except catch_exceptions as e:
                if log_fallback:
                    logger.warning(f"Graceful fallback activated for {func.__name__}: {e}")
                    
                if fallback_function is not None:
                    result = fallback_function(*args, **kwargs)
                else:
                    result = fallback_value
                    
                return FallbackResult(
                    value=result,
                    original_error=e,
                    fallback_source=func.__name__
                )
        return wrapper  # type: ignore
    return decorator

# ============================================================================
# BULKHEAD ISOLATION
# ============================================================================

class Bulkhead:
    """
    Bulkhead pattern for resource isolation.
    
    Limits concurrent calls to prevent resource exhaustion.
    """
    
    def __init__(self, max_concurrent: int = 10, max_queue_size: int = 100):
        self.max_concurrent = max_concurrent
        self.max_queue_size = max_queue_size
        self._semaphore = threading.Semaphore(max_concurrent)
        self._active_count = 0
        self._queued_count = 0
        self._lock = threading.Lock()
        
    @property
    def active_count(self) -> int:
        with self._lock:
            return self._active_count
            
    @property
    def queued_count(self) -> int:
        with self._lock:
            return self._queued_count
            
    def execute(self, func: Callable[..., T], *args, **kwargs) -> T:
        """Execute function within bulkhead constraints."""
        with self._lock:
            if self._queued_count >= self.max_queue_size:
                raise NeuralShieldResourceExhaustedError(
                    "Bulkhead queue full",
                    resource_type="bulkhead_queue"
                )
            self._queued_count += 1
            
        try:
            acquired = self._semaphore.acquire(timeout=30)
            if not acquired:
                raise NeuralShieldTimeoutError("Bulkhead acquisition timed out")
                
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
                self._queued_count = max(0, self._queued_count - 1)

# Global bulkheads registry
_bulkheads: Dict[str, Bulkhead] = {}

def get_bulkhead(name: str, max_concurrent: int = 10, max_queue: int = 100) -> Bulkhead:
    """Get or create a named bulkhead."""
    if name not in _bulkheads:
        _bulkheads[name] = Bulkhead(max_concurrent, max_queue)
    return _bulkheads[name]

# ============================================================================
# COMPREHENSIVE ERROR RESILIENCE WRAPPER
# ============================================================================

@dataclass
class ResilienceConfig:
    """Full resilience configuration."""
    retry_config: RetryConfig = field(default_factory=RetryConfig)
    timeout_seconds: Optional[float] = None
    circuit_breaker: Optional[CircuitBreaker] = None
    bulkhead: Optional[Bulkhead] = None
    fallback: Optional[Callable[..., Any]] = None

def resilient(
    config: Optional[ResilienceConfig] = None,
    **kwargs
) -> Callable[[F], F]:
    """
    Comprehensive resilience decorator combining:
    - Retry + backoff
    - Timeout protection
    - Circuit breaker
    - Bulkhead isolation
    - Graceful fallback
    
    All features OPT-IN - happy path 100% preserved.
    """
    cfg = config or ResilienceConfig(**kwargs)
    
    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args, **wrapper_kwargs):
            # Build execution chain from inside out
            current = func
            
            # Apply bulkhead
            if cfg.bulkhead is not None:
                bh = cfg.bulkhead
                def make_bulkhead(fn):
                    def bulkhead_wrapper(*a, **kw):
                        return bh.execute(fn, *a, **kw)
                    return bulkhead_wrapper
                current = make_bulkhead(current)
                
            # Apply circuit breaker
            if cfg.circuit_breaker is not None:
                cb = cfg.circuit_breaker
                def make_circuit(fn):
                    def circuit_wrapper(*a, **kw):
                        return cb.execute(fn, *a, **kw)
                    return circuit_wrapper
                current = make_circuit(current)
                
            # Apply timeout
            if cfg.timeout_seconds is not None:
                ts = cfg.timeout_seconds
                fb = cfg.fallback
                def make_timeout(fn):
                    def timeout_wrapper(*a, **kw):
                        manager = TimeoutManager(ts, fb)
                        return manager.execute(fn, *a, **kw)
                    return timeout_wrapper
                current = make_timeout(current)
                
            # Apply retry (outermost)
            retry_manager = RetryManager(cfg.retry_config)
            return retry_manager.execute(current, *args, **wrapper_kwargs)
            
        return wrapper  # type: ignore
    return decorator

# ============================================================================
# EXPORT PUBLIC API
# ============================================================================

__all__ = [
    # Enums
    'ExceptionSeverity',
    'ExceptionCategory',
    'BackoffStrategy',
    'CircuitState',
    
    # Base Exceptions
    'NeuralShieldBaseError',
    'NeuralShieldTransientError',
    'NeuralShieldTimeoutError',
    'NeuralShieldRateLimitError',
    'NeuralShieldNetworkError',
    'NeuralShieldResourceTemporarilyUnavailableError',
    'NeuralShieldValidationError',
    'NeuralShieldInputSanitizationError',
    'NeuralShieldPromptInjectionDetectedError',
    'NeuralShieldSecurityError',
    'NeuralShieldAuthenticationError',
    'NeuralShieldAuthorizationError',
    'NeuralShieldIntegrityError',
    'NeuralShieldConfigurationError',
    'NeuralShieldResourceExhaustedError',
    
    # Retry
    'RetryConfig',
    'RetryManager',
    'retry',
    
    # Timeout
    'TimeoutManager',
    'timeout',
    
    # Circuit Breaker
    'CircuitBreakerConfig',
    'CircuitBreaker',
    'get_circuit_breaker',
    
    # Fallback
    'FallbackResult',
    'graceful_fallback',
    
    # Bulkhead
    'Bulkhead',
    'get_bulkhead',
    
    # Comprehensive
    'ResilienceConfig',
    'resilient',
]
