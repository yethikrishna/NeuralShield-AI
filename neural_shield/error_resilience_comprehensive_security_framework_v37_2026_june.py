"""
Error Resilience Comprehensive Security Framework v37
Dimension E: Error Resilience - June 2026

Add-only incremental enhancement:
- Custom security-focused exception hierarchy
- Advanced timeout wrappers with context propagation
- Exponential backoff with jitter retry utilities
- Graceful degradation fallbacks for security modules

Happy path behavior 100% preserved - all instrumentation is OPT-IN and wraps existing code.
"""

import time
import random
import logging
import functools
import threading
from typing import Any, Callable, Optional, Type, Tuple, Union, Dict, List
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta


# -----------------------------------------------------------------------------
# Custom Exception Hierarchy (Security-Focused)
# -----------------------------------------------------------------------------

class NeuralShieldError(Exception):
    """Base exception for all NeuralShield errors."""
    error_code: str = "NEURALSHIELD_ERROR"
    severity: str = "ERROR"
    timestamp: datetime
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        self.timestamp = datetime.utcnow()
        self.details = details or {}
        super().__init__(message)


class NeuralShieldWarning(NeuralShieldError):
    """Warning-level exceptions - non-critical, recoverable."""
    error_code = "NEURALSHIELD_WARNING"
    severity = "WARNING"


class NeuralShieldCritical(NeuralShieldError):
    """Critical-level exceptions - requires immediate attention."""
    error_code = "NEURALSHIELD_CRITICAL"
    severity = "CRITICAL"


# Threat Detection Exceptions
class ThreatDetectionError(NeuralShieldError):
    """Base exception for threat detection subsystem errors."""
    error_code = "THREAT_DETECTION_ERROR"


class ThreatDetectionTimeout(ThreatDetectionError, NeuralShieldWarning):
    """Threat detection operation timed out - graceful fallback available."""
    error_code = "THREAT_DETECTION_TIMEOUT"


class ThreatDetectionTemporaryFailure(ThreatDetectionError, NeuralShieldWarning):
    """Temporary failure - retry recommended."""
    error_code = "THREAT_DETECTION_TEMPORARY_FAILURE"


class ThreatDetectionPermanentFailure(ThreatDetectionError, NeuralShieldCritical):
    """Permanent failure - do not retry."""
    error_code = "THREAT_DETECTION_PERMANENT_FAILURE"


# Model Inference Exceptions
class ModelInferenceError(NeuralShieldError):
    """Base exception for model inference errors."""
    error_code = "MODEL_INFERENCE_ERROR"


class ModelInferenceTimeout(ModelInferenceError, NeuralShieldWarning):
    """Model inference timed out."""
    error_code = "MODEL_INFERENCE_TIMEOUT"


class ModelInferenceOverloaded(ModelInferenceError, NeuralShieldWarning):
    """Model service overloaded - backoff recommended."""
    error_code = "MODEL_INFERENCE_OVERLOADED"


class ModelInferenceUnavailable(ModelInferenceError, NeuralShieldCritical):
    """Model service unavailable."""
    error_code = "MODEL_INFERENCE_UNAVAILABLE"


# Security Validation Exceptions
class SecurityValidationError(NeuralShieldError):
    """Base exception for security validation errors."""
    error_code = "SECURITY_VALIDATION_ERROR"


class InputValidationError(SecurityValidationError):
    """Input validation failed."""
    error_code = "INPUT_VALIDATION_ERROR"


class RateLimitExceeded(SecurityValidationError, NeuralShieldWarning):
    """Rate limit exceeded."""
    error_code = "RATE_LIMIT_EXCEEDED"


# -----------------------------------------------------------------------------
# Retry Strategies with Exponential Backoff + Jitter
# -----------------------------------------------------------------------------

class RetryStrategy(Enum):
    """Available retry strategies."""
    EXPONENTIAL_BACKOFF = "exponential_backoff"
    FIXED_INTERVAL = "fixed_interval"
    LINEAR_BACKOFF = "linear_backoff"


@dataclass
class RetryConfig:
    """Configuration for retry behavior."""
    max_attempts: int = 3
    initial_delay: float = 0.1
    max_delay: float = 5.0
    backoff_factor: float = 2.0
    jitter_factor: float = 0.1
    strategy: RetryStrategy = RetryStrategy.EXPONENTIAL_BACKOFF
    retry_on: Tuple[Type[Exception], ...] = (
        ThreatDetectionTemporaryFailure,
        ModelInferenceTimeout,
        ModelInferenceOverloaded,
        TimeoutError,
        ConnectionError,
    )
    on_retry_callback: Optional[Callable[[int, Exception], None]] = None


class RetryManager:
    """
    Manages retry logic with configurable backoff strategies.
    Fully backward compatible - wraps existing functions.
    """
    
    def __init__(self, config: Optional[RetryConfig] = None):
        self.config = config or RetryConfig()
        self._retry_counts: Dict[str, int] = {}
    
    def _calculate_delay(self, attempt: int) -> float:
        """Calculate delay with jitter based on strategy."""
        if self.config.strategy == RetryStrategy.EXPONENTIAL_BACKOFF:
            delay = self.config.initial_delay * (self.config.backoff_factor ** (attempt - 1))
        elif self.config.strategy == RetryStrategy.LINEAR_BACKOFF:
            delay = self.config.initial_delay * attempt
        else:  # FIXED_INTERVAL
            delay = self.config.initial_delay
        
        delay = min(delay, self.config.max_delay)
        
        # Add jitter
        jitter = random.uniform(
            -delay * self.config.jitter_factor,
            delay * self.config.jitter_factor
        )
        
        return max(0.001, delay + jitter)
    
    def __call__(self, func: Callable) -> Callable:
        """Decorator for retry logic."""
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            func_name = f"{func.__module__}.{func.__name__}"
            last_exception: Optional[Exception] = None
            
            for attempt in range(1, self.config.max_attempts + 1):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    
                    # Check if this exception type should be retried
                    if not isinstance(e, self.config.retry_on):
                        raise
                    
                    # Check if we've exhausted retries
                    if attempt >= self.config.max_attempts:
                        break
                    
                    # Calculate and apply delay
                    delay = self._calculate_delay(attempt)
                    
                    if self.config.on_retry_callback:
                        self.config.on_retry_callback(attempt, e)
                    
                    self._retry_counts[func_name] = self._retry_counts.get(func_name, 0) + 1
                    
                    time.sleep(delay)
            
            # If we get here, all retries failed
            raise ThreatDetectionTemporaryFailure(
                f"All {self.config.max_attempts} retry attempts failed for {func_name}",
                details={"last_error": str(last_exception), "attempts": attempt}
            ) from last_exception
        
        return wrapper
    
    def get_retry_stats(self) -> Dict[str, int]:
        """Get retry statistics."""
        return dict(self._retry_counts)


# -----------------------------------------------------------------------------
# Timeout Wrappers with Context Propagation
# -----------------------------------------------------------------------------

@dataclass
class TimeoutContext:
    """Context for timeout operations."""
    deadline: datetime
    operation_name: str
    timeout_seconds: float
    start_time: datetime = field(default_factory=datetime.utcnow)
    
    def remaining_time(self) -> float:
        """Get remaining time in seconds."""
        return max(0.0, (self.deadline - datetime.utcnow()).total_seconds())
    
    def is_expired(self) -> bool:
        """Check if deadline has passed."""
        return datetime.utcnow() >= self.deadline


class TimeoutManager:
    """
    Thread-safe timeout manager with context propagation.
    Wraps existing functions - no breaking changes.
    """
    
    def __init__(self, default_timeout: float = 30.0):
        self.default_timeout = default_timeout
        self._local = threading.local()
    
    def _get_current_context(self) -> Optional[TimeoutContext]:
        """Get current thread's timeout context."""
        return getattr(self._local, 'current_context', None)
    
    def _set_current_context(self, ctx: Optional[TimeoutContext]):
        """Set current thread's timeout context."""
        self._local.current_context = ctx
    
    def check_timeout(self) -> None:
        """Check if current operation has timed out."""
        ctx = self._get_current_context()
        if ctx and ctx.is_expired():
            raise ThreatDetectionTimeout(
                f"Operation '{ctx.operation_name}' timed out after {ctx.timeout_seconds}s",
                details={"deadline": ctx.deadline.isoformat()}
            )
    
    def with_timeout(self, timeout_seconds: Optional[float] = None, 
                     operation_name: Optional[str] = None) -> Callable:
        """Decorator to add timeout to a function."""
        timeout = timeout_seconds or self.default_timeout
        
        def decorator(func: Callable) -> Callable:
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                op_name = operation_name or func.__name__
                deadline = datetime.utcnow() + timedelta(seconds=timeout)
                
                # Propagate parent deadline if it's earlier
                parent_ctx = self._get_current_context()
                if parent_ctx and parent_ctx.deadline < deadline:
                    deadline = parent_ctx.deadline
                
                new_ctx = TimeoutContext(
                    deadline=deadline,
                    operation_name=op_name,
                    timeout_seconds=timeout
                )
                
                old_ctx = self._get_current_context()
                self._set_current_context(new_ctx)
                
                try:
                    self.check_timeout()
                    return func(*args, **kwargs)
                finally:
                    self._set_current_context(old_ctx)
            
            return wrapper
        
        return decorator


# -----------------------------------------------------------------------------
# Graceful Degradation Fallbacks
# -----------------------------------------------------------------------------

class FallbackStrategy(Enum):
    """Fallback strategies for graceful degradation."""
    RETURN_DEFAULT = "return_default"
    RETURN_CACHED = "return_cached"
    DEGRADE_FUNCTIONALITY = "degrade_functionality"
    RAISE_SAFE_EXCEPTION = "raise_safe_exception"


@dataclass
class FallbackConfig:
    """Configuration for fallback behavior."""
    strategy: FallbackStrategy = FallbackStrategy.RETURN_DEFAULT
    default_value: Any = None
    fallback_function: Optional[Callable] = None
    cache_ttl: float = 60.0
    log_warnings: bool = True


class GracefulDegradationManager:
    """
    Provides graceful degradation for security modules.
    Never breaks happy path - only activates on errors.
    """
    
    def __init__(self):
        self._cache: Dict[str, Tuple[Any, datetime]] = {}
        self._fallback_counts: Dict[str, int] = {}
        self._logger = logging.getLogger(__name__)
    
    def _get_cached(self, key: str, ttl: float) -> Optional[Any]:
        """Get cached value if valid."""
        if key in self._cache:
            value, timestamp = self._cache[key]
            if (datetime.utcnow() - timestamp).total_seconds() < ttl:
                return value
            del self._cache[key]
        return None
    
    def _cache_value(self, key: str, value: Any) -> None:
        """Cache a value."""
        self._cache[key] = (value, datetime.utcnow())
    
    def with_fallback(self, config: Optional[FallbackConfig] = None,
                      cache_key: Optional[str] = None) -> Callable:
        """Decorator for graceful fallback behavior."""
        cfg = config or FallbackConfig()
        
        def decorator(func: Callable) -> Callable:
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                func_key = cache_key or f"{func.__module__}.{func.__name__}"
                
                try:
                    # Happy path - normal execution
                    result = func(*args, **kwargs)
                    
                    # Cache successful result
                    if cfg.strategy == FallbackStrategy.RETURN_CACHED:
                        self._cache_value(func_key, result)
                    
                    return result
                    
                except Exception as e:
                    # Error path - apply fallback strategy
                    self._fallback_counts[func_key] = self._fallback_counts.get(func_key, 0) + 1
                    
                    if cfg.log_warnings:
                        self._logger.warning(
                            f"Graceful degradation activated for {func_key}: {str(e)}"
                        )
                    
                    if cfg.strategy == FallbackStrategy.RETURN_DEFAULT:
                        return cfg.default_value
                    
                    elif cfg.strategy == FallbackStrategy.RETURN_CACHED:
                        cached = self._get_cached(func_key, cfg.cache_ttl)
                        if cached is not None:
                            return cached
                        return cfg.default_value
                    
                    elif cfg.strategy == FallbackStrategy.DEGRADE_FUNCTIONALITY:
                        if cfg.fallback_function:
                            return cfg.fallback_function(*args, **kwargs)
                        return cfg.default_value
                    
                    elif cfg.strategy == FallbackStrategy.RAISE_SAFE_EXCEPTION:
                        raise NeuralShieldWarning(
                            f"Operation degraded: {func_key}",
                            details={"original_error": str(e)}
                        ) from e
                    
                    # Default: return default value
                    return cfg.default_value
            
            return wrapper
        
        return decorator
    
    def get_fallback_stats(self) -> Dict[str, Any]:
        """Get fallback statistics."""
        return {
            "fallback_counts": dict(self._fallback_counts),
            "cache_size": len(self._cache),
            "total_fallbacks": sum(self._fallback_counts.values())
        }


# -----------------------------------------------------------------------------
# Composite Error Resilience Manager
# -----------------------------------------------------------------------------

class SecurityErrorResilienceManager:
    """
    Unified manager combining all error resilience features.
    Fully backward compatible - OPT-IN only.
    """
    
    def __init__(self, 
                 default_timeout: float = 30.0,
                 retry_config: Optional[RetryConfig] = None,
                 fallback_config: Optional[FallbackConfig] = None):
        self.timeout_manager = TimeoutManager(default_timeout)
        self.retry_manager = RetryManager(retry_config)
        self.fallback_manager = GracefulDegradationManager()
        self._default_fallback = fallback_config or FallbackConfig()
    
    def secure_operation(self,
                        timeout: Optional[float] = None,
                        retry: bool = True,
                        fallback: bool = True,
                        fallback_config: Optional[FallbackConfig] = None) -> Callable:
        """
        Composite decorator applying timeout, retry, and fallback.
        Happy path behavior 100% preserved.
        """
        def decorator(func: Callable) -> Callable:
            wrapped = func
            
            if timeout is not None:
                wrapped = self.timeout_manager.with_timeout(timeout)(wrapped)
            
            if retry:
                wrapped = self.retry_manager(wrapped)
            
            if fallback:
                wrapped = self.fallback_manager.with_fallback(
                    fallback_config or self._default_fallback
                )(wrapped)
            
            return wrapped
        
        return decorator
    
    def get_health_metrics(self) -> Dict[str, Any]:
        """Get comprehensive health metrics."""
        return {
            "retry_stats": self.retry_manager.get_retry_stats(),
            "fallback_stats": self.fallback_manager.get_fallback_stats(),
            "timestamp": datetime.utcnow().isoformat()
        }


# -----------------------------------------------------------------------------
# Module Exports
# -----------------------------------------------------------------------------

__all__ = [
    # Exceptions
    "NeuralShieldError",
    "NeuralShieldWarning",
    "NeuralShieldCritical",
    "ThreatDetectionError",
    "ThreatDetectionTimeout",
    "ThreatDetectionTemporaryFailure",
    "ThreatDetectionPermanentFailure",
    "ModelInferenceError",
    "ModelInferenceTimeout",
    "ModelInferenceOverloaded",
    "ModelInferenceUnavailable",
    "SecurityValidationError",
    "InputValidationError",
    "RateLimitExceeded",
    
    # Retry
    "RetryStrategy",
    "RetryConfig",
    "RetryManager",
    
    # Timeout
    "TimeoutContext",
    "TimeoutManager",
    
    # Fallback
    "FallbackStrategy",
    "FallbackConfig",
    "GracefulDegradationManager",
    
    # Composite
    "SecurityErrorResilienceManager",
]
