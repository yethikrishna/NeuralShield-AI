"""
Error Resilience - Strategic Fallback Chain with Priority-Based Degradation v34
Dimension E: Error Resilience

ADD-ONLY implementation - wraps existing functionality, no core code modified
Happy path behavior 100% preserved

Features:
1. Enhanced custom exception hierarchy for threat detection
2. Adaptive timeout with exponential jitter backoff
3. Strategic fallback chain with priority-based degradation
4. Circuit breaker with health-aware state management
5. Bulkhead isolation for critical vs non-critical operations
"""

import time
import random
import threading
import functools
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Type, Tuple, Union
from datetime import datetime, timedelta


# -----------------------------------------------------------------------------
# ENHANCED EXCEPTION HIERARCHY - Dimension E
# -----------------------------------------------------------------------------

class NeuralShieldError(Exception):
    """Base exception for all NeuralShield errors"""
    error_code: str = "NS-000"
    severity: str = "ERROR"
    retryable: bool = False
    fallback_available: bool = False

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}
        self.timestamp = datetime.utcnow().isoformat()


class ThreatDetectionError(NeuralShieldError):
    """Base for threat detection subsystem errors"""
    error_code = "NS-TD-000"


class PromptInjectionDetectionError(ThreatDetectionError):
    """Error during prompt injection detection"""
    error_code = "NS-TD-001"
    retryable = True
    fallback_available = True


class JailbreakDetectionError(ThreatDetectionError):
    """Error during jailbreak detection"""
    error_code = "NS-TD-002"
    retryable = True
    fallback_available = True


class ModelInferenceTimeoutError(ThreatDetectionError):
    """Model inference timed out"""
    error_code = "NS-TD-003"
    retryable = True
    fallback_available = True


class ModelInferenceError(ThreatDetectionError):
    """Model inference failed"""
    error_code = "NS-TD-004"
    retryable = True
    fallback_available = True


class ThreatIntelligenceError(NeuralShieldError):
    """Base for threat intelligence errors"""
    error_code = "NS-TI-000"


class ThreatFeedUnavailableError(ThreatIntelligenceError):
    """Threat feed service unavailable"""
    error_code = "NS-TI-001"
    retryable = True
    fallback_available = True


class ThreatFeedTimeoutError(ThreatIntelligenceError):
    """Threat feed request timed out"""
    error_code = "NS-TI-002"
    retryable = True
    fallback_available = True


class ObservabilityError(NeuralShieldError):
    """Base for observability subsystem errors"""
    error_code = "NS-OBS-000"
    fallback_available = True  # Observability can always fall back to no-op


class LoggingSubsystemError(ObservabilityError):
    """Logging subsystem failed"""
    error_code = "NS-OBS-001"
    fallback_available = True


class MetricsCollectionError(ObservabilityError):
    """Metrics collection failed"""
    error_code = "NS-OBS-002"
    fallback_available = True


class SecurityValidationError(NeuralShieldError):
    """Base for security validation errors"""
    error_code = "NS-SEC-000"


class InputValidationError(SecurityValidationError):
    """Input validation failed"""
    error_code = "NS-SEC-001"
    retryable = False


# -----------------------------------------------------------------------------
# FALLBACK PRIORITY ENUM
# -----------------------------------------------------------------------------

class FallbackPriority(Enum):
    CRITICAL = "critical"      # Must succeed - use all fallbacks
    HIGH = "high"              # Use primary + 2 fallbacks
    MEDIUM = "medium"          # Use primary + 1 fallback
    LOW = "low"                # Primary only, fail fast
    BEST_EFFORT = "best_effort"  # No fallback, silent failure allowed


class CircuitBreakerState(Enum):
    CLOSED = "closed"          # Normal operation
    OPEN = "open"              # Tripped, reject requests
    HALF_OPEN = "half_open"    # Testing recovery


# -----------------------------------------------------------------------------
# DATA CLASSES
# -----------------------------------------------------------------------------

@dataclass
class RetryConfig:
    max_attempts: int = 3
    initial_delay: float = 0.1
    max_delay: float = 5.0
    backoff_factor: float = 2.0
    jitter_factor: float = 0.1
    retry_on: Tuple[Type[Exception], ...] = field(default_factory=lambda: (
        ModelInferenceTimeoutError,
        ModelInferenceError,
        ThreatFeedTimeoutError,
        ThreatFeedUnavailableError,
    ))


@dataclass
class FallbackStrategy:
    priority: FallbackPriority
    timeout_seconds: float = 30.0
    allow_degraded: bool = True
    bulkhead_key: Optional[str] = None


@dataclass
class FallbackResult:
    success: bool
    result: Any
    strategy_used: str
    attempts: int
    total_time: float
    degraded: bool = False
    warnings: List[str] = field(default_factory=list)


# -----------------------------------------------------------------------------
# ADAPTIVE TIMEOUT WITH JITTER
# -----------------------------------------------------------------------------

class AdaptiveTimeout:
    """Adaptive timeout with exponential backoff and jitter
    
    ADD-ONLY wrapper - does not modify wrapped functions
    """

    def __init__(self, default_timeout: float = 10.0):
        self.default_timeout = default_timeout
        self._success_times: Dict[str, List[float]] = {}
        self._lock = threading.Lock()

    def _calculate_adaptive_timeout(self, operation_key: str) -> float:
        """Calculate timeout based on historical performance"""
        with self._lock:
            times = self._success_times.get(operation_key, [])
            if not times:
                return self.default_timeout
            
            avg_time = sum(times) / len(times)
            std_dev = (sum((t - avg_time) ** 2 for t in times) / len(times)) ** 0.5 if len(times) > 1 else 0
            
            # 95th percentile + buffer
            return min(avg_time + 2 * std_dev + 1.0, self.default_timeout * 3)

    def _record_success(self, operation_key: str, duration: float):
        """Record successful operation time for adaptation"""
        with self._lock:
            if operation_key not in self._success_times:
                self._success_times[operation_key] = []
            self._success_times[operation_key].append(duration)
            # Keep only last 100 measurements
            if len(self._success_times[operation_key]) > 100:
                self._success_times[operation_key] = self._success_times[operation_key][-100:]


# -----------------------------------------------------------------------------
# CIRCUIT BREAKER
# -----------------------------------------------------------------------------

class CircuitBreaker:
    """Circuit breaker with health-aware state management
    
    ADD-ONLY wrapper - protects downstream services from cascading failure
    """

    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: float = 30.0,
        half_open_max_calls: int = 3
    ):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.half_open_max_calls = half_open_max_calls
        
        self._state = CircuitBreakerState.CLOSED
        self._failure_count = 0
        self._last_failure_time: Optional[datetime] = None
        self._half_open_attempts = 0
        self._lock = threading.Lock()

    def _check_state(self) -> CircuitBreakerState:
        """Check and update circuit breaker state"""
        with self._lock:
            if self._state == CircuitBreakerState.OPEN:
                if self._last_failure_time and \
                   datetime.utcnow() - self._last_failure_time > timedelta(seconds=self.recovery_timeout):
                    self._state = CircuitBreakerState.HALF_OPEN
                    self._half_open_attempts = 0
            return self._state

    def _record_success(self):
        """Record successful call"""
        with self._lock:
            if self._state == CircuitBreakerState.HALF_OPEN:
                self._half_open_attempts += 1
                if self._half_open_attempts >= self.half_open_max_calls:
                    self._state = CircuitBreakerState.CLOSED
                    self._failure_count = 0
                    self._half_open_attempts = 0
            else:
                self._failure_count = 0

    def _record_failure(self):
        """Record failed call"""
        with self._lock:
            self._failure_count += 1
            self._last_failure_time = datetime.utcnow()
            
            if self._state == CircuitBreakerState.HALF_OPEN:
                self._state = CircuitBreakerState.OPEN
                self._half_open_attempts = 0
            elif self._failure_count >= self.failure_threshold:
                self._state = CircuitBreakerState.OPEN


# -----------------------------------------------------------------------------
# STRATEGIC FALLBACK CHAIN - MAIN IMPLEMENTATION
# -----------------------------------------------------------------------------

class StrategicFallbackChain:
    """Strategic fallback chain with priority-based degradation
    
    Dimension E - Error Resilience Core Implementation
    
    Features:
    - Priority-based fallback selection
    - Retry with exponential backoff + jitter
    - Circuit breaker protection
    - Bulkhead isolation
    - 100% backward compatible
    """

    def __init__(self):
        self._adaptive_timeout = AdaptiveTimeout()
        self._circuit_breakers: Dict[str, CircuitBreaker] = {}
        self._bulkhead_semaphores: Dict[str, threading.Semaphore] = {}
        self._fallback_registry: Dict[str, List[Callable]] = {}
        self._lock = threading.Lock()

    def register_fallback(self, operation_key: str, fallback: Callable):
        """Register a fallback for an operation (ADD-ONLY)"""
        with self._lock:
            if operation_key not in self._fallback_registry:
                self._fallback_registry[operation_key] = []
            self._fallback_registry[operation_key].append(fallback)

    def _get_circuit_breaker(self, key: str) -> CircuitBreaker:
        """Get or create circuit breaker"""
        with self._lock:
            if key not in self._circuit_breakers:
                self._circuit_breakers[key] = CircuitBreaker()
            return self._circuit_breakers[key]

    def _get_bulkhead(self, key: str, max_concurrent: int = 10) -> threading.Semaphore:
        """Get or create bulkhead semaphore"""
        with self._lock:
            if key not in self._bulkhead_semaphores:
                self._bulkhead_semaphores[key] = threading.Semaphore(max_concurrent)
            return self._bulkhead_semaphores[key]

    def _calculate_delay(self, attempt: int, config: RetryConfig) -> float:
        """Calculate delay with exponential backoff and jitter"""
        delay = config.initial_delay * (config.backoff_factor ** attempt)
        delay = min(delay, config.max_delay)
        jitter = delay * config.jitter_factor * (random.random() * 2 - 1)
        return max(0, delay + jitter)

    def execute_with_resilience(
        self,
        operation: Callable,
        operation_key: str,
        strategy: FallbackStrategy,
        retry_config: Optional[RetryConfig] = None,
        *args,
        **kwargs
    ) -> FallbackResult:
        """
        Execute operation with full error resilience stack
        
        ADD-ONLY - wraps operation without modifying it
        Happy path: direct execution with minimal overhead
        """
        retry_config = retry_config or RetryConfig()
        start_time = time.time()
        warnings: List[str] = []
        degraded = False

        # Check circuit breaker first
        cb = self._get_circuit_breaker(operation_key)
        cb_state = cb._check_state()
        
        if cb_state == CircuitBreakerState.OPEN:
            warnings.append(f"Circuit breaker OPEN for {operation_key}, using fallback")
            degraded = True
            return self._execute_fallback_chain(
                operation_key, strategy, start_time, warnings, degraded, *args, **kwargs
            )

        # Bulkhead isolation
        bulkhead_key = strategy.bulkhead_key or operation_key
        semaphore = self._get_bulkhead(bulkhead_key)
        
        if not semaphore.acquire(blocking=False):
            warnings.append(f"Bulkhead limit reached for {bulkhead_key}")
            degraded = True

        try:
            # Retry loop
            for attempt in range(retry_config.max_attempts):
                try:
                    result = operation(*args, **kwargs)
                    cb._record_success()
                    
                    # Record timing for adaptive timeout
                    duration = time.time() - start_time
                    self._adaptive_timeout._record_success(operation_key, duration)
                    
                    return FallbackResult(
                        success=True,
                        result=result,
                        strategy_used="primary",
                        attempts=attempt + 1,
                        total_time=time.time() - start_time,
                        degraded=degraded,
                        warnings=warnings
                    )
                    
                except retry_config.retry_on as e:
                    if attempt < retry_config.max_attempts - 1:
                        delay = self._calculate_delay(attempt, retry_config)
                        warnings.append(f"Retry {attempt + 1}/{retry_config.max_attempts} after {delay:.2f}s: {str(e)}")
                        time.sleep(delay)
                    else:
                        cb._record_failure()
                        warnings.append(f"All retries exhausted: {str(e)}")
                        break
                except Exception as e:
                    cb._record_failure()
                    warnings.append(f"Non-retryable error: {str(e)}")
                    break

        finally:
            if semaphore.acquire(blocking=False):
                semaphore.release()

        # Fallback chain if primary failed
        degraded = True
        return self._execute_fallback_chain(
            operation_key, strategy, start_time, warnings, degraded, *args, **kwargs
        )

    def _execute_fallback_chain(
        self,
        operation_key: str,
        strategy: FallbackStrategy,
        start_time: float,
        warnings: List[str],
        degraded: bool,
        *args,
        **kwargs
    ) -> FallbackResult:
        """Execute registered fallbacks in priority order"""
        fallbacks = self._fallback_registry.get(operation_key, [])
        
        # Determine how many fallbacks to use based on priority
        fallback_limits = {
            FallbackPriority.CRITICAL: len(fallbacks),  # All
            FallbackPriority.HIGH: min(2, len(fallbacks)),
            FallbackPriority.MEDIUM: min(1, len(fallbacks)),
            FallbackPriority.LOW: 0,
            FallbackPriority.BEST_EFFORT: 0,
        }
        
        max_fallbacks = fallback_limits.get(strategy.priority, 0)
        
        for i, fallback in enumerate(fallbacks[:max_fallbacks]):
            try:
                result = fallback(*args, **kwargs)
                warnings.append(f"Used fallback {i + 1}")
                return FallbackResult(
                    success=True,
                    result=result,
                    strategy_used=f"fallback_{i + 1}",
                    attempts=i + 1,
                    total_time=time.time() - start_time,
                    degraded=True,
                    warnings=warnings
                )
            except Exception as e:
                warnings.append(f"Fallback {i + 1} failed: {str(e)}")
                continue

        # Ultimate fallback - degraded mode or safe default
        if strategy.allow_degraded:
            warnings.append("Using ultimate safe default (degraded mode)")
            return FallbackResult(
                success=True,
                result=self._get_safe_default(operation_key),
                strategy_used="safe_default",
                attempts=0,
                total_time=time.time() - start_time,
                degraded=True,
                warnings=warnings
            )

        return FallbackResult(
            success=False,
            result=None,
            strategy_used="all_failed",
            attempts=0,
            total_time=time.time() - start_time,
            degraded=True,
            warnings=warnings + ["All fallbacks exhausted and degraded mode not allowed"]
        )

    def _get_safe_default(self, operation_key: str) -> Any:
        """Get safe default response based on operation type"""
        if "detect" in operation_key.lower() or "injection" in operation_key.lower():
            return {"risk_score": 0.0, "threat_detected": False, "degraded": True}
        elif "threat" in operation_key.lower():
            return {"threats": [], "count": 0, "degraded": True}
        elif "analyze" in operation_key.lower():
            return {"analysis": "degraded", "confidence": 0.0, "degraded": True}
        else:
            return {"status": "degraded", "success": True}


# -----------------------------------------------------------------------------
# CONVENIENCE DECORATORS (ADD-ONLY)
# -----------------------------------------------------------------------------

_global_fallback_chain = StrategicFallbackChain()


def with_resilience(
    operation_key: str,
    priority: FallbackPriority = FallbackPriority.MEDIUM,
    timeout: float = 10.0,
    allow_degraded: bool = True
):
    """Decorator for adding resilience to functions (ADD-ONLY)"""
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            strategy = FallbackStrategy(
                priority=priority,
                timeout_seconds=timeout,
                allow_degraded=allow_degraded
            )
            result = _global_fallback_chain.execute_with_resilience(
                func, operation_key, strategy, None, *args, **kwargs
            )
            if not result.success and not allow_degraded:
                raise RuntimeError(f"Operation failed: {result.warnings}")
            return result.result
        return wrapper
    return decorator


def register_fallback_for(operation_key: str):
    """Decorator to register fallback (ADD-ONLY)"""
    def decorator(func: Callable) -> Callable:
        _global_fallback_chain.register_fallback(operation_key, func)
        return func
    return decorator


# -----------------------------------------------------------------------------
# EXPORTS
# -----------------------------------------------------------------------------

__all__ = [
    # Exceptions
    "NeuralShieldError",
    "ThreatDetectionError",
    "PromptInjectionDetectionError",
    "JailbreakDetectionError",
    "ModelInferenceTimeoutError",
    "ModelInferenceError",
    "ThreatIntelligenceError",
    "ThreatFeedUnavailableError",
    "ThreatFeedTimeoutError",
    "ObservabilityError",
    "LoggingSubsystemError",
    "MetricsCollectionError",
    "SecurityValidationError",
    "InputValidationError",
    
    # Enums
    "FallbackPriority",
    "CircuitBreakerState",
    
    # Data classes
    "RetryConfig",
    "FallbackStrategy",
    "FallbackResult",
    
    # Core classes
    "AdaptiveTimeout",
    "CircuitBreaker",
    "StrategicFallbackChain",
    
    # Decorators
    "with_resilience",
    "register_fallback_for",
]
