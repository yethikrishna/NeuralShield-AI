"""
NeuralShield Error Resilience v22 - Advanced Circuit Breaker with Intelligent Fallback Orchestration

ADD-ONLY MODULE - No existing code modified
100% backward compatible - wraps existing code, never replaces

Features:
- Advanced Circuit Breaker with half-open state auto-recovery
- Priority-based Fallback Chain Orchestrator
- Bulkhead Isolation with per-operation resource limits
- Adaptive Timeout with exponential jitter backoff
- Health-based request routing
- Graceful degradation with quality tiers
"""

import time
import random
import threading
import enum
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, TypeVar, Generic, Tuple
from collections import deque
from functools import wraps

T = TypeVar('T')

class CircuitState(enum.Enum):
    CLOSED = "closed"           # Normal operation
    OPEN = "open"               # Tripped - fail fast
    HALF_OPEN = "half_open"     # Testing recovery

class FallbackPriority(enum.Enum):
    CRITICAL = 0    # Must succeed, try all fallbacks
    HIGH = 1        # Try primary + 2 fallbacks
    MEDIUM = 2      # Try primary + 1 fallback
    LOW = 3         # Only try primary, no fallbacks

class DegradationLevel(enum.Enum):
    FULL = "full_quality"           # 100% quality, full features
    REDUCED = "reduced_quality"     # 70% quality, core features only
    MINIMAL = "minimal_quality"     # 30% quality, essential features only
    OFFLINE = "offline"             # 0% quality, cached/stub only

@dataclass
class CircuitBreakerConfig:
    failure_threshold: int = 5
    success_threshold: int = 3
    reset_timeout: float = 30.0
    sampling_window: int = 100
    min_calls_to_open: int = 10
    half_open_max_calls: int = 5

@dataclass
class BulkheadConfig:
    max_concurrent_calls: int = 10
    max_queue_size: int = 100
    max_wait_time: float = 5.0
    operation_timeout: float = 30.0

@dataclass
class RetryConfig:
    max_attempts: int = 3
    initial_delay: float = 0.1
    max_delay: float = 10.0
    jitter_factor: float = 0.5
    backoff_multiplier: float = 2.0

@dataclass
class CircuitMetrics:
    total_calls: int = 0
    success_calls: int = 0
    failure_calls: int = 0
    timeout_calls: int = 0
    rejected_calls: int = 0
    fallback_calls: int = 0
    state_transitions: int = 0
    half_open_attempts: int = 0

class AdvancedCircuitBreaker:
    """
    Advanced Circuit Breaker with half-open state auto-recovery.
    
    ADD-ONLY wrapper - never modifies wrapped function.
    100% backward compatible.
    """
    
    def __init__(self, config: Optional[CircuitBreakerConfig] = None):
        self.config = config or CircuitBreakerConfig()
        self._state = CircuitState.CLOSED
        self._metrics = CircuitMetrics()
        self._failure_window: deque = deque(maxlen=self.config.sampling_window)
        self._success_in_half_open = 0
        self._last_open_time = 0.0
        self._lock = threading.RLock()
    
    @property
    def state(self) -> CircuitState:
        with self._lock:
            self._maybe_transition_to_half_open()
            return self._state
    
    @property
    def metrics(self) -> CircuitMetrics:
        with self._lock:
            return CircuitMetrics(**vars(self._metrics))
    
    def _maybe_transition_to_half_open(self) -> None:
        if self._state == CircuitState.OPEN:
            elapsed = time.time() - self._last_open_time
            if elapsed >= self.config.reset_timeout:
                self._state = CircuitState.HALF_OPEN
                self._success_in_half_open = 0
                self._metrics.state_transitions += 1
    
    def _record_failure(self) -> None:
        self._failure_window.append(True)
        self._metrics.failure_calls += 1
        
        if self._state == CircuitState.CLOSED:
            if len(self._failure_window) >= self.config.min_calls_to_open:
                failure_rate = sum(self._failure_window) / len(self._failure_window)
                if failure_rate >= (self.config.failure_threshold / self.config.sampling_window):
                    self._open_circuit()
        
        elif self._state == CircuitState.HALF_OPEN:
            self._open_circuit()
    
    def _record_success(self) -> None:
        self._failure_window.append(False)
        self._metrics.success_calls += 1
        
        if self._state == CircuitState.HALF_OPEN:
            self._success_in_half_open += 1
            self._metrics.half_open_attempts += 1
            if self._success_in_half_open >= self.config.success_threshold:
                self._close_circuit()
    
    def _open_circuit(self) -> None:
        self._state = CircuitState.OPEN
        self._last_open_time = time.time()
        self._metrics.state_transitions += 1
    
    def _close_circuit(self) -> None:
        self._state = CircuitState.CLOSED
        self._failure_window.clear()
        self._metrics.state_transitions += 1
    
    def allow_request(self) -> bool:
        with self._lock:
            self._metrics.total_calls += 1
            self._maybe_transition_to_half_open()
            
            if self._state == CircuitState.OPEN:
                self._metrics.rejected_calls += 1
                return False
            
            if self._state == CircuitState.HALF_OPEN:
                half_open_calls = self._metrics.half_open_attempts - self._success_in_half_open
                if half_open_calls >= self.config.half_open_max_calls:
                    self._metrics.rejected_calls += 1
                    return False
            
            return True
    
    def execute(self, func: Callable[..., T], *args, **kwargs) -> T:
        if not self.allow_request():
            raise CircuitBreakerOpenError(f"Circuit breaker is {self._state.value}")
        
        try:
            result = func(*args, **kwargs)
            with self._lock:
                self._record_success()
            return result
        except Exception as e:
            with self._lock:
                self._record_failure()
            raise


class BulkheadIsolator:
    """
    Bulkhead pattern - isolate failures to prevent cascade.
    
    ADD-ONLY wrapper - limits concurrent calls per operation.
    """
    
    def __init__(self, config: Optional[BulkheadConfig] = None):
        self.config = config or BulkheadConfig()
        self._active_calls = 0
        self._lock = threading.Lock()
        self._not_full = threading.Condition(self._lock)
    
    @property
    def active_calls(self) -> int:
        with self._lock:
            return self._active_calls
    
    @property
    def available_capacity(self) -> int:
        with self._lock:
            return self.config.max_concurrent_calls - self._active_calls
    
    def execute(self, func: Callable[..., T], *args, **kwargs) -> T:
        start_wait = time.time()
        
        with self._lock:
            while self._active_calls >= self.config.max_concurrent_calls:
                wait_remaining = self.config.max_wait_time - (time.time() - start_wait)
                if wait_remaining <= 0:
                    raise BulkheadTimeoutError("Bulkhead queue wait timeout")
                self._not_full.wait(wait_remaining)
            
            self._active_calls += 1
        
        try:
            return func(*args, **kwargs)
        finally:
            with self._lock:
                self._active_calls -= 1
                self._not_full.notify()


class PriorityFallbackOrchestrator:
    """
    Priority-based fallback chain orchestration.
    
    ADD-ONLY - chains multiple fallback functions by priority.
    """
    
    def __init__(self):
        self._fallbacks: List[Tuple[int, Callable]] = []
        self._lock = threading.Lock()
    
    def add_fallback(self, priority: int, fallback: Callable) -> None:
        """Add fallback with lower number = higher priority."""
        with self._lock:
            self._fallbacks.append((priority, fallback))
            self._fallbacks.sort(key=lambda x: x[0])
    
    def execute(self, 
                primary: Callable[..., T], 
                *args,
                priority: FallbackPriority = FallbackPriority.MEDIUM,
                **kwargs) -> T:
        max_fallbacks = {
            FallbackPriority.CRITICAL: len(self._fallbacks),
            FallbackPriority.HIGH: 2,
            FallbackPriority.MEDIUM: 1,
            FallbackPriority.LOW: 0,
        }[priority]
        
        exceptions = []
        
        # Try primary first
        try:
            return primary(*args, **kwargs)
        except Exception as e:
            exceptions.append(e)
        
        # Try fallbacks in priority order
        with self._lock:
            fallbacks_to_try = self._fallbacks[:max_fallbacks]
        
        for _, fallback in fallbacks_to_try:
            try:
                return fallback(*args, **kwargs)
            except Exception as e:
                exceptions.append(e)
        
        raise FallbackChainExhaustedError(
            f"All fallbacks exhausted. Exceptions: {[str(e) for e in exceptions]}"
        )


class AdaptiveTimeoutWithJitter:
    """
    Adaptive timeout with exponential backoff and jitter.
    
    ADD-ONLY wrapper - never modifies wrapped function.
    """
    
    def __init__(self, config: Optional[RetryConfig] = None):
        self.config = config or RetryConfig()
        self._lock = threading.Lock()
    
    def _calculate_delay(self, attempt: int) -> float:
        delay = min(
            self.config.initial_delay * (self.config.backoff_multiplier ** attempt),
            self.config.max_delay
        )
        jitter = random.uniform(0, delay * self.config.jitter_factor)
        return delay + jitter
    
    def execute(self, func: Callable[..., T], *args, **kwargs) -> T:
        last_exception = None
        
        for attempt in range(self.config.max_attempts):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                last_exception = e
                if attempt < self.config.max_attempts - 1:
                    delay = self._calculate_delay(attempt)
                    time.sleep(delay)
        
        raise last_exception


class GracefulDegradationManager:
    """
    Graceful degradation with quality tier management.
    
    ADD-ONLY - routes to appropriate implementation based on health.
    """
    
    def __init__(self):
        self._implementations: Dict[DegradationLevel, Callable] = {}
        self._current_level = DegradationLevel.FULL
        self._lock = threading.Lock()
        self._error_rate_window: deque = deque(maxlen=100)
    
    @property
    def current_level(self) -> DegradationLevel:
        with self._lock:
            return self._current_level
    
    def register_implementation(self, level: DegradationLevel, impl: Callable) -> None:
        with self._lock:
            self._implementations[level] = impl
    
    def _assess_health(self) -> None:
        if len(self._error_rate_window) < 20:
            return
        
        error_rate = sum(self._error_rate_window) / len(self._error_rate_window)
        
        if error_rate > 0.5:
            self._current_level = DegradationLevel.MINIMAL
        elif error_rate > 0.2:
            self._current_level = DegradationLevel.REDUCED
        elif error_rate < 0.05:
            self._current_level = DegradationLevel.FULL
    
    _LEVEL_ORDER = [
        DegradationLevel.FULL,
        DegradationLevel.REDUCED,
        DegradationLevel.MINIMAL,
        DegradationLevel.OFFLINE,
    ]
    
    def execute(self, *args, **kwargs) -> Any:
        with self._lock:
            self._assess_health()
            start_idx = self._LEVEL_ORDER.index(self._current_level)
            
            # Find first available implementation
            impl = None
            for i in range(start_idx, len(self._LEVEL_ORDER)):
                level = self._LEVEL_ORDER[i]
                if level in self._implementations:
                    impl = self._implementations[level]
                    break
            
            if impl is None:
                raise NoImplementationError("No implementation available for any degradation level")
        
        try:
            result = impl(*args, **kwargs)
            with self._lock:
                self._error_rate_window.append(0)
            return result
        except Exception:
            with self._lock:
                self._error_rate_window.append(1)
            raise


# Exception Hierarchy
class ErrorResilienceError(Exception):
    """Base exception for all error resilience errors."""
    pass

class CircuitBreakerOpenError(ErrorResilienceError):
    """Raised when circuit breaker is open."""
    pass

class BulkheadTimeoutError(ErrorResilienceError):
    """Raised when bulkhead wait times out."""
    pass

class FallbackChainExhaustedError(ErrorResilienceError):
    """Raised when all fallbacks are exhausted."""
    pass

class NoImplementationError(ErrorResilienceError):
    """Raised when no implementation is available."""
    pass


# Convenience decorators
def with_circuit_breaker(config: Optional[CircuitBreakerConfig] = None):
    """Decorator for circuit breaker protection."""
    breaker = AdvancedCircuitBreaker(config)
    
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args, **kwargs) -> T:
            return breaker.execute(func, *args, **kwargs)
        wrapper.circuit_breaker = breaker
        return wrapper
    return decorator

def with_bulkhead(config: Optional[BulkheadConfig] = None):
    """Decorator for bulkhead isolation."""
    bulkhead = BulkheadIsolator(config)
    
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args, **kwargs) -> T:
            return bulkhead.execute(func, *args, **kwargs)
        wrapper.bulkhead = bulkhead
        return wrapper
    return decorator

def with_retry(config: Optional[RetryConfig] = None):
    """Decorator for retry with jitter backoff."""
    retry = AdaptiveTimeoutWithJitter(config)
    
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args, **kwargs) -> T:
            return retry.execute(func, *args, **kwargs)
        wrapper.retry = retry
        return wrapper
    return decorator


# Factory function - MAIN ENTRY POINT
def create_error_resilience_v22(
    enable_circuit_breaker: bool = True,
    enable_bulkhead: bool = True,
    enable_retry: bool = True,
    enable_fallback_orchestration: bool = True
) -> Dict[str, Any]:
    """
    Factory function to create v22 error resilience components.
    
    ADD-ONLY: All components are OPT-IN.
    No existing code modified.
    All happy paths preserved.
    """
    return {
        "circuit_breaker": AdvancedCircuitBreaker() if enable_circuit_breaker else None,
        "bulkhead": BulkheadIsolator() if enable_bulkhead else None,
        "retry_manager": AdaptiveTimeoutWithJitter() if enable_retry else None,
        "fallback_orchestrator": PriorityFallbackOrchestrator() if enable_fallback_orchestration else None,
        "degradation_manager": GracefulDegradationManager(),
        "version": "v22",
        "enabled": True,
    }
