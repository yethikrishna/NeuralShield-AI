"""
Error Resilience - Comprehensive Threat Detection Framework v31
Dimension E: Error Resilience
Session 132 - June 24, 2026

ADD-ONLY implementation - wraps existing threat detection
with comprehensive error resilience patterns.
"""

import time
import random
import logging
import threading
from enum import Enum
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, TypeVar, Generic, Union
from functools import wraps
from collections import deque
from datetime import datetime, timedelta

# Configure logging - OPT-IN only
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

T = TypeVar('T')
R = TypeVar('R')

# ============================================================================
# CUSTOM EXCEPTION HIERARCHY - Threat Detection Specific
# ============================================================================

class ThreatDetectionError(Exception):
    """Base exception for all threat detection errors."""
    def __init__(self, message: str, error_code: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.error_code = error_code
        self.details = details or {}
        self.timestamp = datetime.utcnow().isoformat()

class ThreatDetectionTimeoutError(ThreatDetectionError):
    """Threat detection operation timed out."""
    def __init__(self, message: str, timeout_seconds: float, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "THREAT_TIMEOUT_001", details)
        self.timeout_seconds = timeout_seconds

class ThreatDetectionModelError(ThreatDetectionError):
    """Model inference failed."""
    def __init__(self, message: str, model_name: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "THREAT_MODEL_001", details)
        self.model_name = model_name

class ThreatDetectionInputError(ThreatDetectionError):
    """Invalid input for threat detection."""
    def __init__(self, message: str, input_type: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "THREAT_INPUT_001", details)
        self.input_type = input_type

class ThreatDetectionResourceError(ThreatDetectionError):
    """Resource exhaustion during detection."""
    def __init__(self, message: str, resource_type: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "THREAT_RESOURCE_001", details)
        self.resource_type = resource_type

class ThreatDetectionCircuitOpenError(ThreatDetectionError):
    """Circuit breaker is open - operation rejected."""
    def __init__(self, message: str, recovery_time: float, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "THREAT_CIRCUIT_001", details)
        self.recovery_time = recovery_time

# ============================================================================
# CIRCUIT BREAKER STATES
# ============================================================================

class CircuitState(Enum):
    CLOSED = "CLOSED"           # Normal operation
    OPEN = "OPEN"               # Circuit tripped - reject requests
    HALF_OPEN = "HALF_OPEN"     # Testing recovery

# ============================================================================
# DATA STRUCTURES
# ============================================================================

@dataclass
class ErrorResilienceConfig:
    """Configuration for error resilience behavior."""
    timeout_seconds: float = 30.0
    max_retries: int = 3
    initial_backoff_ms: float = 100.0
    max_backoff_ms: float = 5000.0
    jitter_factor: float = 0.1
    circuit_failure_threshold: int = 5
    circuit_reset_timeout: float = 30.0
    circuit_half_open_max_calls: int = 3
    bulkhead_max_concurrent: int = 10
    bulkhead_max_waiting: int = 100
    enable_graceful_degradation: bool = True
    fallback_timeout_seconds: float = 5.0

@dataclass
class RetryMetrics:
    """Metrics for retry operations."""
    total_attempts: int = 0
    successful_on_first: int = 0
    successful_after_retry: int = 0
    total_failures: int = 0
    total_retries: int = 0
    backoff_times_ms: List[float] = field(default_factory=list)

@dataclass
class CircuitBreakerMetrics:
    """Metrics for circuit breaker."""
    state_transitions: int = 0
    total_failures: int = 0
    total_successes: int = 0
    total_rejections: int = 0
    last_state_change: Optional[str] = None

@dataclass
class OperationResult(Generic[T]):
    """Result wrapper with resilience metadata."""
    success: bool
    result: Optional[T] = None
    error: Optional[Exception] = None
    attempt_count: int = 1
    total_time_ms: float = 0.0
    used_fallback: bool = False
    fallback_result: Optional[T] = None
    circuit_state: Optional[CircuitState] = None
    warnings: List[str] = field(default_factory=list)

# ============================================================================
# ADAPTIVE TIMEOUT WITH JITTER AND BACKOFF
# ============================================================================

class AdaptiveTimeoutJitterBackoff:
    """
    Adaptive timeout with exponential backoff and jitter.
    Prevents thundering herd and adapts to system load.
    """
    
    def __init__(self, config: Optional[ErrorResilienceConfig] = None):
        self.config = config or ErrorResilienceConfig()
        self.metrics = RetryMetrics()
        self._lock = threading.Lock()
    
    def calculate_backoff(self, attempt: int) -> float:
        """Calculate backoff with jitter for given attempt."""
        base_backoff = min(
            self.config.initial_backoff_ms * (2 ** (attempt - 1)),
            self.config.max_backoff_ms
        )
        jitter = base_backoff * self.config.jitter_factor * random.uniform(-1, 1)
        backoff = max(0.0, base_backoff + jitter)
        
        with self._lock:
            self.metrics.backoff_times_ms.append(backoff)
        
        return backoff / 1000.0  # Convert to seconds
    
    def execute_with_retry(
        self,
        operation: Callable[[], T],
        fallback: Optional[Callable[[], T]] = None
    ) -> OperationResult[T]:
        """Execute operation with retry, backoff, and optional fallback."""
        start_time = time.time()
        attempt = 0
        last_error: Optional[Exception] = None
        
        while attempt < self.config.max_retries:
            attempt += 1
            with self._lock:
                self.metrics.total_attempts += 1
            
            try:
                result = operation()
                total_time = (time.time() - start_time) * 1000
                
                with self._lock:
                    if attempt == 1:
                        self.metrics.successful_on_first += 1
                    else:
                        self.metrics.successful_after_retry += 1
                
                return OperationResult[T](
                    success=True,
                    result=result,
                    attempt_count=attempt,
                    total_time_ms=total_time
                )
                
            except Exception as e:
                last_error = e
                with self._lock:
                    self.metrics.total_failures += 1
                    if attempt < self.config.max_retries:
                        self.metrics.total_retries += 1
                
                if attempt < self.config.max_retries:
                    backoff = self.calculate_backoff(attempt)
                    time.sleep(backoff)
                else:
                    break
        
        # All retries failed - try fallback if enabled
        total_time = (time.time() - start_time) * 1000
        
        if fallback is not None and self.config.enable_graceful_degradation:
            try:
                fallback_result = fallback()
                return OperationResult[T](
                    success=True,
                    error=last_error,
                    attempt_count=attempt,
                    total_time_ms=total_time,
                    used_fallback=True,
                    fallback_result=fallback_result,
                    warnings=["Operation failed, using degraded fallback result"]
                )
            except Exception as fallback_error:
                return OperationResult[T](
                    success=False,
                    error=last_error,
                    attempt_count=attempt,
                    total_time_ms=total_time,
                    used_fallback=True,
                    warnings=["Fallback also failed: " + str(fallback_error)]
                )
        
        return OperationResult[T](
            success=False,
            error=last_error,
            attempt_count=attempt,
            total_time_ms=total_time
        )
    
    def get_metrics(self) -> RetryMetrics:
        """Get current retry metrics."""
        with self._lock:
            return RetryMetrics(**self.metrics.__dict__)

# ============================================================================
# CIRCUIT BREAKER WITH GRACEFUL DEGRADATION
# ============================================================================

class ThreatDetectionCircuitBreaker:
    """
    Circuit breaker for threat detection operations.
    Prevents cascading failures with graceful degradation.
    """
    
    def __init__(self, config: Optional[ErrorResilienceConfig] = None):
        self.config = config or ErrorResilienceConfig()
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._open_timestamp: Optional[float] = None
        self._half_open_attempts = 0
        self._metrics = CircuitBreakerMetrics()
        self._lock = threading.Lock()
    
    @property
    def state(self) -> CircuitState:
        """Get current circuit state."""
        with self._lock:
            return self._state
    
    def _transition_to(self, new_state: CircuitState) -> None:
        """Transition to new circuit state."""
        if self._state != new_state:
            logger.info(f"Circuit breaker transitioning from {self._state.value} to {new_state.value}")
            self._state = new_state
            self._metrics.state_transitions += 1
            self._metrics.last_state_change = datetime.utcnow().isoformat()
            self._failure_count = 0
            self._success_count = 0
            self._half_open_attempts = 0
    
    def _check_state(self) -> None:
        """Check and update circuit state based on time and conditions."""
        now = time.time()
        
        if self._state == CircuitState.OPEN:
            if self._open_timestamp and (now - self._open_timestamp) >= self.config.circuit_reset_timeout:
                self._transition_to(CircuitState.HALF_OPEN)
    
    def record_success(self) -> None:
        """Record successful operation."""
        with self._lock:
            self._check_state()
            self._metrics.total_successes += 1
            
            if self._state == CircuitState.HALF_OPEN:
                self._success_count += 1
                if self._success_count >= self.config.circuit_half_open_max_calls:
                    self._transition_to(CircuitState.CLOSED)
            elif self._state == CircuitState.CLOSED:
                self._failure_count = 0  # Reset on success
    
    def record_failure(self) -> None:
        """Record failed operation."""
        with self._lock:
            self._check_state()
            self._metrics.total_failures += 1
            
            if self._state == CircuitState.CLOSED:
                self._failure_count += 1
                if self._failure_count >= self.config.circuit_failure_threshold:
                    self._transition_to(CircuitState.OPEN)
                    self._open_timestamp = time.time()
            elif self._state == CircuitState.HALF_OPEN:
                self._transition_to(CircuitState.OPEN)
                self._open_timestamp = time.time()
    
    def allow_request(self) -> bool:
        """Check if request should be allowed through."""
        with self._lock:
            self._check_state()
            
            if self._state == CircuitState.OPEN:
                self._metrics.total_rejections += 1
                return False
            elif self._state == CircuitState.HALF_OPEN:
                self._half_open_attempts += 1
                return True
            return True
    
    def get_recovery_time_remaining(self) -> float:
        """Get time remaining until circuit reset attempt."""
        with self._lock:
            if self._state != CircuitState.OPEN or not self._open_timestamp:
                return 0.0
            elapsed = time.time() - self._open_timestamp
            return max(0.0, self.config.circuit_reset_timeout - elapsed)
    
    def get_metrics(self) -> CircuitBreakerMetrics:
        """Get circuit breaker metrics."""
        with self._lock:
            return CircuitBreakerMetrics(**self._metrics.__dict__)
    
    def execute(
        self,
        operation: Callable[[], T],
        fallback: Optional[Callable[[], T]] = None
    ) -> OperationResult[T]:
        """Execute operation with circuit breaker protection."""
        start_time = time.time()
        
        if not self.allow_request():
            recovery_time = self.get_recovery_time_remaining()
            error = ThreatDetectionCircuitOpenError(
                "Circuit breaker is OPEN - operation rejected",
                recovery_time,
                {"failures_before_open": self.config.circuit_failure_threshold}
            )
            
            if fallback is not None and self.config.enable_graceful_degradation:
                try:
                    fallback_result = fallback()
                    return OperationResult[T](
                        success=True,
                        error=error,
                        total_time_ms=(time.time() - start_time) * 1000,
                        used_fallback=True,
                        fallback_result=fallback_result,
                        circuit_state=CircuitState.OPEN,
                        warnings=["Circuit open, using fallback"]
                    )
                except Exception:
                    pass
            
            return OperationResult[T](
                success=False,
                error=error,
                total_time_ms=(time.time() - start_time) * 1000,
                circuit_state=CircuitState.OPEN
            )
        
        try:
            result = operation()
            self.record_success()
            return OperationResult[T](
                success=True,
                result=result,
                total_time_ms=(time.time() - start_time) * 1000,
                circuit_state=self.state
            )
        except Exception as e:
            self.record_failure()
            
            if fallback is not None and self.config.enable_graceful_degradation:
                try:
                    fallback_result = fallback()
                    return OperationResult[T](
                        success=True,
                        error=e,
                        total_time_ms=(time.time() - start_time) * 1000,
                        used_fallback=True,
                        fallback_result=fallback_result,
                        circuit_state=self.state,
                        warnings=["Operation failed, using fallback"]
                    )
                except Exception:
                    pass
            
            return OperationResult[T](
                success=False,
                error=e,
                total_time_ms=(time.time() - start_time) * 1000,
                circuit_state=self.state
            )

# ============================================================================
# BULKHEAD ISOLATION FOR MODEL INFERENCE
# ============================================================================

class BulkheadIsolation:
    """
    Bulkhead pattern for isolating model inference operations.
    Prevents one failing component from taking down the whole system.
    """
    
    def __init__(self, config: Optional[ErrorResilienceConfig] = None):
        self.config = config or ErrorResilienceConfig()
        self._concurrent_count = 0
        self._waiting_count = 0
        self._lock = threading.Lock()
        self._condition = threading.Condition(self._lock)
    
    @property
    def concurrent_count(self) -> int:
        with self._lock:
            return self._concurrent_count
    
    @property
    def waiting_count(self) -> int:
        with self._lock:
            return self._waiting_count
    
    def acquire(self, timeout: Optional[float] = None) -> bool:
        """Acquire bulkhead slot."""
        effective_timeout = timeout or self.config.timeout_seconds
        deadline = time.time() + effective_timeout
        
        with self._condition:
            while self._concurrent_count >= self.config.bulkhead_max_concurrent:
                if self._waiting_count >= self.config.bulkhead_max_waiting:
                    return False
                
                self._waiting_count += 1
                remaining = deadline - time.time()
                if remaining <= 0:
                    self._waiting_count -= 1
                    return False
                
                self._condition.wait(remaining)
                self._waiting_count -= 1
            
            self._concurrent_count += 1
            return True
    
    def release(self) -> None:
        """Release bulkhead slot."""
        with self._condition:
            self._concurrent_count = max(0, self._concurrent_count - 1)
            self._condition.notify()
    
    def execute(
        self,
        operation: Callable[[], T],
        fallback: Optional[Callable[[], T]] = None
    ) -> OperationResult[T]:
        """Execute operation with bulkhead isolation."""
        start_time = time.time()
        
        if not self.acquire():
            error = ThreatDetectionResourceError(
                "Bulkhead capacity exhausted",
                "bulkhead",
                {
                    "max_concurrent": self.config.bulkhead_max_concurrent,
                    "max_waiting": self.config.bulkhead_max_waiting,
                    "current_concurrent": self.concurrent_count,
                    "current_waiting": self.waiting_count
                }
            )
            
            if fallback is not None and self.config.enable_graceful_degradation:
                try:
                    fallback_result = fallback()
                    return OperationResult[T](
                        success=True,
                        error=error,
                        total_time_ms=(time.time() - start_time) * 1000,
                        used_fallback=True,
                        fallback_result=fallback_result,
                        warnings=["Bulkhead full, using fallback"]
                    )
                except Exception:
                    pass
            
            return OperationResult[T](
                success=False,
                error=error,
                total_time_ms=(time.time() - start_time) * 1000
            )
        
        try:
            result = operation()
            return OperationResult[T](
                success=True,
                result=result,
                total_time_ms=(time.time() - start_time) * 1000
            )
        except Exception as e:
            if fallback is not None and self.config.enable_graceful_degradation:
                try:
                    fallback_result = fallback()
                    return OperationResult[T](
                        success=True,
                        error=e,
                        total_time_ms=(time.time() - start_time) * 1000,
                        used_fallback=True,
                        fallback_result=fallback_result,
                        warnings=["Operation failed, using fallback"]
                    )
                except Exception:
                    pass
            
            return OperationResult[T](
                success=False,
                error=e,
                total_time_ms=(time.time() - start_time) * 1000
            )
        finally:
            self.release()

# ============================================================================
# FALLBACK CHAIN ORCHESTRATOR
# ============================================================================

class FallbackLevel(Enum):
    PRIMARY = "PRIMARY"
    FAST_FALLBACK = "FAST_FALLBACK"
    SIMPLIFIED = "SIMPLIFIED"
    SAFE_DEFAULT = "SAFE_DEFAULT"
    EMERGENCY = "EMERGENCY"

@dataclass
class FallbackEntry(Generic[T]):
    level: FallbackLevel
    handler: Callable[[], T]
    timeout_seconds: float = 5.0
    is_critical: bool = False

class FallbackChainOrchestrator:
    """
    Orchestrates fallback chain with multiple degradation levels.
    Ensures system always returns something rather than failing completely.
    """
    
    def __init__(self, enable_logging: bool = False):
        self._fallbacks: List[FallbackEntry] = []
        self._lock = threading.Lock()
        self._degradation_events: deque = deque(maxlen=100)
    
    def add_fallback(
        self,
        level: FallbackLevel,
        handler: Callable[[], T],
        timeout_seconds: float = 5.0,
        is_critical: bool = False
    ) -> None:
        """Add fallback handler for specific level."""
        with self._lock:
            self._fallbacks.append(FallbackEntry(
                level=level,
                handler=handler,
                timeout_seconds=timeout_seconds,
                is_critical=is_critical
            ))
            # Sort by level priority
            priority_order = {
                FallbackLevel.PRIMARY: 0,
                FallbackLevel.FAST_FALLBACK: 1,
                FallbackLevel.SIMPLIFIED: 2,
                FallbackLevel.SAFE_DEFAULT: 3,
                FallbackLevel.EMERGENCY: 4
            }
            self._fallbacks.sort(key=lambda f: priority_order[f.level])
    
    def execute(self, primary_operation: Callable[[], T]) -> OperationResult[T]:
        """Execute with full fallback chain."""
        start_time = time.time()
        warnings: List[str] = []
        used_level: Optional[FallbackLevel] = None
        last_error: Optional[Exception] = None
        
        # Try primary first
        try:
            result = primary_operation()
            return OperationResult[T](
                success=True,
                result=result,
                total_time_ms=(time.time() - start_time) * 1000
            )
        except Exception as e:
            last_error = e
            warnings.append(f"Primary failed: {str(e)}")
        
        # Try fallbacks in order
        with self._lock:
            fallbacks = list(self._fallbacks)
        
        for fallback in fallbacks:
            try:
                fallback_result = fallback.handler()
                used_level = fallback.level
                
                self._degradation_events.append({
                    "timestamp": datetime.utcnow().isoformat(),
                    "primary_error": str(last_error),
                    "fallback_level": fallback.level.value,
                    "time_ms": (time.time() - start_time) * 1000
                })
                
                warnings.append(f"Using {fallback.level.value} fallback")
                
                return OperationResult[T](
                    success=True,
                    error=last_error,
                    total_time_ms=(time.time() - start_time) * 1000,
                    used_fallback=True,
                    fallback_result=fallback_result,
                    warnings=warnings
                )
            except Exception as e:
                warnings.append(f"{fallback.level.value} fallback failed: {str(e)}")
                continue
        
        # All fallbacks failed
        return OperationResult[T](
            success=False,
            error=last_error,
            total_time_ms=(time.time() - start_time) * 1000,
            warnings=warnings + ["All fallbacks exhausted"]
        )
    
    def get_degradation_events(self) -> List[Dict[str, Any]]:
        """Get recent degradation events."""
        with self._lock:
            return list(self._degradation_events)

# ============================================================================
# COMPREHENSIVE ERROR RESILIENCE WRAPPER
# ============================================================================

class ComprehensiveThreatDetectionResilience:
    """
    Combined error resilience wrapper for threat detection.
    Integrates: Retry + Backoff + Circuit Breaker + Bulkhead + Fallback Chain
    """
    
    def __init__(self, config: Optional[ErrorResilienceConfig] = None):
        self.config = config or ErrorResilienceConfig()
        self.retry_handler = AdaptiveTimeoutJitterBackoff(self.config)
        self.circuit_breaker = ThreatDetectionCircuitBreaker(self.config)
        self.bulkhead = BulkheadIsolation(self.config)
        self.fallback_orchestrator = FallbackChainOrchestrator()
    
    def wrap_threat_detection(
        self,
        detection_function: Callable[[str], Dict[str, Any]],
        fallback_function: Optional[Callable[[str], Dict[str, Any]]] = None
    ) -> Callable[[str], OperationResult[Dict[str, Any]]]:
        """Wrap threat detection function with all resilience patterns."""
        
        def resilient_detection(input_text: str) -> OperationResult[Dict[str, Any]]:
            def primary_op():
                return detection_function(input_text)
            
            def fallback_op():
                if fallback_function:
                    return fallback_function(input_text)
                # Default safe fallback
                return {
                    "threat_detected": False,
                    "confidence": 0.0,
                    "risk_level": "unknown",
                    "detection_method": "safe_fallback",
                    "warning": "Using degraded fallback detection",
                    "timestamp": datetime.utcnow().isoformat()
                }
            
            # Bulkhead -> Circuit Breaker -> Retry with Fallback
            def circuit_op():
                return self.circuit_breaker.execute(primary_op, fallback_op)
            
            result = self.bulkhead.execute(circuit_op)
            
            # If bulkhead rejected, use fallback chain
            if not result.success:
                chain_result = self.fallback_orchestrator.execute(primary_op)
                if chain_result.success:
                    return chain_result
            
            return result
        
        return resilient_detection
    
    def get_health_status(self) -> Dict[str, Any]:
        """Get comprehensive health status of all resilience components."""
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "circuit_breaker": {
                "state": self.circuit_breaker.state.value,
                "recovery_time_remaining": self.circuit_breaker.get_recovery_time_remaining(),
                "metrics": self.circuit_breaker.get_metrics().__dict__
            },
            "bulkhead": {
                "concurrent_count": self.bulkhead.concurrent_count,
                "waiting_count": self.bulkhead.waiting_count,
                "max_concurrent": self.config.bulkhead_max_concurrent,
                "max_waiting": self.config.bulkhead_max_waiting
            },
            "retry_metrics": self.retry_handler.get_metrics().__dict__,
            "degradation_events": len(self.fallback_orchestrator.get_degradation_events())
        }

# ============================================================================
# MODULE EXPORTS
# ============================================================================

__all__ = [
    # Exceptions
    "ThreatDetectionError",
    "ThreatDetectionTimeoutError",
    "ThreatDetectionModelError",
    "ThreatDetectionInputError",
    "ThreatDetectionResourceError",
    "ThreatDetectionCircuitOpenError",
    
    # Enums
    "CircuitState",
    "FallbackLevel",
    
    # Data Structures
    "ErrorResilienceConfig",
    "RetryMetrics",
    "CircuitBreakerMetrics",
    "OperationResult",
    "FallbackEntry",
    
    # Resilience Components
    "AdaptiveTimeoutJitterBackoff",
    "ThreatDetectionCircuitBreaker",
    "BulkheadIsolation",
    "FallbackChainOrchestrator",
    "ComprehensiveThreatDetectionResilience",
]
