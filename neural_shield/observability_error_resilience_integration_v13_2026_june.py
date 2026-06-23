"""
NeuralShield-AI: Observability v13 - Error Resilience Integration
DIMENSION D - Observability & Instrumentation
STATUS: STABLE

Integration layer between Observability v12 and Error Resilience v22 systems.
Provides metrics, tracing, and health monitoring for circuit breakers,
fallback chains, timeout wrappers, and retry mechanisms.

ALL FEATURES ARE OPT-IN AND DISABLED BY DEFAULT.
No performance impact when not explicitly enabled.
100% ADD-ONLY - wraps existing code, does not modify it.
"""

import time
import threading
from typing import Dict, Any, Optional, Callable, List
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict


class ErrorResilienceMetricType(Enum):
    """Types of error resilience metrics being tracked."""
    CIRCUIT_BREAKER_STATE_CHANGE = "circuit_breaker_state_change"
    CIRCUIT_BREAKER_TRIPPED = "circuit_breaker_tripped"
    CIRCUIT_BREAKER_RESET = "circuit_breaker_reset"
    FALLBACK_ACTIVATED = "fallback_activated"
    FALLBACK_CHAIN_EXHAUSTED = "fallback_chain_exhausted"
    FALLBACK_SUCCESS = "fallback_success"
    TIMEOUT_TRIGGERED = "timeout_triggered"
    RETRY_ATTEMPT = "retry_attempt"
    RETRY_SUCCESS = "retry_success"
    RETRY_EXHAUSTED = "retry_exhausted"
    BULKHEAD_REJECTED = "bulkhead_rejected"
    RATE_LIMIT_TRIGGERED = "rate_limit_triggered"


class CircuitBreakerState(Enum):
    """Circuit breaker states for observability."""
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


@dataclass
class ErrorResilienceMetric:
    """Single metric record for error resilience events."""
    metric_type: ErrorResilienceMetricType
    timestamp: float
    component_name: str
    duration_ms: Optional[float] = None
    error_type: Optional[str] = None
    retry_attempt: Optional[int] = None
    fallback_level: Optional[int] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CircuitBreakerSnapshot:
    """Snapshot of circuit breaker state for observability."""
    component_name: str
    current_state: CircuitBreakerState
    failure_count: int
    success_count: int
    last_state_change: float
    open_duration_seconds: float
    half_open_attempts: int


@dataclass
class FallbackChainSnapshot:
    """Snapshot of fallback chain performance."""
    chain_name: str
    total_activations: int
    successful_fallbacks: int
    exhausted_chains: int
    average_fallback_duration_ms: float


class ErrorResilienceObservability:
    """
    Observability integration for Error Resilience v22 system.
    
    Tracks:
    - Circuit breaker state transitions and performance
    - Fallback chain activations and success rates  
    - Retry attempts and outcomes
    - Timeout trigger frequency
    - Bulkhead and rate limit rejections
    
    OPT-IN ONLY - must be explicitly enabled.
    Zero overhead when disabled.
    """
    
    _instance: Optional['ErrorResilienceObservability'] = None
    _instance_lock: threading.Lock = threading.Lock()
    
    def __new__(cls) -> 'ErrorResilienceObservability':
        """Thread-safe singleton implementation."""
        if cls._instance is None:
            with cls._instance_lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        """Initialize observability system (disabled by default)."""
        if not hasattr(self, '_initialized'):
            self._enabled: bool = False
            self._lock: threading.Lock = threading.Lock()
            
            # Metric storage
            self._metrics: List[ErrorResilienceMetric] = []
            self._max_metrics: int = 10000
            
            # Circuit breaker tracking
            self._circuit_breakers: Dict[str, CircuitBreakerSnapshot] = {}
            
            # Fallback tracking
            self._fallback_chains: Dict[str, FallbackChainSnapshot] = {}
            
            # Counter metrics (separate for exhausted chains)
            self._counters: Dict[str, int] = defaultdict(int)
            self._exhausted_chains_count: int = 0
            self._timers: Dict[str, List[float]] = defaultdict(list)
            
            # Health check callbacks
            self._health_callbacks: List[Callable[[], Dict[str, Any]]] = []
            
            self._initialized = True
    
    def enable(self) -> None:
        """Enable observability collection."""
        with self._lock:
            self._enabled = True
    
    def disable(self) -> None:
        """Disable observability collection."""
        with self._lock:
            self._enabled = False
    
    def is_enabled(self) -> bool:
        """Check if observability is enabled."""
        return self._enabled
    
    def _record_metric(self, metric: ErrorResilienceMetric) -> None:
        """Internal: Record a metric if enabled."""
        if not self._enabled:
            return
        
        with self._lock:
            self._metrics.append(metric)
            # Trim old metrics if needed
            if len(self._metrics) > self._max_metrics:
                self._metrics = self._metrics[-self._max_metrics // 2:]
            
            # Update counters
            counter_key = f"{metric.metric_type.value}:{metric.component_name}"
            self._counters[counter_key] += 1
            
            if metric.duration_ms is not None:
                timer_key = f"duration:{metric.metric_type.value}"
                self._timers[timer_key].append(metric.duration_ms)
                # Keep only last 1000 durations
                if len(self._timers[timer_key]) > 1000:
                    self._timers[timer_key] = self._timers[timer_key][-500:]
    
    def track_circuit_breaker_state_change(
        self,
        component_name: str,
        old_state: CircuitBreakerState,
        new_state: CircuitBreakerState,
        failure_count: int = 0
    ) -> None:
        """Track a circuit breaker state transition."""
        metric = ErrorResilienceMetric(
            metric_type=ErrorResilienceMetricType.CIRCUIT_BREAKER_STATE_CHANGE,
            timestamp=time.time(),
            component_name=component_name,
            metadata={
                "old_state": old_state.value,
                "new_state": new_state.value,
                "failure_count": failure_count
            }
        )
        self._record_metric(metric)
        
        # Update snapshot
        with self._lock:
            if component_name not in self._circuit_breakers:
                self._circuit_breakers[component_name] = CircuitBreakerSnapshot(
                    component_name=component_name,
                    current_state=new_state,
                    failure_count=0,
                    success_count=0,
                    last_state_change=time.time(),
                    open_duration_seconds=0.0,
                    half_open_attempts=0
                )
            
            snapshot = self._circuit_breakers[component_name]
            snapshot.current_state = new_state
            snapshot.last_state_change = time.time()
            
            if new_state == CircuitBreakerState.OPEN:
                self._counters[f"circuit_breaker:tripped:{component_name}"] += 1
            elif new_state == CircuitBreakerState.CLOSED:
                self._counters[f"circuit_breaker:reset:{component_name}"] += 1
    
    def track_fallback_activation(
        self,
        chain_name: str,
        fallback_level: int,
        duration_ms: float,
        success: bool = True,
        error_type: Optional[str] = None
    ) -> None:
        """Track a fallback activation."""
        metric_type = (
            ErrorResilienceMetricType.FALLBACK_SUCCESS
            if success
            else ErrorResilienceMetricType.FALLBACK_ACTIVATED
        )
        
        metric = ErrorResilienceMetric(
            metric_type=metric_type,
            timestamp=time.time(),
            component_name=chain_name,
            duration_ms=duration_ms,
            fallback_level=fallback_level,
            error_type=error_type
        )
        self._record_metric(metric)
        
        with self._lock:
            if chain_name not in self._fallback_chains:
                self._fallback_chains[chain_name] = FallbackChainSnapshot(
                    chain_name=chain_name,
                    total_activations=0,
                    successful_fallbacks=0,
                    exhausted_chains=0,
                    average_fallback_duration_ms=0.0
                )
            
            snapshot = self._fallback_chains[chain_name]
            snapshot.total_activations += 1
            if success:
                snapshot.successful_fallbacks += 1
    
    def track_fallback_exhausted(self, chain_name: str) -> None:
        """Track when all fallbacks in a chain are exhausted."""
        metric = ErrorResilienceMetric(
            metric_type=ErrorResilienceMetricType.FALLBACK_CHAIN_EXHAUSTED,
            timestamp=time.time(),
            component_name=chain_name
        )
        self._record_metric(metric)
        
        with self._lock:
            # Always increment the global counter
            self._exhausted_chains_count += 1
            
            # Also update per-chain if it exists
            if chain_name not in self._fallback_chains:
                self._fallback_chains[chain_name] = FallbackChainSnapshot(
                    chain_name=chain_name,
                    total_activations=0,
                    successful_fallbacks=0,
                    exhausted_chains=0,
                    average_fallback_duration_ms=0.0
                )
            
            self._fallback_chains[chain_name].exhausted_chains += 1
    
    def track_retry_attempt(
        self,
        operation_name: str,
        attempt_number: int,
        duration_ms: float,
        success: bool,
        error_type: Optional[str] = None
    ) -> None:
        """Track a retry attempt."""
        metric_type = (
            ErrorResilienceMetricType.RETRY_SUCCESS
            if success
            else ErrorResilienceMetricType.RETRY_ATTEMPT
        )
        
        metric = ErrorResilienceMetric(
            metric_type=metric_type,
            timestamp=time.time(),
            component_name=operation_name,
            duration_ms=duration_ms,
            retry_attempt=attempt_number,
            error_type=error_type
        )
        self._record_metric(metric)
    
    def track_retry_exhausted(self, operation_name: str, max_attempts: int) -> None:
        """Track when retry attempts are exhausted."""
        metric = ErrorResilienceMetric(
            metric_type=ErrorResilienceMetricType.RETRY_EXHAUSTED,
            timestamp=time.time(),
            component_name=operation_name,
            metadata={"max_attempts": max_attempts}
        )
        self._record_metric(metric)
    
    def track_timeout_triggered(self, operation_name: str, timeout_seconds: float) -> None:
        """Track when an operation times out."""
        metric = ErrorResilienceMetric(
            metric_type=ErrorResilienceMetricType.TIMEOUT_TRIGGERED,
            timestamp=time.time(),
            component_name=operation_name,
            metadata={"timeout_seconds": timeout_seconds}
        )
        self._record_metric(metric)
    
    def track_bulkhead_rejected(self, component_name: str, current_concurrency: int) -> None:
        """Track when bulkhead isolation rejects an operation."""
        metric = ErrorResilienceMetric(
            metric_type=ErrorResilienceMetricType.BULKHEAD_REJECTED,
            timestamp=time.time(),
            component_name=component_name,
            metadata={"current_concurrency": current_concurrency}
        )
        self._record_metric(metric)
    
    def get_circuit_breaker_summary(self) -> Dict[str, Any]:
        """Get summary of all circuit breaker states."""
        with self._lock:
            return {
                "total_circuit_breakers": len(self._circuit_breakers),
                "open_count": sum(
                    1 for cb in self._circuit_breakers.values()
                    if cb.current_state == CircuitBreakerState.OPEN
                ),
                "half_open_count": sum(
                    1 for cb in self._circuit_breakers.values()
                    if cb.current_state == CircuitBreakerState.HALF_OPEN
                ),
                "closed_count": sum(
                    1 for cb in self._circuit_breakers.values()
                    if cb.current_state == CircuitBreakerState.CLOSED
                ),
                "breakers": {
                    name: {
                        "state": cb.current_state.value,
                        "failures": cb.failure_count,
                        "successes": cb.success_count
                    }
                    for name, cb in self._circuit_breakers.items()
                }
            }
    
    def get_fallback_summary(self) -> Dict[str, Any]:
        """Get summary of fallback chain performance."""
        with self._lock:
            total_activations = sum(fb.total_activations for fb in self._fallback_chains.values())
            total_success = sum(fb.successful_fallbacks for fb in self._fallback_chains.values())
            # Use the separate counter for exhausted chains
            total_exhausted = self._exhausted_chains_count
            
            success_rate = (
                total_success / total_activations if total_activations > 0 else 1.0
            )
            
            return {
                "total_chains": len(self._fallback_chains),
                "total_activations": total_activations,
                "successful_fallbacks": total_success,
                "exhausted_chains": total_exhausted,
                "success_rate": success_rate,
                "chains": {
                    name: {
                        "activations": fb.total_activations,
                        "successes": fb.successful_fallbacks,
                        "exhausted": fb.exhausted_chains
                    }
                    for name, fb in self._fallback_chains.items()
                }
            }
    
    def get_counter_summary(self) -> Dict[str, int]:
        """Get all counter metrics."""
        with self._lock:
            return dict(self._counters)
    
    def get_health_status(self) -> Dict[str, Any]:
        """Get comprehensive health status for error resilience system."""
        cb_summary = self.get_circuit_breaker_summary()
        fb_summary = self.get_fallback_summary()
        
        health_status = "HEALTHY"
        warnings = []
        
        if cb_summary["open_count"] > 0:
            health_status = "DEGRADED"
            warnings.append(f"{cb_summary['open_count']} circuit breakers OPEN")
        
        if fb_summary["exhausted_chains"] > 0:
            health_status = "DEGRADED"
            warnings.append(f"{fb_summary['exhausted_chains']} fallback chains EXHAUSTED")
        
        if fb_summary.get("success_rate", 1.0) < 0.5:
            health_status = "AT_RISK"
            warnings.append("Fallback success rate below 50%")
        
        return {
            "status": health_status,
            "timestamp": time.time(),
            "warnings": warnings,
            "circuit_breakers": cb_summary,
            "fallbacks": fb_summary,
            "observability_enabled": self._enabled
        }
    
    def export_prometheus_format(self) -> str:
        """Export metrics in Prometheus text format."""
        if not self._enabled:
            return "# Observability disabled - no metrics exported"
        
        cb_summary = self.get_circuit_breaker_summary()
        fb_summary = self.get_fallback_summary()
        counters = self.get_counter_summary()
        
        lines = [
            "# HELP neuralshield_error_resilience_circuit_breakers_total Total circuit breakers",
            "# TYPE neuralshield_error_resilience_circuit_breakers_total gauge",
            f"neuralshield_error_resilience_circuit_breakers_total {cb_summary['total_circuit_breakers']}",
            "",
            "# HELP neuralshield_error_resilience_circuit_breakers_open Open circuit breakers",
            "# TYPE neuralshield_error_resilience_circuit_breakers_open gauge",
            f"neuralshield_error_resilience_circuit_breakers_open {cb_summary['open_count']}",
            "",
            "# HELP neuralshield_error_resilience_fallback_activations_total Total fallback activations",
            "# TYPE neuralshield_error_resilience_fallback_activations_total counter",
            f"neuralshield_error_resilience_fallback_activations_total {fb_summary['total_activations']}",
            "",
            "# HELP neuralshield_error_resilience_fallback_exhausted_total Total exhausted fallback chains",
            "# TYPE neuralshield_error_resilience_fallback_exhausted_total counter",
            f"neuralshield_error_resilience_fallback_exhausted_total {fb_summary['exhausted_chains']}",
            "",
            "# HELP neuralshield_error_resilience_fallback_success_rate Fallback success rate",
            "# TYPE neuralshield_error_resilience_fallback_success_rate gauge",
            f"neuralshield_error_resilience_fallback_success_rate {fb_summary.get('success_rate', 1.0)}",
        ]
        
        # Add custom counters
        for counter_name, value in counters.items():
            safe_name = counter_name.replace(":", "_").replace("-", "_")
            lines.extend([
                "",
                f"# HELP neuralshield_{safe_name} Custom counter",
                f"# TYPE neuralshield_{safe_name} counter",
                f"neuralshield_{safe_name} {value}"
            ])
        
        return "\n".join(lines)
    
    def reset_metrics(self) -> None:
        """Reset all collected metrics (for testing)."""
        with self._lock:
            self._metrics.clear()
            self._circuit_breakers.clear()
            self._fallback_chains.clear()
            self._counters.clear()
            self._exhausted_chains_count = 0
            self._timers.clear()


# Global instance for easy access
error_resilience_observability = ErrorResilienceObservability()


def get_error_resilience_observability() -> ErrorResilienceObservability:
    """Get the global observability instance for error resilience."""
    return error_resilience_observability


def enable_error_resilience_observability() -> None:
    """Convenience function to enable error resilience observability."""
    error_resilience_observability.enable()


def disable_error_resilience_observability() -> None:
    """Convenience function to disable error resilience observability."""
    error_resilience_observability.disable()
