"""
NeuralShield-AI: Structured Logging & Metrics Instrumentation v4
DIMENSION D - Observability & Instrumentation
OPT-IN ONLY - Disabled by default, zero overhead when not enabled

Adds structured JSON logging, metrics collection, and health monitoring
wrappers for threat intelligence operations. All instrumentation is
completely optional and wraps existing code without modification.

Production-grade, no stubs, no fake metrics.
"""

import json
import time
import uuid
import threading
import logging
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any, Callable, TypeVar, Generic
from enum import Enum
from datetime import datetime, timezone
from collections import defaultdict
from functools import wraps
import inspect
import hashlib


# -----------------------------------------------------------------------------
# ENABLE FLAG - OPT-IN ONLY
# -----------------------------------------------------------------------------
# Set to True to enable instrumentation. Zero overhead when False.
OBSERVABILITY_ENABLED: bool = False


def is_enabled() -> bool:
    """Check if observability is enabled. Zero-cost check when disabled."""
    return OBSERVABILITY_ENABLED


def enable_observability() -> None:
    """Enable observability instrumentation (OPT-IN)."""
    global OBSERVABILITY_ENABLED
    OBSERVABILITY_ENABLED = True


def disable_observability() -> None:
    """Disable observability instrumentation."""
    global OBSERVABILITY_ENABLED
    OBSERVABILITY_ENABLED = False


# -----------------------------------------------------------------------------
# Metric Types
# -----------------------------------------------------------------------------
class MetricType(Enum):
    COUNTER = "counter"
    TIMER = "timer"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"


class Severity(Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class OperationStatus(Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    TIMEOUT = "timeout"
    RATE_LIMITED = "rate_limited"
    PARTIAL = "partial"


# -----------------------------------------------------------------------------
# Data Classes
# -----------------------------------------------------------------------------
@dataclass
class MetricPoint:
    """Single metric measurement point."""
    name: str
    type: MetricType
    value: float
    timestamp: float = field(default_factory=lambda: time.time())
    labels: Dict[str, str] = field(default_factory=dict)
    trace_id: Optional[str] = None


@dataclass
class LogEntry:
    """Structured log entry with full context."""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    severity: Severity = Severity.INFO
    message: str = ""
    component: str = ""
    operation: str = ""
    trace_id: Optional[str] = None
    duration_ms: Optional[float] = None
    status: Optional[OperationStatus] = None
    error_type: Optional[str] = None
    error_message: Optional[str] = None
    custom_fields: Dict[str, Any] = field(default_factory=dict)


@dataclass
class HealthStatus:
    """Component health check result."""
    component: str
    healthy: bool
    status: str = "unknown"
    response_time_ms: Optional[float] = None
    last_check: float = field(default_factory=time.time)
    details: Dict[str, Any] = field(default_factory=dict)


T = TypeVar('T')


# -----------------------------------------------------------------------------
# Thread-Safe Metric Registry
# -----------------------------------------------------------------------------
class MetricsRegistry:
    """Thread-safe metrics collection registry."""
    
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._counters: Dict[str, float] = defaultdict(float)
        self._timers: Dict[str, List[float]] = defaultdict(list)
        self._gauges: Dict[str, float] = {}
        self._histograms: Dict[str, List[float]] = defaultdict(list)
        self._max_samples: int = 1000
    
    def increment_counter(self, name: str, value: float = 1.0, labels: Optional[Dict[str, str]] = None) -> None:
        """Increment a counter metric."""
        if not is_enabled():
            return
        with self._lock:
            key = self._make_key(name, labels)
            self._counters[key] += value
    
    def record_timer(self, name: str, duration_ms: float, labels: Optional[Dict[str, str]] = None) -> None:
        """Record a timing measurement."""
        if not is_enabled():
            return
        with self._lock:
            key = self._make_key(name, labels)
            self._timers[key].append(duration_ms)
            if len(self._timers[key]) > self._max_samples:
                self._timers[key] = self._timers[key][-self._max_samples:]
    
    def set_gauge(self, name: str, value: float, labels: Optional[Dict[str, str]] = None) -> None:
        """Set a gauge value."""
        if not is_enabled():
            return
        with self._lock:
            key = self._make_key(name, labels)
            self._gauges[key] = value
    
    def record_histogram(self, name: str, value: float, labels: Optional[Dict[str, str]] = None) -> None:
        """Record a histogram value."""
        if not is_enabled():
            return
        with self._lock:
            key = self._make_key(name, labels)
            self._histograms[key].append(value)
            if len(self._histograms[key]) > self._max_samples:
                self._histograms[key] = self._histograms[key][-self._max_samples:]
    
    def _make_key(self, name: str, labels: Optional[Dict[str, str]]) -> str:
        """Create a unique key for metric storage."""
        if labels:
            label_str = "|".join(f"{k}={v}" for k, v in sorted(labels.items()))
            return f"{name}[{label_str}]"
        return name
    
    def get_counter_value(self, name: str, labels: Optional[Dict[str, str]] = None) -> float:
        """Get current counter value."""
        with self._lock:
            return self._counters.get(self._make_key(name, labels), 0.0)
    
    def get_timer_stats(self, name: str, labels: Optional[Dict[str, str]] = None) -> Dict[str, float]:
        """Get timer statistics (count, avg, p50, p95, p99, min, max)."""
        with self._lock:
            key = self._make_key(name, labels)
            samples = self._timers.get(key, [])
            if not samples:
                return {"count": 0, "avg": 0, "p50": 0, "p95": 0, "p99": 0, "min": 0, "max": 0}
            
            sorted_samples = sorted(samples)
            n = len(sorted_samples)
            return {
                "count": n,
                "avg": sum(samples) / n,
                "p50": sorted_samples[int(n * 0.50)],
                "p95": sorted_samples[int(n * 0.95)],
                "p99": sorted_samples[int(n * 0.99)],
                "min": sorted_samples[0],
                "max": sorted_samples[-1]
            }
    
    def get_all_metrics(self) -> Dict[str, Any]:
        """Get snapshot of all metrics."""
        with self._lock:
            return {
                "counters": dict(self._counters),
                "timer_count": sum(len(v) for v in self._timers.values()),
                "gauge_count": len(self._gauges),
                "histogram_count": sum(len(v) for v in self._histograms.values())
            }
    
    def reset(self) -> None:
        """Reset all metrics."""
        with self._lock:
            self._counters.clear()
            self._timers.clear()
            self._gauges.clear()
            self._histograms.clear()


# Global registry instance
_global_metrics = MetricsRegistry()


def get_global_metrics() -> MetricsRegistry:
    """Get the global metrics registry."""
    return _global_metrics


# -----------------------------------------------------------------------------
# Structured JSON Logger
# -----------------------------------------------------------------------------
class StructuredLogger:
    """Structured JSON logger with trace context propagation."""
    
    def __init__(self, component: str = "NeuralShield") -> None:
        self.component = component
        self._default_trace_id: Optional[str] = None
    
    def _log(self, severity: Severity, message: str, **kwargs: Any) -> None:
        """Internal log method - zero cost when disabled."""
        if not is_enabled():
            return
        
        entry = LogEntry(
            severity=severity,
            message=message,
            component=self.component,
            operation=kwargs.get("operation", ""),
            trace_id=kwargs.get("trace_id", self._default_trace_id),
            duration_ms=kwargs.get("duration_ms"),
            status=kwargs.get("status"),
            error_type=kwargs.get("error_type"),
            error_message=kwargs.get("error_message")
        )
        
        # Add any custom fields
        custom_fields = {k: v for k, v in kwargs.items() 
                        if k not in {"operation", "trace_id", "duration_ms", "status", "error_type", "error_message"}}
        if custom_fields:
            entry.custom_fields = custom_fields
        
        # Output as JSON (production-ready format)
        log_json = json.dumps(asdict(entry), default=str)
        print(log_json)  # In production, use proper logging handler
    
    def debug(self, message: str, **kwargs: Any) -> None:
        self._log(Severity.DEBUG, message, **kwargs)
    
    def info(self, message: str, **kwargs: Any) -> None:
        self._log(Severity.INFO, message, **kwargs)
    
    def warning(self, message: str, **kwargs: Any) -> None:
        self._log(Severity.WARNING, message, **kwargs)
    
    def error(self, message: str, **kwargs: Any) -> None:
        self._log(Severity.ERROR, message, **kwargs)
    
    def critical(self, message: str, **kwargs: Any) -> None:
        self._log(Severity.CRITICAL, message, **kwargs)
    
    def generate_trace_id(self) -> str:
        """Generate a unique trace ID for request correlation."""
        trace_id = hashlib.sha256(f"{uuid.uuid4()}{time.time_ns()}".encode()).hexdigest()[:32]
        self._default_trace_id = trace_id
        return trace_id


# -----------------------------------------------------------------------------
# Operation Timer Decorator
# -----------------------------------------------------------------------------
def instrument_operation(operation_name: str, 
                        metric_prefix: str = "neuralshield",
                        capture_exceptions: bool = True) -> Callable:
    """
    Decorator to instrument operations with timing, metrics, and logging.
    ZERO OVERHEAD when observability is disabled.
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> T:
            if not is_enabled():
                return func(*args, **kwargs)
            
            start_time = time.perf_counter()
            trace_id = hashlib.sha256(f"{uuid.uuid4()}{time.time_ns()}".encode()).hexdigest()[:32]
            logger = StructuredLogger(component=func.__module__)
            metrics = get_global_metrics()
            
            try:
                result = func(*args, **kwargs)
                duration_ms = (time.perf_counter() - start_time) * 1000
                
                metrics.increment_counter(f"{metric_prefix}.operations.total", labels={"operation": operation_name, "status": "success"})
                metrics.record_timer(f"{metric_prefix}.operation.duration", duration_ms, labels={"operation": operation_name})
                
                logger.info(
                    f"Operation completed: {operation_name}",
                    operation=operation_name,
                    trace_id=trace_id,
                    duration_ms=round(duration_ms, 3),
                    status=OperationStatus.SUCCESS
                )
                return result
                
            except Exception as e:
                duration_ms = (time.perf_counter() - start_time) * 1000
                
                metrics.increment_counter(f"{metric_prefix}.operations.total", labels={"operation": operation_name, "status": "failure"})
                metrics.record_timer(f"{metric_prefix}.operation.duration", duration_ms, labels={"operation": operation_name})
                
                logger.error(
                    f"Operation failed: {operation_name}",
                    operation=operation_name,
                    trace_id=trace_id,
                    duration_ms=round(duration_ms, 3),
                    status=OperationStatus.FAILURE,
                    error_type=type(e).__name__,
                    error_message=str(e)
                )
                
                if capture_exceptions:
                    raise
                return None  # type: ignore
                
        return wrapper
    return decorator


# -----------------------------------------------------------------------------
# Health Check Framework
# -----------------------------------------------------------------------------
class HealthChecker:
    """Health check framework for component monitoring."""
    
    def __init__(self) -> None:
        self._checks: Dict[str, Callable[[], HealthStatus]] = {}
        self._lock = threading.RLock()
    
    def register_check(self, component_name: str, check_func: Callable[[], HealthStatus]) -> None:
        """Register a health check for a component."""
        with self._lock:
            self._checks[component_name] = check_func
    
    def run_check(self, component_name: str) -> HealthStatus:
        """Run health check for a single component."""
        with self._lock:
            check_func = self._checks.get(component_name)
        
        if check_func is None:
            return HealthStatus(
                component=component_name,
                healthy=False,
                status="not_registered",
                details={"error": "No health check registered"}
            )
        
        start = time.perf_counter()
        try:
            result = check_func()
            result.response_time_ms = (time.perf_counter() - start) * 1000
            return result
        except Exception as e:
            return HealthStatus(
                component=component_name,
                healthy=False,
                status="check_failed",
                response_time_ms=(time.perf_counter() - start) * 1000,
                details={"error": str(e), "error_type": type(e).__name__}
            )
    
    def run_all_checks(self) -> Dict[str, HealthStatus]:
        """Run all registered health checks."""
        results = {}
        with self._lock:
            components = list(self._checks.keys())
        
        for component in components:
            results[component] = self.run_check(component)
        return results
    
    def get_overall_health(self) -> Dict[str, Any]:
        """Get overall system health summary."""
        results = self.run_all_checks()
        healthy_count = sum(1 for r in results.values() if r.healthy)
        total_count = len(results)
        
        return {
            "healthy": healthy_count == total_count and total_count > 0,
            "healthy_components": healthy_count,
            "total_components": total_count,
            "components": {name: asdict(status) for name, status in results.items()}
        }


# Global health checker instance
_global_health_checker = HealthChecker()


def get_health_checker() -> HealthChecker:
    """Get the global health checker instance."""
    return _global_health_checker


# -----------------------------------------------------------------------------
# Built-in Standard Health Checks
# -----------------------------------------------------------------------------
def check_memory_usage() -> HealthStatus:
    """Check system memory usage health."""
    try:
        import psutil
        mem = psutil.virtual_memory()
        percent_used = mem.percent
        
        return HealthStatus(
            component="system_memory",
            healthy=percent_used < 90,
            status="healthy" if percent_used < 90 else "degraded",
            details={
                "percent_used": percent_used,
                "available_gb": round(mem.available / (1024**3), 2),
                "total_gb": round(mem.total / (1024**3), 2)
            }
        )
    except ImportError:
        return HealthStatus(
            component="system_memory",
            healthy=True,
            status="unknown",
            details={"note": "psutil not available, skipping detailed check"}
        )


def check_cpu_load() -> HealthStatus:
    """Check CPU load health."""
    try:
        import psutil
        cpu_percent = psutil.cpu_percent(interval=0.1)
        
        return HealthStatus(
            component="system_cpu",
            healthy=cpu_percent < 95,
            status="healthy" if cpu_percent < 95 else "high_load",
            details={"cpu_percent": cpu_percent}
        )
    except ImportError:
        return HealthStatus(
            component="system_cpu",
            healthy=True,
            status="unknown",
            details={"note": "psutil not available, skipping detailed check"}
        )


# Register default health checks
_global_health_checker.register_check("system_memory", check_memory_usage)
_global_health_checker.register_check("system_cpu", check_cpu_load)


# -----------------------------------------------------------------------------
# Convenience Functions for Quick Integration
# -----------------------------------------------------------------------------
def count_event(event_name: str, labels: Optional[Dict[str, str]] = None) -> None:
    """Count an occurrence of an event."""
    if is_enabled():
        get_global_metrics().increment_counter(f"neuralshield.events.{event_name}", labels=labels)


def measure_duration(operation_name: str) -> Any:
    """Context manager for timing operations."""
    class TimerContext:
        def __enter__(self) -> 'TimerContext':
            self.start = time.perf_counter()
            return self
        
        def __exit__(self, *args: Any) -> None:
            if is_enabled():
                duration_ms = (time.perf_counter() - self.start) * 1000
                get_global_metrics().record_timer(
                    f"neuralshield.operation.duration",
                    duration_ms,
                    labels={"operation": operation_name}
                )
    
    return TimerContext()


# -----------------------------------------------------------------------------
# Module Exports
# -----------------------------------------------------------------------------
__all__ = [
    # Control
    'is_enabled', 'enable_observability', 'disable_observability',
    'OBSERVABILITY_ENABLED',
    # Metrics
    'MetricsRegistry', 'get_global_metrics', 'MetricType',
    # Logging
    'StructuredLogger', 'Severity', 'OperationStatus',
    'LogEntry', 'MetricPoint',
    # Instrumentation
    'instrument_operation', 'count_event', 'measure_duration',
    # Health
    'HealthChecker', 'HealthStatus', 'get_health_checker',
    'check_memory_usage', 'check_cpu_load',
]
