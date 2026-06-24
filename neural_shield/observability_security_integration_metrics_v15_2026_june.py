"""
Observability & Instrumentation Integration v15 - NeuralShield-AI
Security Module Metrics, Structured Logging, and Health Checks
================================================================
API STABILITY: EXPERIMENTAL (v15 - first security integration)
BACKWARD COMPATIBLE: YES - 100% opt-in, no breaking changes
DEPENDENCIES: Standard library only (no external packages)

This module provides:
1. Structured security event logging (OPT-IN, disabled by default)
2. Metrics collection for security validation operations
3. Health check endpoints for security subsystems
4. Distributed tracing correlation for security events
5. All instrumentation wraps existing code - NO core modifications
"""

import time
import json
import hashlib
import hmac
import threading
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
from datetime import datetime, timezone


class SecurityEventType(Enum):
    """Types of security events that can be instrumented."""
    INPUT_VALIDATION = "input_validation"
    MEMORY_ZEROIZATION = "memory_zeroization"
    CONSTANT_TIME_COMPARE = "constant_time_compare"
    RATE_LIMIT_CHECK = "rate_limit_check"
    SENSITIVE_DATA_REDACTION = "sensitive_data_redaction"
    THREAT_DETECTION = "threat_detection"
    AUDIT_LOG_ENTRY = "audit_log_entry"
    HEALTH_CHECK = "health_check"


class MetricType(Enum):
    """Types of metrics collected."""
    COUNTER = "counter"
    GAUGE = "gauge"
    TIMER = "timer"
    HISTOGRAM = "histogram"


@dataclass
class SecurityEvent:
    """Structured security event with correlation context."""
    event_type: SecurityEventType
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    correlation_id: str = ""
    module_name: str = ""
    success: bool = True
    duration_ms: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    trace_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_type": self.event_type.value,
            "timestamp": self.timestamp,
            "correlation_id": self.correlation_id,
            "module_name": self.module_name,
            "success": self.success,
            "duration_ms": round(self.duration_ms, 4),
            "metadata": self.metadata,
            "trace_id": self.trace_id,
            "version": "v15"
        }


class SecurityMetricsCollector:
    """
    Thread-safe metrics collector for security operations.
    OPT-IN: Must be explicitly enabled via enable()
    """

    def __init__(self):
        self._enabled = False
        self._lock = threading.RLock()
        self._counters: Dict[str, int] = defaultdict(int)
        self._gauges: Dict[str, float] = {}
        self._timers: Dict[str, List[float]] = defaultdict(list)
        self._histograms: Dict[str, List[float]] = defaultdict(list)
        self._max_samples = 1000  # Prevent memory explosion

    def enable(self) -> None:
        """Enable metrics collection. Disabled by default."""
        with self._lock:
            self._enabled = True

    def disable(self) -> None:
        """Disable metrics collection."""
        with self._lock:
            self._enabled = False

    def is_enabled(self) -> bool:
        return self._enabled

    def increment_counter(self, name: str, value: int = 1, labels: Optional[Dict[str, str]] = None) -> None:
        """Increment a counter metric."""
        if not self._enabled:
            return
        with self._lock:
            key = self._make_key(name, labels)
            self._counters[key] += value

    def set_gauge(self, name: str, value: float, labels: Optional[Dict[str, str]] = None) -> None:
        """Set a gauge metric."""
        if not self._enabled:
            return
        with self._lock:
            key = self._make_key(name, labels)
            self._gauges[key] = value

    def record_timer(self, name: str, duration_ms: float, labels: Optional[Dict[str, str]] = None) -> None:
        """Record a timing metric."""
        if not self._enabled:
            return
        with self._lock:
            key = self._make_key(name, labels)
            self._timers[key].append(duration_ms)
            if len(self._timers[key]) > self._max_samples:
                self._timers[key] = self._timers[key][-self._max_samples:]

    def record_histogram(self, name: str, value: float, labels: Optional[Dict[str, str]] = None) -> None:
        """Record a histogram value."""
        if not self._enabled:
            return
        with self._lock:
            key = self._make_key(name, labels)
            self._histograms[key].append(value)
            if len(self._histograms[key]) > self._max_samples:
                self._histograms[key] = self._histograms[key][-self._max_samples:]

    def _make_key(self, name: str, labels: Optional[Dict[str, str]]) -> str:
        if not labels:
            return name
        sorted_labels = sorted(labels.items())
        label_str = ",".join(f"{k}={v}" for k, v in sorted_labels)
        return f"{name}[{label_str}]"

    def get_snapshot(self) -> Dict[str, Any]:
        """Get a snapshot of all collected metrics."""
        with self._lock:
            return {
                "counters": dict(self._counters),
                "gauges": dict(self._gauges),
                "timer_stats": {
                    name: {
                        "count": len(timings),
                        "min": min(timings) if timings else 0,
                        "max": max(timings) if timings else 0,
                        "avg": sum(timings) / len(timings) if timings else 0,
                        "p50": sorted(timings)[len(timings) // 2] if timings else 0,
                        "p95": sorted(timings)[int(len(timings) * 0.95)] if timings else 0,
                        "p99": sorted(timings)[int(len(timings) * 0.99)] if timings else 0,
                    }
                    for name, timings in self._timers.items()
                },
                "histogram_stats": {
                    name: {
                        "count": len(values),
                        "min": min(values) if values else 0,
                        "max": max(values) if values else 0,
                        "avg": sum(values) / len(values) if values else 0,
                    }
                    for name, values in self._histograms.items()
                },
                "enabled": self._enabled,
                "version": "v15"
            }

    def reset(self) -> None:
        """Reset all metrics."""
        with self._lock:
            self._counters.clear()
            self._gauges.clear()
            self._timers.clear()
            self._histograms.clear()


class StructuredSecurityLogger:
    """
    Structured logger for security events.
    OPT-IN: Must be explicitly enabled
    Outputs JSON-formatted logs to stdout by default
    """

    def __init__(self, metrics_collector: SecurityMetricsCollector):
        self._enabled = False
        self._metrics = metrics_collector
        self._output_handler: Callable[[str], None] = print
        self._lock = threading.Lock()

    def enable(self) -> None:
        """Enable structured logging."""
        with self._lock:
            self._enabled = True

    def disable(self) -> None:
        """Disable structured logging."""
        with self._lock:
            self._enabled = False

    def is_enabled(self) -> bool:
        return self._enabled

    def set_output_handler(self, handler: Callable[[str], None]) -> None:
        """Set custom log output handler (e.g., file writer, syslog)."""
        with self._lock:
            self._output_handler = handler

    def log_event(self, event: SecurityEvent) -> None:
        """Log a security event if enabled."""
        if not self._enabled:
            return

        log_entry = json.dumps(event.to_dict(), separators=(",", ":"))

        with self._lock:
            self._output_handler(log_entry)

        if self._metrics.is_enabled():
            self._metrics.increment_counter(
                "security_events_logged",
                labels={"event_type": event.event_type.value, "success": str(event.success).lower()}
            )

    def log_security_operation(
        self,
        event_type: SecurityEventType,
        module_name: str,
        success: bool = True,
        duration_ms: float = 0.0,
        metadata: Optional[Dict[str, Any]] = None,
        correlation_id: str = ""
    ) -> None:
        """Convenience method to log a security operation."""
        event = SecurityEvent(
            event_type=event_type,
            module_name=module_name,
            success=success,
            duration_ms=duration_ms,
            metadata=metadata or {},
            correlation_id=correlation_id
        )
        self.log_event(event)


class SecurityHealthChecker:
    """
    Health check framework for security subsystems.
    Provides liveness and readiness probes.
    """

    def __init__(self, metrics_collector: SecurityMetricsCollector):
        self._metrics = metrics_collector
        self._checks: Dict[str, Callable[[], Dict[str, Any]]] = {}
        self._lock = threading.Lock()

    def register_check(self, name: str, check_fn: Callable[[], Dict[str, Any]]) -> None:
        """Register a health check function."""
        with self._lock:
            self._checks[name] = check_fn

    def run_health_check(self) -> Dict[str, Any]:
        """Run all registered health checks."""
        start_time = time.time()
        results = {}
        overall_healthy = True

        with self._lock:
            checks_copy = dict(self._checks)

        for name, check_fn in checks_copy.items():
            try:
                result = check_fn()
                results[name] = result
                if not result.get("healthy", True):
                    overall_healthy = False
            except Exception as e:
                results[name] = {
                    "healthy": False,
                    "error": str(type(e).__name__),
                    "message": str(e)
                }
                overall_healthy = False

        duration_ms = (time.time() - start_time) * 1000

        if self._metrics.is_enabled():
            self._metrics.increment_counter("health_checks_run", labels={"status": "healthy" if overall_healthy else "unhealthy"})
            self._metrics.record_timer("health_check_duration_ms", duration_ms)

        return {
            "healthy": overall_healthy,
            "checks": results,
            "duration_ms": round(duration_ms, 4),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "version": "v15"
        }

    def get_liveness_probe(self) -> Dict[str, Any]:
        """Simple liveness probe - always returns healthy unless catastrophic."""
        return {
            "alive": True,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "version": "v15"
        }

    def get_readiness_probe(self) -> Dict[str, Any]:
        """Full readiness probe - runs all health checks."""
        return self.run_health_check()


class SecurityInstrumentationWrapper:
    """
    Wrapper class that instruments security operations with metrics and logging.
    WRAPS existing security functions - NO core code modifications.
    All instrumentation is OPT-IN via enable_instrumentation().
    """

    def __init__(self):
        self.metrics = SecurityMetricsCollector()
        self.logger = StructuredSecurityLogger(self.metrics)
        self.health = SecurityHealthChecker(self.metrics)
        self._instrumentation_enabled = False
        self._lock = threading.Lock()

    def enable_instrumentation(self) -> None:
        """Enable ALL instrumentation (metrics + logging)."""
        with self._lock:
            self.metrics.enable()
            self.logger.enable()
            self._instrumentation_enabled = True

    def disable_instrumentation(self) -> None:
        """Disable ALL instrumentation."""
        with self._lock:
            self.metrics.disable()
            self.logger.disable()
            self._instrumentation_enabled = False

    def is_instrumented(self) -> bool:
        return self._instrumentation_enabled

    def wrap_security_function(
        self,
        func: Callable,
        event_type: SecurityEventType,
        module_name: str
    ) -> Callable:
        """
        Wrap a security function with metrics and logging.
        Returns the original function if instrumentation is disabled.
        """
        def wrapped(*args, **kwargs):
            if not self._instrumentation_enabled:
                return func(*args, **kwargs)

            start_time = time.time()
            success = True
            result = None

            try:
                result = func(*args, **kwargs)
                return result
            except Exception as e:
                success = False
                raise
            finally:
                duration_ms = (time.time() - start_time) * 1000
                self.metrics.record_timer(
                    "security_operation_duration_ms",
                    duration_ms,
                    labels={"operation": event_type.value, "module": module_name}
                )
                self.metrics.increment_counter(
                    "security_operations",
                    labels={"operation": event_type.value, "module": module_name, "success": str(success).lower()}
                )
                self.logger.log_security_operation(
                    event_type=event_type,
                    module_name=module_name,
                    success=success,
                    duration_ms=duration_ms,
                    metadata={"args_count": len(args), "has_kwargs": bool(kwargs)}
                )

        return wrapped

    def timed_operation(self, name: str, labels: Optional[Dict[str, str]] = None):
        """Decorator for timing operations."""
        def decorator(func):
            def wrapper(*args, **kwargs):
                if not self._instrumentation_enabled:
                    return func(*args, **kwargs)

                start_time = time.time()
                try:
                    return func(*args, **kwargs)
                finally:
                    duration_ms = (time.time() - start_time) * 1000
                    self.metrics.record_timer(name, duration_ms, labels)
            return wrapper
        return decorator


# Global singleton instance - OPT-IN, disabled by default
# Users must explicitly call .enable_instrumentation() to use it
SECURITY_INSTRUMENTATION = SecurityInstrumentationWrapper()


def get_instrumentation() -> SecurityInstrumentationWrapper:
    """
    Get the global instrumentation instance.
    NOTE: Instrumentation is DISABLED by default.
    Call .enable_instrumentation() to activate.
    """
    return SECURITY_INSTRUMENTATION


def generate_correlation_id() -> str:
    """Generate a unique correlation ID for tracing."""
    timestamp = str(time.time_ns()).encode()
    random_data = str(time.perf_counter_ns()).encode()
    return hashlib.sha256(timestamp + random_data).hexdigest()[:32]


"""
HONEST LIMITATIONS (v15):
1. DISABLED BY DEFAULT - Users must explicitly opt-in to all instrumentation
2. Memory bounded - max 1000 samples per metric to prevent leaks
3. No network export - Metrics stay in memory, user must export manually
4. No distributed tracing backend integration - Just correlation ID generation
5. Thread-safe but not multiprocess-safe
6. Logs go to stdout by default - User must provide custom handler for files
7. Health checks are user-defined - No built-in checks provided
8. No automatic metric cardinality limits - User responsible for label explosion
9. No persistence - Metrics reset on process restart
10. Standard library only - No Prometheus, OpenTelemetry, or statsd integration
"""
