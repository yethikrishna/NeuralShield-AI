"""
Comprehensive Observability & Instrumentation Framework v16
Dimension D - Observability & Instrumentation

ADD-ONLY implementation - wraps existing code, no core modifications
All instrumentation is OPT-IN, disabled by default by default

Features:
- Structured logging (optional, disabled by default)
- Metrics collection (counters, timers, gauges, histograms)
- Health check framework with multiple check types
- Distributed tracing context propagation
- Performance profiling wrappers
- Event emission system
"""

import time
import logging
import json
import threading
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, List, Optional, Any, Callable, TypeVar, Generic
from datetime import datetime, timezone
from functools import wraps
from collections import defaultdict
from contextlib import contextmanager
import inspect
import os


# -----------------------------------------------------------------------------
# Configuration - ALL OPT-IN, DISABLED BY DEFAULT
# -----------------------------------------------------------------------------
class ObservabilityConfig:
    """Global configuration for observability systems.
    
    All features are DISABLED by default. Explicit opt-in required.
    """
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialize_defaults()
            return cls._instance
    
    def _initialize_defaults(self):
        """Initialize with ALL features DISABLED by default."""
        self.LOGGING_ENABLED = False
        self.METRICS_ENABLED = False
        self.HEALTH_CHECKS_ENABLED = False
        self.TRACING_ENABLED = False
        self.PROFILING_ENABLED = False
        self.EVENTS_ENABLED = False
        
        self.LOG_LEVEL = logging.WARNING
        self.LOG_FORMAT = "structured_json"
        self.METRICS_FLUSH_INTERVAL = 60
        self.HEALTH_CHECK_INTERVAL = 30
        self.MAX_METRICS_HISTORY = 1000
        
        # Environment variable overrides (still require explicit opt-in)
        self._apply_env_overrides()
    
    def _apply_env_overrides(self):
        """Apply environment variable overrides if explicitly set."""
        if os.getenv("NEURALSHIELD_OBSERVABILITY_ENABLE_ALL") == "1":
            self.enable_all()
    
    def enable_all(self):
        """Enable all observability features (explicit opt-in)."""
        self.LOGGING_ENABLED = True
        self.METRICS_ENABLED = True
        self.HEALTH_CHECKS_ENABLED = True
        self.TRACING_ENABLED = True
        self.PROFILING_ENABLED = True
        self.EVENTS_ENABLED = True
    
    def disable_all(self):
        """Disable all observability features."""
        self.LOGGING_ENABLED = False
        self.METRICS_ENABLED = False
        self.HEALTH_CHECKS_ENABLED = False
        self.TRACING_ENABLED = False
        self.PROFILING_ENABLED = False
        self.EVENTS_ENABLED = False


# -----------------------------------------------------------------------------
# Enums and Data Classes
# -----------------------------------------------------------------------------
class MetricType(Enum):
    COUNTER = "counter"
    GAUGE = "gauge"
    TIMER = "timer"
    HISTOGRAM = "histogram"


class HealthStatus(Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


class LogLevel(Enum):
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class MetricPoint:
    name: str
    type: MetricType
    value: float
    timestamp: float = field(default_factory=lambda: time.time())
    labels: Dict[str, str] = field(default_factory=dict)
    unit: Optional[str] = None


@dataclass
class HealthCheckResult:
    check_name: str
    status: HealthStatus
    message: str = ""
    duration_ms: float = 0.0
    timestamp: float = field(default_factory=lambda: time.time())
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TraceSpan:
    trace_id: str
    span_id: str
    parent_span_id: Optional[str]
    name: str
    start_time: float
    end_time: Optional[float] = None
    duration_ms: Optional[float] = None
    attributes: Dict[str, Any] = field(default_factory=dict)
    status: str = "in_progress"


@dataclass
class ObservabilityEvent:
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    event_type: str = "general"
    timestamp: float = field(default_factory=lambda: time.time())
    source: str = ""
    severity: str = "info"
    message: str = ""
    data: Dict[str, Any] = field(default_factory=dict)


T = TypeVar('T')


# -----------------------------------------------------------------------------
# Structured Logging (OPT-IN ONLY)
# -----------------------------------------------------------------------------
class StructuredLogger:
    """Structured JSON logger - disabled by default."""
    
    def __init__(self, name: str = "neural_shield"):
        self.config = ObservabilityConfig()
        self.logger = logging.getLogger(name)
        self._setup_logger()
    
    def _setup_logger(self):
        """Configure logger only if enabled."""
        if not self.config.LOGGING_ENABLED:
            return
        
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s %(name)s %(levelname)s %(message)s'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
        
        self.logger.setLevel(self.config.LOG_LEVEL)
    
    def _log(self, level: LogLevel, message: str, **kwargs):
        """Log only if explicitly enabled."""
        if not self.config.LOGGING_ENABLED:
            return
        
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": level.value,
            "message": message,
            **kwargs
        }
        
        log_method = getattr(self.logger, level.value)
        log_method(json.dumps(log_entry))
    
    def debug(self, message: str, **kwargs):
        self._log(LogLevel.DEBUG, message, **kwargs)
    
    def info(self, message: str, **kwargs):
        self._log(LogLevel.INFO, message, **kwargs)
    
    def warning(self, message: str, **kwargs):
        self._log(LogLevel.WARNING, message, **kwargs)
    
    def error(self, message: str, **kwargs):
        self._log(LogLevel.ERROR, message, **kwargs)
    
    def critical(self, message: str, **kwargs):
        self._log(LogLevel.CRITICAL, message, **kwargs)


# -----------------------------------------------------------------------------
# Metrics Collection (OPT-IN ONLY)
# -----------------------------------------------------------------------------
class MetricsCollector:
    """Collect and store metrics - disabled by default."""
    
    def __init__(self):
        self.config = ObservabilityConfig()
        self._lock = threading.Lock()
        self._counters: Dict[str, float] = defaultdict(float)
        self._gauges: Dict[str, float] = {}
        self._timers: Dict[str, List[float]] = defaultdict(list)
        self._histograms: Dict[str, List[float]] = defaultdict(list)
        self._history: List[MetricPoint] = []
    
    def increment_counter(self, name: str, value: float = 1.0, labels: Dict[str, str] = None):
        """Increment a counter metric."""
        if not self.config.METRICS_ENABLED:
            return
        
        with self._lock:
            self._counters[name] += value
            self._record_metric(MetricType.COUNTER, name, self._counters[name], labels)
    
    def set_gauge(self, name: str, value: float, labels: Dict[str, str] = None):
        """Set a gauge metric."""
        if not self.config.METRICS_ENABLED:
            return
        
        with self._lock:
            self._gauges[name] = value
            self._record_metric(MetricType.GAUGE, name, value, labels)
    
    def record_timer(self, name: str, duration_ms: float, labels: Dict[str, str] = None):
        """Record a timer value."""
        if not self.config.METRICS_ENABLED:
            return
        
        with self._lock:
            self._timers[name].append(duration_ms)
            if len(self._timers[name]) > self.config.MAX_METRICS_HISTORY:
                self._timers[name] = self._timers[name][-self.config.MAX_METRICS_HISTORY:]
            self._record_metric(MetricType.TIMER, name, duration_ms, labels, "ms")
    
    def record_histogram(self, name: str, value: float, labels: Dict[str, str] = None):
        """Record a histogram value."""
        if not self.config.METRICS_ENABLED:
            return
        
        with self._lock:
            self._histograms[name].append(value)
            if len(self._histograms[name]) > self.config.MAX_METRICS_HISTORY:
                self._histograms[name] = self._histograms[name][-self.config.MAX_METRICS_HISTORY:]
            self._record_metric(MetricType.HISTOGRAM, name, value, labels)
    
    def _record_metric(self, metric_type: MetricType, name: str, value: float, 
                       labels: Optional[Dict[str, str]], unit: Optional[str] = None):
        """Record a metric point."""
        point = MetricPoint(
            name=name,
            type=metric_type,
            value=value,
            labels=labels or {},
            unit=unit
        )
        self._history.append(point)
        if len(self._history) > self.config.MAX_METRICS_HISTORY:
            self._history.pop(0)
    
    def get_counter(self, name: str) -> float:
        """Get current counter value."""
        return self._counters.get(name, 0.0)
    
    def get_gauge(self, name: str) -> Optional[float]:
        """Get current gauge value."""
        return self._gauges.get(name)
    
    def get_timer_stats(self, name: str) -> Dict[str, Optional[float]]:
        """Get timer statistics."""
        timers = self._timers.get(name, [])
        if not timers:
            return {"count": 0, "avg": None, "min": None, "max": None, "p95": None}
        
        sorted_timers = sorted(timers)
        return {
            "count": len(timers),
            "avg": sum(timers) / len(timers),
            "min": min(timers),
            "max": max(timers),
            "p95": sorted_timers[int(len(sorted_timers) * 0.95)]
        }
    
    def get_all_metrics(self) -> Dict[str, Any]:
        """Get all metrics summary."""
        return {
            "counters": dict(self._counters),
            "gauges": dict(self._gauges),
            "timer_stats": {name: self.get_timer_stats(name) for name in self._timers},
            "history_count": len(self._history)
        }
    
    def reset(self):
        """Reset all metrics."""
        with self._lock:
            self._counters.clear()
            self._gauges.clear()
            self._timers.clear()
            self._histograms.clear()
            self._history.clear()


# Global metrics instance
_global_metrics = MetricsCollector()


def get_global_metrics() -> MetricsCollector:
    """Get the global metrics collector instance."""
    return _global_metrics


# -----------------------------------------------------------------------------
# Timer Decorator and Context Manager
# -----------------------------------------------------------------------------
def timed(name: Optional[str] = None, labels: Dict[str, str] = None):
    """Decorator to time function execution (OPT-IN ONLY)."""
    
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        metric_name = name or f"timer.{func.__module__}.{func.__name__}"
        
        @wraps(func)
        def wrapper(*args, **kwargs) -> T:
            config = ObservabilityConfig()
            if not config.METRICS_ENABLED:
                return func(*args, **kwargs)
            
            start_time = time.time()
            try:
                result = func(*args, **kwargs)
                return result
            finally:
                duration_ms = (time.time() - start_time) * 1000
                _global_metrics.record_timer(metric_name, duration_ms, labels)
        
        return wrapper
    
    return decorator


@contextmanager
def timer_context(name: str, labels: Dict[str, str] = None):
    """Context manager for timing code blocks (OPT-IN ONLY)."""
    config = ObservabilityConfig()
    if not config.METRICS_ENABLED:
        yield
        return
    
    start_time = time.time()
    try:
        yield
    finally:
        duration_ms = (time.time() - start_time) * 1000
        _global_metrics.record_timer(name, duration_ms, labels)


# -----------------------------------------------------------------------------
# Health Check Framework (OPT-IN ONLY)
# -----------------------------------------------------------------------------
class HealthChecker:
    """Health check framework - disabled by default."""
    
    def __init__(self):
        self.config = ObservabilityConfig()
        self._lock = threading.Lock()
        self._checks: Dict[str, Callable[[], HealthCheckResult]] = {}
        self._last_results: Dict[str, HealthCheckResult] = {}
    
    def register_check(self, name: str, check_func: Callable[[], HealthCheckResult]):
        """Register a health check function."""
        with self._lock:
            self._checks[name] = check_func
    
    def run_check(self, name: str) -> Optional[HealthCheckResult]:
        """Run a single health check."""
        if not self.config.HEALTH_CHECKS_ENABLED:
            return None
        
        check_func = self._checks.get(name)
        if not check_func:
            return None
        
        start_time = time.time()
        try:
            result = check_func()
            result.duration_ms = (time.time() - start_time) * 1000
            with self._lock:
                self._last_results[name] = result
            return result
        except Exception as e:
            result = HealthCheckResult(
                check_name=name,
                status=HealthStatus.UNHEALTHY,
                message=f"Check exception: {str(e)}",
                duration_ms=(time.time() - start_time) * 1000
            )
            with self._lock:
                self._last_results[name] = result
            return result
    
    def run_all_checks(self) -> List[HealthCheckResult]:
        """Run all registered health checks."""
        results = []
        for name in list(self._checks.keys()):
            result = self.run_check(name)
            if result:
                results.append(result)
        return results
    
    def get_overall_status(self) -> HealthStatus:
        """Get overall health status."""
        if not self._last_results:
            return HealthStatus.UNKNOWN
        
        statuses = [r.status for r in self._last_results.values()]
        if HealthStatus.UNHEALTHY in statuses:
            return HealthStatus.UNHEALTHY
        if HealthStatus.DEGRADED in statuses:
            return HealthStatus.DEGRADED
        return HealthStatus.HEALTHY
    
    def get_last_results(self) -> Dict[str, HealthCheckResult]:
        """Get last check results."""
        return dict(self._last_results)


# Global health checker instance
_global_health_checker = HealthChecker()


def get_global_health_checker() -> HealthChecker:
    """Get the global health checker instance."""
    return _global_health_checker


# -----------------------------------------------------------------------------
# Standard Health Checks
# -----------------------------------------------------------------------------
def create_memory_health_check() -> HealthCheckResult:
    """Check memory usage health."""
    try:
        import psutil
        process = psutil.Process()
        memory_mb = process.memory_info().rss / (1024 * 1024)
        
        if memory_mb < 500:
            return HealthCheckResult(
                check_name="memory_usage",
                status=HealthStatus.HEALTHY,
                message=f"Memory usage: {memory_mb:.1f} MB",
                metadata={"memory_mb": memory_mb}
            )
        elif memory_mb < 1000:
            return HealthCheckResult(
                check_name="memory_usage",
                status=HealthStatus.DEGRADED,
                message=f"Memory usage elevated: {memory_mb:.1f} MB",
                metadata={"memory_mb": memory_mb}
            )
        else:
            return HealthCheckResult(
                check_name="memory_usage",
                status=HealthStatus.UNHEALTHY,
                message=f"Memory usage high: {memory_mb:.1f} MB",
                metadata={"memory_mb": memory_mb}
            )
    except ImportError:
        return HealthCheckResult(
            check_name="memory_usage",
            status=HealthStatus.UNKNOWN,
            message="psutil not available for memory check"
        )


def create_cpu_health_check() -> HealthCheckResult:
    """Check CPU usage health."""
    try:
        import psutil
        cpu_percent = psutil.cpu_percent(interval=0.1)
        
        if cpu_percent < 70:
            return HealthCheckResult(
                check_name="cpu_usage",
                status=HealthStatus.HEALTHY,
                message=f"CPU usage: {cpu_percent}%",
                metadata={"cpu_percent": cpu_percent}
            )
        elif cpu_percent < 90:
            return HealthCheckResult(
                check_name="cpu_usage",
                status=HealthStatus.DEGRADED,
                message=f"CPU usage elevated: {cpu_percent}%",
                metadata={"cpu_percent": cpu_percent}
            )
        else:
            return HealthCheckResult(
                check_name="cpu_usage",
                status=HealthStatus.UNHEALTHY,
                message=f"CPU usage high: {cpu_percent}%",
                metadata={"cpu_percent": cpu_percent}
            )
    except ImportError:
        return HealthCheckResult(
            check_name="cpu_usage",
            status=HealthStatus.UNKNOWN,
            message="psutil not available for CPU check"
        )


# Register standard health checks
_global_health_checker.register_check("memory_usage", create_memory_health_check)
_global_health_checker.register_check("cpu_usage", create_cpu_health_check)


# -----------------------------------------------------------------------------
# Distributed Tracing (OPT-IN ONLY)
# -----------------------------------------------------------------------------
class TraceContext:
    """Thread-local trace context management."""
    
    _local = threading.local()
    
    @classmethod
    def get_current_trace_id(cls) -> Optional[str]:
        """Get current trace ID."""
        return getattr(cls._local, 'trace_id', None)
    
    @classmethod
    def get_current_span_id(cls) -> Optional[str]:
        """Get current span ID."""
        return getattr(cls._local, 'span_id', None)
    
    @classmethod
    def set_current(cls, trace_id: str, span_id: str):
        """Set current trace context."""
        cls._local.trace_id = trace_id
        cls._local.span_id = span_id
    
    @classmethod
    def clear(cls):
        """Clear current trace context."""
        if hasattr(cls._local, 'trace_id'):
            del cls._local.trace_id
        if hasattr(cls._local, 'span_id'):
            del cls._local.span_id


class Tracer:
    """Distributed tracer - disabled by default."""
    
    def __init__(self):
        self.config = ObservabilityConfig()
        self._lock = threading.Lock()
        self._spans: Dict[str, TraceSpan] = {}
    
    def start_span(self, name: str, parent_span_id: Optional[str] = None) -> str:
        """Start a new trace span."""
        if not self.config.TRACING_ENABLED:
            return ""
        
        trace_id = TraceContext.get_current_trace_id() or str(uuid.uuid4())
        span_id = str(uuid.uuid4())
        
        span = TraceSpan(
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=parent_span_id or TraceContext.get_current_span_id(),
            name=name,
            start_time=time.time()
        )
        
        with self._lock:
            self._spans[span_id] = span
        
        TraceContext.set_current(trace_id, span_id)
        return span_id
    
    def end_span(self, span_id: str, attributes: Dict[str, Any] = None, status: str = "ok"):
        """End a trace span."""
        if not self.config.TRACING_ENABLED or not span_id:
            return
        
        with self._lock:
            span = self._spans.get(span_id)
            if span:
                span.end_time = time.time()
                span.duration_ms = (span.end_time - span.start_time) * 1000
                span.attributes.update(attributes or {})
                span.status = status
        
        TraceContext.clear()
    
    def get_span(self, span_id: str) -> Optional[TraceSpan]:
        """Get a span by ID."""
        return self._spans.get(span_id)
    
    def get_all_spans(self) -> List[TraceSpan]:
        """Get all spans."""
        return list(self._spans.values())


# Global tracer instance
_global_tracer = Tracer()


def get_global_tracer() -> Tracer:
    """Get the global tracer instance."""
    return _global_tracer


def traced(name: Optional[str] = None):
    """Decorator for tracing function execution (OPT-IN ONLY)."""
    
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        span_name = name or f"trace.{func.__module__}.{func.__name__}"
        
        @wraps(func)
        def wrapper(*args, **kwargs) -> T:
            config = ObservabilityConfig()
            if not config.TRACING_ENABLED:
                return func(*args, **kwargs)
            
            span_id = _global_tracer.start_span(span_name)
            try:
                result = func(*args, **kwargs)
                _global_tracer.end_span(span_id, {"result": "success"}, "ok")
                return result
            except Exception as e:
                _global_tracer.end_span(span_id, {"error": str(e), "result": "error"}, "error")
                raise
        
        return wrapper
    
    return decorator


# -----------------------------------------------------------------------------
# Event Emitter (OPT-IN ONLY)
# -----------------------------------------------------------------------------
class EventEmitter:
    """Event emission system - disabled by default."""
    
    def __init__(self):
        self.config = ObservabilityConfig()
        self._lock = threading.Lock()
        self._events: List[ObservabilityEvent] = []
        self._handlers: Dict[str, List[Callable[[ObservabilityEvent], None]]] = defaultdict(list)
    
    def emit(self, event_type: str, message: str = "", severity: str = "info", 
             source: str = "", **kwargs) -> Optional[str]:
        """Emit an event."""
        if not self.config.EVENTS_ENABLED:
            return None
        
        event = ObservabilityEvent(
            event_type=event_type,
            message=message,
            severity=severity,
            source=source or inspect.stack()[1].function,
            data=kwargs
        )
        
        with self._lock:
            self._events.append(event)
            if len(self._events) > ObservabilityConfig().MAX_METRICS_HISTORY:
                self._events.pop(0)
        
        # Call handlers
        handlers = self._handlers.get(event_type, []) + self._handlers.get("*", [])
        for handler in handlers:
            try:
                handler(event)
            except Exception:
                pass  # Silently fail handler errors
        
        return event.event_id
    
    def on(self, event_type: str, handler: Callable[[ObservabilityEvent], None]):
        """Register an event handler."""
        with self._lock:
            self._handlers[event_type].append(handler)
    
    def get_recent_events(self, limit: int = 100) -> List[ObservabilityEvent]:
        """Get recent events."""
        with self._lock:
            return list(self._events[-limit:])


# Global event emitter instance
_global_event_emitter = EventEmitter()


def get_global_event_emitter() -> EventEmitter:
    """Get the global event emitter instance."""
    return _global_event_emitter


# -----------------------------------------------------------------------------
# Convenience Functions for Easy Integration
# -----------------------------------------------------------------------------
def count(name: str, value: float = 1.0, **labels):
    """Convenience function to increment a counter."""
    _global_metrics.increment_counter(name, value, labels)


def gauge(name: str, value: float, **labels):
    """Convenience function to set a gauge."""
    _global_metrics.set_gauge(name, value, labels)


def event(event_type: str, message: str = "", severity: str = "info", **kwargs):
    """Convenience function to emit an event."""
    _global_event_emitter.emit(event_type, message, severity, **kwargs)


def log_info(message: str, **kwargs):
    """Convenience function to log info."""
    StructuredLogger().info(message, **kwargs)


def log_warning(message: str, **kwargs):
    """Convenience function to log warning."""
    StructuredLogger().warning(message, **kwargs)


def log_error(message: str, **kwargs):
    """Convenience function to log error."""
    StructuredLogger().error(message, **kwargs)


# -----------------------------------------------------------------------------
# Module Metadata
# -----------------------------------------------------------------------------
OBSERVABILITY_VERSION = "16.0.0"
OBSERVABILITY_API_STABILITY = "stable"
OBSERVABILITY_DOCUMENTATION = """
Comprehensive Observability & Instrumentation Framework v16

ALL FEATURES ARE DISABLED BY DEFAULT.
To enable, call: ObservabilityConfig().enable_all()
Or set environment variable: NEURALSHIELD_OBSERVABILITY_ENABLE_ALL=1

Features:
1. StructuredLogger - JSON structured logging
2. MetricsCollector - counters, gauges, timers, histograms
3. HealthChecker - pluggable health check framework
4. Tracer - distributed tracing with context propagation
5. EventEmitter - event emission with handler support

Decorators:
- @timed() - time function execution
- @traced() - trace function execution

Context Managers:
- timer_context() - time code blocks

All instrumentation is completely OPT-IN and has zero overhead when disabled.
"""


def get_observability_status() -> Dict[str, Any]:
    """Get current observability status summary."""
    config = ObservabilityConfig()
    return {
        "version": OBSERVABILITY_VERSION,
        "api_stability": OBSERVABILITY_API_STABILITY,
        "enabled_features": {
            "logging": config.LOGGING_ENABLED,
            "metrics": config.METRICS_ENABLED,
            "health_checks": config.HEALTH_CHECKS_ENABLED,
            "tracing": config.TRACING_ENABLED,
            "profiling": config.PROFILING_ENABLED,
            "events": config.EVENTS_ENABLED
        },
        "metrics": _global_metrics.get_all_metrics(),
        "health_status": _global_health_checker.get_overall_status().value,
        "span_count": len(_global_tracer.get_all_spans()),
        "event_count": len(_global_event_emitter.get_recent_events())
    }
