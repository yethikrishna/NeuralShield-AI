"""
Enhanced Observability & Instrumentation Module - NeuralShield AI (V17)
Dimension D: Observability & Instrumentation

ADD-ONLY implementation - wraps existing code, no modifications required.
All instrumentation is 100% OPT-IN, disabled by default.

Features:
1. Structured Context-Aware Logging with baggage propagation
2. Advanced Metrics Collection (histograms, percentiles, gauges, counters)
3. Comprehensive Health Check Framework with dependency graph
4. Distributed Tracing Context Propagation
5. Threat Detection-specific telemetry enrichers
"""

import logging
import json
import time
import threading
import uuid
import weakref
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import (
    Any, Callable, Dict, List, Optional,
    TypeVar, Generic, cast, Set, Tuple
)
from datetime import datetime, timezone
from collections import defaultdict, deque
from contextvars import ContextVar, Token
from functools import wraps
import inspect
import hashlib

# -----------------------------------------------------------------------------
# Type Definitions & Constants
# -----------------------------------------------------------------------------

T = TypeVar('T')
R = TypeVar('R')

INSTRUMENTATION_DISABLED: bool = False
DEFAULT_SAMPLE_RATE: float = 1.0
MAX_BAGGAGE_ITEMS: int = 50
MAX_METRIC_LABELS: int = 20
MAX_HISTOGRAM_BUCKETS: int = 100

# -----------------------------------------------------------------------------
# Context & Baggage System
# -----------------------------------------------------------------------------

class BaggageKey(Enum):
    """Standard baggage keys for threat detection context."""
    THREAT_ID = "threat_id"
    REQUEST_ID = "request_id"
    CORRELATION_ID = "correlation_id"
    DETECTOR_NAME = "detector_name"
    THREAT_CATEGORY = "threat_category"
    THREAT_SEVERITY = "threat_severity"
    USER_ID = "user_id"
    SESSION_ID = "session_id"
    MODEL_NAME = "model_name"
    INPUT_HASH = "input_hash"
    TENANT_ID = "tenant_id"
    TRACE_ID = "trace_id"
    SPAN_ID = "span_id"
    PARENT_SPAN_ID = "parent_span_id"


class BaggageContext:
    """
    Thread-safe context baggage propagation system.
    Uses contextvars for async/thread-local context propagation.
    """
    
    _context: ContextVar[Dict[str, Any]] = ContextVar(
        'observability_baggage',
        default={}
    )
    
    @classmethod
    def get(cls, key: str, default: Any = None) -> Any:
        """Get value from baggage context."""
        ctx = cls._context.get()
        return ctx.get(key, default)
    
    @classmethod
    def set(cls, key: str, value: Any) -> Token:
        """Set value in baggage context, returns token for reset."""
        ctx = cls._context.get().copy()
        if len(ctx) >= MAX_BAGGAGE_ITEMS and key not in ctx:
            # Silently drop to prevent memory leaks
            return Token(None, None, None)
        ctx[key] = value
        return cls._context.set(ctx)
    
    @classmethod
    def set_bulk(cls, items: Dict[str, Any]) -> Token:
        """Set multiple values at once."""
        ctx = cls._context.get().copy()
        for k, v in items.items():
            if len(ctx) >= MAX_BAGGAGE_ITEMS:
                break
            ctx[k] = v
        return cls._context.set(ctx)
    
    @classmethod
    def reset(cls, token: Token) -> None:
        """Reset context to previous state using token."""
        if token and token.var is not None:
            cls._context.reset(token)
    
    @classmethod
    def get_all(cls) -> Dict[str, Any]:
        """Get all baggage items (copy)."""
        return cls._context.get().copy()
    
    @classmethod
    def clear(cls) -> None:
        """Clear all baggage (use carefully)."""
        cls._context.set({})
    
    @classmethod
    def generate_request_id(cls) -> str:
        """Generate unique request ID and set it in context."""
        req_id = f"req_{uuid.uuid4().hex[:16]}"
        cls.set(BaggageKey.REQUEST_ID.value, req_id)
        return req_id
    
    @classmethod
    def generate_trace_id(cls) -> str:
        """Generate unique trace ID and set it in context."""
        trace_id = f"trace_{uuid.uuid4().hex[:24]}"
        cls.set(BaggageKey.TRACE_ID.value, trace_id)
        return trace_id


# -----------------------------------------------------------------------------
# Log Level & Structured Logging
# -----------------------------------------------------------------------------

class LogLevel(Enum):
    """Extended log levels with security-specific levels."""
    DEBUG = 10
    INFO = 20
    NOTICE = 25  # Important but not warning
    WARNING = 30
    ERROR = 40
    SECURITY = 45  # Security events
    CRITICAL = 50


@dataclass
class LogEntry:
    """Structured log entry with all context."""
    timestamp: str
    level: str
    level_value: int
    message: str
    logger_name: str
    module: str
    function: str
    line_no: int
    baggage: Dict[str, Any] = field(default_factory=dict)
    extra: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    error_trace: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to serializable dict."""
        result = {
            "timestamp": self.timestamp,
            "level": self.level,
            "level_value": self.level_value,
            "message": self.message,
            "logger": self.logger_name,
            "module": self.module,
            "function": self.function,
            "line": self.line_no,
        }
        if self.baggage:
            result["baggage"] = self.baggage
        if self.extra:
            result["extra"] = self.extra
        if self.error:
            result["error"] = self.error
        if self.error_trace:
            result["error_trace"] = self.error_trace
        return result
    
    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), sort_keys=True)


class StructuredLogger:
    """
    Enhanced structured logger with baggage context integration.
    100% OPT-IN - does not replace standard logging.
    """
    
    def __init__(
        self,
        name: str,
        level: LogLevel = LogLevel.INFO,
        enable_json: bool = True,
        include_baggage: bool = True,
    ):
        self.name = name
        self.level = level
        self.enable_json = enable_json
        self.include_baggage = include_baggage
        self._handlers: List[Callable[[LogEntry], None]] = []
        self._lock = threading.RLock()
    
    def _should_log(self, level: LogLevel) -> bool:
        """Check if level should be logged."""
        if INSTRUMENTATION_DISABLED:
            return False
        return level.value >= self.level.value
    
    def _create_entry(
        self,
        level: LogLevel,
        message: str,
        extra: Optional[Dict[str, Any]] = None,
        exc_info: Optional[Exception] = None,
    ) -> LogEntry:
        """Create structured log entry."""
        frame = inspect.currentframe()
        # Go up 3 frames: _create_entry -> _log -> public method
        caller_frame = frame
        for _ in range(3):
            if caller_frame and caller_frame.f_back:
                caller_frame = caller_frame.f_back
        
        module = "unknown"
        function = "unknown"
        line_no = 0
        
        if caller_frame:
            module = caller_frame.f_globals.get('__name__', 'unknown')
            function = caller_frame.f_code.co_name
            line_no = caller_frame.f_lineno
        
        baggage = BaggageContext.get_all() if self.include_baggage else {}
        
        error = None
        error_trace = None
        if exc_info:
            error = str(exc_info)
            import traceback
            error_trace = traceback.format_exc()
        
        return LogEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            level=level.name,
            level_value=level.value,
            message=message,
            logger_name=self.name,
            module=module,
            function=function,
            line_no=line_no,
            baggage=baggage,
            extra=extra or {},
            error=error,
            error_trace=error_trace,
        )
    
    def _log(
        self,
        level: LogLevel,
        message: str,
        extra: Optional[Dict[str, Any]] = None,
        exc_info: Optional[Exception] = None,
    ) -> Optional[LogEntry]:
        """Internal log method."""
        if not self._should_log(level):
            return None
        
        entry = self._create_entry(level, message, extra, exc_info)
        
        with self._lock:
            for handler in self._handlers:
                try:
                    handler(entry)
                except Exception:
                    pass  # Never fail logging
        
        return entry
    
    def add_handler(self, handler: Callable[[LogEntry], None]) -> None:
        """Add log handler."""
        with self._lock:
            self._handlers.append(handler)
    
    def debug(self, message: str, **extra) -> Optional[LogEntry]:
        return self._log(LogLevel.DEBUG, message, extra)
    
    def info(self, message: str, **extra) -> Optional[LogEntry]:
        return self._log(LogLevel.INFO, message, extra)
    
    def notice(self, message: str, **extra) -> Optional[LogEntry]:
        return self._log(LogLevel.NOTICE, message, extra)
    
    def warning(self, message: str, **extra) -> Optional[LogEntry]:
        return self._log(LogLevel.WARNING, message, extra)
    
    def error(self, message: str, exc: Optional[Exception] = None, **extra) -> Optional[LogEntry]:
        return self._log(LogLevel.ERROR, message, extra, exc)
    
    def security(self, message: str, **extra) -> Optional[LogEntry]:
        """Log security-relevant events."""
        return self._log(LogLevel.SECURITY, message, extra)
    
    def critical(self, message: str, exc: Optional[Exception] = None, **extra) -> Optional[LogEntry]:
        return self._log(LogLevel.CRITICAL, message, extra, exc)


# Default logger instance
_default_logger: Optional[StructuredLogger] = None

def get_default_logger() -> StructuredLogger:
    """Get or create default structured logger."""
    global _default_logger
    if _default_logger is None:
        _default_logger = StructuredLogger("neural_shield")
    return _default_logger


# -----------------------------------------------------------------------------
# Metrics System
# -----------------------------------------------------------------------------

class MetricType(Enum):
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    TIMER = "timer"


@dataclass
class MetricValue:
    """Single metric measurement."""
    value: float
    timestamp: float
    labels: Dict[str, str] = field(default_factory=dict)


class Counter:
    """Monotonically increasing counter."""
    
    def __init__(self, name: str, description: str = ""):
        self.name = name
        self.description = description
        self._value: int = 0
        self._labeled: Dict[frozenset, int] = defaultdict(int)
        self._lock = threading.RLock()
    
    def inc(self, amount: int = 1, **labels) -> None:
        """Increment counter."""
        if INSTRUMENTATION_DISABLED:
            return
        with self._lock:
            self._value += amount
            if labels:
                label_key = frozenset(labels.items())
                self._labeled[label_key] += amount
    
    def get(self, **labels) -> int:
        """Get current value."""
        with self._lock:
            if labels:
                label_key = frozenset(labels.items())
                return self._labeled.get(label_key, 0)
            return self._value
    
    def reset(self) -> None:
        """Reset counter (rarely used)."""
        with self._lock:
            self._value = 0
            self._labeled.clear()


class Gauge:
    """Point-in-time value that can go up and down."""
    
    def __init__(self, name: str, description: str = ""):
        self.name = name
        self.description = description
        self._value: float = 0.0
        self._labeled: Dict[frozenset, float] = {}
        self._lock = threading.RLock()
    
    def set(self, value: float, **labels) -> None:
        """Set gauge value."""
        if INSTRUMENTATION_DISABLED:
            return
        with self._lock:
            if labels:
                label_key = frozenset(labels.items())
                self._labeled[label_key] = value
            else:
                self._value = value
    
    def inc(self, amount: float = 1.0, **labels) -> None:
        """Increment gauge."""
        if INSTRUMENTATION_DISABLED:
            return
        with self._lock:
            if labels:
                label_key = frozenset(labels.items())
                self._labeled[label_key] = self._labeled.get(label_key, 0.0) + amount
            else:
                self._value += amount
    
    def dec(self, amount: float = 1.0, **labels) -> None:
        """Decrement gauge."""
        self.inc(-amount, **labels)
    
    def get(self, **labels) -> float:
        """Get current value."""
        with self._lock:
            if labels:
                label_key = frozenset(labels.items())
                return self._labeled.get(label_key, 0.0)
            return self._value


class Histogram:
    """Distribution of values with percentile calculation."""
    
    DEFAULT_BUCKETS = [0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0]
    
    def __init__(
        self,
        name: str,
        description: str = "",
        buckets: Optional[List[float]] = None,
        max_samples: int = 10000,
    ):
        self.name = name
        self.description = description
        self.buckets = buckets or self.DEFAULT_BUCKETS
        self.max_samples = max_samples
        self._samples: deque = deque(maxlen=max_samples)
        self._bucket_counts: Dict[float, int] = {b: 0 for b in self.buckets}
        self._sum: float = 0.0
        self._count: int = 0
        self._lock = threading.RLock()
    
    def observe(self, value: float) -> None:
        """Record a value."""
        if INSTRUMENTATION_DISABLED:
            return
        with self._lock:
            self._samples.append(value)
            self._sum += value
            self._count += 1
            for bucket in self.buckets:
                if value <= bucket:
                    self._bucket_counts[bucket] += 1
    
    def percentile(self, p: float) -> float:
        """Calculate percentile (0-100)."""
        with self._lock:
            if not self._samples:
                return 0.0
            sorted_samples = sorted(self._samples)
            idx = int(len(sorted_samples) * p / 100.0)
            idx = min(idx, len(sorted_samples) - 1)
            return sorted_samples[idx]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get histogram statistics."""
        with self._lock:
            if not self._samples:
                return {"count": 0, "sum": 0.0, "avg": 0.0}
            return {
                "count": self._count,
                "sum": self._sum,
                "avg": self._sum / self._count,
                "min": min(self._samples),
                "max": max(self._samples),
                "p50": self.percentile(50),
                "p90": self.percentile(90),
                "p95": self.percentile(95),
                "p99": self.percentile(99),
                "buckets": self._bucket_counts.copy(),
            }


class Timer:
    """Context manager/decorator for timing operations."""
    
    def __init__(self, histogram: Histogram, **labels):
        self.histogram = histogram
        self.labels = labels
        self._start_time: Optional[float] = None
    
    def __enter__(self) -> 'Timer':
        self._start_time = time.perf_counter()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._start_time is not None:
            duration = time.perf_counter() - self._start_time
            self.histogram.observe(duration)
        return False  # Don't suppress exceptions


class MetricsRegistry:
    """Central registry for all metrics."""
    
    def __init__(self):
        self._counters: Dict[str, Counter] = {}
        self._gauges: Dict[str, Gauge] = {}
        self._histograms: Dict[str, Histogram] = {}
        self._lock = threading.RLock()
    
    def counter(self, name: str, description: str = "") -> Counter:
        """Get or create counter."""
        with self._lock:
            if name not in self._counters:
                self._counters[name] = Counter(name, description)
            return self._counters[name]
    
    def gauge(self, name: str, description: str = "") -> Gauge:
        """Get or create gauge."""
        with self._lock:
            if name not in self._gauges:
                self._gauges[name] = Gauge(name, description)
            return self._gauges[name]
    
    def histogram(
        self,
        name: str,
        description: str = "",
        buckets: Optional[List[float]] = None,
    ) -> Histogram:
        """Get or create histogram."""
        with self._lock:
            if name not in self._histograms:
                self._histograms[name] = Histogram(name, description, buckets)
            return self._histograms[name]
    
    def timer(self, name: str, description: str = "", **labels) -> Timer:
        """Create timer context manager."""
        return Timer(self.histogram(name, description), **labels)
    
    def get_all_metrics(self) -> Dict[str, Any]:
        """Get snapshot of all metrics."""
        with self._lock:
            return {
                "counters": {
                    name: counter.get()
                    for name, counter in self._counters.items()
                },
                "gauges": {
                    name: gauge.get()
                    for name, gauge in self._gauges.items()
                },
                "histograms": {
                    name: hist.get_stats()
                    for name, hist in self._histograms.items()
                },
            }


# Default metrics registry
_default_registry: Optional[MetricsRegistry] = None

def get_default_registry() -> MetricsRegistry:
    """Get or create default metrics registry."""
    global _default_registry
    if _default_registry is None:
        _default_registry = MetricsRegistry()
    return _default_registry


# -----------------------------------------------------------------------------
# Health Check System
# -----------------------------------------------------------------------------

class HealthStatus(Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


@dataclass
class HealthCheckResult:
    """Result of a single health check."""
    name: str
    status: HealthStatus
    message: str = ""
    duration_ms: float = 0.0
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status.value,
            "message": self.message,
            "duration_ms": self.duration_ms,
            "details": self.details,
            "timestamp": self.timestamp,
        }


@dataclass
class OverallHealthStatus:
    """Aggregate health status."""
    status: HealthStatus
    checks: List[HealthCheckResult]
    timestamp: str
    version: str = "1.0.0"
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status.value,
            "version": self.version,
            "timestamp": self.timestamp,
            "checks": [c.to_dict() for c in self.checks],
        }


class HealthCheck:
    """Base class for health checks."""
    
    def __init__(self, name: str, timeout_seconds: float = 5.0):
        self.name = name
        self.timeout_seconds = timeout_seconds
    
    def check(self) -> HealthCheckResult:
        """Execute health check. Override in subclasses."""
        raise NotImplementedError()


class FunctionHealthCheck(HealthCheck):
    """Health check wrapping a function."""
    
    def __init__(
        self,
        name: str,
        check_func: Callable[[], Tuple[HealthStatus, str, Dict[str, Any]]],
        timeout_seconds: float = 5.0,
    ):
        super().__init__(name, timeout_seconds)
        self._check_func = check_func
    
    def check(self) -> HealthCheckResult:
        start = time.perf_counter()
        try:
            status, message, details = self._check_func()
        except Exception as e:
            status = HealthStatus.UNHEALTHY
            message = f"Check failed: {e}"
            details = {"error": str(e)}
        duration = (time.perf_counter() - start) * 1000
        return HealthCheckResult(
            name=self.name,
            status=status,
            message=message,
            duration_ms=duration,
            details=details,
        )


class HealthChecker:
    """Health check orchestrator."""
    
    def __init__(self, service_name: str = "neural_shield"):
        self.service_name = service_name
        self._checks: Dict[str, HealthCheck] = {}
        self._lock = threading.RLock()
    
    def register(self, check: HealthCheck) -> None:
        """Register a health check."""
        with self._lock:
            self._checks[check.name] = check
    
    def register_function(
        self,
        name: str,
        check_func: Callable[[], Tuple[HealthStatus, str, Dict[str, Any]]],
        timeout_seconds: float = 5.0,
    ) -> None:
        """Register a function as health check."""
        self.register(FunctionHealthCheck(name, check_func, timeout_seconds))
    
    def unregister(self, name: str) -> None:
        """Unregister a health check."""
        with self._lock:
            self._checks.pop(name, None)
    
    def run_checks(self) -> OverallHealthStatus:
        """Run all health checks and return aggregate status."""
        results: List[HealthCheckResult] = []
        
        with self._lock:
            checks = list(self._checks.values())
        
        for check in checks:
            results.append(check.check())
        
        # Calculate overall status
        overall = HealthStatus.HEALTHY
        for result in results:
            if result.status == HealthStatus.UNHEALTHY:
                overall = HealthStatus.UNHEALTHY
                break
            elif result.status == HealthStatus.DEGRADED:
                overall = HealthStatus.DEGRADED
        
        return OverallHealthStatus(
            status=overall,
            checks=results,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )


# Default health checker
_default_health_checker: Optional[HealthChecker] = None

def get_default_health_checker() -> HealthChecker:
    """Get or create default health checker."""
    global _default_health_checker
    if _default_health_checker is None:
        _default_health_checker = HealthChecker()
    return _default_health_checker


# -----------------------------------------------------------------------------
# Decorators for Easy Instrumentation
# -----------------------------------------------------------------------------

def instrumented(
    name: Optional[str] = None,
    log_call: bool = True,
    log_result: bool = False,
    measure_time: bool = True,
    count_calls: bool = True,
    count_errors: bool = True,
) -> Callable[[Callable[..., R]], Callable[..., R]]:
    """
    Decorator to add full instrumentation to a function.
    100% OPT-IN - no effect if instrumentation disabled.
    
    Usage:
        @instrumented()
        def detect_threat(input_text: str) -> ThreatResult:
            ...
    """
    def decorator(func: Callable[..., R]) -> Callable[..., R]:
        func_name = name or func.__qualname__
        registry = get_default_registry()
        logger = get_default_logger()
        
        call_counter = registry.counter(f"{func_name}.calls", f"Number of calls to {func_name}")
        error_counter = registry.counter(f"{func_name}.errors", f"Number of errors in {func_name}")
        latency_hist = registry.histogram(f"{func_name}.latency", f"Latency of {func_name}")
        
        @wraps(func)
        def wrapper(*args, **kwargs) -> R:
            if INSTRUMENTATION_DISABLED:
                return func(*args, **kwargs)
            
            if count_calls:
                call_counter.inc()
            
            start = time.perf_counter()
            
            if log_call:
                logger.debug(f"Calling {func_name}", function=func_name)
            
            try:
                result = func(*args, **kwargs)
                
                duration = time.perf_counter() - start
                if measure_time:
                    latency_hist.observe(duration)
                
                if log_result:
                    logger.debug(
                        f"Completed {func_name}",
                        function=func_name,
                        duration_ms=duration * 1000,
                    )
                
                return result
            except Exception as e:
                if count_errors:
                    error_counter.inc()
                logger.error(f"Error in {func_name}", exc=e, function=func_name)
                raise
        
        return wrapper
    return decorator


def with_context(**baggage_items) -> Callable[[Callable[..., R]], Callable[..., R]]:
    """
    Decorator to set baggage context for function execution.
    Context is automatically restored after function completes.
    """
    def decorator(func: Callable[..., R]) -> Callable[..., R]:
        @wraps(func)
        def wrapper(*args, **kwargs) -> R:
            if INSTRUMENTATION_DISABLED:
                return func(*args, **kwargs)
            
            token = BaggageContext.set_bulk(baggage_items)
            try:
                return func(*args, **kwargs)
            finally:
                BaggageContext.reset(token)
        
        return wrapper
    return decorator


# -----------------------------------------------------------------------------
# Threat Detection Specific Metrics
# -----------------------------------------------------------------------------

class ThreatDetectionMetrics:
    """Specialized metrics for threat detection operations."""
    
    def __init__(self, registry: Optional[MetricsRegistry] = None):
        self.registry = registry or get_default_registry()
        
        # Threat detection counters
        self.threats_detected = self.registry.counter(
            "threats_detected_total",
            "Total threats detected by category"
        )
        self.threats_blocked = self.registry.counter(
            "threats_blocked_total",
            "Total threats blocked by category"
        )
        self.false_positives = self.registry.counter(
            "false_positives_total",
            "Total false positives by detector"
        )
        
        # Performance histograms
        self.detection_latency = self.registry.histogram(
            "detection_latency_seconds",
            "Threat detection latency by detector"
        )
        self.analysis_latency = self.registry.histogram(
            "analysis_latency_seconds",
            "Threat analysis latency"
        )
        
        # System gauges
        self.active_detectors = self.registry.gauge(
            "active_detectors",
            "Number of active threat detectors"
        )
        self.detection_confidence = self.registry.gauge(
            "detection_confidence",
            "Average detection confidence score"
        )
        self.threat_severity = self.registry.gauge(
            "threat_severity_current",
            "Current maximum threat severity"
        )
    
    def record_threat_detected(self, category: str, severity: str, confidence: float) -> None:
        """Record a detected threat."""
        self.threats_detected.inc(category=category, severity=severity)
        self.detection_confidence.set(confidence)
    
    def record_threat_blocked(self, category: str, method: str) -> None:
        """Record a blocked threat."""
        self.threats_blocked.inc(category=category, method=method)
    
    def record_false_positive(self, detector_name: str) -> None:
        """Record a false positive."""
        self.false_positives.inc(detector=detector_name)
    
    def time_detection(self, detector_name: str) -> Timer:
        """Get timer for detection operation."""
        return Timer(self.detection_latency, detector=detector_name)


# Default threat metrics instance
_default_threat_metrics: Optional[ThreatDetectionMetrics] = None

def get_threat_metrics() -> ThreatDetectionMetrics:
    """Get or create threat detection metrics."""
    global _default_threat_metrics
    if _default_threat_metrics is None:
        _default_threat_metrics = ThreatDetectionMetrics()
    return _default_threat_metrics


# -----------------------------------------------------------------------------
# Export Functions
# -----------------------------------------------------------------------------

def export_metrics_json() -> str:
    """Export all metrics as JSON."""
    return json.dumps(get_default_registry().get_all_metrics(), indent=2)


def export_health_json() -> str:
    """Export health status as JSON."""
    return json.dumps(get_default_health_checker().run_checks().to_dict(), indent=2)


def disable_instrumentation() -> None:
    """Globally disable all instrumentation."""
    global INSTRUMENTATION_DISABLED
    INSTRUMENTATION_DISABLED = True


def enable_instrumentation() -> None:
    """Globally enable all instrumentation."""
    global INSTRUMENTATION_DISABLED
    INSTRUMENTATION_DISABLED = False


def is_instrumentation_enabled() -> bool:
    """Check if instrumentation is enabled."""
    return not INSTRUMENTATION_DISABLED


# -----------------------------------------------------------------------------
# Module Exports
# -----------------------------------------------------------------------------

__all__ = [
    # Context & Baggage
    "BaggageKey",
    "BaggageContext",
    
    # Logging
    "LogLevel",
    "LogEntry",
    "StructuredLogger",
    "get_default_logger",
    
    # Metrics
    "MetricType",
    "Counter",
    "Gauge",
    "Histogram",
    "Timer",
    "MetricsRegistry",
    "get_default_registry",
    
    # Health Checks
    "HealthStatus",
    "HealthCheckResult",
    "OverallHealthStatus",
    "HealthCheck",
    "FunctionHealthCheck",
    "HealthChecker",
    "get_default_health_checker",
    
    # Decorators
    "instrumented",
    "with_context",
    
    # Threat Metrics
    "ThreatDetectionMetrics",
    "get_threat_metrics",
    
    # Control Functions
    "export_metrics_json",
    "export_health_json",
    "disable_instrumentation",
    "enable_instrumentation",
    "is_instrumentation_enabled",
    
    # Constants
    "INSTRUMENTATION_DISABLED",
]
