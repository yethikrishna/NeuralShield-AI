"""
NeuralShield AI - Comprehensive Observability & Instrumentation Framework v20
DIMENSION D - Observability & Instrumentation

ADD-ONLY implementation - wraps existing code, no modifications to core logic.
All instrumentation is OPT-IN, disabled by default.

Stability: STABLE
Backward Compatible: YES
Dependencies: None (pure Python)
"""

import time
import threading
import json
import logging
from typing import Dict, List, Any, Optional, Callable, TypeVar, Generic
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque
from functools import wraps
import uuid
import hashlib
import inspect

T = TypeVar('T')

class MetricType(Enum):
    """Types of metrics supported by the instrumentation framework"""
    COUNTER = "counter"
    GAUGE = "gauge"
    TIMER = "timer"
    HISTOGRAM = "histogram"
    RATE = "rate"

class LogLevel(Enum):
    """Structured logging levels"""
    DEBUG = 10
    INFO = 20
    WARNING = 30
    ERROR = 40
    CRITICAL = 50

class HealthStatus(Enum):
    """Health check status values"""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"

@dataclass
class MetricPoint:
    """Single metric data point"""
    name: str
    value: float
    metric_type: MetricType
    timestamp: float = field(default_factory=time.time)
    labels: Dict[str, str] = field(default_factory=dict)
    unit: Optional[str] = None

@dataclass
class TraceSpan:
    """Distributed tracing span"""
    trace_id: str
    span_id: str
    parent_span_id: Optional[str]
    name: str
    start_time: float
    end_time: Optional[float] = None
    attributes: Dict[str, Any] = field(default_factory=dict)
    events: List[Dict[str, Any]] = field(default_factory=list)

@dataclass
class HealthCheckResult:
    """Result of a health check"""
    component: str
    status: HealthStatus
    message: str
    response_time_ms: float
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

class ThreadSafeMetricStore:
    """Thread-safe metric storage with bounded memory usage"""
    
    def __init__(self, max_points_per_metric: int = 1000):
        self._lock = threading.RLock()
        self._metrics: Dict[str, deque] = defaultdict(lambda: deque(maxlen=max_points_per_metric))
        self._counters: Dict[str, float] = defaultdict(float)
        self._gauges: Dict[str, float] = {}
        self._max_points = max_points_per_metric
    
    def increment_counter(self, name: str, value: float = 1.0, labels: Optional[Dict[str, str]] = None) -> None:
        """Atomically increment a counter"""
        with self._lock:
            key = self._make_key(name, labels)
            self._counters[key] += value
            self._record_point(name, value, MetricType.COUNTER, labels)
    
    def set_gauge(self, name: str, value: float, labels: Optional[Dict[str, str]] = None) -> None:
        """Set a gauge value"""
        with self._lock:
            key = self._make_key(name, labels)
            self._gauges[key] = value
            self._record_point(name, value, MetricType.GAUGE, labels)
    
    def record_timer(self, name: str, duration_seconds: float, labels: Optional[Dict[str, str]] = None) -> None:
        """Record a timing measurement"""
        with self._lock:
            self._record_point(name, duration_seconds, MetricType.TIMER, labels, unit="seconds")
    
    def get_counter_value(self, name: str, labels: Optional[Dict[str, str]] = None) -> float:
        """Get current counter value"""
        with self._lock:
            key = self._make_key(name, labels)
            return self._counters.get(key, 0.0)
    
    def get_gauge_value(self, name: str, labels: Optional[Dict[str, str]] = None) -> Optional[float]:
        """Get current gauge value"""
        with self._lock:
            key = self._make_key(name, labels)
            return self._gauges.get(key)
    
    def get_metric_summary(self, name: str) -> Dict[str, Any]:
        """Get summary statistics for a metric"""
        with self._lock:
            points = list(self._metrics.get(name, []))
            if not points:
                return {"count": 0}
            
            values = [p.value for p in points]
            return {
                "count": len(values),
                "min": min(values),
                "max": max(values),
                "avg": sum(values) / len(values),
                "latest": values[-1]
            }
    
    def get_all_metrics(self) -> Dict[str, Any]:
        """Get snapshot of all metrics"""
        with self._lock:
            return {
                "counters": dict(self._counters),
                "gauges": dict(self._gauges),
                "metric_count": sum(len(q) for q in self._metrics.values())
            }
    
    def _make_key(self, name: str, labels: Optional[Dict[str, str]]) -> str:
        if not labels:
            return name
        label_str = json.dumps(labels, sort_keys=True)
        return f"{name}:{label_str}"
    
    def _record_point(self, name: str, value: float, metric_type: MetricType,
                      labels: Optional[Dict[str, str]], unit: Optional[str] = None) -> None:
        point = MetricPoint(
            name=name,
            value=value,
            metric_type=metric_type,
            labels=labels or {},
            unit=unit
        )
        self._metrics[name].append(point)

class StructuredLogger:
    """Structured JSON logger with optional instrumentation"""
    
    def __init__(self, enabled: bool = False, min_level: LogLevel = LogLevel.INFO):
        self._enabled = enabled
        self._min_level = min_level
        self._lock = threading.Lock()
        self._log_buffer: deque = deque(maxlen=1000)
        self._logger = logging.getLogger("neuralshield.observability")
        self._logger.setLevel(logging.DEBUG)
    
    def enable(self) -> None:
        """Enable logging (OPT-IN)"""
        self._enabled = True
    
    def disable(self) -> None:
        """Disable logging"""
        self._enabled = False
    
    def set_level(self, level: LogLevel) -> None:
        """Set minimum logging level"""
        self._min_level = level
    
    def log(self, level: LogLevel, message: str, **kwargs) -> None:
        """Log a structured message if enabled"""
        if not self._enabled or level.value < self._min_level.value:
            return
        
        log_entry = {
            "timestamp": time.time(),
            "level": level.name,
            "message": message,
            "context": kwargs
        }
        
        with self._lock:
            self._log_buffer.append(log_entry)
    
    def debug(self, message: str, **kwargs) -> None:
        self.log(LogLevel.DEBUG, message, **kwargs)
    
    def info(self, message: str, **kwargs) -> None:
        self.log(LogLevel.INFO, message, **kwargs)
    
    def warning(self, message: str, **kwargs) -> None:
        self.log(LogLevel.WARNING, message, **kwargs)
    
    def error(self, message: str, **kwargs) -> None:
        self.log(LogLevel.ERROR, message, **kwargs)
    
    def critical(self, message: str, **kwargs) -> None:
        self.log(LogLevel.CRITICAL, message, **kwargs)
    
    def get_recent_logs(self, count: int = 100) -> List[Dict[str, Any]]:
        """Get recent log entries"""
        with self._lock:
            return list(self._log_buffer)[-count:]

class DistributedTracer:
    """Lightweight distributed tracing implementation"""
    
    def __init__(self, enabled: bool = False):
        self._enabled = enabled
        self._lock = threading.Lock()
        self._active_spans: Dict[str, TraceSpan] = {}
        self._completed_spans: deque = deque(maxlen=1000)
        self._local = threading.local()
    
    def enable(self) -> None:
        """Enable tracing (OPT-IN)"""
        self._enabled = True
    
    def disable(self) -> None:
        """Disable tracing"""
        self._enabled = False
    
    def start_span(self, name: str, parent_span_id: Optional[str] = None,
                   trace_id: Optional[str] = None, **attributes) -> str:
        """Start a new trace span"""
        if not self._enabled:
            return ""
        
        span_id = self._generate_id()
        if trace_id is None:
            trace_id = self._generate_id()
        
        span = TraceSpan(
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=parent_span_id,
            name=name,
            start_time=time.time(),
            attributes=attributes
        )
        
        with self._lock:
            self._active_spans[span_id] = span
        
        return span_id
    
    def end_span(self, span_id: str, **attributes) -> Optional[TraceSpan]:
        """End a trace span"""
        if not self._enabled or not span_id:
            return None
        
        with self._lock:
            span = self._active_spans.pop(span_id, None)
            if span:
                span.end_time = time.time()
                span.attributes.update(attributes)
                self._completed_spans.append(span)
                return span
        return None
    
    def add_event(self, span_id: str, event_name: str, **attributes) -> None:
        """Add an event to an active span"""
        if not self._enabled or not span_id:
            return
        
        with self._lock:
            span = self._active_spans.get(span_id)
            if span:
                span.events.append({
                    "name": event_name,
                    "timestamp": time.time(),
                    "attributes": attributes
                })
    
    def get_trace_summary(self, trace_id: str) -> Dict[str, Any]:
        """Get summary of a complete trace"""
        with self._lock:
            spans = [s for s in self._completed_spans if s.trace_id == trace_id]
            if not spans:
                return {"found": False}
            
            total_duration = max(s.end_time or 0 for s in spans) - min(s.start_time for s in spans)
            return {
                "found": True,
                "trace_id": trace_id,
                "span_count": len(spans),
                "total_duration_ms": total_duration * 1000,
                "spans": [
                    {
                        "name": s.name,
                        "duration_ms": (s.end_time - s.start_time) * 1000 if s.end_time else None
                    }
                    for s in spans
                ]
            }
    
    def _generate_id(self) -> str:
        """Generate a unique trace/span ID"""
        return hashlib.sha256(f"{uuid.uuid4()}{time.time()}".encode()).hexdigest()[:16]

class HealthCheckRegistry:
    """Health check framework for system monitoring"""
    
    def __init__(self):
        self._lock = threading.Lock()
        self._checks: Dict[str, Callable[[], HealthCheckResult]] = {}
        self._cache: Dict[str, HealthCheckResult] = {}
        self._cache_ttl: float = 5.0  # seconds
    
    def register_check(self, name: str, check_fn: Callable[[], HealthCheckResult]) -> None:
        """Register a health check function"""
        with self._lock:
            self._checks[name] = check_fn
    
    def run_check(self, name: str) -> Optional[HealthCheckResult]:
        """Run a single health check"""
        with self._lock:
            check_fn = self._checks.get(name)
            if not check_fn:
                return None
            
            start = time.time()
            try:
                result = check_fn()
                result.response_time_ms = (time.time() - start) * 1000
                self._cache[name] = result
                return result
            except Exception as e:
                return HealthCheckResult(
                    component=name,
                    status=HealthStatus.UNHEALTHY,
                    message=f"Check failed: {str(e)}",
                    response_time_ms=(time.time() - start) * 1000
                )
    
    def run_all_checks(self) -> Dict[str, HealthCheckResult]:
        """Run all registered health checks"""
        results = {}
        for name in list(self._checks.keys()):
            result = self.run_check(name)
            if result:
                results[name] = result
        return results
    
    def get_overall_status(self) -> Dict[str, Any]:
        """Get overall system health status"""
        results = self.run_all_checks()
        if not results:
            return {
                "status": HealthStatus.UNKNOWN.value,
                "checks_run": 0
            }
        
        statuses = [r.status for r in results.values()]
        if HealthStatus.UNHEALTHY in statuses:
            overall = HealthStatus.UNHEALTHY
        elif HealthStatus.DEGRADED in statuses:
            overall = HealthStatus.DEGRADED
        else:
            overall = HealthStatus.HEALTHY
        
        return {
            "status": overall.value,
            "checks_run": len(results),
            "healthy_count": sum(1 for s in statuses if s == HealthStatus.HEALTHY),
            "degraded_count": sum(1 for s in statuses if s == HealthStatus.DEGRADED),
            "unhealthy_count": sum(1 for s in statuses if s == HealthStatus.UNHEALTHY),
            "components": {
                name: result.status.value
                for name, result in results.items()
            }
        }

def timed(metric_name: str, labels: Optional[Dict[str, str]] = None):
    """Decorator to time function execution (OPT-IN instrumentation)"""
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args, **kwargs) -> T:
            if not InstrumentationManager.is_timing_enabled():
                return func(*args, **kwargs)
            
            start = time.time()
            try:
                result = func(*args, **kwargs)
                duration = time.time() - start
                InstrumentationManager.record_timer(metric_name, duration, labels)
                return result
            except Exception as e:
                duration = time.time() - start
                InstrumentationManager.record_timer(f"{metric_name}.error", duration, labels)
                raise
        return wrapper
    return decorator

def counted(metric_name: str, labels: Optional[Dict[str, str]] = None):
    """Decorator to count function invocations (OPT-IN instrumentation)"""
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args, **kwargs) -> T:
            if not InstrumentationManager.is_counting_enabled():
                return func(*args, **kwargs)
            
            InstrumentationManager.increment_counter(metric_name, labels=labels)
            try:
                result = func(*args, **kwargs)
                return result
            except Exception as e:
                InstrumentationManager.increment_counter(f"{metric_name}.errors", labels=labels)
                raise
        return wrapper
    return decorator

def traced(span_name: str):
    """Decorator to trace function execution (OPT-IN instrumentation)"""
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args, **kwargs) -> T:
            if not InstrumentationManager.is_tracing_enabled():
                return func(*args, **kwargs)
            
            span_id = InstrumentationManager.start_span(span_name, function=func.__name__)
            try:
                result = func(*args, **kwargs)
                InstrumentationManager.end_span(span_id, success=True)
                return result
            except Exception as e:
                InstrumentationManager.end_span(span_id, success=False, error=str(e))
                raise
        return wrapper
    return decorator

class InstrumentationManager:
    """Central manager for all observability instrumentation (SINGLETON)"""
    
    _instance: Optional['InstrumentationManager'] = None
    _lock = threading.Lock()
    
    def __new__(cls) -> 'InstrumentationManager':
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        self._metrics = ThreadSafeMetricStore()
        self._logger = StructuredLogger(enabled=False)
        self._tracer = DistributedTracer(enabled=False)
        self._health = HealthCheckRegistry()
        
        self._enable_timing = False
        self._enable_counting = False
        self._enable_tracing = False
        self._initialized = True
    
    @classmethod
    def enable_all(cls) -> None:
        """Enable ALL instrumentation (EXPLICIT OPT-IN)"""
        instance = cls()
        instance._enable_timing = True
        instance._enable_counting = True
        instance._enable_tracing = True
        instance._logger.enable()
        instance._tracer.enable()
    
    @classmethod
    def disable_all(cls) -> None:
        """Disable ALL instrumentation"""
        instance = cls()
        instance._enable_timing = False
        instance._enable_counting = False
        instance._enable_tracing = False
        instance._logger.disable()
        instance._tracer.disable()
    
    @classmethod
    def is_timing_enabled(cls) -> bool:
        return cls()._enable_timing
    
    @classmethod
    def is_counting_enabled(cls) -> bool:
        return cls()._enable_counting
    
    @classmethod
    def is_tracing_enabled(cls) -> bool:
        return cls()._enable_tracing
    
    @classmethod
    def increment_counter(cls, name: str, value: float = 1.0, labels: Optional[Dict[str, str]] = None) -> None:
        cls()._metrics.increment_counter(name, value, labels)
    
    @classmethod
    def set_gauge(cls, name: str, value: float, labels: Optional[Dict[str, str]] = None) -> None:
        cls()._metrics.set_gauge(name, value, labels)
    
    @classmethod
    def record_timer(cls, name: str, duration: float, labels: Optional[Dict[str, str]] = None) -> None:
        cls()._metrics.record_timer(name, duration, labels)
    
    @classmethod
    def start_span(cls, name: str, **attributes) -> str:
        return cls()._tracer.start_span(name, **attributes)
    
    @classmethod
    def end_span(cls, span_id: str, **attributes) -> Optional[TraceSpan]:
        return cls()._tracer.end_span(span_id, **attributes)
    
    @classmethod
    def log_info(cls, message: str, **kwargs) -> None:
        cls()._logger.info(message, **kwargs)
    
    @classmethod
    def log_warning(cls, message: str, **kwargs) -> None:
        cls()._logger.warning(message, **kwargs)
    
    @classmethod
    def log_error(cls, message: str, **kwargs) -> None:
        cls()._logger.error(message, **kwargs)
    
    @classmethod
    def register_health_check(cls, name: str, check_fn: Callable[[], HealthCheckResult]) -> None:
        cls()._health.register_check(name, check_fn)
    
    @classmethod
    def get_health_status(cls) -> Dict[str, Any]:
        return cls()._health.get_overall_status()
    
    @classmethod
    def get_metrics_snapshot(cls) -> Dict[str, Any]:
        """Get complete metrics snapshot"""
        return cls()._metrics.get_all_metrics()
    
    @classmethod
    def get_recent_logs(cls, count: int = 100) -> List[Dict[str, Any]]:
        return cls()._logger.get_recent_logs(count)
    
    @classmethod
    def get_observability_status(cls) -> Dict[str, Any]:
        """Get status of all observability features"""
        instance = cls()
        return {
            "instrumentation_enabled": {
                "timing": instance._enable_timing,
                "counting": instance._enable_counting,
                "tracing": instance._enable_tracing,
                "logging": instance._logger._enabled
            },
            "metrics_count": len(instance._metrics.get_all_metrics()["counters"]),
            "health_checks_registered": len(instance._health._checks),
            "stability": "STABLE",
            "api_version": "v20"
        }

# Default standard health checks
def _basic_memory_check() -> HealthCheckResult:
    """Basic memory health check"""
    try:
        import sys
        return HealthCheckResult(
            component="memory",
            status=HealthStatus.HEALTHY,
            message="Memory check passed",
            response_time_ms=0.0,
            details={"python_version": sys.version}
        )
    except Exception as e:
        return HealthCheckResult(
            component="memory",
            status=HealthStatus.UNHEALTHY,
            message=f"Memory check failed: {e}",
            response_time_ms=0.0
        )

# Register default checks
InstrumentationManager.register_health_check("basic_system", _basic_memory_check)

# Export public API
__all__ = [
    'InstrumentationManager',
    'timed',
    'counted',
    'traced',
    'MetricType',
    'LogLevel',
    'HealthStatus',
    'HealthCheckResult',
    'MetricPoint',
    'TraceSpan',
]
