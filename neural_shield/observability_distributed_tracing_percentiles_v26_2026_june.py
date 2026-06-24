"""
NeuralShield AI - Observability & Instrumentation Module (Dimension D)
Version: v26 - June 2026
Philosophy: ADD-ONLY, OPT-IN, Backward Compatible, No breaking changes
This module extends v25 with:
1. Distributed tracing context propagation with baggage
2. Metrics percentiles calculation (P50, P95, P99)
3. Prometheus-style metrics exposition format
4. Correlation ID propagation across module boundaries
5. Adaptive event sampling for high-volume logs
6. Health check dependency graph with cascading status
7. All instrumentation is OPT-IN - existing code behavior 100% preserved
"""
import json
import time
import uuid
import math
import threading
from datetime import datetime
from typing import Dict, Any, Optional, Callable, List, Set, Tuple
from functools import wraps
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
import contextvars
import random
import inspect

# -----------------------------------------------------------------------------
# Core Enums and Data Classes
# -----------------------------------------------------------------------------
class LogLevel(Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class MetricType(Enum):
    COUNTER = "counter"
    GAUGE = "gauge"
    TIMER = "timer"
    HISTOGRAM = "histogram"


class HealthStatus(Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


class TracingFlags(Enum):
    SAMPLED = "01"
    NOT_SAMPLED = "00"


@dataclass
class Metric:
    name: str
    type: MetricType
    value: float = 0.0
    labels: Dict[str, str] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


@dataclass
class PercentileResult:
    p50: float
    p95: float
    p99: float
    min: float
    max: float
    avg: float
    count: int


@dataclass
class SpanContext:
    trace_id: str
    span_id: str
    parent_span_id: Optional[str] = None
    flags: str = TracingFlags.SAMPLED.value
    baggage: Dict[str, str] = field(default_factory=dict)


@dataclass
class HealthCheck:
    name: str
    status: HealthStatus
    message: str = ""
    duration_ms: float = 0.0
    details: Dict[str, Any] = field(default_factory=dict)
    dependencies: List[str] = field(default_factory=list)


@dataclass
class SamplingConfig:
    base_rate: float = 1.0  # 100% by default
    max_events_per_second: int = 1000
    adaptive_sampling: bool = True


# -----------------------------------------------------------------------------
# Context Variables for Distributed Tracing (Thread-Safe)
# -----------------------------------------------------------------------------
_current_span_context: contextvars.ContextVar[Optional[SpanContext]] = contextvars.ContextVar(
    "current_span_context",
    default=None
)

_correlation_id: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "correlation_id",
    default=None
)


# -----------------------------------------------------------------------------
# Global Configuration (ALL OPT-IN BY DEFAULT)
# -----------------------------------------------------------------------------
class ObservabilityConfig:
    """Global configuration for observability - ALL OPT-IN by default"""
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        # ALL FEATURES DISABLED BY DEFAULT - OPT-IN ONLY
        self.structured_logging_enabled: bool = False
        self.metrics_collection_enabled: bool = False
        self.health_checks_enabled: bool = False
        self.tracing_enabled: bool = False
        self.distributed_context_enabled: bool = False
        self.prometheus_exposition_enabled: bool = False
        self.correlation_id_propagation: bool = False
        self.min_log_level: LogLevel = LogLevel.INFO
        self.log_destination: str = "console"
        self.sampling_config: SamplingConfig = SamplingConfig()
        self._initialized = True
    
    def enable_all(self):
        """Enable all observability features - explicit opt-in"""
        self.structured_logging_enabled = True
        self.metrics_collection_enabled = True
        self.health_checks_enabled = True
        self.tracing_enabled = True
        self.distributed_context_enabled = True
        self.prometheus_exposition_enabled = True
        self.correlation_id_propagation = True
    
    def enable_structured_logging(self):
        self.structured_logging_enabled = True
    
    def enable_metrics(self):
        self.metrics_collection_enabled = True
    
    def enable_health_checks(self):
        self.health_checks_enabled = True
    
    def enable_tracing(self):
        self.tracing_enabled = True
        self.distributed_context_enabled = True
    
    def enable_prometheus(self):
        self.prometheus_exposition_enabled = True
    
    def enable_correlation_ids(self):
        self.correlation_id_propagation = True
    
    @classmethod
    def _reset_for_testing(cls):
        """Reset singleton for test isolation - FOR TESTING ONLY"""
        with cls._lock:
            cls._instance = None


# -----------------------------------------------------------------------------
# Percentile Histogram for Accurate Latency Measurement
# -----------------------------------------------------------------------------
class PercentileHistogram:
    """Thread-safe histogram with accurate percentile calculation"""
    
    def __init__(self, max_samples: int = 10000):
        self._samples: deque = deque(maxlen=max_samples)
        self._lock = threading.Lock()
        self._sum = 0.0
        self._count = 0
    
    def record(self, value: float):
        """Record a measurement"""
        with self._lock:
            self._samples.append(value)
            self._sum += value
            self._count += 1
    
    def get_percentiles(self) -> PercentileResult:
        """Calculate P50, P95, P99 percentiles"""
        with self._lock:
            if not self._samples:
                return PercentileResult(0, 0, 0, 0, 0, 0, 0)
            
            sorted_samples = sorted(self._samples)
            n = len(sorted_samples)
            
            def get_p(pct: float) -> float:
                idx = max(0, min(n - 1, int(math.ceil(n * pct / 100)) - 1))
                return sorted_samples[idx]
            
            return PercentileResult(
                p50=get_p(50),
                p95=get_p(95),
                p99=get_p(99),
                min=sorted_samples[0],
                max=sorted_samples[-1],
                avg=self._sum / self._count if self._count > 0 else 0,
                count=self._count
            )
    
    def reset(self):
        with self._lock:
            self._samples.clear()
            self._sum = 0.0
            self._count = 0


# -----------------------------------------------------------------------------
# Distributed Tracing Manager
# -----------------------------------------------------------------------------
class TracingManager:
    """Distributed tracing with W3C Trace Context propagation"""
    
    def __init__(self):
        self.config = ObservabilityConfig()
    
    def generate_trace_id(self) -> str:
        """Generate W3C compliant trace ID (16 hex bytes)"""
        return uuid.uuid4().hex
    
    def generate_span_id(self) -> str:
        """Generate W3C compliant span ID (8 hex bytes)"""
        return uuid.uuid4().hex[:16]
    
    def start_span(self, name: str, parent_context: Optional[SpanContext] = None) -> SpanContext:
        """Start a new span with optional parent"""
        if not self.config.tracing_enabled:
            return SpanContext(trace_id="", span_id="")
        
        if parent_context and parent_context.trace_id:
            trace_id = parent_context.trace_id
            parent_span_id = parent_context.span_id
        else:
            trace_id = self.generate_trace_id()
            parent_span_id = None
        
        span_context = SpanContext(
            trace_id=trace_id,
            span_id=self.generate_span_id(),
            parent_span_id=parent_span_id,
            baggage=parent_context.baggage.copy() if parent_context else {}
        )
        
        _current_span_context.set(span_context)
        return span_context
    
    def end_span(self, span_context: SpanContext):
        """End a span - no-op for now (metrics/logs capture actual data)"""
        pass
    
    def get_current_context(self) -> Optional[SpanContext]:
        """Get the current span context from context vars"""
        return _current_span_context.get()
    
    def inject_traceparent(self) -> str:
        """Inject W3C traceparent header format"""
        ctx = self.get_current_context()
        if not ctx or not ctx.trace_id:
            return ""
        return f"00-{ctx.trace_id}-{ctx.span_id}-{ctx.flags}"
    
    def extract_traceparent(self, traceparent: str) -> Optional[SpanContext]:
        """Extract W3C traceparent header format"""
        try:
            parts = traceparent.split("-")
            if len(parts) != 4:
                return None
            return SpanContext(
                trace_id=parts[1],
                span_id=parts[2],
                flags=parts[3]
            )
        except Exception:
            return None
    
    def set_baggage(self, key: str, value: str):
        """Set baggage item in current context"""
        ctx = self.get_current_context()
        if ctx:
            ctx.baggage[key] = value
    
    def get_baggage(self, key: str) -> Optional[str]:
        """Get baggage item from current context"""
        ctx = self.get_current_context()
        if ctx:
            return ctx.baggage.get(key)
        return None


# -----------------------------------------------------------------------------
# Correlation ID Manager
# -----------------------------------------------------------------------------
class CorrelationIdManager:
    """Correlation ID propagation across module boundaries"""
    
    def __init__(self):
        self.config = ObservabilityConfig()
    
    def generate(self) -> str:
        """Generate a new correlation ID"""
        return f"ns-cid-{uuid.uuid4().hex[:12]}"
    
    def set(self, cid: Optional[str] = None) -> str:
        """Set current correlation ID, generate if not provided"""
        if not self.config.correlation_id_propagation:
            return ""
        
        actual_cid = cid or self.generate()
        _correlation_id.set(actual_cid)
        return actual_cid
    
    def get(self) -> Optional[str]:
        """Get current correlation ID"""
        return _correlation_id.get()
    
    def clear(self):
        """Clear current correlation ID"""
        _correlation_id.set(None)


# -----------------------------------------------------------------------------
# Enhanced Metrics Collector with Percentiles
# -----------------------------------------------------------------------------
class MetricsCollector:
    """Thread-safe metrics collector with percentiles and Prometheus export"""
    
    def __init__(self):
        self.config = ObservabilityConfig()
        self._metrics: Dict[str, List[Metric]] = defaultdict(list)
        self._histograms: Dict[str, PercentileHistogram] = {}
        self._lock = threading.Lock()
        self._start_times: Dict[str, float] = {}
    
    def increment_counter(self, name: str, value: float = 1.0, labels: Optional[Dict[str, str]] = None):
        """Increment a counter metric - only if enabled"""
        if not self.config.metrics_collection_enabled:
            return
        
        with self._lock:
            metric = Metric(
                name=name,
                type=MetricType.COUNTER,
                value=value,
                labels=labels or {}
            )
            self._metrics[name].append(metric)
    
    def set_gauge(self, name: str, value: float, labels: Optional[Dict[str, str]] = None):
        """Set a gauge metric - only if enabled"""
        if not self.config.metrics_collection_enabled:
            return
        
        with self._lock:
            metric = Metric(
                name=name,
                type=MetricType.GAUGE,
                value=value,
                labels=labels or {}
            )
            self._metrics[name].append(metric)
    
    def start_timer(self, name: str):
        """Start a timer"""
        if not self.config.metrics_collection_enabled:
            return
        self._start_times[name] = time.time()
    
    def stop_timer(self, name: str, labels: Optional[Dict[str, str]] = None) -> Optional[float]:
        """Stop a timer and record duration - returns duration in ms"""
        if not self.config.metrics_collection_enabled:
            return None
        
        start_time = self._start_times.pop(name, None)
        if start_time is None:
            return None
        
        duration_ms = (time.time() - start_time) * 1000
        
        with self._lock:
            # Record in regular metrics
            metric = Metric(
                name=name,
                type=MetricType.TIMER,
                value=duration_ms,
                labels=labels or {}
            )
            self._metrics[name].append(metric)
            
            # Record in histogram for percentiles
            if name not in self._histograms:
                self._histograms[name] = PercentileHistogram()
            self._histograms[name].record(duration_ms)
        
        return duration_ms
    
    def record_histogram(self, name: str, value: float, labels: Optional[Dict[str, str]] = None):
        """Record a histogram value for percentile calculation"""
        if not self.config.metrics_collection_enabled:
            return
        
        with self._lock:
            if name not in self._histograms:
                self._histograms[name] = PercentileHistogram()
            self._histograms[name].record(value)
    
    def get_timer_percentiles(self, name: str) -> Optional[PercentileResult]:
        """Get percentile statistics for a timer"""
        with self._lock:
            histogram = self._histograms.get(name)
            if histogram:
                return histogram.get_percentiles()
            return None
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get aggregated metrics snapshot"""
        with self._lock:
            result = {}
            for name, metrics_list in self._metrics.items():
                if not metrics_list:
                    continue
                
                metric_type = metrics_list[0].type
                if metric_type == MetricType.COUNTER:
                    result[name] = {
                        "type": "counter",
                        "total": sum(m.value for m in metrics_list),
                        "count": len(metrics_list)
                    }
                elif metric_type == MetricType.TIMER:
                    values = [m.value for m in metrics_list]
                    percentiles = self.get_timer_percentiles(name)
                    result[name] = {
                        "type": "timer",
                        "count": len(values),
                        "avg_ms": sum(values) / len(values),
                        "min_ms": min(values),
                        "max_ms": max(values),
                        "percentiles": percentiles.__dict__ if percentiles else None
                    }
                elif metric_type == MetricType.GAUGE:
                    result[name] = {
                        "type": "gauge",
                        "current": metrics_list[-1].value
                    }
            return result
    
    def export_prometheus(self) -> str:
        """Export metrics in Prometheus exposition format"""
        if not self.config.prometheus_exposition_enabled:
            return ""
        
        lines = []
        metrics = self.get_metrics()
        
        for name, data in metrics.items():
            metric_type = data["type"]
            safe_name = name.replace(".", "_").replace("-", "_")
            
            if metric_type == "counter":
                lines.append(f"# TYPE {safe_name}_total counter")
                lines.append(f"{safe_name}_total {data['total']}")
            elif metric_type == "gauge":
                lines.append(f"# TYPE {safe_name} gauge")
                lines.append(f"{safe_name} {data['current']}")
            elif metric_type == "timer":
                lines.append(f"# TYPE {safe_name}_seconds summary")
                p = data.get("percentiles", {})
                if isinstance(p, dict):
                    lines.append(f"{safe_name}_seconds{{quantile=\"0.5\"}} {p.get('p50', 0) / 1000}")
                    lines.append(f"{safe_name}_seconds{{quantile=\"0.95\"}} {p.get('p95', 0) / 1000}")
                    lines.append(f"{safe_name}_seconds{{quantile=\"0.99\"}} {p.get('p99', 0) / 1000}")
                lines.append(f"{safe_name}_seconds_count {data['count']}")
        
        return "\n".join(lines) + "\n"
    
    def reset(self):
        """Clear all metrics"""
        with self._lock:
            self._metrics.clear()
            self._histograms.clear()


# -----------------------------------------------------------------------------
# Adaptive Sampling Logger
# -----------------------------------------------------------------------------
class AdaptiveSamplingLogger:
    """Structured logger with adaptive sampling for high volume"""
    
    def __init__(self, name: str = "neural_shield"):
        self.name = name
        self.config = ObservabilityConfig()
        self._event_count: Dict[LogLevel, int] = defaultdict(int)
        self._window_start = time.time()
        self._lock = threading.Lock()
    
    def _should_sample(self, level: LogLevel) -> bool:
        """Determine if event should be sampled based on rate limiting"""
        cfg = self.config.sampling_config
        
        if not cfg.adaptive_sampling:
            return random.random() < cfg.base_rate
        
        with self._lock:
            now = time.time()
            window_elapsed = now - self._window_start
            
            # Reset window every second
            if window_elapsed >= 1.0:
                self._event_count.clear()
                self._window_start = now
            
            current_count = self._event_count[level]
            if current_count >= cfg.max_events_per_second:
                return False
            
            self._event_count[level] += 1
            return True
    
    def _log(self, level: LogLevel, message: str, **kwargs):
        """Internal log method - only executes if explicitly enabled"""
        if not self.config.structured_logging_enabled:
            return
        
        if level.value < self.config.min_log_level.value:
            return
        
        if not self._should_sample(level):
            return
        
        # Get tracing context
        tracing = TracingManager()
        ctx = tracing.get_current_context()
        
        # Get correlation ID
        cid_manager = CorrelationIdManager()
        cid = cid_manager.get()
        
        log_entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "logger": self.name,
            "level": level.value,
            "message": message,
            "trace_id": ctx.trace_id if ctx else kwargs.get("trace_id", str(uuid.uuid4())),
            "span_id": ctx.span_id if ctx else kwargs.get("span_id", str(uuid.uuid4())[:8]),
            "correlation_id": cid or kwargs.get("correlation_id"),
        }
        
        # Add extra fields
        for key, value in kwargs.items():
            if key not in ("trace_id", "span_id", "correlation_id"):
                log_entry[key] = value
        
        # Output based on destination
        if self.config.log_destination == "console":
            print(json.dumps(log_entry))
    
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
# Health Check Registry with Dependencies
# -----------------------------------------------------------------------------
class HealthCheckRegistry:
    """Health check registry with dependency graph support"""
    
    def __init__(self):
        self.config = ObservabilityConfig()
        self._checks: Dict[str, Callable[[], HealthCheck]] = {}
        self._dependencies: Dict[str, List[str]] = {}
        self._lock = threading.Lock()
    
    def register(self, name: str, check_func: Callable[[], HealthCheck], 
                 dependencies: Optional[List[str]] = None):
        """Register a health check function with optional dependencies"""
        with self._lock:
            self._checks[name] = check_func
            self._dependencies[name] = dependencies or []
    
    def _get_dependency_status(self, name: str, results: Dict[str, HealthCheck]) -> HealthStatus:
        """Get status considering dependencies"""
        check = results.get(name)
        if not check:
            return HealthStatus.UNHEALTHY
        
        status = check.status
        
        # If any dependency is unhealthy, this check is unhealthy
        for dep in self._dependencies.get(name, []):
            dep_status = self._get_dependency_status(dep, results)
            if dep_status == HealthStatus.UNHEALTHY:
                return HealthStatus.UNHEALTHY
            elif dep_status == HealthStatus.DEGRADED and status == HealthStatus.HEALTHY:
                status = HealthStatus.DEGRADED
        
        return status
    
    def run_all_checks(self) -> Dict[str, Any]:
        """Run all registered health checks with dependency resolution"""
        if not self.config.health_checks_enabled:
            return {"health_checks_enabled": False, "status": "not_configured"}
        
        raw_results = {}
        
        with self._lock:
            # First run all checks
            for name, check_func in self._checks.items():
                start_time = time.time()
                try:
                    check_result = check_func()
                    check_result.duration_ms = (time.time() - start_time) * 1000
                    raw_results[name] = check_result
                except Exception as e:
                    raw_results[name] = HealthCheck(
                        name=name,
                        status=HealthStatus.UNHEALTHY,
                        message=f"Health check failed: {str(e)}",
                        duration_ms=(time.time() - start_time) * 1000
                    )
            
            # Then resolve dependencies
            final_results = []
            overall_status = HealthStatus.HEALTHY
            
            for name, result in raw_results.items():
                resolved_status = self._get_dependency_status(name, raw_results)
                result.status = resolved_status
                final_results.append(result)
                
                if resolved_status == HealthStatus.UNHEALTHY:
                    overall_status = HealthStatus.UNHEALTHY
                elif resolved_status == HealthStatus.DEGRADED and overall_status == HealthStatus.HEALTHY:
                    overall_status = HealthStatus.DEGRADED
        
        return {
            "overall_status": overall_status.value,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "dependency_resolution": "enabled",
            "checks": [
                {
                    "name": r.name,
                    "status": r.status.value,
                    "message": r.message,
                    "duration_ms": round(r.duration_ms, 2),
                    "dependencies": self._dependencies.get(r.name, []),
                    "details": r.details
                }
                for r in final_results
            ]
        }


# -----------------------------------------------------------------------------
# Decorators
# -----------------------------------------------------------------------------
def timed_operation(metric_name: str, labels: Optional[Dict[str, str]] = None):
    """
    Decorator for timing operations - OPT-IN, no-op if metrics disabled
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            config = ObservabilityConfig()
            if not config.metrics_collection_enabled:
                return func(*args, **kwargs)
            
            collector = get_metrics()
            start_time = time.time()
            try:
                result = func(*args, **kwargs)
                duration_ms = (time.time() - start_time) * 1000
                collector.increment_counter(f"{metric_name}_success", labels=labels)
                collector.set_gauge(f"{metric_name}_duration_ms", duration_ms, labels=labels)
                return result
            except Exception as e:
                duration_ms = (time.time() - start_time) * 1000
                collector.increment_counter(f"{metric_name}_errors", labels={**(labels or {}), "error": type(e).__name__})
                collector.set_gauge(f"{metric_name}_duration_ms", duration_ms, labels=labels)
                raise
        return wrapper
    return decorator


def traced_operation(span_name: str, with_correlation_id: bool = True):
    """
    Decorator for distributed tracing - OPT-IN, no-op if tracing disabled
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            config = ObservabilityConfig()
            if not config.tracing_enabled:
                return func(*args, **kwargs)
            
            tracing = TracingManager()
            cid_manager = CorrelationIdManager()
            
            # Set correlation ID if enabled
            if with_correlation_id and config.correlation_id_propagation:
                if not cid_manager.get():
                    cid_manager.set()
            
            # Start span
            parent_ctx = tracing.get_current_context()
            span_ctx = tracing.start_span(span_name, parent_ctx)
            
            try:
                result = func(*args, **kwargs)
                return result
            finally:
                tracing.end_span(span_ctx)
        return wrapper
    return decorator


def logged_operation(log_level: LogLevel = LogLevel.INFO, message: Optional[str] = None):
    """
    Decorator for logging function entry/exit - OPT-IN, no-op if logging disabled
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            config = ObservabilityConfig()
            if not config.structured_logging_enabled:
                return func(*args, **kwargs)
            
            logger = AdaptiveSamplingLogger(func.__module__)
            func_name = func.__name__
            
            log_msg = message or f"Executing {func_name}"
            logger.info(f"START: {log_msg}", 
                       function=func_name,
                       args_count=len(args),
                       kwargs_count=len(kwargs))
            
            start_time = time.time()
            try:
                result = func(*args, **kwargs)
                duration_ms = (time.time() - start_time) * 1000
                logger.info(f"COMPLETE: {log_msg}",
                           function=func_name,
                           duration_ms=round(duration_ms, 2),
                           success=True)
                return result
            except Exception as e:
                duration_ms = (time.time() - start_time) * 1000
                logger.error(f"FAILED: {log_msg}",
                            function=func_name,
                            duration_ms=round(duration_ms, 2),
                            error_type=type(e).__name__,
                            error_message=str(e),
                            success=False)
                raise
        return wrapper
    return decorator


# -----------------------------------------------------------------------------
# Global Singleton Instances
# -----------------------------------------------------------------------------
_global_logger: Optional[AdaptiveSamplingLogger] = None
_global_metrics: Optional[MetricsCollector] = None
_global_health: Optional[HealthCheckRegistry] = None
_global_tracing: Optional[TracingManager] = None
_global_correlation: Optional[CorrelationIdManager] = None


def get_logger() -> AdaptiveSamplingLogger:
    """Get the global structured logger instance"""
    global _global_logger
    if _global_logger is None:
        _global_logger = AdaptiveSamplingLogger()
    return _global_logger


def get_metrics() -> MetricsCollector:
    """Get the global metrics collector instance"""
    global _global_metrics
    if _global_metrics is None:
        _global_metrics = MetricsCollector()
    return _global_metrics


def get_health_registry() -> HealthCheckRegistry:
    """Get the global health check registry instance"""
    global _global_health
    if _global_health is None:
        _global_health = HealthCheckRegistry()
    return _global_health


def get_tracing() -> TracingManager:
    """Get the global tracing manager instance"""
    global _global_tracing
    if _global_tracing is None:
        _global_tracing = TracingManager()
    return _global_tracing


def get_correlation_manager() -> CorrelationIdManager:
    """Get the global correlation ID manager instance"""
    global _global_correlation
    if _global_correlation is None:
        _global_correlation = CorrelationIdManager()
    return _global_correlation


def get_config() -> ObservabilityConfig:
    """Get the global observability configuration"""
    return ObservabilityConfig()


# -----------------------------------------------------------------------------
# Export Public API
# -----------------------------------------------------------------------------
__all__ = [
    "ObservabilityConfig", "get_config",
    "LogLevel", "AdaptiveSamplingLogger", "get_logger", "logged_operation",
    "MetricType", "Metric", "PercentileResult", "PercentileHistogram",
    "MetricsCollector", "get_metrics", "timed_operation",
    "HealthStatus", "HealthCheck", "HealthCheckRegistry", "get_health_registry",
    "TracingFlags", "SpanContext", "TracingManager", "get_tracing", "traced_operation",
    "CorrelationIdManager", "get_correlation_manager",
    "SamplingConfig",
]
