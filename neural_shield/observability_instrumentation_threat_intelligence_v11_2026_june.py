"""
NeuralShield AI - Observability & Instrumentation Module v11
Session 110 - Dimension D: Observability & Instrumentation

PHILOSOPHY: ADD-ONLY, NO EXISTING CODE MODIFIED
ALL FEATURES OPT-IN - DISABLED BY DEFAULT
100% BACKWARD COMPATIBLE

This module provides:
1. Structured logging (severity-based, no sensitive data)
2. Metrics collection (counters, timers, gauges, histograms)
3. Health check framework (liveness, readiness, degraded states)
4. Distributed tracing (correlation IDs, baggage propagation)
5. SLO tracking (error budgets, burn rates)
6. Thread-safe singleton pattern
"""

import time
import json
import uuid
import threading
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime, timedelta
from collections import defaultdict, deque


class LogSeverity(Enum):
    """Log severity levels matching standard logging conventions."""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class MetricType(Enum):
    """Types of metrics supported."""
    COUNTER = "counter"
    GAUGE = "gauge"
    TIMER = "timer"
    HISTOGRAM = "histogram"


class HealthStatus(Enum):
    """Health check status levels."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


class SLOStatus(Enum):
    """SLO burn rate status."""
    OK = "ok"
    WARNING = "warning"
    BURNING = "burning"
    EXHAUSTED = "exhausted"
    UNKNOWN = "unknown"


@dataclass
class LogEntry:
    """Structured log entry with metadata."""
    timestamp: str
    severity: LogSeverity
    message: str
    correlation_id: str
    component: str
    attributes: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "severity": self.severity.value,
            "message": self.message,
            "correlation_id": self.correlation_id,
            "component": self.component,
            "attributes": self.attributes
        }


@dataclass
class MetricValue:
    """Metric value with metadata."""
    name: str
    type: MetricType
    value: float
    timestamp: str
    labels: Dict[str, str] = field(default_factory=dict)


@dataclass
class HealthCheckResult:
    """Result of a health check."""
    name: str
    status: HealthStatus
    message: str
    duration_ms: float
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())


@dataclass
class SLOConfig:
    """Configuration for an SLO."""
    name: str
    target_percentage: float  # e.g., 99.9 for 99.9% availability
    window_days: int = 30
    error_budget_burn_rate_warning: float = 2.0
    error_budget_burn_rate_critical: float = 10.0


@dataclass
class ObservabilityConfig:
    """Master configuration for all observability features."""
    # All features disabled by default - OPT-IN pattern
    logging_enabled: bool = False
    metrics_enabled: bool = False
    health_checks_enabled: bool = False
    tracing_enabled: bool = False
    slo_tracking_enabled: bool = False
    
    # Logging configuration
    log_level: LogSeverity = LogSeverity.INFO
    max_log_entries: int = 10000
    include_timestamps: bool = True
    
    # Metrics configuration
    max_metric_samples: int = 1000
    retain_histogram_buckets: bool = True
    
    # Health check configuration
    default_health_check_timeout_ms: int = 5000
    
    # Tracing configuration
    generate_correlation_ids: bool = True
    propagate_baggage: bool = True
    
    # SLO configuration
    slo_error_budget_window_days: int = 30


class StructuredLogger:
    """Thread-safe structured logging with ring buffer storage."""
    
    def __init__(self, config: ObservabilityConfig):
        self._config = config
        self._logs: deque = deque(maxlen=config.max_log_entries)
        self._lock = threading.Lock()
        self._python_logger = logging.getLogger("neuralshield.observability")
    
    def _should_log(self, severity: LogSeverity) -> bool:
        if not self._config.logging_enabled:
            return False
        severity_order = [LogSeverity.DEBUG, LogSeverity.INFO, 
                         LogSeverity.WARNING, LogSeverity.ERROR, LogSeverity.CRITICAL]
        return severity_order.index(severity) >= severity_order.index(self._config.log_level)
    
    def log(self, severity: LogSeverity, message: str, component: str,
            correlation_id: Optional[str] = None, **attributes) -> Optional[LogEntry]:
        """Log a structured entry - returns None if logging disabled."""
        if not self._should_log(severity):
            return None
        
        entry = LogEntry(
            timestamp=datetime.utcnow().isoformat(),
            severity=severity,
            message=message,
            correlation_id=correlation_id or str(uuid.uuid4()),
            component=component,
            attributes=attributes
        )
        
        with self._lock:
            self._logs.append(entry)
        
        # Also emit to Python logging if configured
        py_level = {
            LogSeverity.DEBUG: logging.DEBUG,
            LogSeverity.INFO: logging.INFO,
            LogSeverity.WARNING: logging.WARNING,
            LogSeverity.ERROR: logging.ERROR,
            LogSeverity.CRITICAL: logging.CRITICAL
        }.get(severity, logging.INFO)
        
        self._python_logger.log(py_level, json.dumps(entry.to_dict()))
        return entry
    
    def debug(self, message: str, component: str, **kwargs):
        return self.log(LogSeverity.DEBUG, message, component, **kwargs)
    
    def info(self, message: str, component: str, **kwargs):
        return self.log(LogSeverity.INFO, message, component, **kwargs)
    
    def warning(self, message: str, component: str, **kwargs):
        return self.log(LogSeverity.WARNING, message, component, **kwargs)
    
    def error(self, message: str, component: str, **kwargs):
        return self.log(LogSeverity.ERROR, message, component, **kwargs)
    
    def critical(self, message: str, component: str, **kwargs):
        return self.log(LogSeverity.CRITICAL, message, component, **kwargs)
    
    def get_recent_logs(self, count: int = 100, 
                       min_severity: Optional[LogSeverity] = None) -> List[LogEntry]:
        with self._lock:
            logs = list(self._logs)
        if min_severity:
            severity_order = [LogSeverity.DEBUG, LogSeverity.INFO, 
                             LogSeverity.WARNING, LogSeverity.ERROR, LogSeverity.CRITICAL]
            min_idx = severity_order.index(min_severity)
            logs = [l for l in logs if severity_order.index(l.severity) >= min_idx]
        return logs[-count:]
    
    def clear_logs(self) -> None:
        with self._lock:
            self._logs.clear()


class MetricsCollector:
    """Thread-safe metrics collection with counters, gauges, timers, and histograms."""
    
    HISTOGRAM_BUCKETS = [0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
    
    def __init__(self, config: ObservabilityConfig):
        self._config = config
        self._counters: Dict[str, int] = defaultdict(int)
        self._gauges: Dict[str, float] = {}
        self._timers: Dict[str, List[float]] = defaultdict(list)
        self._histograms: Dict[str, Dict[float, int]] = defaultdict(lambda: defaultdict(int))
        self._samples: deque = deque(maxlen=config.max_metric_samples)
        self._lock = threading.Lock()
    
    def _record_sample(self, name: str, metric_type: MetricType, 
                      value: float, labels: Optional[Dict[str, str]] = None) -> None:
        if not self._config.metrics_enabled:
            return
        sample = MetricValue(
            name=name,
            type=metric_type,
            value=value,
            timestamp=datetime.utcnow().isoformat(),
            labels=labels or {}
        )
        with self._lock:
            self._samples.append(sample)
    
    def increment_counter(self, name: str, value: int = 1, 
                         labels: Optional[Dict[str, str]] = None) -> int:
        """Increment a counter - returns 0 if metrics disabled."""
        if not self._config.metrics_enabled:
            return 0
        with self._lock:
            self._counters[name] += value
            current = self._counters[name]
        self._record_sample(name, MetricType.COUNTER, float(current), labels)
        return current
    
    def set_gauge(self, name: str, value: float, 
                 labels: Optional[Dict[str, str]] = None) -> float:
        """Set a gauge value - returns value if enabled, 0 otherwise."""
        if not self._config.metrics_enabled:
            return 0.0
        with self._lock:
            self._gauges[name] = value
        self._record_sample(name, MetricType.GAUGE, value, labels)
        return value
    
    def record_timer(self, name: str, duration_seconds: float,
                    labels: Optional[Dict[str, str]] = None) -> None:
        """Record a timer measurement."""
        if not self._config.metrics_enabled:
            return
        with self._lock:
            self._timers[name].append(duration_seconds)
            # Also add to histogram
            for bucket in self.HISTOGRAM_BUCKETS:
                if duration_seconds <= bucket:
                    self._histograms[name][bucket] += 1
                    break
        self._record_sample(name, MetricType.TIMER, duration_seconds, labels)
    
    def time_function(self, name: Optional[str] = None, 
                     labels: Optional[Dict[str, str]] = None):
        """Decorator to time function execution."""
        def decorator(func: Callable) -> Callable:
            metric_name = name or f"timer.{func.__name__}"
            def wrapper(*args, **kwargs):
                start = time.perf_counter()
                try:
                    return func(*args, **kwargs)
                finally:
                    duration = time.perf_counter() - start
                    self.record_timer(metric_name, duration, labels)
            return wrapper
        return decorator
    
    def get_counter_value(self, name: str) -> int:
        with self._lock:
            return self._counters.get(name, 0)
    
    def get_gauge_value(self, name: str) -> Optional[float]:
        with self._lock:
            return self._gauges.get(name)
    
    def get_timer_stats(self, name: str) -> Dict[str, Optional[float]]:
        with self._lock:
            values = self._timers.get(name, [])
        if not values:
            return {"count": 0, "avg": None, "min": None, "max": None, "p50": None, "p95": None, "p99": None}
        sorted_vals = sorted(values)
        n = len(sorted_vals)
        return {
            "count": n,
            "avg": sum(values) / n,
            "min": sorted_vals[0],
            "max": sorted_vals[-1],
            "p50": sorted_vals[int(n * 0.5)],
            "p95": sorted_vals[int(n * 0.95)],
            "p99": sorted_vals[int(n * 0.99)]
        }
    
    def get_all_counters(self) -> Dict[str, int]:
        with self._lock:
            return dict(self._counters)
    
    def get_all_gauges(self) -> Dict[str, float]:
        with self._lock:
            return dict(self._gauges)
    
    def get_recent_samples(self, count: int = 100) -> List[MetricValue]:
        with self._lock:
            return list(self._samples)[-count:]


class HealthCheckFramework:
    """Health check framework with liveness/readiness probes."""
    
    def __init__(self, config: ObservabilityConfig):
        self._config = config
        self._checks: Dict[str, Callable[[], HealthCheckResult]] = {}
        self._lock = threading.Lock()
        self._last_results: Dict[str, HealthCheckResult] = {}
    
    def register_check(self, name: str, check_func: Callable[[], HealthCheckResult]) -> None:
        """Register a health check function."""
        with self._lock:
            self._checks[name] = check_func
    
    def run_check(self, name: str) -> Optional[HealthCheckResult]:
        """Run a single health check - returns None if disabled."""
        if not self._config.health_checks_enabled:
            return None
        
        with self._lock:
            check_func = self._checks.get(name)
        
        if not check_func:
            return HealthCheckResult(
                name=name,
                status=HealthStatus.UNKNOWN,
                message=f"Health check '{name}' not registered",
                duration_ms=0.0
            )
        
        start = time.perf_counter()
        try:
            result = check_func()
        except Exception as e:
            result = HealthCheckResult(
                name=name,
                status=HealthStatus.UNHEALTHY,
                message=f"Health check exception: {str(e)}",
                duration_ms=(time.perf_counter() - start) * 1000
            )
        
        duration_ms = (time.perf_counter() - start) * 1000
        result.duration_ms = duration_ms
        
        with self._lock:
            self._last_results[name] = result
        
        return result
    
    def run_all_checks(self) -> Dict[str, Optional[HealthCheckResult]]:
        """Run all registered health checks."""
        results = {}
        for name in list(self._checks.keys()):
            results[name] = self.run_check(name)
        return results
    
    def get_overall_status(self) -> HealthStatus:
        """Get aggregate health status across all checks."""
        if not self._config.health_checks_enabled or not self._last_results:
            return HealthStatus.UNKNOWN
        
        statuses = [r.status for r in self._last_results.values()]
        if HealthStatus.UNHEALTHY in statuses:
            return HealthStatus.UNHEALTHY
        if HealthStatus.DEGRADED in statuses:
            return HealthStatus.DEGRADED
        return HealthStatus.HEALTHY
    
    def get_last_results(self) -> Dict[str, HealthCheckResult]:
        with self._lock:
            return dict(self._last_results)


class DistributedTracer:
    """Distributed tracing with correlation IDs and baggage propagation."""
    
    def __init__(self, config: ObservabilityConfig):
        self._config = config
        self._local = threading.local()
        self._lock = threading.Lock()
        self._trace_count = 0
    
    def generate_correlation_id(self) -> str:
        """Generate a new correlation ID."""
        if not self._config.tracing_enabled or not self._config.generate_correlation_ids:
            return ""
        return str(uuid.uuid4())
    
    def set_correlation_id(self, correlation_id: str) -> None:
        """Set correlation ID for current thread context."""
        if self._config.tracing_enabled:
            self._local.correlation_id = correlation_id
    
    def get_correlation_id(self) -> Optional[str]:
        """Get correlation ID from current thread context."""
        if not self._config.tracing_enabled:
            return None
        return getattr(self._local, 'correlation_id', None)
    
    def set_baggage(self, key: str, value: str) -> None:
        """Set baggage item for propagation."""
        if not self._config.tracing_enabled or not self._config.propagate_baggage:
            return
        if not hasattr(self._local, 'baggage'):
            self._local.baggage = {}
        self._local.baggage[key] = value
    
    def get_baggage(self) -> Dict[str, str]:
        """Get all baggage items."""
        if not self._config.tracing_enabled or not self._config.propagate_baggage:
            return {}
        return getattr(self._local, 'baggage', {}).copy()
    
    def clear_context(self) -> None:
        """Clear tracing context for current thread."""
        if hasattr(self._local, 'correlation_id'):
            delattr(self._local, 'correlation_id')
        if hasattr(self._local, 'baggage'):
            delattr(self._local, 'baggage')
    
    def trace_span(self, name: str, **attributes):
        """Decorator for creating a trace span."""
        def decorator(func: Callable) -> Callable:
            def wrapper(*args, **kwargs):
                if not self._config.tracing_enabled:
                    return func(*args, **kwargs)
                
                cid = self.get_correlation_id() or self.generate_correlation_id()
                self.set_correlation_id(cid)
                for k, v in attributes.items():
                    self.set_baggage(k, str(v))
                
                with self._lock:
                    self._trace_count += 1
                
                try:
                    return func(*args, **kwargs)
                finally:
                    pass  # Span end - could record timing here
            return wrapper
        return decorator
    
    def get_trace_count(self) -> int:
        with self._lock:
            return self._trace_count


class SLOTracker:
    """Service Level Objective tracking with error budget calculation."""
    
    def __init__(self, config: ObservabilityConfig):
        self._config = config
        self._slos: Dict[str, SLOConfig] = {}
        self._events: deque = deque(maxlen=100000)  # (timestamp, is_error)
        self._lock = threading.Lock()
    
    def register_slo(self, slo: SLOConfig) -> None:
        """Register an SLO for tracking."""
        with self._lock:
            self._slos[slo.name] = slo
    
    def record_success(self, slo_name: str) -> None:
        """Record a successful event for an SLO."""
        if not self._config.slo_tracking_enabled:
            return
        with self._lock:
            self._events.append((time.time(), False, slo_name))
    
    def record_error(self, slo_name: str) -> None:
        """Record an error event for an SLO."""
        if not self._config.slo_tracking_enabled:
            return
        with self._lock:
            self._events.append((time.time(), True, slo_name))
    
    def get_slo_status(self, slo_name: str) -> Dict[str, Any]:
        """Get current SLO status including error budget burn rate."""
        if not self._config.slo_tracking_enabled:
            return {"status": SLOStatus.UNKNOWN, "message": "SLO tracking disabled"}
        
        with self._lock:
            slo = self._slos.get(slo_name)
            if not slo:
                return {"status": SLOStatus.UNKNOWN, "message": f"SLO '{slo_name}' not registered"}
            
            window_start = time.time() - (slo.window_days * 86400)
            window_events = [(t, e) for t, e, n in self._events 
                           if n == slo_name and t >= window_start]
            
            if not window_events:
                return {
                    "status": SLOStatus.OK,
                    "message": "No events in window",
                    "total_events": 0,
                    "error_count": 0,
                    "availability": 100.0,
                    "error_budget_remaining": 100.0,
                    "burn_rate": 0.0
                }
            
            total = len(window_events)
            errors = sum(1 for _, e in window_events if e)
            availability = ((total - errors) / total) * 100
            error_budget = 100.0 - slo.target_percentage
            error_budget_used = (errors / total) * 100
            error_budget_remaining = max(0, error_budget - error_budget_used)
            
            # Burn rate: how fast we're consuming error budget
            # 1.0 = consuming at exactly the rate allowed by SLO
            if error_budget > 0:
                burn_rate = (error_budget_used / error_budget) * (30 / slo.window_days)
            else:
                burn_rate = float('inf')
            
            if error_budget_remaining <= 0:
                status = SLOStatus.EXHAUSTED
            elif burn_rate >= slo.error_budget_burn_rate_critical:
                status = SLOStatus.BURNING
            elif burn_rate >= slo.error_budget_burn_rate_warning:
                status = SLOStatus.WARNING
            else:
                status = SLOStatus.OK
            
            return {
                "status": status,
                "total_events": total,
                "error_count": errors,
                "availability": availability,
                "target_availability": slo.target_percentage,
                "error_budget_total": error_budget,
                "error_budget_used": error_budget_used,
                "error_budget_remaining": error_budget_remaining,
                "burn_rate": burn_rate
            }


class ThreatIntelligenceObservability:
    """
    Main observability facade for Threat Intelligence operations.
    Thread-safe singleton - OPT-IN, disabled by default.
    
    USAGE (OPT-IN REQUIRED):
        from neural_shield.observability_instrumentation_threat_intelligence_v11_2026_june import observability
        
        # Enable features you want
        observability.enable_logging()
        observability.enable_metrics()
        observability.enable_health_checks()
        observability.enable_tracing()
        observability.enable_slo_tracking()
        
        # Use features
        observability.logger.info("Indicator processed", "threat_intel", indicator_type="ip")
        observability.metrics.increment_counter("indicators_processed")
    """
    
    _instance = None
    _instance_lock = threading.Lock()
    
    def __new__(cls):
        if cls._instance is None:
            with cls._instance_lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self._config = ObservabilityConfig()  # ALL DISABLED BY DEFAULT
        self._lock = threading.Lock()
        
        # Initialize all sub-components (they respect config.enabled flags)
        self._logger = StructuredLogger(self._config)
        self._metrics = MetricsCollector(self._config)
        self._health = HealthCheckFramework(self._config)
        self._tracer = DistributedTracer(self._config)
        self._slo = SLOTracker(self._config)
        
        # Register default health checks
        self._register_default_health_checks()
        
        # Register default SLOs
        self._register_default_slos()
    
    def _register_default_health_checks(self) -> None:
        """Register default health checks for threat intelligence."""
        
        def memory_check() -> HealthCheckResult:
            try:
                import psutil
                mem = psutil.virtual_memory()
                if mem.percent > 90:
                    return HealthCheckResult(
                        name="memory",
                        status=HealthStatus.UNHEALTHY,
                        message=f"Memory usage critical: {mem.percent}%",
                        duration_ms=0.0,
                        details={"percent_used": mem.percent, "available_mb": mem.available / 1024 / 1024}
                    )
                elif mem.percent > 75:
                    return HealthCheckResult(
                        name="memory",
                        status=HealthStatus.DEGRADED,
                        message=f"Memory usage high: {mem.percent}%",
                        duration_ms=0.0,
                        details={"percent_used": mem.percent}
                    )
                return HealthCheckResult(
                    name="memory",
                    status=HealthStatus.HEALTHY,
                    message=f"Memory usage normal: {mem.percent}%",
                    duration_ms=0.0,
                    details={"percent_used": mem.percent}
                )
            except ImportError:
                return HealthCheckResult(
                    name="memory",
                    status=HealthStatus.UNKNOWN,
                    message="psutil not available for memory check",
                    duration_ms=0.0
                )
        
        self._health.register_check("memory", memory_check)
    
    def _register_default_slos(self) -> None:
        """Register default SLOs for threat intelligence."""
        self._slo.register_slo(SLOConfig(
            name="threat_intel_processing",
            target_percentage=99.9,
            window_days=30
        ))
        self._slo.register_slo(SLOConfig(
            name="indicator_lookup",
            target_percentage=99.5,
            window_days=30
        ))
    
    # Enable/disable methods (OPT-IN pattern)
    def enable_logging(self, level: LogSeverity = LogSeverity.INFO) -> None:
        with self._lock:
            self._config.logging_enabled = True
            self._config.log_level = level
    
    def enable_metrics(self) -> None:
        with self._lock:
            self._config.metrics_enabled = True
    
    def enable_health_checks(self) -> None:
        with self._lock:
            self._config.health_checks_enabled = True
    
    def enable_tracing(self) -> None:
        with self._lock:
            self._config.tracing_enabled = True
    
    def enable_slo_tracking(self) -> None:
        with self._lock:
            self._config.slo_tracking_enabled = True
    
    def enable_all(self) -> None:
        """Enable ALL observability features."""
        self.enable_logging()
        self.enable_metrics()
        self.enable_health_checks()
        self.enable_tracing()
        self.enable_slo_tracking()
    
    # Property accessors
    @property
    def logger(self) -> StructuredLogger:
        return self._logger
    
    @property
    def metrics(self) -> MetricsCollector:
        return self._metrics
    
    @property
    def health(self) -> HealthCheckFramework:
        return self._health
    
    @property
    def tracer(self) -> DistributedTracer:
        return self._tracer
    
    @property
    def slo(self) -> SLOTracker:
        return self._slo
    
    @property
    def config(self) -> ObservabilityConfig:
        return self._config
    
    # Convenience methods
    def get_status_summary(self) -> Dict[str, Any]:
        """Get comprehensive observability status summary."""
        return {
            "config": {
                "logging_enabled": self._config.logging_enabled,
                "metrics_enabled": self._config.metrics_enabled,
                "health_checks_enabled": self._config.health_checks_enabled,
                "tracing_enabled": self._config.tracing_enabled,
                "slo_tracking_enabled": self._config.slo_tracking_enabled
            },
            "health": {
                "overall_status": self._health.get_overall_status().value,
                "checks": {k: v.status.value for k, v in self._health.get_last_results().items()}
            },
            "metrics": {
                "counters_count": len(self._metrics.get_all_counters()),
                "gauges_count": len(self._metrics.get_all_gauges()),
                "samples_count": len(self._metrics.get_recent_samples(1000))
            },
            "tracing": {
                "trace_count": self._tracer.get_trace_count()
            }
        }


# Global singleton instance - OPT-IN, disabled by default
observability = ThreatIntelligenceObservability()
