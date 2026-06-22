"""
NeuralShield Unified Health Monitoring & Metrics Dashboard v4
Dimension D: Observability & Instrumentation

COMPREHENSIVE OBSERVABILITY FRAMEWORK
- Unified health check system for ALL modules
- Prometheus-style metrics collection
- Distributed tracing context propagation
- Status dashboard with severity levels
- OPT-IN only - disabled by default
- 100% backward compatible - wraps existing code, no core changes

Incremental Build Philosophy: ADD-ONLY, no existing code modified
"""

import time
import threading
import uuid
import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Callable
from enum import Enum
from collections import defaultdict, deque
from datetime import datetime, timedelta


class HealthStatus(Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


class SeverityLevel(Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class MetricType(Enum):
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    TIMER = "timer"


@dataclass
class HealthCheckResult:
    module_name: str
    status: HealthStatus
    message: str
    response_time_ms: float
    timestamp: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class MetricRecord:
    name: str
    type: MetricType
    value: float
    labels: Dict[str, str] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class TraceSpan:
    trace_id: str
    span_id: str
    parent_span_id: Optional[str]
    operation_name: str
    start_time: float
    end_time: Optional[float] = None
    attributes: Dict[str, Any] = field(default_factory=dict)
    events: List[Dict[str, Any]] = field(default_factory=list)


class ModuleHealthChecker:
    """Health check wrapper for existing modules - NO MODIFICATION TO CORE CODE"""
    
    def __init__(self, module_name: str, check_function: Optional[Callable] = None):
        self.module_name = module_name
        self.check_function = check_function or self._default_check
        self.history: deque = deque(maxlen=100)
        self.consecutive_failures = 0
        self.consecutive_successes = 0
    
    def _default_check(self) -> HealthCheckResult:
        return HealthCheckResult(
            module_name=self.module_name,
            status=HealthStatus.HEALTHY,
            message="Default health check passed",
            response_time_ms=0.0
        )
    
    def run_check(self) -> HealthCheckResult:
        start = time.perf_counter()
        try:
            result = self.check_function()
            elapsed = (time.perf_counter() - start) * 1000
            result.response_time_ms = elapsed
            
            if result.status == HealthStatus.HEALTHY:
                self.consecutive_successes += 1
                self.consecutive_failures = 0
            else:
                self.consecutive_failures += 1
                self.consecutive_successes = 0
                
            self.history.append(result)
            return result
        except Exception as e:
            elapsed = (time.perf_counter() - start) * 1000
            self.consecutive_failures += 1
            self.consecutive_successes = 0
            result = HealthCheckResult(
                module_name=self.module_name,
                status=HealthStatus.UNHEALTHY,
                message=f"Health check failed: {str(e)}",
                response_time_ms=elapsed
            )
            self.history.append(result)
            return result
    
    def get_status_summary(self) -> Dict[str, Any]:
        if not self.history:
            return {"status": HealthStatus.UNKNOWN.value, "history_count": 0}
        
        recent = list(self.history)[-10:]
        healthy_count = sum(1 for r in recent if r.status == HealthStatus.HEALTHY)
        
        if healthy_count >= 9:
            overall = HealthStatus.HEALTHY
        elif healthy_count >= 5:
            overall = HealthStatus.DEGRADED
        else:
            overall = HealthStatus.UNHEALTHY
            
        return {
            "module_name": self.module_name,
            "current_status": overall.value,
            "consecutive_failures": self.consecutive_failures,
            "consecutive_successes": self.consecutive_successes,
            "avg_response_ms": sum(r.response_time_ms for r in recent) / len(recent),
            "history_count": len(self.history)
        }


class MetricsCollector:
    """Prometheus-style metrics collection - OPT-IN only"""
    
    def __init__(self, enabled: bool = False):
        self.enabled = enabled
        self._counters: Dict[str, float] = defaultdict(float)
        self._gauges: Dict[str, float] = {}
        self._histograms: Dict[str, List[float]] = defaultdict(list)
        self._timers: Dict[str, List[float]] = defaultdict(list)
        self._labels: Dict[str, Dict[str, str]] = defaultdict(dict)
        self._lock = threading.Lock()
    
    def increment_counter(self, name: str, value: float = 1.0, labels: Optional[Dict[str, str]] = None):
        if not self.enabled:
            return
        with self._lock:
            key = self._make_key(name, labels)
            self._counters[key] += value
            self._labels[key] = labels or {}
    
    def set_gauge(self, name: str, value: float, labels: Optional[Dict[str, str]] = None):
        if not self.enabled:
            return
        with self._lock:
            key = self._make_key(name, labels)
            self._gauges[key] = value
            self._labels[key] = labels or {}
    
    def record_histogram(self, name: str, value: float, labels: Optional[Dict[str, str]] = None):
        if not self.enabled:
            return
        with self._lock:
            key = self._make_key(name, labels)
            self._histograms[key].append(value)
            if len(self._histograms[key]) > 1000:
                self._histograms[key] = self._histograms[key][-500:]
            self._labels[key] = labels or {}
    
    def record_timer(self, name: str, duration_ms: float, labels: Optional[Dict[str, str]] = None):
        if not self.enabled:
            return
        with self._lock:
            key = self._make_key(name, labels)
            self._timers[key].append(duration_ms)
            if len(self._timers[key]) > 1000:
                self._timers[key] = self._timers[key][-500:]
            self._labels[key] = labels or {}
    
    def _make_key(self, name: str, labels: Optional[Dict[str, str]]) -> str:
        if not labels:
            return name
        sorted_labels = sorted(labels.items())
        label_str = ",".join(f"{k}={v}" for k, v in sorted_labels)
        return f"{name}[{label_str}]"
    
    def get_prometheus_format(self) -> str:
        if not self.enabled:
            return "# Metrics collection disabled"
        
        lines = []
        with self._lock:
            for key, value in self._counters.items():
                lines.append(f"neuralshield_counter_{key} {value}")
            for key, value in self._gauges.items():
                lines.append(f"neuralshield_gauge_{key} {value}")
        return "\n".join(lines)
    
    def get_summary(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "counters_count": len(self._counters),
                "gauges_count": len(self._gauges),
                "histograms_count": len(self._histograms),
                "timers_count": len(self._timers),
                "enabled": self.enabled
            }


class DistributedTracer:
    """Distributed tracing - OPT-IN, zero overhead when disabled"""
    
    def __init__(self, enabled: bool = False):
        self.enabled = enabled
        self._spans: Dict[str, TraceSpan] = {}
        self._active_spans: Dict[str, str] = {}  # thread_id -> span_id
        self._lock = threading.Lock()
    
    def start_span(self, operation_name: str, parent_span_id: Optional[str] = None) -> str:
        if not self.enabled:
            return ""
        
        trace_id = str(uuid.uuid4())
        span_id = str(uuid.uuid4())
        
        span = TraceSpan(
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=parent_span_id,
            operation_name=operation_name,
            start_time=time.perf_counter()
        )
        
        with self._lock:
            self._spans[span_id] = span
            thread_id = str(threading.get_ident())
            self._active_spans[thread_id] = span_id
        
        return span_id
    
    def end_span(self, span_id: str, attributes: Optional[Dict[str, Any]] = None):
        if not self.enabled or not span_id:
            return
        
        with self._lock:
            if span_id in self._spans:
                self._spans[span_id].end_time = time.perf_counter()
                if attributes:
                    self._spans[span_id].attributes.update(attributes)
    
    def add_event(self, span_id: str, event_name: str, attributes: Optional[Dict[str, Any]] = None):
        if not self.enabled or not span_id:
            return
        
        with self._lock:
            if span_id in self._spans:
                self._spans[span_id].events.append({
                    "name": event_name,
                    "timestamp": time.perf_counter(),
                    "attributes": attributes or {}
                })
    
    def get_trace_summary(self, trace_id: str) -> Dict[str, Any]:
        if not self.enabled:
            return {"enabled": False}
        
        spans = [s for s in self._spans.values() if s.trace_id == trace_id]
        if not spans:
            return {"spans": 0}
        
        total_duration = sum(
            (s.end_time - s.start_time) for s in spans if s.end_time
        )
        
        return {
            "trace_id": trace_id,
            "span_count": len(spans),
            "completed_spans": sum(1 for s in spans if s.end_time),
            "total_duration_ms": total_duration * 1000
        }


class UnifiedObservabilityDashboard:
    """
    Central observability dashboard for NeuralShield
    ALL INSTRUMENTATION IS OPT-IN - DISABLED BY DEFAULT
    
    Usage:
        dashboard = UnifiedObservabilityDashboard(enabled=False)
        dashboard.enable()  # Only if explicitly requested
    """
    
    def __init__(self, enabled: bool = False):
        self.enabled = enabled
        self._health_checkers: Dict[str, ModuleHealthChecker] = {}
        self.metrics = MetricsCollector(enabled=enabled)
        self.tracer = DistributedTracer(enabled=enabled)
        self._alerts: List[Dict[str, Any]] = []
        self._start_time = datetime.utcnow()
        self._lock = threading.Lock()
    
    def enable(self):
        """Explicitly enable observability - OPT-IN"""
        self.enabled = True
        self.metrics.enabled = True
        self.tracer.enabled = True
    
    def disable(self):
        self.enabled = False
        self.metrics.enabled = False
        self.tracer.enabled = False
    
    def register_module_health_check(
        self, 
        module_name: str, 
        check_function: Optional[Callable] = None
    ):
        """Register a module for health monitoring - wraps existing module"""
        checker = ModuleHealthChecker(module_name, check_function)
        with self._lock:
            self._health_checkers[module_name] = checker
    
    def run_all_health_checks(self) -> Dict[str, Any]:
        if not self.enabled:
            return {"enabled": False, "message": "Observability disabled"}
        
        results = {}
        for name, checker in self._health_checkers.items():
            results[name] = checker.run_check()
        
        summary = self._calculate_overall_health(results)
        self.metrics.increment_counter("health_checks_run")
        return summary
    
    def _calculate_overall_health(self, results: Dict[str, HealthCheckResult]) -> Dict[str, Any]:
        healthy = sum(1 for r in results.values() if r.status == HealthStatus.HEALTHY)
        degraded = sum(1 for r in results.values() if r.status == HealthStatus.DEGRADED)
        unhealthy = sum(1 for r in results.values() if r.status == HealthStatus.UNHEALTHY)
        total = len(results)
        
        if total == 0:
            overall = HealthStatus.UNKNOWN
        elif unhealthy > 0:
            overall = HealthStatus.UNHEALTHY
        elif degraded > 0:
            overall = HealthStatus.DEGRADED
        else:
            overall = HealthStatus.HEALTHY
        
        return {
            "overall_status": overall.value,
            "modules_healthy": healthy,
            "modules_degraded": degraded,
            "modules_unhealthy": unhealthy,
            "total_monitored": total,
            "uptime_seconds": (datetime.utcnow() - self._start_time).total_seconds(),
            "check_results": {k: v.status.value for k, v in results.items()}
        }
    
    def instrument_function(self, module_name: str, metric_name: str):
        """
        Decorator to instrument existing functions - NO CODE MODIFICATION
        Wraps existing functions with timing and metrics
        """
        def decorator(func):
            def wrapper(*args, **kwargs):
                if not self.enabled:
                    return func(*args, **kwargs)
                
                start = time.perf_counter()
                span_id = self.tracer.start_span(f"{module_name}.{func.__name__}")
                
                try:
                    result = func(*args, **kwargs)
                    elapsed = (time.perf_counter() - start) * 1000
                    
                    self.metrics.record_timer(f"{metric_name}_duration", elapsed)
                    self.metrics.increment_counter(f"{metric_name}_calls")
                    self.tracer.end_span(span_id, {"success": True})
                    
                    return result
                except Exception as e:
                    elapsed = (time.perf_counter() - start) * 1000
                    self.metrics.increment_counter(f"{metric_name}_errors")
                    self.tracer.end_span(span_id, {"success": False, "error": str(e)})
                    raise
                    
            return wrapper
        return decorator
    
    def get_dashboard_status(self) -> Dict[str, Any]:
        """Get complete dashboard status"""
        health_summaries = {
            name: checker.get_status_summary()
            for name, checker in self._health_checkers.items()
        }
        
        return {
            "enabled": self.enabled,
            "uptime_seconds": (datetime.utcnow() - self._start_time).total_seconds(),
            "modules_monitored": len(self._health_checkers),
            "health_summaries": health_summaries,
            "metrics_summary": self.metrics.get_summary(),
            "alert_count": len(self._alerts)
        }
    
    def export_json(self) -> str:
        return json.dumps(self.get_dashboard_status(), indent=2, default=str)


# Singleton instance - OPT-IN, disabled by default
_global_dashboard = UnifiedObservabilityDashboard(enabled=False)


def get_observability_dashboard() -> UnifiedObservabilityDashboard:
    """Get the global observability dashboard - disabled by default"""
    return _global_dashboard


def enable_observability():
    """Explicitly enable - must be called intentionally"""
    _global_dashboard.enable()


def disable_observability():
    _global_dashboard.disable()


"""
BACKWARD COMPATIBILITY GUARANTEE:
- All existing code works exactly as before
- Zero overhead when disabled (default)
- No modifications to any existing module
- Pure wrapper layer on top
"""
