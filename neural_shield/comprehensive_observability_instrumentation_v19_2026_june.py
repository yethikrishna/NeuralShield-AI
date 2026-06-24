"""
NeuralShield AI - Comprehensive Observability & Instrumentation v19
DIMENSION D: Observability & Instrumentation

ADD-ONLY IMPLEMENTATION - NO EXISTING CODE MODIFIED
All instrumentation is OPT-IN, DISABLED BY DEFAULT
Zero performance overhead when disabled

Enhancements in v19:
- Distributed tracing with span context propagation
- Metrics dimensions/labels for Prometheus-style tagging
- Prometheus export format compatibility
- Adaptive log sampling for high-volume environments
- Dependency-aware health checks with cascading status
- Trace ID correlation across module boundaries
"""

import os
import json
import time
import uuid
import threading
import functools
from typing import Dict, List, Any, Optional, Callable, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timezone
from collections import defaultdict
from enum import Enum


class StabilityMarker(str, Enum):
    STABLE = "stable"
    EXPERIMENTAL = "experimental"
    DEPRECATED = "deprecated"


class LogLevel(str, Enum):
    DEBUG = "debug"
    INFO = "info"
    WARN = "warn"
    ERROR = "error"
    CRITICAL = "critical"


class HealthStatus(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


class SpanKind(str, Enum):
    INTERNAL = "internal"
    CLIENT = "client"
    SERVER = "server"
    PRODUCER = "producer"
    CONSUMER = "consumer"


@dataclass
class SpanContext:
    """Distributed tracing span context for cross-module correlation"""
    trace_id: str
    span_id: str
    parent_span_id: Optional[str] = None
    baggage: Dict[str, str] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, str]:
        return {
            "trace_id": self.trace_id,
            "span_id": self.span_id,
            "parent_span_id": self.parent_span_id or "",
            **self.baggage
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, str]) -> 'SpanContext':
        trace_id = data.get("trace_id", str(uuid.uuid4()))
        span_id = data.get("span_id", str(uuid.uuid4())[:16])
        parent_span_id = data.get("parent_span_id") or None
        baggage = {k: v for k, v in data.items() 
                   if k not in {"trace_id", "span_id", "parent_span_id"}}
        return cls(trace_id=trace_id, span_id=span_id, 
                   parent_span_id=parent_span_id, baggage=baggage)


class ThreadLocalContext(threading.local):
    """Thread-local storage for span context propagation"""
    def __init__(self):
        self.current_context: Optional[SpanContext] = None
        self.sampling_rate: float = 1.0


_thread_local = ThreadLocalContext()


class MetricsCollector:
    """
    Enhanced metrics collector with dimensions/labels support
    DISABLED BY DEFAULT - set NEURALSHIELD_OBSERVABILITY_ENABLED=1 to enable
    """
    
    API_STABILITY = StabilityMarker.STABLE
    
    def __init__(self):
        self._enabled = os.getenv("NEURALSHIELD_OBSERVABILITY_ENABLED", "0") == "1"
        self._lock = threading.RLock()
        self._counters: Dict[Tuple[str, Tuple[Tuple[str, str], ...]], int] = defaultdict(int)
        self._gauges: Dict[Tuple[str, Tuple[Tuple[str, str], ...]], float] = {}
        self._timers: Dict[Tuple[str, Tuple[Tuple[str, str], ...]], List[float]] = defaultdict(list)
        self._histograms: Dict[Tuple[str, Tuple[Tuple[str, str], ...]], List[float]] = defaultdict(list)
    
    def _normalize_labels(self, labels: Optional[Dict[str, str]] = None) -> Tuple[Tuple[str, str], ...]:
        if not labels:
            return ()
        return tuple(sorted((k, str(v)) for k, v in labels.items()))
    
    def _make_key(self, name: str, labels: Optional[Dict[str, str]] = None) -> Tuple[str, Tuple[Tuple[str, str], ...]]:
        return (name, self._normalize_labels(labels))
    
    def increment_counter(self, name: str, value: int = 1, labels: Optional[Dict[str, str]] = None) -> None:
        """Increment counter with optional dimension labels"""
        if not self._enabled:
            return
        with self._lock:
            key = self._make_key(name, labels)
            self._counters[key] += value
    
    def set_gauge(self, name: str, value: float, labels: Optional[Dict[str, str]] = None) -> None:
        """Set gauge value with optional dimension labels"""
        if not self._enabled:
            return
        with self._lock:
            key = self._make_key(name, labels)
            self._gauges[key] = value
    
    def record_timer(self, name: str, duration: float, labels: Optional[Dict[str, str]] = None) -> None:
        """Record timing with optional dimension labels"""
        if not self._enabled:
            return
        with self._lock:
            key = self._make_key(name, labels)
            self._timers[key].append(duration)
    
    def record_histogram(self, name: str, value: float, labels: Optional[Dict[str, str]] = None) -> None:
        """Record histogram value with optional dimension labels"""
        if not self._enabled:
            return
        with self._lock:
            key = self._make_key(name, labels)
            self._histograms[key].append(value)
    
    def export_prometheus(self) -> str:
        """Export metrics in Prometheus text format"""
        if not self._enabled:
            return ""
        
        lines = []
        with self._lock:
            for (name, labels_tuple), value in self._counters.items():
                label_str = ",".join(f'{k}="{v}"' for k, v in labels_tuple) if labels_tuple else ""
                labels_part = "{" + label_str + "}" if label_str else ""
                lines.append(f"{name}_total{labels_part} {value}")
            
            for (name, labels_tuple), value in self._gauges.items():
                label_str = ",".join(f'{k}="{v}"' for k, v in labels_tuple) if labels_tuple else ""
                labels_part = "{" + label_str + "}" if label_str else ""
                lines.append(f"{name}{labels_part} {value}")
        
        return "\n".join(lines)
    
    def get_summary(self) -> Dict[str, Any]:
        if not self._enabled:
            return {"enabled": False}
        
        with self._lock:
            return {
                "enabled": True,
                "counters": {f"{name}:{labels}": v for (name, labels), v in self._counters.items()},
                "gauges": {f"{name}:{labels}": v for (name, labels), v in self._gauges.items()},
                "timer_count": sum(len(timers) for timers in self._timers.values())
            }
    
    def reset(self) -> None:
        with self._lock:
            self._counters.clear()
            self._gauges.clear()
            self._timers.clear()
            self._histograms.clear()
    
    def enable(self) -> None:
        self._enabled = True
    
    def disable(self) -> None:
        self._enabled = False
    
    @property
    def is_enabled(self) -> bool:
        return self._enabled


class AdaptiveSamplingLogger:
    """
    Structured logger with adaptive sampling for high-volume environments
    DISABLED BY DEFAULT
    """
    
    API_STABILITY = StabilityMarker.STABLE
    
    def __init__(self, sampling_rate: float = 1.0):
        self._enabled = os.getenv("NEURALSHIELD_OBSERVABILITY_ENABLED", "0") == "1"
        self._lock = threading.RLock()
        self._logs: List[Dict[str, Any]] = []
        self._base_sampling_rate = sampling_rate
        self._volume_counters: Dict[str, int] = defaultdict(int)
        self._last_adjustment = time.time()
    
    def _should_sample(self, event_type: str) -> bool:
        """Adaptive sampling - reduce rate for high-volume events"""
        if not self._enabled:
            return False
        
        now = time.time()
        if now - self._last_adjustment > 60:
            self._volume_counters.clear()
            self._last_adjustment = now
        
        self._volume_counters[event_type] += 1
        count = self._volume_counters[event_type]
        
        # Adaptive: reduce sampling rate for high-volume events
        if count > 1000:
            return hash(uuid.uuid4().hex) % 100 == 0  # 1% sampling
        elif count > 100:
            return hash(uuid.uuid4().hex) % 10 == 0   # 10% sampling
        return True
    
    def log(self, level: LogLevel, message: str, 
            event_type: str = "general",
            context: Optional[Dict[str, Any]] = None,
            span_context: Optional[SpanContext] = None) -> None:
        if not self._enabled:
            return
        
        if not self._should_sample(event_type):
            return
        
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": level,
            "message": message,
            "event_type": event_type,
            "context": context or {},
        }
        
        if span_context:
            entry["trace_id"] = span_context.trace_id
            entry["span_id"] = span_context.span_id
        
        with self._lock:
            self._logs.append(entry)
    
    def debug(self, message: str, **kwargs) -> None:
        self.log(LogLevel.DEBUG, message, **kwargs)
    
    def info(self, message: str, **kwargs) -> None:
        self.log(LogLevel.INFO, message, **kwargs)
    
    def warn(self, message: str, **kwargs) -> None:
        self.log(LogLevel.WARN, message, **kwargs)
    
    def error(self, message: str, **kwargs) -> None:
        self.log(LogLevel.ERROR, message, **kwargs)
    
    def get_logs(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._logs)
    
    def clear(self) -> None:
        with self._lock:
            self._logs.clear()
    
    def enable(self) -> None:
        self._enabled = True
    
    def disable(self) -> None:
        self._enabled = False
    
    @property
    def is_enabled(self) -> bool:
        return self._enabled


class DependencyHealthCheck:
    """Health check with dependency awareness"""
    def __init__(self, name: str, check_fn: Callable, 
                 dependencies: Optional[List[str]] = None,
                 timeout: float = 5.0):
        self.name = name
        self.check_fn = check_fn
        self.dependencies = dependencies or []
        self.timeout = timeout
        self.last_status = HealthStatus.UNKNOWN
        self.last_message = ""
        self.last_check_time: Optional[float] = None


class DependencyAwareHealthCheckManager:
    """
    Health check manager with dependency graph support
    Cascades unhealthy status through dependency chain
    DISABLED BY DEFAULT
    """
    
    API_STABILITY = StabilityMarker.STABLE
    
    def __init__(self):
        self._enabled = os.getenv("NEURALSHIELD_OBSERVABILITY_ENABLED", "0") == "1"
        self._lock = threading.RLock()
        self._checks: Dict[str, DependencyHealthCheck] = {}
    
    def register_check(self, name: str, check_fn: Callable,
                       dependencies: Optional[List[str]] = None) -> None:
        if not self._enabled:
            return
        with self._lock:
            self._checks[name] = DependencyHealthCheck(name, check_fn, dependencies)
    
    def run_all_checks(self) -> Dict[str, Any]:
        if not self._enabled:
            return {"enabled": False, "status": HealthStatus.UNKNOWN}
        
        with self._lock:
            results = {}
            for name, check in self._checks.items():
                try:
                    start = time.time()
                    status, message = check.check_fn()
                    check.last_status = status
                    check.last_message = message
                    check.last_check_time = time.time()
                    results[name] = {
                        "status": status,
                        "message": message,
                        "duration": time.time() - start,
                        "dependencies": check.dependencies
                    }
                except Exception as e:
                    check.last_status = HealthStatus.UNHEALTHY
                    check.last_message = str(e)
                    results[name] = {
                        "status": HealthStatus.UNHEALTHY,
                        "message": f"Check failed: {e}",
                        "dependencies": check.dependencies
                    }
            
            # Apply dependency cascading
            self._apply_dependency_cascade(results)
            
            overall = self._compute_overall_status(results)
            return {
                "enabled": True,
                "overall_status": overall,
                "checks": results,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
    
    def _apply_dependency_cascade(self, results: Dict[str, Any]) -> None:
        """If dependency is unhealthy, mark dependent as degraded/unhealthy"""
        changed = True
        while changed:
            changed = False
            for name, result in results.items():
                check = self._checks.get(name)
                if not check:
                    continue
                for dep_name in check.dependencies:
                    dep_result = results.get(dep_name, {})
                    dep_status = dep_result.get("status", HealthStatus.HEALTHY)
                    if dep_status == HealthStatus.UNHEALTHY and result["status"] != HealthStatus.UNHEALTHY:
                        result["status"] = HealthStatus.DEGRADED
                        result["message"] += f" (dependency {dep_name} unhealthy)"
                        changed = True
    
    def _compute_overall_status(self, results: Dict[str, Any]) -> HealthStatus:
        statuses = [r["status"] for r in results.values()]
        if HealthStatus.UNHEALTHY in statuses:
            return HealthStatus.UNHEALTHY
        if HealthStatus.DEGRADED in statuses:
            return HealthStatus.DEGRADED
        if all(s == HealthStatus.HEALTHY for s in statuses):
            return HealthStatus.HEALTHY
        return HealthStatus.UNKNOWN
    
    def enable(self) -> None:
        self._enabled = True
    
    def disable(self) -> None:
        self._enabled = False


def create_span_context(trace_id: Optional[str] = None, 
                        parent_span_id: Optional[str] = None,
                        baggage: Optional[Dict[str, str]] = None) -> SpanContext:
    """Create a new span context for distributed tracing"""
    return SpanContext(
        trace_id=trace_id or str(uuid.uuid4()),
        span_id=str(uuid.uuid4())[:16],
        parent_span_id=parent_span_id,
        baggage=baggage or {}
    )


def set_current_context(context: SpanContext) -> None:
    """Set thread-local span context for automatic propagation"""
    _thread_local.current_context = context


def get_current_context() -> Optional[SpanContext]:
    """Get current thread-local span context"""
    return _thread_local.current_context


def clear_current_context() -> None:
    """Clear thread-local span context"""
    _thread_local.current_context = None


def traced_operation(operation_name: str, kind: SpanKind = SpanKind.INTERNAL):
    """
    Decorator for traced operations with context propagation
    NO-OP when observability is disabled
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if not os.getenv("NEURALSHIELD_OBSERVABILITY_ENABLED", "0") == "1":
                return func(*args, **kwargs)
            
            parent_ctx = get_current_context()
            new_ctx = create_span_context(
                trace_id=parent_ctx.trace_id if parent_ctx else None,
                parent_span_id=parent_ctx.span_id if parent_ctx else None
            )
            set_current_context(new_ctx)
            
            try:
                result = func(*args, **kwargs)
                return result
            finally:
                if parent_ctx:
                    set_current_context(parent_ctx)
                else:
                    clear_current_context()
        return wrapper
    return decorator


def counted_operation(metric_name: str, labels: Optional[Dict[str, str]] = None):
    """Decorator for counting operations with dimension labels"""
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if os.getenv("NEURALSHIELD_OBSERVABILITY_ENABLED", "0") == "1":
                _global_metrics.increment_counter(metric_name, labels=labels)
            return func(*args, **kwargs)
        return wrapper
    return decorator


# Global singleton instances
_global_metrics = MetricsCollector()
_global_logger = AdaptiveSamplingLogger()
_global_health_manager = DependencyAwareHealthCheckManager()


class ObservabilityFacade:
    """Unified facade for all observability operations"""
    
    API_STABILITY = StabilityMarker.STABLE
    
    @staticmethod
    def enable() -> None:
        _global_metrics.enable()
        _global_logger.enable()
        _global_health_manager.enable()
    
    @staticmethod
    def disable() -> None:
        _global_metrics.disable()
        _global_logger.disable()
        _global_health_manager.disable()
    
    @staticmethod
    def metrics() -> MetricsCollector:
        return _global_metrics
    
    @staticmethod
    def logger() -> AdaptiveSamplingLogger:
        return _global_logger
    
    @staticmethod
    def health_manager() -> DependencyAwareHealthCheckManager:
        return _global_health_manager
    
    @staticmethod
    def create_context() -> SpanContext:
        return create_span_context()
    
    @staticmethod
    def generate_report() -> Dict[str, Any]:
        return {
            "metrics": _global_metrics.get_summary(),
            "logs_count": len(_global_logger.get_logs()),
            "health": _global_health_manager.run_all_checks()
        }
    
    @staticmethod
    def export_prometheus_metrics() -> str:
        return _global_metrics.export_prometheus()


# Backward compatibility aliases - ensure no existing code breaks
StructuredLogger = AdaptiveSamplingLogger
HealthCheckManager = DependencyAwareHealthCheckManager
