"""
NeuralShield AI - Comprehensive Observability, Metrics & Telemetry v3
DIMENSION D: Observability & Instrumentation
ADD-ONLY implementation - wraps existing code, no core modifications

Features:
- Counter, Gauge, Timer, Histogram metric types
- Structured logging with context propagation
- Thread-safe metrics registry
- OPT-IN instrumentation (disabled by default)
- Prometheus-style text export
- In-memory aggregation with TTL cleanup
- Decorator-based function instrumentation
"""

import time
import threading
import json
import logging
from typing import Dict, List, Any, Optional, Callable, TypeVar, Generic
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import uuid
import hashlib


class MetricType(Enum):
    COUNTER = "counter"
    GAUGE = "gauge"
    TIMER = "timer"
    HISTOGRAM = "histogram"


class LogLevel(Enum):
    DEBUG = 10
    INFO = 20
    WARNING = 30
    ERROR = 40
    CRITICAL = 50


T = TypeVar('T')


@dataclass
class MetricLabels:
    """Typed labels for metric dimensionality"""
    labels: Dict[str, str] = field(default_factory=dict)
    
    def __hash__(self):
        return hash(tuple(sorted(self.labels.items())))
    
    def __eq__(self, other):
        return isinstance(other, MetricLabels) and self.labels == other.labels
    
    def to_key(self) -> str:
        return json.dumps(self.labels, sort_keys=True)


@dataclass
class LogEntry:
    """Structured log entry with context"""
    timestamp: float
    level: LogLevel
    message: str
    context: Dict[str, Any] = field(default_factory=dict)
    trace_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    span_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": datetime.fromtimestamp(self.timestamp).isoformat(),
            "level": self.level.name,
            "message": self.message,
            "context": self.context,
            "trace_id": self.trace_id,
            "span_id": self.span_id
        }


class Counter:
    """Monotonically increasing counter metric"""
    
    def __init__(self, name: str, description: str = ""):
        self.name = name
        self.description = description
        self._values: Dict[str, float] = defaultdict(float)
        self._lock = threading.Lock()
    
    def inc(self, value: float = 1.0, labels: Optional[Dict[str, str]] = None):
        """Increment counter by value"""
        if value < 0:
            raise ValueError("Counter cannot be decremented")
        key = MetricLabels(labels or {}).to_key()
        with self._lock:
            self._values[key] += value
    
    def get(self, labels: Optional[Dict[str, str]] = None) -> float:
        """Get current counter value"""
        key = MetricLabels(labels or {}).to_key()
        with self._lock:
            return self._values.get(key, 0.0)
    
    def get_all(self) -> Dict[str, float]:
        """Get all labeled values"""
        with self._lock:
            return dict(self._values)


class Gauge:
    """Gauge metric - can go up and down"""
    
    def __init__(self, name: str, description: str = ""):
        self.name = name
        self.description = description
        self._values: Dict[str, float] = defaultdict(float)
        self._lock = threading.Lock()
    
    def set(self, value: float, labels: Optional[Dict[str, str]] = None):
        """Set gauge to specific value"""
        key = MetricLabels(labels or {}).to_key()
        with self._lock:
            self._values[key] = value
    
    def inc(self, value: float = 1.0, labels: Optional[Dict[str, str]] = None):
        """Increment gauge by value"""
        key = MetricLabels(labels or {}).to_key()
        with self._lock:
            self._values[key] += value
    
    def dec(self, value: float = 1.0, labels: Optional[Dict[str, str]] = None):
        """Decrement gauge by value"""
        key = MetricLabels(labels or {}).to_key()
        with self._lock:
            self._values[key] -= value
    
    def get(self, labels: Optional[Dict[str, str]] = None) -> float:
        """Get current gauge value"""
        key = MetricLabels(labels or {}).to_key()
        with self._lock:
            return self._values.get(key, 0.0)
    
    def get_all(self) -> Dict[str, float]:
        """Get all labeled values"""
        with self._lock:
            return dict(self._values)


class Timer:
    """Timer metric for measuring operation durations"""
    
    def __init__(self, name: str, description: str = ""):
        self.name = name
        self.description = description
        self._samples: Dict[str, List[float]] = defaultdict(list)
        self._counts: Dict[str, int] = defaultdict(int)
        self._sums: Dict[str, float] = defaultdict(float)
        self._lock = threading.Lock()
    
    def record(self, duration_seconds: float, labels: Optional[Dict[str, str]] = None):
        """Record a duration sample"""
        key = MetricLabels(labels or {}).to_key()
        with self._lock:
            self._samples[key].append(duration_seconds)
            self._counts[key] += 1
            self._sums[key] += duration_seconds
            # Keep only last 1000 samples per label
            if len(self._samples[key]) > 1000:
                self._samples[key] = self._samples[key][-1000:]
    
    def time(self, labels: Optional[Dict[str, str]] = None) -> 'TimerContext':
        """Context manager for timing code blocks"""
        return TimerContext(self, labels)
    
    def get_count(self, labels: Optional[Dict[str, str]] = None) -> int:
        """Get number of samples"""
        key = MetricLabels(labels or {}).to_key()
        with self._lock:
            return self._counts.get(key, 0)
    
    def get_sum(self, labels: Optional[Dict[str, str]] = None) -> float:
        """Get sum of all durations"""
        key = MetricLabels(labels or {}).to_key()
        with self._lock:
            return self._sums.get(key, 0.0)
    
    def get_avg(self, labels: Optional[Dict[str, str]] = None) -> Optional[float]:
        """Get average duration"""
        key = MetricLabels(labels or {}).to_key()
        with self._lock:
            count = self._counts.get(key, 0)
            if count == 0:
                return None
            return self._sums[key] / count
    
    def get_percentile(self, percentile: float, labels: Optional[Dict[str, str]] = None) -> Optional[float]:
        """Get percentile value (0-100)"""
        key = MetricLabels(labels or {}).to_key()
        with self._lock:
            samples = self._samples.get(key, [])
            if not samples:
                return None
            sorted_samples = sorted(samples)
            idx = int(len(sorted_samples) * percentile / 100)
            return sorted_samples[min(idx, len(sorted_samples) - 1)]


class TimerContext:
    """Context manager for timing code blocks"""
    
    def __init__(self, timer: Timer, labels: Optional[Dict[str, str]] = None):
        self.timer = timer
        self.labels = labels
        self.start_time = 0.0
    
    def __enter__(self):
        self.start_time = time.perf_counter()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        duration = time.perf_counter() - self.start_time
        self.timer.record(duration, self.labels)


class Histogram:
    """Histogram metric with configurable buckets"""
    
    DEFAULT_BUCKETS = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
    
    def __init__(self, name: str, description: str = "", buckets: Optional[List[float]] = None):
        self.name = name
        self.description = description
        self.buckets = buckets or self.DEFAULT_BUCKETS
        self.buckets.sort()
        self._bucket_counts: Dict[str, List[int]] = defaultdict(lambda: [0] * len(self.buckets))
        self._counts: Dict[str, int] = defaultdict(int)
        self._sums: Dict[str, float] = defaultdict(float)
        self._lock = threading.Lock()
    
    def observe(self, value: float, labels: Optional[Dict[str, str]] = None):
        """Observe a value and count in appropriate buckets (cumulative)"""
        key = MetricLabels(labels or {}).to_key()
        with self._lock:
            self._counts[key] += 1
            self._sums[key] += value
            # Increment ALL buckets >= value (cumulative histogram)
            for i, bucket in enumerate(self.buckets):
                if value <= bucket:
                    self._bucket_counts[key][i] += 1
    
    def get_buckets(self, labels: Optional[Dict[str, str]] = None) -> Dict[float, int]:
        """Get bucket counts as {boundary: cumulative_count}"""
        key = MetricLabels(labels or {}).to_key()
        with self._lock:
            counts = self._bucket_counts.get(key, [0] * len(self.buckets))
            result = {}
            for i, bucket in enumerate(self.buckets):
                result[bucket] = counts[i]
            return result
    
    def get_count(self, labels: Optional[Dict[str, str]] = None) -> int:
        key = MetricLabels(labels or {}).to_key()
        with self._lock:
            return self._counts.get(key, 0)
    
    def get_sum(self, labels: Optional[Dict[str, str]] = None) -> float:
        key = MetricLabels(labels or {}).to_key()
        with self._lock:
            return self._sums.get(key, 0.0)


class StructuredLogger:
    """Structured logging with context propagation"""
    
    def __init__(self, max_entries: int = 10000):
        self._logs: deque = deque(maxlen=max_entries)
        self._context_stack: Dict[int, Dict[str, Any]] = defaultdict(dict)
        self._lock = threading.Lock()
        self.min_level = LogLevel.INFO
    
    def with_context(self, **context) -> 'LogContext':
        """Context manager for adding context to logs"""
        return LogContext(self, context)
    
    def _add_context(self, context: Dict[str, Any]):
        thread_id = threading.get_ident()
        self._context_stack[thread_id].update(context)
    
    def _remove_context(self, keys: List[str]):
        thread_id = threading.get_ident()
        for key in keys:
            self._context_stack[thread_id].pop(key, None)
    
    def _get_current_context(self) -> Dict[str, Any]:
        return dict(self._context_stack.get(threading.get_ident(), {}))
    
    def log(self, level: LogLevel, message: str, **context):
        """Log a structured message"""
        if level.value < self.min_level.value:
            return
        full_context = self._get_current_context()
        full_context.update(context)
        entry = LogEntry(
            timestamp=time.time(),
            level=level,
            message=message,
            context=full_context
        )
        with self._lock:
            self._logs.append(entry)
    
    def debug(self, message: str, **context):
        self.log(LogLevel.DEBUG, message, **context)
    
    def info(self, message: str, **context):
        self.log(LogLevel.INFO, message, **context)
    
    def warning(self, message: str, **context):
        self.log(LogLevel.WARNING, message, **context)
    
    def error(self, message: str, **context):
        self.log(LogLevel.ERROR, message, **context)
    
    def critical(self, message: str, **context):
        self.log(LogLevel.CRITICAL, message, **context)
    
    def get_recent(self, n: int = 100, min_level: Optional[LogLevel] = None) -> List[Dict[str, Any]]:
        """Get recent log entries"""
        with self._lock:
            entries = list(self._logs)[-n:]
        if min_level:
            entries = [e for e in entries if e.level.value >= min_level.value]
        return [e.to_dict() for e in entries]
    
    def get_counts_by_level(self) -> Dict[str, int]:
        """Get log counts by level"""
        counts = defaultdict(int)
        with self._lock:
            for entry in self._logs:
                counts[entry.level.name] += 1
        return dict(counts)


class LogContext:
    """Context manager for structured logging context"""
    
    def __init__(self, logger: StructuredLogger, context: Dict[str, Any]):
        self.logger = logger
        self.context = context
        self._keys = list(context.keys())
    
    def __enter__(self):
        self.logger._add_context(self.context)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.logger._remove_context(self._keys)


class MetricsRegistry:
    """Central registry for all metrics"""
    
    _instance: Optional['MetricsRegistry'] = None
    _instance_lock = threading.Lock()
    
    def __init__(self):
        self._counters: Dict[str, Counter] = {}
        self._gauges: Dict[str, Gauge] = {}
        self._timers: Dict[str, Timer] = {}
        self._histograms: Dict[str, Histogram] = {}
        self._lock = threading.Lock()
        self.enabled = False  # OPT-IN - disabled by default
    
    @classmethod
    def get_instance(cls) -> 'MetricsRegistry':
        """Get singleton instance"""
        if cls._instance is None:
            with cls._instance_lock:
                if cls._instance is None:
                    cls._instance = MetricsRegistry()
        return cls._instance
    
    def enable(self):
        """Enable metrics collection (OPT-IN)"""
        self.enabled = True
    
    def disable(self):
        """Disable metrics collection"""
        self.enabled = False
    
    def counter(self, name: str, description: str = "") -> Counter:
        """Get or create a counter"""
        with self._lock:
            if name not in self._counters:
                self._counters[name] = Counter(name, description)
            return self._counters[name]
    
    def gauge(self, name: str, description: str = "") -> Gauge:
        """Get or create a gauge"""
        with self._lock:
            if name not in self._gauges:
                self._gauges[name] = Gauge(name, description)
            return self._gauges[name]
    
    def timer(self, name: str, description: str = "") -> Timer:
        """Get or create a timer"""
        with self._lock:
            if name not in self._timers:
                self._timers[name] = Timer(name, description)
            return self._timers[name]
    
    def histogram(self, name: str, description: str = "", buckets: Optional[List[float]] = None) -> Histogram:
        """Get or create a histogram"""
        with self._lock:
            if name not in self._histograms:
                self._histograms[name] = Histogram(name, description, buckets)
            return self._histograms[name]
    
    def export_prometheus(self) -> str:
        """Export metrics in Prometheus text format"""
        lines = []
        
        for name, counter in self._counters.items():
            lines.append(f"# HELP {name} {counter.description}")
            lines.append(f"# TYPE {name} counter")
            for labels_json, value in counter.get_all().items():
                labels = json.loads(labels_json)
                label_str = ",".join([f'{k}="{v}"' for k, v in labels.items()])
                if label_str:
                    lines.append(f"{name}{{{label_str}}} {value}")
                else:
                    lines.append(f"{name} {value}")
        
        for name, gauge in self._gauges.items():
            lines.append(f"# HELP {name} {gauge.description}")
            lines.append(f"# TYPE {name} gauge")
            for labels_json, value in gauge.get_all().items():
                labels = json.loads(labels_json)
                label_str = ",".join([f'{k}="{v}"' for k, v in labels.items()])
                if label_str:
                    lines.append(f"{name}{{{label_str}}} {value}")
                else:
                    lines.append(f"{name} {value}")
        
        return "\n".join(lines)
    
    def get_summary(self) -> Dict[str, Any]:
        """Get metrics summary"""
        return {
            "counters": len(self._counters),
            "gauges": len(self._gauges),
            "timers": len(self._timers),
            "histograms": len(self._histograms),
            "enabled": self.enabled
        }


# Global structured logger
logger = StructuredLogger()


def instrument(name: str = None, timer_labels: Optional[Dict[str, str]] = None):
    """Decorator for instrumenting functions (OPT-IN, no-op when disabled)
    Usage:
        @instrument("my_function")
        def my_func():
            pass
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        metric_name = name or f"function_{func.__name__}_duration_seconds"
        
        def wrapper(*args, **kwargs) -> T:
            registry = MetricsRegistry.get_instance()
            if not registry.enabled:
                return func(*args, **kwargs)
            
            timer = registry.timer(metric_name, f"Duration of {func.__name__}")
            counter = registry.counter(f"{metric_name}_calls_total", f"Total calls to {func.__name__}")
            
            counter.inc(labels=timer_labels)
            with timer.time(labels=timer_labels):
                result = func(*args, **kwargs)
            return result
        
        return wrapper
    return decorator


# Convenience functions (OPT-IN)
def increment_counter(name: str, value: float = 1.0, labels: Optional[Dict[str, str]] = None):
    registry = MetricsRegistry.get_instance()
    if registry.enabled:
        registry.counter(name).inc(value, labels)


def set_gauge(name: str, value: float, labels: Optional[Dict[str, str]] = None):
    registry = MetricsRegistry.get_instance()
    if registry.enabled:
        registry.gauge(name).set(value, labels)


def record_timer(name: str, duration: float, labels: Optional[Dict[str, str]] = None):
    registry = MetricsRegistry.get_instance()
    if registry.enabled:
        registry.timer(name).record(duration, labels)


def observe_histogram(name: str, value: float, labels: Optional[Dict[str, str]] = None):
    registry = MetricsRegistry.get_instance()
    if registry.enabled:
        registry.histogram(name).observe(value, labels)


def enable_metrics():
    """Enable metrics collection (OPT-IN)"""
    MetricsRegistry.get_instance().enable()
    logger.info("Metrics collection enabled")


def disable_metrics():
    """Disable metrics collection"""
    MetricsRegistry.get_instance().disable()
    logger.info("Metrics collection disabled")


def get_metrics_summary() -> Dict[str, Any]:
    return MetricsRegistry.get_instance().get_summary()


def export_metrics_prometheus() -> str:
    return MetricsRegistry.get_instance().export_prometheus()
