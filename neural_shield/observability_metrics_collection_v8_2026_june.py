"""
Observability Metrics Collection v8 - NeuralShield-AI
====================================================
DIMENSION D - Observability & Instrumentation v8

ADD-ONLY IMPLEMENTATION: No existing code modified
OPT-IN DESIGN: Disabled by default, zero overhead when off

Features:
- Counters (increment, decrement, reset)
- Timers (start/stop, context manager, decorator)
- Gauges (set, increment, decrement)
- Histograms (percentile calculation, bucket aggregation)
- Thread-safe operations
- Memory-bounded collections
- Metrics export (JSON, dict)
- Registry pattern for global access
- OPT-IN: Must call enable() explicitly

Philosophy: If it ain't broke, don't rewrite it.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Callable, TypeVar, Generic
from datetime import datetime, timezone
import threading
import time
import math
import json
from collections import defaultdict
from functools import wraps


class MetricType(Enum):
    COUNTER = "counter"
    TIMER = "timer"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"


class MetricStatus(Enum):
    DISABLED = "disabled"
    ENABLED = "enabled"


F = TypeVar('F', bound=Callable[..., Any])


@dataclass
class Counter:
    """Thread-safe counter metric for counting occurrences."""
    name: str
    description: str = ""
    labels: Dict[str, str] = field(default_factory=dict)
    _value: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def increment(self, amount: int = 1) -> None:
        """Increment counter by amount (default: 1)."""
        with self._lock:
            self._value += max(0, amount)

    def decrement(self, amount: int = 1) -> None:
        """Decrement counter by amount (cannot go below 0)."""
        with self._lock:
            self._value = max(0, self._value - amount)

    def reset(self) -> None:
        """Reset counter to zero."""
        with self._lock:
            self._value = 0

    @property
    def value(self) -> int:
        """Get current counter value."""
        with self._lock:
            return self._value

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": MetricType.COUNTER.value,
            "name": self.name,
            "description": self.description,
            "labels": self.labels,
            "value": self.value,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }


@dataclass
class Timer:
    """Thread-safe timer metric for measuring durations."""
    name: str
    description: str = ""
    labels: Dict[str, str] = field(default_factory=dict)
    _durations: List[float] = field(default_factory=list)
    _active: Dict[int, float] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _max_samples: int = 10000

    def start(self) -> int:
        """Start timing, returns timer ID."""
        timer_id = threading.get_ident()
        with self._lock:
            self._active[timer_id] = time.perf_counter()
        return timer_id

    def stop(self, timer_id: Optional[int] = None) -> float:
        """Stop timing, returns duration in seconds."""
        tid = timer_id or threading.get_ident()
        end_time = time.perf_counter()
        with self._lock:
            start_time = self._active.pop(tid, end_time)
            duration = max(0.0, end_time - start_time)
            if len(self._durations) >= self._max_samples:
                self._durations.pop(0)
            self._durations.append(duration)
        return duration

    def __enter__(self) -> 'Timer':
        self.start()
        return self

    def __exit__(self, *args) -> None:
        self.stop()

    @property
    def count(self) -> int:
        with self._lock:
            return len(self._durations)

    @property
    def total(self) -> float:
        with self._lock:
            return sum(self._durations)

    @property
    def avg(self) -> float:
        with self._lock:
            if not self._durations:
                return 0.0
            return sum(self._durations) / len(self._durations)

    @property
    def min(self) -> float:
        with self._lock:
            return min(self._durations) if self._durations else 0.0

    @property
    def max(self) -> float:
        with self._lock:
            return max(self._durations) if self._durations else 0.0

    @property
    def p50(self) -> float:
        return self.percentile(50)

    @property
    def p95(self) -> float:
        return self.percentile(95)

    @property
    def p99(self) -> float:
        return self.percentile(99)

    def percentile(self, p: float) -> float:
        """Calculate percentile (0-100)."""
        with self._lock:
            if not self._durations:
                return 0.0
            sorted_durs = sorted(self._durations)
            idx = min(int(len(sorted_durs) * p / 100), len(sorted_durs) - 1)
            return sorted_durs[idx]

    def reset(self) -> None:
        """Clear all recorded durations."""
        with self._lock:
            self._durations.clear()
            self._active.clear()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": MetricType.TIMER.value,
            "name": self.name,
            "description": self.description,
            "labels": self.labels,
            "count": self.count,
            "total_seconds": round(self.total, 6),
            "avg_seconds": round(self.avg, 6),
            "min_seconds": round(self.min, 6),
            "max_seconds": round(self.max, 6),
            "p50_seconds": round(self.p50, 6),
            "p95_seconds": round(self.p95, 6),
            "p99_seconds": round(self.p99, 6),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }


@dataclass
class Gauge:
    """Thread-safe gauge metric for point-in-time values."""
    name: str
    description: str = ""
    labels: Dict[str, str] = field(default_factory=dict)
    _value: float = 0.0
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def set(self, value: float) -> None:
        """Set gauge to specific value."""
        with self._lock:
            self._value = float(value)

    def increment(self, amount: float = 1.0) -> None:
        """Increment gauge by amount."""
        with self._lock:
            self._value += float(amount)

    def decrement(self, amount: float = 1.0) -> None:
        """Decrement gauge by amount."""
        with self._lock:
            self._value -= float(amount)

    @property
    def value(self) -> float:
        with self._lock:
            return self._value

    def reset(self) -> None:
        with self._lock:
            self._value = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": MetricType.GAUGE.value,
            "name": self.name,
            "description": self.description,
            "labels": self.labels,
            "value": self.value,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }


DEFAULT_BUCKETS = [0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]


@dataclass
class Histogram:
    """Thread-safe histogram with bucket aggregation."""
    name: str
    description: str = ""
    labels: Dict[str, str] = field(default_factory=dict)
    buckets: List[float] = field(default_factory=lambda: DEFAULT_BUCKETS.copy())
    _counts: Dict[float, int] = field(default_factory=lambda: defaultdict(int))
    _values: List[float] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _max_samples: int = 10000

    def observe(self, value: float) -> None:
        """Record a value observation."""
        with self._lock:
            for bucket in self.buckets:
                if value <= bucket:
                    self._counts[bucket] += 1
            self._counts[float('inf')] += 1
            if len(self._values) >= self._max_samples:
                self._values.pop(0)
            self._values.append(value)

    @property
    def count(self) -> int:
        with self._lock:
            return self._counts.get(float('inf'), 0)

    @property
    def sum(self) -> float:
        with self._lock:
            return sum(self._values)

    @property
    def avg(self) -> float:
        with self._lock:
            if not self._values:
                return 0.0
            return sum(self._values) / len(self._values)

    def percentile(self, p: float) -> float:
        with self._lock:
            if not self._values:
                return 0.0
            sorted_vals = sorted(self._values)
            idx = min(int(len(sorted_vals) * p / 100), len(sorted_vals) - 1)
            return sorted_vals[idx]

    def get_bucket_counts(self) -> Dict[str, int]:
        with self._lock:
            return {str(b): self._counts.get(b, 0) for b in self.buckets + [float('inf')]}

    def reset(self) -> None:
        with self._lock:
            self._counts.clear()
            self._values.clear()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": MetricType.HISTOGRAM.value,
            "name": self.name,
            "description": self.description,
            "labels": self.labels,
            "count": self.count,
            "sum": round(self.sum, 6),
            "avg": round(self.avg, 6),
            "buckets": self.get_bucket_counts(),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }


class NoOpCounter:
    """No-op counter for when metrics are disabled."""
    def increment(self, amount: int = 1) -> None: pass
    def decrement(self, amount: int = 1) -> None: pass
    def reset(self) -> None: pass
    @property
    def value(self) -> int: return 0
    def to_dict(self) -> Dict[str, Any]: return {}


class NoOpTimer:
    """No-op timer for when metrics are disabled."""
    def start(self) -> int: return 0
    def stop(self, timer_id: Optional[int] = None) -> float: return 0.0
    def __enter__(self) -> 'NoOpTimer': return self
    def __exit__(self, *args) -> None: pass
    @property
    def count(self) -> int: return 0
    @property
    def total(self) -> float: return 0.0
    @property
    def avg(self) -> float: return 0.0
    @property
    def min(self) -> float: return 0.0
    @property
    def max(self) -> float: return 0.0
    @property
    def p50(self) -> float: return 0.0
    @property
    def p95(self) -> float: return 0.0
    @property
    def p99(self) -> float: return 0.0
    def percentile(self, p: float) -> float: return 0.0
    def reset(self) -> None: pass
    def to_dict(self) -> Dict[str, Any]: return {}


class NoOpGauge:
    """No-op gauge for when metrics are disabled."""
    def set(self, value: float) -> None: pass
    def increment(self, amount: float = 1.0) -> None: pass
    def decrement(self, amount: float = 1.0) -> None: pass
    @property
    def value(self) -> float: return 0.0
    def reset(self) -> None: pass
    def to_dict(self) -> Dict[str, Any]: return {}


class NoOpHistogram:
    """No-op histogram for when metrics are disabled."""
    def observe(self, value: float) -> None: pass
    @property
    def count(self) -> int: return 0
    @property
    def sum(self) -> float: return 0.0
    @property
    def avg(self) -> float: return 0.0
    def percentile(self, p: float) -> float: return 0.0
    def get_bucket_counts(self) -> Dict[str, int]: return {}
    def reset(self) -> None: pass
    def to_dict(self) -> Dict[str, Any]: return {}


class MetricsRegistry:
    """Central registry for all metrics - OPT-IN, disabled by default."""

    def __init__(self):
        self._status = MetricStatus.DISABLED
        self._counters: Dict[str, Counter] = {}
        self._timers: Dict[str, Timer] = {}
        self._gauges: Dict[str, Gauge] = {}
        self._histograms: Dict[str, Histogram] = {}
        self._lock = threading.Lock()

    def enable(self) -> None:
        """Enable metrics collection - OPT-IN required."""
        self._status = MetricStatus.ENABLED

    def disable(self) -> None:
        """Disable metrics collection."""
        self._status = MetricStatus.DISABLED

    @property
    def is_enabled(self) -> bool:
        return self._status == MetricStatus.ENABLED

    def counter(self, name: str, description: str = "", labels: Optional[Dict[str, str]] = None) -> Counter:
        """Get or create a counter."""
        if not self.is_enabled:
            return NoOpCounter()  # type: ignore
        with self._lock:
            if name not in self._counters:
                self._counters[name] = Counter(name, description, labels or {})
            return self._counters[name]

    def timer(self, name: str, description: str = "", labels: Optional[Dict[str, str]] = None) -> Timer:
        """Get or create a timer."""
        if not self.is_enabled:
            return NoOpTimer()  # type: ignore
        with self._lock:
            if name not in self._timers:
                self._timers[name] = Timer(name, description, labels or {})
            return self._timers[name]

    def gauge(self, name: str, description: str = "", labels: Optional[Dict[str, str]] = None) -> Gauge:
        """Get or create a gauge."""
        if not self.is_enabled:
            return NoOpGauge()  # type: ignore
        with self._lock:
            if name not in self._gauges:
                self._gauges[name] = Gauge(name, description, labels or {})
            return self._gauges[name]

    def histogram(self, name: str, description: str = "", labels: Optional[Dict[str, str]] = None,
                  buckets: Optional[List[float]] = None) -> Histogram:
        """Get or create a histogram."""
        if not self.is_enabled:
            return NoOpHistogram()  # type: ignore
        with self._lock:
            if name not in self._histograms:
                self._histograms[name] = Histogram(name, description, labels or {}, buckets or DEFAULT_BUCKETS.copy())
            return self._histograms[name]

    def timed(self, name: str, description: str = "", labels: Optional[Dict[str, str]] = None) -> Callable[[F], F]:
        """Decorator to time function execution."""
        def decorator(func: F) -> F:
            @wraps(func)
            def wrapper(*args, **kwargs):
                if not self.is_enabled:
                    return func(*args, **kwargs)
                timer = self.timer(name, description, labels)
                with timer:
                    return func(*args, **kwargs)
            return wrapper  # type: ignore
        return decorator

    def counted(self, name: str, description: str = "", labels: Optional[Dict[str, str]] = None) -> Callable[[F], F]:
        """Decorator to count function calls."""
        def decorator(func: F) -> F:
            @wraps(func)
            def wrapper(*args, **kwargs):
                if self.is_enabled:
                    self.counter(name, description, labels).increment()
                return func(*args, **kwargs)
            return wrapper  # type: ignore
        return decorator

    def export_dict(self) -> Dict[str, Any]:
        """Export all metrics as dictionary."""
        if not self.is_enabled:
            return {"status": "disabled", "metrics": []}
        with self._lock:
            return {
                "status": "enabled",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "metrics": {
                    "counters": [c.to_dict() for c in self._counters.values()],
                    "timers": [t.to_dict() for t in self._timers.values()],
                    "gauges": [g.to_dict() for g in self._gauges.values()],
                    "histograms": [h.to_dict() for h in self._histograms.values()]
                },
                "summary": {
                    "counters_count": len(self._counters),
                    "timers_count": len(self._timers),
                    "gauges_count": len(self._gauges),
                    "histograms_count": len(self._histograms),
                    "total_metrics": len(self._counters) + len(self._timers) + len(self._gauges) + len(self._histograms)
                }
            }

    def export_json(self, indent: int = 2) -> str:
        """Export all metrics as JSON string."""
        return json.dumps(self.export_dict(), indent=indent)

    def reset_all(self) -> None:
        """Reset all metrics to initial state."""
        with self._lock:
            for counter in self._counters.values():
                counter.reset()
            for timer in self._timers.values():
                timer.reset()
            for gauge in self._gauges.values():
                gauge.reset()
            for histogram in self._histograms.values():
                histogram.reset()


# Global registry - SINGLETON pattern
GLOBAL_METRICS = MetricsRegistry()


# Convenience exports
def enable_metrics() -> None:
    """Enable global metrics collection (OPT-IN required)."""
    GLOBAL_METRICS.enable()


def disable_metrics() -> None:
    """Disable global metrics collection."""
    GLOBAL_METRICS.disable()


def get_global_metrics() -> MetricsRegistry:
    """Get the global metrics registry."""
    return GLOBAL_METRICS


# Module metadata
MODULE_INFO = {
    "name": "observability_metrics_collection_v8",
    "dimension": "D - Observability & Instrumentation",
    "version": "v8",
    "date": "2026-06-23",
    "status": "production-ready",
    "opt_in_required": True,
    "features": ["counters", "timers", "gauges", "histograms", "decorators", "thread-safe", "export"]
}
