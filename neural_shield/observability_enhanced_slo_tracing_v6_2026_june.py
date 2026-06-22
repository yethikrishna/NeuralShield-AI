"""
NeuralShield AI - Enhanced Observability & SLO Monitoring V6
DIMENSION D: Observability & Instrumentation
OPT-IN ONLY - Disabled by default

Adds:
- Distributed tracing with context propagation across modules
- SLO (Service Level Objective) monitoring with error budget tracking
- Burn rate alerting for SLO violations
- Latency histogram percentiles (p50, p95, p99, p99.9)
- Performance metrics for threat detection operations
- Health check with dependency tracking

All instrumentation is OPT-IN and does not modify core behavior.
"""

import time
import uuid
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Callable
from enum import Enum
from collections import defaultdict, deque
import json


class SLOStatus(Enum):
    HEALTHY = "healthy"
    WARNING = "warning"
    BREACHING = "breaching"
    EXHAUSTED = "exhausted"


class TraceLevel(Enum):
    DEBUG = "debug"
    INFO = "info"
    WARN = "warn"
    ERROR = "error"


@dataclass
class Span:
    trace_id: str
    span_id: str
    parent_span_id: Optional[str]
    name: str
    start_time: float
    end_time: Optional[float] = None
    attributes: Dict[str, Any] = field(default_factory=dict)
    level: TraceLevel = TraceLevel.INFO


@dataclass
class SLOConfig:
    name: str
    target_percentage: float  # e.g., 99.9 for 99.9% availability
    window_days: int = 30
    description: str = ""


@dataclass
class SLOStatusSnapshot:
    slo_name: str
    current_availability: float
    error_budget_remaining: float
    error_budget_consumed_pct: float
    burn_rate: float
    status: SLOStatus
    window_events: int
    window_errors: int


class ThreadLocalContext:
    """Thread-local storage for trace context propagation"""
    _local = threading.local()
    
    @classmethod
    def get_current_trace_id(cls) -> Optional[str]:
        return getattr(cls._local, 'trace_id', None)
    
    @classmethod
    def set_current_trace_id(cls, trace_id: str):
        cls._local.trace_id = trace_id
    
    @classmethod
    def get_current_span_id(cls) -> Optional[str]:
        return getattr(cls._local, 'span_id', None)
    
    @classmethod
    def set_current_span_id(cls, span_id: str):
        cls._local.span_id = span_id
    
    @classmethod
    def clear(cls):
        cls._local.trace_id = None
        cls._local.span_id = None


class LatencyHistogram:
    """Histogram for latency tracking with percentiles"""
    
    def __init__(self, name: str, buckets: Optional[List[float]] = None):
        self.name = name
        self.buckets = buckets or [0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
        self.counts = [0] * len(self.buckets)
        self.sum = 0.0
        self.total_count = 0
        self._values: deque = deque(maxlen=10000)  # Keep last 10k samples
    
    def record(self, value: float):
        self.sum += value
        self.total_count += 1
        self._values.append(value)
        
        for i, bucket in enumerate(self.buckets):
            if value <= bucket:
                self.counts[i] += 1
                break
    
    def get_percentile(self, p: float) -> float:
        """Get percentile (0-100) from recent samples"""
        if not self._values:
            return 0.0
        sorted_vals = sorted(self._values)
        idx = int(len(sorted_vals) * p / 100)
        return sorted_vals[min(idx, len(sorted_vals) - 1)]
    
    def get_stats(self) -> Dict[str, float]:
        return {
            "p50": self.get_percentile(50),
            "p95": self.get_percentile(95),
            "p99": self.get_percentile(99),
            "p99.9": self.get_percentile(99.9),
            "avg": self.sum / self.total_count if self.total_count > 0 else 0,
            "count": self.total_count
        }


class SLOMonitor:
    """SLO monitoring with error budget tracking and burn rate alerting"""
    
    def __init__(self):
        self._slos: Dict[str, SLOConfig] = {}
        self._event_log: deque = deque(maxlen=100000)  # (timestamp, is_error)
        self._lock = threading.Lock()
    
    def register_slo(self, config: SLOConfig):
        self._slos[config.name] = config
    
    def record_event(self, slo_name: str, is_error: bool = False):
        with self._lock:
            self._event_log.append((time.time(), slo_name, is_error))
    
    def _get_window_events(self, slo_name: str, window_seconds: float):
        cutoff = time.time() - window_seconds
        events = []
        for ts, name, is_error in self._event_log:
            if ts >= cutoff and name == slo_name:
                events.append(is_error)
        return events
    
    def get_slo_status(self, slo_name: str) -> Optional[SLOStatusSnapshot]:
        if slo_name not in self._slos:
            return None
        
        config = self._slos[slo_name]
        window_seconds = config.window_days * 86400
        events = self._get_window_events(slo_name, window_seconds)
        
        if not events:
            return SLOStatusSnapshot(
                slo_name=slo_name,
                current_availability=100.0,
                error_budget_remaining=1.0,
                error_budget_consumed_pct=0.0,
                burn_rate=0.0,
                status=SLOStatus.HEALTHY,
                window_events=0,
                window_errors=0
            )
        
        total_events = len(events)
        total_errors = sum(1 for e in events if e)
        availability = 100.0 * (1 - total_errors / total_events) if total_events > 0 else 100.0
        
        error_budget_total = 1.0 - config.target_percentage / 100.0
        error_budget_used = total_errors / total_events if total_events > 0 else 0
        budget_remaining = max(0.0, error_budget_total - error_budget_used)
        budget_consumed_pct = 100.0 * (1 - budget_remaining / error_budget_total) if error_budget_total > 0 else 0
        
        # Calculate burn rate (1 hour window vs expected)
        hour_events = self._get_window_events(slo_name, 3600)
        hour_errors = sum(1 for e in hour_events if e)
        hour_error_rate = hour_errors / len(hour_events) if hour_events else 0
        allowed_error_rate = 1.0 - config.target_percentage / 100.0
        burn_rate = hour_error_rate / allowed_error_rate if allowed_error_rate > 0 else float('inf')
        
        # Determine status
        if budget_consumed_pct >= 100:
            status = SLOStatus.EXHAUSTED
        elif burn_rate >= 10:
            status = SLOStatus.BREACHING
        elif burn_rate >= 2:
            status = SLOStatus.WARNING
        else:
            status = SLOStatus.HEALTHY
        
        return SLOStatusSnapshot(
            slo_name=slo_name,
            current_availability=round(availability, 4),
            error_budget_remaining=round(budget_remaining, 6),
            error_budget_consumed_pct=round(budget_consumed_pct, 2),
            burn_rate=round(burn_rate, 2),
            status=status,
            window_events=total_events,
            window_errors=total_errors
        )


class EnhancedObservabilityEngine:
    """Main observability engine - OPT-IN ONLY"""
    
    def __init__(self, enabled: bool = False):
        self.enabled = enabled
        self._spans: Dict[str, List[Span]] = defaultdict(list)
        self._histograms: Dict[str, LatencyHistogram] = {}
        self._counters: Dict[str, int] = defaultdict(int)
        self._gauges: Dict[str, float] = {}
        self._slo_monitor = SLOMonitor()
        self._health_checks: Dict[str, Callable] = {}
        self._lock = threading.Lock()
        
        # Default SLO configurations
        self._register_default_slos()
    
    def _register_default_slos(self):
        self._slo_monitor.register_slo(SLOConfig(
            name="threat_detection_availability",
            target_percentage=99.9,
            window_days=30,
            description="Threat detection API availability"
        ))
        self._slo_monitor.register_slo(SLOConfig(
            name="detection_latency_slo",
            target_percentage=99.5,
            window_days=7,
            description="Detection latency under 100ms"
        ))
    
    def start_trace(self, name: str, trace_id: Optional[str] = None, 
                   parent_span_id: Optional[str] = None, 
                   attributes: Optional[Dict] = None) -> Span:
        """Start a new trace span with context propagation"""
        if not self.enabled:
            return Span("", "", None, name, 0)
        
        trace_id = trace_id or ThreadLocalContext.get_current_trace_id() or str(uuid.uuid4())
        span_id = str(uuid.uuid4())[:8]
        
        span = Span(
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=parent_span_id or ThreadLocalContext.get_current_span_id(),
            name=name,
            start_time=time.time(),
            attributes=attributes or {}
        )
        
        ThreadLocalContext.set_current_trace_id(trace_id)
        ThreadLocalContext.set_current_span_id(span_id)
        
        return span
    
    def end_trace(self, span: Span, attributes: Optional[Dict] = None):
        """End a trace span"""
        if not self.enabled or not span.trace_id:
            return
        
        span.end_time = time.time()
        if attributes:
            span.attributes.update(attributes)
        
        with self._lock:
            self._spans[span.trace_id].append(span)
        
        # Record latency
        latency = span.end_time - span.start_time
        self.record_latency(span.name, latency)
    
    def trace(self, name: Optional[str] = None):
        """Decorator for tracing function calls"""
        def decorator(func: Callable) -> Callable:
            span_name = name or func.__name__
            def wrapper(*args, **kwargs):
                span = self.start_trace(span_name)
                try:
                    result = func(*args, **kwargs)
                    self.end_trace(span, {"status": "success"})
                    return result
                except Exception as e:
                    self.end_trace(span, {"status": "error", "error": str(e)})
                    raise
            return wrapper
        return decorator
    
    def record_latency(self, operation: str, latency_seconds: float):
        """Record latency for an operation"""
        if not self.enabled:
            return
        
        with self._lock:
            if operation not in self._histograms:
                self._histograms[operation] = LatencyHistogram(operation)
            self._histograms[operation].record(latency_seconds)
    
    def increment_counter(self, metric: str, value: int = 1, labels: Optional[Dict] = None):
        """Increment a counter metric"""
        if not self.enabled:
            return
        key = f"{metric}:{json.dumps(labels or {}, sort_keys=True)}"
        with self._lock:
            self._counters[key] += value
    
    def set_gauge(self, metric: str, value: float, labels: Optional[Dict] = None):
        """Set a gauge metric"""
        if not self.enabled:
            return
        key = f"{metric}:{json.dumps(labels or {}, sort_keys=True)}"
        with self._lock:
            self._gauges[key] = value
    
    def record_slo_event(self, slo_name: str, is_error: bool = False):
        """Record an event for SLO tracking"""
        if self.enabled:
            self._slo_monitor.record_event(slo_name, is_error)
    
    def get_all_slo_status(self) -> List[SLOStatusSnapshot]:
        """Get status of all SLOs"""
        return [
            self._slo_monitor.get_slo_status(name)
            for name in self._slo_monitor._slos.keys()
        ]
    
    def register_health_check(self, name: str, check_fn: Callable[[], bool]):
        """Register a health check function"""
        self._health_checks[name] = check_fn
    
    def run_health_checks(self) -> Dict[str, Any]:
        """Run all registered health checks"""
        results = {}
        overall_healthy = True
        
        for name, check_fn in self._health_checks.items():
            try:
                healthy = check_fn()
                results[name] = {"healthy": healthy, "error": None}
                if not healthy:
                    overall_healthy = False
            except Exception as e:
                results[name] = {"healthy": False, "error": str(e)}
                overall_healthy = False
        
        return {
            "overall_healthy": overall_healthy,
            "timestamp": time.time(),
            "checks": results
        }
    
    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get summary of all metrics"""
        if not self.enabled:
            return {"enabled": False}
        
        with self._lock:
            return {
                "enabled": True,
                "counters": dict(self._counters),
                "gauges": dict(self._gauges),
                "latency": {
                    name: hist.get_stats()
                    for name, hist in self._histograms.items()
                },
                "active_traces": len(self._spans)
            }
    
    def get_trace(self, trace_id: str) -> List[Dict]:
        """Get all spans for a trace"""
        if trace_id not in self._spans:
            return []
        
        return [
            {
                "span_id": s.span_id,
                "parent_span_id": s.parent_span_id,
                "name": s.name,
                "duration_ms": round((s.end_time - s.start_time) * 1000, 2) if s.end_time else None,
                "attributes": s.attributes
            }
            for s in self._spans[trace_id]
        ]


# Global observability instance - DISABLED BY DEFAULT
observability = EnhancedObservabilityEngine(enabled=False)


def enable_observability():
    """Explicit opt-in to enable observability"""
    observability.enabled = True


def disable_observability():
    """Disable observability"""
    observability.enabled = False
