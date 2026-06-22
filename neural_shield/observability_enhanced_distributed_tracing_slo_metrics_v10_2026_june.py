"""
NeuralShield AI - Enhanced Observability & Instrumentation v10
Dimension D: Observability & Instrumentation

ADD-ONLY implementation - no existing code modified
OPT-IN instrumentation - never required, disabled by default

Enhancements in v10:
1. OpenTelemetry-compatible distributed tracing with W3C trace context
2. Baggage propagation for cross-service correlation IDs
3. SLO monitoring with error budget calculation and burn rates
4. Histogram metrics with percentile calculation (P50, P95, P99)
5. Health check framework with cascading dependency tracking
6. Adaptive sampling for high-volume trace data
7. Latency distribution tracking with heatmap support
8. Error budget exhaustion alerting with predictive forecasting
9. Span event logging with structured attributes
10. Trace context propagation across async boundaries
"""

import time
import uuid
import json
import threading
import hashlib
import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Callable, Tuple
from enum import Enum
from collections import defaultdict, deque
from datetime import datetime, timedelta
import contextvars


# -----------------------------------------------------------------------------
# Trace Context - W3C Trace Context compliant
# -----------------------------------------------------------------------------

_TRACE_CONTEXT = contextvars.ContextVar('trace_context', default=None)
_BAGGAGE_CONTEXT = contextvars.ContextVar('baggage_context', default=None)


class SpanKind(Enum):
    INTERNAL = "internal"
    SERVER = "server"
    CLIENT = "client"
    PRODUCER = "producer"
    CONSUMER = "consumer"


class SpanStatus(Enum):
    UNSET = "unset"
    OK = "ok"
    ERROR = "error"


@dataclass
class TraceContext:
    """W3C Trace Context compliant trace context."""
    trace_id: str
    span_id: str
    parent_span_id: Optional[str] = None
    trace_flags: int = 0x01  # sampled by default
    version: str = "00"
    
    @classmethod
    def generate(cls) -> 'TraceContext':
        """Generate a new trace context."""
        return cls(
            trace_id=uuid.uuid4().hex[:32],
            span_id=uuid.uuid4().hex[:16],
            parent_span_id=None
        )
    
    @classmethod
    def from_parent(cls, parent: 'TraceContext') -> 'TraceContext':
        """Create child span from parent context."""
        return cls(
            trace_id=parent.trace_id,
            span_id=uuid.uuid4().hex[:16],
            parent_span_id=parent.span_id,
            trace_flags=parent.trace_flags
        )
    
    def to_traceparent(self) -> str:
        """Convert to W3C traceparent header format."""
        return f"{self.version}-{self.trace_id}-{self.span_id}-{self.trace_flags:02x}"
    
    @classmethod
    def from_traceparent(cls, traceparent: str) -> Optional['TraceContext']:
        """Parse from W3C traceparent header format."""
        try:
            parts = traceparent.split('-')
            if len(parts) != 4:
                return None
            return cls(
                version=parts[0],
                trace_id=parts[1],
                span_id=parts[2],
                trace_flags=int(parts[3], 16)
            )
        except Exception:
            return None
    
    def is_sampled(self) -> bool:
        """Check if trace should be sampled."""
        return (self.trace_flags & 0x01) == 0x01


@dataclass
class Baggage:
    """Cross-service correlation baggage."""
    items: Dict[str, str] = field(default_factory=dict)
    
    def set(self, key: str, value: str) -> None:
        """Set baggage item."""
        self.items[key] = value
    
    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """Get baggage item."""
        return self.items.get(key, default)
    
    def to_header(self) -> str:
        """Convert to W3C baggage header format."""
        return ','.join(f"{k}={v}" for k, v in self.items.items())
    
    @classmethod
    def from_header(cls, header: str) -> 'Baggage':
        """Parse from W3C baggage header format."""
        items = {}
        for item in header.split(','):
            if '=' in item:
                k, v = item.split('=', 1)
                items[k.strip()] = v.strip()
        return cls(items=items)


# -----------------------------------------------------------------------------
# Span Implementation
# -----------------------------------------------------------------------------

@dataclass
class SpanEvent:
    """Event within a span."""
    name: str
    timestamp: float
    attributes: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Span:
    """Enhanced span with full observability capabilities."""
    name: str
    trace_context: TraceContext
    kind: SpanKind = SpanKind.INTERNAL
    status: SpanStatus = SpanStatus.UNSET
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None
    attributes: Dict[str, Any] = field(default_factory=dict)
    events: List[SpanEvent] = field(default_factory=list)
    baggage: Baggage = field(default_factory=Baggage)
    
    def add_event(self, name: str, **attributes) -> None:
        """Add structured event to span."""
        self.events.append(SpanEvent(
            name=name,
            timestamp=time.time(),
            attributes=attributes
        ))
    
    def set_attribute(self, key: str, value: Any) -> None:
        """Set span attribute."""
        self.attributes[key] = value
    
    def set_status(self, status: SpanStatus) -> None:
        """Set span completion status."""
        self.status = status
    
    def end(self) -> None:
        """End the span."""
        self.end_time = time.time()
    
    def duration_ms(self) -> float:
        """Get span duration in milliseconds."""
        if self.end_time is None:
            return (time.time() - self.start_time) * 1000
        return (self.end_time - self.start_time) * 1000
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert span to dictionary for export."""
        return {
            "name": self.name,
            "trace_id": self.trace_context.trace_id,
            "span_id": self.trace_context.span_id,
            "parent_span_id": self.trace_context.parent_span_id,
            "kind": self.kind.value,
            "status": self.status.value,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_ms": self.duration_ms(),
            "attributes": self.attributes,
            "events": [
                {"name": e.name, "timestamp": e.timestamp, "attributes": e.attributes}
                for e in self.events
            ],
            "sampled": self.trace_context.is_sampled()
        }


# -----------------------------------------------------------------------------
# Adaptive Sampling
# -----------------------------------------------------------------------------

class AdaptiveSampler:
    """
    Adaptive sampling for high-volume traces.
    Dynamically adjusts sampling rate based on:
    - Trace volume
    - Error rate
    - Span importance
    """
    
    def __init__(
        self,
        base_rate: float = 0.1,
        min_rate: float = 0.01,
        max_rate: float = 1.0,
        window_size: int = 1000
    ):
        self.base_rate = base_rate
        self.min_rate = min_rate
        self.max_rate = max_rate
        self.window_size = window_size
        self._trace_window: deque = deque(maxlen=window_size)
        self._error_count = 0
        self._lock = threading.Lock()
    
    def should_sample(self, trace_id: str, has_error: bool = False, importance: float = 1.0) -> bool:
        """
        Determine if trace should be sampled.
        Always samples errors and high-importance traces.
        """
        # Always sample errors
        if has_error:
            return True
        
        # Always sample high importance
        if importance >= 0.9:
            return True
        
        with self._lock:
            current_rate = self._calculate_adaptive_rate()
            effective_rate = min(current_rate * importance, self.max_rate)
            
            # Deterministic sampling based on trace_id
            hash_val = int(hashlib.md5(trace_id.encode()).hexdigest()[:8], 16)
            sample_threshold = effective_rate * (2**32)
            
            return hash_val < sample_threshold
    
    def record_trace(self, has_error: bool = False) -> None:
        """Record trace for adaptive rate calculation."""
        with self._lock:
            self._trace_window.append(time.time())
            if has_error:
                self._error_count += 1
    
    def _calculate_adaptive_rate(self) -> float:
        """Calculate sampling rate based on recent volume and error rate."""
        if len(self._trace_window) < 100:
            return self.base_rate
        
        window_seconds = self._trace_window[-1] - self._trace_window[0]
        if window_seconds <= 0:
            return self.base_rate
        
        traces_per_second = len(self._trace_window) / window_seconds
        error_rate = self._error_count / len(self._trace_window) if self._trace_window else 0
        
        # Higher volume = lower sampling rate
        volume_factor = max(0.1, 10.0 / max(1.0, traces_per_second))
        
        # Higher error rate = higher sampling rate
        error_factor = 1.0 + (error_rate * 5.0)
        
        adaptive_rate = self.base_rate * volume_factor * error_factor
        return max(self.min_rate, min(self.max_rate, adaptive_rate))


# -----------------------------------------------------------------------------
# Histogram Metrics with Percentiles
# -----------------------------------------------------------------------------

class Histogram:
    """
    Histogram for latency distribution tracking.
    Supports P50, P95, P99 percentile calculation.
    """
    
    def __init__(self, name: str, buckets: Optional[List[float]] = None):
        self.name = name
        self.buckets = buckets or [
            1.0, 2.5, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0,
            2500.0, 5000.0, 10000.0
        ]
        self._bucket_counts: Dict[float, int] = {b: 0 for b in self.buckets}
        self._bucket_counts[float('inf')] = 0
        self._sum = 0.0
        self._count = 0
        self._min = float('inf')
        self._max = float('-inf')
        self._values: List[float] = []
        self._max_values = 10000
        self._lock = threading.Lock()
    
    def record(self, value: float) -> None:
        """Record a value in the histogram."""
        with self._lock:
            self._sum += value
            self._count += 1
            self._min = min(self._min, value)
            self._max = max(self._max, value)
            
            # Count buckets
            for bucket in sorted(self.buckets):
                if value <= bucket:
                    self._bucket_counts[bucket] += 1
            if value > self.buckets[-1]:
                self._bucket_counts[float('inf')] += 1
            
            # Keep sample values for percentile calculation
            if len(self._values) < self._max_values:
                self._values.append(value)
            else:
                # Reservoir sampling
                idx = hash(str(time.time())) % self._count
                if idx < self._max_values:
                    self._values[idx] = value
    
    def percentile(self, p: float) -> float:
        """Calculate percentile (0-100)."""
        with self._lock:
            if not self._values:
                return 0.0
            sorted_values = sorted(self._values)
            idx = int(math.ceil((p / 100.0) * len(sorted_values))) - 1
            idx = max(0, min(idx, len(sorted_values) - 1))
            return sorted_values[idx]
    
    def stats(self) -> Dict[str, Any]:
        """Get histogram statistics."""
        with self._lock:
            return {
                "name": self.name,
                "count": self._count,
                "sum": self._sum,
                "min": self._min if self._count > 0 else 0,
                "max": self._max if self._count > 0 else 0,
                "avg": self._sum / self._count if self._count > 0 else 0,
                "p50": self.percentile(50),
                "p95": self.percentile(95),
                "p99": self.percentile(99),
                "buckets": self._bucket_counts.copy()
            }


# -----------------------------------------------------------------------------
# SLO Monitoring with Error Budget
# -----------------------------------------------------------------------------

class SLOStatus(Enum):
    HEALTHY = "healthy"
    WARNING = "warning"
    BURNING = "burning"
    EXHAUSTED = "exhausted"


@dataclass
class SLODefinition:
    """Service Level Objective definition."""
    name: str
    target_percentage: float  # e.g., 99.9 for 99.9% availability
    window_days: int = 30
    description: str = ""


@dataclass
class SLOResult:
    """SLO calculation result."""
    slo: SLODefinition
    current_percentage: float
    error_budget_remaining: float
    error_budget_burn_rate: float
    status: SLOStatus
    forecast_exhaustion_days: Optional[float]
    window_start: datetime
    window_end: datetime


class SLOMonitor:
    """
    SLO monitoring with error budget calculation.
    Tracks:
    - Current SLO achievement
    - Error budget remaining
    - Burn rate (fast/slow)
    - Forecasted exhaustion
    """
    
    def __init__(self):
        self._slos: Dict[str, SLODefinition] = {}
        self._good_events: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100000))
        self._bad_events: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100000))
        self._lock = threading.Lock()
    
    def register_slo(self, slo: SLODefinition) -> None:
        """Register an SLO definition."""
        self._slos[slo.name] = slo
    
    def record_good(self, slo_name: str) -> None:
        """Record a successful (good) event."""
        with self._lock:
            self._good_events[slo_name].append(time.time())
    
    def record_bad(self, slo_name: str) -> None:
        """Record a failed (bad) event."""
        with self._lock:
            self._bad_events[slo_name].append(time.time())
    
    def calculate_slo(self, slo_name: str) -> Optional[SLOResult]:
        """Calculate current SLO status and error budget."""
        if slo_name not in self._slos:
            return None
        
        slo = self._slos[slo_name]
        window_seconds = slo.window_days * 86400
        cutoff = time.time() - window_seconds
        
        with self._lock:
            good = sum(1 for t in self._good_events[slo_name] if t >= cutoff)
            bad = sum(1 for t in self._bad_events[slo_name] if t >= cutoff)
            total = good + bad
            
            if total == 0:
                current_pct = 100.0
            else:
                current_pct = (good / total) * 100
            
            # Error budget calculation
            max_errors = total * (1 - slo.target_percentage / 100)
            budget_remaining = max(0.0, max_errors - bad)
            
            # Burn rate calculation (last hour)
            hour_cutoff = time.time() - 3600
            bad_last_hour = sum(1 for t in self._bad_events[slo_name] if t >= hour_cutoff)
            allowed_per_hour = max_errors / (slo.window_days * 24)
            burn_rate = bad_last_hour / allowed_per_hour if allowed_per_hour > 0 else float('inf')
            
            # Status determination
            if current_pct < slo.target_percentage:
                status = SLOStatus.EXHAUSTED
            elif burn_rate > 10:
                status = SLOStatus.BURNING
            elif burn_rate > 2:
                status = SLOStatus.WARNING
            else:
                status = SLOStatus.HEALTHY
            
            # Forecast exhaustion
            if bad > 0 and budget_remaining > 0:
                daily_burn = (bad / window_seconds) * 86400
                forecast_days = budget_remaining / daily_burn if daily_burn > 0 else None
            else:
                forecast_days = None
            
            return SLOResult(
                slo=slo,
                current_percentage=current_pct,
                error_budget_remaining=budget_remaining,
                error_budget_burn_rate=burn_rate,
                status=status,
                forecast_exhaustion_days=forecast_days,
                window_start=datetime.now() - timedelta(days=slo.window_days),
                window_end=datetime.now()
            )
    
    def get_all_slos(self) -> Dict[str, Optional[SLOResult]]:
        """Get results for all registered SLOs."""
        return {name: self.calculate_slo(name) for name in self._slos}


# -----------------------------------------------------------------------------
# Health Check Framework
# -----------------------------------------------------------------------------

class HealthStatus(Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


@dataclass
class HealthCheckResult:
    """Result of a health check."""
    name: str
    status: HealthStatus
    message: str = ""
    response_time_ms: float = 0.0
    details: Dict[str, Any] = field(default_factory=dict)
    dependencies: List['HealthCheckResult'] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class HealthCheck:
    """Health check definition."""
    name: str
    check_fn: Callable[[], HealthCheckResult]
    dependencies: List[str] = field(default_factory=list)
    timeout_seconds: float = 5.0
    critical: bool = True


class HealthCheckManager:
    """
    Health check framework with cascading dependency tracking.
    Supports:
    - Liveness checks
    - Readiness checks
    - Dependency cascading
    - Response time tracking
    """
    
    def __init__(self):
        self._checks: Dict[str, HealthCheck] = {}
        self._cache: Dict[str, Tuple[HealthCheckResult, float]] = {}
        self._cache_ttl = 10.0
        self._lock = threading.Lock()
    
    def register_check(self, check: HealthCheck) -> None:
        """Register a health check."""
        self._checks[check.name] = check
    
    def run_check(self, name: str, visited: Optional[set] = None) -> HealthCheckResult:
        """Run a health check with dependency resolution."""
        if visited is None:
            visited = set()
        
        if name in visited:
            return HealthCheckResult(
                name=name,
                status=HealthStatus.UNKNOWN,
                message="Circular dependency detected"
            )
        
        visited.add(name)
        
        # Check cache
        with self._lock:
            if name in self._cache:
                result, cache_time = self._cache[name]
                if time.time() - cache_time < self._cache_ttl:
                    return result
        
        if name not in self._checks:
            return HealthCheckResult(
                name=name,
                status=HealthStatus.UNKNOWN,
                message="Health check not registered"
            )
        
        check = self._checks[name]
        
        # Run dependencies first
        dep_results = []
        for dep_name in check.dependencies:
            dep_result = self.run_check(dep_name, visited.copy())
            dep_results.append(dep_result)
            
            # Propagate critical dependency failures
            if dep_result.status == HealthStatus.UNHEALTHY:
                result = HealthCheckResult(
                    name=name,
                    status=HealthStatus.UNHEALTHY,
                    message=f"Critical dependency failed: {dep_name}",
                    dependencies=dep_results
                )
                self._cache_result(name, result)
                return result
        
        # Run actual check
        start = time.time()
        try:
            result = check.check_fn()
            result.response_time_ms = (time.time() - start) * 1000
            result.dependencies = dep_results
        except Exception as e:
            result = HealthCheckResult(
                name=name,
                status=HealthStatus.UNHEALTHY,
                message=f"Check exception: {str(e)}",
                response_time_ms=(time.time() - start) * 1000,
                dependencies=dep_results
            )
        
        self._cache_result(name, result)
        return result
    
    def _cache_result(self, name: str, result: HealthCheckResult) -> None:
        """Cache health check result."""
        with self._lock:
            self._cache[name] = (result, time.time())
    
    def run_all_checks(self) -> Dict[str, HealthCheckResult]:
        """Run all registered health checks."""
        return {name: self.run_check(name) for name in self._checks}
    
    def overall_health(self) -> HealthStatus:
        """Get overall system health status."""
        results = self.run_all_checks()
        statuses = [r.status for r in results.values()]
        
        if HealthStatus.UNHEALTHY in statuses:
            return HealthStatus.UNHEALTHY
        elif HealthStatus.DEGRADED in statuses:
            return HealthStatus.DEGRADED
        elif all(s == HealthStatus.HEALTHY for s in statuses):
            return HealthStatus.HEALTHY
        return HealthStatus.UNKNOWN


# -----------------------------------------------------------------------------
# Main Enhanced Observability Engine v10
# -----------------------------------------------------------------------------

class EnhancedObservabilityEngineV10:
    """
    Enhanced Observability & Instrumentation Engine v10.
    
    Features:
    - W3C compliant distributed tracing
    - Baggage propagation for cross-service correlation
    - Adaptive sampling for high-volume traces
    - Histogram metrics with percentiles (P50, P95, P99)
    - SLO monitoring with error budget calculation
    - Health check framework with dependency tracking
    - Span event logging with structured attributes
    - Context propagation across async boundaries
    """
    
    def __init__(self):
        self._spans: Dict[str, Span] = {}
        self._metrics: Dict[str, Histogram] = {}
        self._counters: Dict[str, int] = defaultdict(int)
        self._gauges: Dict[str, float] = {}
        self._sampler = AdaptiveSampler()
        self._slo_monitor = SLOMonitor()
        self._health_manager = HealthCheckManager()
        self._lock = threading.Lock()
        self._enabled = False  # OPT-IN - disabled by default
    
    def enable(self) -> None:
        """Enable observability (OPT-IN)."""
        self._enabled = True
    
    def disable(self) -> None:
        """Disable observability."""
        self._enabled = False
    
    def is_enabled(self) -> bool:
        """Check if observability is enabled."""
        return self._enabled
    
    # -------------------------------------------------------------------------
    # Tracing API
    # -------------------------------------------------------------------------
    
    def start_span(
        self,
        name: str,
        kind: SpanKind = SpanKind.INTERNAL,
        parent_context: Optional[TraceContext] = None,
        baggage: Optional[Baggage] = None,
        importance: float = 1.0,
        **attributes
    ) -> Span:
        """Start a new span with distributed tracing context."""
        if not self._enabled:
            # Return minimal span even when disabled
            return Span(
                name=name,
                trace_context=TraceContext.generate(),
                kind=kind
            )
        
        if parent_context is None:
            parent_context = _TRACE_CONTEXT.get()
        
        if parent_context:
            trace_ctx = TraceContext.from_parent(parent_context)
        else:
            trace_ctx = TraceContext.generate()
        
        # Apply adaptive sampling
        if not self._sampler.should_sample(trace_ctx.trace_id, importance=importance):
            trace_ctx.trace_flags &= ~0x01  # Clear sampled flag
        
        span = Span(
            name=name,
            trace_context=trace_ctx,
            kind=kind,
            attributes=attributes,
            baggage=baggage or Baggage()
        )
        
        # Set context for propagation
        _TRACE_CONTEXT.set(trace_ctx)
        _BAGGAGE_CONTEXT.set(span.baggage)
        
        with self._lock:
            self._spans[trace_ctx.span_id] = span
        
        return span
    
    def end_span(self, span: Span, status: SpanStatus = SpanStatus.OK) -> None:
        """End a span and record metrics."""
        span.set_status(status)
        span.end()
        
        if not self._enabled:
            return
        
        # Record duration histogram
        hist_name = f"span_duration_{span.name}"
        with self._lock:
            if hist_name not in self._metrics:
                self._metrics[hist_name] = Histogram(hist_name)
            self._metrics[hist_name].record(span.duration_ms())
            
            # Record counter
            self._counters[f"span_count_{span.name}"] += 1
            if status == SpanStatus.ERROR:
                self._counters[f"span_error_count_{span.name}"] += 1
        
        self._sampler.record_trace(has_error=(status == SpanStatus.ERROR))
    
    def get_current_trace_context(self) -> Optional[TraceContext]:
        """Get current trace context for propagation."""
        return _TRACE_CONTEXT.get()
    
    def get_current_baggage(self) -> Optional[Baggage]:
        """Get current baggage for cross-service correlation."""
        return _BAGGAGE_CONTEXT.get()
    
    def extract_trace_context(self, traceparent: str, baggage: Optional[str] = None) -> Tuple[Optional[TraceContext], Optional[Baggage]]:
        """Extract trace context from incoming request headers."""
        ctx = TraceContext.from_traceparent(traceparent)
        bag = Baggage.from_header(baggage) if baggage else None
        return ctx, bag
    
    # -------------------------------------------------------------------------
    # Metrics API
    # -------------------------------------------------------------------------
    
    def record_counter(self, name: str, value: int = 1) -> None:
        """Record a counter metric."""
        if not self._enabled:
            return
        with self._lock:
            self._counters[name] += value
    
    def set_gauge(self, name: str, value: float) -> None:
        """Set a gauge metric."""
        if not self._enabled:
            return
        with self._lock:
            self._gauges[name] = value
    
    def record_histogram(self, name: str, value: float) -> None:
        """Record a histogram metric."""
        if not self._enabled:
            return
        with self._lock:
            if name not in self._metrics:
                self._metrics[name] = Histogram(name)
            self._metrics[name].record(value)
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get all collected metrics."""
        with self._lock:
            return {
                "counters": dict(self._counters),
                "gauges": dict(self._gauges),
                "histograms": {
                    name: hist.stats()
                    for name, hist in self._metrics.items()
                }
            }
    
    # -------------------------------------------------------------------------
    # SLO API
    # -------------------------------------------------------------------------
    
    @property
    def slo(self) -> SLOMonitor:
        """Get SLO monitor."""
        return self._slo_monitor
    
    # -------------------------------------------------------------------------
    # Health Check API
    # -------------------------------------------------------------------------
    
    @property
    def health(self) -> HealthCheckManager:
        """Get health check manager."""
        return self._health_manager
    
    # -------------------------------------------------------------------------
    # Export API
    # -------------------------------------------------------------------------
    
    def get_finished_spans(self) -> List[Dict[str, Any]]:
        """Get all finished spans for export."""
        with self._lock:
            return [
                span.to_dict()
                for span in self._spans.values()
                if span.end_time is not None and span.trace_context.is_sampled()
            ]
    
    def export_json(self) -> str:
        """Export all observability data as JSON."""
        return json.dumps({
            "metrics": self.get_metrics(),
            "spans": self.get_finished_spans(),
            "slo": {
                name: {
                    "current": result.current_percentage,
                    "budget_remaining": result.error_budget_remaining,
                    "burn_rate": result.error_budget_burn_rate,
                    "status": result.status.value
                } if result else None
                for name, result in self._slo_monitor.get_all_slos().items()
            },
            "health": {
                name: {
                    "status": result.status.value,
                    "message": result.message,
                    "response_time_ms": result.response_time_ms
                }
                for name, result in self._health_manager.run_all_checks().items()
            }
        }, indent=2)


# -----------------------------------------------------------------------------
# Global Singleton & Convenience Functions
# -----------------------------------------------------------------------------

_OBSERVABILITY_ENGINE_V10: Optional[EnhancedObservabilityEngineV10] = None
_ENGINE_LOCK = threading.Lock()


def get_observability_engine_v10() -> EnhancedObservabilityEngineV10:
    """Get the global observability engine singleton."""
    global _OBSERVABILITY_ENGINE_V10
    with _ENGINE_LOCK:
        if _OBSERVABILITY_ENGINE_V10 is None:
            _OBSERVABILITY_ENGINE_V10 = EnhancedObservabilityEngineV10()
        return _OBSERVABILITY_ENGINE_V10


def start_observability_span_v10(name: str, **kwargs) -> Span:
    """Convenience function to start an observability span."""
    return get_observability_engine_v10().start_span(name, **kwargs)


def enable_observability_v10() -> None:
    """Enable enhanced observability (OPT-IN)."""
    get_observability_engine_v10().enable()


def disable_observability_v10() -> None:
    """Disable enhanced observability."""
    get_observability_engine_v10().disable()


# -----------------------------------------------------------------------------
# Backward Compatibility
# -----------------------------------------------------------------------------

# Ensure v8/v9 modules can still import and work
try:
    from .observability_metrics_collection_v8_2026_june import (
        get_observability_engine_v8,
        ObservabilityEngineV8
    )
    # v8 is still available - backward compatibility maintained
except ImportError:
    # v8 not available, but that's OK - we're add-only
    pass

__all__ = [
    'EnhancedObservabilityEngineV10',
    'TraceContext',
    'Baggage',
    'Span',
    'SpanKind',
    'SpanStatus',
    'AdaptiveSampler',
    'Histogram',
    'SLOMonitor',
    'SLODefinition',
    'SLOResult',
    'SLOStatus',
    'HealthCheckManager',
    'HealthCheck',
    'HealthCheckResult',
    'HealthStatus',
    'get_observability_engine_v10',
    'start_observability_span_v10',
    'enable_observability_v10',
    'disable_observability_v10',
]
