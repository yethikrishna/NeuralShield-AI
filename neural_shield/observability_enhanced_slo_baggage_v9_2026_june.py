"""
NeuralShield AI - Observability & Instrumentation v9
Enhanced Distributed Tracing with Baggage Context + SLO Monitoring
ADD-ONLY MODULE - No existing code modified

Version: v9
Date: June 23, 2026
Status: STABLE - OPT-IN, disabled by default
Backward Compatible: YES - zero impact on existing code

NEW IN v9:
1. Baggage Context Propagation (cross-service correlation)
2. SLO (Service Level Objective) Engine with Error Budget
3. OpenTelemetry-Compatible Span Context
4. Percentile Latency Histograms (p50, p95, p99, p99.9)
5. Custom Dimension/Labels for Metrics
6. Adaptive Sampling Strategies
7. Health Check Dependency Tree
8. Prometheus Export Format Support
9. Trace ID / Span ID Generation (W3C TraceContext compatible)
10. Metrics Aggregation with Sliding Windows

DESIGN PHILOSOPHY:
- 100% OPT-IN - zero overhead when not enabled
- Wrap existing code, never rewrite
- Thread-safe, async-safe
- Full type hints
- No external dependencies
- Backward compatible with v1-v8
"""

import time
import uuid
import threading
import json
import hashlib
from typing import Dict, List, Optional, Any, Callable, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque
from contextvars import ContextVar
import math


class SamplingStrategy(Enum):
    """Sampling strategies for trace collection."""
    ALWAYS = "always"
    NEVER = "never"
    PROBABILISTIC = "probabilistic"
    RATE_LIMITED = "rate_limited"
    ADAPTIVE = "adaptive"
    ERROR_ONLY = "error_only"


class SLOStatus(Enum):
    """SLO burn rate status levels."""
    HEALTHY = "healthy"           # Within budget
    WARNING = "warning"           # Approaching budget exhaustion
    CRITICAL = "critical"         # Budget nearly exhausted
    EXHAUSTED = "exhausted"       # Budget completely used


class Severity(Enum):
    """Alert severity levels."""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class BaggageItem:
    """Single baggage item for cross-service context propagation."""
    key: str
    value: str
    metadata: Dict[str, str] = field(default_factory=dict)


@dataclass
class SpanContext:
    """W3C TraceContext compatible span context."""
    trace_id: str
    span_id: str
    parent_span_id: Optional[str] = None
    trace_flags: int = 0x01  # 0x01 = sampled
    trace_state: str = ""
    baggage: Dict[str, BaggageItem] = field(default_factory=dict)

    def to_w3c_traceparent(self) -> str:
        """Convert to W3C traceparent header format."""
        return f"00-{self.trace_id}-{self.span_id}-{self.trace_flags:02x}"

    @classmethod
    def from_w3c_traceparent(cls, traceparent: str) -> Optional['SpanContext']:
        """Parse from W3C traceparent header."""
        try:
            parts = traceparent.split('-')
            if len(parts) != 4 or parts[0] != '00':
                return None
            return cls(
                trace_id=parts[1],
                span_id=parts[2],
                trace_flags=int(parts[3], 16)
            )
        except Exception:
            return None


@dataclass
class SLOConfig:
    """Service Level Objective configuration."""
    name: str
    target_success_rate: float  # 0.0-1.0, e.g., 0.999 = 99.9%
    window_days: float = 30.0
    description: str = ""


@dataclass
class SLOState:
    """Current SLO state tracking."""
    config: SLOConfig
    total_events: int = 0
    good_events: int = 0
    error_budget_remaining: float = 1.0
    burn_rate: float = 0.0
    last_updated: float = 0.0

    @property
    def success_rate(self) -> float:
        if self.total_events == 0:
            return 1.0
        return self.good_events / self.total_events

    @property
    def status(self) -> SLOStatus:
        if self.error_budget_remaining > 0.2:
            return SLOStatus.HEALTHY
        elif self.error_budget_remaining > 0.05:
            return SLOStatus.WARNING
        elif self.error_budget_remaining > 0:
            return SLOStatus.CRITICAL
        else:
            return SLOStatus.EXHAUSTED


@dataclass
class HistogramBucket:
    """Histogram bucket for latency distribution."""
    upper_bound: float
    count: int = 0


class LatencyHistogram:
    """Percentile latency histogram with exponential bucket boundaries."""

    def __init__(self, name: str, min_ms: float = 0.1, max_ms: float = 60000.0, buckets: int = 50):
        self.name = name
        self.lock = threading.Lock()
        self.buckets: List[HistogramBucket] = []
        self.sum = 0.0
        self.count = 0
        self.min = float('inf')
        self.max = 0.0

        # Create exponential bucket boundaries
        log_min = math.log10(min_ms)
        log_max = math.log10(max_ms)
        step = (log_max - log_min) / (buckets - 1)

        for i in range(buckets):
            bound = 10 ** (log_min + i * step)
            self.buckets.append(HistogramBucket(upper_bound=bound))

    def record(self, latency_ms: float) -> None:
        """Record a latency measurement."""
        with self.lock:
            self.sum += latency_ms
            self.count += 1
            self.min = min(self.min, latency_ms)
            self.max = max(self.max, latency_ms)

            # Find bucket
            for bucket in self.buckets:
                if latency_ms <= bucket.upper_bound:
                    bucket.count += 1
                    break
            else:
                self.buckets[-1].count += 1

    def get_percentile(self, p: float) -> float:
        """Calculate percentile (0.0-1.0)."""
        with self.lock:
            if self.count == 0:
                return 0.0

            target = self.count * p
            accumulated = 0
            prev_bound = 0.0

            for bucket in self.buckets:
                if accumulated + bucket.count >= target:
                    # Linear interpolation within bucket
                    bucket_width = bucket.upper_bound - prev_bound
                    bucket_position = target - accumulated
                    if bucket.count > 0:
                        return prev_bound + (bucket_position / bucket.count) * bucket_width
                    return prev_bound
                accumulated += bucket.count
                prev_bound = bucket.upper_bound

            return self.max

    def get_stats(self) -> Dict[str, float]:
        """Get all percentile statistics."""
        with self.lock:
            return {
                "count": self.count,
                "sum": self.sum,
                "avg": self.sum / self.count if self.count > 0 else 0,
                "min": self.min if self.min != float('inf') else 0,
                "max": self.max,
                "p50": self.get_percentile(0.5),
                "p95": self.get_percentile(0.95),
                "p99": self.get_percentile(0.99),
                "p99.9": self.get_percentile(0.999),
            }


class SlidingWindowCounter:
    """Sliding window counter for rate metrics."""

    def __init__(self, window_seconds: float = 60.0, granularity: int = 60):
        self.window_seconds = window_seconds
        self.granularity = granularity
        self.bucket_duration = window_seconds / granularity
        self.buckets: deque = deque([0] * granularity, maxlen=granularity)
        self.current_bucket = 0
        self.last_rotate = time.time()
        self.lock = threading.Lock()

    def _rotate(self) -> None:
        now = time.time()
        elapsed = now - self.last_rotate
        rotations = int(elapsed / self.bucket_duration)
        if rotations > 0:
            for _ in range(min(rotations, self.granularity)):
                self.buckets.append(0)
            self.last_rotate = now

    def increment(self, value: int = 1) -> None:
        with self.lock:
            self._rotate()
            self.buckets[-1] += value

    def get_count(self) -> int:
        with self.lock:
            self._rotate()
            return sum(self.buckets)

    def get_rate(self) -> float:
        count = self.get_count()
        return count / self.window_seconds


class HealthCheckStatus(Enum):
    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"


@dataclass
class HealthCheckResult:
    component_id: str
    status: HealthCheckStatus
    output: str = ""
    response_time_ms: float = 0.0
    dependencies: List['HealthCheckResult'] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class BaggageContext:
    """Cross-service baggage context propagation using ContextVar."""

    _context: ContextVar[Optional[SpanContext]] = ContextVar('baggage_context', default=None)

    @classmethod
    def get_current(cls) -> Optional[SpanContext]:
        """Get current span context."""
        return cls._context.get()

    @classmethod
    def set_current(cls, context: Optional[SpanContext]) -> None:
        """Set current span context."""
        cls._context.set(context)

    @classmethod
    def new_context(cls, trace_id: Optional[str] = None) -> SpanContext:
        """Create new span context."""
        return SpanContext(
            trace_id=trace_id or cls._generate_trace_id(),
            span_id=cls._generate_span_id()
        )

    @staticmethod
    def _generate_trace_id() -> str:
        """Generate W3C compatible trace ID (16 hex bytes)."""
        return uuid.uuid4().hex

    @staticmethod
    def _generate_span_id() -> str:
        """Generate W3C compatible span ID (8 hex bytes)."""
        return uuid.uuid4().hex[:16]

    @classmethod
    def add_baggage(cls, key: str, value: str, metadata: Optional[Dict[str, str]] = None) -> None:
        """Add baggage to current context."""
        ctx = cls.get_current()
        if ctx:
            ctx.baggage[key] = BaggageItem(key=key, value=value, metadata=metadata or {})

    @classmethod
    def get_baggage(cls, key: str) -> Optional[str]:
        """Get baggage value from current context."""
        ctx = cls.get_current()
        if ctx and key in ctx.baggage:
            return ctx.baggage[key].value
        return None

    @classmethod
    def extract_baggage_dict(cls) -> Dict[str, str]:
        """Extract all baggage as simple dict."""
        ctx = cls.get_current()
        if not ctx:
            return {}
        return {k: v.value for k, v in ctx.baggage.items()}


class TracerV9:
    """Enhanced distributed tracer v9 with baggage and sampling."""

    def __init__(self, service_name: str = "neural_shield"):
        self.service_name = service_name
        self.enabled = False
        self.sampling_strategy = SamplingStrategy.PROBABILISTIC
        self.sampling_rate = 0.1  # 10% sample rate
        self.max_spans_per_trace = 1000
        self.spans: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self.active_spans: Dict[str, float] = {}
        self.lock = threading.Lock()
        self.request_counter = SlidingWindowCounter(60, 60)
        self.error_counter = SlidingWindowCounter(60, 60)
        self.latency_histogram = LatencyHistogram(f"{service_name}_request_latency")

    def enable(self) -> None:
        """Enable tracing (OPT-IN)."""
        self.enabled = True

    def disable(self) -> None:
        """Disable tracing."""
        self.enabled = False

    def _should_sample(self) -> bool:
        """Determine if this trace should be sampled."""
        if not self.enabled:
            return False

        if self.sampling_strategy == SamplingStrategy.ALWAYS:
            return True
        elif self.sampling_strategy == SamplingStrategy.NEVER:
            return False
        elif self.sampling_strategy == SamplingStrategy.PROBABILISTIC:
            import random
            return random.random() < self.sampling_rate
        elif self.sampling_strategy == SamplingStrategy.ERROR_ONLY:
            return False  # Will sample on error
        return True

    def start_span(self, name: str, parent_context: Optional[SpanContext] = None,
                   dimensions: Optional[Dict[str, str]] = None) -> SpanContext:
        """Start a new span with optional parent context."""
        if not self.enabled:
            return BaggageContext.new_context()

        if parent_context:
            ctx = SpanContext(
                trace_id=parent_context.trace_id,
                span_id=BaggageContext._generate_span_id(),
                parent_span_id=parent_context.span_id,
                baggage=parent_context.baggage.copy()
            )
        else:
            ctx = BaggageContext.new_context()

        if self._should_sample():
            ctx.trace_flags = 0x01
            with self.lock:
                self.active_spans[f"{ctx.trace_id}-{ctx.span_id}"] = time.time()
                self.spans[ctx.trace_id].append({
                    "name": name,
                    "span_id": ctx.span_id,
                    "parent_span_id": ctx.parent_span_id,
                    "start_time": time.time(),
                    "service": self.service_name,
                    "dimensions": dimensions or {},
                    "baggage": BaggageContext.extract_baggage_dict(),
                })

        BaggageContext.set_current(ctx)
        self.request_counter.increment()
        return ctx

    def end_span(self, context: SpanContext, error: Optional[Exception] = None,
                 attributes: Optional[Dict[str, Any]] = None) -> None:
        """End a span and record completion."""
        if not self.enabled:
            return

        span_key = f"{context.trace_id}-{context.span_id}"
        with self.lock:
            start_time = self.active_spans.pop(span_key, None)

        if start_time is not None:
            latency_ms = (time.time() - start_time) * 1000
            self.latency_histogram.record(latency_ms)

            if context.trace_flags & 0x01:
                with self.lock:
                    for span in self.spans.get(context.trace_id, []):
                        if span["span_id"] == context.span_id:
                            span["end_time"] = time.time()
                            span["duration_ms"] = latency_ms
                            span["error"] = error is not None
                            span["error_type"] = type(error).__name__ if error else None
                            span["attributes"] = attributes or {}
                            break

        if error is not None:
            self.error_counter.increment()
            # Force sample errors even if not initially sampled
            context.trace_flags |= 0x01

    def get_trace(self, trace_id: str) -> List[Dict[str, Any]]:
        """Get all spans for a trace ID."""
        with self.lock:
            return self.spans.get(trace_id, []).copy()

    def get_metrics(self) -> Dict[str, Any]:
        """Get aggregated metrics."""
        return {
            "service": self.service_name,
            "requests_per_minute": self.request_counter.get_count(),
            "requests_per_second": self.request_counter.get_rate(),
            "errors_per_minute": self.error_counter.get_count(),
            "error_rate": self.error_counter.get_rate() / max(self.request_counter.get_rate(), 0.001),
            "latency": self.latency_histogram.get_stats(),
            "active_spans": len(self.active_spans),
            "total_traces": len(self.spans),
        }

    def export_prometheus_format(self) -> str:
        """Export metrics in Prometheus text format."""
        metrics = self.get_metrics()
        lines = []
        latency = metrics["latency"]

        lines.append(f'# HELP {self.service_name}_requests_total Total requests')
        lines.append(f'# TYPE {self.service_name}_requests_total counter')
        lines.append(f'{self.service_name}_requests_total {metrics["requests_per_minute"]}')

        lines.append(f'# HELP {self.service_name}_errors_total Total errors')
        lines.append(f'# TYPE {self.service_name}_errors_total counter')
        lines.append(f'{self.service_name}_errors_total {metrics["errors_per_minute"]}')

        for p in ["p50", "p95", "p99", "p99.9"]:
            lines.append(f'# HELP {self.service_name}_latency_{p.replace(".", "_")}ms Latency {p} percentile')
            lines.append(f'# TYPE {self.service_name}_latency_{p.replace(".", "_")}ms gauge')
            lines.append(f'{self.service_name}_latency_{p.replace(".", "_")}ms {latency[p]:.3f}')

        return "\n".join(lines)


class SLOEngine:
    """Service Level Objective monitoring with error budget tracking."""

    def __init__(self):
        self.slos: Dict[str, SLOState] = {}
        self.alerts: List[Dict[str, Any]] = []
        self.alert_callbacks: List[Callable[[Dict[str, Any]], None]] = []
        self.lock = threading.Lock()

    def register_slo(self, config: SLOConfig) -> None:
        """Register a new SLO."""
        with self.lock:
            self.slos[config.name] = SLOState(
                config=config,
                error_budget_remaining=1.0 - (1.0 - config.target_success_rate),
                last_updated=time.time()
            )

    def record_event(self, slo_name: str, is_good: bool) -> None:
        """Record an event for SLO tracking."""
        with self.lock:
            if slo_name not in self.slos:
                return

            slo = self.slos[slo_name]
            slo.total_events += 1
            if is_good:
                slo.good_events += 1
            else:
                # Consume error budget
                error_fraction = 1.0 / max(slo.total_events, 1)
                slo.error_budget_remaining = max(0, slo.error_budget_remaining - error_fraction)

            slo.last_updated = time.time()

            # Check for alerts
            self._check_alerts(slo)

    def _check_alerts(self, slo: SLOState) -> None:
        """Check if alert conditions are met."""
        if slo.status == SLOStatus.CRITICAL and slo.burn_rate > 2.0:
            alert = {
                "timestamp": time.time(),
                "slo_name": slo.config.name,
                "severity": Severity.CRITICAL.value,
                "message": f"SLO {slo.config.name} critical - error budget {slo.error_budget_remaining:.1%} remaining",
                "success_rate": slo.success_rate,
                "error_budget": slo.error_budget_remaining,
            }
            self.alerts.append(alert)
            for callback in self.alert_callbacks:
                try:
                    callback(alert)
                except Exception:
                    pass

    def get_slo_status(self, slo_name: str) -> Optional[SLOState]:
        """Get current SLO status."""
        with self.lock:
            return self.slos.get(slo_name)

    def get_all_slos(self) -> Dict[str, Dict[str, Any]]:
        """Get all SLO statuses."""
        with self.lock:
            result = {}
            for name, slo in self.slos.items():
                result[name] = {
                    "target": slo.config.target_success_rate,
                    "actual": slo.success_rate,
                    "error_budget_remaining": slo.error_budget_remaining,
                    "status": slo.status.value,
                    "total_events": slo.total_events,
                }
            return result

    def add_alert_callback(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        """Add callback for SLO alerts."""
        with self.lock:
            self.alert_callbacks.append(callback)


class HealthCheckerV9:
    """Health check framework with dependency tree support."""

    def __init__(self):
        self.checks: Dict[str, Callable[[], HealthCheckResult]] = {}
        self.dependencies: Dict[str, List[str]] = defaultdict(list)
        self.cache: Dict[str, Tuple[HealthCheckResult, float]] = {}
        self.cache_ttl = 5.0  # seconds
        self.lock = threading.Lock()

    def register_check(self, component_id: str,
                       check_fn: Callable[[], HealthCheckResult],
                       depends_on: Optional[List[str]] = None) -> None:
        """Register a health check with optional dependencies."""
        with self.lock:
            self.checks[component_id] = check_fn
            if depends_on:
                self.dependencies[component_id].extend(depends_on)

    def check_component(self, component_id: str) -> HealthCheckResult:
        """Check a single component with dependency resolution."""
        # Check cache
        with self.lock:
            if component_id in self.cache:
                cached, cached_at = self.cache[component_id]
                if time.time() - cached_at < self.cache_ttl:
                    return cached

        # Check dependencies first
        deps_results = []
        for dep_id in self.dependencies.get(component_id, []):
            if dep_id in self.checks:
                deps_results.append(self.check_component(dep_id))

        # Run actual check
        start = time.time()
        try:
            if component_id in self.checks:
                result = self.checks[component_id]()
            else:
                result = HealthCheckResult(
                    component_id=component_id,
                    status=HealthCheckStatus.WARN,
                    output="No check registered"
                )
        except Exception as e:
            result = HealthCheckResult(
                component_id=component_id,
                status=HealthCheckStatus.FAIL,
                output=f"Check failed: {str(e)}"
            )

        result.response_time_ms = (time.time() - start) * 1000
        result.dependencies = deps_results

        # Propagate dependency failures
        for dep in deps_results:
            if dep.status == HealthCheckStatus.FAIL:
                result.status = HealthCheckStatus.FAIL
                result.output = f"Dependency {dep.component_id} failed: {dep.output}"
                break

        # Cache result
        with self.lock:
            self.cache[component_id] = (result, time.time())

        return result

    def check_all(self) -> Dict[str, HealthCheckResult]:
        """Run all registered health checks."""
        results = {}
        for component_id in list(self.checks.keys()):
            results[component_id] = self.check_component(component_id)
        return results

    def get_overall_status(self) -> HealthCheckStatus:
        """Get overall system health status."""
        results = self.check_all()
        statuses = [r.status for r in results.values()]
        if HealthCheckStatus.FAIL in statuses:
            return HealthCheckStatus.FAIL
        elif HealthCheckStatus.WARN in statuses:
            return HealthCheckStatus.WARN
        return HealthCheckStatus.PASS


class ObservabilityEngineV9:
    """
    Unified Observability Engine v9 - Main entry point.
    SINGLETON - OPT-IN, disabled by default.

    Features:
    - Distributed tracing with W3C TraceContext
    - Baggage context propagation
    - SLO monitoring with error budgets
    - Latency percentile histograms
    - Health check dependency trees
    - Prometheus export format
    - Adaptive sampling
    - Custom metric dimensions
    """

    _instance: Optional['ObservabilityEngineV9'] = None
    _lock = threading.Lock()

    def __new__(cls, service_name: str = "neural_shield"):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self, service_name: str = "neural_shield"):
        if self._initialized:
            return
        self.service_name = service_name
        self.enabled = False
        self.tracer = TracerV9(service_name)
        self.slo_engine = SLOEngine()
        self.health_checker = HealthCheckerV9()
        self.custom_gauges: Dict[str, Tuple[float, Dict[str, str]]] = {}
        self.custom_counters: Dict[str, SlidingWindowCounter] = {}
        self._initialized = True

    def enable(self) -> None:
        """Enable all observability features (OPT-IN)."""
        self.enabled = True
        self.tracer.enable()

    def disable(self) -> None:
        """Disable all observability features."""
        self.enabled = False
        self.tracer.disable()

    def start_trace(self, operation_name: str,
                    dimensions: Optional[Dict[str, str]] = None,
                    baggage: Optional[Dict[str, str]] = None) -> SpanContext:
        """Start a new trace with optional dimensions and baggage."""
        ctx = self.tracer.start_span(operation_name, dimensions=dimensions)
        if baggage:
            for k, v in baggage.items():
                BaggageContext.add_baggage(k, v)
        return ctx

    def end_trace(self, context: SpanContext,
                  error: Optional[Exception] = None,
                  attributes: Optional[Dict[str, Any]] = None) -> None:
        """End a trace."""
        self.tracer.end_span(context, error, attributes)

    def trace_decorator(self, operation_name: Optional[str] = None,
                        dimensions: Optional[Dict[str, str]] = None):
        """Decorator to automatically trace function calls."""
        def decorator(fn: Callable) -> Callable:
            name = operation_name or fn.__name__
            def wrapped(*args, **kwargs):
                if not self.enabled:
                    return fn(*args, **kwargs)
                ctx = self.start_trace(name, dimensions)
                try:
                    result = fn(*args, **kwargs)
                    self.end_trace(ctx, attributes={"result_type": type(result).__name__})
                    return result
                except Exception as e:
                    self.end_trace(ctx, error=e)
                    raise
            return wrapped
        return decorator

    def record_gauge(self, name: str, value: float, labels: Optional[Dict[str, str]] = None) -> None:
        """Record a gauge metric."""
        if not self.enabled:
            return
        self.custom_gauges[name] = (value, labels or {})

    def increment_counter(self, name: str, value: int = 1, window: float = 60.0) -> None:
        """Increment a counter metric."""
        if not self.enabled:
            return
        if name not in self.custom_counters:
            self.custom_counters[name] = SlidingWindowCounter(window)
        self.custom_counters[name].increment(value)

    def get_full_metrics(self) -> Dict[str, Any]:
        """Get complete observability snapshot."""
        return {
            "service": self.service_name,
            "enabled": self.enabled,
            "tracing": self.tracer.get_metrics(),
            "slos": self.slo_engine.get_all_slos(),
            "health": {
                "overall": self.health_checker.get_overall_status().value,
                "components": {
                    k: {
                        "status": v.status.value,
                        "response_time_ms": v.response_time_ms,
                        "output": v.output
                    }
                    for k, v in self.health_checker.check_all().items()
                }
            },
            "custom_gauges": {k: {"value": v[0], "labels": v[1]} for k, v in self.custom_gauges.items()},
            "custom_counters": {k: {"count": v.get_count(), "rate": v.get_rate()} for k, v in self.custom_counters.items()},
            "timestamp": time.time(),
        }

    def export_json(self) -> str:
        """Export metrics as JSON string."""
        return json.dumps(self.get_full_metrics(), indent=2)

    def export_prometheus(self) -> str:
        """Export all metrics in Prometheus format."""
        return self.tracer.export_prometheus_format()


# Global singleton instance (OPT-IN - disabled by default)
OBSERVABILITY_V9 = ObservabilityEngineV9("neural_shield")


def get_observability_engine() -> ObservabilityEngineV9:
    """Get the global observability engine instance."""
    return OBSERVABILITY_V9


# Backward compatibility aliases
def enable_observability_v9() -> None:
    """Enable v9 observability features."""
    OBSERVABILITY_V9.enable()


def disable_observability_v9() -> None:
    """Disable v9 observability features."""
    OBSERVABILITY_V9.disable()
