"""
NeuralShield Enhanced Observability v12 - Sampling, Async Context, Logging Bridge
Dimension D - Observability & Instrumentation
Add-only module - wraps existing threat detection modules with:
- Probabilistic span sampling (configurable sampling rate)
- Async/await context propagation across coroutines
- Structured logging bridge with trace context injection
- Span metrics aggregation (count, latency, error rates)
- Health check endpoint integration
- Optional, opt-in instrumentation only
All existing code behavior is 100% preserved.
"""
import uuid
import time
import json
import random
import asyncio
import logging
import threading
from typing import Dict, Any, Optional, List, Callable, Awaitable
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timezone
from collections import defaultdict


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


class SamplingDecision(Enum):
    RECORD = "record"
    DROP = "drop"
    RECORD_AND_SAMPLE = "record_and_sample"


@dataclass
class TraceBaggage:
    """Thread-safe and async-safe baggage carrier for cross-module trace context."""
    _thread_storage: threading.local = field(default_factory=threading.local)
    _task_storage: Dict[int, Dict[str, Any]] = field(default_factory=dict)
    _task_lock: threading.Lock = field(default_factory=threading.Lock)
    
    def _get_storage(self) -> Dict[str, Any]:
        """Get appropriate storage based on execution context."""
        try:
            task = asyncio.current_task()
            if task:
                with self._task_lock:
                    task_id = id(task)
                    if task_id not in self._task_storage:
                        self._task_storage[task_id] = {}
                    return self._task_storage[task_id]
        except RuntimeError:
            pass
        # Fall back to thread-local storage
        if not hasattr(self._thread_storage, 'data'):
            self._thread_storage.data = {}
        return self._thread_storage.data
    
    def set_correlation_id(self, correlation_id: str) -> None:
        """Set correlation ID for current context."""
        storage = self._get_storage()
        storage['correlation_id'] = correlation_id
    
    def get_correlation_id(self) -> Optional[str]:
        """Get correlation ID from current context."""
        return self._get_storage().get('correlation_id')
    
    def set_baggage_item(self, key: str, value: str) -> None:
        """Set a baggage item in current context."""
        storage = self._get_storage()
        if 'baggage' not in storage:
            storage['baggage'] = {}
        storage['baggage'][key] = value
    
    def get_baggage_item(self, key: str) -> Optional[str]:
        """Get a baggage item from current context."""
        storage = self._get_storage()
        return storage.get('baggage', {}).get(key)
    
    def get_all_baggage(self) -> Dict[str, str]:
        """Get all baggage items."""
        storage = self._get_storage()
        return dict(storage.get('baggage', {}))
    
    def clear(self) -> None:
        """Clear all baggage for current context."""
        storage = self._get_storage()
        storage.clear()
    
    def propagate_from_parent(self, parent_baggage: Dict[str, str], correlation_id: Optional[str] = None) -> None:
        """Propagate baggage from parent context to child context."""
        storage = self._get_storage()
        storage['baggage'] = dict(parent_baggage)
        if correlation_id:
            storage['correlation_id'] = correlation_id


@dataclass
class TraceSpan:
    """Single trace span representing a unit of work with sampling support."""
    trace_id: str
    span_id: str
    parent_span_id: Optional[str]
    name: str
    kind: SpanKind
    start_time: float
    sampling_decision: SamplingDecision = SamplingDecision.RECORD_AND_SAMPLE
    end_time: Optional[float] = None
    status: SpanStatus = SpanStatus.UNSET
    attributes: Dict[str, Any] = field(default_factory=dict)
    events: List[Dict[str, Any]] = field(default_factory=list)
    baggage: Dict[str, str] = field(default_factory=dict)
    
    def add_attribute(self, key: str, value: Any) -> None:
        """Add an attribute to the span."""
        self.attributes[key] = value
    
    def add_event(self, name: str, attributes: Optional[Dict[str, Any]] = None) -> None:
        """Add an event to the span."""
        self.events.append({
            "name": name,
            "timestamp": time.time(),
            "attributes": attributes or {}
        })
    
    def set_status(self, status: SpanStatus) -> None:
        """Set span completion status."""
        self.status = status
    
    def end(self) -> None:
        """Mark span as completed."""
        self.end_time = time.time()
        if self.status == SpanStatus.UNSET:
            self.status = SpanStatus.OK
    
    def get_duration_ms(self) -> Optional[float]:
        """Get span duration in milliseconds."""
        if self.end_time is None:
            return None
        return (self.end_time - self.start_time) * 1000
    
    def should_export(self) -> bool:
        """Check if span should be exported based on sampling decision."""
        return self.sampling_decision == SamplingDecision.RECORD_AND_SAMPLE
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert span to dictionary representation."""
        return {
            "trace_id": self.trace_id,
            "span_id": self.span_id,
            "parent_span_id": self.parent_span_id,
            "name": self.name,
            "kind": self.kind.value,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_ms": self.get_duration_ms(),
            "status": self.status.value,
            "sampling_decision": self.sampling_decision.value,
            "attributes": self.attributes,
            "events": self.events,
            "baggage": self.baggage
        }


class ProbabilisticSampler:
    """Configurable probabilistic span sampler."""
    
    def __init__(self, sampling_rate: float = 1.0):
        """
        Initialize sampler with given sampling rate.
        sampling_rate: 0.0 = sample nothing, 1.0 = sample everything
        """
        self._sampling_rate = max(0.0, min(1.0, sampling_rate))
        self._random = random.Random()
    
    def set_sampling_rate(self, rate: float) -> None:
        """Update sampling rate dynamically."""
        self._sampling_rate = max(0.0, min(1.0, rate))
    
    def get_sampling_rate(self) -> float:
        """Get current sampling rate."""
        return self._sampling_rate
    
    def should_sample(self, trace_id: str, operation_name: str) -> SamplingDecision:
        """Make sampling decision for a trace."""
        if self._sampling_rate >= 1.0:
            return SamplingDecision.RECORD_AND_SAMPLE
        if self._sampling_rate <= 0.0:
            return SamplingDecision.DROP
        
        # Deterministic sampling based on trace_id hash
        trace_hash = hash(trace_id) & 0xFFFFFFFF
        threshold = self._sampling_rate * 0xFFFFFFFF
        if trace_hash < threshold:
            return SamplingDecision.RECORD_AND_SAMPLE
        return SamplingDecision.DROP


class SpanMetricsAggregator:
    """Aggregates span metrics for observability."""
    
    def __init__(self):
        self._lock = threading.Lock()
        self._span_counts: Dict[str, int] = defaultdict(int)
        self._error_counts: Dict[str, int] = defaultdict(int)
        self._latency_sum: Dict[str, float] = defaultdict(float)
        self._latency_count: Dict[str, int] = defaultdict(int)
        self._start_time = time.time()
    
    def record_span(self, span: TraceSpan) -> None:
        """Record span completion metrics."""
        with self._lock:
            operation = span.name
            self._span_counts[operation] += 1
            
            if span.status == SpanStatus.ERROR:
                self._error_counts[operation] += 1
            
            duration = span.get_duration_ms()
            if duration is not None:
                self._latency_sum[operation] += duration
                self._latency_count[operation] += 1
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get aggregated metrics snapshot."""
        with self._lock:
            operations = set(self._span_counts.keys()) | set(self._error_counts.keys())
            metrics = {}
            
            for op in operations:
                count = self._span_counts.get(op, 0)
                errors = self._error_counts.get(op, 0)
                latency_sum = self._latency_sum.get(op, 0.0)
                latency_count = self._latency_count.get(op, 0)
                
                metrics[op] = {
                    "total_count": count,
                    "error_count": errors,
                    "error_rate": errors / count if count > 0 else 0.0,
                    "avg_latency_ms": latency_sum / latency_count if latency_count > 0 else 0.0,
                    "throughput": count / max(1.0, time.time() - self._start_time)
                }
            
            return {
                "operations": metrics,
                "total_spans": sum(self._span_counts.values()),
                "total_errors": sum(self._error_counts.values()),
                "uptime_seconds": time.time() - self._start_time
            }
    
    def reset(self) -> None:
        """Reset all metrics."""
        with self._lock:
            self._span_counts.clear()
            self._error_counts.clear()
            self._latency_sum.clear()
            self._latency_count.clear()
            self._start_time = time.time()


class TraceContextLoggingFilter(logging.Filter):
    """Logging filter that injects trace context into log records."""
    
    def __init__(self, tracer: 'Tracer'):
        super().__init__()
        self._tracer = tracer
    
    def filter(self, record: logging.LogRecord) -> bool:
        """Inject trace context into log record."""
        current_span = self._tracer.get_current_span()
        correlation_id = self._tracer.baggage.get_correlation_id()
        
        record.trace_id = current_span.trace_id if current_span else None
        record.span_id = current_span.span_id if current_span else None
        record.correlation_id = correlation_id
        
        return True


class HealthCheckProvider:
    """Health check integration for observability."""
    
    def __init__(self, tracer: 'Tracer', metrics: SpanMetricsAggregator):
        self._tracer = tracer
        self._metrics = metrics
    
    def get_health_status(self) -> Dict[str, Any]:
        """Get comprehensive health status."""
        metrics = self._metrics.get_metrics()
        total_error_rate = (
            metrics["total_errors"] / metrics["total_spans"] 
            if metrics["total_spans"] > 0 else 0.0
        )
        
        health = "healthy"
        if total_error_rate > 0.1:  # >10% error rate
            health = "degraded"
        if total_error_rate > 0.5:  # >50% error rate
            health = "unhealthy"
        
        return {
            "status": health,
            "tracing_enabled": self._tracer.is_enabled(),
            "sampling_rate": self._tracer.sampler.get_sampling_rate(),
            "metrics": metrics,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "checks": {
                "error_rate": {
                    "value": total_error_rate,
                    "threshold": 0.1,
                    "status": "ok" if total_error_rate <= 0.1 else "warn"
                }
            }
        }


class TraceContextPropagator:
    """Handles trace context serialization and propagation."""
    
    TRACEPARENT_HEADER = "traceparent"
    TRACESTATE_HEADER = "tracestate"
    
    @staticmethod
    def generate_trace_id() -> str:
        """Generate a new random trace ID."""
        return uuid.uuid4().hex
    
    @staticmethod
    def generate_span_id() -> str:
        """Generate a new random span ID."""
        return uuid.uuid4().hex[:16]
    
    @staticmethod
    def serialize_traceparent(trace_id: str, span_id: str, trace_flags: str = "01") -> str:
        """Serialize context to W3C traceparent format."""
        return f"00-{trace_id}-{span_id}-{trace_flags}"
    
    @staticmethod
    def deserialize_traceparent(traceparent: str) -> Optional[Dict[str, str]]:
        """Deserialize W3C traceparent format."""
        try:
            parts = traceparent.split("-")
            if len(parts) != 4:
                return None
            return {
                "version": parts[0],
                "trace_id": parts[1],
                "span_id": parts[2],
                "trace_flags": parts[3]
            }
        except Exception:
            return None
    
    @staticmethod
    def serialize_baggage(baggage: Dict[str, str]) -> str:
        """Serialize baggage items to W3C baggage format."""
        return ",".join(f"{k}={v}" for k, v in baggage.items())
    
    @staticmethod
    def deserialize_baggage(baggage_str: str) -> Dict[str, str]:
        """Deserialize W3C baggage format."""
        result = {}
        for item in baggage_str.split(","):
            if "=" in item:
                k, v = item.split("=", 1)
                result[k.strip()] = v.strip()
        return result


class Tracer:
    """Main tracer implementation - opt-in only with async support."""
    
    def __init__(self, service_name: str = "neuralshield", sampling_rate: float = 1.0):
        self.service_name = service_name
        self.baggage = TraceBaggage()
        self.sampler = ProbabilisticSampler(sampling_rate)
        self.metrics = SpanMetricsAggregator()
        self.health = HealthCheckProvider(self, self.metrics)
        
        self._spans: Dict[str, TraceSpan] = {}
        self._thread_active: threading.local = threading.local()
        self._task_active: Dict[int, TraceSpan] = {}
        self._task_lock: threading.Lock = threading.Lock()
        
        self._enabled = False
        self._on_span_end_callbacks: List[Callable[[TraceSpan], None]] = []
    
    def enable(self) -> None:
        """Enable tracing - opt-in explicitly required."""
        self._enabled = True
    
    def disable(self) -> None:
        """Disable tracing."""
        self._enabled = False
    
    def is_enabled(self) -> bool:
        """Check if tracing is enabled."""
        return self._enabled
    
    def _get_active_span(self) -> Optional[TraceSpan]:
        """Get active span from current context."""
        try:
            task = asyncio.current_task()
            if task:
                with self._task_lock:
                    return self._task_active.get(id(task))
        except RuntimeError:
            pass
        return getattr(self._thread_active, 'current', None)
    
    def _set_active_span(self, span: Optional[TraceSpan]) -> None:
        """Set active span in current context."""
        try:
            task = asyncio.current_task()
            if task:
                with self._task_lock:
                    if span:
                        self._task_active[id(task)] = span
                    else:
                        self._task_active.pop(id(task), None)
                return
        except RuntimeError:
            pass
        self._thread_active.current = span
    
    def register_span_end_callback(self, callback: Callable[[TraceSpan], None]) -> None:
        """Register callback for span end events."""
        self._on_span_end_callbacks.append(callback)
    
    def start_span(
        self,
        name: str,
        kind: SpanKind = SpanKind.INTERNAL,
        parent_context: Optional[Dict[str, str]] = None,
        attributes: Optional[Dict[str, Any]] = None
    ) -> TraceSpan:
        """Start a new trace span."""
        if not self._enabled:
            return TraceSpan(
                trace_id="disabled",
                span_id="disabled",
                parent_span_id=None,
                name=name,
                kind=kind,
                start_time=time.time(),
                sampling_decision=SamplingDecision.DROP
            )
        
        trace_id = TraceContextPropagator.generate_trace_id()
        parent_span_id = None
        parent_baggage = {}
        
        parent_span = self._get_active_span()
        if parent_span:
            trace_id = parent_span.trace_id
            parent_span_id = parent_span.span_id
            parent_baggage = parent_span.baggage
        
        if parent_context:
            if "trace_id" in parent_context:
                trace_id = parent_context["trace_id"]
            if "span_id" in parent_context:
                parent_span_id = parent_context["span_id"]
        
        sampling_decision = self.sampler.should_sample(trace_id, name)
        
        span = TraceSpan(
            trace_id=trace_id,
            span_id=TraceContextPropagator.generate_span_id(),
            parent_span_id=parent_span_id,
            name=name,
            kind=kind,
            start_time=time.time(),
            sampling_decision=sampling_decision,
            attributes=attributes or {},
            baggage=dict(parent_baggage, **self.baggage.get_all_baggage())
        )
        
        if sampling_decision != SamplingDecision.DROP:
            self._spans[span.span_id] = span
        
        self._set_active_span(span)
        
        if not self.baggage.get_correlation_id():
            self.baggage.set_correlation_id(trace_id)
        
        return span
    
    def end_span(self, span: TraceSpan, status: SpanStatus = SpanStatus.OK) -> None:
        """End a span and trigger callbacks."""
        if not self._enabled:
            return
        
        span.set_status(status)
        span.end()
        
        self.metrics.record_span(span)
        
        if span.should_export():
            for callback in self._on_span_end_callbacks:
                try:
                    callback(span)
                except Exception:
                    pass
        
        current = self._get_active_span()
        if current and current.span_id == span.span_id:
            self._set_active_span(None)
    
    def get_current_span(self) -> Optional[TraceSpan]:
        """Get currently active span."""
        if not self._enabled:
            return None
        return self._get_active_span()
    
    def get_span_by_id(self, span_id: str) -> Optional[TraceSpan]:
        """Get span by ID."""
        return self._spans.get(span_id)
    
    def get_sampled_spans(self) -> List[TraceSpan]:
        """Get all sampled spans."""
        return [s for s in self._spans.values() if s.should_export()]
    
    def trace_as_span(
        self,
        name: Optional[str] = None,
        kind: SpanKind = SpanKind.INTERNAL,
        attributes: Optional[Dict[str, Any]] = None
    ):
        """Decorator to wrap sync function calls as spans."""
        def decorator(func: Callable) -> Callable:
            span_name = name or func.__name__
            def wrapper(*args, **kwargs):
                if not self._enabled:
                    return func(*args, **kwargs)
                
                span = self.start_span(span_name, kind, attributes=attributes)
                try:
                    result = func(*args, **kwargs)
                    self.end_span(span, SpanStatus.OK)
                    return result
                except Exception as e:
                    span.add_attribute("error.type", type(e).__name__)
                    span.add_attribute("error.message", str(e))
                    self.end_span(span, SpanStatus.ERROR)
                    raise
            return wrapper
        return decorator
    
    def trace_as_span_async(
        self,
        name: Optional[str] = None,
        kind: SpanKind = SpanKind.INTERNAL,
        attributes: Optional[Dict[str, Any]] = None
    ):
        """Decorator to wrap async function calls as spans."""
        def decorator(func: Callable[..., Awaitable]) -> Callable[..., Awaitable]:
            span_name = name or func.__name__
            async def wrapper(*args, **kwargs):
                if not self._enabled:
                    return await func(*args, **kwargs)
                
                span = self.start_span(span_name, kind, attributes=attributes)
                try:
                    result = await func(*args, **kwargs)
                    self.end_span(span, SpanStatus.OK)
                    return result
                except Exception as e:
                    span.add_attribute("error.type", type(e).__name__)
                    span.add_attribute("error.message", str(e))
                    self.end_span(span, SpanStatus.ERROR)
                    raise
            return wrapper
        return decorator
    
    def get_logging_filter(self) -> logging.Filter:
        """Get logging filter for trace context injection."""
        return TraceContextLoggingFilter(self)
    
    def inject_logging_context(self, logger: logging.Logger) -> None:
        """Inject trace context into a logger."""
        logger.addFilter(self.get_logging_filter())
    
    def extract_trace_context(self, headers: Dict[str, str]) -> Optional[Dict[str, str]]:
        """Extract trace context from HTTP headers."""
        traceparent = headers.get(TraceContextPropagator.TRACEPARENT_HEADER.lower())
        if not traceparent:
            return None
        
        parsed = TraceContextPropagator.deserialize_traceparent(traceparent)
        if not parsed:
            return None
        
        baggage_header = headers.get("baggage", "")
        if baggage_header:
            baggage = TraceContextPropagator.deserialize_baggage(baggage_header)
            for k, v in baggage.items():
                self.baggage.set_baggage_item(k, v)
        
        return parsed
    
    def inject_trace_context(self) -> Dict[str, str]:
        """Inject current trace context as headers."""
        if not self._enabled:
            return {}
        
        current_span = self.get_current_span()
        if not current_span:
            return {}
        
        trace_flags = "01" if current_span.should_export() else "00"
        headers = {
            TraceContextPropagator.TRACEPARENT_HEADER: 
                TraceContextPropagator.serialize_traceparent(
                    current_span.trace_id,
                    current_span.span_id,
                    trace_flags
                )
        }
        
        baggage = self.baggage.get_all_baggage()
        if baggage:
            headers["baggage"] = TraceContextPropagator.serialize_baggage(baggage)
        
        return headers


# Global singleton tracer - disabled by default (opt-in)
global_tracer = Tracer()


# Exported convenience functions
def enable_tracing(sampling_rate: float = 1.0) -> None:
    """Enable distributed tracing (opt-in)."""
    global_tracer.sampler.set_sampling_rate(sampling_rate)
    global_tracer.enable()


def disable_tracing() -> None:
    """Disable distributed tracing."""
    global_tracer.disable()


def is_tracing_enabled() -> bool:
    """Check if tracing is enabled."""
    return global_tracer.is_enabled()


def set_sampling_rate(rate: float) -> None:
    """Set sampling rate dynamically."""
    global_tracer.sampler.set_sampling_rate(rate)


def start_span(name: str, **kwargs) -> TraceSpan:
    """Start a new span."""
    return global_tracer.start_span(name, **kwargs)


def end_span(span: TraceSpan, **kwargs) -> None:
    """End a span."""
    global_tracer.end_span(span, **kwargs)


def get_tracer() -> Tracer:
    """Get the global tracer instance."""
    return global_tracer


def trace(name: Optional[str] = None, **kwargs):
    """Decorator to trace sync function execution."""
    return global_tracer.trace_as_span(name, **kwargs)


def trace_async(name: Optional[str] = None, **kwargs):
    """Decorator to trace async function execution."""
    return global_tracer.trace_as_span_async(name, **kwargs)


def get_metrics() -> Dict[str, Any]:
    """Get current span metrics."""
    return global_tracer.metrics.get_metrics()


def get_health_status() -> Dict[str, Any]:
    """Get health check status."""
    return global_tracer.health.get_health_status()


def inject_logging_context(logger: logging.Logger) -> None:
    """Inject trace context into a logger."""
    global_tracer.inject_logging_context(logger)
