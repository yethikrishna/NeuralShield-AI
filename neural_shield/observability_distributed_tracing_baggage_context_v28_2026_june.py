"""
Observability: Distributed Tracing with Baggage Context Propagation v28
DIMENSION D - Observability & Instrumentation

This module provides OPT-IN distributed tracing with baggage context propagation
for cross-module correlation. All instrumentation is disabled by default and
must be explicitly enabled.

Philosophy: WRAP, DON'T REPLACE. Layer on top of existing code.
"""

import os
import time
import uuid
import threading
from typing import Dict, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict


class BaggageKey(Enum):
    """Standardized baggage keys for context propagation"""
    TRACE_ID = "x-trace-id"
    PARENT_SPAN_ID = "x-parent-span-id"
    REQUEST_ID = "x-request-id"
    USER_ID = "x-user-id"
    THREAT_LEVEL = "x-threat-level"
    DETECTOR_TYPE = "x-detector-type"
    CORRELATION_ID = "x-correlation-id"
    SERVICE_NAME = "x-service-name"


@dataclass
class Span:
    """A single trace span with timing and metadata"""
    name: str
    span_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    trace_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    parent_span_id: Optional[str] = None
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None
    attributes: Dict[str, Any] = field(default_factory=dict)
    events: list = field(default_factory=list)
    baggage: Dict[str, str] = field(default_factory=dict)
    error: Optional[Exception] = None

    @property
    def duration_ms(self) -> Optional[float]:
        if self.end_time:
            return (self.end_time - self.start_time) * 1000
        return None

    def add_event(self, name: str, attributes: Optional[Dict] = None):
        """Add a timed event to the span"""
        self.events.append({
            "name": name,
            "timestamp": time.time(),
            "attributes": attributes or {}
        })

    def set_attribute(self, key: str, value: Any):
        """Set a span attribute"""
        self.attributes[key] = value

    def end(self, error: Optional[Exception] = None):
        """End the span"""
        self.end_time = time.time()
        self.error = error


class BaggageContext:
    """Thread-local baggage context for cross-module propagation"""
    
    _thread_local = threading.local()

    @classmethod
    def _get_storage(cls) -> Dict:
        if not hasattr(cls._thread_local, "baggage"):
            cls._thread_local.baggage = {}
        return cls._thread_local.baggage

    @classmethod
    def set(cls, key: str, value: str):
        """Set a baggage value"""
        cls._get_storage()[key] = value

    @classmethod
    def get(cls, key: str, default: Optional[str] = None) -> Optional[str]:
        """Get a baggage value"""
        return cls._get_storage().get(key, default)

    @classmethod
    def get_all(cls) -> Dict[str, str]:
        """Get all baggage values"""
        return dict(cls._get_storage())

    @classmethod
    def clear(cls):
        """Clear all baggage"""
        cls._get_storage().clear()

    @classmethod
    def from_headers(cls, headers: Dict[str, str]):
        """Extract baggage from HTTP headers"""
        for key in BaggageKey:
            if key.value in headers:
                cls.set(key.value, headers[key.value])

    @classmethod
    def to_headers(cls) -> Dict[str, str]:
        """Convert baggage to HTTP headers"""
        return dict(cls.get_all())


class Tracer:
    """OPT-IN distributed tracer with baggage propagation
    
    Disabled by default. Enable with:
        Tracer.enable()
    """
    
    _enabled: bool = False
    _spans: Dict[str, Span] = {}
    _active_spans: Dict[str, Span] = {}
    _metrics: Dict[str, list] = defaultdict(list)
    _max_spans: int = 10000

    @classmethod
    def enable(cls):
        """Enable tracing (OPT-IN only)"""
        cls._enabled = True

    @classmethod
    def disable(cls):
        """Disable tracing"""
        cls._enabled = False

    @classmethod
    def is_enabled(cls) -> bool:
        return cls._enabled and os.environ.get("NEURALSHIELD_TRACING_ENABLED", "0") == "1"

    @classmethod
    def start_span(
        cls,
        name: str,
        parent_span_id: Optional[str] = None,
        trace_id: Optional[str] = None,
        baggage: Optional[Dict[str, str]] = None
    ) -> Optional[Span]:
        """Start a new span if tracing is enabled"""
        if not cls.is_enabled():
            return None

        span = Span(
            name=name,
            parent_span_id=parent_span_id or BaggageContext.get(BaggageKey.PARENT_SPAN_ID.value),
            trace_id=trace_id or BaggageContext.get(BaggageKey.TRACE_ID.value) or str(uuid.uuid4())
        )

        # Merge baggage
        if baggage:
            span.baggage.update(baggage)
        span.baggage.update(BaggageContext.get_all())

        # Update context
        BaggageContext.set(BaggageKey.TRACE_ID.value, span.trace_id)
        BaggageContext.set(BaggageKey.PARENT_SPAN_ID.value, span.span_id)

        cls._active_spans[span.span_id] = span
        return span

    @classmethod
    def end_span(cls, span: Span, error: Optional[Exception] = None):
        """End a span"""
        if not cls.is_enabled() or span is None:
            return

        span.end(error)
        cls._spans[span.span_id] = span
        cls._metrics[span.name].append(span.duration_ms or 0)

        # Cleanup active spans
        if span.span_id in cls._active_spans:
            del cls._active_spans[span.span_id]

        # Trim old spans
        if len(cls._spans) > cls._max_spans:
            oldest = sorted(cls._spans.values(), key=lambda s: s.start_time)[:100]
            for s in oldest:
                del cls._spans[s.span_id]

    @classmethod
    def get_trace(cls, trace_id: str) -> list:
        """Get all spans for a trace"""
        return [s for s in cls._spans.values() if s.trace_id == trace_id]

    @classmethod
    def get_percentiles(cls, operation_name: str) -> Dict[str, float]:
        """Get latency percentiles for an operation"""
        durations = sorted(cls._metrics.get(operation_name, []))
        if not durations:
            return {}

        def pct(p):
            idx = int(len(durations) * p / 100)
            return durations[min(idx, len(durations) - 1)]

        return {
            "p50": pct(50),
            "p75": pct(75),
            "p90": pct(90),
            "p95": pct(95),
            "p99": pct(99),
            "p999": pct(99.9),
            "count": len(durations),
            "avg": sum(durations) / len(durations)
        }

    @classmethod
    def get_all_metrics(cls) -> Dict[str, Dict]:
        """Get metrics for all operations"""
        return {name: cls.get_percentiles(name) for name in cls._metrics}


def traced(name: Optional[str] = None, baggage_keys: Optional[list] = None):
    """Decorator for OPT-IN tracing of functions
    
    Usage:
        @traced("detect_threat")
        def detect_threat(input_text):
            ...
    """
    def decorator(func: Callable) -> Callable:
        span_name = name or func.__name__
        
        def wrapper(*args, **kwargs):
            if not Tracer.is_enabled():
                return func(*args, **kwargs)

            span = Tracer.start_span(span_name)
            try:
                result = func(*args, **kwargs)
                if span:
                    Tracer.end_span(span)
                return result
            except Exception as e:
                if span:
                    Tracer.end_span(span, error=e)
                raise
        return wrapper
    return decorator


class HealthCheckStatus(Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


@dataclass
class HealthCheck:
    """Health check result with details"""
    name: str
    status: HealthCheckStatus
    message: str
    duration_ms: float
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


class HealthChecker:
    """OPT-IN health check framework
    
    Disabled by default. Register checks and run on demand.
    """
    
    _checks: Dict[str, Callable] = {}

    @classmethod
    def register_check(cls, name: str, check_fn: Callable):
        """Register a health check function"""
        cls._checks[name] = check_fn

    @classmethod
    def run_check(cls, name: str) -> HealthCheck:
        """Run a single health check"""
        if name not in cls._checks:
            return HealthCheck(
                name=name,
                status=HealthCheckStatus.UNHEALTHY,
                message=f"Check {name} not found",
                duration_ms=0
            )

        start = time.time()
        try:
            result = cls._checks[name]()
            duration = (time.time() - start) * 1000
            
            if isinstance(result, tuple):
                if len(result) == 3:
                    status, message, details = result
                else:
                    status, message = result
                    details = {}
            else:
                status, message = result
                details = {}

            return HealthCheck(
                name=name,
                status=status,
                message=message,
                duration_ms=duration,
                details=details
            )
        except Exception as e:
            duration = (time.time() - start) * 1000
            return HealthCheck(
                name=name,
                status=HealthCheckStatus.UNHEALTHY,
                message=f"Check failed: {str(e)}",
                duration_ms=duration,
                details={"error": str(e)}
            )

    @classmethod
    def run_all_checks(cls) -> Dict[str, HealthCheck]:
        """Run all registered health checks"""
        return {name: cls.run_check(name) for name in cls._checks}

    @classmethod
    def get_overall_status(cls) -> HealthCheckStatus:
        """Get overall health status"""
        checks = cls.run_all_checks().values()
        statuses = [c.status for c in checks]
        
        if HealthCheckStatus.UNHEALTHY in statuses:
            return HealthCheckStatus.UNHEALTHY
        if HealthCheckStatus.DEGRADED in statuses:
            return HealthCheckStatus.DEGRADED
        return HealthCheckStatus.HEALTHY


# Export public API
__all__ = [
    "Tracer",
    "BaggageContext",
    "BaggageKey",
    "Span",
    "traced",
    "HealthChecker",
    "HealthCheck",
    "HealthCheckStatus",
]
