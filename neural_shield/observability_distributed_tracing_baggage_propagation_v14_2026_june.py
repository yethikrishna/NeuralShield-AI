"""
NeuralShield AI - Distributed Tracing & Baggage Propagation v14
DIMENSION D: Observability & Instrumentation

100% ADD-ONLY - NO EXISTING CODE MODIFIED
OPT-IN ONLY - Disabled by default
Backward compatible with all existing modules

Implements:
- W3C Trace Context compliant traceparent header generation/parsing
- Baggage context propagation across module boundaries
- Cross-module correlation IDs
- Trace state management
- Thread-local context storage
- Optional sampling with configurable rates
"""

import threading
import time
import uuid
import secrets
import hashlib
from typing import Dict, Optional, Any, Callable, List, Tuple
from dataclasses import dataclass, field
from enum import Enum
import json


class TraceFlags(Enum):
    """W3C Trace Flags enumeration."""
    NOT_SAMPLED = 0x00
    SAMPLED = 0x01


class SpanKind(Enum):
    """Span kind classification per OpenTelemetry spec."""
    INTERNAL = "internal"
    SERVER = "server"
    CLIENT = "client"
    PRODUCER = "producer"
    CONSUMER = "consumer"


@dataclass
class TraceContext:
    """W3C compliant trace context container."""
    trace_id: str
    span_id: str
    trace_flags: TraceFlags = TraceFlags.NOT_SAMPLED
    version: str = "00"
    trace_state: Dict[str, str] = field(default_factory=dict)
    
    def to_traceparent(self) -> str:
        """Serialize to W3C traceparent header format."""
        flags = f"{self.trace_flags.value:02x}"
        return f"{self.version}-{self.trace_id}-{self.span_id}-{flags}"
    
    @classmethod
    def from_traceparent(cls, traceparent: str) -> Optional['TraceContext']:
        """Parse from W3C traceparent header format."""
        try:
            parts = traceparent.split('-')
            if len(parts) != 4:
                return None
            version, trace_id, span_id, flags_hex = parts
            if len(trace_id) != 32 or len(span_id) != 16:
                return None
            flags = int(flags_hex, 16)
            return cls(
                trace_id=trace_id,
                span_id=span_id,
                trace_flags=TraceFlags(flags & 0x01),
                version=version
            )
        except Exception:
            return None
    
    def is_sampled(self) -> bool:
        """Check if this trace is sampled."""
        return self.trace_flags == TraceFlags.SAMPLED


@dataclass
class BaggageEntry:
    """Single baggage entry with metadata."""
    value: str
    metadata: Dict[str, str] = field(default_factory=dict)


class Baggage:
    """W3C Baggage implementation for cross-module context propagation."""
    
    def __init__(self):
        self._entries: Dict[str, BaggageEntry] = {}
        self._lock = threading.RLock()
    
    def set(self, key: str, value: str, metadata: Optional[Dict[str, str]] = None) -> None:
        """Set a baggage entry."""
        with self._lock:
            self._entries[key] = BaggageEntry(
                value=value,
                metadata=metadata or {}
            )
    
    def get(self, key: str) -> Optional[str]:
        """Get a baggage value."""
        with self._lock:
            entry = self._entries.get(key)
            return entry.value if entry else None
    
    def remove(self, key: str) -> None:
        """Remove a baggage entry."""
        with self._lock:
            self._entries.pop(key, None)
    
    def to_header(self) -> str:
        """Serialize to W3C baggage header format."""
        with self._lock:
            parts = []
            for key, entry in self._entries.items():
                part = f"{key}={entry.value}"
                for meta_key, meta_value in entry.metadata.items():
                    part += f";{meta_key}={meta_value}"
                parts.append(part)
            return ",".join(parts)
    
    def keys(self) -> List[str]:
        """Get all baggage keys."""
        with self._lock:
            return list(self._entries.keys())
    
    def clone(self) -> 'Baggage':
        """Create a deep copy."""
        new_baggage = Baggage()
        with self._lock:
            for key, entry in self._entries.items():
                new_baggage.set(key, entry.value, entry.metadata.copy())
        return new_baggage


@dataclass
class SpanEvent:
    """Event within a span with timestamp."""
    name: str
    timestamp: float
    attributes: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Span:
    """Single trace span."""
    name: str
    context: TraceContext
    parent_span_id: Optional[str] = None
    kind: SpanKind = SpanKind.INTERNAL
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None
    attributes: Dict[str, Any] = field(default_factory=dict)
    events: List[SpanEvent] = field(default_factory=list)
    status_code: str = "UNSET"
    status_message: Optional[str] = None
    
    def add_event(self, name: str, attributes: Optional[Dict[str, Any]] = None) -> None:
        """Add an event to this span."""
        self.events.append(SpanEvent(
            name=name,
            timestamp=time.time(),
            attributes=attributes or {}
        ))
    
    def set_attribute(self, key: str, value: Any) -> None:
        """Set a span attribute."""
        self.attributes[key] = value
    
    def set_status(self, code: str, message: Optional[str] = None) -> None:
        """Set span status."""
        self.status_code = code
        self.status_message = message
    
    def end(self) -> None:
        """End the span."""
        self.end_time = time.time()
    
    def duration_ms(self) -> Optional[float]:
        """Get span duration in milliseconds."""
        if self.end_time is None:
            return None
        return (self.end_time - self.start_time) * 1000


class ThreadLocalContext:
    """Thread-local storage for trace context and baggage."""
    
    def __init__(self):
        self._thread_local = threading.local()
    
    def get_trace_context(self) -> Optional[TraceContext]:
        """Get current thread's trace context."""
        return getattr(self._thread_local, 'trace_context', None)
    
    def set_trace_context(self, context: Optional[TraceContext]) -> None:
        """Set current thread's trace context."""
        self._thread_local.trace_context = context
    
    def get_baggage(self) -> Baggage:
        """Get current thread's baggage."""
        baggage = getattr(self._thread_local, 'baggage', None)
        if baggage is None:
            baggage = Baggage()
            self._thread_local.baggage = baggage
        return baggage
    
    def set_baggage(self, baggage: Baggage) -> None:
        """Set current thread's baggage."""
        self._thread_local.baggage = baggage
    
    def get_active_span(self) -> Optional[Span]:
        """Get current active span."""
        return getattr(self._thread_local, 'active_span', None)
    
    def set_active_span(self, span: Optional[Span]) -> None:
        """Set current active span."""
        self._thread_local.active_span = span


class DistributedTracer:
    """
    Main distributed tracing implementation.
    
    OPT-IN ONLY - All instrumentation disabled by default.
    Must be explicitly enabled via enable() or ENABLE_TRACING env var.
    """
    
    def __init__(self, enabled: bool = False, sampling_rate: float = 0.01):
        self._enabled = enabled
        self._sampling_rate = max(0.0, min(1.0, sampling_rate))
        self._context = ThreadLocalContext()
        self._spans: Dict[str, Span] = {}
        self._finished_spans: List[Span] = []
        self._lock = threading.RLock()
        self._max_finished_spans = 1000
        self._service_name = "neuralshield-ai"
    
    def enable(self) -> None:
        """Enable tracing (OPT-IN)."""
        self._enabled = True
    
    def disable(self) -> None:
        """Disable tracing."""
        self._enabled = False
    
    def is_enabled(self) -> bool:
        """Check if tracing is enabled."""
        return self._enabled
    
    def _should_sample(self) -> bool:
        """Determine if this trace should be sampled."""
        if not self._enabled:
            return False
        if self._sampling_rate >= 1.0:
            return True
        if self._sampling_rate <= 0.0:
            return False
        return secrets.SystemRandom().random() < self._sampling_rate
    
    @staticmethod
    def _generate_trace_id() -> str:
        """Generate a valid W3C trace ID (16 bytes, 32 hex chars)."""
        return secrets.token_hex(16)
    
    @staticmethod
    def _generate_span_id() -> str:
        """Generate a valid W3C span ID (8 bytes, 16 hex chars)."""
        return secrets.token_hex(8)
    
    def start_span(
        self,
        name: str,
        kind: SpanKind = SpanKind.INTERNAL,
        parent_context: Optional[TraceContext] = None,
        attributes: Optional[Dict[str, Any]] = None,
        force_sampled: bool = False
    ) -> Span:
        """
        Start a new span.
        
        Returns a valid Span object even when disabled (no-op behavior).
        """
        if not self._enabled:
            # Return no-op span when disabled
            ctx = TraceContext(
                trace_id=self._generate_trace_id(),
                span_id=self._generate_span_id(),
                trace_flags=TraceFlags.NOT_SAMPLED
            )
            return Span(name=name, context=ctx)
        
        # Use parent context or current thread context
        current_ctx = parent_context or self._context.get_trace_context()
        should_sample = force_sampled or self._should_sample()
        
        if current_ctx:
            # Continue existing trace
            trace_id = current_ctx.trace_id
            parent_span_id = current_ctx.span_id
            trace_flags = TraceFlags.SAMPLED if should_sample else TraceFlags.NOT_SAMPLED
        else:
            # Start new trace
            trace_id = self._generate_trace_id()
            parent_span_id = None
            trace_flags = TraceFlags.SAMPLED if should_sample else TraceFlags.NOT_SAMPLED
        
        span_id = self._generate_span_id()
        ctx = TraceContext(
            trace_id=trace_id,
            span_id=span_id,
            trace_flags=trace_flags
        )
        
        span = Span(
            name=name,
            context=ctx,
            parent_span_id=parent_span_id,
            kind=kind,
            attributes=attributes or {}
        )
        span.set_attribute("service.name", self._service_name)
        
        with self._lock:
            self._spans[span_id] = span
        
        self._context.set_active_span(span)
        self._context.set_trace_context(ctx)
        
        return span
    
    def end_span(self, span: Span, status: str = "OK", message: Optional[str] = None) -> None:
        """End a span."""
        if not self._enabled:
            return
        
        span.end()
        span.set_status(status, message)
        
        with self._lock:
            self._spans.pop(span.context.span_id, None)
            
            if span.context.is_sampled():
                self._finished_spans.append(span)
                # Trim if needed
                if len(self._finished_spans) > self._max_finished_spans:
                    self._finished_spans = self._finished_spans[-self._max_finished_spans:]
        
        # Clear active span if this was it
        current = self._context.get_active_span()
        if current and current.context.span_id == span.context.span_id:
            self._context.set_active_span(None)
    
    def get_current_trace_context(self) -> Optional[TraceContext]:
        """Get current thread's trace context."""
        if not self._enabled:
            return None
        return self._context.get_trace_context()
    
    def get_baggage(self) -> Baggage:
        """Get current baggage (always works, even when disabled)."""
        return self._context.get_baggage()
    
    def inject_correlation_headers(self) -> Dict[str, str]:
        """
        Inject correlation headers for cross-service calls.
        
        Returns empty dict when disabled.
        """
        if not self._enabled:
            return {}
        
        headers = {}
        ctx = self._context.get_trace_context()
        if ctx:
            headers["traceparent"] = ctx.to_traceparent()
        
        baggage = self._context.get_baggage()
        if baggage.keys():
            headers["baggage"] = baggage.to_header()
        
        return headers
    
    def extract_correlation_headers(self, headers: Dict[str, str]) -> None:
        """
        Extract correlation headers from incoming request.
        
        Safe no-op when disabled.
        """
        if not self._enabled:
            return
        
        traceparent = headers.get("traceparent") or headers.get("Traceparent")
        if traceparent:
            ctx = TraceContext.from_traceparent(traceparent)
            if ctx:
                self._context.set_trace_context(ctx)
        
        baggage_header = headers.get("baggage") or headers.get("Baggage")
        if baggage_header:
            # Parse W3C baggage header (simplified)
            baggage = self._context.get_baggage()
            for entry in baggage_header.split(","):
                if "=" in entry:
                    key, value = entry.split("=", 1)
                    key = key.strip()
                    value = value.split(";")[0].strip()
                    baggage.set(key, value)
    
    def trace(
        self,
        name: Optional[str] = None,
        kind: SpanKind = SpanKind.INTERNAL
    ) -> Callable:
        """
        Decorator for automatic function tracing.
        
        Safe no-op when disabled.
        """
        def decorator(func: Callable) -> Callable:
            span_name = name or func.__name__
            
            def wrapper(*args, **kwargs) -> Any:
                if not self._enabled:
                    return func(*args, **kwargs)
                
                span = self.start_span(span_name, kind=kind)
                try:
                    result = func(*args, **kwargs)
                    self.end_span(span, "OK")
                    return result
                except Exception as e:
                    self.end_span(span, "ERROR", str(e))
                    raise
            return wrapper
        return decorator
    
    def get_trace_statistics(self) -> Dict[str, Any]:
        """Get tracing statistics."""
        if not self._enabled:
            return {"enabled": False}
        
        with self._lock:
            active_count = len(self._spans)
            finished_count = len(self._finished_spans)
            
            if self._finished_spans:
                durations = [s.duration_ms() for s in self._finished_spans if s.duration_ms() is not None]
                avg_duration = sum(durations) / len(durations) if durations else 0
                max_duration = max(durations) if durations else 0
            else:
                avg_duration = 0
                max_duration = 0
            
            error_count = sum(1 for s in self._finished_spans if s.status_code == "ERROR")
            
            return {
                "enabled": True,
                "sampling_rate": self._sampling_rate,
                "active_spans": active_count,
                "finished_spans": finished_count,
                "average_duration_ms": round(avg_duration, 2),
                "max_duration_ms": round(max_duration, 2),
                "error_count": error_count,
                "error_rate": round(error_count / finished_count * 100, 2) if finished_count > 0 else 0
            }
    
    def export_finished_spans(self, clear: bool = True) -> List[Dict[str, Any]]:
        """Export finished spans as JSON-serializable dictionaries."""
        if not self._enabled:
            return []
        
        with self._lock:
            output = []
            for span in self._finished_spans:
                output.append({
                    "name": span.name,
                    "trace_id": span.context.trace_id,
                    "span_id": span.context.span_id,
                    "parent_span_id": span.parent_span_id,
                    "kind": span.kind.value,
                    "start_time": span.start_time,
                    "end_time": span.end_time,
                    "duration_ms": span.duration_ms(),
                    "attributes": span.attributes,
                    "events": [{"name": e.name, "timestamp": e.timestamp, "attributes": e.attributes} for e in span.events],
                    "status": span.status_code,
                    "status_message": span.status_message
                })
            
            if clear:
                self._finished_spans.clear()
            
            return output


# Global singleton instance (DISABLED BY DEFAULT - OPT-IN ONLY)
_global_tracer = DistributedTracer(enabled=False, sampling_rate=0.01)


def get_tracer() -> DistributedTracer:
    """Get the global tracer instance. DISABLED by default."""
    return _global_tracer


def enable_tracing(sampling_rate: float = 0.01) -> None:
    """EXPLICIT OPT-IN - Enable distributed tracing."""
    _global_tracer._sampling_rate = max(0.0, min(1.0, sampling_rate))
    _global_tracer.enable()


def disable_tracing() -> None:
    """Disable distributed tracing."""
    _global_tracer.disable()


def is_tracing_enabled() -> bool:
    """Check if tracing is enabled."""
    return _global_tracer.is_enabled()


# Convenience decorator that safely no-ops when disabled
def traced(name: Optional[str] = None) -> Callable:
    """
    Safe tracing decorator.
    
    Automatically no-ops when tracing is disabled.
    No performance impact when disabled.
    """
    return _global_tracer.trace(name=name)
