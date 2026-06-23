"""
NeuralShield AI - OpenTelemetry Compatible Distributed Tracing Context Propagation
Dimension D: Observability & Instrumentation v13
Version: 13.0.0
Status: STABLE (OPT-IN ONLY - disabled by default)

This module provides OpenTelemetry W3C Trace Context compatible
distributed tracing with baggage correlation for cross-module
observability. All instrumentation is OPT-IN and disabled by default.

COMPLIES WITH INCREMENTAL BUILD PHILOSOPHY:
- ADD-ONLY: New module, no existing code modified
- WRAPPER: Wraps existing functions, no core logic changes
- OPT-IN: Disabled by default, explicit enable required
- BACKWARD COMPATIBLE: No breaking changes
"""

import os
import time
import uuid
import json
import threading
from typing import Dict, Any, Optional, Callable, TypeVar, Tuple
from dataclasses import dataclass, field
from enum import Enum
from contextvars import ContextVar
import functools

# -----------------------------------------------------------------------------
# GLOBAL CONFIGURATION - OPT-IN BY DEFAULT
# -----------------------------------------------------------------------------
# ALL instrumentation is DISABLED by default
# Must explicitly set NEURALSHIELD_OTEL_ENABLED=1 to enable

OTEL_ENABLED: bool = os.environ.get("NEURALSHIELD_OTEL_ENABLED", "0") == "1"

class TraceFlag(Enum):
    """W3C Trace Context trace flags"""
    NOT_SAMPLED = 0x00
    SAMPLED = 0x01

@dataclass
class TraceContext:
    """W3C Trace Context compatible trace context"""
    trace_id: str
    span_id: str
    parent_span_id: Optional[str] = None
    trace_flags: TraceFlag = TraceFlag.NOT_SAMPLED
    version: str = "00"
    
    def to_traceparent(self) -> str:
        """Convert to W3C traceparent header format"""
        flags_hex = f"{self.trace_flags.value:02x}"
        return f"{self.version}-{self.trace_id}-{self.span_id}-{flags_hex}"
    
    @classmethod
    def from_traceparent(cls, traceparent: str) -> 'TraceContext':
        """Parse from W3C traceparent header format"""
        parts = traceparent.split("-")
        if len(parts) != 4:
            raise ValueError("Invalid traceparent format")
        version, trace_id, span_id, flags_hex = parts
        return cls(
            trace_id=trace_id,
            span_id=span_id,
            trace_flags=TraceFlag(int(flags_hex, 16)),
            version=version
        )

@dataclass
class BaggageItem:
    """Single baggage item with optional metadata"""
    value: str
    metadata: Dict[str, str] = field(default_factory=dict)

class Baggage:
    """W3C Baggage compatible context propagation"""
    
    def __init__(self):
        self._items: Dict[str, BaggageItem] = {}
        self._lock = threading.Lock()
    
    def set(self, key: str, value: str, metadata: Optional[Dict[str, str]] = None) -> None:
        """Set a baggage item"""
        with self._lock:
            self._items[key] = BaggageItem(value, metadata or {})
    
    def get(self, key: str) -> Optional[str]:
        """Get a baggage item value"""
        with self._lock:
            item = self._items.get(key)
            return item.value if item else None
    
    def remove(self, key: str) -> None:
        """Remove a baggage item"""
        with self._lock:
            self._items.pop(key, None)
    
    def to_header(self) -> str:
        """Convert to W3C baggage header format"""
        with self._lock:
            items = []
            for key, item in self._items.items():
                parts = [f"{key}={item.value}"]
                for meta_key, meta_value in item.metadata.items():
                    parts.append(f"{meta_key}={meta_value}")
                items.append(";".join(parts))
            return ",".join(items)
    
    def clear(self) -> None:
        """Clear all baggage items"""
        with self._lock:
            self._items.clear()
    
    def to_dict(self) -> Dict[str, str]:
        """Convert to simple dict for logging"""
        with self._lock:
            return {k: v.value for k, v in self._items.items()}

# -----------------------------------------------------------------------------
# CONTEXT VARIABLES - THREAD LOCAL CONTEXT PROPAGATION
# -----------------------------------------------------------------------------

_current_trace_context: ContextVar[Optional[TraceContext]] = ContextVar(
    'current_trace_context',
    default=None
)

_current_baggage: ContextVar[Optional[Baggage]] = ContextVar(
    'current_baggage',
    default=None
)

# -----------------------------------------------------------------------------
# TRACE CONTEXT MANAGEMENT
# -----------------------------------------------------------------------------

def generate_trace_id() -> str:
    """Generate a valid W3C trace ID (16 bytes, 32 hex chars)"""
    return uuid.uuid4().hex  # uuid4().hex is exactly 32 hex chars (16 bytes)

def generate_span_id() -> str:
    """Generate a valid W3C span ID (8 bytes, 16 hex chars)"""
    return uuid.uuid4().hex[:16]

def create_new_trace(sampled: bool = False) -> TraceContext:
    """Create a new trace context"""
    return TraceContext(
        trace_id=generate_trace_id(),
        span_id=generate_span_id(),
        trace_flags=TraceFlag.SAMPLED if sampled else TraceFlag.NOT_SAMPLED
    )

def create_child_span(parent: Optional[TraceContext] = None) -> TraceContext:
    """Create a child span from parent context"""
    if parent is None:
        return create_new_trace()
    
    return TraceContext(
        trace_id=parent.trace_id,
        span_id=generate_span_id(),
        parent_span_id=parent.span_id,
        trace_flags=parent.trace_flags,
        version=parent.version
    )

def get_current_trace_context() -> Optional[TraceContext]:
    """Get the current trace context (thread-safe)"""
    if not OTEL_ENABLED:
        return None
    return _current_trace_context.get()

def set_current_trace_context(ctx: Optional[TraceContext]) -> None:
    """Set the current trace context (thread-safe)"""
    if OTEL_ENABLED:
        _current_trace_context.set(ctx)

def get_current_baggage() -> Baggage:
    """Get the current baggage (thread-safe)"""
    baggage = _current_baggage.get()
    if baggage is None:
        baggage = Baggage()
        _current_baggage.set(baggage)
    return baggage

# -----------------------------------------------------------------------------
# SPAN DATA STRUCTURE
# -----------------------------------------------------------------------------

@dataclass
class SpanEvent:
    """Event within a span"""
    name: str
    timestamp: float = field(default_factory=time.time)
    attributes: Dict[str, Any] = field(default_factory=dict)

@dataclass
class Span:
    """Single trace span"""
    name: str
    context: TraceContext
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None
    attributes: Dict[str, Any] = field(default_factory=dict)
    events: list = field(default_factory=list)
    status: str = "OK"
    status_message: Optional[str] = None
    
    def add_event(self, name: str, attributes: Optional[Dict[str, Any]] = None) -> None:
        """Add an event to the span - always works regardless of enable flag"""
        self.events.append(SpanEvent(name, attributes=attributes or {}))
    
    def set_attribute(self, key: str, value: Any) -> None:
        """Set a span attribute - always works regardless of enable flag"""
        self.attributes[key] = value
    
    def set_status(self, status: str, message: Optional[str] = None) -> None:
        """Set span status - always works regardless of enable flag"""
        self.status = status
        self.status_message = message
    
    def end(self, status: Optional[str] = None) -> None:
        """End the span - always works regardless of enable flag"""
        self.end_time = time.time()
        if status:
            self.status = status
    
    @property
    def duration_ms(self) -> Optional[float]:
        """Get span duration in milliseconds"""
        if self.end_time is None:
            return None
        return (self.end_time - self.start_time) * 1000
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert span to dictionary for export"""
        return {
            "name": self.name,
            "trace_id": self.context.trace_id,
            "span_id": self.context.span_id,
            "parent_span_id": self.context.parent_span_id,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_ms": self.duration_ms,
            "attributes": self.attributes,
            "events": [
                {"name": e.name, "timestamp": e.timestamp, "attributes": e.attributes}
                for e in self.events
            ],
            "status": self.status,
            "status_message": self.status_message,
            "trace_flags": self.context.trace_flags.value
        }

# -----------------------------------------------------------------------------
# SPAN PROCESSORS AND EXPORTERS
# -----------------------------------------------------------------------------

class SpanExporter:
    """Base class for span exporters"""
    
    def export(self, spans: list) -> None:
        """Export spans - override in subclasses"""
        pass
    
    def shutdown(self) -> None:
        """Shutdown exporter"""
        pass

class ConsoleSpanExporter(SpanExporter):
    """Simple console exporter for debugging"""
    
    def export(self, spans: list) -> None:
        """Export spans to console"""
        for span in spans:
            print(f"[TRACE] {span.name} | trace_id={span.context.trace_id} | "
                  f"span_id={span.context.span_id} | duration={span.duration_ms:.2f}ms | "
                  f"status={span.status}")

class InMemorySpanExporter(SpanExporter):
    """In-memory exporter for testing and buffering"""
    
    def __init__(self, max_spans: int = 1000):
        self._spans: list = []
        self._max_spans = max_spans
        self._lock = threading.Lock()
    
    def export(self, spans: list) -> None:
        """Export spans to memory buffer"""
        with self._lock:
            self._spans.extend(spans)
            if len(self._spans) > self._max_spans:
                self._spans = self._spans[-self._max_spans:]
    
    def get_finished_spans(self) -> list:
        """Get all finished spans"""
        with self._lock:
            return list(self._spans)
    
    def clear(self) -> None:
        """Clear all spans"""
        with self._lock:
            self._spans.clear()

# Global exporter registry
_exporters: list = []
_exporter_lock = threading.Lock()

def add_span_exporter(exporter: SpanExporter) -> None:
    """Add a span exporter"""
    if not OTEL_ENABLED:
        return
    with _exporter_lock:
        _exporters.append(exporter)

def remove_span_exporter(exporter: SpanExporter) -> None:
    """Remove a span exporter"""
    with _exporter_lock:
        if exporter in _exporters:
            _exporters.remove(exporter)

def _export_spans(spans: list) -> None:
    """Export spans to all registered exporters"""
    if not OTEL_ENABLED:
        return
    with _exporter_lock:
        exporters = list(_exporters)
    
    for exporter in exporters:
        try:
            exporter.export(spans)
        except Exception:
            # Never fail the application due to tracing
            pass

# -----------------------------------------------------------------------------
# TRACER IMPLEMENTATION
# -----------------------------------------------------------------------------

class Tracer:
    """Main tracer implementation"""
    
    def __init__(self, name: str, version: str = "1.0.0"):
        self.name = name
        self.version = version
        self._active_spans: Dict[str, Span] = {}
        self._lock = threading.Lock()
    
    def start_span(
        self,
        name: str,
        parent: Optional[TraceContext] = None,
        attributes: Optional[Dict[str, Any]] = None,
        sampled: bool = False
    ) -> Span:
        """Start a new span - always creates valid span objects"""
        if parent is None:
            parent = get_current_trace_context()
        
        span_context = create_child_span(parent)
        span = Span(
            name=name,
            context=span_context,
            attributes=attributes or {}
        )
        
        if OTEL_ENABLED:
            with self._lock:
                self._active_spans[span_context.span_id] = span
        
        return span
    
    def end_span(self, span: Span, status: Optional[str] = None) -> None:
        """End a span and export it"""
        if not OTEL_ENABLED:
            return
        
        span.end(status)
        
        with self._lock:
            self._active_spans.pop(span.context.span_id, None)
        
        _export_spans([span])

# Global tracer instance
_global_tracer = Tracer("neural_shield", "13.0.0")

def get_tracer() -> Tracer:
    """Get the global tracer instance"""
    return _global_tracer

# -----------------------------------------------------------------------------
# DECORATOR FOR EASY INSTRUMENTATION
# -----------------------------------------------------------------------------

T = TypeVar('T')

def instrument(
    name: Optional[str] = None,
    attributes: Optional[Dict[str, Any]] = None,
    add_baggage: Optional[Dict[str, str]] = None
) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """
    Decorator to instrument a function with tracing.
    OPT-IN ONLY - does nothing unless NEURALSHIELD_OTEL_ENABLED=1
    
    Usage:
        @instrument()
        def my_function():
            pass
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        span_name = name or func.__name__
        
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> T:
            if not OTEL_ENABLED:
                return func(*args, **kwargs)
            
            tracer = get_tracer()
            span = tracer.start_span(span_name, attributes=attributes)
            
            # Add baggage items if specified
            if add_baggage:
                baggage = get_current_baggage()
                for key, value in add_baggage.items():
                    baggage.set(key, value)
            
            token = _current_trace_context.set(span.context)
            
            try:
                result = func(*args, **kwargs)
                span.set_status("OK")
                return result
            except Exception as e:
                span.set_status("ERROR", str(e))
                span.add_event("exception", {
                    "exception.type": type(e).__name__,
                    "exception.message": str(e)
                })
                raise
            finally:
                tracer.end_span(span)
                _current_trace_context.reset(token)
        
        return wrapper
    return decorator

# -----------------------------------------------------------------------------
# CONTEXT PROPAGATION HELPERS
# -----------------------------------------------------------------------------

def inject_trace_headers() -> Dict[str, str]:
    """
    Inject trace context into headers for cross-service propagation.
    Returns W3C compliant traceparent and baggage headers.
    """
    if not OTEL_ENABLED:
        return {}
    
    headers = {}
    ctx = get_current_trace_context()
    
    if ctx:
        headers["traceparent"] = ctx.to_traceparent()
    
    baggage = get_current_baggage()
    baggage_header = baggage.to_header()
    if baggage_header:
        headers["baggage"] = baggage_header
    
    return headers

def extract_trace_headers(headers: Dict[str, str]) -> None:
    """
    Extract trace context from incoming request headers.
    Supports W3C traceparent and baggage headers.
    """
    if not OTEL_ENABLED:
        return
    
    traceparent = headers.get("traceparent")
    if traceparent:
        try:
            ctx = TraceContext.from_traceparent(traceparent)
            set_current_trace_context(ctx)
        except ValueError:
            pass
    
    baggage_header = headers.get("baggage")
    if baggage_header:
        baggage = get_current_baggage()
        for item in baggage_header.split(","):
            parts = item.split(";")
            if parts:
                key_value = parts[0].split("=", 1)
                if len(key_value) == 2:
                    key, value = key_value
                    metadata = {}
                    for meta_part in parts[1:]:
                        meta_kv = meta_part.split("=", 1)
                        if len(meta_kv) == 2:
                            metadata[meta_kv[0]] = meta_kv[1]
                    baggage.set(key, value, metadata)

# -----------------------------------------------------------------------------
# METRICS COLLECTION INTEGRATION
# -----------------------------------------------------------------------------

@dataclass
class TraceMetrics:
    """Metrics aggregated from traces"""
    total_spans: int = 0
    error_spans: int = 0
    total_duration_ms: float = 0.0
    span_counts_by_name: Dict[str, int] = field(default_factory=dict)
    
    def record_span(self, span: Span) -> None:
        """Record a span for metrics"""
        self.total_spans += 1
        if span.status == "ERROR":
            self.error_spans += 1
        if span.duration_ms:
            self.total_duration_ms += span.duration_ms
        self.span_counts_by_name[span.name] = self.span_counts_by_name.get(span.name, 0) + 1
    
    @property
    def error_rate(self) -> float:
        """Get error rate as percentage"""
        if self.total_spans == 0:
            return 0.0
        return (self.error_spans / self.total_spans) * 100
    
    @property
    def average_duration_ms(self) -> float:
        """Get average span duration"""
        if self.total_spans == 0:
            return 0.0
        return self.total_duration_ms / self.total_spans

# -----------------------------------------------------------------------------
# USAGE EXAMPLES (DOCUMENTATION)
# -----------------------------------------------------------------------------

"""
EXAMPLE USAGE - OPT-IN ONLY:

1. Enable tracing:
   export NEURALSHIELD_OTEL_ENABLED=1

2. Add console exporter:
   from neural_shield.observability_opentelemetry_context_propagation_baggage_v13_2026_june import (
       add_span_exporter, ConsoleSpanExporter, instrument
   )
   add_span_exporter(ConsoleSpanExporter())

3. Instrument functions:
   @instrument("detect_threat", attributes={"module": "security"})
   def detect_threat(prompt: str) -> dict:
       # Your existing code here
       return {"threat_detected": False}

4. Cross-service propagation:
   # Outgoing request
   headers = inject_trace_headers()
   requests.post(url, headers=headers, ...)
   
   # Incoming request
   extract_trace_headers(request.headers)

5. Baggage for correlation:
   baggage = get_current_baggage()
   baggage.set("user_id", "12345")
   baggage.set("tenant_id", "acme-corp")
"""

# -----------------------------------------------------------------------------
# SANITY CHECK - ENSURE NO SIDE EFFECTS WHEN DISABLED
# -----------------------------------------------------------------------------

# This module has ZERO runtime impact when OTEL_ENABLED is False (default)
# All instrumentation paths are guarded by the OTEL_ENABLED flag
# No monkey-patching, no global side effects
# Purely additive and opt-in only
