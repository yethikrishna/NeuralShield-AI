"""
NeuralShield Enhanced Distributed Tracing with Baggage Context Propagation v11
Dimension D - Observability & Instrumentation

Add-only module - wraps existing threat detection modules with:
- Distributed tracing span context propagation
- Baggage carrier for cross-module correlation
- Correlation ID management across request lifecycle
- Trace context serialization/deserialization
- Parent-child span relationship management
- Optional, opt-in instrumentation only

All existing code behavior is 100% preserved.
"""

import uuid
import time
import json
import threading
from typing import Dict, Any, Optional, List, Callable
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timezone


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
class TraceBaggage:
    """Thread-safe baggage carrier for cross-module trace context."""
    _storage: threading.local = field(default_factory=threading.local)
    
    def set_correlation_id(self, correlation_id: str) -> None:
        """Set correlation ID for current thread context."""
        setattr(self._storage, 'correlation_id', correlation_id)
    
    def get_correlation_id(self) -> Optional[str]:
        """Get correlation ID from current thread context."""
        return getattr(self._storage, 'correlation_id', None)
    
    def set_baggage_item(self, key: str, value: str) -> None:
        """Set a baggage item in current context."""
        if not hasattr(self._storage, 'baggage'):
            self._storage.baggage = {}
        self._storage.baggage[key] = value
    
    def get_baggage_item(self, key: str) -> Optional[str]:
        """Get a baggage item from current context."""
        if not hasattr(self._storage, 'baggage'):
            return None
        return self._storage.baggage.get(key)
    
    def get_all_baggage(self) -> Dict[str, str]:
        """Get all baggage items."""
        if not hasattr(self._storage, 'baggage'):
            return {}
        return dict(self._storage.baggage)
    
    def clear(self) -> None:
        """Clear all baggage for current thread."""
        self._storage.__dict__.clear()


@dataclass
class TraceSpan:
    """Single trace span representing a unit of work."""
    trace_id: str
    span_id: str
    parent_span_id: Optional[str]
    name: str
    kind: SpanKind
    start_time: float
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
            "attributes": self.attributes,
            "events": self.events,
            "baggage": self.baggage
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
    """Main tracer implementation - opt-in only."""
    
    def __init__(self, service_name: str = "neuralshield"):
        self.service_name = service_name
        self.baggage = TraceBaggage()
        self._spans: Dict[str, TraceSpan] = {}
        self._active_spans: threading.local = threading.local()
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
            # Return no-op span when disabled
            return TraceSpan(
                trace_id="disabled",
                span_id="disabled",
                parent_span_id=None,
                name=name,
                kind=kind,
                start_time=time.time()
            )
        
        trace_id = TraceContextPropagator.generate_trace_id()
        parent_span_id = None
        
        # Extract parent context if provided
        if parent_context:
            if "trace_id" in parent_context:
                trace_id = parent_context["trace_id"]
            if "span_id" in parent_context:
                parent_span_id = parent_context["span_id"]
        elif hasattr(self._active_spans, 'current') and self._active_spans.current:
            parent_span_id = self._active_spans.current.span_id
            trace_id = self._active_spans.current.trace_id
        
        span = TraceSpan(
            trace_id=trace_id,
            span_id=TraceContextPropagator.generate_span_id(),
            parent_span_id=parent_span_id,
            name=name,
            kind=kind,
            start_time=time.time(),
            attributes=attributes or {},
            baggage=self.baggage.get_all_baggage()
        )
        
        self._spans[span.span_id] = span
        self._active_spans.current = span
        
        # Set correlation ID
        if not self.baggage.get_correlation_id():
            self.baggage.set_correlation_id(trace_id)
        
        return span
    
    def end_span(self, span: TraceSpan, status: SpanStatus = SpanStatus.OK) -> None:
        """End a span and trigger callbacks."""
        if not self._enabled:
            return
        
        span.set_status(status)
        span.end()
        
        for callback in self._on_span_end_callbacks:
            try:
                callback(span)
            except Exception:
                pass  # Never break user code for instrumentation failures
        
        # Clear active span if this was the active one
        if (hasattr(self._active_spans, 'current') and 
            self._active_spans.current and 
            self._active_spans.current.span_id == span.span_id):
            self._active_spans.current = None
    
    def get_current_span(self) -> Optional[TraceSpan]:
        """Get currently active span."""
        if not self._enabled:
            return None
        return getattr(self._active_spans, 'current', None)
    
    def get_span_by_id(self, span_id: str) -> Optional[TraceSpan]:
        """Get span by ID."""
        return self._spans.get(span_id)
    
    def get_all_spans(self) -> List[TraceSpan]:
        """Get all recorded spans."""
        return list(self._spans.values())
    
    def trace_as_span(
        self,
        name: Optional[str] = None,
        kind: SpanKind = SpanKind.INTERNAL,
        attributes: Optional[Dict[str, Any]] = None
    ):
        """Decorator to wrap function calls as spans."""
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
    
    def extract_trace_context(self, headers: Dict[str, str]) -> Optional[Dict[str, str]]:
        """Extract trace context from HTTP headers."""
        traceparent = headers.get(TraceContextPropagator.TRACEPARENT_HEADER.lower())
        if not traceparent:
            return None
        
        parsed = TraceContextPropagator.deserialize_traceparent(traceparent)
        if not parsed:
            return None
        
        # Extract baggage
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
        
        headers = {
            TraceContextPropagator.TRACEPARENT_HEADER: 
                TraceContextPropagator.serialize_traceparent(
                    current_span.trace_id,
                    current_span.span_id
                )
        }
        
        baggage = self.baggage.get_all_baggage()
        if baggage:
            headers["baggage"] = TraceContextPropagator.serialize_baggage(baggage)
        
        return headers


# Global singleton tracer - disabled by default (opt-in)
global_tracer = Tracer()


# Exported convenience functions
def enable_tracing() -> None:
    """Enable distributed tracing (opt-in)."""
    global_tracer.enable()


def disable_tracing() -> None:
    """Disable distributed tracing."""
    global_tracer.disable()


def is_tracing_enabled() -> bool:
    """Check if tracing is enabled."""
    return global_tracer.is_enabled()


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
    """Decorator to trace function execution."""
    return global_tracer.trace_as_span(name, **kwargs)
