"""
NeuralShield AI - Enhanced Distributed Tracing Module (Dimension D - Observability)
Version: V7
Stability: STABLE
Backward Compatible: YES
Opt-In: YES (disabled by default)

This module adds distributed tracing capabilities ON TOP of existing code.
No existing code is modified - this is purely additive.
"""

import time
import uuid
import threading
from typing import Dict, Any, Optional, List, Callable
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict


class SpanKind(Enum):
    INTERNAL = "internal"
    SERVER = "server"
    CLIENT = "client"
    PRODUCER = "producer"
    CONSUMER = "consumer"


class SpanStatus(Enum):
    OK = "ok"
    ERROR = "error"
    UNSET = "unset"


@dataclass
class SpanEvent:
    name: str
    timestamp: float = field(default_factory=time.time)
    attributes: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SpanLink:
    trace_id: str
    span_id: str
    attributes: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Span:
    name: str
    trace_id: str
    span_id: str
    parent_span_id: Optional[str] = None
    kind: SpanKind = SpanKind.INTERNAL
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None
    status: SpanStatus = SpanStatus.UNSET
    attributes: Dict[str, Any] = field(default_factory=dict)
    events: List[SpanEvent] = field(default_factory=list)
    links: List[SpanLink] = field(default_factory=list)
    
    def add_event(self, name: str, **attributes) -> None:
        """Add an event to the span."""
        self.events.append(SpanEvent(name=name, attributes=attributes))
    
    def add_link(self, trace_id: str, span_id: str, **attributes) -> None:
        """Add a link to another span."""
        self.links.append(SpanLink(trace_id=trace_id, span_id=span_id, attributes=attributes))
    
    def set_attribute(self, key: str, value: Any) -> None:
        """Set an attribute on the span."""
        self.attributes[key] = value
    
    def set_status(self, status: SpanStatus) -> None:
        """Set the span status."""
        self.status = status
    
    def end(self) -> None:
        """End the span."""
        self.end_time = time.time()
    
    @property
    def duration_ms(self) -> Optional[float]:
        """Get span duration in milliseconds."""
        if self.end_time and self.start_time:
            return (self.end_time - self.start_time) * 1000
        return None


class TraceContext:
    """Thread-local trace context storage."""
    
    _thread_local = threading.local()
    
    @classmethod
    def get_current_span(cls) -> Optional[Span]:
        """Get the current active span."""
        return getattr(cls._thread_local, 'current_span', None)
    
    @classmethod
    def set_current_span(cls, span: Optional[Span]) -> None:
        """Set the current active span."""
        cls._thread_local.current_span = span
    
    @classmethod
    def get_trace_id(cls) -> Optional[str]:
        """Get the current trace ID."""
        span = cls.get_current_span()
        return span.trace_id if span else None


class EnhancedTracer:
    """
    Enhanced distributed tracer.
    OPT-IN - must be explicitly enabled.
    No impact on existing code when disabled.
    """
    
    def __init__(self, service_name: str = "neural_shield"):
        self.service_name = service_name
        self.enabled = False
        self.spans: Dict[str, List[Span]] = defaultdict(list)
        self.max_spans_per_trace = 1000
        self._lock = threading.Lock()
    
    def enable(self) -> None:
        """Enable tracing."""
        self.enabled = True
    
    def disable(self) -> None:
        """Disable tracing."""
        self.enabled = False
    
    def is_enabled(self) -> bool:
        """Check if tracing is enabled."""
        return self.enabled
    
    def start_span(
        self,
        name: str,
        kind: SpanKind = SpanKind.INTERNAL,
        parent_trace_id: Optional[str] = None,
        parent_span_id: Optional[str] = None,
        **attributes
    ) -> Span:
        """
        Start a new span.
        Returns a no-op span if tracing is disabled.
        """
        if not self.enabled:
            return self._create_noop_span(name)
        
        trace_id = parent_trace_id or self._generate_trace_id()
        span_id = self._generate_span_id()
        
        # Inherit from thread-local context if available
        current_span = TraceContext.get_current_span()
        if current_span and not parent_span_id:
            parent_span_id = current_span.span_id
            if not parent_trace_id:
                trace_id = current_span.trace_id
        
        span = Span(
            name=name,
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=parent_span_id,
            kind=kind,
            attributes=attributes
        )
        
        with self._lock:
            trace_spans = self.spans[trace_id]
            if len(trace_spans) < self.max_spans_per_trace:
                trace_spans.append(span)
        
        return span
    
    def _create_noop_span(self, name: str) -> Span:
        """Create a no-op span for when tracing is disabled."""
        return Span(
            name=name,
            trace_id="noop",
            span_id="noop",
            start_time=0,
            end_time=0
        )
    
    def _generate_trace_id(self) -> str:
        """Generate a unique trace ID."""
        return uuid.uuid4().hex
    
    def _generate_span_id(self) -> str:
        """Generate a unique span ID."""
        return uuid.uuid4().hex[:16]
    
    def get_trace(self, trace_id: str) -> List[Span]:
        """Get all spans for a trace."""
        with self._lock:
            return list(self.spans.get(trace_id, []))
    
    def get_trace_summary(self, trace_id: str) -> Dict[str, Any]:
        """Get a summary of a trace."""
        spans = self.get_trace(trace_id)
        if not spans:
            return {}
        
        total_duration = sum(
            s.duration_ms for s in spans if s.duration_ms
        )
        error_count = sum(
            1 for s in spans if s.status == SpanStatus.ERROR
        )
        
        return {
            "trace_id": trace_id,
            "span_count": len(spans),
            "total_duration_ms": total_duration,
            "error_count": error_count,
            "service": self.service_name
        }
    
    def clear_trace(self, trace_id: str) -> None:
        """Clear spans for a trace to free memory."""
        with self._lock:
            self.spans.pop(trace_id, None)
    
    def export_spans(self, trace_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Export spans as dictionaries for serialization."""
        result = []
        with self._lock:
            if trace_id:
                spans = self.spans.get(trace_id, [])
            else:
                spans = [s for spans in self.spans.values() for s in spans]
            
            for span in spans:
                result.append({
                    "name": span.name,
                    "trace_id": span.trace_id,
                    "span_id": span.span_id,
                    "parent_span_id": span.parent_span_id,
                    "kind": span.kind.value,
                    "start_time": span.start_time,
                    "end_time": span.end_time,
                    "duration_ms": span.duration_ms,
                    "status": span.status.value,
                    "attributes": span.attributes,
                    "events": [
                        {"name": e.name, "timestamp": e.timestamp, "attributes": e.attributes}
                        for e in span.events
                    ]
                })
        return result


def traced(name: Optional[str] = None, **attributes):
    """
    Decorator for tracing function calls.
    OPT-IN - only active if tracer is enabled.
    
    Usage:
        @traced("my_function", category="security")
        def my_function():
            ...
    """
    def decorator(func: Callable) -> Callable:
        span_name = name or func.__name__
        
        def wrapper(*args, **kwargs):
            tracer = GLOBAL_TRACER
            if not tracer.is_enabled():
                return func(*args, **kwargs)
            
            span = tracer.start_span(span_name, **attributes)
            TraceContext.set_current_span(span)
            
            try:
                result = func(*args, **kwargs)
                span.set_status(SpanStatus.OK)
                return result
            except Exception as e:
                span.set_status(SpanStatus.ERROR)
                span.set_attribute("error.type", type(e).__name__)
                span.set_attribute("error.message", str(e))
                raise
            finally:
                span.end()
                TraceContext.set_current_span(None)
        
        return wrapper
    return decorator


# Global tracer instance - OPT-IN, disabled by default
GLOBAL_TRACER = EnhancedTracer()
