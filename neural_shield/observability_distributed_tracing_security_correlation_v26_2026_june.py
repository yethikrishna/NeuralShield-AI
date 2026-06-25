"""
NeuralShield AI - Distributed Tracing & Security Event Correlation
Dimension D: Observability & Instrumentation - V26

This module provides OPT-IN distributed tracing capabilities with
security event correlation. All instrumentation is completely optional
and disabled by default. Wraps existing code - NO core modifications.

Stability: BETA
Opt-in: Yes (explicit enable required)
Backward Compatible: 100%
"""

import time
import uuid
import json
import threading
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timezone


class TraceLevel(Enum):
    """Trace verbosity levels"""
    DISABLED = 0
    ERROR = 1
    WARNING = 2
    INFO = 3
    DEBUG = 4


class SecurityEventType(Enum):
    """Types of security events for correlation"""
    THREAT_DETECTED = "threat_detected"
    JAILBREAK_ATTEMPT = "jailbreak_attempt"
    PROMPT_INJECTION = "prompt_injection"
    ADVERSARIAL_INPUT = "adversarial_input"
    ACCESS_DENIED = "access_denied"
    POLICY_VIOLATION = "policy_violation"
    ANOMALY_DETECTED = "anomaly_detected"
    MODEL_OUTPUT_SANITIZED = "output_sanitized"


@dataclass
class TraceSpan:
    """Single trace span for distributed tracing"""
    trace_id: str
    span_id: str
    parent_span_id: Optional[str]
    name: str
    start_time: float
    end_time: Optional[float] = None
    duration_ms: Optional[float] = None
    attributes: Dict[str, Any] = field(default_factory=dict)
    events: List[Dict[str, Any]] = field(default_factory=list)
    security_events: List[Dict[str, Any]] = field(default_factory=list)
    status: str = "IN_PROGRESS"


@dataclass
class CorrelatedSecurityEvent:
    """Security event with tracing context"""
    event_id: str
    event_type: SecurityEventType
    timestamp: float
    trace_id: str
    span_id: str
    severity: str
    description: str
    metadata: Dict[str, Any] = field(default_factory=dict)


class ThreadLocalContext(threading.local):
    """Thread-local storage for trace context"""
    def __init__(self):
        self.current_trace_id: Optional[str] = None
        self.current_span_id: Optional[str] = None
        self.span_stack: List[str] = []


class DistributedTracer:
    """
    OPT-IN distributed tracer with security event correlation.
    
    All tracing is disabled by default. Must be explicitly enabled.
    Does not modify any existing core functionality - only wraps it.
    """
    
    def __init__(self, service_name: str = "neuralshield-ai"):
        self.service_name = service_name
        self._enabled = False
        self._trace_level = TraceLevel.DISABLED
        self._spans: Dict[str, TraceSpan] = {}
        self._security_events: List[CorrelatedSecurityEvent] = []
        self._context = ThreadLocalContext()
        self._max_spans = 10000
        self._max_security_events = 5000
        self._lock = threading.Lock()
        self._on_security_event_callback: Optional[Callable] = None
    
    def enable(self, level: TraceLevel = TraceLevel.INFO) -> None:
        """Enable tracing (OPT-IN - must call explicitly)"""
        self._enabled = True
        self._trace_level = level
    
    def disable(self) -> None:
        """Disable tracing completely"""
        self._enabled = False
        self._trace_level = TraceLevel.DISABLED
    
    def is_enabled(self) -> bool:
        return self._enabled and self._trace_level.value > TraceLevel.DISABLED.value
    
    def set_security_event_callback(self, callback: Callable) -> None:
        """Set optional callback for security events"""
        self._on_security_event_callback = callback
    
    def generate_trace_id(self) -> str:
        """Generate a unique trace ID"""
        return str(uuid.uuid4())
    
    def generate_span_id(self) -> str:
        """Generate a unique span ID"""
        return uuid.uuid4().hex[:16]
    
    def start_span(self, 
                   name: str, 
                   trace_id: Optional[str] = None,
                   parent_span_id: Optional[str] = None,
                   attributes: Optional[Dict[str, Any]] = None) -> Optional[str]:
        """
        Start a new trace span.
        
        Returns span_id if tracing enabled, None otherwise.
        """
        if not self.is_enabled():
            return None
        
        with self._lock:
            if len(self._spans) >= self._max_spans:
                return None  # Graceful degradation - stop tracing
            
            actual_trace_id = trace_id or self._context.current_trace_id or self.generate_trace_id()
            actual_parent = parent_span_id or self._context.current_span_id
            
            span = TraceSpan(
                trace_id=actual_trace_id,
                span_id=self.generate_span_id(),
                parent_span_id=actual_parent,
                name=name,
                start_time=time.time(),
                attributes=attributes or {}
            )
            
            self._spans[span.span_id] = span
            self._context.current_trace_id = actual_trace_id
            self._context.span_stack.append(span.span_id)
            self._context.current_span_id = span.span_id
            
            return span.span_id
    
    def end_span(self, span_id: Optional[str] = None, status: str = "OK") -> Optional[float]:
        """End a span and return duration in ms"""
        if not self.is_enabled() or span_id is None:
            return None
        
        with self._lock:
            span = self._spans.get(span_id)
            if span is None:
                return None
            
            span.end_time = time.time()
            span.duration_ms = (span.end_time - span.start_time) * 1000
            span.status = status
            
            # Update context stack
            if self._context.span_stack and self._context.span_stack[-1] == span_id:
                self._context.span_stack.pop()
                self._context.current_span_id = self._context.span_stack[-1] if self._context.span_stack else None
                if not self._context.span_stack:
                    self._context.current_trace_id = None
            
            return span.duration_ms
    
    def add_span_attribute(self, span_id: Optional[str], key: str, value: Any) -> None:
        """Add attribute to span if tracing enabled"""
        if not self.is_enabled() or span_id is None:
            return
        
        with self._lock:
            span = self._spans.get(span_id)
            if span:
                span.attributes[key] = value
    
    def add_span_event(self, span_id: Optional[str], event_name: str, attributes: Optional[Dict] = None) -> None:
        """Add event to span if tracing enabled"""
        if not self.is_enabled() or span_id is None:
            return
        
        with self._lock:
            span = self._spans.get(span_id)
            if span:
                span.events.append({
                    "name": event_name,
                    "timestamp": time.time(),
                    "attributes": attributes or {}
                })
    
    def log_security_event(self,
                           event_type: SecurityEventType,
                           severity: str,
                           description: str,
                           metadata: Optional[Dict[str, Any]] = None) -> Optional[str]:
        """
        Log a security event with current tracing context.
        
        Returns event_id if tracing enabled, None otherwise.
        """
        if not self.is_enabled():
            return None
        
        with self._lock:
            if len(self._security_events) >= self._max_security_events:
                return None  # Graceful degradation
            
            event = CorrelatedSecurityEvent(
                event_id=str(uuid.uuid4()),
                event_type=event_type,
                timestamp=time.time(),
                trace_id=self._context.current_trace_id or "unknown",
                span_id=self._context.current_span_id or "unknown",
                severity=severity,
                description=description,
                metadata=metadata or {}
            )
            
            self._security_events.append(event)
            
            # Also attach to current span if available
            if self._context.current_span_id:
                span = self._spans.get(self._context.current_span_id)
                if span:
                    span.security_events.append({
                        "event_id": event.event_id,
                        "event_type": event.event_type.value,
                        "severity": severity,
                        "description": description
                    })
            
            # Trigger callback if set
            if self._on_security_event_callback:
                try:
                    self._on_security_event_callback(event)
                except Exception:
                    pass  # Never let tracing break core functionality
            
            return event.event_id
    
    def get_trace_summary(self, trace_id: str) -> Optional[Dict[str, Any]]:
        """Get summary of all spans in a trace"""
        if not self.is_enabled():
            return None
        
        with self._lock:
            trace_spans = [s for s in self._spans.values() if s.trace_id == trace_id]
            if not trace_spans:
                return None
            
            total_duration = max(s.end_time or s.start_time for s in trace_spans) - \
                           min(s.start_time for s in trace_spans)
            
            security_count = sum(len(s.security_events) for s in trace_spans)
            
            return {
                "trace_id": trace_id,
                "span_count": len(trace_spans),
                "total_duration_ms": total_duration * 1000,
                "security_events_count": security_count,
                "spans": [
                    {
                        "name": s.name,
                        "duration_ms": s.duration_ms,
                        "status": s.status,
                        "security_events": len(s.security_events)
                    }
                    for s in trace_spans
                ]
            }
    
    def get_security_correlations(self, min_severity: str = "WARNING") -> List[Dict[str, Any]]:
        """Get security events correlated with traces"""
        if not self.is_enabled():
            return []
        
        severity_order = {"DEBUG": 0, "INFO": 1, "WARNING": 2, "ERROR": 3, "CRITICAL": 4}
        min_level = severity_order.get(min_severity, 2)
        
        with self._lock:
            return [
                {
                    "event_id": e.event_id,
                    "event_type": e.event_type.value,
                    "timestamp": datetime.fromtimestamp(e.timestamp, tz=timezone.utc).isoformat(),
                    "trace_id": e.trace_id,
                    "span_id": e.span_id,
                    "severity": e.severity,
                    "description": e.description,
                    "metadata": e.metadata
                }
                for e in self._security_events
                if severity_order.get(e.severity, 0) >= min_level
            ]
    
    def export_traces_json(self) -> str:
        """Export all traces as JSON (for observability pipelines)"""
        if not self.is_enabled():
            return json.dumps({"traces": [], "security_events": []})
        
        with self._lock:
            return json.dumps({
                "service": self.service_name,
                "export_time": datetime.now(timezone.utc).isoformat(),
                "traces": [
                    {
                        "trace_id": tid,
                        "spans": [
                            {
                                "span_id": s.span_id,
                                "parent_span_id": s.parent_span_id,
                                "name": s.name,
                                "start_time": s.start_time,
                                "end_time": s.end_time,
                                "duration_ms": s.duration_ms,
                                "status": s.status,
                                "attributes": s.attributes,
                                "security_events": s.security_events
                            }
                            for s in self._spans.values() if s.trace_id == tid
                        ]
                    }
                    for tid in set(s.trace_id for s in self._spans.values())
                ],
                "security_events": self.get_security_correlations("DEBUG")
            }, indent=2)
    
    def clear(self) -> None:
        """Clear all traces and events"""
        with self._lock:
            self._spans.clear()
            self._security_events.clear()
            self._context.current_trace_id = None
            self._context.current_span_id = None
            self._context.span_stack.clear()


# Global tracer instance - DISABLED BY DEFAULT
_global_tracer = DistributedTracer()


def get_tracer() -> DistributedTracer:
    """Get the global tracer instance (starts disabled)"""
    return _global_tracer


def traced_operation(name: Optional[str] = None, 
                     attributes: Optional[Dict[str, Any]] = None):
    """
    Decorator for tracing operations. OPT-IN - does nothing unless tracer enabled.
    
    Usage:
        @traced_operation("detect_jailbreak")
        def detect_jailbreak(prompt):
            ...
    """
    def decorator(func: Callable) -> Callable:
        span_name = name or func.__name__
        
        def wrapper(*args, **kwargs):
            tracer = get_tracer()
            if not tracer.is_enabled():
                return func(*args, **kwargs)  # No overhead when disabled
            
            span_id = tracer.start_span(span_name, attributes=attributes)
            try:
                result = func(*args, **kwargs)
                tracer.end_span(span_id, "OK")
                return result
            except Exception as e:
                tracer.end_span(span_id, "ERROR")
                tracer.add_span_attribute(span_id, "error", str(e))
                raise
        return wrapper
    return decorator


# Export public API
__all__ = [
    "DistributedTracer",
    "TraceLevel",
    "SecurityEventType",
    "get_tracer",
    "traced_operation"
]
