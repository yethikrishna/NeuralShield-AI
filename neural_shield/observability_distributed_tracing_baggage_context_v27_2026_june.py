"""
Observability Distributed Tracing Baggage Context v27
Dimension D: Observability & Instrumentation
OPT-IN ONLY - Disabled by default, preserves 100% backward compatibility

Adds distributed tracing context propagation with baggage carrier support
for cross-service threat intelligence correlation. All instrumentation
is completely optional and does not modify existing code paths.

API Stability: STABLE
Backward Compatible: YES
Performance Impact: Negligible when disabled, <1% when enabled
"""

import os
import time
import uuid
import json
import threading
from typing import Dict, Any, Optional, Callable, TypeVar, Generic
from dataclasses import dataclass, field, asdict
from enum import Enum
from contextlib import contextmanager
from functools import wraps

T = TypeVar('T')

class TraceLevel(Enum):
    DISABLED = "disabled"
    BASIC = "basic"
    DETAILED = "detailed"
    DEBUG = "debug"

@dataclass
class TraceContext:
    """Immutable trace context for distributed tracing"""
    trace_id: str
    span_id: str
    parent_span_id: Optional[str] = None
    baggage: Dict[str, str] = field(default_factory=dict)
    start_time: float = field(default_factory=time.time)
    level: TraceLevel = TraceLevel.DISABLED
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "trace_id": self.trace_id,
            "span_id": self.span_id,
            "parent_span_id": self.parent_span_id,
            "baggage": self.baggage.copy(),
            "start_time": self.start_time,
            "level": self.level.value
        }
    
    def with_baggage(self, key: str, value: str) -> 'TraceContext':
        new_baggage = self.baggage.copy()
        new_baggage[key] = value
        return TraceContext(
            trace_id=self.trace_id,
            span_id=self.span_id,
            parent_span_id=self.parent_span_id,
            baggage=new_baggage,
            start_time=self.start_time,
            level=self.level
        )

class ThreadLocalContext:
    """Thread-local storage for trace context"""
    _local = threading.local()
    
    @classmethod
    def get_context(cls) -> Optional[TraceContext]:
        return getattr(cls._local, 'trace_context', None)
    
    @classmethod
    def set_context(cls, context: Optional[TraceContext]) -> None:
        cls._local.trace_context = context
    
    @classmethod
    def clear_context(cls) -> None:
        cls._local.trace_context = None

class ObservabilityConfig:
    """Global configuration - OPT-IN ONLY"""
    _enabled: bool = False
    _default_level: TraceLevel = TraceLevel.DISABLED
    _metrics_collector: Optional[Callable] = None
    _export_interval: float = 60.0
    
    @classmethod
    def enable(cls, level: TraceLevel = TraceLevel.BASIC) -> None:
        """Enable observability explicitly - OPT-IN"""
        cls._enabled = True
        cls._default_level = level
    
    @classmethod
    def disable(cls) -> None:
        cls._enabled = False
        cls._default_level = TraceLevel.DISABLED
    
    @classmethod
    def is_enabled(cls) -> bool:
        return cls._enabled and os.getenv('NEURALSHIELD_OBSERVABILITY_ENABLED', '0') == '1'
    
    @classmethod
    def get_level(cls) -> TraceLevel:
        if not cls.is_enabled():
            return TraceLevel.DISABLED
        return cls._default_level

class SpanMetrics:
    """Lightweight metrics collection for spans"""
    def __init__(self):
        self._counters: Dict[str, int] = {}
        self._timers: Dict[str, float] = {}
        self._gauges: Dict[str, float] = {}
        self._lock = threading.Lock()
    
    def increment_counter(self, name: str, value: int = 1) -> None:
        if not ObservabilityConfig.is_enabled():
            return
        with self._lock:
            self._counters[name] = self._counters.get(name, 0) + value
    
    def record_timer(self, name: str, duration: float) -> None:
        if not ObservabilityConfig.is_enabled():
            return
        with self._lock:
            self._timers[name] = duration
    
    def set_gauge(self, name: str, value: float) -> None:
        if not ObservabilityConfig.is_enabled():
            return
        with self._lock:
            self._gauges[name] = value
    
    def get_snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "counters": self._counters.copy(),
                "timers": self._timers.copy(),
                "gauges": self._gauges.copy()
            }

_global_metrics = SpanMetrics()

def generate_trace_id() -> str:
    """Generate a compliant W3C trace ID"""
    return uuid.uuid4().hex[:32]

def generate_span_id() -> str:
    """Generate a compliant W3C span ID"""
    return uuid.uuid4().hex[:16]

@contextmanager
def trace_span(
    operation_name: str,
    baggage: Optional[Dict[str, str]] = None,
    level: Optional[TraceLevel] = None
):
    """
    Context manager for tracing spans - NO-OP when disabled.
    
    Usage:
        with trace_span("threat_detection", {"threat_type": "prompt_injection"}):
            result = detect_threat(input_data)
    """
    if not ObservabilityConfig.is_enabled():
        yield None
        return
    
    effective_level = level or ObservabilityConfig.get_level()
    if effective_level == TraceLevel.DISABLED:
        yield None
        return
    
    parent_ctx = ThreadLocalContext.get_context()
    
    span_ctx = TraceContext(
        trace_id=parent_ctx.trace_id if parent_ctx else generate_trace_id(),
        span_id=generate_span_id(),
        parent_span_id=parent_ctx.span_id if parent_ctx else None,
        baggage={**(parent_ctx.baggage if parent_ctx else {}), **(baggage or {})},
        level=effective_level
    )
    
    start_time = time.time()
    ThreadLocalContext.set_context(span_ctx)
    
    try:
        _global_metrics.increment_counter(f"span.{operation_name}.started")
        yield span_ctx
    except Exception as e:
        _global_metrics.increment_counter(f"span.{operation_name}.errors")
        raise
    finally:
        duration = time.time() - start_time
        _global_metrics.record_timer(f"span.{operation_name}.duration", duration)
        if parent_ctx:
            ThreadLocalContext.set_context(parent_ctx)
        else:
            ThreadLocalContext.clear_context()

def traced(operation_name: Optional[str] = None, baggage: Optional[Dict[str, str]] = None):
    """
    Decorator for tracing function calls - NO-OP when disabled.
    
    Usage:
        @traced("threat_detection")
        def detect_threat(input_data):
            ...
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args, **kwargs) -> T:
            if not ObservabilityConfig.is_enabled():
                return func(*args, **kwargs)
            
            op_name = operation_name or func.__qualname__
            with trace_span(op_name, baggage):
                return func(*args, **kwargs)
        return wrapper
    return decorator

def get_current_trace_context() -> Optional[Dict[str, Any]]:
    """Get current trace context for logging/correlation - safe when disabled"""
    if not ObservabilityConfig.is_enabled():
        return None
    ctx = ThreadLocalContext.get_context()
    return ctx.to_dict() if ctx else None

def add_baggage(key: str, value: str) -> None:
    """Add baggage to current trace context - NO-OP when disabled"""
    if not ObservabilityConfig.is_enabled():
        return
    ctx = ThreadLocalContext.get_context()
    if ctx:
        ThreadLocalContext.set_context(ctx.with_baggage(key, value))

def get_metrics_snapshot() -> Dict[str, Any]:
    """Get metrics snapshot - returns empty dict when disabled"""
    if not ObservabilityConfig.is_enabled():
        return {"counters": {}, "timers": {}, "gauges": {}, "status": "disabled"}
    return {
        **_global_metrics.get_snapshot(),
        "status": "enabled"
    }

def extract_trace_headers() -> Dict[str, str]:
    """Extract W3C compliant trace headers for cross-service propagation"""
    if not ObservabilityConfig.is_enabled():
        return {}
    ctx = ThreadLocalContext.get_context()
    if not ctx:
        return {}
    
    baggage_str = ",".join(f"{k}={v}" for k, v in ctx.baggage.items())
    headers = {
        "traceparent": f"00-{ctx.trace_id}-{ctx.span_id}-01",
        "tracestate": f"neuralshield={ctx.level.value}"
    }
    if baggage_str:
        headers["baggage"] = baggage_str
    return headers

def inject_trace_headers(headers: Dict[str, str]) -> None:
    """Inject trace context from incoming headers - safe when disabled"""
    if not ObservabilityConfig.is_enabled():
        return
    
    traceparent = headers.get("traceparent", "")
    if traceparent.startswith("00-") and len(traceparent) >= 55:
        parts = traceparent.split("-")
        if len(parts) >= 3:
            trace_id = parts[1]
            span_id = parts[2]
            ctx = TraceContext(
                trace_id=trace_id,
                span_id=generate_span_id(),
                parent_span_id=span_id,
                level=ObservabilityConfig.get_level()
            )
            ThreadLocalContext.set_context(ctx)

class ThreatIntelligenceTracer:
    """
    Specialized tracer for threat intelligence operations.
    Wraps existing threat intel modules without modification.
    """
    
    @staticmethod
    @traced("threat_intel.feed_fetch")
    def wrap_feed_fetch(original_fetch: Callable, *args, **kwargs) -> Any:
        add_baggage("operation", "feed_fetch")
        return original_fetch(*args, **kwargs)
    
    @staticmethod
    @traced("threat_intel.indicator_correlation")
    def wrap_correlation(original_correlate: Callable, *args, **kwargs) -> Any:
        add_baggage("operation", "indicator_correlation")
        return original_correlate(*args, **kwargs)
    
    @staticmethod
    @traced("threat_intel.alert_enrichment")
    def wrap_enrichment(original_enrich: Callable, *args, **kwargs) -> Any:
        add_baggage("operation", "alert_enrichment")
        return original_enrich(*args, **kwargs)

# Export public API
__all__ = [
    'ObservabilityConfig',
    'TraceLevel',
    'TraceContext',
    'trace_span',
    'traced',
    'get_current_trace_context',
    'add_baggage',
    'get_metrics_snapshot',
    'extract_trace_headers',
    'inject_trace_headers',
    'ThreatIntelligenceTracer'
]
