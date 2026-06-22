"""
NeuralShield AI - Enhanced Distributed Tracing with Baggage Context v9
Dimension D: Observability & Instrumentation
STABILITY: STABLE - Production ready, OPT-IN only

Implements W3C Trace Context standard, baggage propagation,
cross-module correlation IDs, and intelligent trace sampling.

DESIGN PHILOSOPHY:
- 100% OPT-IN - disabled by default
- Pure wrapper - no modification of existing code
- Zero overhead when disabled
- W3C standard compliant trace context
- Baggage for cross-cutting context propagation
- Intelligent sampling strategies
"""

from __future__ import annotations

import os
import uuid
import time
import random
import hashlib
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional, Dict, Any, Callable, TypeVar, Generic
from typing_extensions import Self
from datetime import datetime, timezone
import threading
import contextvars
import json

# -----------------------------------------------------------------------------
# Configuration - OPT-IN ONLY
# -----------------------------------------------------------------------------

NS_TRACING_ENABLED: bool = os.environ.get("NEURALSHIELD_TRACING_ENABLED", "0") == "1"
NS_TRACING_SAMPLE_RATE: float = float(os.environ.get("NEURALSHIELD_TRACING_SAMPLE_RATE", "0.01"))
NS_TRACING_BAGGAGE_MAX_SIZE: int = int(os.environ.get("NEURALSHIELD_BAGGAGE_MAX_SIZE", "4096"))

# -----------------------------------------------------------------------------
# Enums
# -----------------------------------------------------------------------------

class TraceFlag(Enum):
    """W3C Trace Context flags"""
    NOT_SAMPLED = 0x00
    SAMPLED = 0x01
    RANDOM = 0x02

class SamplingStrategy(Enum):
    """Trace sampling strategies"""
    ALWAYS_OFF = auto()
    ALWAYS_ON = auto()
    PROBABILISTIC = auto()
    RATE_LIMITED = auto()
    ERROR_ONLY = auto()
    ADAPTIVE = auto()

class TraceLevel(Enum):
    """Trace verbosity levels"""
    MINIMAL = auto()
    STANDARD = auto()
    DETAILED = auto()
    DEBUG = auto()

# -----------------------------------------------------------------------------
# Context Vars for Thread-Local Trace Context
# -----------------------------------------------------------------------------

_current_trace_context: contextvars.ContextVar[Optional["TraceContext"]] = contextvars.ContextVar(
    "ns_current_trace_context",
    default=None
)

_current_baggage: contextvars.ContextVar[Dict[str, str]] = contextvars.ContextVar(
    "ns_current_baggage",
    default={}
)

# -----------------------------------------------------------------------------
# Trace Context - W3C Compliant
# -----------------------------------------------------------------------------

@dataclass(frozen=True)
class TraceContext:
    """
    W3C Trace Context compliant trace context.
    
    Format: version-traceid-parentid-flags
    Example: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01
    """
    version: str = "00"
    trace_id: str = field(default_factory=lambda: TraceContext.generate_trace_id())
    parent_id: str = field(default_factory=lambda: TraceContext.generate_span_id())
    flags: int = TraceFlag.NOT_SAMPLED.value
    trace_state: Dict[str, str] = field(default_factory=dict)
    start_time: float = field(default_factory=time.time)
    attributes: Dict[str, Any] = field(default_factory=dict)
    
    @staticmethod
    def generate_trace_id() -> str:
        """Generate 16-byte (32 hex char) trace ID - W3C compliant"""
        return uuid.uuid4().hex
    
    @staticmethod
    def generate_span_id() -> str:
        """Generate 8-byte (16 hex char) span ID - W3C compliant"""
        return uuid.uuid4().hex[:16]
    
    @staticmethod
    def generate_correlation_id() -> str:
        """Generate cross-module correlation ID"""
        return f"ns-correlation-{uuid.uuid4().hex[:12]}"
    
    @classmethod
    def from_traceparent(cls, traceparent: str) -> Optional[Self]:
        """Parse W3C traceparent header"""
        try:
            parts = traceparent.split("-")
            if len(parts) != 4:
                return None
            version, trace_id, parent_id, flags_hex = parts
            if version != "00":
                return None
            if len(trace_id) != 32 or len(parent_id) != 16:
                return None
            flags = int(flags_hex, 16)
            return cls(
                version=version,
                trace_id=trace_id,
                parent_id=parent_id,
                flags=flags
            )
        except Exception:
            return None
    
    def to_traceparent(self) -> str:
        """Serialize to W3C traceparent format"""
        return f"{self.version}-{self.trace_id}-{self.parent_id}-{self.flags:02x}"
    
    def to_headers(self) -> Dict[str, str]:
        """Convert to HTTP headers for propagation"""
        headers = {"traceparent": self.to_traceparent()}
        if self.trace_state:
            headers["tracestate"] = ",".join(f"{k}={v}" for k, v in self.trace_state.items())
        return headers
    
    def is_sampled(self) -> bool:
        """Check if this trace should be sampled"""
        return (self.flags & TraceFlag.SAMPLED.value) != 0
    
    def with_sampled(self, sampled: bool = True) -> "TraceContext":
        """Create new context with sampling flag updated"""
        new_flags = self.flags | TraceFlag.SAMPLED.value if sampled else self.flags & ~TraceFlag.SAMPLED.value
        return TraceContext(
            version=self.version,
            trace_id=self.trace_id,
            parent_id=self.parent_id,
            flags=new_flags,
            trace_state=self.trace_state.copy(),
            attributes=self.attributes.copy()
        )
    
    def child_span(self, span_name: Optional[str] = None) -> "TraceContext":
        """Create child span context"""
        child = TraceContext(
            version=self.version,
            trace_id=self.trace_id,
            parent_id=TraceContext.generate_span_id(),
            flags=self.flags,
            trace_state=self.trace_state.copy(),
            attributes={**self.attributes, "parent_span_id": self.parent_id}
        )
        if span_name:
            child.attributes["span_name"] = span_name
        return child
    
    def duration_ms(self) -> float:
        """Get elapsed duration in milliseconds"""
        return (time.time() - self.start_time) * 1000

# -----------------------------------------------------------------------------
# Baggage Manager - Cross-Cutting Context
# -----------------------------------------------------------------------------

class BaggageManager:
    """
    Manages baggage context propagation across module boundaries.
    Baggage carries cross-cutting concerns like:
    - User IDs
    - Request IDs
    - Tenant IDs
    - Feature flags
    - Security context
    """
    
    MAX_ENTRY_LENGTH = 4096
    MAX_ENTRIES = 64
    
    @staticmethod
    def set_baggage(key: str, value: str) -> None:
        """Set baggage entry in current context"""
        if not NS_TRACING_ENABLED:
            return
        if len(key) > 128 or len(value) > BaggageManager.MAX_ENTRY_LENGTH:
            return
        current = _current_baggage.get()
        if len(current) >= BaggageManager.MAX_ENTRIES:
            return
        current = dict(current)
        current[key] = value
        _current_baggage.set(current)
    
    @staticmethod
    def get_baggage(key: str, default: Optional[str] = None) -> Optional[str]:
        """Get baggage entry from current context"""
        if not NS_TRACING_ENABLED:
            return default
        return _current_baggage.get().get(key, default)
    
    @staticmethod
    def get_all_baggage() -> Dict[str, str]:
        """Get all baggage entries"""
        if not NS_TRACING_ENABLED:
            return {}
        return dict(_current_baggage.get())
    
    @staticmethod
    def clear_baggage() -> None:
        """Clear all baggage"""
        if not NS_TRACING_ENABLED:
            return
        _current_baggage.set({})
    
    @staticmethod
    def remove_baggage(key: str) -> None:
        """Remove specific baggage entry"""
        if not NS_TRACING_ENABLED:
            return
        current = dict(_current_baggage.get())
        current.pop(key, None)
        _current_baggage.set(current)
    
    @staticmethod
    def to_baggage_header() -> str:
        """Serialize baggage to W3C baggage header format"""
        if not NS_TRACING_ENABLED:
            return ""
        items = []
        for k, v in _current_baggage.get().items():
            items.append(f"{k}={v}")
        return ",".join(items)
    
    @staticmethod
    def from_baggage_header(header: str) -> None:
        """Parse W3C baggage header into current context"""
        if not NS_TRACING_ENABLED:
            return
        if not header:
            return
        baggage: Dict[str, str] = {}
        for item in header.split(","):
            if "=" in item:
                k, v = item.split("=", 1)
                if len(baggage) < BaggageManager.MAX_ENTRIES:
                    baggage[k.strip()] = v.strip()
        _current_baggage.set(baggage)

# -----------------------------------------------------------------------------
# Trace Sampler - Intelligent Sampling
# -----------------------------------------------------------------------------

class TraceSampler:
    """Intelligent trace sampling strategies"""
    
    def __init__(
        self,
        strategy: SamplingStrategy = SamplingStrategy.PROBABILISTIC,
        sample_rate: float = 0.01,
        max_traces_per_second: int = 100
    ):
        self.strategy = strategy
        self.sample_rate = max(0.0, min(1.0, sample_rate))
        self.max_traces_per_second = max_traces_per_second
        self._trace_count = 0
        self._window_start = time.time()
        self._lock = threading.Lock()
    
    def should_sample(self, trace_context: TraceContext, error_occurred: bool = False) -> bool:
        """Determine if trace should be sampled based on strategy"""
        if not NS_TRACING_ENABLED:
            return False
        
        if self.strategy == SamplingStrategy.ALWAYS_OFF:
            return False
        elif self.strategy == SamplingStrategy.ALWAYS_ON:
            return True
        elif self.strategy == SamplingStrategy.ERROR_ONLY:
            return error_occurred
        elif self.strategy == SamplingStrategy.PROBABILISTIC:
            return random.random() < self.sample_rate
        elif self.strategy == SamplingStrategy.RATE_LIMITED:
            with self._lock:
                now = time.time()
                if now - self._window_start > 1.0:
                    self._trace_count = 0
                    self._window_start = now
                if self._trace_count < self.max_traces_per_second:
                    self._trace_count += 1
                    return True
                return False
        elif self.strategy == SamplingStrategy.ADAPTIVE:
            # Adaptive: sample errors always, success probabilistically
            if error_occurred:
                return True
            return random.random() < (self.sample_rate * 0.5)
        
        return random.random() < self.sample_rate
    
    def deterministic_sample(self, trace_id: str) -> bool:
        """Deterministic sampling based on trace ID hash"""
        if not NS_TRACING_ENABLED:
            return False
        hash_val = int(hashlib.sha256(trace_id.encode()).hexdigest()[:8], 16)
        return (hash_val / 0xFFFFFFFF) < self.sample_rate

# -----------------------------------------------------------------------------
# Global Trace Manager
# -----------------------------------------------------------------------------

class TraceManager:
    """Global trace context manager"""
    
    _default_sampler: TraceSampler = TraceSampler(
        strategy=SamplingStrategy.PROBABILISTIC,
        sample_rate=NS_TRACING_SAMPLE_RATE
    )
    
    @staticmethod
    def is_enabled() -> bool:
        """Check if tracing is enabled"""
        return NS_TRACING_ENABLED
    
    @staticmethod
    def start_trace(
        name: str,
        parent: Optional[TraceContext] = None,
        attributes: Optional[Dict[str, Any]] = None,
        force_sample: bool = False
    ) -> TraceContext:
        """Start a new trace"""
        if not NS_TRACING_ENABLED:
            return TraceContext(flags=0)
        
        if parent:
            ctx = parent.child_span(name)
        else:
            ctx = TraceContext()
            ctx.attributes["trace_name"] = name
        
        if attributes:
            ctx.attributes.update(attributes)
        
        # Apply sampling
        if force_sample or TraceManager._default_sampler.should_sample(ctx):
            ctx = ctx.with_sampled(True)
        
        _current_trace_context.set(ctx)
        return ctx
    
    @staticmethod
    def current_trace() -> Optional[TraceContext]:
        """Get current trace context"""
        if not NS_TRACING_ENABLED:
            return None
        return _current_trace_context.get()
    
    @staticmethod
    def end_trace(ctx: Optional[TraceContext] = None) -> Optional[Dict[str, Any]]:
        """End trace and return summary if sampled"""
        if not NS_TRACING_ENABLED:
            return None
        
        trace_ctx = ctx or _current_trace_context.get()
        if not trace_ctx:
            return None
        
        if trace_ctx.is_sampled():
            summary = {
                "trace_id": trace_ctx.trace_id,
                "span_id": trace_ctx.parent_id,
                "duration_ms": trace_ctx.duration_ms(),
                "attributes": trace_ctx.attributes,
                "baggage": BaggageManager.get_all_baggage(),
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            return summary
        
        _current_trace_context.set(None)
        return None
    
    @staticmethod
    def extract_context(headers: Dict[str, str]) -> Optional[TraceContext]:
        """Extract trace context from HTTP headers"""
        if not NS_TRACING_ENABLED:
            return None
        
        traceparent = headers.get("traceparent") or headers.get("Traceparent")
        if traceparent:
            return TraceContext.from_traceparent(traceparent)
        return None
    
    @staticmethod
    def inject_context(ctx: Optional[TraceContext] = None) -> Dict[str, str]:
        """Inject trace context into headers dict"""
        if not NS_TRACING_ENABLED:
            return {}
        
        trace_ctx = ctx or _current_trace_context.get()
        if not trace_ctx:
            return {}
        
        headers = trace_ctx.to_headers()
        baggage = BaggageManager.to_baggage_header()
        if baggage:
            headers["baggage"] = baggage
        return headers
    
    @staticmethod
    def get_correlation_id() -> str:
        """Get or create correlation ID for current context"""
        if not NS_TRACING_ENABLED:
            return TraceContext.generate_correlation_id()
        
        existing = BaggageManager.get_baggage("correlation_id")
        if existing:
            return existing
        
        corr_id = TraceContext.generate_correlation_id()
        BaggageManager.set_baggage("correlation_id", corr_id)
        return corr_id

# -----------------------------------------------------------------------------
# Decorator for Tracing
# -----------------------------------------------------------------------------

T = TypeVar('T')

def traced(
    name: Optional[str] = None,
    attributes: Optional[Dict[str, Any]] = None,
    capture_exceptions: bool = True,
    set_correlation_id: bool = True
):
    """
    OPT-IN tracing decorator.
    
    Usage:
        @traced(name="my_function")
        def my_function():
            pass
    
    Has ZERO overhead when NEURALSHIELD_TRACING_ENABLED=0
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        if not NS_TRACING_ENABLED:
            return func
        
        def wrapper(*args: Any, **kwargs: Any) -> T:
            span_name = name or func.__name__
            ctx = TraceManager.start_trace(span_name, attributes=attributes)
            
            if set_correlation_id:
                TraceManager.get_correlation_id()
            
            try:
                result = func(*args, **kwargs)
                TraceManager.end_trace(ctx)
                return result
            except Exception as e:
                if capture_exceptions and ctx:
                    ctx.attributes["error"] = str(e)
                    ctx.attributes["error_type"] = type(e).__name__
                    # Force sample errors
                    ctx = ctx.with_sampled(True)
                TraceManager.end_trace(ctx)
                raise
        
        return wrapper
    return decorator

# -----------------------------------------------------------------------------
# Trace Exporter Interface
# -----------------------------------------------------------------------------

class TraceExporter:
    """Base class for trace exporters"""
    
    def export(self, trace_summary: Dict[str, Any]) -> None:
        """Export trace summary - override in implementations"""
        pass

class LogTraceExporter(TraceExporter):
    """Export traces to structured log format"""
    
    def export(self, trace_summary: Dict[str, Any]) -> None:
        """Export as structured JSON log line"""
        log_entry = {
            "type": "trace",
            "service": "neuralshield-ai",
            **trace_summary
        }
        # In production, this would go to logging infrastructure
        print(json.dumps(log_entry), flush=True)

# -----------------------------------------------------------------------------
# Module Exports
# -----------------------------------------------------------------------------

__all__ = [
    "TraceContext",
    "TraceManager",
    "BaggageManager",
    "TraceSampler",
    "TraceFlag",
    "SamplingStrategy",
    "TraceLevel",
    "TraceExporter",
    "LogTraceExporter",
    "traced",
    "NS_TRACING_ENABLED",
]
