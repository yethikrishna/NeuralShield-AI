"""
NeuralShield AI - Distributed Tracing with Security Event Correlation v27
DIMENSION D: Observability & Instrumentation

ADD-ONLY implementation - wraps existing code, no core modifications.
All instrumentation is OPT-IN, disabled by default.
Preserves 100% backward compatibility.

Features added in v27:
- Security event correlation across trace boundaries
- Threat detection span tagging and baggage propagation
- MITRE ATT&CK technique mapping in trace metadata
- Percentile-based latency tracking for security operations
- Alert threshold integration with tracing data
"""

import time
import uuid
import threading
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
import json


class SecurityEventType(Enum):
    """Types of security events for tracing correlation."""
    THREAT_DETECTED = "threat_detected"
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK_ATTEMPT = "jailbreak_attempt"
    ADVERSARIAL_PROMPT = "adversarial_prompt"
    DATA_LEAKAGE = "data_leakage"
    MEMORY_POISONING = "memory_poisoning"
    RAG_POISONING = "rag_poisoning"
    TOOL_CALL_VALIDATION = "tool_call_validation"
    INPUT_SANITIZATION = "input_sanitization"
    OUTPUT_FILTERING = "output_filtering"


class MitreTechnique(Enum):
    """MITRE ATT&CK techniques for trace metadata."""
    PROMPT_INJECTION = "T1562.001"
    JAILBREAK = "T1562.002"
    ADVERSARIAL_EXAMPLES = "T1562.003"
    DATA_EXFILTRATION = "T1020"
    PRIVILEGE_ESCALATION = "T1068"
    DEFENSE_EVASION = "T1562"


@dataclass
class SpanContext:
    """Context for distributed tracing span."""
    trace_id: str
    span_id: str
    parent_span_id: Optional[str] = None
    baggage: Dict[str, Any] = field(default_factory=dict)
    security_events: List[Dict[str, Any]] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None
    attributes: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PercentileMetrics:
    """Percentile-based latency tracking."""
    p50: float = 0.0
    p75: float = 0.0
    p90: float = 0.0
    p95: float = 0.0
    p99: float = 0.0
    p999: float = 0.0
    count: int = 0
    min: float = 0.0
    max: float = 0.0
    avg: float = 0.0


class ThreadLocalStorage:
    """Thread-local storage for trace context."""
    _local = threading.local()

    @classmethod
    def get_current_span(cls) -> Optional[SpanContext]:
        return getattr(cls._local, 'current_span', None)

    @classmethod
    def set_current_span(cls, span: Optional[SpanContext]):
        cls._local.current_span = span


class SecurityCorrelationTracer:
    """
    Distributed tracer with security event correlation.
    
    OPT-IN instrumentation - must be explicitly enabled.
    Wraps existing security modules without modification.
    """

    def __init__(self, service_name: str = "neuralshield-ai", enabled: bool = False):
        self.service_name = service_name
        self.enabled = enabled
        self._spans: Dict[str, SpanContext] = {}
        self._traces: Dict[str, List[SpanContext]] = defaultdict(list)
        self._latency_samples: Dict[str, List[float]] = defaultdict(list)
        self._security_correlations: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self._alert_thresholds: Dict[str, float] = {
            "detection_latency_ms": 1000.0,
            "security_events_per_trace": 5,
        }
        self._lock = threading.Lock()

    def generate_trace_id(self) -> str:
        """Generate a unique trace ID."""
        return str(uuid.uuid4())

    def generate_span_id(self) -> str:
        """Generate a unique span ID."""
        return str(uuid.uuid4())[:16]

    def start_span(
        self,
        name: str,
        trace_id: Optional[str] = None,
        parent_span_id: Optional[str] = None,
        baggage: Optional[Dict[str, Any]] = None,
        mitre_techniques: Optional[List[str]] = None,
        attributes: Optional[Dict[str, Any]] = None,
    ) -> Optional[SpanContext]:
        """
        Start a new tracing span.
        
        Returns None if tracing is disabled - safe for no-op calls.
        """
        if not self.enabled:
            return None

        span = SpanContext(
            trace_id=trace_id or self.generate_trace_id(),
            span_id=self.generate_span_id(),
            parent_span_id=parent_span_id,
            baggage=baggage or {},
            mitre_techniques=mitre_techniques or [],
            attributes=attributes or {},
            start_time=time.time(),
        )

        with self._lock:
            self._spans[span.span_id] = span
            self._traces[span.trace_id].append(span)

        ThreadLocalStorage.set_current_span(span)
        return span

    def end_span(self, span: Optional[SpanContext], error: Optional[str] = None) -> None:
        """End a tracing span."""
        if not self.enabled or span is None:
            return

        span.end_time = time.time()
        duration_ms = (span.end_time - span.start_time) * 1000

        with self._lock:
            operation_name = span.attributes.get("operation", "unknown")
            self._latency_samples[operation_name].append(duration_ms)

            if error:
                span.attributes["error"] = error
                span.attributes["error_type"] = "security_violation"

        ThreadLocalStorage.set_current_span(None)

    def add_security_event(
        self,
        span: Optional[SpanContext],
        event_type: SecurityEventType,
        severity: str = "medium",
        details: Optional[Dict[str, Any]] = None,
        mitre_technique: Optional[MitreTechnique] = None,
    ) -> None:
        """
        Add a security event to the trace for correlation.
        
        Thread-safe, no-op if tracing disabled.
        """
        if not self.enabled or span is None:
            return

        event = {
            "event_type": event_type.value,
            "severity": severity,
            "timestamp": time.time(),
            "details": details or {},
            "mitre_technique": mitre_technique.value if mitre_technique else None,
        }

        with self._lock:
            span.security_events.append(event)
            self._security_correlations[span.trace_id].append(event)

    def propagate_baggage(
        self,
        span: Optional[SpanContext],
        key: str,
        value: Any,
    ) -> None:
        """Propagate baggage across span boundaries."""
        if not self.enabled or span is None:
            return

        with self._lock:
            span.baggage[key] = value

    def get_baggage(self, span: Optional[SpanContext], key: str) -> Optional[Any]:
        """Get baggage value from span context."""
        if not self.enabled or span is None:
            return None
        return span.baggage.get(key)

    def calculate_percentiles(self, operation_name: str) -> PercentileMetrics:
        """Calculate percentile metrics for an operation."""
        with self._lock:
            samples = sorted(self._latency_samples.get(operation_name, []))

        if not samples:
            return PercentileMetrics()

        def _p(percentile: float) -> float:
            idx = int(len(samples) * percentile)
            return samples[min(idx, len(samples) - 1)]

        return PercentileMetrics(
            p50=_p(0.50),
            p75=_p(0.75),
            p90=_p(0.90),
            p95=_p(0.95),
            p99=_p(0.99),
            p999=_p(0.999),
            count=len(samples),
            min=samples[0],
            max=samples[-1],
            avg=sum(samples) / len(samples),
        )

    def get_correlated_security_events(self, trace_id: str) -> List[Dict[str, Any]]:
        """Get all security events correlated within a trace."""
        with self._lock:
            return list(self._security_correlations.get(trace_id, []))

    def check_alert_thresholds(self, operation_name: str) -> List[str]:
        """Check if any alert thresholds have been breached."""
        alerts = []
        metrics = self.calculate_percentiles(operation_name)

        if metrics.p99 > self._alert_thresholds["detection_latency_ms"]:
            alerts.append(
                f"HIGH_LATENCY: p99 latency {metrics.p99:.2f}ms exceeds "
                f"threshold {self._alert_thresholds['detection_latency_ms']}ms"
            )

        return alerts

    def get_trace_summary(self, trace_id: str) -> Dict[str, Any]:
        """Get summary of all spans and security events in a trace."""
        with self._lock:
            spans = self._traces.get(trace_id, [])
            security_events = self._security_correlations.get(trace_id, [])

        total_duration = 0.0
        if spans:
            start = min(s.start_time for s in spans)
            end = max(s.end_time or s.start_time for s in spans)
            total_duration = (end - start) * 1000

        return {
            "trace_id": trace_id,
            "span_count": len(spans),
            "security_event_count": len(security_events),
            "total_duration_ms": total_duration,
            "mitre_techniques": list({
                evt.get("mitre_technique")
                for evt in security_events
                if evt.get("mitre_technique")
            }),
            "severity_counts": {
                sev: sum(1 for e in security_events if e.get("severity") == sev)
                for sev in ["low", "medium", "high", "critical"]
            },
        }

    def trace_security_operation(
        self,
        operation_name: str,
        mitre_techniques: Optional[List[str]] = None,
    ) -> Callable:
        """
        Decorator for tracing security operations.
        
        ADD-ONLY wrapper - does not modify wrapped function.
        100% backward compatible - no-op if disabled.
        """
        def decorator(func: Callable) -> Callable:
            def wrapper(*args, **kwargs):
                if not self.enabled:
                    return func(*args, **kwargs)

                parent = ThreadLocalStorage.get_current_span()
                span = self.start_span(
                    name=operation_name,
                    trace_id=parent.trace_id if parent else None,
                    parent_span_id=parent.span_id if parent else None,
                    attributes={
                        "operation": operation_name,
                        "function": func.__name__,
                    },
                    mitre_techniques=mitre_techniques,
                    baggage=parent.baggage if parent else {},
                )

                try:
                    result = func(*args, **kwargs)

                    # Add result context to span
                    if span:
                        span.attributes["result_type"] = type(result).__name__
                        if hasattr(result, 'get'):
                            span.attributes["threat_detected"] = result.get('threat_detected', False)
                            span.attributes["confidence"] = result.get('confidence', 0.0)

                    self.end_span(span)
                    return result

                except Exception as e:
                    self.end_span(span, error=str(e))
                    raise

            return wrapper
        return decorator

    def export_spans_json(self) -> str:
        """Export all span data as JSON for observability platforms."""
        with self._lock:
            export_data = {
                "service": self.service_name,
                "export_time": time.time(),
                "trace_count": len(self._traces),
                "span_count": len(self._spans),
                "traces": {
                    trace_id: [
                        {
                            "span_id": s.span_id,
                            "parent_span_id": s.parent_span_id,
                            "start_time": s.start_time,
                            "end_time": s.end_time,
                            "duration_ms": (s.end_time - s.start_time) * 1000 if s.end_time else None,
                            "attributes": s.attributes,
                            "security_events": s.security_events,
                            "mitre_techniques": s.mitre_techniques,
                        }
                        for s in spans
                    ]
                    for trace_id, spans in self._traces.items()
                },
                "percentile_metrics": {
                    op: self.calculate_percentiles(op).__dict__
                    for op in self._latency_samples
                },
            }

        return json.dumps(export_data, indent=2)


# Global tracer instance - OPT-IN, disabled by default
_global_tracer = SecurityCorrelationTracer(enabled=False)


def get_global_tracer() -> SecurityCorrelationTracer:
    """Get the global tracer instance."""
    return _global_tracer


def enable_tracing(service_name: str = "neuralshield-ai") -> None:
    """Explicitly enable tracing - must be called to activate."""
    global _global_tracer
    _global_tracer = SecurityCorrelationTracer(service_name=service_name, enabled=True)


def disable_tracing() -> None:
    """Disable tracing completely."""
    global _global_tracer
    _global_tracer = SecurityCorrelationTracer(enabled=False)
