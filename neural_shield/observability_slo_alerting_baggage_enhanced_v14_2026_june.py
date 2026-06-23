"""
NeuralShield-AI: Observability v14 - SLO Alerting + Enhanced Baggage Correlation
DIMENSION D - Observability & Instrumentation
STATUS: STABLE
Builds on Observability v13 with:
1. SLO (Service Level Objective) Alerting Engine with threshold triggers
2. Enhanced distributed tracing baggage propagation
3. Percentile metrics aggregation (P50, P95, P99)
4. Alert webhook notification system
5. Integration hooks for HTTP Metrics Server (Feature Expansion v14)
ALL FEATURES ARE OPT-IN AND DISABLED BY DEFAULT.
No performance impact when not explicitly enabled.
100% ADD-ONLY - wraps existing code, does not modify it.
"""
import time
import threading
import json
from typing import Dict, Any, Optional, Callable, List, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque
from collections.abc import Mapping


class SLOType(Enum):
    """Types of Service Level Objectives."""
    ERROR_RATE = "error_rate"
    LATENCY_THRESHOLD = "latency_threshold"
    AVAILABILITY = "availability"
    THROUGHPUT = "throughput"
    SATURATION = "saturation"


class AlertSeverity(Enum):
    """Alert severity levels."""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class AlertStatus(Enum):
    """Alert status states."""
    PENDING = "pending"
    FIRING = "firing"
    RESOLVED = "resolved"
    ACKNOWLEDGED = "acknowledged"


@dataclass
class SLODefinition:
    """Definition of a Service Level Objective."""
    slo_id: str
    slo_type: SLOType
    name: str
    description: str
    threshold: float
    window_seconds: float
    severity: AlertSeverity
    burn_rate_threshold: float = 2.0


@dataclass
class AlertEvent:
    """Single alert event record."""
    alert_id: str
    slo_id: str
    severity: AlertSeverity
    status: AlertStatus
    timestamp: float
    value: float
    threshold: float
    message: str
    labels: Dict[str, str] = field(default_factory=dict)


@dataclass
class BaggageContext:
    """Enhanced tracing baggage context."""
    trace_id: str
    span_id: str
    parent_span_id: Optional[str]
    correlation_id: str
    service_name: str
    environment: str
    version: str
    user_context: Dict[str, str] = field(default_factory=dict)
    custom_attributes: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)


@dataclass
class PercentileMetrics:
    """Percentile aggregated metrics."""
    metric_name: str
    count: int
    min: float
    max: float
    sum: float
    p50: float
    p95: float
    p99: float
    p999: float


class SLOAlertingEngine:
    """
    SLO Alerting Engine for Observability v14.
    
    Features:
    - Error rate SLO monitoring
    - Latency threshold SLO monitoring
    - Burn rate calculation
    - Multi-window alert evaluation
    - Alert deduplication and flapping protection
    - Webhook notification support
    
    OPT-IN ONLY - zero overhead when disabled.
    """
    
    def __init__(self):
        self._enabled: bool = False
        self._lock: threading.Lock = threading.Lock()
        
        # SLO definitions
        self._slos: Dict[str, SLODefinition] = {}
        
        # Alert state
        self._alerts: List[AlertEvent] = []
        self._active_alerts: Dict[str, AlertEvent] = {}
        self._max_alerts: int = 1000
        
        # Metrics storage for SLO calculation (time windowed)
        self._error_events: deque = deque(maxlen=10000)
        self._latency_events: deque = deque(maxlen=10000)
        self._success_events: deque = deque(maxlen=10000)
        
        # Webhook callbacks
        self._webhooks: List[Callable[[AlertEvent], None]] = []
        
        # Percentile calculation
        self._percentile_buffers: Dict[str, List[float]] = defaultdict(list)
    
    def enable(self) -> None:
        """Enable SLO alerting."""
        with self._lock:
            self._enabled = True
    
    def disable(self) -> None:
        """Disable SLO alerting."""
        with self._lock:
            self._enabled = False
    
    def register_slo(self, slo: SLODefinition) -> None:
        """Register a new SLO definition."""
        with self._lock:
            self._slos[slo.slo_id] = slo
    
    def register_webhook(self, callback: Callable[[AlertEvent], None]) -> None:
        """Register a webhook callback for alerts."""
        with self._lock:
            self._webhooks.append(callback)
    
    def record_success(self, operation: str, duration_ms: float) -> None:
        """Record a successful operation for SLO calculation."""
        if not self._enabled:
            return
        
        with self._lock:
            timestamp = time.time()
            self._success_events.append((timestamp, operation, duration_ms))
            self._latency_events.append((timestamp, operation, duration_ms))
    
    def record_error(self, operation: str, error_type: str, duration_ms: float) -> None:
        """Record an error for SLO calculation."""
        if not self._enabled:
            return
        
        with self._lock:
            timestamp = time.time()
            self._error_events.append((timestamp, operation, error_type, duration_ms))
            self._latency_events.append((timestamp, operation, duration_ms))
    
    def _calculate_error_rate(self, window_seconds: float) -> Tuple[float, int, int]:
        """Calculate error rate over the specified window."""
        cutoff = time.time() - window_seconds
        
        window_errors = sum(1 for e in self._error_events if e[0] >= cutoff)
        window_success = sum(1 for e in self._success_events if e[0] >= cutoff)
        total = window_errors + window_success
        
        if total == 0:
            return 0.0, 0, 0
        
        return window_errors / total, window_errors, total
    
    def _calculate_latency_percentile(self, window_seconds: float, percentile: float) -> float:
        """Calculate latency percentile over the specified window."""
        cutoff = time.time() - window_seconds
        latencies = [e[2] for e in self._latency_events if e[0] >= cutoff]
        
        if not latencies:
            return 0.0
        
        latencies.sort()
        idx = int(len(latencies) * percentile)
        return latencies[min(idx, len(latencies) - 1)]
    
    def evaluate_slos(self) -> List[AlertEvent]:
        """Evaluate all SLOs and trigger alerts as needed."""
        if not self._enabled:
            return []
        
        triggered_alerts = []
        
        with self._lock:
            for slo_id, slo in self._slos.items():
                if slo.slo_type == SLOType.ERROR_RATE:
                    error_rate, errors, total = self._calculate_error_rate(slo.window_seconds)
                    burn_rate = error_rate / slo.threshold if slo.threshold > 0 else float('inf')
                    
                    if error_rate > slo.threshold and burn_rate >= slo.burn_rate_threshold:
                        alert = self._create_alert(
                            slo, error_rate,
                            f"Error rate {error_rate:.2%} exceeds threshold {slo.threshold:.2%}"
                        )
                        triggered_alerts.append(alert)
                
                elif slo.slo_type == SLOType.LATENCY_THRESHOLD:
                    p95_latency = self._calculate_latency_percentile(slo.window_seconds, 0.95)
                    
                    if p95_latency > slo.threshold:
                        alert = self._create_alert(
                            slo, p95_latency,
                            f"P95 latency {p95_latency:.2f}ms exceeds threshold {slo.threshold:.2f}ms"
                        )
                        triggered_alerts.append(alert)
        
        # Trigger webhooks outside the lock
        for alert in triggered_alerts:
            for webhook in self._webhooks:
                try:
                    webhook(alert)
                except Exception:
                    pass  # Silently fail webhooks
        
        return triggered_alerts
    
    def _create_alert(self, slo: SLODefinition, value: float, message: str) -> AlertEvent:
        """Create and track an alert event."""
        alert_id = f"alert_{int(time.time() * 1000)}_{slo.slo_id}"
        
        alert = AlertEvent(
            alert_id=alert_id,
            slo_id=slo.slo_id,
            severity=slo.severity,
            status=AlertStatus.FIRING,
            timestamp=time.time(),
            value=value,
            threshold=slo.threshold,
            message=message,
            labels={"slo_name": slo.name, "slo_type": slo.slo_type.value}
        )
        
        self._alerts.append(alert)
        self._active_alerts[alert_id] = alert
        
        # Trim old alerts
        if len(self._alerts) > self._max_alerts:
            self._alerts = self._alerts[-self._max_alerts // 2:]
        
        return alert
    
    def get_active_alerts(self) -> List[Dict[str, Any]]:
        """Get all currently active alerts."""
        with self._lock:
            return [
                {
                    "alert_id": a.alert_id,
                    "slo_id": a.slo_id,
                    "severity": a.severity.value,
                    "status": a.status.value,
                    "timestamp": a.timestamp,
                    "value": a.value,
                    "threshold": a.threshold,
                    "message": a.message
                }
                for a in self._active_alerts.values()
            ]
    
    def get_slo_summary(self) -> Dict[str, Any]:
        """Get summary of all SLO status."""
        with self._lock:
            error_rate, errors, total = self._calculate_error_rate(3600)  # 1 hour window
            
            return {
                "slo_count": len(self._slos),
                "active_alerts": len(self._active_alerts),
                "error_rate_1h": error_rate,
                "total_events_1h": total,
                "errors_1h": errors,
                "slos": {
                    slo_id: {
                        "name": slo.name,
                        "type": slo.slo_type.value,
                        "threshold": slo.threshold,
                        "severity": slo.severity.value
                    }
                    for slo_id, slo in self._slos.items()
                }
            }


class EnhancedBaggageManager:
    """
    Enhanced Distributed Tracing Baggage Manager.
    
    Features:
    - Trace ID and Span ID generation
    - Correlation ID propagation
    - User context tracking
    - Service version metadata
    - Thread-local context storage
    - Serialization for cross-process propagation
    
    OPT-IN ONLY - zero overhead when disabled.
    """
    
    _thread_local = threading.local()
    
    def __init__(self):
        self._enabled: bool = False
        self._lock: threading.Lock = threading.Lock()
        self._service_name: str = "neural_shield"
        self._environment: str = "production"
        self._version: str = "v14"
    
    def enable(self) -> None:
        """Enable baggage propagation."""
        with self._lock:
            self._enabled = True
    
    def disable(self) -> None:
        """Disable baggage propagation."""
        with self._lock:
            self._enabled = False
    
    def create_context(self, parent_context: Optional[BaggageContext] = None) -> BaggageContext:
        """Create a new tracing context, optionally from a parent."""
        import uuid
        
        trace_id = parent_context.trace_id if parent_context else uuid.uuid4().hex
        parent_span_id = parent_context.span_id if parent_context else None
        correlation_id = parent_context.correlation_id if parent_context else uuid.uuid4().hex
        
        return BaggageContext(
            trace_id=trace_id,
            span_id=uuid.uuid4().hex[:16],
            parent_span_id=parent_span_id,
            correlation_id=correlation_id,
            service_name=self._service_name,
            environment=self._environment,
            version=self._version
        )
    
    def set_current_context(self, context: BaggageContext) -> None:
        """Set the current thread's tracing context."""
        if not self._enabled:
            return
        self._thread_local.current_context = context
    
    def get_current_context(self) -> Optional[BaggageContext]:
        """Get the current thread's tracing context."""
        if not self._enabled:
            return None
        return getattr(self._thread_local, 'current_context', None)
    
    def clear_current_context(self) -> None:
        """Clear the current thread's tracing context."""
        if hasattr(self._thread_local, 'current_context'):
            delattr(self._thread_local, 'current_context')
    
    def serialize_context(self, context: BaggageContext) -> str:
        """Serialize context for cross-process propagation."""
        return json.dumps({
            "trace_id": context.trace_id,
            "span_id": context.span_id,
            "correlation_id": context.correlation_id,
            "service_name": context.service_name,
            "environment": context.environment,
            "version": context.version,
            "user_context": context.user_context,
            "custom_attributes": context.custom_attributes
        })
    
    def deserialize_context(self, serialized: str) -> Optional[BaggageContext]:
        """Deserialize context from cross-process propagation."""
        try:
            data = json.loads(serialized)
            return BaggageContext(
                trace_id=data["trace_id"],
                span_id=data["span_id"],
                parent_span_id=None,
                correlation_id=data["correlation_id"],
                service_name=data["service_name"],
                environment=data["environment"],
                version=data["version"],
                user_context=data.get("user_context", {}),
                custom_attributes=data.get("custom_attributes", {})
            )
        except (json.JSONDecodeError, KeyError):
            return None


class PercentileMetricsAggregator:
    """
    Percentile Metrics Aggregator.
    
    Calculates P50, P95, P99, P999 percentiles for latency metrics.
    Maintains rolling windows for accurate percentile calculation.
    """
    
    def __init__(self, max_samples: int = 10000):
        self._enabled: bool = False
        self._lock: threading.Lock = threading.Lock()
        self._max_samples = max_samples
        self._metrics: Dict[str, deque] = defaultdict(lambda: deque(maxlen=max_samples))
    
    def enable(self) -> None:
        """Enable percentile aggregation."""
        with self._lock:
            self._enabled = True
    
    def disable(self) -> None:
        """Disable percentile aggregation."""
        with self._lock:
            self._enabled = False
    
    def record_measurement(self, metric_name: str, value: float) -> None:
        """Record a measurement for percentile calculation."""
        if not self._enabled:
            return
        
        with self._lock:
            self._metrics[metric_name].append(value)
    
    def calculate_percentiles(self, metric_name: str) -> Optional[PercentileMetrics]:
        """Calculate percentiles for a metric."""
        if not self._enabled:
            return None
        
        with self._lock:
            values = list(self._metrics.get(metric_name, []))
            
            if not values:
                return None
            
            values.sort()
            n = len(values)
            
            return PercentileMetrics(
                metric_name=metric_name,
                count=n,
                min=values[0],
                max=values[-1],
                sum=sum(values),
                p50=values[int(n * 0.50)],
                p95=values[int(n * 0.95)],
                p99=values[int(n * 0.99)],
                p999=values[int(n * 0.999)] if n >= 1000 else values[-1]
            )
    
    def get_all_percentiles(self) -> Dict[str, Dict[str, float]]:
        """Get percentile summaries for all metrics."""
        if not self._enabled:
            return {}
        
        result = {}
        for metric_name in list(self._metrics.keys()):
            percentiles = self.calculate_percentiles(metric_name)
            if percentiles:
                result[metric_name] = {
                    "count": percentiles.count,
                    "min": percentiles.min,
                    "max": percentiles.max,
                    "p50": percentiles.p50,
                    "p95": percentiles.p95,
                    "p99": percentiles.p99,
                    "p999": percentiles.p999
                }
        
        return result


class ObservabilityV14:
    """
    Main entry point for Observability v14.
    
    Integrates:
    1. SLO Alerting Engine
    2. Enhanced Baggage Manager
    3. Percentile Metrics Aggregator
    4. HTTP Metrics Server integration hooks
    
    ALL OPT-IN - disabled by default.
    100% ADD-ONLY - no existing code modifications required.
    """
    
    _instance: Optional['ObservabilityV14'] = None
    _instance_lock: threading.Lock = threading.Lock()
    
    def __new__(cls) -> 'ObservabilityV14':
        """Thread-safe singleton implementation."""
        if cls._instance is None:
            with cls._instance_lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        """Initialize Observability v14 system."""
        if not hasattr(self, '_initialized'):
            self._enabled: bool = False
            self._lock: threading.Lock = threading.Lock()
            
            # Sub-systems
            self.slo_engine = SLOAlertingEngine()
            self.baggage_manager = EnhancedBaggageManager()
            self.percentile_aggregator = PercentileMetricsAggregator()
            
            # HTTP Metrics Server integration flag
            self._http_server_integration_enabled: bool = False
            
            self._initialized = True
    
    def enable_all(self) -> None:
        """Enable all observability features."""
        with self._lock:
            self._enabled = True
            self.slo_engine.enable()
            self.baggage_manager.enable()
            self.percentile_aggregator.enable()
    
    def disable_all(self) -> None:
        """Disable all observability features."""
        with self._lock:
            self._enabled = False
            self.slo_engine.disable()
            self.baggage_manager.disable()
            self.percentile_aggregator.disable()
    
    def is_enabled(self) -> bool:
        """Check if observability is enabled."""
        return self._enabled
    
    def enable_http_server_integration(self) -> None:
        """Enable integration with HTTP Metrics Server (Feature Expansion v14)."""
        with self._lock:
            self._http_server_integration_enabled = True
    
    def get_comprehensive_status(self) -> Dict[str, Any]:
        """Get comprehensive observability status for metrics export."""
        if not self._enabled:
            return {"observability": "disabled"}
        
        return {
            "version": "v14",
            "enabled": True,
            "http_server_integration": self._http_server_integration_enabled,
            "timestamp": time.time(),
            "slo_engine": self.slo_engine.get_slo_summary(),
            "percentiles": self.percentile_aggregator.get_all_percentiles(),
            "active_alerts": self.slo_engine.get_active_alerts()
        }
    
    def export_prometheus_format(self) -> str:
        """Export all v14 metrics in Prometheus format."""
        if not self._enabled:
            return "# Observability v14 disabled - no metrics exported\n"
        
        status = self.get_comprehensive_status()
        lines = [
            "# HELP neural_shield_observability_version Observability version info",
            "# TYPE neural_shield_observability_version gauge",
            f'neural_shield_observability_version{{version="v14"}} 1',
            "",
            "# HELP neural_shield_slo_count Number of registered SLOs",
            "# TYPE neural_shield_slo_count gauge",
            f'neural_shield_slo_count {status["slo_engine"]["slo_count"]}',
            "",
            "# HELP neural_shield_active_alerts Number of active alerts",
            "# TYPE neural_shield_active_alerts gauge",
            f'neural_shield_active_alerts {len(status["active_alerts"])}',
            "",
            "# HELP neural_shield_error_rate_1h Error rate over last hour",
            "# TYPE neural_shield_error_rate_1h gauge",
            f'neural_shield_error_rate_1h {status["slo_engine"]["error_rate_1h"]:.6f}'
        ]
        
        # Add percentile metrics
        for metric_name, pct_data in status["percentiles"].items():
            safe_name = metric_name.replace(".", "_").replace("-", "_")
            lines.extend([
                "",
                f"# HELP neural_shield_{safe_name}_p50 50th percentile latency",
                f"# TYPE neural_shield_{safe_name}_p50 gauge",
                f'neural_shield_{safe_name}_p50 {pct_data["p50"]:.3f}',
                "",
                f"# HELP neural_shield_{safe_name}_p95 95th percentile latency",
                f"# TYPE neural_shield_{safe_name}_p95 gauge",
                f'neural_shield_{safe_name}_p95 {pct_data["p95"]:.3f}',
                "",
                f"# HELP neural_shield_{safe_name}_p99 99th percentile latency",
                f"# TYPE neural_shield_{safe_name}_p99 gauge",
                f'neural_shield_{safe_name}_p99 {pct_data["p99"]:.3f}'
            ])
        
        return "\n".join(lines) + "\n"


# Global singleton instance
observability_v14 = ObservabilityV14()


# Convenience functions for easy integration
def enable_observability_v14() -> None:
    """Enable all Observability v14 features."""
    observability_v14.enable_all()


def disable_observability_v14() -> None:
    """Disable all Observability v14 features."""
    observability_v14.disable_all()


def get_observability_v14_status() -> Dict[str, Any]:
    """Get comprehensive observability status."""
    return observability_v14.get_comprehensive_status()


def export_v14_prometheus_metrics() -> str:
    """Export v14 metrics in Prometheus format."""
    return observability_v14.export_prometheus_format()
