"""
NeuralShield Observability v14 - Security Hardening Telemetry Integration
Dimension D: Observability & Instrumentation
Provides OPT-IN telemetry, metrics, and tracing for v17 side-channel timing resistance modules.

DESIGN PHILOSOPHY:
- ADD-ONLY: Wraps existing functionality, NO core modification
- BACKWARD COMPATIBLE: All existing code continues to work unchanged
- OPT-IN: ALL features DISABLED by default, explicit enable required
- ZERO OVERHEAD: When disabled, operations are pure no-ops
- STRUCTURED: JSON-formatted logs, Prometheus-compatible metrics

STABILITY: EXPERIMENTAL (OPT-IN only)
"""
import os
import sys
import time
import json
import threading
from typing import Any, Callable, Optional, Dict, List, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
import hashlib

# Try to import the v17 security module gracefully
try:
    from .security_hardening_side_channel_timing_resistance_v17_2026_june import (
        TimingResistanceConfig,
        ConstantTimeComparer,
        SecureMemoryManager,
        TimingJitterInjector,
        ExecutionTimePadder,
        SideChannelResistantEvaluator,
        PromptInjectionTimingProtector,
    )
    SECURITY_MODULE_AVAILABLE = True
except ImportError:
    SECURITY_MODULE_AVAILABLE = False


class TelemetryLevel(Enum):
    """Telemetry verbosity levels"""
    DISABLED = 0
    BASIC = 1
    DETAILED = 2
    DEBUG = 3


@dataclass
class SecurityTelemetryConfig:
    """Configuration for security hardening telemetry"""
    # Master switch - ALL disabled by default
    enabled: bool = False
    
    # Telemetry level
    telemetry_level: TelemetryLevel = TelemetryLevel.DISABLED
    
    # Feature toggles - all disabled by default
    enable_metrics: bool = False
    enable_tracing: bool = False
    enable_structured_logging: bool = False
    enable_health_checks: bool = False
    
    # Metrics configuration
    metrics_namespace: str = "neuralshield_security"
    max_metrics_points: int = 10000
    enable_prometheus_export: bool = False
    
    # Logging configuration
    log_json_format: bool = True
    include_timestamps: bool = True
    include_stack_traces: bool = False
    
    # Sampling configuration
    sampling_rate: float = 1.0  # 1.0 = 100% sampling
    max_log_entries_per_second: int = 100
    
    def __post_init__(self):
        self._thread_local = threading.local()
        # If master enabled is False, force all features off
        if not self.enabled:
            self.enable_metrics = False
            self.enable_tracing = False
            self.enable_structured_logging = False
            self.enable_health_checks = False
            self.telemetry_level = TelemetryLevel.DISABLED


class SecurityOperationMetrics:
    """
    Metrics collector for security hardening operations.
    Tracks counts, durations, error rates for timing-resistant operations.
    ALL OPERATIONS ARE NO-OP WHEN DISABLED.
    """
    
    def __init__(self, config: Optional[SecurityTelemetryConfig] = None):
        self.config = config or SecurityTelemetryConfig()
        self._lock = threading.Lock()
        
        # Metrics storage - only used if enabled
        self._operation_counts: Dict[str, int] = defaultdict(int)
        self._operation_durations: Dict[str, List[float]] = defaultdict(list)
        self._error_counts: Dict[str, int] = defaultdict(int)
        self._comparison_counts: Dict[str, int] = defaultdict(int)
        
        # Health metrics
        self._start_time = time.time()
        self._last_reset = time.time()
    
    def record_operation(self, operation_name: str, duration_ns: int, success: bool = True) -> None:
        """Record a security operation - NO-OP if disabled"""
        if not self.config.enable_metrics:
            return
        
        with self._lock:
            self._operation_counts[operation_name] += 1
            self._operation_durations[operation_name].append(duration_ns / 1e9)
            
            # Trim old entries to prevent memory growth
            if len(self._operation_durations[operation_name]) > 1000:
                self._operation_durations[operation_name] = self._operation_durations[operation_name][-500:]
            
            if not success:
                self._error_counts[operation_name] += 1
    
    def record_comparison(self, comparison_type: str, result: bool) -> None:
        """Record a constant-time comparison - NO-OP if disabled"""
        if not self.config.enable_metrics:
            return
        
        with self._lock:
            key = f"{comparison_type}_{'match' if result else 'mismatch'}"
            self._comparison_counts[key] += 1
    
    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get metrics summary - returns empty dict if disabled"""
        if not self.config.enable_metrics:
            return {}
        
        with self._lock:
            summary = {
                "total_operations": sum(self._operation_counts.values()),
                "total_errors": sum(self._error_counts.values()),
                "operations_by_type": dict(self._operation_counts),
                "comparisons": dict(self._comparison_counts),
                "uptime_seconds": time.time() - self._start_time,
            }
            
            # Calculate average durations
            avg_durations = {}
            for op_name, durations in self._operation_durations.items():
                if durations:
                    avg_durations[op_name] = sum(durations) / len(durations)
            summary["average_durations_seconds"] = avg_durations
            
            return summary
    
    def export_prometheus_format(self) -> str:
        """Export metrics in Prometheus text format - empty string if disabled"""
        if not self.config.enable_metrics or not self.config.enable_prometheus_export:
            return ""
        
        metrics = self.get_metrics_summary()
        namespace = self.config.metrics_namespace
        lines = []
        
        lines.append(f"# HELP {namespace}_operations_total Total security operations")
        lines.append(f"# TYPE {namespace}_operations_total counter")
        lines.append(f"{namespace}_operations_total {metrics.get('total_operations', 0)}")
        
        lines.append(f"# HELP {namespace}_errors_total Total security operation errors")
        lines.append(f"# TYPE {namespace}_errors_total counter")
        lines.append(f"{namespace}_errors_total {metrics.get('total_errors', 0)}")
        
        for op_name, count in metrics.get("operations_by_type", {}).items():
            safe_name = op_name.replace(" ", "_").lower()
            lines.append(f"{namespace}_operation_{safe_name}_total {count}")
        
        return "\n".join(lines) + "\n"
    
    def reset_metrics(self) -> None:
        """Reset all metrics - NO-OP if disabled"""
        if not self.config.enable_metrics:
            return
        
        with self._lock:
            self._operation_counts.clear()
            self._operation_durations.clear()
            self._error_counts.clear()
            self._comparison_counts.clear()
            self._last_reset = time.time()


class StructuredSecurityLogger:
    """
    Structured JSON logger for security operations.
    ALL LOGGING IS DISABLED BY DEFAULT.
    """
    
    def __init__(self, config: Optional[SecurityTelemetryConfig] = None):
        self.config = config or SecurityTelemetryConfig()
        self._lock = threading.Lock()
        self._log_buffer: List[Dict[str, Any]] = []
    
    def _should_log(self) -> bool:
        """Check if logging should occur"""
        if not self.config.enable_structured_logging:
            return False
        if self.config.sampling_rate < 1.0:
            import random
            return random.random() < self.config.sampling_rate
        return True
    
    def log_operation(
        self,
        operation: str,
        level: str = "INFO",
        **kwargs
    ) -> None:
        """Log a security operation - NO-OP if disabled"""
        if not self._should_log():
            return
        
        log_entry = {
            "timestamp": time.time() if self.config.include_timestamps else None,
            "level": level,
            "operation": operation,
            "module": "security_hardening_v17",
            "observability_version": "v14",
        }
        log_entry.update(kwargs)
        
        with self._lock:
            self._log_buffer.append(log_entry)
            # Trim buffer to prevent memory growth
            if len(self._log_buffer) > 1000:
                self._log_buffer = self._log_buffer[-500:]
    
    def get_logs(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get buffered logs - empty list if disabled"""
        if not self.config.enable_structured_logging:
            return []
        
        with self._lock:
            return list(self._log_buffer[-limit:])
    
    def export_logs_json(self, limit: int = 100) -> str:
        """Export logs as JSON - empty array if disabled"""
        logs = self.get_logs(limit)
        if self.config.log_json_format:
            return json.dumps(logs, indent=2)
        return "\n".join([str(log) for log in logs])


class SecurityOperationTracer:
    """
    Distributed tracing for security hardening operations.
    Creates spans for timing-resistant operations with baggage context.
    ALL TRACING DISABLED BY DEFAULT.
    """
    
    def __init__(self, config: Optional[SecurityTelemetryConfig] = None):
        self.config = config or SecurityTelemetryConfig()
        self._thread_local = threading.local()
    
    def _get_current_span_id(self) -> Optional[str]:
        """Get current span ID - None if disabled"""
        if not self.config.enable_tracing:
            return None
        return getattr(self._thread_local, 'current_span_id', None)
    
    def start_span(self, operation_name: str, parent_span_id: Optional[str] = None) -> Optional[str]:
        """Start a new trace span - returns None if disabled"""
        if not self.config.enable_tracing:
            return None
        
        import secrets
        span_id = secrets.token_hex(8)
        trace_id = getattr(self._thread_local, 'trace_id', secrets.token_hex(16))
        
        self._thread_local.trace_id = trace_id
        self._thread_local.current_span_id = span_id
        self._thread_local.span_start = time.perf_counter_ns()
        self._thread_local.span_name = operation_name
        self._thread_local.parent_span_id = parent_span_id
        
        return span_id
    
    def end_span(self, span_id: Optional[str] = None, success: bool = True) -> Optional[Dict[str, Any]]:
        """End a trace span - returns None if disabled"""
        if not self.config.enable_tracing:
            return None
        
        end_time = time.perf_counter_ns()
        start_time = getattr(self._thread_local, 'span_start', end_time)
        duration = end_time - start_time
        
        span_data = {
            "trace_id": getattr(self._thread_local, 'trace_id', None),
            "span_id": span_id or getattr(self._thread_local, 'current_span_id', None),
            "parent_span_id": getattr(self._thread_local, 'parent_span_id', None),
            "operation": getattr(self._thread_local, 'span_name', 'unknown'),
            "duration_ns": duration,
            "success": success,
            "end_time": time.time(),
        }
        
        # Clear thread local
        for attr in ['trace_id', 'current_span_id', 'span_start', 'span_name', 'parent_span_id']:
            if hasattr(self._thread_local, attr):
                delattr(self._thread_local, attr)
        
        return span_data
    
    def get_baggage_context(self) -> Dict[str, str]:
        """Get tracing baggage context - empty dict if disabled"""
        if not self.config.enable_tracing:
            return {}
        return {
            "trace_id": getattr(self._thread_local, 'trace_id', ''),
            "span_id": getattr(self._thread_local, 'current_span_id', ''),
        }


class InstrumentedTimingResistance:
    """
    OPT-IN instrumented wrapper for v17 SideChannelResistantEvaluator.
    Adds telemetry, metrics, and tracing WITHOUT modifying core security logic.
    
    WHEN DISABLED (DEFAULT): Pure pass-through with ZERO overhead
    WHEN ENABLED: Full observability with minimal overhead
    """
    
    def __init__(
        self,
        security_evaluator: Any = None,
        config: Optional[SecurityTelemetryConfig] = None
    ):
        self.config = config or SecurityTelemetryConfig()
        self._security = security_evaluator
        
        # Initialize observability components (all disabled by default)
        self._metrics = SecurityOperationMetrics(self.config)
        self._logger = StructuredSecurityLogger(self.config)
        self._tracer = SecurityOperationTracer(self.config)
    
    def _wrap_operation(self, operation_name: str, func: Callable, *args, **kwargs) -> Any:
        """Wrap operation with optional instrumentation - ZERO overhead when disabled"""
        if not self.config.enabled:
            return func(*args, **kwargs)
        
        start_time = time.perf_counter_ns()
        span_id = self._tracer.start_span(operation_name)
        success = True
        
        try:
            result = func(*args, **kwargs)
            
            # Record comparison result if applicable
            if isinstance(result, bool):
                self._metrics.record_comparison(operation_name, result)
            
            return result
            
        except Exception as e:
            success = False
            self._logger.log_operation(
                operation_name,
                level="ERROR",
                error=str(e),
                error_type=type(e).__name__
            )
            raise
            
        finally:
            duration = time.perf_counter_ns() - start_time
            self._metrics.record_operation(operation_name, duration, success)
            self._tracer.end_span(span_id, success)
            
            if self.config.telemetry_level.value >= TelemetryLevel.DETAILED.value:
                self._logger.log_operation(
                    operation_name,
                    duration_ns=duration,
                    success=success,
                    level="DEBUG" if not success else "INFO"
                )
    
    def evaluate_threshold(
        self,
        value: float,
        threshold: float,
        operation_name: str = "threshold_check"
    ) -> bool:
        """Timing-resistant threshold evaluation with OPTIONAL telemetry"""
        if self._security is not None:
            return self._wrap_operation(
                f"threshold_{operation_name}",
                self._security.evaluate_threshold,
                value, threshold, operation_name
            )
        
        # Fallback if security module not available
        return value >= threshold
    
    def secure_compare(self, a: Any, b: Any) -> bool:
        """Constant-time comparison with OPTIONAL telemetry"""
        if self._security is not None:
            return self._wrap_operation(
                "secure_compare",
                self._security.secure_compare,
                a, b
            )
        
        # Fallback
        return a == b
    
    def protected_operation(self, func: Callable, *args, **kwargs) -> Any:
        """Protected function execution with OPTIONAL telemetry"""
        if self._security is not None:
            return self._wrap_operation(
                f"protected_{func.__name__}",
                self._security.protected_operation,
                func, *args, **kwargs
            )
        
        # Fallback
        return func(*args, **kwargs)
    
    def get_telemetry_summary(self) -> Dict[str, Any]:
        """Get combined telemetry summary - empty if disabled"""
        if not self.config.enabled:
            return {"enabled": False, "status": "telemetry_disabled"}
        
        return {
            "enabled": True,
            "config": {
                "enable_metrics": self.config.enable_metrics,
                "enable_tracing": self.config.enable_tracing,
                "enable_logging": self.config.enable_structured_logging,
                "telemetry_level": self.config.telemetry_level.name,
            },
            "metrics": self._metrics.get_metrics_summary(),
            "tracing_active": self.config.enable_tracing,
        }
    
    def get_health_status(self) -> Dict[str, Any]:
        """Health check endpoint - always returns status"""
        return {
            "status": "healthy" if SECURITY_MODULE_AVAILABLE else "security_module_unavailable",
            "security_module_loaded": SECURITY_MODULE_AVAILABLE,
            "telemetry_enabled": self.config.enabled,
            "version": "v14",
            "timestamp": time.time(),
        }


# Module-level factory function
def create_instrumented_security(
    enable_telemetry: bool = False,
    enable_metrics: bool = False,
    enable_tracing: bool = False,
    enable_logging: bool = False,
) -> InstrumentedTimingResistance:
    """
    Factory function to create instrumented security wrapper.
    ALL FEATURES DISABLED BY DEFAULT - explicit enable required.
    
    Example:
        # Default: NO telemetry, pure pass-through
        security = create_instrumented_security()
        
        # With full observability (OPT-IN)
        security = create_instrumented_security(
            enable_telemetry=True,
            enable_metrics=True,
            enable_tracing=True,
            enable_logging=True
        )
    """
    config = SecurityTelemetryConfig(
        enabled=enable_telemetry,
        enable_metrics=enable_metrics,
        enable_tracing=enable_tracing,
        enable_structured_logging=enable_logging,
        telemetry_level=TelemetryLevel.BASIC if enable_telemetry else TelemetryLevel.DISABLED,
    )
    
    security_evaluator = None
    if SECURITY_MODULE_AVAILABLE:
        from .security_hardening_side_channel_timing_resistance_v17_2026_june import timing_protector
        security_evaluator = timing_protector
    
    return InstrumentedTimingResistance(security_evaluator, config)


# Default instance - ALL TELEMETRY DISABLED, pure pass-through
default_instrumented_security = create_instrumented_security(
    enable_telemetry=False,
    enable_metrics=False,
    enable_tracing=False,
    enable_logging=False,
)

__all__ = [
    'TelemetryLevel',
    'SecurityTelemetryConfig',
    'SecurityOperationMetrics',
    'StructuredSecurityLogger',
    'SecurityOperationTracer',
    'InstrumentedTimingResistance',
    'create_instrumented_security',
    'default_instrumented_security',
    'SECURITY_MODULE_AVAILABLE',
]
