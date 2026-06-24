"""
NeuralShield AI - Observability & Instrumentation Module (Dimension D - V25)
===========================================================================
Production-grade, OPT-IN structured logging, metrics collection, and health check framework.

DESIGN PHILOSOPHY:
- 100% OPT-IN - disabled by default, no impact on existing code
- Wrap existing code, never rewrite core logic
- Zero overhead when disabled
- Backward compatible with all existing modules
- No external dependencies beyond standard library

DIMENSION D FOCUS:
- Structured JSON logging (optional, disabled by default)
- Metrics collection (counters, timers, gauges, histograms)
- Health check framework (liveness, readiness, depth checks)
- Distributed tracing context propagation
- All instrumentation is OPT-IN, never required
"""

import os
import sys
import json
import time
import uuid
import threading
import functools
from typing import Dict, Any, Optional, Callable, List, Tuple
from datetime import datetime, timezone
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum


class LogLevel(Enum):
    """Standard log levels for structured logging."""
    DEBUG = 10
    INFO = 20
    WARNING = 30
    ERROR = 40
    CRITICAL = 50


class MetricType(Enum):
    """Types of metrics supported by the instrumentation system."""
    COUNTER = "counter"
    GAUGE = "gauge"
    TIMER = "timer"
    HISTOGRAM = "histogram"


class HealthStatus(Enum):
    """Health check status enumeration."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


@dataclass
class MetricValue:
    """Container for metric values with metadata."""
    value: float = 0.0
    type: MetricType = MetricType.COUNTER
    labels: Dict[str, str] = field(default_factory=dict)
    timestamp: float = field(default_factory=lambda: time.time())
    description: str = ""


@dataclass
class HealthCheckResult:
    """Result of a health check execution."""
    name: str
    status: HealthStatus
    message: str = ""
    duration_ms: float = 0.0
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class NullLock:
    """No-op lock for when instrumentation is disabled."""
    def __enter__(self): return self
    def __exit__(self, *args): pass


class ObservabilityConfig:
    """Configuration for observability instrumentation - all OPT-IN."""
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        
        # ALL FEATURES DISABLED BY DEFAULT - EXPLICIT OPT-IN REQUIRED
        self.enable_structured_logging: bool = os.getenv("NEURALSHIELD_ENABLE_LOGGING", "0") == "1"
        self.enable_metrics_collection: bool = os.getenv("NEURALSHIELD_ENABLE_METRICS", "0") == "1"
        self.enable_health_checks: bool = os.getenv("NEURALSHIELD_ENABLE_HEALTH", "0") == "1"
        self.enable_tracing: bool = os.getenv("NEURALSHIELD_ENABLE_TRACING", "0") == "1"
        
        # Logging configuration
        self.min_log_level: LogLevel = LogLevel[os.getenv("NEURALSHIELD_LOG_LEVEL", "INFO")]
        self.log_format: str = os.getenv("NEURALSHIELD_LOG_FORMAT", "json")
        
        # Metrics configuration
        self.metrics_retention_seconds: int = int(os.getenv("NEURALSHIELD_METRICS_RETENTION", "3600"))
        self.max_metrics_per_type: int = int(os.getenv("NEURALSHIELD_MAX_METRICS", "10000"))
        
        # Health check configuration
        self.health_check_timeout_seconds: int = int(os.getenv("NEURALSHIELD_HEALTH_TIMEOUT", "5"))


class StructuredLogger:
    """
    OPT-IN structured JSON logger.
    Falls back to no-op when disabled.
    """
    
    def __init__(self, config: Optional[ObservabilityConfig] = None):
        self._config = config or ObservabilityConfig()
        self._context: Dict[str, Any] = {}
    
    def _log(self, level: LogLevel, message: str, **kwargs) -> None:
        """Internal log method - no-op when disabled."""
        if not self._config.enable_structured_logging:
            return
        if level.value < self._config.min_log_level.value:
            return
        
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": level.name,
            "message": message,
            "logger": "neural_shield.observability",
            **self._context,
            **kwargs
        }
        
        if self._config.log_format == "json":
            print(json.dumps(log_entry), file=sys.stderr, flush=True)
        else:
            print(f"[{log_entry['timestamp']}] {level.name}: {message}", file=sys.stderr, flush=True)
    
    def debug(self, message: str, **kwargs) -> None:
        self._log(LogLevel.DEBUG, message, **kwargs)
    
    def info(self, message: str, **kwargs) -> None:
        self._log(LogLevel.INFO, message, **kwargs)
    
    def warning(self, message: str, **kwargs) -> None:
        self._log(LogLevel.WARNING, message, **kwargs)
    
    def error(self, message: str, **kwargs) -> None:
        self._log(LogLevel.ERROR, message, **kwargs)
    
    def critical(self, message: str, **kwargs) -> None:
        self._log(LogLevel.CRITICAL, message, **kwargs)
    
    def bind(self, **context) -> 'StructuredLogger':
        """Create a new logger with bound context."""
        new_logger = StructuredLogger(self._config)
        new_logger._context = {**self._context, **context}
        return new_logger


class MetricsCollector:
    """
    OPT-IN metrics collection system.
    Supports counters, gauges, timers, and histograms.
    No overhead when disabled.
    """
    
    def __init__(self, config: Optional[ObservabilityConfig] = None):
        self._config = config or ObservabilityConfig()
        self._metrics: Dict[str, MetricValue] = {}
        self._histograms: Dict[str, List[float]] = defaultdict(list)
        self._lock = threading.Lock() if self._config.enable_metrics_collection else NullLock()
    
    def increment(self, name: str, value: float = 1.0, labels: Optional[Dict[str, str]] = None, description: str = "") -> None:
        """Increment a counter metric - no-op when disabled."""
        if not self._config.enable_metrics_collection:
            return
        
        with self._lock:
            if name not in self._metrics:
                self._metrics[name] = MetricValue(
                    value=0.0,
                    type=MetricType.COUNTER,
                    labels=labels or {},
                    description=description
                )
            self._metrics[name].value += value
            self._metrics[name].timestamp = time.time()
    
    def gauge(self, name: str, value: float, labels: Optional[Dict[str, str]] = None, description: str = "") -> None:
        """Set a gauge metric - no-op when disabled."""
        if not self._config.enable_metrics_collection:
            return
        
        with self._lock:
            self._metrics[name] = MetricValue(
                value=value,
                type=MetricType.GAUGE,
                labels=labels or {},
                description=description
            )
    
    def record_timing(self, name: str, duration_ms: float, labels: Optional[Dict[str, str]] = None) -> None:
        """Record a timing measurement - no-op when disabled."""
        if not self._config.enable_metrics_collection:
            return
        
        with self._lock:
            if name not in self._histograms:
                self._histograms[name] = []
            self._histograms[name].append(duration_ms)
            
            # Keep only recent metrics
            max_samples = 1000
            if len(self._histograms[name]) > max_samples:
                self._histograms[name] = self._histograms[name][-max_samples:]
    
    def timer(self, name: str, labels: Optional[Dict[str, str]] = None) -> Callable:
        """Decorator/context manager for timing function execution - no-op when disabled."""
        def decorator(func: Callable) -> Callable:
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                if not self._config.enable_metrics_collection:
                    return func(*args, **kwargs)
                
                start = time.perf_counter()
                try:
                    return func(*args, **kwargs)
                finally:
                    duration_ms = (time.perf_counter() - start) * 1000
                    self.record_timing(name, duration_ms, labels)
            return wrapper
        return decorator
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get all collected metrics - returns empty dict when disabled."""
        if not self._config.enable_metrics_collection:
            return {}
        
        with self._lock:
            result = {
                "counters": {},
                "gauges": {},
                "timers": {}
            }
            
            for name, metric in self._metrics.items():
                if metric.type == MetricType.COUNTER:
                    result["counters"][name] = {"value": metric.value, "labels": metric.labels, "description": metric.description}
                elif metric.type == MetricType.GAUGE:
                    result["gauges"][name] = {"value": metric.value, "labels": metric.labels, "description": metric.description}
            
            for name, samples in self._histograms.items():
                if samples:
                    result["timers"][name] = {
                        "count": len(samples),
                        "avg_ms": sum(samples) / len(samples),
                        "min_ms": min(samples),
                        "max_ms": max(samples),
                        "p50_ms": sorted(samples)[len(samples) // 2]
                    }
            
            return result
    
    def reset(self) -> None:
        """Reset all metrics - no-op when disabled."""
        if not self._config.enable_metrics_collection:
            return
        
        with self._lock:
            self._metrics.clear()
            self._histograms.clear()


class HealthCheckRegistry:
    """
    OPT-IN health check framework.
    Supports liveness, readiness, and deep health checks.
    """
    
    def __init__(self, config: Optional[ObservabilityConfig] = None):
        self._config = config or ObservabilityConfig()
        self._checks: Dict[str, Callable[[], HealthCheckResult]] = {}
        self._lock = threading.Lock()
    
    def register(self, name: str, check_func: Callable[[], HealthCheckResult]) -> None:
        """Register a health check - no-op when disabled."""
        if not self._config.enable_health_checks:
            return
        
        with self._lock:
            self._checks[name] = check_func
    
    def unregister(self, name: str) -> None:
        """Unregister a health check."""
        with self._lock:
            self._checks.pop(name, None)
    
    def run_check(self, name: str) -> Optional[HealthCheckResult]:
        """Run a single health check - returns None when disabled."""
        if not self._config.enable_health_checks:
            return None
        
        check_func = self._checks.get(name)
        if not check_func:
            return None
        
        start = time.perf_counter()
        try:
            result = check_func()
            result.duration_ms = (time.perf_counter() - start) * 1000
            return result
        except Exception as e:
            return HealthCheckResult(
                name=name,
                status=HealthStatus.UNHEALTHY,
                message=f"Check failed with exception: {str(e)}",
                duration_ms=(time.perf_counter() - start) * 1000,
                details={"exception_type": type(e).__name__}
            )
    
    def run_all_checks(self) -> Dict[str, Any]:
        """Run all registered health checks - returns empty dict when disabled."""
        if not self._config.enable_health_checks:
            return {}
        
        results = []
        overall_status = HealthStatus.HEALTHY
        
        for name in list(self._checks.keys()):
            result = self.run_check(name)
            if result:
                results.append(result)
                if result.status == HealthStatus.UNHEALTHY:
                    overall_status = HealthStatus.UNHEALTHY
                elif result.status == HealthStatus.DEGRADED and overall_status == HealthStatus.HEALTHY:
                    overall_status = HealthStatus.DEGRADED
        
        return {
            "overall_status": overall_status.value,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "checks": [
                {
                    "name": r.name,
                    "status": r.status.value,
                    "message": r.message,
                    "duration_ms": r.duration_ms,
                    "details": r.details
                }
                for r in results
            ]
        }


# Singleton instances - lazy initialization
_default_logger: Optional[StructuredLogger] = None
_default_metrics: Optional[MetricsCollector] = None
_default_health: Optional[HealthCheckRegistry] = None


def get_logger() -> StructuredLogger:
    """Get the default structured logger instance."""
    global _default_logger
    if _default_logger is None:
        _default_logger = StructuredLogger()
    return _default_logger


def get_metrics() -> MetricsCollector:
    """Get the default metrics collector instance."""
    global _default_metrics
    if _default_metrics is None:
        _default_metrics = MetricsCollector()
    return _default_metrics


def get_health_registry() -> HealthCheckRegistry:
    """Get the default health check registry instance."""
    global _default_health
    if _default_health is None:
        _default_health = HealthCheckRegistry()
    return _default_health


def instrument_threat_detection(func: Callable) -> Callable:
    """
    OPT-IN decorator for instrumenting threat detection functions.
    Adds timing metrics and structured logging without modifying core logic.
    100% backward compatible - no behavior change when disabled.
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        metrics = get_metrics()
        logger = get_logger()
        
        trace_id = str(uuid.uuid4())
        start = time.perf_counter()
        
        logger.debug("Threat detection started", trace_id=trace_id, function=func.__name__)
        metrics.increment("threat_detection_calls_total", labels={"function": func.__name__})
        
        try:
            result = func(*args, **kwargs)
            
            duration_ms = (time.perf_counter() - start) * 1000
            metrics.record_timing("threat_detection_duration_ms", duration_ms, labels={"function": func.__name__})
            
            logger.debug(
                "Threat detection completed",
                trace_id=trace_id,
                function=func.__name__,
                duration_ms=round(duration_ms, 2)
            )
            
            return result
            
        except Exception as e:
            metrics.increment("threat_detection_errors_total", labels={"function": func.__name__, "error": type(e).__name__})
            logger.error(
                "Threat detection failed",
                trace_id=trace_id,
                function=func.__name__,
                error=str(e),
                error_type=type(e).__name__
            )
            raise
    
    return wrapper


# Export public API
__all__ = [
    'ObservabilityConfig',
    'StructuredLogger',
    'MetricsCollector',
    'HealthCheckRegistry',
    'HealthCheckResult',
    'HealthStatus',
    'LogLevel',
    'MetricType',
    'get_logger',
    'get_metrics',
    'get_health_registry',
    'instrument_threat_detection',
]
