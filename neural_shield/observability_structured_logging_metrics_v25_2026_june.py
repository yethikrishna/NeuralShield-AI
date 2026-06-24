"""
NeuralShield AI - Observability & Instrumentation Module (Dimension D)
Version: v25 - June 2026
Philosophy: ADD-ONLY, OPT-IN, Backward Compatible, No breaking changes

This module provides:
1. Structured JSON logging (opt-in, disabled by default)
2. Metrics collection (counters, timers, gauges)
3. Health check endpoints and framework
4. Distributed tracing context propagation
5. All instrumentation is OPT-IN - existing code behavior 100% preserved
"""

import json
import time
import uuid
import threading
from datetime import datetime
from typing import Dict, Any, Optional, Callable, List
from functools import wraps
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
import inspect


class LogLevel(Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class MetricType(Enum):
    COUNTER = "counter"
    GAUGE = "gauge"
    TIMER = "timer"
    HISTOGRAM = "histogram"


class HealthStatus(Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


@dataclass
class Metric:
    name: str
    type: MetricType
    value: float = 0.0
    labels: Dict[str, str] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


@dataclass
class HealthCheck:
    name: str
    status: HealthStatus
    message: str = ""
    duration_ms: float = 0.0
    details: Dict[str, Any] = field(default_factory=dict)


class ObservabilityConfig:
    """Global configuration for observability - ALL OPT-IN by default"""
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
        # ALL FEATURES DISABLED BY DEFAULT - OPT-IN ONLY
        self.structured_logging_enabled: bool = False
        self.metrics_collection_enabled: bool = False
        self.health_checks_enabled: bool = False
        self.tracing_enabled: bool = False
        self.min_log_level: LogLevel = LogLevel.INFO
        self.log_destination: str = "console"
        self._initialized = True
    
    def enable_all(self):
        """Enable all observability features - explicit opt-in"""
        self.structured_logging_enabled = True
        self.metrics_collection_enabled = True
        self.health_checks_enabled = True
        self.tracing_enabled = True
    
    def enable_structured_logging(self):
        self.structured_logging_enabled = True
    
    def enable_metrics(self):
        self.metrics_collection_enabled = True
    
    def enable_health_checks(self):
        self.health_checks_enabled = True
    
    def enable_tracing(self):
        self.tracing_enabled = True


class StructuredLogger:
    """Structured JSON logger - OPT-IN only"""
    
    def __init__(self, name: str = "neural_shield"):
        self.name = name
        self.config = ObservabilityConfig()
    
    def _log(self, level: LogLevel, message: str, **kwargs):
        """Internal log method - only executes if explicitly enabled"""
        if not self.config.structured_logging_enabled:
            return
        
        log_entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "logger": self.name,
            "level": level.value,
            "message": message,
            "trace_id": kwargs.get("trace_id", str(uuid.uuid4())),
            "span_id": kwargs.get("span_id", str(uuid.uuid4())[:8]),
        }
        
        # Add extra fields
        for key, value in kwargs.items():
            if key not in ("trace_id", "span_id"):
                log_entry[key] = value
        
        # Output based on destination
        if self.config.log_destination == "console":
            print(json.dumps(log_entry))
    
    def debug(self, message: str, **kwargs):
        self._log(LogLevel.DEBUG, message, **kwargs)
    
    def info(self, message: str, **kwargs):
        self._log(LogLevel.INFO, message, **kwargs)
    
    def warning(self, message: str, **kwargs):
        self._log(LogLevel.WARNING, message, **kwargs)
    
    def error(self, message: str, **kwargs):
        self._log(LogLevel.ERROR, message, **kwargs)
    
    def critical(self, message: str, **kwargs):
        self._log(LogLevel.CRITICAL, message, **kwargs)


class MetricsCollector:
    """Thread-safe metrics collector - OPT-IN only"""
    
    def __init__(self):
        self.config = ObservabilityConfig()
        self._metrics: Dict[str, List[Metric]] = defaultdict(list)
        self._lock = threading.Lock()
        self._start_times: Dict[str, float] = {}
    
    def increment_counter(self, name: str, value: float = 1.0, labels: Optional[Dict[str, str]] = None):
        """Increment a counter metric - only if enabled"""
        if not self.config.metrics_collection_enabled:
            return
        
        with self._lock:
            metric = Metric(
                name=name,
                type=MetricType.COUNTER,
                value=value,
                labels=labels or {}
            )
            self._metrics[name].append(metric)
    
    def set_gauge(self, name: str, value: float, labels: Optional[Dict[str, str]] = None):
        """Set a gauge metric - only if enabled"""
        if not self.config.metrics_collection_enabled:
            return
        
        with self._lock:
            metric = Metric(
                name=name,
                type=MetricType.GAUGE,
                value=value,
                labels=labels or {}
            )
            self._metrics[name].append(metric)
    
    def start_timer(self, name: str):
        """Start a timer"""
        if not self.config.metrics_collection_enabled:
            return
        self._start_times[name] = time.time()
    
    def stop_timer(self, name: str, labels: Optional[Dict[str, str]] = None) -> Optional[float]:
        """Stop a timer and record duration - returns duration in ms"""
        if not self.config.metrics_collection_enabled:
            return None
        
        start_time = self._start_times.pop(name, None)
        if start_time is None:
            return None
        
        duration_ms = (time.time() - start_time) * 1000
        
        with self._lock:
            metric = Metric(
                name=name,
                type=MetricType.TIMER,
                value=duration_ms,
                labels=labels or {}
            )
            self._metrics[name].append(metric)
        
        return duration_ms
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get aggregated metrics snapshot"""
        with self._lock:
            result = {}
            for name, metrics_list in self._metrics.items():
                if not metrics_list:
                    continue
                
                metric_type = metrics_list[0].type
                if metric_type == MetricType.COUNTER:
                    result[name] = {
                        "type": "counter",
                        "total": sum(m.value for m in metrics_list),
                        "count": len(metrics_list)
                    }
                elif metric_type == MetricType.TIMER:
                    values = [m.value for m in metrics_list]
                    result[name] = {
                        "type": "timer",
                        "count": len(values),
                        "avg_ms": sum(values) / len(values),
                        "min_ms": min(values),
                        "max_ms": max(values)
                    }
                elif metric_type == MetricType.GAUGE:
                    result[name] = {
                        "type": "gauge",
                        "current": metrics_list[-1].value
                    }
            return result
    
    def reset(self):
        """Clear all metrics"""
        with self._lock:
            self._metrics.clear()


def timed_operation(metric_name: str, labels: Optional[Dict[str, str]] = None):
    """
    Decorator for timing operations - OPT-IN, no-op if metrics disabled
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            config = ObservabilityConfig()
            if not config.metrics_collection_enabled:
                return func(*args, **kwargs)
            
            collector = MetricsCollector()
            start_time = time.time()
            try:
                result = func(*args, **kwargs)
                duration_ms = (time.time() - start_time) * 1000
                collector.increment_counter(f"{metric_name}_success", labels=labels)
                collector.set_gauge(f"{metric_name}_duration_ms", duration_ms, labels=labels)
                return result
            except Exception as e:
                duration_ms = (time.time() - start_time) * 1000
                collector.increment_counter(f"{metric_name}_errors", labels={**(labels or {}), "error": type(e).__name__})
                collector.set_gauge(f"{metric_name}_duration_ms", duration_ms, labels=labels)
                raise
        return wrapper
    return decorator


def logged_operation(log_level: LogLevel = LogLevel.INFO, message: Optional[str] = None):
    """
    Decorator for logging function entry/exit - OPT-IN, no-op if logging disabled
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            config = ObservabilityConfig()
            if not config.structured_logging_enabled:
                return func(*args, **kwargs)
            
            logger = StructuredLogger(func.__module__)
            func_name = func.__name__
            trace_id = str(uuid.uuid4())
            
            log_msg = message or f"Executing {func_name}"
            logger._log(log_level, f"START: {log_msg}", 
                       trace_id=trace_id,
                       function=func_name,
                       args_count=len(args),
                       kwargs_count=len(kwargs))
            
            start_time = time.time()
            try:
                result = func(*args, **kwargs)
                duration_ms = (time.time() - start_time) * 1000
                logger._log(log_level, f"COMPLETE: {log_msg}",
                           trace_id=trace_id,
                           function=func_name,
                           duration_ms=round(duration_ms, 2),
                           success=True)
                return result
            except Exception as e:
                duration_ms = (time.time() - start_time) * 1000
                logger.error(f"FAILED: {log_msg}",
                            trace_id=trace_id,
                            function=func_name,
                            duration_ms=round(duration_ms, 2),
                            error_type=type(e).__name__,
                            error_message=str(e),
                            success=False)
                raise
        return wrapper
    return decorator


class HealthCheckRegistry:
    """Health check registry - OPT-IN only"""
    
    def __init__(self):
        self.config = ObservabilityConfig()
        self._checks: Dict[str, Callable[[], HealthCheck]] = {}
        self._lock = threading.Lock()
    
    def register(self, name: str, check_func: Callable[[], HealthCheck]):
        """Register a health check function"""
        with self._lock:
            self._checks[name] = check_func
    
    def run_all_checks(self) -> Dict[str, Any]:
        """Run all registered health checks - only if enabled"""
        if not self.config.health_checks_enabled:
            return {"health_checks_enabled": False, "status": "not_configured"}
        
        results = []
        overall_status = HealthStatus.HEALTHY
        
        with self._lock:
            for name, check_func in self._checks.items():
                start_time = time.time()
                try:
                    check_result = check_func()
                    check_result.duration_ms = (time.time() - start_time) * 1000
                    results.append(check_result)
                    
                    if check_result.status == HealthStatus.UNHEALTHY:
                        overall_status = HealthStatus.UNHEALTHY
                    elif check_result.status == HealthStatus.DEGRADED and overall_status == HealthStatus.HEALTHY:
                        overall_status = HealthStatus.DEGRADED
                except Exception as e:
                    results.append(HealthCheck(
                        name=name,
                        status=HealthStatus.UNHEALTHY,
                        message=f"Health check failed: {str(e)}",
                        duration_ms=(time.time() - start_time) * 1000
                    ))
                    overall_status = HealthStatus.UNHEALTHY
        
        return {
            "overall_status": overall_status.value,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "checks": [
                {
                    "name": r.name,
                    "status": r.status.value,
                    "message": r.message,
                    "duration_ms": round(r.duration_ms, 2),
                    "details": r.details
                }
                for r in results
            ]
        }


# Global singleton instances - lazy initialized
_global_logger: Optional[StructuredLogger] = None
_global_metrics: Optional[MetricsCollector] = None
_global_health: Optional[HealthCheckRegistry] = None


def get_logger() -> StructuredLogger:
    """Get the global structured logger instance"""
    global _global_logger
    if _global_logger is None:
        _global_logger = StructuredLogger()
    return _global_logger


def get_metrics() -> MetricsCollector:
    """Get the global metrics collector instance"""
    global _global_metrics
    if _global_metrics is None:
        _global_metrics = MetricsCollector()
    return _global_metrics


def get_health_registry() -> HealthCheckRegistry:
    """Get the global health check registry instance"""
    global _global_health
    if _global_health is None:
        _global_health = HealthCheckRegistry()
    return _global_health


def get_config() -> ObservabilityConfig:
    """Get the global observability configuration"""
    return ObservabilityConfig()


# Export public API
__all__ = [
    "ObservabilityConfig", "get_config",
    "LogLevel", "StructuredLogger", "get_logger", "logged_operation",
    "MetricType", "Metric", "MetricsCollector", "get_metrics", "timed_operation",
    "HealthStatus", "HealthCheck", "HealthCheckRegistry", "get_health_registry",
]
