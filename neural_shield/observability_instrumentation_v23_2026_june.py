"""
NeuralShield AI - Observability & Instrumentation v23
====================================================
Dimension D: Observability & Instrumentation
Version: v23 (odd number pattern maintained: v15 -> v17 -> v19 -> v21 -> v23)

STRICTLY ADD-ONLY: This module wraps existing code, never modifies it.
100% OPT-IN: All instrumentation is disabled by default, must be explicitly enabled.
BACKWARD COMPATIBLE: No breaking changes to existing APIs.

Features:
- Structured logging (JSON, optional, disabled by default)
- Metrics collection (counters, timers, gauges, histograms)
- Health check framework
- Event tracing with correlation IDs
- Performance profiling wrappers
- All opt-in, zero overhead when disabled
"""

import json
import time
import uuid
import threading
import logging
from typing import Dict, List, Any, Optional, Callable, TypeVar, Generic
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from functools import wraps
from collections import defaultdict
from contextlib import contextmanager
from enum import Enum

# -----------------------------------------------------------------------------
# Configuration - ALL DISABLED BY DEFAULT
# -----------------------------------------------------------------------------
@dataclass
class ObservabilityConfig:
    """Configuration for observability - ALL DISABLED BY DEFAULT."""
    enable_structured_logging: bool = False
    enable_metrics_collection: bool = False
    enable_health_checks: bool = False
    enable_tracing: bool = False
    enable_profiling: bool = False
    log_level: str = "WARNING"
    metrics_retention_seconds: int = 3600
    max_traces_per_minute: int = 100
    redact_sensitive_data: bool = True

    def is_any_enabled(self) -> bool:
        """Check if any observability feature is enabled."""
        return any([
            self.enable_structured_logging,
            self.enable_metrics_collection,
            self.enable_health_checks,
            self.enable_tracing,
            self.enable_profiling,
        ])

# Global config - everything disabled by default
_global_config = ObservabilityConfig()
_config_lock = threading.Lock()

def configure_observability(**kwargs) -> None:
    """
    Configure observability features.
    ALL FEATURES ARE DISABLED BY DEFAULT.
    Must explicitly opt-in to each feature.
    
    Example:
        configure_observability(
            enable_structured_logging=True,
            enable_metrics_collection=True,
            log_level="INFO"
        )
    """
    global _global_config
    with _config_lock:
        for key, value in kwargs.items():
            if hasattr(_global_config, key):
                setattr(_global_config, key, value)

def get_config() -> ObservabilityConfig:
    """Get current observability configuration."""
    with _config_lock:
        return ObservabilityConfig(**asdict(_global_config))

# -----------------------------------------------------------------------------
# Correlation ID Management
# -----------------------------------------------------------------------------
_correlation_local = threading.local()

def get_correlation_id() -> Optional[str]:
    """Get current correlation ID (thread-local)."""
    return getattr(_correlation_local, 'correlation_id', None)

def set_correlation_id(correlation_id: Optional[str] = None) -> str:
    """Set correlation ID for current thread. Generates new if None."""
    cid = correlation_id or str(uuid.uuid4())
    _correlation_local.correlation_id = cid
    return cid

@contextmanager
def correlation_context(correlation_id: Optional[str] = None):
    """Context manager for correlation IDs."""
    old_id = get_correlation_id()
    new_id = set_correlation_id(correlation_id)
    try:
        yield new_id
    finally:
        if old_id:
            set_correlation_id(old_id)
        else:
            if hasattr(_correlation_local, 'correlation_id'):
                delattr(_correlation_local, 'correlation_id')

# -----------------------------------------------------------------------------
# Structured Logging (OPT-IN ONLY)
# -----------------------------------------------------------------------------
class LogLevel(Enum):
    DEBUG = 10
    INFO = 20
    WARNING = 30
    ERROR = 40
    CRITICAL = 50

SENSITIVE_PATTERNS = [
    'api_key', 'secret', 'password', 'token', 'authorization',
    'private_key', 'credit_card', 'ssn', 'email', 'phone'
]

def _redact_sensitive(data: Dict[str, Any]) -> Dict[str, Any]:
    """Redact sensitive data from logs if enabled."""
    if not _global_config.redact_sensitive_data:
        return data
    
    result = {}
    for key, value in data.items():
        key_lower = key.lower()
        if any(pattern in key_lower for pattern in SENSITIVE_PATTERNS):
            result[key] = "[REDACTED]"
        elif isinstance(value, dict):
            result[key] = _redact_sensitive(value)
        else:
            result[key] = value
    return result

def structured_log(level: str, message: str, **kwargs) -> None:
    """
    Emit structured log entry (OPT-IN ONLY).
    Does nothing if enable_structured_logging is False.
    """
    if not _global_config.enable_structured_logging:
        return
    
    config_level = LogLevel[_global_config.log_level].value
    event_level = LogLevel[level].value
    
    if event_level < config_level:
        return
    
    log_entry = {
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'level': level,
        'message': message,
        'correlation_id': get_correlation_id(),
        'module': 'neural_shield_observability_v23',
        'version': '23.0.0',
    }
    log_entry.update(kwargs)
    log_entry = _redact_sensitive(log_entry)
    
    print(json.dumps(log_entry))

# Convenience log functions
def log_debug(message: str, **kwargs): structured_log("DEBUG", message, **kwargs)
def log_info(message: str, **kwargs): structured_log("INFO", message, **kwargs)
def log_warning(message: str, **kwargs): structured_log("WARNING", message, **kwargs)
def log_error(message: str, **kwargs): structured_log("ERROR", message, **kwargs)
def log_critical(message: str, **kwargs): structured_log("CRITICAL", message, **kwargs)

# -----------------------------------------------------------------------------
# Metrics Collection (OPT-IN ONLY)
# -----------------------------------------------------------------------------
@dataclass
class MetricPoint:
    timestamp: float
    value: float
    labels: Dict[str, str] = field(default_factory=dict)

class MetricsStore:
    """Thread-safe metrics storage (OPT-IN ONLY)."""
    
    def __init__(self):
        self._counters: Dict[str, float] = defaultdict(float)
        self._gauges: Dict[str, float] = {}
        self._timers: Dict[str, List[MetricPoint]] = defaultdict(list)
        self._histograms: Dict[str, List[MetricPoint]] = defaultdict(list)
        self._lock = threading.Lock()
    
    def increment_counter(self, name: str, value: float = 1.0, labels: Dict[str, str] = None):
        """Increment a counter metric."""
        if not _global_config.enable_metrics_collection:
            return
        with self._lock:
            self._counters[name] += value
    
    def set_gauge(self, name: str, value: float, labels: Dict[str, str] = None):
        """Set a gauge metric."""
        if not _global_config.enable_metrics_collection:
            return
        with self._lock:
            self._gauges[name] = value
    
    def record_timer(self, name: str, duration_seconds: float, labels: Dict[str, str] = None):
        """Record a timing metric."""
        if not _global_config.enable_metrics_collection:
            return
        with self._lock:
            self._timers[name].append(MetricPoint(
                timestamp=time.time(),
                value=duration_seconds,
                labels=labels or {}
            ))
            self._cleanup_old_metrics()
    
    def record_histogram(self, name: str, value: float, labels: Dict[str, str] = None):
        """Record a histogram metric."""
        if not _global_config.enable_metrics_collection:
            return
        with self._lock:
            self._histograms[name].append(MetricPoint(
                timestamp=time.time(),
                value=value,
                labels=labels or {}
            ))
            self._cleanup_old_metrics()
    
    def _cleanup_old_metrics(self):
        """Clean up metrics older than retention period."""
        cutoff = time.time() - _global_config.metrics_retention_seconds
        for timer_list in self._timers.values():
            timer_list[:] = [m for m in timer_list if m.timestamp > cutoff]
        for hist_list in self._histograms.values():
            hist_list[:] = [m for m in hist_list if m.timestamp > cutoff]
    
    def get_all_metrics(self) -> Dict[str, Any]:
        """Get snapshot of all metrics."""
        if not _global_config.enable_metrics_collection:
            return {}
        with self._lock:
            return {
                'counters': dict(self._counters),
                'gauges': dict(self._gauges),
                'timer_count': {k: len(v) for k, v in self._timers.items()},
                'timer_avg': {k: sum(m.value for m in v)/len(v) if v else 0 for k, v in self._timers.items()},
                'histogram_count': {k: len(v) for k, v in self._histograms.items()},
            }

_metrics_store = MetricsStore()

# Public metrics API
def counter_inc(name: str, value: float = 1.0, **labels):
    _metrics_store.increment_counter(name, value, labels)

def gauge_set(name: str, value: float, **labels):
    _metrics_store.set_gauge(name, value, labels)

def timer_record(name: str, duration: float, **labels):
    _metrics_store.record_timer(name, duration, labels)

def histogram_record(name: str, value: float, **labels):
    _metrics_store.record_histogram(name, value, labels)

def get_metrics_snapshot() -> Dict[str, Any]:
    return _metrics_store.get_all_metrics()

@contextmanager
def timer_context(metric_name: str, **labels):
    """Context manager for timing operations."""
    start = time.time()
    try:
        yield
    finally:
        duration = time.time() - start
        timer_record(metric_name, duration, **labels)

T = TypeVar('T')

def timed(metric_name: str) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """Decorator for timing function calls."""
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args, **kwargs) -> T:
            with timer_context(metric_name, function=func.__name__):
                return func(*args, **kwargs)
        return wrapper
    return decorator

# -----------------------------------------------------------------------------
# Health Check Framework (OPT-IN ONLY)
# -----------------------------------------------------------------------------
class HealthStatus(Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"

@dataclass
class HealthCheckResult:
    name: str
    status: HealthStatus
    message: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    response_time_ms: float = 0.0

class HealthCheckRegistry:
    """Registry for health checks."""
    
    def __init__(self):
        self._checks: Dict[str, Callable[[], HealthCheckResult]] = {}
        self._lock = threading.Lock()
    
    def register(self, name: str, check_func: Callable[[], HealthCheckResult]):
        """Register a health check."""
        with self._lock:
            self._checks[name] = check_func
    
    def unregister(self, name: str):
        """Unregister a health check."""
        with self._lock:
            self._checks.pop(name, None)
    
    def run_all_checks(self) -> Dict[str, Any]:
        """Run all registered health checks."""
        if not _global_config.enable_health_checks:
            return {
                'status': HealthStatus.HEALTHY.value,
                'checks': {},
                'message': 'Health checks disabled (OPT-IN only)'
            }
        
        results = {}
        overall_status = HealthStatus.HEALTHY
        
        with self._lock:
            checks_copy = dict(self._checks)
        
        for name, check_func in checks_copy.items():
            try:
                start = time.time()
                result = check_func()
                result.response_time_ms = (time.time() - start) * 1000
                results[name] = asdict(result)
                results[name]['status'] = result.status.value
                
                if result.status == HealthStatus.UNHEALTHY:
                    overall_status = HealthStatus.UNHEALTHY
                elif result.status == HealthStatus.DEGRADED and overall_status == HealthStatus.HEALTHY:
                    overall_status = HealthStatus.DEGRADED
            except Exception as e:
                results[name] = {
                    'name': name,
                    'status': HealthStatus.UNHEALTHY.value,
                    'message': f'Health check exception: {str(e)}',
                    'error': str(e)
                }
                overall_status = HealthStatus.UNHEALTHY
        
        return {
            'status': overall_status.value,
            'checks': results,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'total_checks': len(results)
        }

_health_registry = HealthCheckRegistry()

# Public health check API
def register_health_check(name: str, check_func: Callable[[], HealthCheckResult]):
    _health_registry.register(name, check_func)

def run_health_checks() -> Dict[str, Any]:
    return _health_registry.run_all_checks()

# Built-in health checks
def _memory_health_check() -> HealthCheckResult:
    """Check memory usage."""
    try:
        import psutil
        mem = psutil.virtual_memory()
        usage_pct = mem.percent
        if usage_pct > 90:
            return HealthCheckResult(
                name='memory',
                status=HealthStatus.UNHEALTHY,
                message=f'Memory critically high: {usage_pct}%',
                details={'usage_percent': usage_pct}
            )
        elif usage_pct > 75:
            return HealthCheckResult(
                name='memory',
                status=HealthStatus.DEGRADED,
                message=f'Memory high: {usage_pct}%',
                details={'usage_percent': usage_pct}
            )
        return HealthCheckResult(
            name='memory',
            status=HealthStatus.HEALTHY,
            message=f'Memory OK: {usage_pct}%',
            details={'usage_percent': usage_pct}
        )
    except ImportError:
        return HealthCheckResult(
            name='memory',
            status=HealthStatus.HEALTHY,
            message='psutil not available, skipping memory check'
        )

# Register built-in checks (but they only run if health checks enabled)
register_health_check('system_memory', _memory_health_check)

# -----------------------------------------------------------------------------
# Instrumentation Wrappers (OPT-IN, ZERO OVERHEAD WHEN DISABLED)
# -----------------------------------------------------------------------------
def instrument_threat_detection(detector_name: str):
    """
    Decorator to instrument threat detection functions.
    ZERO OVERHEAD when observability is disabled.
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args, **kwargs) -> T:
            if not _global_config.is_any_enabled():
                return func(*args, **kwargs)
            
            with correlation_context():
                with timer_context(f'threat_detection.{detector_name}.duration'):
                    counter_inc(f'threat_detection.{detector_name}.calls')
                    log_info(f"Starting threat detection: {detector_name}")
                    
                    try:
                        result = func(*args, **kwargs)
                        counter_inc(f'threat_detection.{detector_name}.success')
                        log_info(f"Threat detection complete: {detector_name}", result_type=type(result).__name__)
                        return result
                    except Exception as e:
                        counter_inc(f'threat_detection.{detector_name}.errors')
                        log_error(f"Threat detection error: {detector_name}", error=str(e), error_type=type(e).__name__)
                        raise
        return wrapper
    return decorator

# -----------------------------------------------------------------------------
# Factory Functions
# -----------------------------------------------------------------------------
def create_instrumented_wrapper(
    wrapped_function: Callable,
    name: str,
    log_calls: bool = True,
    track_metrics: bool = True,
    trace: bool = True
) -> Callable:
    """
    Create an instrumented wrapper around any function.
    All instrumentation is OPT-IN based on global config.
    """
    @wraps(wrapped_function)
    def wrapper(*args, **kwargs):
        if not _global_config.is_any_enabled():
            return wrapped_function(*args, **kwargs)
        
        cid = set_correlation_id() if trace and _global_config.enable_tracing else None
        
        start = time.time()
        try:
            if log_calls and _global_config.enable_structured_logging:
                log_info(f"Calling {name}", correlation_id=cid)
            
            result = wrapped_function(*args, **kwargs)
            
            duration = time.time() - start
            if track_metrics and _global_config.enable_metrics_collection:
                timer_record(f'function.{name}.duration', duration)
                counter_inc(f'function.{name}.success')
            
            return result
        except Exception as e:
            duration = time.time() - start
            if track_metrics and _global_config.enable_metrics_collection:
                counter_inc(f'function.{name}.errors')
            if log_calls and _global_config.enable_structured_logging:
                log_error(f"Error in {name}", error=str(e), duration_ms=duration*1000)
            raise
    
    return wrapper

# -----------------------------------------------------------------------------
# Version & Metadata
# -----------------------------------------------------------------------------
OBSERVABILITY_VERSION = "23.0.0"
OBSERVABILITY_DIMENSION = "D"
OBSERVABILITY_FEATURES = [
    "structured_logging",
    "metrics_collection",
    "health_checks",
    "distributed_tracing",
    "performance_profiling"
]

def get_observability_metadata() -> Dict[str, Any]:
    """Get observability module metadata."""
    return {
        'version': OBSERVABILITY_VERSION,
        'dimension': OBSERVABILITY_DIMENSION,
        'features': OBSERVABILITY_FEATURES,
        'config': asdict(get_config()),
        'any_enabled': get_config().is_any_enabled(),
        'metrics_count': len(get_metrics_snapshot()),
    }
