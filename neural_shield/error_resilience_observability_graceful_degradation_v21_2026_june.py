"""
NeuralShield AI - Error Resilience Module v21
Observability Graceful Degradation + Telemetry Circuit Breaker + Metric Export Fallbacks
DIMENSION E - Error Resilience
- Graceful degradation for observability v12 system
- Circuit breaker for high-volume telemetry endpoints
- Fallback mechanisms when observability backend is unavailable
- Timeout wrappers for external metric exports
- Memory pressure monitoring for high-volume metrics
- Async-safe error resilience patterns
- OPT-IN instrumentation - disabled by default
- Happy path behavior 100% preserved
ADD-ONLY implementation - wraps existing code, no modifications
"""
import time
import random
import threading
import functools
import logging
from typing import Any, Callable, Dict, List, Optional, Type, Union, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque
import asyncio
import sys
import gc

# Configure logging (disabled by default - OPT-IN)
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


class DegradationLevel(Enum):
    """System degradation levels for graceful degradation."""
    NORMAL = "normal"                   # Full functionality
    LIGHT = "light_degradation"         # Reduced sampling
    MODERATE = "moderate_degradation"   # Only critical metrics
    SEVERE = "severe_degradation"       # Only errors and alerts
    FAILSAFE = "failsafe"               # Complete telemetry shutdown


class TelemetryBackendStatus(Enum):
    """Status of telemetry export backend."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"
    CIRCUIT_OPEN = "circuit_open"


class ObservabilityResilienceError(Exception):
    """Base exception for observability resilience errors."""
    pass


class TelemetryExportError(ObservabilityResilienceError):
    """Raised when telemetry export fails."""
    pass


class MemoryPressureExceededError(ObservabilityResilienceError):
    """Raised when memory pressure exceeds threshold."""
    pass


class BackendCircuitOpenError(ObservabilityResilienceError):
    """Raised when backend circuit breaker is open."""
    pass


@dataclass
class GracefulDegradationConfig:
    """Configuration for graceful degradation behavior."""
    # Memory thresholds (percentage of system memory)
    memory_pressure_light: float = 60.0
    memory_pressure_moderate: float = 75.0
    memory_pressure_severe: float = 85.0
    memory_pressure_failsafe: float = 95.0
    
    # Sampling rates per degradation level
    sampling_rate_normal: float = 1.0
    sampling_rate_light: float = 0.5
    sampling_rate_moderate: float = 0.1
    sampling_rate_severe: float = 0.01
    sampling_rate_failsafe: float = 0.0
    
    # Error rate thresholds
    error_rate_threshold_light: float = 0.05
    error_rate_threshold_moderate: float = 0.15
    error_rate_threshold_severe: float = 0.30
    
    # Latency thresholds (seconds)
    latency_threshold_light: float = 0.1
    latency_threshold_moderate: float = 0.5
    latency_threshold_severe: float = 2.0
    
    # Check intervals
    health_check_interval: float = 5.0
    memory_check_interval: float = 10.0


@dataclass
class TelemetryCircuitBreakerConfig:
    """Configuration for telemetry circuit breaker."""
    failure_threshold: int = 10
    success_threshold: int = 3
    reset_timeout: float = 60.0
    timeout_window: float = 120.0
    half_open_max_attempts: int = 5
    max_queue_size: int = 10000
    drop_oldest_when_full: bool = True


@dataclass
class ExportFallbackConfig:
    """Configuration for export fallback mechanisms."""
    enable_in_memory_fallback: bool = True
    max_in_memory_entries: int = 50000
    enable_disk_fallback: bool = False
    disk_fallback_path: Optional[str] = None
    retry_on_recovery: bool = True
    max_retry_attempts: int = 3
    batch_size_on_recovery: int = 100


@dataclass
class MetricExportTimeoutConfig:
    """Configuration for metric export timeouts."""
    prometheus_export_timeout: float = 2.0
    open_telemetry_export_timeout: float = 5.0
    statsd_export_timeout: float = 1.0
    file_export_timeout: float = 10.0
    http_export_timeout: float = 10.0
    adaptive_timeout: bool = True
    timeout_history_window: int = 50


class MemoryPressureMonitor:
    """Monitors system memory pressure for adaptive degradation."""
    
    def __init__(self, config: Optional[GracefulDegradationConfig] = None):
        self.config = config or GracefulDegradationConfig()
        self._last_check = 0.0
        self._current_pressure = 0.0
        self._lock = threading.Lock()
    
    def get_memory_usage_percent(self) -> float:
        """Get current memory usage percentage."""
        try:
            import psutil
            return psutil.virtual_memory().percent
        except (ImportError, Exception):
            # Fallback calculation if psutil not available
            process = None
            try:
                import gc
                gc.collect()
                objects = len(gc.get_objects())
                # Rough estimation based on object count
                return min(100.0, (objects / 100000.0) * 50.0)
            except:
                return 50.0  # Default safe value
    
    def get_current_pressure(self) -> float:
        """Get current memory pressure level."""
        now = time.time()
        with self._lock:
            if now - self._last_check > self.config.memory_check_interval:
                self._current_pressure = self.get_memory_usage_percent()
                self._last_check = now
            return self._current_pressure
    
    def get_degradation_level(self) -> DegradationLevel:
        """Determine degradation level based on memory pressure."""
        pressure = self.get_current_pressure()
        
        if pressure >= self.config.memory_pressure_failsafe:
            return DegradationLevel.FAILSAFE
        elif pressure >= self.config.memory_pressure_severe:
            return DegradationLevel.SEVERE
        elif pressure >= self.config.memory_pressure_moderate:
            return DegradationLevel.MODERATE
        elif pressure >= self.config.memory_pressure_light:
            return DegradationLevel.LIGHT
        return DegradationLevel.NORMAL


class TelemetryCircuitBreaker:
    """Circuit breaker specifically for telemetry export endpoints."""
    
    def __init__(self, config: Optional[TelemetryCircuitBreakerConfig] = None, name: str = "default"):
        self.config = config or TelemetryCircuitBreakerConfig()
        self.name = name
        self._state = TelemetryBackendStatus.HEALTHY
        self._failure_count = 0
        self._success_count = 0
        self._consecutive_successes = 0
        self._last_failure_time = 0.0
        self._failure_timestamps: deque = deque(maxlen=config.failure_threshold * 2 if config else 20)
        self._lock = threading.Lock()
        self._queue: deque = deque(maxlen=self.config.max_queue_size)
    
    @property
    def state(self) -> TelemetryBackendStatus:
        """Get current backend status."""
        return self._state
    
    @property
    def queue_size(self) -> int:
        """Get current queue size."""
        with self._lock:
            return len(self._queue)
    
    def enqueue_metric(self, metric_data: Any) -> bool:
        """Enqueue metric data for later export."""
        with self._lock:
            if len(self._queue) >= self.config.max_queue_size:
                if self.config.drop_oldest_when_full:
                    self._queue.popleft()
                else:
                    return False
            self._queue.append((time.time(), metric_data))
            return True
    
    def get_queued_metrics(self, max_count: Optional[int] = None) -> List[Any]:
        """Get queued metrics for export on recovery."""
        with self._lock:
            count = max_count if max_count else len(self._queue)
            metrics = []
            for _ in range(min(count, len(self._queue))):
                metrics.append(self._queue.popleft())
            return [m[1] for m in metrics]
    
    def record_success(self) -> None:
        """Record successful export."""
        with self._lock:
            self._consecutive_successes += 1
            
            if self._state == TelemetryBackendStatus.CIRCUIT_OPEN:
                if self._consecutive_successes >= self.config.success_threshold:
                    self._state = TelemetryBackendStatus.HEALTHY
                    self._failure_count = 0
                    self._consecutive_successes = 0
                    logger.info(f"Telemetry circuit '{self.name}' closed - backend recovered")
            
            elif self._state == TelemetryBackendStatus.UNAVAILABLE:
                if self._consecutive_successes >= self.config.success_threshold:
                    self._state = TelemetryBackendStatus.HEALTHY
                    self._failure_count = 0
                    logger.info(f"Telemetry backend '{self.name}' recovered")
            
            elif self._state == TelemetryBackendStatus.DEGRADED:
                if self._consecutive_successes >= self.config.success_threshold:
                    self._state = TelemetryBackendStatus.HEALTHY
                    self._failure_count = 0
            
            self._failure_count = max(0, self._failure_count - 1)
    
    def record_failure(self) -> None:
        """Record failed export attempt."""
        with self._lock:
            self._last_failure_time = time.time()
            self._failure_timestamps.append(time.time())
            self._failure_count += 1
            self._consecutive_successes = 0
            
            # Calculate recent failure rate
            window_start = time.time() - self.config.timeout_window
            recent_failures = sum(1 for ts in self._failure_timestamps if ts > window_start)
            
            if recent_failures >= self.config.failure_threshold:
                if self._state == TelemetryBackendStatus.HEALTHY:
                    self._state = TelemetryBackendStatus.DEGRADED
                    logger.warning(f"Telemetry backend '{self.name}' degraded")
                elif self._state == TelemetryBackendStatus.DEGRADED:
                    self._state = TelemetryBackendStatus.UNAVAILABLE
                    logger.warning(f"Telemetry backend '{self.name}' unavailable")
                elif self._state == TelemetryBackendStatus.UNAVAILABLE:
                    self._state = TelemetryBackendStatus.CIRCUIT_OPEN
                    logger.warning(f"Telemetry circuit '{self.name}' OPEN - stopping exports")
    
    def allow_export(self) -> bool:
        """Check if export should be attempted."""
        with self._lock:
            if self._state == TelemetryBackendStatus.HEALTHY:
                return True
            
            if self._state == TelemetryBackendStatus.DEGRADED:
                # Allow 50% of requests through
                return random.random() < 0.5
            
            if self._state == TelemetryBackendStatus.UNAVAILABLE:
                # Allow 10% of requests for health probing
                return random.random() < 0.1
            
            if self._state == TelemetryBackendStatus.CIRCUIT_OPEN:
                elapsed = time.time() - self._last_failure_time
                if elapsed >= self.config.reset_timeout:
                    self._state = TelemetryBackendStatus.UNAVAILABLE
                    logger.info(f"Telemetry circuit '{self.name}' probing for recovery")
                    return True
                return False
            
            return False


class ExportFallbackManager:
    """Manages fallback mechanisms when telemetry export fails."""
    
    def __init__(self, config: Optional[ExportFallbackConfig] = None):
        self.config = config or ExportFallbackConfig()
        self._in_memory_buffer: deque = deque(maxlen=self.config.max_in_memory_entries)
        self._lock = threading.Lock()
        self._total_dropped = 0
    
    @property
    def buffer_size(self) -> int:
        """Get current in-memory buffer size."""
        with self._lock:
            return len(self._in_memory_buffer)
    
    @property
    def total_dropped(self) -> int:
        """Get total dropped metrics count."""
        with self._lock:
            return self._total_dropped
    
    def store_fallback(self, metric_data: Any) -> bool:
        """Store metric data in fallback buffer."""
        if not self.config.enable_in_memory_fallback:
            return False
        
        with self._lock:
            if len(self._in_memory_buffer) >= self.config.max_in_memory_entries:
                self._in_memory_buffer.popleft()
                self._total_dropped += 1
            self._in_memory_buffer.append((time.time(), metric_data))
            return True
    
    def get_buffered_metrics(self, batch_size: Optional[int] = None) -> List[Any]:
        """Get buffered metrics for retry on backend recovery."""
        if not self.config.retry_on_recovery:
            return []
        
        with self._lock:
            count = batch_size if batch_size else self.config.batch_size_on_recovery
            metrics = []
            for _ in range(min(count, len(self._in_memory_buffer))):
                metrics.append(self._in_memory_buffer.popleft())
            return [m[1] for m in metrics]
    
    def clear_buffer(self) -> None:
        """Clear all buffered metrics."""
        with self._lock:
            self._in_memory_buffer.clear()


class ObservabilityResilienceOrchestrator:
    """Orchestrates all observability resilience mechanisms."""
    
    _instance: Optional['ObservabilityResilienceOrchestrator'] = None
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
        
        self._degradation_config = GracefulDegradationConfig()
        self._circuit_config = TelemetryCircuitBreakerConfig()
        self._fallback_config = ExportFallbackConfig()
        self._timeout_config = MetricExportTimeoutConfig()
        
        self._memory_monitor = MemoryPressureMonitor(self._degradation_config)
        self._circuit_breakers: Dict[str, TelemetryCircuitBreaker] = {}
        self._fallback_managers: Dict[str, ExportFallbackManager] = {}
        
        self._export_error_rates: Dict[str, List[float]] = defaultdict(lambda: [])
        self._export_latencies: Dict[str, List[float]] = defaultdict(lambda: [])
        
        self._global_lock = threading.Lock()
        self._enabled = False  # OPT-IN - disabled by default
        self._initialized = True
    
    def enable(self) -> None:
        """Enable observability resilience (OPT-IN)."""
        with self._global_lock:
            self._enabled = True
            logger.info("Observability resilience enabled")
    
    def disable(self) -> None:
        """Disable observability resilience."""
        with self._global_lock:
            self._enabled = False
            logger.info("Observability resilience disabled")
    
    @property
    def enabled(self) -> bool:
        """Check if resilience is enabled."""
        return self._enabled
    
    def should_sample_metric(self, metric_type: str = "default") -> bool:
        """Determine if metric should be sampled based on current degradation level."""
        if not self._enabled:
            return True  # No resilience = all metrics pass through
        
        level = self._memory_monitor.get_degradation_level()
        
        sampling_rates = {
            DegradationLevel.NORMAL: self._degradation_config.sampling_rate_normal,
            DegradationLevel.LIGHT: self._degradation_config.sampling_rate_light,
            DegradationLevel.MODERATE: self._degradation_config.sampling_rate_moderate,
            DegradationLevel.SEVERE: self._degradation_config.sampling_rate_severe,
            DegradationLevel.FAILSAFE: self._degradation_config.sampling_rate_failsafe,
        }
        
        rate = sampling_rates.get(level, 1.0)
        return random.random() < rate
    
    def get_circuit_breaker(self, name: str) -> TelemetryCircuitBreaker:
        """Get or create telemetry circuit breaker by name."""
        with self._global_lock:
            if name not in self._circuit_breakers:
                self._circuit_breakers[name] = TelemetryCircuitBreaker(self._circuit_config, name)
            return self._circuit_breakers[name]
    
    def get_fallback_manager(self, name: str) -> ExportFallbackManager:
        """Get or create export fallback manager by name."""
        with self._global_lock:
            if name not in self._fallback_managers:
                self._fallback_managers[name] = ExportFallbackManager(self._fallback_config)
            return self._fallback_managers[name]
    
    def get_degradation_level(self) -> DegradationLevel:
        """Get current system degradation level."""
        return self._memory_monitor.get_degradation_level()
    
    def get_status(self) -> Dict[str, Any]:
        """Get comprehensive resilience status."""
        return {
            "enabled": self._enabled,
            "degradation_level": self._memory_monitor.get_degradation_level().value,
            "memory_pressure": self._memory_monitor.get_current_pressure(),
            "circuit_breakers": {
                name: {
                    "state": cb.state.value,
                    "queue_size": cb.queue_size,
                    "failure_count": cb._failure_count
                }
                for name, cb in self._circuit_breakers.items()
            },
            "fallback_buffers": {
                name: {
                    "buffer_size": fm.buffer_size,
                    "total_dropped": fm.total_dropped
                }
                for name, fm in self._fallback_managers.items()
            }
        }


def with_observability_resilience(
    export_name: str = "default",
    enable_fallback: bool = True,
    timeout_seconds: Optional[float] = None
):
    """
    Decorator for observability export resilience.
    
    Provides:
    - Circuit breaking for failing backends
    - Graceful degradation based on memory pressure
    - Fallback buffering when export fails
    - Timeout enforcement
    
    Usage:
        @with_observability_resilience(export_name="prometheus")
        def export_metrics():
            ...
    """
    orchestrator = ObservabilityResilienceOrchestrator()
    
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if not orchestrator.enabled:
                # Resilience disabled - direct passthrough
                return func(*args, **kwargs)
            
            circuit_breaker = orchestrator.get_circuit_breaker(export_name)
            fallback_manager = orchestrator.get_fallback_manager(export_name)
            
            # Check sampling based on degradation level
            if not orchestrator.should_sample_metric(export_name):
                return None  # Gracefully skip this export
            
            # Check circuit breaker
            if not circuit_breaker.allow_export():
                if enable_fallback:
                    # Store in fallback buffer
                    fallback_manager.store_fallback((args, kwargs))
                return None
            
            timeout = timeout_seconds if timeout_seconds else 5.0
            result = [None]
            exception = [None]
            success = [False]
            
            def target():
                try:
                    start_time = time.time()
                    result[0] = func(*args, **kwargs)
                    duration = time.time() - start_time
                    success[0] = True
                except Exception as e:
                    exception[0] = e
            
            thread = threading.Thread(target=target)
            thread.daemon = True
            thread.start()
            thread.join(timeout=timeout)
            
            if thread.is_alive():
                circuit_breaker.record_failure()
                if enable_fallback:
                    fallback_manager.store_fallback((args, kwargs))
                return None
            
            if success[0]:
                circuit_breaker.record_success()
                return result[0]
            else:
                circuit_breaker.record_failure()
                if enable_fallback:
                    fallback_manager.store_fallback((args, kwargs))
                return None
        
        return wrapper
    return decorator


def safe_metric_export(
    export_func: Callable,
    *args,
    export_name: str = "default",
    **kwargs
) -> Optional[Any]:
    """
    Safe metric export with graceful degradation.
    
    Returns None on failure rather than raising exceptions.
    """
    orchestrator = ObservabilityResilienceOrchestrator()
    
    if not orchestrator.enabled:
        try:
            return export_func(*args, **kwargs)
        except:
            return None
    
    circuit_breaker = orchestrator.get_circuit_breaker(export_name)
    fallback_manager = orchestrator.get_fallback_manager(export_name)
    
    if not orchestrator.should_sample_metric(export_name):
        return None
    
    if not circuit_breaker.allow_export():
        fallback_manager.store_fallback((args, kwargs))
        return None
    
    try:
        result = export_func(*args, **kwargs)
        circuit_breaker.record_success()
        return result
    except Exception:
        circuit_breaker.record_failure()
        fallback_manager.store_fallback((args, kwargs))
        return None


# Global singleton instance for easy access
observability_resilience = ObservabilityResilienceOrchestrator()
