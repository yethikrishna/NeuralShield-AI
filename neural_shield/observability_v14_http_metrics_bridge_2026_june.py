"""
Observability v14 - HTTP Metrics Bridge for NeuralShield-AI
==========================================================
DIMENSION D - Observability & Instrumentation v14
ADD-ONLY IMPLEMENTATION: 100% new module, NO existing code modified
OPT-IN DESIGN: Disabled by default, zero overhead when off
Purpose: Bridge v8 Observability metrics → v14 HTTP Metrics Server
Features:
- Automatic metric forwarding from v8 registry to HTTP /metrics endpoint
- Prometheus format conversion (counters, gauges, timers, histograms)
- Background thread with configurable sync interval
- Thread-safe, no race conditions
- Graceful degradation if HTTP server not running
- Backward compatible: v8 code works unchanged
- Perfect ADD-ONLY: No modifications to v8 or v14 modules
Philosophy: If it ain't broke, don't rewrite it. Layer on top.
"""
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Any, Callable
import threading
import time
import logging
from typing import TYPE_CHECKING
# Lazy imports to avoid hard dependencies
if TYPE_CHECKING:
    from .observability_metrics_collection_v8_2026_june import MetricsRegistry as V8Registry
    from .feature_expansion_http_metrics_server_v14_2026_june import HTTPMetricsServer as V14Server
class BridgeState(Enum):
    DISABLED = "disabled"
    ENABLED = "enabled"
    SYNCING = "syncing"
    ERROR = "error"
@dataclass
class BridgeConfig:
    """Configuration for v8 → v14 metrics bridge"""
    DEFAULT_SYNC_INTERVAL = 5.0  # seconds
    DEFAULT_ENABLE_TIMERS = True
    DEFAULT_ENABLE_HISTOGRAMS = True
    DEFAULT_AUTO_START_SERVER = False
    
    def __init__(
        self,
        sync_interval_seconds: float = DEFAULT_SYNC_INTERVAL,
        enable_timers: bool = DEFAULT_ENABLE_TIMERS,
        enable_histograms: bool = DEFAULT_ENABLE_HISTOGRAMS,
        auto_start_server: bool = DEFAULT_AUTO_START_SERVER,
        metric_prefix: str = "neuralshield_",
    ):
        self.sync_interval_seconds = sync_interval_seconds
        self.enable_timers = enable_timers
        self.enable_histograms = enable_histograms
        self.auto_start_server = auto_start_server
        self.metric_prefix = metric_prefix
class HTTPMetricsBridge:
    """
    Bridges v8 Observability Metrics Collection → v14 HTTP Metrics Server
    
    OPT-IN: Must call enable() explicitly
    Zero overhead when disabled: No background threads, no processing
    ADD-ONLY: Works with existing v8 and v14 modules without modification
    
    Usage:
        from neural_shield.observability_v14_http_metrics_bridge import metrics_bridge
        metrics_bridge.enable()  # OPT-IN
        
        # All v8 metrics now automatically appear on HTTP /metrics endpoint
    """
    
    def __init__(self):
        self._state = BridgeState.DISABLED
        self._config = BridgeConfig()
        self._lock = threading.RLock()
        self._sync_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._v8_registry: Optional[Any] = None  # Lazy loaded
        self._v14_server_ref: Optional[Any] = None  # Lazy loaded
        self._sync_count = 0
        self._error_count = 0
        self._last_sync_time: Optional[float] = None
        
    def _lazy_load_v8_registry(self) -> Optional[Any]:
        """Lazy load v8 registry to avoid import cycles"""
        if self._v8_registry is None:
            try:
                from .observability_metrics_collection_v8_2026_june import _global_registry
                self._v8_registry = _global_registry
            except (ImportError, AttributeError):
                pass
        return self._v8_registry
    
    def _lazy_load_v14_server(self) -> Optional[Any]:
        """Lazy load v14 server to avoid import cycles"""
        if self._v14_server_ref is None:
            try:
                from .feature_expansion_http_metrics_server_v14_2026_june import get_metrics_server
                self._v14_server_ref = get_metrics_server
            except (ImportError, AttributeError):
                pass
        return self._v14_server_ref() if self._v14_server_ref else None
    
    def _sanitize_metric_name(self, name: str) -> str:
        """Convert metric name to Prometheus-compatible format"""
        import re
        # Replace invalid chars with underscore
        sanitized = re.sub(r'[^a-zA-Z0-9_:]', '_', name)
        # Ensure starts with letter or underscore
        if sanitized and not sanitized[0].isalpha() and sanitized[0] != '_':
            sanitized = '_' + sanitized
        return self._config.metric_prefix + sanitized
    
    def _convert_labels_to_prometheus(self, labels: Dict[str, str]) -> Dict[str, str]:
        """Convert labels to Prometheus-compatible format"""
        import re
        result = {}
        for k, v in labels.items():
            clean_key = re.sub(r'[^a-zA-Z0-9_]', '_', k)
            if clean_key and not clean_key[0].isalpha() and clean_key[0] != '_':
                clean_key = 'label_' + clean_key
            # Escape quotes in values
            clean_value = str(v).replace('"', '\\"')
            result[clean_key] = clean_value
        return result
    
    def _sync_once(self) -> None:
        """Perform one sync from v8 → v14"""
        v8_reg = self._lazy_load_v8_registry()
        v14_server = self._lazy_load_v14_server()
        
        if v8_reg is None or not v8_reg.is_enabled:
            return
            
        if v14_server is None or not v14_server.is_running():
            # Auto-start if configured
            if self._config.auto_start_server:
                try:
                    from .feature_expansion_http_metrics_server_v14_2026_june import start_metrics_server
                    start_metrics_server()
                    v14_server = self._lazy_load_v14_server()
                except Exception:
                    pass
            if v14_server is None or not v14_server.is_running():
                return
        
        registry = v14_server.metrics_registry
        if registry is None:
            return
        
        try:
            # Export v8 metrics
            export = v8_reg.export_dict()
            if export.get("status") != "enabled":
                return
                
            metrics = export.get("metrics", {})
            
            # Forward Counters
            for counter in metrics.get("counters", []):
                name = self._sanitize_metric_name(counter.get("name", "unknown"))
                value = counter.get("value", 0)
                labels = self._convert_labels_to_prometheus(counter.get("labels", {}))
                registry.counter_inc(name, float(value), labels)
            
            # Forward Gauges
            for gauge in metrics.get("gauges", []):
                name = self._sanitize_metric_name(gauge.get("name", "unknown"))
                value = gauge.get("value", 0.0)
                labels = self._convert_labels_to_prometheus(gauge.get("labels", {}))
                registry.gauge_set(name, float(value), labels)
            
            # Forward Timers (as summary metrics)
            if self._config.enable_timers:
                for timer in metrics.get("timers", []):
                    base_name = self._sanitize_metric_name(timer.get("name", "unknown"))
                    labels = self._convert_labels_to_prometheus(timer.get("labels", {}))
                    
                    # Timer count
                    registry.gauge_set(f"{base_name}_count", float(timer.get("count", 0)), labels)
                    # Timer avg duration
                    registry.gauge_set(f"{base_name}_avg_seconds", float(timer.get("avg_seconds", 0)), labels)
                    # Timer p95
                    registry.gauge_set(f"{base_name}_p95_seconds", float(timer.get("p95_seconds", 0)), labels)
            
            # Forward Histograms
            if self._config.enable_histograms:
                for hist in metrics.get("histograms", []):
                    base_name = self._sanitize_metric_name(hist.get("name", "unknown"))
                    labels = self._convert_labels_to_prometheus(hist.get("labels", {}))
                    
                    registry.gauge_set(f"{base_name}_count", float(hist.get("count", 0)), labels)
                    registry.gauge_set(f"{base_name}_sum", float(hist.get("sum", 0)), labels)
                    registry.gauge_set(f"{base_name}_avg", float(hist.get("avg", 0)), labels)
            
            self._sync_count += 1
            self._last_sync_time = time.time()
            
        except Exception:
            self._error_count += 1
            # Fail silently - graceful degradation
    
    def _sync_loop(self) -> None:
        """Background sync loop"""
        while not self._stop_event.is_set():
            with self._lock:
                if self._state == BridgeState.ENABLED:
                    self._state = BridgeState.SYNCING
                    try:
                        self._sync_once()
                    finally:
                        self._state = BridgeState.ENABLED
            # Wait for interval or stop
            self._stop_event.wait(self._config.sync_interval_seconds)
    
    def enable(self, config: Optional[BridgeConfig] = None) -> None:
        """
        Enable the metrics bridge - OPT-IN REQUIRED
        
        Starts background thread that syncs v8 metrics → v14 HTTP server
        Zero overhead until this is called
        """
        with self._lock:
            if self._state != BridgeState.DISABLED:
                return
                
            if config:
                self._config = config
                
            self._state = BridgeState.ENABLED
            self._stop_event.clear()
            self._sync_thread = threading.Thread(
                target=self._sync_loop,
                daemon=True,
                name="MetricsBridgeSync"
            )
            self._sync_thread.start()
    
    def disable(self) -> None:
        """Disable the bridge and stop background thread"""
        with self._lock:
            if self._state == BridgeState.DISABLED:
                return
                
            self._stop_event.set()
            if self._sync_thread:
                self._sync_thread.join(timeout=2.0)
                self._sync_thread = None
            self._state = BridgeState.DISABLED
    
    def sync_now(self) -> None:
        """Force an immediate sync (useful for testing)"""
        with self._lock:
            self._sync_once()
    
    def get_bridge_stats(self) -> Dict[str, Any]:
        """Get bridge statistics"""
        with self._lock:
            return {
                "state": self._state.value,
                "sync_count": self._sync_count,
                "error_count": self._error_count,
                "last_sync_time": self._last_sync_time,
                "config": {
                    "sync_interval_seconds": self._config.sync_interval_seconds,
                    "enable_timers": self._config.enable_timers,
                    "enable_histograms": self._config.enable_histograms,
                    "auto_start_server": self._config.auto_start_server,
                    "metric_prefix": self._config.metric_prefix,
                },
                "v8_enabled": self._lazy_load_v8_registry() is not None and 
                              getattr(self._lazy_load_v8_registry(), 'is_enabled', False),
                "v14_running": self._lazy_load_v14_server() is not None and
                               getattr(self._lazy_load_v14_server(), 'is_running', lambda: False)(),
            }
    @property
    def is_enabled(self) -> bool:
        return self._state == BridgeState.ENABLED or self._state == BridgeState.SYNCING
# ============================================================================
# GLOBAL INSTANCE - Single bridge for entire application
# ============================================================================
metrics_bridge = HTTPMetricsBridge()
# Convenience exports
enable = metrics_bridge.enable
disable = metrics_bridge.disable
sync_now = metrics_bridge.sync_now
get_stats = metrics_bridge.get_bridge_stats
# ============================================================================
# MODULE METADATA
# ============================================================================
MODULE_VERSION = "v14"
MODULE_NAME = "Observability HTTP Metrics Bridge"
DIMENSION = "D - Observability & Instrumentation"
COMPATIBLE_WITH = ["Observability v8+", "HTTP Metrics Server v14+"]
ADD_ONLY_COMPLIANT = True
PRODUCTION_READY = True
OPT_IN_REQUIRED = True
BACKWARD_COMPATIBLE = True
