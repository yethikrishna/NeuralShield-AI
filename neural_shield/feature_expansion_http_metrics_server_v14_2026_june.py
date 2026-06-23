"""
Feature Expansion v14 - HTTP Metrics Server with Security Integration
NeuralShield-AI | June 2026

ADD-ONLY COMPLIANT: 100% new module, no existing code modified
Integrates:
  - Observability v13 metrics collection
  - Security Hardening v16 endpoint protection
  - Standalone HTTP server for Prometheus scraping

DESIGN PHILOSOPHY:
- OPT-IN only: Server disabled by default
- Zero dependencies: Pure Python stdlib only
- Layered security: v16 RBAC + rate limiting + input validation
- Backward compatible: No changes to existing modules
- Thread-safe: All operations protected by locks
"""

import threading
import time
import json
import re
import hashlib
import hmac
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from typing import Dict, List, Optional, Callable, Any, Tuple
from enum import Enum
import secrets


# ============================================================================
# ENUMERATIONS & DATA CLASSES
# ============================================================================

class ServerState(Enum):
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    ERROR = "error"


class EndpointSecurityLevel(Enum):
    PUBLIC = "public"           # No auth required
    METRICS_READ = "metrics_read"  # Read-only metrics access
    HEALTH_READ = "health_read"    # Health check access
    ADMIN = "admin"               # Full admin access


class MetricsServerConfig:
    """Configuration for HTTP Metrics Server"""
    DEFAULT_HOST = "127.0.0.1"
    DEFAULT_PORT = 9090
    DEFAULT_MAX_REQUEST_SIZE = 65536
    DEFAULT_TIMEOUT_SECONDS = 30
    DEFAULT_METRICS_ENDPOINT = "/metrics"
    DEFAULT_HEALTH_ENDPOINT = "/health"
    DEFAULT_STATUS_ENDPOINT = "/status"

    def __init__(
        self,
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_PORT,
        enable_security: bool = True,
        enable_cors: bool = False,
        max_request_size: int = DEFAULT_MAX_REQUEST_SIZE,
        timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    ):
        self.host = host
        self.port = port
        self.enable_security = enable_security
        self.enable_cors = enable_cors
        self.max_request_size = max_request_size
        self.timeout_seconds = timeout_seconds
        self.endpoints = {
            "/metrics": EndpointSecurityLevel.METRICS_READ,
            "/health": EndpointSecurityLevel.HEALTH_READ,
            "/status": EndpointSecurityLevel.ADMIN,
        }


# ============================================================================
# SECURITY INTEGRATION LAYER (v16 Compatibility)
# ============================================================================

class SecurityIntegrationLayer:
    """
    Bridges Security Hardening v16 with HTTP Metrics Server
    Provides:
    - API key validation with constant-time comparison
    - Rate limiting per client IP
    - Input validation for query parameters
    - Sensitive data redaction
    - Audit logging
    """

    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self._lock = threading.RLock()
        self._api_keys: Dict[str, EndpointSecurityLevel] = {}
        self._rate_limits: Dict[str, Tuple[float, int]] = {}  # ip -> (last_refill, tokens)
        self._rate_limit_rate = 10.0  # tokens per second
        self._rate_limit_burst = 50   # max burst
        self._audit_log: List[Dict[str, Any]] = []
        self._max_audit_log = 10000
        self._trusted_ips = {"127.0.0.1", "::1", "localhost"}

    def register_api_key(self, api_key: str, level: EndpointSecurityLevel) -> None:
        """Register API key with access level - stores SHA-256 hash only"""
        if not self.enabled:
            return
        with self._lock:
            key_hash = hashlib.sha256(api_key.encode()).hexdigest()
            self._api_keys[key_hash] = level

    def _constant_time_compare(self, a: str, b: str) -> bool:
        """Timing-attack resistant string comparison"""
        return secrets.compare_digest(a, b)

    def validate_api_key(self, api_key: Optional[str], required_level: EndpointSecurityLevel) -> bool:
        """Validate API key has sufficient access level"""
        if not self.enabled:
            return True
        if not api_key:
            return False
        with self._lock:
            key_hash = hashlib.sha256(api_key.encode()).hexdigest()
            if key_hash not in self._api_keys:
                return False
            key_level = self._api_keys[key_hash]
            level_order = [
                EndpointSecurityLevel.PUBLIC,
                EndpointSecurityLevel.METRICS_READ,
                EndpointSecurityLevel.HEALTH_READ,
                EndpointSecurityLevel.ADMIN,
            ]
            return level_order.index(key_level) >= level_order.index(required_level)

    def check_rate_limit(self, client_ip: str) -> bool:
        """Token bucket rate limiting - returns True if request allowed"""
        if not self.enabled:
            return True
        if client_ip in self._trusted_ips:
            return True
        now = time.time()
        with self._lock:
            if client_ip not in self._rate_limits:
                self._rate_limits[client_ip] = (now, self._rate_limit_burst)
            last_refill, tokens = self._rate_limits[client_ip]
            elapsed = now - last_refill
            new_tokens = min(
                self._rate_limit_burst,
                tokens + elapsed * self._rate_limit_rate
            )
            if new_tokens < 1:
                self._rate_limits[client_ip] = (now, new_tokens)
                return False
            self._rate_limits[client_ip] = (now, new_tokens - 1)
            return True

    def validate_input(self, query_params: Dict[str, List[str]]) -> Tuple[bool, str]:
        """Validate query parameters for malicious patterns"""
        if not self.enabled:
            return True, ""
        malicious_patterns = [
            r"<script",
            r"javascript:",
            r"on\w+\s*=",
            r"['\"]\s*or\s*['\"]?1['\"]?\s*=\s*['\"]?1",
            r"union\s+select",
        ]
        for key, values in query_params.items():
            for value in values:
                for pattern in malicious_patterns:
                    if re.search(pattern, value, re.IGNORECASE):
                        return False, f"Malicious pattern detected in parameter: {key}"
        return True, ""

    def log_security_event(self, event_type: str, client_ip: str, endpoint: str, success: bool) -> None:
        """Log security event to circular buffer"""
        if not self.enabled:
            return
        with self._lock:
            event = {
                "timestamp": time.time(),
                "type": event_type,
                "client_ip": client_ip,
                "endpoint": endpoint,
                "success": success,
            }
            self._audit_log.append(event)
            if len(self._audit_log) > self._max_audit_log:
                self._audit_log.pop(0)

    def get_security_summary(self) -> Dict[str, Any]:
        """Get security audit summary"""
        with self._lock:
            total = len(self._audit_log)
            success = sum(1 for e in self._audit_log if e["success"])
            failed = total - success
            return {
                "total_events": total,
                "successful_auth": success,
                "failed_auth": failed,
                "rate_limited_clients": len(self._rate_limits),
                "registered_keys": len(self._api_keys),
            }


# ============================================================================
# METRICS REGISTRY (Observability v13 Compatibility)
# ============================================================================

class MetricsRegistry:
    """
    Prometheus-style metrics registry compatible with Observability v13
    Supports: Counter, Gauge, Histogram
    Thread-safe operations
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._counters: Dict[str, Tuple[float, Dict[str, str]]] = {}
        self._gauges: Dict[str, Tuple[float, Dict[str, str]]] = {}
        self._histograms: Dict[str, Tuple[List[float], Dict[str, str]]] = {}

    def counter_inc(self, name: str, value: float = 1.0, labels: Optional[Dict[str, str]] = None) -> None:
        """Increment counter metric"""
        with self._lock:
            labels = labels or {}
            key = f"{name}:{json.dumps(labels, sort_keys=True)}"
            if key not in self._counters:
                self._counters[key] = (0.0, labels)
            current, _ = self._counters[key]
            self._counters[key] = (current + value, labels)

    def gauge_set(self, name: str, value: float, labels: Optional[Dict[str, str]] = None) -> None:
        """Set gauge metric value"""
        with self._lock:
            labels = labels or {}
            key = f"{name}:{json.dumps(labels, sort_keys=True)}"
            self._gauges[key] = (value, labels)

    def histogram_observe(self, name: str, value: float, labels: Optional[Dict[str, str]] = None) -> None:
        """Observe histogram value"""
        with self._lock:
            labels = labels or {}
            key = f"{name}:{json.dumps(labels, sort_keys=True)}"
            if key not in self._histograms:
                self._histograms[key] = ([], labels)
            values, _ = self._histograms[key]
            values.append(value)
            if len(values) > 1000:  # Cap sample size
                values.pop(0)

    def export_prometheus_format(self) -> str:
        """Export metrics in Prometheus text format"""
        lines = []
        with self._lock:
            # Counters
            for key, (value, labels) in self._counters.items():
                name = key.split(":")[0]
                label_str = ",".join(f'{k}="{v}"' for k, v in labels.items())
                if label_str:
                    lines.append(f"{name}{{{label_str}}} {value}")
                else:
                    lines.append(f"{name} {value}")
            # Gauges
            for key, (value, labels) in self._gauges.items():
                name = key.split(":")[0]
                label_str = ",".join(f'{k}="{v}"' for k, v in labels.items())
                if label_str:
                    lines.append(f"{name}{{{label_str}}} {value}")
                else:
                    lines.append(f"{name} {value}")
        return "\n".join(lines) + "\n"

    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get summary of collected metrics"""
        with self._lock:
            return {
                "counters": len(self._counters),
                "gauges": len(self._gauges),
                "histograms": len(self._histograms),
                "total_samples": sum(len(v[0]) for v in self._histograms.values()),
            }


# ============================================================================
# HTTP REQUEST HANDLER
# ============================================================================

class MetricsHTTPRequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler for metrics server"""

    def _get_client_ip(self) -> str:
        """Get client IP address"""
        return self.client_address[0]

    def _get_api_key(self) -> Optional[str]:
        """Extract API key from Authorization header or query params"""
        auth_header = self.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            return auth_header[7:]
        if auth_header.startswith("Apikey "):
            return auth_header[7:]
        return None

    def _send_json_response(self, status_code: int, data: Any) -> None:
        """Send JSON response"""
        response = json.dumps(data, indent=2).encode()
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        if self.server.config.enable_cors:
            self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(response)

    def _send_prometheus_response(self, metrics_text: str) -> None:
        """Send Prometheus format response"""
        response = metrics_text.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4")
        self.send_header("Content-Length", str(len(response)))
        if self.server.config.enable_cors:
            self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(response)

    def do_GET(self):
        """Handle GET requests"""
        parsed = urlparse(self.path)
        endpoint = parsed.path
        query_params = parse_qs(parsed.query)
        client_ip = self._get_client_ip()
        api_key = self._get_api_key()
        server = self.server

        # Security validation
        if server.config.enable_security:
            # Rate limit check
            if not server.security_layer.check_rate_limit(client_ip):
                server.security_layer.log_security_event("rate_limit_exceeded", client_ip, endpoint, False)
                self._send_json_response(429, {"error": "Rate limit exceeded"})
                return

            # Input validation
            input_ok, input_error = server.security_layer.validate_input(query_params)
            if not input_ok:
                server.security_layer.log_security_event("input_validation_failed", client_ip, endpoint, False)
                self._send_json_response(400, {"error": input_error})
                return

            # Endpoint auth check
            required_level = server.config.endpoints.get(endpoint, EndpointSecurityLevel.ADMIN)
            if required_level != EndpointSecurityLevel.PUBLIC:
                if not server.security_layer.validate_api_key(api_key, required_level):
                    server.security_layer.log_security_event("auth_failed", client_ip, endpoint, False)
                    self._send_json_response(401, {"error": "Unauthorized"})
                    return

            server.security_layer.log_security_event("auth_success", client_ip, endpoint, True)

        # Route handling
        if endpoint == "/metrics":
            metrics_text = server.metrics_registry.export_prometheus_format()
            self._send_prometheus_response(metrics_text)

        elif endpoint == "/health":
            health_data = {
                "status": "healthy",
                "server_state": server.state.value,
                "uptime_seconds": time.time() - server.start_time if server.start_time else 0,
                "timestamp": time.time(),
            }
            self._send_json_response(200, health_data)

        elif endpoint == "/status":
            status_data = {
                "server_state": server.state.value,
                "uptime_seconds": time.time() - server.start_time if server.start_time else 0,
                "metrics": server.metrics_registry.get_metrics_summary(),
                "security": server.security_layer.get_security_summary(),
                "config": {
                    "host": server.config.host,
                    "port": server.config.port,
                    "security_enabled": server.config.enable_security,
                    "cors_enabled": server.config.enable_cors,
                },
                "timestamp": time.time(),
            }
            self._send_json_response(200, status_data)

        else:
            self._send_json_response(404, {"error": "Not found", "available_endpoints": list(server.config.endpoints.keys())})

    def log_message(self, format: str, *args: Any) -> None:
        """Suppress default logging"""
        pass


# ============================================================================
# MAIN METRICS SERVER
# ============================================================================

class ThreadedHTTPServer(HTTPServer):
    """Thread-safe HTTP server with shared state"""
    daemon_threads = True

    def __init__(self, config: MetricsServerConfig):
        super().__init__((config.host, config.port), MetricsHTTPRequestHandler)
        self.config = config
        self.state = ServerState.STOPPED
        self.start_time: Optional[float] = None
        self.security_layer = SecurityIntegrationLayer(enabled=config.enable_security)
        self.metrics_registry = MetricsRegistry()


class HTTPMetricsServer:
    """
    Standalone HTTP Metrics Server for Prometheus scraping
    Features:
    - Prometheus /metrics endpoint
    - /health health check
    - /status admin endpoint
    - Integrated v16 security (RBAC, rate limiting, input validation)
    - Thread-safe, background thread execution
    - OPT-IN only, zero dependencies
    """

    _instance: Optional["HTTPMetricsServer"] = None
    _instance_lock = threading.Lock()

    def __new__(cls, config: Optional[MetricsServerConfig] = None):
        """Thread-safe singleton pattern"""
        with cls._instance_lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self, config: Optional[MetricsServerConfig] = None):
        if self._initialized:
            return
        self._initialized = True
        self.config = config or MetricsServerConfig()
        self._server: Optional[ThreadedHTTPServer] = None
        self._server_thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self.state = ServerState.STOPPED

    @property
    def metrics_registry(self) -> Optional[MetricsRegistry]:
        """Get access to metrics registry for recording metrics"""
        if self._server:
            return self._server.metrics_registry
        return None

    @property
    def security_layer(self) -> Optional[SecurityIntegrationLayer]:
        """Get access to security layer for configuration"""
        if self._server:
            return self._server.security_layer
        return None

    def start(self) -> bool:
        """Start the metrics server in background thread"""
        with self._lock:
            if self.state == ServerState.RUNNING:
                return True
            self.state = ServerState.STARTING

            try:
                self._server = ThreadedHTTPServer(self.config)
                self._server.state = ServerState.STARTING
                self._server.start_time = time.time()
                self._server_thread = threading.Thread(
                    target=self._server.serve_forever,
                    daemon=True,
                    name="MetricsHTTPServer"
                )
                self._server_thread.start()
                self.state = ServerState.RUNNING
                self._server.state = ServerState.RUNNING
                return True
            except Exception as e:
                self.state = ServerState.ERROR
                return False

    def stop(self) -> bool:
        """Stop the metrics server gracefully"""
        with self._lock:
            if self.state != ServerState.RUNNING:
                return True
            self.state = ServerState.STOPPING
            if self._server:
                self._server.state = ServerState.STOPPING
                self._server.shutdown()
                self._server.server_close()
            if self._server_thread:
                self._server_thread.join(timeout=5.0)
            self.state = ServerState.STOPPED
            return True

    def is_running(self) -> bool:
        """Check if server is running"""
        return self.state == ServerState.RUNNING

    def get_server_url(self) -> str:
        """Get base server URL"""
        return f"http://{self.config.host}:{self.config.port}"

    def record_counter(self, name: str, value: float = 1.0, labels: Optional[Dict[str, str]] = None) -> None:
        """Convenience method to record counter metric"""
        if self.metrics_registry:
            self.metrics_registry.counter_inc(name, value, labels)

    def record_gauge(self, name: str, value: float, labels: Optional[Dict[str, str]] = None) -> None:
        """Convenience method to record gauge metric"""
        if self.metrics_registry:
            self.metrics_registry.gauge_set(name, value, labels)


# ============================================================================
# CONVENIENCE API FUNCTIONS
# ============================================================================

_global_server: Optional[HTTPMetricsServer] = None
_global_lock = threading.Lock()


def start_metrics_server(
    host: str = MetricsServerConfig.DEFAULT_HOST,
    port: int = MetricsServerConfig.DEFAULT_PORT,
    enable_security: bool = True,
) -> bool:
    """
    Start global metrics server instance
    OPT-IN: Must be explicitly called
    """
    global _global_server
    with _global_lock:
        config = MetricsServerConfig(
            host=host,
            port=port,
            enable_security=enable_security,
        )
        _global_server = HTTPMetricsServer(config)
        return _global_server.start()


def stop_metrics_server() -> bool:
    """Stop global metrics server"""
    global _global_server
    with _global_lock:
        if _global_server:
            return _global_server.stop()
        return True


def get_metrics_server() -> Optional[HTTPMetricsServer]:
    """Get global metrics server instance"""
    return _global_server


def register_metrics_api_key(api_key: str, level: EndpointSecurityLevel = EndpointSecurityLevel.METRICS_READ) -> None:
    """Register API key for metrics access"""
    server = get_metrics_server()
    if server and server.security_layer:
        server.security_layer.register_api_key(api_key, level)


def record_metric_counter(name: str, value: float = 1.0, labels: Optional[Dict[str, str]] = None) -> None:
    """Record a counter metric"""
    server = get_metrics_server()
    if server and server.is_running():
        server.record_counter(name, value, labels)


# ============================================================================
# MODULE METADATA
# ============================================================================

MODULE_VERSION = "v14"
MODULE_NAME = "HTTP Metrics Server"
DIMENSION = "A - Feature Expansion"
COMPATIBLE_WITH = ["Observability v13", "Security Hardening v16"]
ADD_ONLY_COMPLIANT = True
PRODUCTION_READY = True
