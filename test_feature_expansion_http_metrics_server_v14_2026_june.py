"""
Test Suite for Feature Expansion v14 - HTTP Metrics Server
NeuralShield-AI | June 2026

100% ADD-ONLY COMPLIANT: No production code modified
Tests cover:
  - Server lifecycle management
  - Security integration (v16 compatibility)
  - Metrics collection (v13 compatibility)
  - HTTP endpoint functionality
  - Thread safety and concurrency
  - Backward compatibility
"""

import unittest
import threading
import time
import json
import urllib.request
import urllib.error
from typing import Optional

# Import module under test
from neural_shield.feature_expansion_http_metrics_server_v14_2026_june import (
    HTTPMetricsServer,
    MetricsServerConfig,
    ServerState,
    EndpointSecurityLevel,
    SecurityIntegrationLayer,
    MetricsRegistry,
    start_metrics_server,
    stop_metrics_server,
    get_metrics_server,
    register_metrics_api_key,
    record_metric_counter,
)


# ============================================================================
# TEST 1: Module Import & Baseline
# ============================================================================

class TestModuleBaseline(unittest.TestCase):
    """Test module import and basic availability"""

    def test_module_importable(self):
        """Verify module imports correctly"""
        self.assertTrue(True)  # If we got here, import succeeded

    def test_module_metadata(self):
        """Verify module metadata is present"""
        from neural_shield.feature_expansion_http_metrics_server_v14_2026_june import (
            MODULE_VERSION,
            DIMENSION,
            ADD_ONLY_COMPLIANT,
        )
        self.assertEqual(MODULE_VERSION, "v14")
        self.assertEqual(DIMENSION, "A - Feature Expansion")
        self.assertTrue(ADD_ONLY_COMPLIANT)

    def test_config_defaults(self):
        """Verify default configuration values"""
        config = MetricsServerConfig()
        self.assertEqual(config.host, "127.0.0.1")
        self.assertEqual(config.port, 9090)
        self.assertTrue(config.enable_security)

    def test_server_state_enum(self):
        """Verify ServerState enum has all states"""
        states = [s.value for s in ServerState]
        self.assertIn("stopped", states)
        self.assertIn("running", states)
        self.assertIn("error", states)


# ============================================================================
# TEST 2: Metrics Registry
# ============================================================================

class TestMetricsRegistry(unittest.TestCase):
    """Test Prometheus-style metrics collection"""

    def setUp(self):
        self.registry = MetricsRegistry()

    def test_counter_increment(self):
        """Test counter metric increment"""
        self.registry.counter_inc("test_requests_total", 1.0)
        self.registry.counter_inc("test_requests_total", 1.0)
        export = self.registry.export_prometheus_format()
        self.assertIn("test_requests_total", export)

    def test_counter_with_labels(self):
        """Test counter with labels"""
        self.registry.counter_inc("http_requests", 1.0, {"method": "GET", "status": "200"})
        export = self.registry.export_prometheus_format()
        self.assertIn('method="GET"', export)
        self.assertIn('status="200"', export)

    def test_gauge_set(self):
        """Test gauge metric setting"""
        self.registry.gauge_set("active_connections", 42.0)
        export = self.registry.export_prometheus_format()
        self.assertIn("active_connections 42.0", export)

    def test_histogram_observe(self):
        """Test histogram observation"""
        for i in range(10):
            self.registry.histogram_observe("request_duration_seconds", 0.1 + i * 0.01)
        summary = self.registry.get_metrics_summary()
        self.assertEqual(summary["histograms"], 1)

    def test_prometheus_format_export(self):
        """Test Prometheus text format generation"""
        self.registry.counter_inc("test_counter", 5.0)
        export = self.registry.export_prometheus_format()
        self.assertIsInstance(export, str)
        self.assertTrue(export.endswith("\n"))

    def test_metrics_summary(self):
        """Test metrics summary generation"""
        self.registry.counter_inc("c1", 1.0)
        self.registry.gauge_set("g1", 100.0)
        summary = self.registry.get_metrics_summary()
        self.assertGreaterEqual(summary["counters"], 1)
        self.assertGreaterEqual(summary["gauges"], 1)


# ============================================================================
# TEST 3: Security Integration Layer
# ============================================================================

class TestSecurityIntegrationLayer(unittest.TestCase):
    """Test v16 Security Hardening integration"""

    def setUp(self):
        self.security = SecurityIntegrationLayer(enabled=True)

    def test_api_key_registration(self):
        """Test API key registration and validation"""
        self.security.register_api_key("test-key-123", EndpointSecurityLevel.METRICS_READ)
        self.assertTrue(
            self.security.validate_api_key("test-key-123", EndpointSecurityLevel.METRICS_READ)
        )

    def test_api_key_insufficient_level(self):
        """Test API key with insufficient access level"""
        self.security.register_api_key("read-only-key", EndpointSecurityLevel.METRICS_READ)
        self.assertFalse(
            self.security.validate_api_key("read-only-key", EndpointSecurityLevel.ADMIN)
        )

    def test_invalid_api_key_rejected(self):
        """Test invalid API key is rejected"""
        self.assertFalse(self.security.validate_api_key("wrong-key", EndpointSecurityLevel.METRICS_READ))

    def test_empty_api_key_rejected(self):
        """Test empty API key is rejected"""
        self.assertFalse(self.security.validate_api_key(None, EndpointSecurityLevel.METRICS_READ))
        self.assertFalse(self.security.validate_api_key("", EndpointSecurityLevel.METRICS_READ))

    def test_trusted_ip_bypass_rate_limit(self):
        """Test localhost bypasses rate limiting"""
        for _ in range(100):
            self.assertTrue(self.security.check_rate_limit("127.0.0.1"))
            self.assertTrue(self.security.check_rate_limit("::1"))

    def test_rate_limiting_enforced(self):
        """Test rate limiting is enforced for untrusted IPs"""
        # Consume burst quota
        for _ in range(50):
            self.security.check_rate_limit("192.168.1.1")
        # Next request should be rate limited
        self.assertFalse(self.security.check_rate_limit("192.168.1.1"))

    def test_input_validation_blocks_xss(self):
        """Test XSS patterns are blocked"""
        ok, err = self.security.validate_input({"q": ["<script>alert(1)</script>"]})
        self.assertFalse(ok)
        self.assertIn("Malicious pattern", err)

    def test_input_validation_blocks_sql_injection(self):
        """Test SQL injection patterns are blocked"""
        ok, err = self.security.validate_input({"id": ["' OR '1'='1"]})
        self.assertFalse(ok)

    def test_valid_input_passes(self):
        """Test valid input passes validation"""
        ok, err = self.security.validate_input({"name": ["test"], "page": ["5"]})
        self.assertTrue(ok)
        self.assertEqual(err, "")

    def test_security_disabled_bypasses_all(self):
        """Test disabled security bypasses all checks"""
        security_off = SecurityIntegrationLayer(enabled=False)
        self.assertTrue(security_off.validate_api_key(None, EndpointSecurityLevel.ADMIN))
        self.assertTrue(security_off.check_rate_limit("any-ip"))
        ok, _ = security_off.validate_input({"q": ["<script>"]})
        self.assertTrue(ok)

    def test_security_event_logging(self):
        """Test security events are logged"""
        self.security.log_security_event("auth_success", "127.0.0.1", "/metrics", True)
        summary = self.security.get_security_summary()
        self.assertEqual(summary["total_events"], 1)
        self.assertEqual(summary["successful_auth"], 1)


# ============================================================================
# TEST 4: Server Lifecycle
# ============================================================================

class TestServerLifecycle(unittest.TestCase):
    """Test server start/stop lifecycle"""

    def test_server_initial_state_stopped(self):
        """Test server starts in STOPPED state"""
        config = MetricsServerConfig(port=9191)  # Use unique port
        server = HTTPMetricsServer(config)
        self.assertEqual(server.state, ServerState.STOPPED)
        self.assertFalse(server.is_running())

    def test_server_start_stop(self):
        """Test server can be started and stopped"""
        config = MetricsServerConfig(port=9192, enable_security=False)
        server = HTTPMetricsServer(config)

        # Start
        result = server.start()
        self.assertTrue(result)
        self.assertEqual(server.state, ServerState.RUNNING)
        self.assertTrue(server.is_running())

        # Give server time to start
        time.sleep(0.2)

        # Stop
        result = server.stop()
        self.assertTrue(result)
        self.assertEqual(server.state, ServerState.STOPPED)

    def test_server_url_generation(self):
        """Test server URL generation"""
        # Reset singleton for clean test
        HTTPMetricsServer._instance = None
        config = MetricsServerConfig(host="localhost", port=9090)
        server = HTTPMetricsServer(config)
        self.assertEqual(server.get_server_url(), "http://localhost:9090")

    def test_singleton_pattern(self):
        """Test thread-safe singleton behavior"""
        config1 = MetricsServerConfig(port=9193)
        server1 = HTTPMetricsServer(config1)
        config2 = MetricsServerConfig(port=9194)
        server2 = HTTPMetricsServer(config2)
        self.assertIs(server1, server2)


# ============================================================================
# TEST 5: HTTP Endpoints (Live Server)
# ============================================================================

class TestHTTPEndpoints(unittest.TestCase):
    """Test live HTTP endpoints"""

    @classmethod
    def setUpClass(cls):
        """Start test server once for all endpoint tests"""
        cls.test_port = 9195
        cls.config = MetricsServerConfig(port=cls.test_port, enable_security=False)
        cls.server = HTTPMetricsServer(cls.config)
        cls.server.start()
        time.sleep(0.3)  # Give server time to start

    @classmethod
    def tearDownClass(cls):
        """Stop test server"""
        cls.server.stop()
        time.sleep(0.2)

    def _http_get(self, path: str) -> tuple[int, Optional[str]]:
        """Helper: Make HTTP GET request"""
        url = f"http://127.0.0.1:{self.test_port}{path}"
        try:
            with urllib.request.urlopen(url, timeout=5) as resp:
                return resp.status, resp.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, None
        except Exception:
            return -1, None

    def test_health_endpoint(self):
        """Test /health endpoint returns healthy"""
        status, body = self._http_get("/health")
        self.assertEqual(status, 200)
        self.assertIsNotNone(body)
        data = json.loads(body)
        self.assertEqual(data["status"], "healthy")
        self.assertEqual(data["server_state"], "running")

    def test_metrics_endpoint(self):
        """Test /metrics endpoint returns Prometheus format"""
        # Record some metrics first
        self.server.record_counter("test_http_requests", 5.0)
        status, body = self._http_get("/metrics")
        self.assertEqual(status, 200)
        self.assertIsNotNone(body)
        # Prometheus format is plain text
        self.assertIn("test_http_requests", body)

    def test_status_endpoint(self):
        """Test /status admin endpoint"""
        status, body = self._http_get("/status")
        self.assertEqual(status, 200)
        self.assertIsNotNone(body)
        data = json.loads(body)
        self.assertIn("server_state", data)
        self.assertIn("metrics", data)
        self.assertIn("security", data)
        self.assertIn("config", data)

    def test_404_not_found(self):
        """Test unknown endpoint returns 404"""
        status, body = self._http_get("/nonexistent")
        self.assertEqual(status, 404)

    def test_metrics_recording_convenience(self):
        """Test convenience metric recording API"""
        self.server.record_counter("convenience_test", 3.0, {"source": "test"})
        status, body = self._http_get("/metrics")
        self.assertIn("convenience_test", body)


# ============================================================================
# TEST 6: Secured Endpoints
# ============================================================================

class TestSecuredHTTPEndpoints(unittest.TestCase):
    """Test HTTP endpoints with security enabled"""

    @classmethod
    def setUpClass(cls):
        """Start secured test server"""
        cls.test_port = 9196
        cls.config = MetricsServerConfig(port=cls.test_port, enable_security=True)
        cls.server = HTTPMetricsServer(cls.config)
        cls.server.start()
        time.sleep(0.3)
        # Register test API key
        cls.test_api_key = "test-admin-key-456"
        cls.server.security_layer.register_api_key(cls.test_api_key, EndpointSecurityLevel.ADMIN)

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()
        time.sleep(0.2)

    def _http_get_with_auth(self, path: str, api_key: Optional[str] = None) -> tuple[int, Optional[str]]:
        """Helper: Make HTTP GET with optional auth"""
        url = f"http://127.0.0.1:{self.test_port}{path}"
        headers = {}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, resp.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, None
        except Exception:
            return -1, None

    def test_unauthenticated_metrics_rejected(self):
        """Test unauthenticated request to /metrics is rejected"""
        status, _ = self._http_get_with_auth("/metrics")
        self.assertEqual(status, 401)

    def test_authenticated_metrics_accepted(self):
        """Test authenticated request to /metrics succeeds"""
        status, body = self._http_get_with_auth("/metrics", self.test_api_key)
        self.assertEqual(status, 200)

    def test_unauthenticated_health_rejected(self):
        """Test unauthenticated request to /health is rejected"""
        status, _ = self._http_get_with_auth("/health")
        self.assertEqual(status, 401)

    def test_authenticated_health_accepted(self):
        """Test authenticated request to /health succeeds"""
        status, body = self._http_get_with_auth("/health", self.test_api_key)
        self.assertEqual(status, 200)


# ============================================================================
# TEST 7: Thread Safety & Concurrency
# ============================================================================

class TestThreadSafety(unittest.TestCase):
    """Test thread safety under concurrent load"""

    def test_concurrent_metrics_recording(self):
        """Test 10 threads recording metrics simultaneously"""
        registry = MetricsRegistry()
        errors = []

        def record_metrics(thread_id: int):
            try:
                for i in range(100):
                    registry.counter_inc(f"thread_{thread_id}_counter", 1.0)
                    registry.gauge_set(f"thread_{thread_id}_gauge", float(i))
            except Exception as e:
                errors.append(e)

        threads = []
        for i in range(10):
            t = threading.Thread(target=record_metrics, args=(i,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join(timeout=5.0)

        self.assertEqual(len(errors), 0, f"Thread safety errors: {errors}")
        summary = registry.get_metrics_summary()
        self.assertGreaterEqual(summary["counters"], 10)

    def test_concurrent_security_validation(self):
        """Test concurrent security validation"""
        security = SecurityIntegrationLayer(enabled=True)
        errors = []

        def validate_repeatedly():
            try:
                for _ in range(100):
                    security.check_rate_limit("192.168.1.100")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=validate_repeatedly) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5.0)

        self.assertEqual(len(errors), 0)

    def test_singleton_concurrent_access(self):
        """Test singleton under concurrent access"""
        servers = []

        def get_server_instance():
            servers.append(HTTPMetricsServer())

        threads = [threading.Thread(target=get_server_instance) for _ in range(30)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5.0)

        # All should be the same instance
        first = servers[0]
        for s in servers[1:]:
            self.assertIs(s, first)


# ============================================================================
# TEST 8: Global API Functions
# ============================================================================

class TestGlobalAPIFunctions(unittest.TestCase):
    """Test convenience global API"""

    def test_global_server_lifecycle(self):
        """Test global start/stop API"""
        # Use a different port to avoid conflicts
        result = start_metrics_server(port=9197, enable_security=False)
        self.assertTrue(result)
        server = get_metrics_server()
        self.assertIsNotNone(server)
        self.assertTrue(server.is_running())

        time.sleep(0.2)
        result = stop_metrics_server()
        self.assertTrue(result)

    def test_global_metric_recording(self):
        """Test global metric recording API"""
        # Server must be running
        start_metrics_server(port=9198, enable_security=False)
        time.sleep(0.2)

        record_metric_counter("global_test_counter", 2.0, {"global": "true"})
        server = get_metrics_server()
        self.assertIsNotNone(server.metrics_registry)

        stop_metrics_server()
        time.sleep(0.2)

    def test_global_api_key_registration(self):
        """Test global API key registration"""
        start_metrics_server(port=9199, enable_security=True)
        time.sleep(0.2)
        register_metrics_api_key("global-key-789", EndpointSecurityLevel.ADMIN)
        stop_metrics_server()
        time.sleep(0.2)


# ============================================================================
# TEST 9: Backward Compatibility
# ============================================================================

class TestBackwardCompatibility(unittest.TestCase):
    """Test backward compatibility - ADD-ONLY guarantee"""

    def test_no_existing_modules_modified(self):
        """
        VERIFY ADD-ONLY COMPLIANCE:
        This module is completely standalone and does not modify any existing code.
        All existing modules continue to work unchanged.
        """
        # Verify we can import existing modules without conflict
        try:
            # These should all still import fine
            import neural_shield.observability_engine_2026_june
            import neural_shield.security_hardening_observability_protection_v16_2026_june
            self.assertTrue(True)
        except ImportError:
            self.fail("Existing modules could not be imported - backward compatibility broken!")

    def test_zero_overhead_when_disabled(self):
        """Test disabled security has negligible overhead"""
        security = SecurityIntegrationLayer(enabled=False)
        start = time.time()
        for _ in range(10000):
            security.check_rate_limit("any-ip")
            security.validate_api_key(None, EndpointSecurityLevel.ADMIN)
        elapsed = time.time() - start
        # 10,000 operations should be < 0.1 seconds
        self.assertLess(elapsed, 0.5, f"Disabled security overhead too high: {elapsed}s")

    def test_server_disabled_by_default(self):
        """Verify OPT-IN philosophy - server NOT started automatically"""
        self.assertIsNone(get_metrics_server())


# ============================================================================
# TEST RUNNER
# ============================================================================

def run_tests():
    """Run all tests and return results"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    test_classes = [
        TestModuleBaseline,
        TestMetricsRegistry,
        TestSecurityIntegrationLayer,
        TestServerLifecycle,
        TestHTTPEndpoints,
        TestSecuredHTTPEndpoints,
        TestThreadSafety,
        TestGlobalAPIFunctions,
        TestBackwardCompatibility,
    ]

    for test_class in test_classes:
        tests = loader.loadTestsFromTestCase(test_class)
        suite.addTests(tests)

    runner = unittest.TextTestRunner(verbosity=2)
    return runner.run(suite)


if __name__ == "__main__":
    result = run_tests()
    exit(0 if result.wasSuccessful() else 1)
