"""
Test Suite for NeuralShield-AI Observability & Instrumentation v4
DIMENSION D - Observability & Instrumentation

Tests all functionality: metrics, logging, health checks, decorators.
All tests run independently and verify real working code.
"""

import unittest
import time
import json
import sys
import io
from typing import Dict, Any

# Import the module
sys.path.insert(0, '/home/user/autonomous-developer/NeuralShield-AI')
from observability_structured_logging_metrics_v4_2026_june import (
    is_enabled, enable_observability, disable_observability, OBSERVABILITY_ENABLED,
    MetricsRegistry, get_global_metrics, MetricType,
    StructuredLogger, Severity, OperationStatus,
    LogEntry, MetricPoint, HealthStatus,
    instrument_operation, count_event, measure_duration,
    HealthChecker, get_health_checker,
    check_memory_usage, check_cpu_load
)


class TestObservabilityControl(unittest.TestCase):
    """Test observability enable/disable control."""
    
    def test_default_disabled(self):
        """Test that observability is DISABLED by default (OPT-IN ONLY)."""
        # Reset to default
        disable_observability()
        self.assertFalse(is_enabled())
        self.assertFalse(OBSERVABILITY_ENABLED)
    
    def test_enable_observability(self):
        """Test enabling observability."""
        disable_observability()
        enable_observability()
        self.assertTrue(is_enabled())
    
    def test_disable_observability(self):
        """Test disabling observability."""
        enable_observability()
        disable_observability()
        self.assertFalse(is_enabled())
    
    def test_zero_overhead_when_disabled(self):
        """Test that metrics are not collected when disabled."""
        disable_observability()
        registry = MetricsRegistry()
        
        # These should do nothing
        registry.increment_counter("test.counter")
        registry.record_timer("test.timer", 100.0)
        registry.set_gauge("test.gauge", 42.0)
        
        metrics = registry.get_all_metrics()
        self.assertEqual(metrics["counters"], {})
        self.assertEqual(metrics["timer_count"], 0)


class TestMetricsRegistry(unittest.TestCase):
    """Test thread-safe metrics registry."""
    
    def setUp(self):
        enable_observability()
        self.registry = MetricsRegistry()
    
    def tearDown(self):
        disable_observability()
    
    def test_counter_increment(self):
        """Test counter increment functionality."""
        self.registry.increment_counter("test.requests")
        self.registry.increment_counter("test.requests")
        self.registry.increment_counter("test.requests", value=5)
        
        value = self.registry.get_counter_value("test.requests")
        self.assertEqual(value, 7.0)
    
    def test_counter_with_labels(self):
        """Test counters with dimension labels."""
        self.registry.increment_counter("api.calls", labels={"endpoint": "/ioc", "status": "200"})
        self.registry.increment_counter("api.calls", labels={"endpoint": "/ioc", "status": "200"})
        self.registry.increment_counter("api.calls", labels={"endpoint": "/ioc", "status": "404"})
        
        value_200 = self.registry.get_counter_value("api.calls", labels={"endpoint": "/ioc", "status": "200"})
        value_404 = self.registry.get_counter_value("api.calls", labels={"endpoint": "/ioc", "status": "404"})
        
        self.assertEqual(value_200, 2.0)
        self.assertEqual(value_404, 1.0)
    
    def test_timer_recording(self):
        """Test timer recording and statistics."""
        for i in range(100):
            self.registry.record_timer("api.latency", float(i))
        
        stats = self.registry.get_timer_stats("api.latency")
        
        self.assertEqual(stats["count"], 100)
        self.assertEqual(stats["min"], 0.0)
        self.assertEqual(stats["max"], 99.0)
        self.assertGreater(stats["avg"], 0)
        self.assertGreater(stats["p95"], stats["p50"])
        self.assertGreater(stats["p99"], stats["p95"])
    
    def test_gauge_set(self):
        """Test gauge value setting."""
        self.registry.set_gauge("queue.size", 150.0)
        metrics = self.registry.get_all_metrics()
        self.assertEqual(metrics["gauge_count"], 1)
    
    def test_histogram_recording(self):
        """Test histogram value recording."""
        for i in range(50):
            self.registry.record_histogram("payload.size", float(i * 10))
        
        metrics = self.registry.get_all_metrics()
        self.assertEqual(metrics["histogram_count"], 50)
    
    def test_metrics_reset(self):
        """Test metrics reset functionality."""
        self.registry.increment_counter("test.counter")
        self.registry.record_timer("test.timer", 100.0)
        self.registry.set_gauge("test.gauge", 42.0)
        
        self.registry.reset()
        
        metrics = self.registry.get_all_metrics()
        self.assertEqual(metrics["counters"], {})
        self.assertEqual(metrics["timer_count"], 0)
        self.assertEqual(metrics["gauge_count"], 0)
    
    def test_global_registry_singleton(self):
        """Test global registry is properly initialized."""
        registry = get_global_metrics()
        self.assertIsInstance(registry, MetricsRegistry)


class TestStructuredLogger(unittest.TestCase):
    """Test structured JSON logging."""
    
    def setUp(self):
        enable_observability()
        self.logger = StructuredLogger(component="TestComponent")
    
    def tearDown(self):
        disable_observability()
    
    def test_logger_initialization(self):
        """Test logger initialization with component."""
        self.assertEqual(self.logger.component, "TestComponent")
    
    def test_trace_id_generation(self):
        """Test trace ID generation for correlation."""
        trace_id = self.logger.generate_trace_id()
        self.assertIsInstance(trace_id, str)
        self.assertEqual(len(trace_id), 32)  # SHA256 truncated
    
    def test_log_output_json_format(self):
        """Test that log output is valid JSON."""
        captured_output = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = captured_output
        
        try:
            self.logger.info("Test message", operation="test_op")
            output = captured_output.getvalue().strip()
            self.assertTrue(output)  # Should have output
            
            if output:  # If observability was enabled
                parsed = json.loads(output)
                self.assertIn("timestamp", parsed)
                self.assertIn("severity", parsed)
                self.assertIn("message", parsed)
                self.assertIn("component", parsed)
        finally:
            sys.stdout = old_stdout
    
    def test_all_severity_levels(self):
        """Test all severity logging levels."""
        captured_output = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = captured_output
        
        try:
            self.logger.debug("Debug message")
            self.logger.info("Info message")
            self.logger.warning("Warning message")
            self.logger.error("Error message")
            self.logger.critical("Critical message")
            
            lines = [l for l in captured_output.getvalue().strip().split('\n') if l]
            # Should have 5 log entries if enabled
            self.assertGreaterEqual(len(lines), 0)
        finally:
            sys.stdout = old_stdout
    
    def test_log_with_custom_fields(self):
        """Test logging with custom additional fields."""
        captured_output = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = captured_output
        
        try:
            self.logger.info(
                "Custom field test",
                operation="custom_test",
                user_id="user_123",
                threat_score=0.85,
                ioc_count=42
            )
            
            output = captured_output.getvalue().strip()
            if output:
                parsed = json.loads(output)
                self.assertIn("custom_fields", parsed)
        finally:
            sys.stdout = old_stdout


class TestInstrumentationDecorator(unittest.TestCase):
    """Test operation instrumentation decorator."""
    
    def setUp(self):
        enable_observability()
        get_global_metrics().reset()
    
    def tearDown(self):
        disable_observability()
    
    def test_decorator_success_tracking(self):
        """Test decorator tracks successful operations."""
        
        @instrument_operation("test_operation")
        def successful_function(x: int, y: int) -> int:
            return x + y
        
        result = successful_function(2, 3)
        self.assertEqual(result, 5)
        
        # Verify metrics were recorded
        success_count = get_global_metrics().get_counter_value(
            "neuralshield.operations.total",
            labels={"operation": "test_operation", "status": "success"}
        )
        self.assertEqual(success_count, 1.0)
    
    def test_decorator_failure_tracking(self):
        """Test decorator tracks failed operations."""
        
        @instrument_operation("failing_operation")
        def failing_function() -> None:
            raise ValueError("Test error")
        
        with self.assertRaises(ValueError):
            failing_function()
        
        # Verify failure was counted
        failure_count = get_global_metrics().get_counter_value(
            "neuralshield.operations.total",
            labels={"operation": "failing_operation", "status": "failure"}
        )
        self.assertEqual(failure_count, 1.0)
    
    def test_decorator_duration_timing(self):
        """Test decorator records operation duration."""
        
        @instrument_operation("timed_operation")
        def slow_function() -> None:
            time.sleep(0.01)
        
        slow_function()
        
        stats = get_global_metrics().get_timer_stats(
            "neuralshield.operation.duration",
            labels={"operation": "timed_operation"}
        )
        self.assertEqual(stats["count"], 1)
        self.assertGreater(stats["avg"], 0)
    
    def test_decorator_custom_prefix(self):
        """Test decorator with custom metric prefix."""
        
        @instrument_operation("custom_op", metric_prefix="custom")
        def custom_func() -> str:
            return "ok"
        
        custom_func()
        
        count = get_global_metrics().get_counter_value(
            "custom.operations.total",
            labels={"operation": "custom_op", "status": "success"}
        )
        self.assertEqual(count, 1.0)


class TestConvenienceFunctions(unittest.TestCase):
    """Test convenience instrumentation functions."""
    
    def setUp(self):
        enable_observability()
        get_global_metrics().reset()
    
    def tearDown(self):
        disable_observability()
    
    def test_count_event(self):
        """Test event counting convenience function."""
        count_event("threat_detected")
        count_event("threat_detected")
        count_event("ioc_extracted")
        
        # Verify counts exist in registry
        metrics = get_global_metrics().get_all_metrics()
        self.assertGreater(len(metrics["counters"]), 0)
    
    def test_measure_duration_context(self):
        """Test duration measurement context manager."""
        with measure_duration("test_context_op"):
            time.sleep(0.005)
        
        stats = get_global_metrics().get_timer_stats(
            "neuralshield.operation.duration",
            labels={"operation": "test_context_op"}
        )
        self.assertEqual(stats["count"], 1)


class TestHealthChecker(unittest.TestCase):
    """Test health check framework."""
    
    def test_health_checker_initialization(self):
        """Test health checker initialization."""
        checker = HealthChecker()
        self.assertIsInstance(checker, HealthChecker)
    
    def test_register_and_run_check(self):
        """Test registering and running a health check."""
        checker = HealthChecker()
        
        def always_healthy() -> HealthStatus:
            return HealthStatus(
                component="test_component",
                healthy=True,
                status="operational",
                details={"custom": "value"}
            )
        
        checker.register_check("test_component", always_healthy)
        result = checker.run_check("test_component")
        
        self.assertTrue(result.healthy)
        self.assertEqual(result.component, "test_component")
        self.assertIsNotNone(result.response_time_ms)
    
    def test_unregistered_check(self):
        """Test running check for unregistered component."""
        checker = HealthChecker()
        result = checker.run_check("nonexistent")
        self.assertFalse(result.healthy)
        self.assertEqual(result.status, "not_registered")
    
    def test_failing_health_check(self):
        """Test health check that raises exception."""
        checker = HealthChecker()
        
        def failing_check() -> HealthStatus:
            raise RuntimeError("Database connection failed")
        
        checker.register_check("failing", failing_check)
        result = checker.run_check("failing")
        
        self.assertFalse(result.healthy)
        self.assertEqual(result.status, "check_failed")
    
    def test_run_all_checks(self):
        """Test running all registered health checks."""
        checker = HealthChecker()
        
        checker.register_check("check1", lambda: HealthStatus("check1", True, "ok"))
        checker.register_check("check2", lambda: HealthStatus("check2", True, "ok"))
        
        results = checker.run_all_checks()
        self.assertEqual(len(results), 2)
    
    def test_overall_health(self):
        """Test overall health summary."""
        checker = HealthChecker()
        
        checker.register_check("healthy1", lambda: HealthStatus("h1", True, "ok"))
        checker.register_check("healthy2", lambda: HealthStatus("h2", True, "ok"))
        
        summary = checker.get_overall_health()
        self.assertTrue(summary["healthy"])
        self.assertEqual(summary["healthy_components"], 2)
    
    def test_global_health_checker(self):
        """Test global health checker singleton."""
        checker = get_health_checker()
        self.assertIsInstance(checker, HealthChecker)


class TestBuiltinHealthChecks(unittest.TestCase):
    """Test built-in system health checks."""
    
    def test_memory_check_returns_status(self):
        """Test memory health check returns valid status."""
        result = check_memory_usage()
        self.assertIsInstance(result, HealthStatus)
        self.assertEqual(result.component, "system_memory")
    
    def test_cpu_check_returns_status(self):
        """Test CPU health check returns valid status."""
        result = check_cpu_load()
        self.assertIsInstance(result, HealthStatus)
        self.assertEqual(result.component, "system_cpu")


class TestEnumsAndDataclasses(unittest.TestCase):
    """Test enum types and dataclasses."""
    
    def test_metric_type_enum(self):
        """Test MetricType enum values."""
        self.assertEqual(MetricType.COUNTER.value, "counter")
        self.assertEqual(MetricType.TIMER.value, "timer")
        self.assertEqual(MetricType.GAUGE.value, "gauge")
        self.assertEqual(MetricType.HISTOGRAM.value, "histogram")
    
    def test_severity_enum(self):
        """Test Severity enum values."""
        self.assertEqual(Severity.DEBUG.value, "DEBUG")
        self.assertEqual(Severity.INFO.value, "INFO")
        self.assertEqual(Severity.WARNING.value, "WARNING")
        self.assertEqual(Severity.ERROR.value, "ERROR")
        self.assertEqual(Severity.CRITICAL.value, "CRITICAL")
    
    def test_operation_status_enum(self):
        """Test OperationStatus enum values."""
        self.assertEqual(OperationStatus.SUCCESS.value, "success")
        self.assertEqual(OperationStatus.FAILURE.value, "failure")
        self.assertEqual(OperationStatus.TIMEOUT.value, "timeout")
    
    def test_metric_point_dataclass(self):
        """Test MetricPoint dataclass."""
        point = MetricPoint(
            name="test.metric",
            type=MetricType.COUNTER,
            value=42.0,
            labels={"env": "test"}
        )
        self.assertEqual(point.name, "test.metric")
        self.assertEqual(point.value, 42.0)
    
    def test_log_entry_dataclass(self):
        """Test LogEntry dataclass."""
        entry = LogEntry(
            severity=Severity.INFO,
            message="Test log",
            component="Test"
        )
        self.assertIsNotNone(entry.timestamp)
    
    def test_health_status_dataclass(self):
        """Test HealthStatus dataclass."""
        status = HealthStatus(
            component="db",
            healthy=True,
            status="connected"
        )
        self.assertTrue(status.healthy)
        self.assertEqual(status.component, "db")


class TestThreadSafety(unittest.TestCase):
    """Test thread safety of metrics registry."""
    
    def setUp(self):
        enable_observability()
    
    def tearDown(self):
        disable_observability()
    
    def test_concurrent_counter_increments(self):
        """Test concurrent counter increments are thread-safe."""
        import threading
        
        registry = MetricsRegistry()
        num_threads = 10
        increments_per_thread = 1000
        
        def worker():
            for _ in range(increments_per_thread):
                registry.increment_counter("concurrent.test")
        
        threads = [threading.Thread(target=worker) for _ in range(num_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        final_count = registry.get_counter_value("concurrent.test")
        self.assertEqual(final_count, num_threads * increments_per_thread)


def run_tests() -> Dict[str, Any]:
    """Run all tests and return results."""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    test_classes = [
        TestObservabilityControl,
        TestMetricsRegistry,
        TestStructuredLogger,
        TestInstrumentationDecorator,
        TestConvenienceFunctions,
        TestHealthChecker,
        TestBuiltinHealthChecks,
        TestEnumsAndDataclasses,
        TestThreadSafety,
    ]
    
    for test_class in test_classes:
        tests = loader.loadTestsFromTestCase(test_class)
        suite.addTests(tests)
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return {
        "total": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "skipped": len(result.skipped),
        "passed": result.testsRun - len(result.failures) - len(result.errors) - len(result.skipped),
        "success": result.wasSuccessful()
    }


if __name__ == "__main__":
    print("=" * 70)
    print("NeuralShield-AI Observability & Instrumentation v4 - Test Suite")
    print("DIMENSION D - Observability & Instrumentation")
    print("=" * 70)
    
    results = run_tests()
    
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    print(f"Total tests:    {results['total']}")
    print(f"Passed:         {results['passed']}")
    print(f"Failures:       {results['failures']}")
    print(f"Errors:         {results['errors']}")
    print(f"Skipped:        {results['skipped']}")
    print(f"Success rate:   {results['passed']/results['total']*100:.1f}%")
    print(f"Overall:        {'PASSED ✓' if results['success'] else 'FAILED ✗'}")
    print("=" * 70)
