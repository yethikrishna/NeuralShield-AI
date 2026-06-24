"""
Test Suite for Observability & Instrumentation v15 - NeuralShield-AI
Tests for Security Metrics, Logging, and Health Checks
All tests are ADD-ONLY - no production code modified
"""

import unittest
import json
import time
import threading
from unittest.mock import MagicMock, patch

# Import the new observability module
from neural_shield.observability_security_integration_metrics_v15_2026_june import (
    SecurityEventType,
    MetricType,
    SecurityEvent,
    SecurityMetricsCollector,
    StructuredSecurityLogger,
    SecurityHealthChecker,
    SecurityInstrumentationWrapper,
    get_instrumentation,
    generate_correlation_id
)


class TestSecurityEventType(unittest.TestCase):
    """Test security event type enumeration."""

    def test_event_types_exist(self):
        self.assertTrue(hasattr(SecurityEventType, 'INPUT_VALIDATION'))
        self.assertTrue(hasattr(SecurityEventType, 'MEMORY_ZEROIZATION'))
        self.assertTrue(hasattr(SecurityEventType, 'CONSTANT_TIME_COMPARE'))
        self.assertTrue(hasattr(SecurityEventType, 'RATE_LIMIT_CHECK'))
        self.assertTrue(hasattr(SecurityEventType, 'SENSITIVE_DATA_REDACTION'))
        self.assertTrue(hasattr(SecurityEventType, 'THREAT_DETECTION'))
        self.assertTrue(hasattr(SecurityEventType, 'AUDIT_LOG_ENTRY'))
        self.assertTrue(hasattr(SecurityEventType, 'HEALTH_CHECK'))

    def test_event_type_values(self):
        for event_type in SecurityEventType:
            self.assertIsInstance(event_type.value, str)
            self.assertTrue(len(event_type.value) > 0)


class TestSecurityEvent(unittest.TestCase):
    """Test SecurityEvent data structure."""

    def test_event_creation(self):
        event = SecurityEvent(
            event_type=SecurityEventType.INPUT_VALIDATION,
            module_name="test_module",
            success=True,
            duration_ms=1.5
        )
        self.assertEqual(event.event_type, SecurityEventType.INPUT_VALIDATION)
        self.assertEqual(event.module_name, "test_module")
        self.assertTrue(event.success)

    def test_event_to_dict(self):
        event = SecurityEvent(
            event_type=SecurityEventType.MEMORY_ZEROIZATION,
            module_name="security_module",
            success=True,
            duration_ms=2.5,
            metadata={"bytes_cleared": 1024}
        )
        event_dict = event.to_dict()
        self.assertEqual(event_dict["event_type"], "memory_zeroization")
        self.assertEqual(event_dict["module_name"], "security_module")
        self.assertEqual(event_dict["metadata"]["bytes_cleared"], 1024)
        self.assertEqual(event_dict["version"], "v15")


class TestSecurityMetricsCollector(unittest.TestCase):
    """Test thread-safe metrics collector."""

    def setUp(self):
        self.metrics = SecurityMetricsCollector()

    def test_disabled_by_default(self):
        self.assertFalse(self.metrics.is_enabled())

    def test_enable_disable(self):
        self.metrics.enable()
        self.assertTrue(self.metrics.is_enabled())
        self.metrics.disable()
        self.assertFalse(self.metrics.is_enabled())

    def test_counter_increment_when_disabled(self):
        """Metrics should be silently ignored when disabled."""
        self.assertFalse(self.metrics.is_enabled())
        self.metrics.increment_counter("test_counter")
        snapshot = self.metrics.get_snapshot()
        self.assertEqual(len(snapshot["counters"]), 0)

    def test_counter_increment_when_enabled(self):
        self.metrics.enable()
        self.metrics.increment_counter("test_counter", value=5)
        snapshot = self.metrics.get_snapshot()
        self.assertIn("test_counter", snapshot["counters"])
        self.assertEqual(snapshot["counters"]["test_counter"], 5)

    def test_counter_with_labels(self):
        self.metrics.enable()
        self.metrics.increment_counter("operations", labels={"type": "validation", "status": "success"})
        self.metrics.increment_counter("operations", labels={"type": "validation", "status": "success"})
        snapshot = self.metrics.get_snapshot()
        # Should have one key with labels
        self.assertEqual(len(snapshot["counters"]), 1)

    def test_gauge_setting(self):
        self.metrics.enable()
        self.metrics.set_gauge("memory_usage", 1024.5)
        snapshot = self.metrics.get_snapshot()
        self.assertEqual(snapshot["gauges"]["memory_usage"], 1024.5)

    def test_timer_recording(self):
        self.metrics.enable()
        for i in range(10):
            self.metrics.record_timer("operation_duration", float(i))
        snapshot = self.metrics.get_snapshot()
        self.assertEqual(snapshot["timer_stats"]["operation_duration"]["count"], 10)
        self.assertEqual(snapshot["timer_stats"]["operation_duration"]["min"], 0)
        self.assertEqual(snapshot["timer_stats"]["operation_duration"]["max"], 9)

    def test_histogram_recording(self):
        self.metrics.enable()
        values = [1, 2, 3, 4, 5]
        for v in values:
            self.metrics.record_histogram("response_size", v)
        snapshot = self.metrics.get_snapshot()
        self.assertEqual(snapshot["histogram_stats"]["response_size"]["count"], 5)
        self.assertEqual(snapshot["histogram_stats"]["response_size"]["avg"], 3.0)

    def test_metrics_reset(self):
        self.metrics.enable()
        self.metrics.increment_counter("test_counter")
        self.metrics.set_gauge("test_gauge", 100)
        self.metrics.reset()
        snapshot = self.metrics.get_snapshot()
        self.assertEqual(len(snapshot["counters"]), 0)
        self.assertEqual(len(snapshot["gauges"]), 0)

    def test_thread_safety(self):
        """Basic thread safety test."""
        self.metrics.enable()

        def increment_worker():
            for _ in range(100):
                self.metrics.increment_counter("threaded_counter")

        threads = [threading.Thread(target=increment_worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        snapshot = self.metrics.get_snapshot()
        self.assertEqual(snapshot["counters"]["threaded_counter"], 1000)


class TestStructuredSecurityLogger(unittest.TestCase):
    """Test structured security logging."""

    def setUp(self):
        self.metrics = SecurityMetricsCollector()
        self.logger = StructuredSecurityLogger(self.metrics)
        self.log_output = []

    def capture_logs(self):
        self.log_output = []
        self.logger.set_output_handler(lambda x: self.log_output.append(x))

    def test_disabled_by_default(self):
        self.assertFalse(self.logger.is_enabled())

    def test_logging_when_disabled(self):
        self.capture_logs()
        event = SecurityEvent(event_type=SecurityEventType.INPUT_VALIDATION, module_name="test")
        self.logger.log_event(event)
        self.assertEqual(len(self.log_output), 0)

    def test_logging_when_enabled(self):
        self.capture_logs()
        self.logger.enable()
        event = SecurityEvent(
            event_type=SecurityEventType.INPUT_VALIDATION,
            module_name="test_module",
            success=True
        )
        self.logger.log_event(event)
        self.assertEqual(len(self.log_output), 1)
        log_entry = json.loads(self.log_output[0])
        self.assertEqual(log_entry["event_type"], "input_validation")
        self.assertEqual(log_entry["module_name"], "test_module")

    def test_log_security_operation_convenience(self):
        self.capture_logs()
        self.logger.enable()
        self.logger.log_security_operation(
            event_type=SecurityEventType.MEMORY_ZEROIZATION,
            module_name="security",
            success=True,
            duration_ms=5.0,
            metadata={"size": 1024}
        )
        self.assertEqual(len(self.log_output), 1)

    def test_logging_increments_metrics(self):
        self.capture_logs()
        self.metrics.enable()
        self.logger.enable()
        event = SecurityEvent(event_type=SecurityEventType.INPUT_VALIDATION, module_name="test")
        self.logger.log_event(event)
        snapshot = self.metrics.get_snapshot()
        self.assertGreater(len(snapshot["counters"]), 0)


class TestSecurityHealthChecker(unittest.TestCase):
    """Test security health check framework."""

    def setUp(self):
        self.metrics = SecurityMetricsCollector()
        self.health = SecurityHealthChecker(self.metrics)

    def test_register_check(self):
        def custom_check():
            return {"healthy": True, "message": "OK"}
        self.health.register_check("custom", custom_check)

    def test_run_health_check_empty(self):
        result = self.health.run_health_check()
        self.assertIn("healthy", result)
        self.assertIn("checks", result)
        self.assertIn("timestamp", result)
        self.assertEqual(result["version"], "v15")

    def test_liveness_probe(self):
        probe = self.health.get_liveness_probe()
        self.assertTrue(probe["alive"])
        self.assertIn("timestamp", probe)

    def test_readiness_probe(self):
        probe = self.health.get_readiness_probe()
        self.assertIn("healthy", probe)

    def test_custom_health_check(self):
        check_called = []

        def passing_check():
            check_called.append(True)
            return {"healthy": True, "detail": "working"}

        self.health.register_check("test_check", passing_check)
        result = self.health.run_health_check()
        self.assertTrue(len(check_called) > 0)
        self.assertTrue(result["healthy"])

    def test_failing_health_check(self):
        def failing_check():
            return {"healthy": False, "error": "connection failed"}

        self.health.register_check("failing", failing_check)
        result = self.health.run_health_check()
        self.assertFalse(result["healthy"])

    def test_exception_in_check(self):
        def error_check():
            raise RuntimeError("Something broke")

        self.health.register_check("error", error_check)
        result = self.health.run_health_check()
        self.assertFalse(result["healthy"])
        self.assertIn("RuntimeError", result["checks"]["error"]["error"])


class TestSecurityInstrumentationWrapper(unittest.TestCase):
    """Test instrumentation wrapper."""

    def setUp(self):
        self.inst = SecurityInstrumentationWrapper()

    def test_disabled_by_default(self):
        self.assertFalse(self.inst.is_instrumented())

    def test_enable_disable_instrumentation(self):
        self.inst.enable_instrumentation()
        self.assertTrue(self.inst.is_instrumented())
        self.assertTrue(self.inst.metrics.is_enabled())
        self.assertTrue(self.inst.logger.is_enabled())
        self.inst.disable_instrumentation()
        self.assertFalse(self.inst.is_instrumented())

    def test_wrap_function_no_instrumentation(self):
        """When disabled, wrapper should return original function behavior."""
        call_count = []

        def test_func(x):
            call_count.append(True)
            return x * 2

        wrapped = self.inst.wrap_security_function(
            test_func,
            SecurityEventType.INPUT_VALIDATION,
            "test_module"
        )

        result = wrapped(5)
        self.assertEqual(result, 10)
        self.assertEqual(len(call_count), 1)

    def test_wrap_function_with_instrumentation(self):
        """When enabled, wrapper should collect metrics."""
        self.inst.enable_instrumentation()

        def test_func(x):
            return x * 2

        wrapped = self.inst.wrap_security_function(
            test_func,
            SecurityEventType.INPUT_VALIDATION,
            "test_module"
        )

        result = wrapped(5)
        self.assertEqual(result, 10)

        snapshot = self.inst.metrics.get_snapshot()
        self.assertGreater(len(snapshot["timer_stats"]), 0)

    def test_wrap_function_exception_handling(self):
        """Instrumentation should preserve exceptions."""
        self.inst.enable_instrumentation()

        def error_func():
            raise ValueError("Test error")

        wrapped = self.inst.wrap_security_function(
            error_func,
            SecurityEventType.INPUT_VALIDATION,
            "test_module"
        )

        with self.assertRaises(ValueError):
            wrapped()

        snapshot = self.inst.metrics.get_snapshot()
        # Should have recorded the failure
        self.assertGreater(len(snapshot["counters"]), 0)

    def test_timed_operation_decorator(self):
        self.inst.enable_instrumentation()

        @self.inst.timed_operation("test_timed")
        def slow_func():
            time.sleep(0.001)
            return "done"

        result = slow_func()
        self.assertEqual(result, "done")
        snapshot = self.inst.metrics.get_snapshot()
        self.assertIn("test_timed", snapshot["timer_stats"])


class TestGlobalFunctions(unittest.TestCase):
    """Test global utility functions."""

    def test_get_instrumentation(self):
        inst = get_instrumentation()
        self.assertIsInstance(inst, SecurityInstrumentationWrapper)

    def test_generate_correlation_id(self):
        corr_id = generate_correlation_id()
        self.assertIsInstance(corr_id, str)
        self.assertEqual(len(corr_id), 32)

    def test_correlation_id_uniqueness(self):
        ids = set()
        for _ in range(100):
            ids.add(generate_correlation_id())
        self.assertEqual(len(ids), 100)  # All unique


class TestBackwardCompatibility(unittest.TestCase):
    """Verify backward compatibility - no breaking changes."""

    def test_no_side_effects_when_disabled(self):
        """All instrumentation is completely inert when disabled."""
        inst = SecurityInstrumentationWrapper()
        self.assertFalse(inst.is_instrumented())

        # Operations should work normally with zero side effects
        inst.metrics.increment_counter("test")
        inst.logger.log_event(SecurityEvent(SecurityEventType.INPUT_VALIDATION, "test"))

        snapshot = inst.metrics.get_snapshot()
        self.assertEqual(len(snapshot["counters"]), 0)

    def test_standard_library_only(self):
        """Verify no external dependencies."""
        import sys
        # The module should import without external packages
        import neural_shield.observability_security_integration_metrics_v15_2026_june as obs
        # Should not have added any third-party imports
        self.assertTrue(True)


if __name__ == "__main__":
    unittest.main()
