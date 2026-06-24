"""
Test Suite for NeuralShield Observability & Instrumentation v23
Dimension D: Observability & Instrumentation
Version: v23

All tests verify ADD-ONLY functionality.
No existing code is modified or broken.
"""

import unittest
import time
import threading
import json
import sys
import io
from typing import Dict, Any
from unittest.mock import patch, MagicMock

# Import the new module
sys.path.insert(0, '/home/user/autonomous-developer/NeuralShield-AI')
from neural_shield.observability_instrumentation_v23_2026_june import (
    # Config
    ObservabilityConfig,
    configure_observability,
    get_config,
    # Correlation IDs
    get_correlation_id,
    set_correlation_id,
    correlation_context,
    _correlation_local,
    # Logging
    structured_log,
    log_info,
    log_warning,
    log_error,
    LogLevel,
    _redact_sensitive,
    # Metrics
    counter_inc,
    gauge_set,
    timer_record,
    histogram_record,
    get_metrics_snapshot,
    timer_context,
    timed,
    # Health checks
    HealthStatus,
    HealthCheckResult,
    register_health_check,
    run_health_checks,
    # Instrumentation
    instrument_threat_detection,
    create_instrumented_wrapper,
    # Metadata
    OBSERVABILITY_VERSION,
    OBSERVABILITY_DIMENSION,
    get_observability_metadata,
)


class TestObservabilityConfig(unittest.TestCase):
    """Test observability configuration."""
    
    def test_default_config_all_disabled(self):
        """ALL FEATURES DISABLED BY DEFAULT - critical requirement."""
        config = get_config()
        self.assertFalse(config.enable_structured_logging)
        self.assertFalse(config.enable_metrics_collection)
        self.assertFalse(config.enable_health_checks)
        self.assertFalse(config.enable_tracing)
        self.assertFalse(config.enable_profiling)
        self.assertFalse(config.is_any_enabled())
    
    def test_configure_observability(self):
        """Test enabling specific features."""
        configure_observability(enable_structured_logging=True)
        config = get_config()
        self.assertTrue(config.enable_structured_logging)
        # Reset
        configure_observability(enable_structured_logging=False)
    
    def test_is_any_enabled(self):
        """Test is_any_enabled detection."""
        config = ObservabilityConfig()
        self.assertFalse(config.is_any_enabled())
        
        config.enable_structured_logging = True
        self.assertTrue(config.is_any_enabled())


class TestCorrelationIds(unittest.TestCase):
    """Test correlation ID management."""
    
    def setUp(self):
        """Ensure clean state for each test."""
        if hasattr(_correlation_local, 'correlation_id'):
            delattr(_correlation_local, 'correlation_id')
    
    def test_get_correlation_id_default_none(self):
        """Default is no correlation ID."""
        self.assertIsNone(get_correlation_id())
    
    def test_set_correlation_id(self):
        """Test setting correlation ID."""
        cid = set_correlation_id("test-id-123")
        self.assertEqual(cid, "test-id-123")
        self.assertEqual(get_correlation_id(), "test-id-123")
    
    def test_set_correlation_id_generates_uuid(self):
        """Test auto-generation of correlation ID."""
        cid = set_correlation_id()
        self.assertIsNotNone(cid)
        self.assertTrue(len(cid) > 10)  # UUID is long
    
    def test_correlation_context_manager(self):
        """Test correlation ID context manager."""
        with correlation_context("ctx-id") as cid:
            self.assertEqual(cid, "ctx-id")
            self.assertEqual(get_correlation_id(), "ctx-id")
        # Should be restored after context
        self.assertIsNone(get_correlation_id())
    
    def test_correlation_context_nested(self):
        """Test nested correlation contexts."""
        set_correlation_id("outer-id")
        with correlation_context("inner-id"):
            self.assertEqual(get_correlation_id(), "inner-id")
        self.assertEqual(get_correlation_id(), "outer-id")
    
    def test_correlation_id_thread_local(self):
        """Test correlation IDs are thread-local."""
        results = {}
        
        def worker(thread_id):
            set_correlation_id(f"thread-{thread_id}")
            time.sleep(0.01)
            results[thread_id] = get_correlation_id()
        
        t1 = threading.Thread(target=worker, args=(1,))
        t2 = threading.Thread(target=worker, args=(2,))
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        
        self.assertEqual(results[1], "thread-1")
        self.assertEqual(results[2], "thread-2")


class TestStructuredLogging(unittest.TestCase):
    """Test structured logging functionality."""
    
    def setUp(self):
        configure_observability(enable_structured_logging=True, log_level="DEBUG")
    
    def tearDown(self):
        configure_observability(enable_structured_logging=False)
    
    def test_structured_log_output_format(self):
        """Test structured log produces valid JSON."""
        captured_output = io.StringIO()
        with patch('sys.stdout', new=captured_output):
            structured_log("INFO", "Test message", custom_field="value")
        
        output = captured_output.getvalue().strip()
        log_entry = json.loads(output)
        
        self.assertIn('timestamp', log_entry)
        self.assertIn('level', log_entry)
        self.assertIn('message', log_entry)
        self.assertEqual(log_entry['message'], "Test message")
        self.assertEqual(log_entry['custom_field'], "value")
    
    def test_log_level_filtering(self):
        """Test log level filtering works."""
        configure_observability(log_level="WARNING")
        
        captured_output = io.StringIO()
        with patch('sys.stdout', new=captured_output):
            log_info("This should be filtered")
            log_warning("This should appear")
        
        output = captured_output.getvalue().strip()
        self.assertNotIn("This should be filtered", output)
        self.assertIn("This should appear", output)
    
    def test_sensitive_data_redaction(self):
        """Test sensitive data is redacted."""
        data = {
            'api_key': 'secret-123',
            'password': 'mypassword',
            'normal_field': 'ok',
            'nested': {'authorization': 'bearer token'}
        }
        redacted = _redact_sensitive(data)
        self.assertEqual(redacted['api_key'], "[REDACTED]")
        self.assertEqual(redacted['password'], "[REDACTED]")
        self.assertEqual(redacted['normal_field'], "ok")
        self.assertEqual(redacted['nested']['authorization'], "[REDACTED]")
    
    def test_logging_disabled_by_default(self):
        """Test logging does nothing when disabled."""
        configure_observability(enable_structured_logging=False)
        
        captured_output = io.StringIO()
        with patch('sys.stdout', new=captured_output):
            log_info("This should not appear")
        
        output = captured_output.getvalue().strip()
        self.assertEqual(output, "")


class TestMetricsCollection(unittest.TestCase):
    """Test metrics collection functionality."""
    
    def setUp(self):
        configure_observability(enable_metrics_collection=True)
    
    def tearDown(self):
        configure_observability(enable_metrics_collection=False)
    
    def test_counter_increment(self):
        """Test counter metrics."""
        counter_inc("test.counter", 1.0)
        counter_inc("test.counter", 2.0)
        metrics = get_metrics_snapshot()
        self.assertEqual(metrics['counters']['test.counter'], 3.0)
    
    def test_gauge_set(self):
        """Test gauge metrics."""
        gauge_set("test.gauge", 42.0)
        metrics = get_metrics_snapshot()
        self.assertEqual(metrics['gauges']['test.gauge'], 42.0)
    
    def test_timer_record(self):
        """Test timer metrics."""
        timer_record("test.timer", 0.5)
        timer_record("test.timer", 1.5)
        metrics = get_metrics_snapshot()
        self.assertEqual(metrics['timer_count']['test.timer'], 2)
        self.assertEqual(metrics['timer_avg']['test.timer'], 1.0)
    
    def test_timer_context_manager(self):
        """Test timer context manager."""
        with timer_context("context.timer"):
            time.sleep(0.01)
        metrics = get_metrics_snapshot()
        self.assertGreater(metrics['timer_count']['context.timer'], 0)
    
    def test_timed_decorator(self):
        """Test timed decorator."""
        @timed("decorated.function")
        def test_func():
            time.sleep(0.01)
            return "ok"
        
        result = test_func()
        self.assertEqual(result, "ok")
        metrics = get_metrics_snapshot()
        self.assertGreater(metrics['timer_count']['decorated.function'], 0)
    
    def test_metrics_disabled_by_default(self):
        """Test metrics do nothing when disabled."""
        configure_observability(enable_metrics_collection=False)
        counter_inc("disabled.counter")
        metrics = get_metrics_snapshot()
        self.assertEqual(metrics, {})


class TestHealthCheckFramework(unittest.TestCase):
    """Test health check framework."""
    
    def setUp(self):
        configure_observability(enable_health_checks=True)
    
    def tearDown(self):
        configure_observability(enable_health_checks=False)
    
    def test_health_check_result_creation(self):
        """Test health check result creation."""
        result = HealthCheckResult(
            name="test-check",
            status=HealthStatus.HEALTHY,
            message="All good"
        )
        self.assertEqual(result.name, "test-check")
        self.assertEqual(result.status, HealthStatus.HEALTHY)
    
    def test_register_and_run_health_check(self):
        """Test registering and running health checks."""
        def custom_check():
            return HealthCheckResult(
                name="custom",
                status=HealthStatus.HEALTHY,
                message="OK"
            )
        
        register_health_check("custom-check", custom_check)
        result = run_health_checks()
        
        # Verify our check was registered and ran
        self.assertIn("custom-check", result['checks'])
        self.assertEqual(result['checks']["custom-check"]['status'], "healthy")
    
    def test_health_check_unhealthy_propagates(self):
        """Test unhealthy status propagates to overall status."""
        def bad_check():
            return HealthCheckResult(
                name="failing",
                status=HealthStatus.UNHEALTHY,
                message="Something broke"
            )
        
        register_health_check("failing-check", bad_check)
        result = run_health_checks()
        
        self.assertEqual(result['status'], "unhealthy")
    
    def test_health_checks_disabled_by_default(self):
        """Test health checks report disabled status."""
        configure_observability(enable_health_checks=False)
        result = run_health_checks()
        self.assertIn("disabled", result['message'].lower())


class TestInstrumentationWrappers(unittest.TestCase):
    """Test instrumentation wrappers."""
    
    def setUp(self):
        configure_observability(
            enable_structured_logging=True,
            enable_metrics_collection=True,
            enable_tracing=True
        )
    
    def tearDown(self):
        configure_observability(
            enable_structured_logging=False,
            enable_metrics_collection=False,
            enable_tracing=False
        )
    
    def test_instrument_threat_detection_decorator(self):
        """Test threat detection instrumentation decorator."""
        @instrument_threat_detection("test-detector")
        def detect_threat(input_text):
            return {"threat": False, "score": 0.1}
        
        result = detect_threat("test input")
        self.assertEqual(result['threat'], False)
        metrics = get_metrics_snapshot()
        self.assertIn('threat_detection.test-detector.calls', metrics['counters'])
    
    def test_create_instrumented_wrapper(self):
        """Test creating instrumented wrapper."""
        def original_func(x, y):
            return x + y
        
        wrapped = create_instrumented_wrapper(original_func, "adder")
        result = wrapped(2, 3)
        self.assertEqual(result, 5)
    
    def test_wrapper_preserves_function_metadata(self):
        """Test wrappers preserve function metadata."""
        def original_func():
            """Original docstring"""
            pass
        
        wrapped = create_instrumented_wrapper(original_func, "test")
        self.assertEqual(wrapped.__doc__, "Original docstring")
        self.assertEqual(wrapped.__name__, "original_func")
    
    def test_zero_overhead_when_disabled(self):
        """Test ZERO overhead path when observability disabled."""
        configure_observability(
            enable_structured_logging=False,
            enable_metrics_collection=False,
            enable_tracing=False
        )
        
        call_count = [0]
        @instrument_threat_detection("zero-overhead-test")
        def test_func():
            call_count[0] += 1
            return "ok"
        
        result = test_func()
        self.assertEqual(result, "ok")
        self.assertEqual(call_count[0], 1)


class TestVersionAndMetadata(unittest.TestCase):
    """Test version and metadata."""
    
    def test_version_correct(self):
        """Test version is v23."""
        self.assertEqual(OBSERVABILITY_VERSION, "23.0.0")
    
    def test_dimension_correct(self):
        """Test dimension is D."""
        self.assertEqual(OBSERVABILITY_DIMENSION, "D")
    
    def test_get_observability_metadata(self):
        """Test metadata function."""
        metadata = get_observability_metadata()
        self.assertEqual(metadata['version'], "23.0.0")
        self.assertEqual(metadata['dimension'], "D")
        self.assertIn('features', metadata)
        self.assertIn('config', metadata)


class TestThreadSafety(unittest.TestCase):
    """Test thread safety of observability components."""
    
    def setUp(self):
        configure_observability(enable_metrics_collection=True)
    
    def tearDown(self):
        configure_observability(enable_metrics_collection=False)
    
    def test_concurrent_counter_increments(self):
        """Test concurrent counter increments are thread-safe."""
        num_threads = 10
        increments_per_thread = 100
        
        def worker():
            for _ in range(increments_per_thread):
                counter_inc("concurrent.test", 1.0)
        
        threads = [threading.Thread(target=worker) for _ in range(num_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        metrics = get_metrics_snapshot()
        expected = num_threads * increments_per_thread
        self.assertEqual(metrics['counters']['concurrent.test'], expected)


if __name__ == '__main__':
    unittest.main(verbosity=2)
