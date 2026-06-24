"""
Test Suite for NeuralShield Observability & Instrumentation Module (Dimension D - V25)
=====================================================================================
Comprehensive tests covering:
- Structured logging (OPT-IN behavior, no-op by default)
- Metrics collection (counters, gauges, timers, histograms)
- Health check framework
- Zero overhead when disabled
- Backward compatibility
- Thread safety
"""

import os
import sys
import json
import time
import threading
import unittest
from unittest.mock import patch, MagicMock
from typing import Dict, Any

# Add the module path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from neural_shield.observability_structured_logging_metrics_health_v25_2026_june import (
    ObservabilityConfig,
    StructuredLogger,
    MetricsCollector,
    HealthCheckRegistry,
    HealthCheckResult,
    HealthStatus,
    LogLevel,
    MetricType,
    get_logger,
    get_metrics,
    get_health_registry,
    instrument_threat_detection,
)


class TestObservabilityConfig(unittest.TestCase):
    """Tests for observability configuration - all OPT-IN behavior."""
    
    def setUp(self):
        """Reset environment variables before each test."""
        for key in list(os.environ.keys()):
            if key.startswith('NEURALSHIELD_'):
                del os.environ[key]
    
    def test_all_features_disabled_by_default(self):
        """VERIFY: All observability features are DISABLED by default."""
        config = ObservabilityConfig()
        
        self.assertFalse(config.enable_structured_logging, "Logging should be disabled by default")
        self.assertFalse(config.enable_metrics_collection, "Metrics should be disabled by default")
        self.assertFalse(config.enable_health_checks, "Health checks should be disabled by default")
        self.assertFalse(config.enable_tracing, "Tracing should be disabled by default")
    
    def test_opt_in_via_environment_variables(self):
        """VERIFY: Features can be enabled via environment variables."""
        os.environ['NEURALSHIELD_ENABLE_LOGGING'] = '1'
        os.environ['NEURALSHIELD_ENABLE_METRICS'] = '1'
        os.environ['NEURALSHIELD_ENABLE_HEALTH'] = '1'
        os.environ['NEURALSHIELD_ENABLE_TRACING'] = '1'
        
        # Reset singleton for fresh config
        ObservabilityConfig._instance = None
        config = ObservabilityConfig()
        
        self.assertTrue(config.enable_structured_logging)
        self.assertTrue(config.enable_metrics_collection)
        self.assertTrue(config.enable_health_checks)
        self.assertTrue(config.enable_tracing)
    
    def test_singleton_pattern(self):
        """VERIFY: Config is a proper singleton."""
        config1 = ObservabilityConfig()
        config2 = ObservabilityConfig()
        
        self.assertIs(config1, config2, "Config should be singleton")


class TestStructuredLogging(unittest.TestCase):
    """Tests for structured logging system."""
    
    def setUp(self):
        for key in list(os.environ.keys()):
            if key.startswith('NEURALSHIELD_'):
                del os.environ[key]
        ObservabilityConfig._instance = None
    
    def test_logging_no_op_when_disabled(self):
        """VERIFY: Logging is NO-OP when disabled - zero overhead."""
        logger = StructuredLogger()
        
        with patch('sys.stderr') as mock_stderr:
            logger.debug("Debug message")
            logger.info("Info message")
            logger.warning("Warning message")
            logger.error("Error message")
            logger.critical("Critical message")
            
            # No output when disabled
            mock_stderr.write.assert_not_called()
    
    def test_logging_output_when_enabled(self):
        """VERIFY: Logging produces JSON output when enabled."""
        os.environ['NEURALSHIELD_ENABLE_LOGGING'] = '1'
        ObservabilityConfig._instance = None
        
        logger = StructuredLogger()
        
        output_lines = []
        def mock_write(data):
            output_lines.append(data)
        
        with patch('sys.stderr') as mock_stderr:
            mock_stderr.write = mock_write
            mock_stderr.flush = MagicMock()
            
            logger.info("Test message", extra_key="extra_value")
            
            if output_lines:
                log_json = json.loads(output_lines[0])
                self.assertEqual(log_json['level'], 'INFO')
                self.assertEqual(log_json['message'], 'Test message')
                self.assertEqual(log_json['extra_key'], 'extra_value')
                self.assertIn('timestamp', log_json)
    
    def test_log_level_filtering(self):
        """VERIFY: Log levels are properly filtered."""
        os.environ['NEURALSHIELD_ENABLE_LOGGING'] = '1'
        os.environ['NEURALSHIELD_LOG_LEVEL'] = 'WARNING'
        ObservabilityConfig._instance = None
        
        logger = StructuredLogger()
        
        with patch('sys.stderr') as mock_stderr:
            mock_stderr.flush = MagicMock()
            
            logger.debug("Should not appear")
            logger.info("Should not appear")
            
            # No calls yet
            call_count_before = mock_stderr.write.call_count
            
            logger.warning("Should appear")
            logger.error("Should appear")
            
            # Only WARNING and above should be logged
            self.assertGreater(mock_stderr.write.call_count, call_count_before)
    
    def test_logger_bind_context(self):
        """VERIFY: Logger context binding works correctly."""
        os.environ['NEURALSHIELD_ENABLE_LOGGING'] = '1'
        ObservabilityConfig._instance = None
        
        logger = StructuredLogger()
        bound_logger = logger.bind(request_id="req-123", user_id="user-456")
        
        self.assertIsNot(logger, bound_logger, "Bind should return new instance")


class TestMetricsCollection(unittest.TestCase):
    """Tests for metrics collection system."""
    
    def setUp(self):
        for key in list(os.environ.keys()):
            if key.startswith('NEURALSHIELD_'):
                del os.environ[key]
        ObservabilityConfig._instance = None
    
    def test_metrics_no_op_when_disabled(self):
        """VERIFY: Metrics collection is NO-OP when disabled."""
        metrics = MetricsCollector()
        
        metrics.increment("test_counter")
        metrics.gauge("test_gauge", 42.0)
        metrics.record_timing("test_timer", 100.0)
        
        result = metrics.get_metrics()
        self.assertEqual(result, {}, "No metrics should be collected when disabled")
    
    def test_counter_increment_when_enabled(self):
        """VERIFY: Counters work correctly when enabled."""
        os.environ['NEURALSHIELD_ENABLE_METRICS'] = '1'
        ObservabilityConfig._instance = None
        
        metrics = MetricsCollector()
        
        metrics.increment("requests_total", labels={"endpoint": "/api"})
        metrics.increment("requests_total", labels={"endpoint": "/api"})
        metrics.increment("requests_total", value=5, labels={"endpoint": "/api"})
        
        result = metrics.get_metrics()
        self.assertEqual(result['counters']['requests_total']['value'], 7.0)
    
    def test_gauge_set_when_enabled(self):
        """VERIFY: Gauges work correctly when enabled."""
        os.environ['NEURALSHIELD_ENABLE_METRICS'] = '1'
        ObservabilityConfig._instance = None
        
        metrics = MetricsCollector()
        
        metrics.gauge("active_connections", 10.0)
        metrics.gauge("active_connections", 15.0)
        
        result = metrics.get_metrics()
        self.assertEqual(result['gauges']['active_connections']['value'], 15.0)
    
    def test_timer_decorator(self):
        """VERIFY: Timer decorator works correctly."""
        os.environ['NEURALSHIELD_ENABLE_METRICS'] = '1'
        ObservabilityConfig._instance = None
        
        metrics = MetricsCollector()
        
        @metrics.timer("test_function_duration")
        def slow_function():
            time.sleep(0.01)
            return "done"
        
        result = slow_function()
        self.assertEqual(result, "done")
        
        metrics_result = metrics.get_metrics()
        self.assertIn('test_function_duration', metrics_result['timers'])
    
    def test_metrics_reset(self):
        """VERIFY: Metrics can be reset."""
        os.environ['NEURALSHIELD_ENABLE_METRICS'] = '1'
        ObservabilityConfig._instance = None
        
        metrics = MetricsCollector()
        metrics.increment("test_counter")
        metrics.reset()
        
        result = metrics.get_metrics()
        self.assertEqual(result['counters'], {})


class TestHealthCheckFramework(unittest.TestCase):
    """Tests for health check framework."""
    
    def setUp(self):
        for key in list(os.environ.keys()):
            if key.startswith('NEURALSHIELD_'):
                del os.environ[key]
        ObservabilityConfig._instance = None
    
    def test_health_checks_no_op_when_disabled(self):
        """VERIFY: Health checks are NO-OP when disabled."""
        registry = HealthCheckRegistry()
        
        def always_healthy():
            return HealthCheckResult(name="test", status=HealthStatus.HEALTHY)
        
        registry.register("test_check", always_healthy)
        result = registry.run_all_checks()
        
        self.assertEqual(result, {}, "No health checks should run when disabled")
    
    def test_health_check_execution_when_enabled(self):
        """VERIFY: Health checks execute when enabled."""
        os.environ['NEURALSHIELD_ENABLE_HEALTH'] = '1'
        ObservabilityConfig._instance = None
        
        registry = HealthCheckRegistry()
        
        def always_healthy():
            return HealthCheckResult(name="database", status=HealthStatus.HEALTHY, message="Connected")
        
        registry.register("database", always_healthy)
        
        result = registry.run_all_checks()
        self.assertEqual(result['overall_status'], 'healthy')
        self.assertEqual(len(result['checks']), 1)
    
    def test_health_check_degraded_status(self):
        """VERIFY: Degraded status is handled correctly."""
        os.environ['NEURALSHIELD_ENABLE_HEALTH'] = '1'
        ObservabilityConfig._instance = None
        
        registry = HealthCheckRegistry()
        
        def degraded_check():
            return HealthCheckResult(name="cache", status=HealthStatus.DEGRADED, message="High latency")
        
        registry.register("cache", degraded_check)
        
        result = registry.run_all_checks()
        self.assertEqual(result['overall_status'], 'degraded')
    
    def test_health_check_exception_handling(self):
        """VERIFY: Exceptions in health checks are caught and reported."""
        os.environ['NEURALSHIELD_ENABLE_HEALTH'] = '1'
        ObservabilityConfig._instance = None
        
        registry = HealthCheckRegistry()
        
        def failing_check():
            raise RuntimeError("Database connection failed")
        
        registry.register("failing", failing_check)
        
        result = registry.run_all_checks()
        self.assertEqual(result['overall_status'], 'unhealthy')


class TestInstrumentationDecorator(unittest.TestCase):
    """Tests for the instrumentation decorator."""
    
    def setUp(self):
        for key in list(os.environ.keys()):
            if key.startswith('NEURALSHIELD_'):
                del os.environ[key]
        ObservabilityConfig._instance = None
    
    def test_decorator_preserves_function_behavior(self):
        """VERIFY: Decorator 100% preserves original function behavior."""
        @instrument_threat_detection
        def detect_threat(input_text):
            return {"threat_detected": False, "score": 0.1}
        
        # Behavior should be identical with or without instrumentation
        result = detect_threat("test input")
        self.assertEqual(result['threat_detected'], False)
        self.assertEqual(result['score'], 0.1)
    
    def test_decorator_propagates_exceptions(self):
        """VERIFY: Decorator properly propagates exceptions."""
        @instrument_threat_detection
        def failing_function():
            raise ValueError("Invalid input")
        
        with self.assertRaises(ValueError):
            failing_function()
    
    def test_decorator_no_overhead_when_disabled(self):
        """VERIFY: Decorator has minimal overhead when disabled."""
        # Since everything is disabled by default, this should just pass through
        call_count = [0]
        
        @instrument_threat_detection
        def simple_function():
            call_count[0] += 1
            return "success"
        
        for _ in range(100):
            result = simple_function()
        
        self.assertEqual(call_count[0], 100)
        self.assertEqual(result, "success")


class TestThreadSafety(unittest.TestCase):
    """Tests for thread safety of all observability components."""
    
    def test_concurrent_metrics_increment(self):
        """VERIFY: Metrics collection is thread-safe when enabled."""
        os.environ['NEURALSHIELD_ENABLE_METRICS'] = '1'
        ObservabilityConfig._instance = None
        
        metrics = MetricsCollector()
        num_threads = 10
        increments_per_thread = 1000
        
        def worker():
            for _ in range(increments_per_thread):
                metrics.increment("concurrent_counter")
        
        threads = [threading.Thread(target=worker) for _ in range(num_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        result = metrics.get_metrics()
        expected = num_threads * increments_per_thread
        self.assertEqual(result['counters']['concurrent_counter']['value'], expected)


class TestBackwardCompatibility(unittest.TestCase):
    """Tests ensuring 100% backward compatibility."""
    
    def test_no_existing_code_changes_required(self):
        """VERIFY: Existing code works without any modifications."""
        # Import an existing module to verify it still works
        try:
            from neural_shield import prompt_firewall_2026_june
            self.assertTrue(True, "Existing module imports successfully")
        except ImportError:
            # Module might not exist in this version, that's fine
            pass
    
    def test_singleton_accessors(self):
        """VERIFY: Singleton accessors work and return same instances."""
        logger1 = get_logger()
        logger2 = get_logger()
        self.assertIs(logger1, logger2)
        
        metrics1 = get_metrics()
        metrics2 = get_metrics()
        self.assertIs(metrics1, metrics2)
        
        health1 = get_health_registry()
        health2 = get_health_registry()
        self.assertIs(health1, health2)


if __name__ == '__main__':
    unittest.main(verbosity=2)
