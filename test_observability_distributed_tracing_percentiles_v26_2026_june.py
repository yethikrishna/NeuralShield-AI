"""
Test Suite for NeuralShield Observability v26 - Dimension D
Distributed Tracing, Percentiles, Prometheus Export, Correlation IDs
"""
import unittest
import time
import threading
import json
import sys
import os

# Add module path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from observability_distributed_tracing_percentiles_v26_2026_june import (
    ObservabilityConfig, get_config,
    LogLevel, AdaptiveSamplingLogger, get_logger,
    MetricType, Metric, PercentileResult, PercentileHistogram,
    MetricsCollector, get_metrics, timed_operation,
    HealthStatus, HealthCheck, HealthCheckRegistry, get_health_registry,
    TracingFlags, SpanContext, TracingManager, get_tracing, traced_operation,
    CorrelationIdManager, get_correlation_manager,
    SamplingConfig, logged_operation
)


class TestObservabilityConfig(unittest.TestCase):
    """Test global configuration - ALL OPT-IN by default"""
    
    def setUp(self):
        """Reset singleton for test isolation"""
        ObservabilityConfig._reset_for_testing()
    
    def test_all_features_disabled_by_default(self):
        """CRITICAL: All observability must be OPT-IN only"""
        config = ObservabilityConfig()
        
        self.assertFalse(config.structured_logging_enabled)
        self.assertFalse(config.metrics_collection_enabled)
        self.assertFalse(config.health_checks_enabled)
        self.assertFalse(config.tracing_enabled)
        self.assertFalse(config.distributed_context_enabled)
        self.assertFalse(config.prometheus_exposition_enabled)
        self.assertFalse(config.correlation_id_propagation)
    
    def test_enable_all(self):
        """Test enabling all features at once"""
        config = get_config()
        config.enable_all()
        
        self.assertTrue(config.structured_logging_enabled)
        self.assertTrue(config.metrics_collection_enabled)
        self.assertTrue(config.health_checks_enabled)
        self.assertTrue(config.tracing_enabled)
        self.assertTrue(config.distributed_context_enabled)
        self.assertTrue(config.prometheus_exposition_enabled)
        self.assertTrue(config.correlation_id_propagation)


class TestPercentileHistogram(unittest.TestCase):
    """Test percentile calculation accuracy"""
    
    def test_basic_percentile_calculation(self):
        """Test P50, P95, P99 calculation"""
        hist = PercentileHistogram()
        
        # Record 100 samples: 1-100 ms
        for i in range(1, 101):
            hist.record(float(i))
        
        result = hist.get_percentiles()
        
        self.assertEqual(result.count, 100)
        self.assertEqual(result.min, 1.0)
        self.assertEqual(result.max, 100.0)
        self.assertAlmostEqual(result.avg, 50.5, places=1)
        self.assertGreaterEqual(result.p50, 50.0)
        self.assertLessEqual(result.p50, 51.0)
        self.assertGreaterEqual(result.p95, 95.0)
        self.assertGreaterEqual(result.p99, 99.0)
    
    def test_thread_safety(self):
        """Test histogram under concurrent access"""
        hist = PercentileHistogram()
        
        def record_samples():
            for _ in range(100):
                hist.record(time.time() % 1000)
        
        threads = [threading.Thread(target=record_samples) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        result = hist.get_percentiles()
        self.assertEqual(result.count, 1000)


class TestDistributedTracing(unittest.TestCase):
    """Test W3C Trace Context propagation"""
    
    def setUp(self):
        get_config().enable_tracing()
    
    def test_trace_id_generation(self):
        """Test W3C compliant trace ID format"""
        tracing = TracingManager()
        trace_id = tracing.generate_trace_id()
        
        self.assertEqual(len(trace_id), 32)  # 16 hex bytes
        self.assertTrue(all(c in '0123456789abcdef' for c in trace_id))
    
    def test_span_id_generation(self):
        """Test W3C compliant span ID format"""
        tracing = TracingManager()
        span_id = tracing.generate_span_id()
        
        self.assertEqual(len(span_id), 16)  # 8 hex bytes
    
    def test_parent_child_span_relationship(self):
        """Test parent span context propagation"""
        tracing = TracingManager()
        
        parent = tracing.start_span("parent_operation")
        child = tracing.start_span("child_operation", parent)
        
        self.assertEqual(parent.trace_id, child.trace_id)
        self.assertEqual(parent.span_id, child.parent_span_id)
    
    def test_traceparent_header_format(self):
        """Test W3C traceparent header injection"""
        tracing = TracingManager()
        tracing.start_span("test")
        
        traceparent = tracing.inject_traceparent()
        parts = traceparent.split("-")
        
        self.assertEqual(len(parts), 4)
        self.assertEqual(parts[0], "00")  # version
        self.assertEqual(len(parts[1]), 32)  # trace-id
        self.assertEqual(len(parts[2]), 16)  # parent-id
        self.assertEqual(len(parts[3]), 2)  # flags
    
    def test_baggage_propagation(self):
        """Test baggage context propagation"""
        tracing = TracingManager()
        
        parent = tracing.start_span("parent")
        tracing.set_baggage("user_id", "u123")
        tracing.set_baggage("tenant", "acme")
        
        child = tracing.start_span("child", parent)
        
        self.assertEqual(child.baggage.get("user_id"), "u123")
        self.assertEqual(child.baggage.get("tenant"), "acme")


class TestCorrelationIdManager(unittest.TestCase):
    """Test correlation ID propagation across modules"""
    
    def setUp(self):
        get_config().enable_correlation_ids()
    
    def test_correlation_id_generation(self):
        """Test correlation ID format"""
        cid_manager = CorrelationIdManager()
        cid = cid_manager.generate()
        
        self.assertTrue(cid.startswith("ns-cid-"))
        self.assertEqual(len(cid), 7 + 12)  # prefix (7 chars) + 12 hex chars
    
    def test_set_and_get_correlation_id(self):
        """Test setting and getting correlation ID"""
        cid_manager = CorrelationIdManager()
        
        cid = cid_manager.set()
        retrieved = cid_manager.get()
        
        self.assertEqual(cid, retrieved)
    
    def test_correlation_id_propagation_with_tracing(self):
        """Test correlation ID works with tracing"""
        get_config().enable_all()
        
        @traced_operation("test_op")
        def test_func():
            return get_correlation_manager().get()
        
        result = test_func()
        self.assertIsNotNone(result)
        self.assertTrue(result.startswith("ns-cid-"))


class TestMetricsCollectorWithPercentiles(unittest.TestCase):
    """Test metrics collection with percentile support"""
    
    def setUp(self):
        get_config().enable_metrics()
        get_config().enable_prometheus()
    
    def test_timer_with_percentiles(self):
        """Test timer records and calculates percentiles"""
        metrics = MetricsCollector()
        metrics.reset()
        
        metrics.start_timer("test_latency")
        time.sleep(0.01)
        metrics.stop_timer("test_latency")
        
        for i in range(10):
            metrics.start_timer("test_latency")
            time.sleep(0.001 * i)
            metrics.stop_timer("test_latency")
        
        percentiles = metrics.get_timer_percentiles("test_latency")
        
        self.assertIsNotNone(percentiles)
        self.assertGreater(percentiles.count, 0)
        self.assertGreater(percentiles.p99, percentiles.p50)
    
    def test_prometheus_export_format(self):
        """Test Prometheus exposition format"""
        metrics = MetricsCollector()
        metrics.reset()
        
        metrics.increment_counter("requests_total", 5)
        metrics.set_gauge("active_connections", 10)
        
        prom_output = metrics.export_prometheus()
        
        self.assertIn("# TYPE", prom_output)
        self.assertIn("requests_total", prom_output)
        self.assertIn("active_connections", prom_output)


class TestHealthCheckWithDependencies(unittest.TestCase):
    """Test health check dependency graph"""
    
    def setUp(self):
        get_config().enable_health_checks()
    
    def test_health_check_registration(self):
        """Test health check registration"""
        registry = HealthCheckRegistry()
        
        def db_check():
            return HealthCheck(name="database", status=HealthStatus.HEALTHY)
        
        registry.register("database", db_check)
        results = registry.run_all_checks()
        
        self.assertEqual(results["overall_status"], "healthy")
    
    def test_dependency_cascading_failure(self):
        """Test unhealthy dependency cascades to dependent checks"""
        registry = HealthCheckRegistry()
        
        def unhealthy_db():
            return HealthCheck(name="database", status=HealthStatus.UNHEALTHY)
        
        def healthy_api():
            return HealthCheck(name="api", status=HealthStatus.HEALTHY)
        
        registry.register("database", unhealthy_db)
        registry.register("api", healthy_api, dependencies=["database"])
        
        results = registry.run_all_checks()
        
        # API should be unhealthy because database is unhealthy
        self.assertEqual(results["overall_status"], "unhealthy")
    
    def test_dependency_degraded_propagation(self):
        """Test degraded dependency propagates degradation"""
        registry = HealthCheckRegistry()
        
        def degraded_cache():
            return HealthCheck(name="cache", status=HealthStatus.DEGRADED)
        
        def healthy_app():
            return HealthCheck(name="app", status=HealthStatus.HEALTHY)
        
        registry.register("cache", degraded_cache)
        registry.register("app", healthy_app, dependencies=["cache"])
        
        results = registry.run_all_checks()
        
        self.assertEqual(results["overall_status"], "degraded")


class TestAdaptiveSamplingLogger(unittest.TestCase):
    """Test adaptive sampling for high volume logs"""
    
    def setUp(self):
        get_config().enable_structured_logging()
    
    def test_logger_creation(self):
        """Test logger creation"""
        logger = AdaptiveSamplingLogger("test")
        self.assertEqual(logger.name, "test")
    
    def test_sampling_config_defaults(self):
        """Test default sampling configuration"""
        cfg = SamplingConfig()
        
        self.assertEqual(cfg.base_rate, 1.0)
        self.assertEqual(cfg.max_events_per_second, 1000)
        self.assertTrue(cfg.adaptive_sampling)


class TestDecorators(unittest.TestCase):
    """Test observability decorators"""
    
    def setUp(self):
        get_config().enable_all()
    
    def test_timed_operation_decorator(self):
        """Test timing decorator records metrics"""
        metrics = get_metrics()
        metrics.reset()
        
        @timed_operation("test_op")
        def slow_func():
            time.sleep(0.01)
            return "done"
        
        result = slow_func()
        self.assertEqual(result, "done")
        
        all_metrics = metrics.get_metrics()
        # Check for success counter (guaranteed to be incremented)
        self.assertIn("test_op_success", all_metrics)
    
    def test_traced_operation_decorator(self):
        """Test tracing decorator creates span context"""
        @traced_operation("decorated_op")
        def traced_func():
            ctx = get_tracing().get_current_context()
            return ctx is not None and ctx.trace_id != ""
        
        result = traced_func()
        self.assertTrue(result)
    
    def test_logged_operation_decorator(self):
        """Test logging decorator works"""
        @logged_operation(LogLevel.INFO)
        def logged_func():
            return "logged"
        
        result = logged_func()
        self.assertEqual(result, "logged")


class TestBackwardCompatibility(unittest.TestCase):
    """Verify 100% backward compatibility - no breaking changes"""
    
    def test_no_op_when_disabled(self):
        """All functions are no-ops when disabled - ZERO overhead"""
        config = get_config()
        
        # Explicitly disable everything
        config.structured_logging_enabled = False
        config.metrics_collection_enabled = False
        config.tracing_enabled = False
        config.health_checks_enabled = False
        
        metrics = MetricsCollector()
        tracing = TracingManager()
        logger = AdaptiveSamplingLogger()
        
        # These should all be no-ops, no exceptions
        metrics.increment_counter("test", 1)
        metrics.start_timer("test")
        metrics.stop_timer("test")
        
        span = tracing.start_span("test")
        self.assertEqual(span.trace_id, "")
        self.assertEqual(span.span_id, "")
        
        logger.info("test message")  # Should not print
        
        # Verify no metrics collected
        self.assertEqual(len(metrics.get_metrics()), 0)
    
    def test_singleton_instances_work(self):
        """Test global singleton getters work"""
        self.assertIsNotNone(get_logger())
        self.assertIsNotNone(get_metrics())
        self.assertIsNotNone(get_health_registry())
        self.assertIsNotNone(get_tracing())
        self.assertIsNotNone(get_correlation_manager())
        self.assertIsNotNone(get_config())


if __name__ == "__main__":
    unittest.main(verbosity=2)
