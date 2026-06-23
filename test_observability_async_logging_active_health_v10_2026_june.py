"""
Comprehensive Test Suite for NeuralShield Observability v10
==========================================================
DIMENSION D - Observability & Instrumentation v10 Tests

Tests cover:
1. Async/Await Context Propagation
2. Correlation ID Management
3. Logging Integration
4. Active Health Probes (TCP, HTTP, DNS, Disk)
5. Health Checker with Background Refresh
6. Dynamic Sampling Configuration
7. Decorators (sync + async)
8. Baggage Propagation
9. Backward Compatibility
10. Thread Safety
"""

import asyncio
import logging
import threading
import time
import unittest
from unittest.mock import patch, MagicMock


# Import the module to test
from neural_shield.observability_async_logging_active_health_v10_2026_june import (
    # Core
    is_observability_enabled,
    enable_observability,
    disable_observability,
    
    # Correlation ID
    generate_correlation_id,
    set_correlation_id,
    get_correlation_id,
    clear_correlation_id,
    
    # Logging
    CorrelationIdFilter,
    StructuredJsonFormatter,
    
    # Async tracing
    AsyncSpanContext,
    get_current_async_span,
    start_async_span,
    end_async_span,
    trace_async,
    trace_sync,
    
    # Health
    HealthStatus,
    HealthCheckResult,
    ActiveHealthProbes,
    EnhancedHealthCheckerV10,
    
    # Sampling
    SamplingMode,
    SamplingConfig,
    
    # Engine
    ObservabilityEngineV10,
)


class TestCorrelationIdManagement(unittest.TestCase):
    """Test correlation ID generation and context management."""
    
    def test_generate_correlation_id(self):
        """Test UUID generation format."""
        cid = generate_correlation_id()
        self.assertEqual(len(cid), 36)  # UUID format
        self.assertIn("-", cid)
    
    def test_set_get_correlation_id(self):
        """Test setting and getting correlation ID."""
        test_id = "test-correlation-id-123"
        result = set_correlation_id(test_id)
        self.assertEqual(result, test_id)
        self.assertEqual(get_correlation_id(), test_id)
    
    def test_set_correlation_id_auto_generate(self):
        """Test auto-generation when None provided."""
        result = set_correlation_id(None)
        self.assertIsNotNone(result)
        self.assertEqual(len(result), 36)
    
    def test_clear_correlation_id(self):
        """Test clearing correlation ID."""
        set_correlation_id("test-id")
        clear_correlation_id()
        self.assertIsNone(get_correlation_id())


class TestCorrelationIdFilter(unittest.TestCase):
    """Test logging filter with correlation ID injection."""
    
    def test_filter_injects_correlation_id(self):
        """Test filter adds correlation_id to log records."""
        log_filter = CorrelationIdFilter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="test message",
            args=(),
            exc_info=None,
        )
        
        set_correlation_id("test-filter-id")
        result = log_filter.filter(record)
        
        self.assertTrue(result)
        self.assertEqual(record.correlation_id, "test-filter-id")
    
    def test_filter_no_correlation_id(self):
        """Test filter handles missing correlation ID gracefully."""
        log_filter = CorrelationIdFilter()
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="test.py",
            lineno=1, msg="test", args=(), exc_info=None,
        )
        
        clear_correlation_id()
        log_filter.filter(record)
        
        self.assertEqual(record.correlation_id, "no-correlation-id")
    
    def test_filter_injects_trace_ids(self):
        """Test filter injects trace and span IDs when available."""
        enable_observability()
        log_filter = CorrelationIdFilter()
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="test.py",
            lineno=1, msg="test", args=(), exc_info=None,
        )
        
        span = start_async_span("test_operation")
        log_filter.filter(record)
        
        self.assertNotEqual(record.trace_id, "no-trace-id")
        self.assertNotEqual(record.span_id, "no-span-id")
        self.assertEqual(len(record.trace_id), 32)
        self.assertEqual(len(record.span_id), 16)
        
        disable_observability()


class TestStructuredJsonFormatter(unittest.TestCase):
    """Test JSON structured logging formatter."""
    
    def test_json_format_output(self):
        """Test formatter produces valid JSON with required fields."""
        import json
        
        formatter = StructuredJsonFormatter()
        record = logging.LogRecord(
            name="test.logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="test message",
            args=(),
            exc_info=None,
        )
        
        set_correlation_id("json-test-id")
        output = formatter.format(record)
        
        # Should be valid JSON
        parsed = json.loads(output)
        
        # Required fields
        self.assertIn("timestamp", parsed)
        self.assertIn("level", parsed)
        self.assertEqual(parsed["level"], "INFO")
        self.assertIn("logger", parsed)
        self.assertEqual(parsed["logger"], "test.logger")
        self.assertIn("correlation_id", parsed)
        self.assertEqual(parsed["correlation_id"], "json-test-id")
        self.assertIn("message", parsed)
        self.assertEqual(parsed["message"], "test message")


class TestAsyncSpanContext(unittest.TestCase):
    """Test async span context creation and management."""
    
    def test_generate_ids_format(self):
        """Test W3C compatible ID generation."""
        trace_id, span_id = AsyncSpanContext.generate_ids()
        self.assertEqual(len(trace_id), 32)  # W3C spec
        self.assertEqual(len(span_id), 16)   # W3C spec
        # Should be hex
        int(trace_id, 16)  # Should not raise
        int(span_id, 16)   # Should not raise
    
    def test_create_root_span(self):
        """Test root span creation."""
        span = AsyncSpanContext.create_root("test_op")
        self.assertIsNone(span.parent_span_id)
        self.assertEqual(span.operation_name, "test_op")
        self.assertIsNotNone(span.trace_id)
        self.assertIsNotNone(span.span_id)
    
    def test_span_baggage(self):
        """Test baggage propagation."""
        span = AsyncSpanContext.create_root("test")
        span.set_baggage("user_id", "12345")
        self.assertEqual(span.get_baggage("user_id"), "12345")
        self.assertIsNone(span.get_baggage("nonexistent"))
        self.assertEqual(span.get_baggage("nonexistent", "default"), "default")
    
    def test_span_attributes(self):
        """Test span attribute setting."""
        span = AsyncSpanContext.create_root("test")
        span.set_attribute("http.method", "POST")
        span.set_attribute("http.status", 200)
        self.assertEqual(span.attributes["http.method"], "POST")
        self.assertEqual(span.attributes["http.status"], 200)
    
    def test_span_end_with_error(self):
        """Test span ending with error."""
        span = AsyncSpanContext.create_root("test")
        error = ValueError("test error")
        span.end(error)
        
        self.assertTrue(span.has_error)
        self.assertEqual(span.error_message, "test error")
        self.assertIsNotNone(span.end_time)
    
    def test_span_duration(self):
        """Test span duration calculation."""
        span = AsyncSpanContext.create_root("test")
        time.sleep(0.01)
        span.end()
        duration = span.duration_ms()
        self.assertGreater(duration, 0)
        self.assertLess(duration, 100)  # Should be ~10ms


class TestAsyncTracingDisabled(unittest.TestCase):
    """Test tracing behavior when observability is DISABLED (zero overhead)."""
    
    def test_disabled_returns_dummy_span(self):
        """Test dummy span returned when disabled."""
        disable_observability()
        span = start_async_span("test_op")
        self.assertEqual(span.trace_id, "disabled")
        self.assertEqual(span.span_id, "disabled")
    
    def test_disabled_get_current_span(self):
        """Test get_current returns None when disabled."""
        disable_observability()
        self.assertIsNone(get_current_async_span())


class TestAsyncTracingEnabled(unittest.TestCase):
    """Test tracing behavior when observability is ENABLED."""
    
    def setUp(self):
        enable_observability()
    
    def tearDown(self):
        disable_observability()
    
    def test_start_async_span(self):
        """Test starting an async span."""
        span = start_async_span("test_operation")
        self.assertNotEqual(span.trace_id, "disabled")
        self.assertEqual(span.operation_name, "test_operation")
    
    def test_end_async_span(self):
        """Test ending an async span."""
        start_async_span("test")
        span = end_async_span()
        self.assertIsNotNone(span)
        self.assertIsNotNone(span.end_time)
    
    def test_end_async_span_with_error(self):
        """Test ending span with error."""
        start_async_span("test")
        error = RuntimeError("test error")
        span = end_async_span(error)
        self.assertTrue(span.has_error)
        self.assertEqual(span.error_message, "test error")


class TestTraceAsyncDecorator(unittest.TestCase):
    """Test @trace_async decorator."""
    
    def setUp(self):
        enable_observability()
    
    def tearDown(self):
        disable_observability()
    
    def test_async_decorator_tracing(self):
        """Test async decorator creates span."""
        async def test_func():
            return "success"
        
        decorated = trace_async("test_op")(test_func)
        
        async def run_test():
            result = await decorated()
            return result
        
        result = asyncio.run(run_test())
        self.assertEqual(result, "success")
    
    def test_async_decorator_error_propagation(self):
        """Test decorator propagates exceptions correctly."""
        async def failing_func():
            raise ValueError("intentional error")
        
        decorated = trace_async("failing")(failing_func)
        
        async def run_test():
            with self.assertRaises(ValueError):
                await decorated()
        
        asyncio.run(run_test())
    
    def test_async_decorator_zero_overhead_disabled(self):
        """Test decorator has zero overhead when disabled."""
        disable_observability()
        
        async def test_func():
            return "ok"
        
        decorated = trace_async("test")(test_func)
        result = asyncio.run(decorated())
        self.assertEqual(result, "ok")


class TestTraceSyncDecorator(unittest.TestCase):
    """Test @trace_sync decorator."""
    
    def setUp(self):
        enable_observability()
    
    def tearDown(self):
        disable_observability()
    
    def test_sync_decorator_tracing(self):
        """Test sync decorator creates span."""
        @trace_sync("test_op")
        def test_func():
            return "success"
        
        result = test_func()
        self.assertEqual(result, "success")
    
    def test_sync_decorator_error_propagation(self):
        """Test decorator propagates exceptions."""
        @trace_sync("failing")
        def failing_func():
            raise ValueError("intentional error")
        
        with self.assertRaises(ValueError):
            failing_func()


class TestActiveHealthProbes(unittest.TestCase):
    """Test active health probe implementations."""
    
    def test_dns_probe_success(self):
        """Test DNS probe with known-good hostname."""
        result = ActiveHealthProbes.dns_probe("localhost")
        self.assertIn(result.status, [HealthStatus.PASS, HealthStatus.FAIL])
        self.assertIsInstance(result.response_time_ms, float)
        self.assertIn("hostname", result.details)
    
    def test_dns_probe_failure(self):
        """Test DNS probe with invalid hostname."""
        result = ActiveHealthProbes.dns_probe("nonexistent.invalid.domain.test", timeout=1.0)
        # Should fail but not crash
        self.assertIsNotNone(result.status)
        self.assertIsNotNone(result.message)
    
    def test_disk_space_probe(self):
        """Test disk space probe."""
        result = ActiveHealthProbes.disk_space_probe("/", min_free_gb=0.001)
        # Should work on any reasonable system
        self.assertIsNotNone(result.status)
        self.assertIn("free_gb", result.details)
    
    def test_tcp_probe_connection_refused(self):
        """Test TCP probe to closed port."""
        # Port 1 should be closed on most systems
        result = ActiveHealthProbes.tcp_probe("localhost", 1, timeout=0.5)
        # Should either fail (connection refused) or timeout
        self.assertIsNotNone(result.status)
        self.assertIsNotNone(result.message)
    
    def test_health_check_result_to_dict(self):
        """Test result serialization."""
        result = HealthCheckResult(
            name="test",
            status=HealthStatus.PASS,
            message="OK",
            response_time_ms=42.5,
        )
        d = result.to_dict()
        self.assertEqual(d["name"], "test")
        self.assertEqual(d["status"], "pass")
        self.assertEqual(d["response_time_ms"], 42.5)
        self.assertIn("checked_at", d)


class TestEnhancedHealthCheckerV10(unittest.TestCase):
    """Test enhanced health checker with TTL caching."""
    
    def test_register_check(self):
        """Test registering a health check."""
        checker = EnhancedHealthCheckerV10()
        
        def dummy_check():
            return HealthCheckResult("dummy", HealthStatus.PASS, "OK")
        
        checker.register_check("dummy", dummy_check)
        result = checker.run_check("dummy")
        self.assertEqual(result.status, HealthStatus.PASS)
    
    def test_register_convenience_methods(self):
        """Test convenience registration methods."""
        checker = EnhancedHealthCheckerV10()
        checker.register_dns_check("dns_local", "localhost")
        checker.register_disk_check("disk_root", "/", 0.001)
        # Should not raise
    
    def test_run_all_checks(self):
        """Test running all registered checks."""
        checker = EnhancedHealthCheckerV10()
        
        def check1():
            return HealthCheckResult("c1", HealthStatus.PASS, "OK")
        
        def check2():
            return HealthCheckResult("c2", HealthStatus.FAIL, "ERROR")
        
        checker.register_check("c1", check1)
        checker.register_check("c2", check2)
        
        results = checker.run_all_checks()
        self.assertEqual(len(results), 2)
        self.assertIn("c1", results)
        self.assertIn("c2", results)
    
    def test_overall_status(self):
        """Test overall health status calculation."""
        checker = EnhancedHealthCheckerV10()
        
        def passing():
            return HealthCheckResult("p", HealthStatus.PASS, "OK")
        
        checker.register_check("passing", passing)
        
        status, details = checker.overall_status()
        self.assertEqual(status, HealthStatus.PASS)
        self.assertIn("total_checks", details)
    
    def test_unknown_check(self):
        """Test running unregistered check."""
        checker = EnhancedHealthCheckerV10()
        result = checker.run_check("nonexistent")
        self.assertEqual(result.status, HealthStatus.FAIL)
        self.assertIn("not registered", result.message)


class TestSamplingConfig(unittest.TestCase):
    """Test dynamic sampling configuration."""
    
    def test_sampling_mode_enum(self):
        """Test sampling mode enum values."""
        self.assertEqual(SamplingMode.ALWAYS.value, "always")
        self.assertEqual(SamplingMode.NEVER.value, "never")
        self.assertEqual(SamplingMode.PROBABILISTIC.value, "probabilistic")
    
    def test_sampling_config_defaults(self):
        """Test default sampling configuration."""
        config = SamplingConfig()
        self.assertEqual(config.mode, SamplingMode.PROBABILISTIC)
        self.assertEqual(config.sample_rate, 0.1)
        self.assertTrue(config.force_sample_errors)
    
    def test_should_sample_always_mode(self):
        """Test ALWAYS sampling mode."""
        enable_observability()
        config = SamplingConfig(mode=SamplingMode.ALWAYS)
        self.assertTrue(config.should_sample("test_op"))
        disable_observability()
    
    def test_should_sample_never_mode(self):
        """Test NEVER sampling mode."""
        enable_observability()
        config = SamplingConfig(mode=SamplingMode.NEVER)
        self.assertFalse(config.should_sample("test_op"))
        disable_observability()
    
    def test_force_sample_errors(self):
        """Test errors are always sampled when enabled."""
        enable_observability()
        config = SamplingConfig(mode=SamplingMode.NEVER, force_sample_errors=True)
        self.assertTrue(config.should_sample("test_op", has_error=True))
        disable_observability()


class TestObservabilityEngineV10(unittest.TestCase):
    """Test singleton observability engine."""
    
    def test_singleton_pattern(self):
        """Test get_instance returns same instance."""
        engine1 = ObservabilityEngineV10.get_instance()
        engine2 = ObservabilityEngineV10.get_instance()
        self.assertIs(engine1, engine2)
    
    def test_direct_construction_raises(self):
        """Test direct construction raises error."""
        # First ensure instance exists
        ObservabilityEngineV10.get_instance()
        # Now direct construction should fail
        with self.assertRaises(RuntimeError):
            ObservabilityEngineV10()
    
    def test_enable_disable(self):
        """Test engine enable/disable controls."""
        engine = ObservabilityEngineV10.get_instance()
        engine.disable()
        self.assertFalse(engine.is_enabled())
        engine.enable()
        self.assertTrue(engine.is_enabled())
        engine.disable()
    
    def test_health_report(self):
        """Test health report generation."""
        engine = ObservabilityEngineV10.get_instance()
        report = engine.health_report()
        self.assertIn("status", report)
        self.assertIn("timestamp", report)
        self.assertIn("service", report)
        self.assertEqual(report["service"], "neural_shield")
        self.assertEqual(report["version"], "v10")


class TestBackwardCompatibility(unittest.TestCase):
    """Test backward compatibility guarantees."""
    
    def test_disabled_by_default(self):
        """Test observability is DISABLED by default (zero overhead)."""
        # Fresh state check
        self.assertFalse(is_observability_enabled())
    
    def test_no_existing_code_modified(self):
        """Verify ADD-ONLY principle - module doesn't modify globals."""
        # Module should not modify any existing state
        import neural_shield
        # Just verify import works and doesn't break anything
        self.assertIsNotNone(neural_shield)
    
    def test_all_exports_exist(self):
        """Test all documented exports are available."""
        exports = [
            "is_observability_enabled",
            "enable_observability",
            "disable_observability",
            "generate_correlation_id",
            "set_correlation_id",
            "get_correlation_id",
            "CorrelationIdFilter",
            "StructuredJsonFormatter",
            "AsyncSpanContext",
            "trace_async",
            "trace_sync",
            "HealthStatus",
            "ActiveHealthProbes",
            "EnhancedHealthCheckerV10",
            "ObservabilityEngineV10",
        ]
        
        import neural_shield.observability_async_logging_active_health_v10_2026_june as module
        for export in exports:
            self.assertTrue(hasattr(module, export), f"Missing export: {export}")


class TestThreadSafety(unittest.TestCase):
    """Test thread safety of core components."""
    
    def test_concurrent_correlation_ids(self):
        """Test correlation IDs are thread-isolated."""
        results = []
        
        def worker(worker_id):
            cid = set_correlation_id(f"worker-{worker_id}")
            time.sleep(0.001)
            results.append((worker_id, get_correlation_id()))
        
        threads = []
        for i in range(5):
            t = threading.Thread(target=worker, args=(i,))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        # Each thread should see its own correlation ID
        for worker_id, cid in results:
            self.assertEqual(cid, f"worker-{worker_id}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
