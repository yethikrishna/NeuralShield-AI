"""
Test Suite for Observability & Instrumentation v9
Covers: Baggage Context, SLO Engine, Latency Histograms, Tracing, Health Checks
ADD-ONLY - No existing tests modified
"""

import unittest
import time
import threading
import json
from typing import Dict, Any

# Import the new v9 module
from neural_shield.observability_enhanced_slo_baggage_v9_2026_june import (
    SamplingStrategy,
    SLOStatus,
    Severity,
    BaggageItem,
    SpanContext,
    SLOConfig,
    SLOState,
    LatencyHistogram,
    SlidingWindowCounter,
    HealthCheckStatus,
    HealthCheckResult,
    BaggageContext,
    TracerV9,
    SLOEngine,
    HealthCheckerV9,
    ObservabilityEngineV9,
    OBSERVABILITY_V9,
    enable_observability_v9,
    disable_observability_v9,
)


class TestSpanContextW3C(unittest.TestCase):
    """Test W3C TraceContext compatibility."""

    def test_traceparent_generation(self):
        """Test W3C traceparent header format."""
        ctx = SpanContext(
            trace_id="4bf92f3577b34da6a3ce929d0e0e4736",
            span_id="00f067aa0ba902b7",
            trace_flags=0x01
        )
        traceparent = ctx.to_w3c_traceparent()
        self.assertEqual(traceparent, "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")

    def test_traceparent_parsing_valid(self):
        """Test valid traceparent parsing."""
        traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
        ctx = SpanContext.from_w3c_traceparent(traceparent)
        self.assertIsNotNone(ctx)
        self.assertEqual(ctx.trace_id, "4bf92f3577b34da6a3ce929d0e0e4736")
        self.assertEqual(ctx.span_id, "00f067aa0ba902b7")
        self.assertEqual(ctx.trace_flags, 0x01)

    def test_traceparent_parsing_invalid(self):
        """Test invalid traceparent parsing."""
        ctx = SpanContext.from_w3c_traceparent("invalid-format")
        self.assertIsNone(ctx)

    def test_id_generation_format(self):
        """Test ID generation format."""
        trace_id = BaggageContext._generate_trace_id()
        span_id = BaggageContext._generate_span_id()
        self.assertEqual(len(trace_id), 32)  # 16 bytes hex
        self.assertEqual(len(span_id), 16)   # 8 bytes hex


class TestBaggageContext(unittest.TestCase):
    """Test cross-service baggage context propagation."""

    def test_baggage_add_get(self):
        """Test basic baggage operations."""
        ctx = BaggageContext.new_context()
        BaggageContext.set_current(ctx)

        BaggageContext.add_baggage("user_id", "u123", {"source": "auth"})
        BaggageContext.add_baggage("request_id", "r456")

        self.assertEqual(BaggageContext.get_baggage("user_id"), "u123")
        self.assertEqual(BaggageContext.get_baggage("request_id"), "r456")
        self.assertIsNone(BaggageContext.get_baggage("nonexistent"))

    def test_baggage_extract_dict(self):
        """Test baggage extraction as dict."""
        ctx = BaggageContext.new_context()
        BaggageContext.set_current(ctx)

        BaggageContext.add_baggage("key1", "value1")
        BaggageContext.add_baggage("key2", "value2")

        baggage = BaggageContext.extract_baggage_dict()
        self.assertEqual(baggage["key1"], "value1")
        self.assertEqual(baggage["key2"], "value2")

    def test_baggage_context_isolation(self):
        """Test that baggage is context isolated."""
        ctx1 = BaggageContext.new_context()
        BaggageContext.set_current(ctx1)
        BaggageContext.add_baggage("key", "from_ctx1")

        ctx2 = BaggageContext.new_context()
        BaggageContext.set_current(ctx2)
        BaggageContext.add_baggage("key", "from_ctx2")

        self.assertEqual(BaggageContext.get_baggage("key"), "from_ctx2")


class TestLatencyHistogram(unittest.TestCase):
    """Test percentile latency histogram."""

    def test_basic_recording(self):
        """Test basic latency recording."""
        hist = LatencyHistogram("test", buckets=10)
        hist.record(10.0)
        hist.record(20.0)
        hist.record(30.0)

        stats = hist.get_stats()
        self.assertEqual(stats["count"], 3)
        self.assertEqual(stats["sum"], 60.0)
        self.assertEqual(stats["avg"], 20.0)

    def test_percentile_calculation(self):
        """Test percentile calculation."""
        hist = LatencyHistogram("test", buckets=100)
        # Record 100 samples: 1ms to 100ms
        for i in range(1, 101):
            hist.record(float(i))

        stats = hist.get_stats()
        # p50 should be around 50ms
        self.assertGreater(stats["p50"], 45)
        self.assertLess(stats["p50"], 55)
        # p95 should be around 95ms
        self.assertGreater(stats["p95"], 90)
        self.assertLess(stats["p95"], 100)
        # p99 should be around 99ms
        self.assertGreater(stats["p99"], 95)

    def test_empty_histogram(self):
        """Test empty histogram behavior."""
        hist = LatencyHistogram("test")
        stats = hist.get_stats()
        self.assertEqual(stats["count"], 0)
        self.assertEqual(stats["p50"], 0.0)

    def test_thread_safety(self):
        """Test histogram under concurrent access."""
        hist = LatencyHistogram("concurrent_test")

        def record_many():
            for i in range(100):
                hist.record(float(i))

        threads = [threading.Thread(target=record_many) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        stats = hist.get_stats()
        self.assertEqual(stats["count"], 1000)


class TestSlidingWindowCounter(unittest.TestCase):
    """Test sliding window rate counter."""

    def test_basic_increment(self):
        """Test basic increment operation."""
        counter = SlidingWindowCounter(window_seconds=1.0, granularity=10)
        counter.increment()
        counter.increment()
        counter.increment()
        self.assertEqual(counter.get_count(), 3)

    def test_rate_calculation(self):
        """Test rate calculation."""
        counter = SlidingWindowCounter(window_seconds=60.0, granularity=60)
        for _ in range(60):
            counter.increment()
        rate = counter.get_rate()
        self.assertAlmostEqual(rate, 1.0, places=1)  # ~1 per second


class TestSLOEngine(unittest.TestCase):
    """Test SLO monitoring with error budget."""

    def test_slo_registration(self):
        """Test SLO registration."""
        engine = SLOEngine()
        config = SLOConfig(
            name="api_availability",
            target_success_rate=0.999,
            window_days=30.0
        )
        engine.register_slo(config)

        status = engine.get_slo_status("api_availability")
        self.assertIsNotNone(status)
        self.assertEqual(status.config.target_success_rate, 0.999)

    def test_slo_event_recording(self):
        """Test SLO event recording."""
        engine = SLOEngine()
        engine.register_slo(SLOConfig("test", 0.99))

        # Record 99 good, 1 bad = 99% success rate
        for _ in range(99):
            engine.record_event("test", is_good=True)
        engine.record_event("test", is_good=False)

        status = engine.get_slo_status("test")
        self.assertEqual(status.total_events, 100)
        self.assertEqual(status.good_events, 99)
        self.assertAlmostEqual(status.success_rate, 0.99, places=2)

    def test_slo_status_levels(self):
        """Test SLO status level transitions."""
        engine = SLOEngine()
        engine.register_slo(SLOConfig("test", 0.99))

        # Initially healthy
        status = engine.get_slo_status("test")
        self.assertEqual(status.status, SLOStatus.HEALTHY)

        # Consume most of error budget
        for _ in range(100):
            engine.record_event("test", is_good=False)

        # Should be critical or exhausted
        status = engine.get_slo_status("test")
        self.assertIn(status.status, [SLOStatus.CRITICAL, SLOStatus.EXHAUSTED])

    def test_get_all_slos(self):
        """Test getting all SLO statuses."""
        engine = SLOEngine()
        engine.register_slo(SLOConfig("slo1", 0.999))
        engine.register_slo(SLOConfig("slo2", 0.95))

        all_slos = engine.get_all_slos()
        self.assertIn("slo1", all_slos)
        self.assertIn("slo2", all_slos)


class TestHealthCheckerV9(unittest.TestCase):
    """Test health check framework with dependency trees."""

    def test_health_check_registration(self):
        """Test health check registration."""
        checker = HealthCheckerV9()

        def db_check():
            return HealthCheckResult("database", HealthCheckStatus.PASS, "Connected")

        checker.register_check("database", db_check)
        result = checker.check_component("database")
        self.assertEqual(result.status, HealthCheckStatus.PASS)
        self.assertEqual(result.output, "Connected")

    def test_health_check_dependency_propagation(self):
        """Test dependency failure propagation."""
        checker = HealthCheckerV9()

        def db_check():
            return HealthCheckResult("database", HealthCheckStatus.FAIL, "Connection refused")

        def api_check():
            return HealthCheckResult("api", HealthCheckStatus.PASS, "OK")

        checker.register_check("database", db_check)
        checker.register_check("api", api_check, depends_on=["database"])

        result = checker.check_component("api")
        # API should fail because database dependency failed
        self.assertEqual(result.status, HealthCheckStatus.FAIL)
        self.assertIn("database", result.output)

    def test_overall_status(self):
        """Test overall system health status."""
        checker = HealthCheckerV9()

        checker.register_check("component1", lambda: HealthCheckResult("c1", HealthCheckStatus.PASS))
        checker.register_check("component2", lambda: HealthCheckResult("c2", HealthCheckStatus.PASS))

        self.assertEqual(checker.get_overall_status(), HealthCheckStatus.PASS)

        # Add a failing component
        checker.register_check("component3", lambda: HealthCheckResult("c3", HealthCheckStatus.FAIL))
        self.assertEqual(checker.get_overall_status(), HealthCheckStatus.FAIL)

    def test_health_check_caching(self):
        """Test health check result caching."""
        checker = HealthCheckerV9()
        checker.cache_ttl = 1.0

        call_count = [0]

        def slow_check():
            call_count[0] += 1
            return HealthCheckResult("slow", HealthCheckStatus.PASS)

        checker.register_check("slow", slow_check)

        # Multiple calls should hit cache
        checker.check_component("slow")
        checker.check_component("slow")
        checker.check_component("slow")

        self.assertEqual(call_count[0], 1)


class TestTracerV9(unittest.TestCase):
    """Test enhanced distributed tracer."""

    def test_tracing_disabled_by_default(self):
        """Test that tracing is disabled by default (OPT-IN)."""
        tracer = TracerV9("test")
        self.assertFalse(tracer.enabled)

    def test_start_end_span(self):
        """Test basic span lifecycle."""
        tracer = TracerV9("test")
        tracer.enable()
        tracer.sampling_strategy = SamplingStrategy.ALWAYS

        ctx = tracer.start_span("test_operation")
        time.sleep(0.001)
        tracer.end_span(ctx)

        metrics = tracer.get_metrics()
        self.assertGreater(metrics["requests_per_minute"], 0)

    def test_parent_child_spans(self):
        """Test parent-child span relationships."""
        tracer = TracerV9("test")
        tracer.enable()
        tracer.sampling_strategy = SamplingStrategy.ALWAYS

        parent_ctx = tracer.start_span("parent")
        child_ctx = tracer.start_span("child", parent_context=parent_ctx)

        self.assertEqual(child_ctx.trace_id, parent_ctx.trace_id)
        self.assertEqual(child_ctx.parent_span_id, parent_ctx.span_id)

        tracer.end_span(child_ctx)
        tracer.end_span(parent_ctx)

    def test_error_tracking(self):
        """Test error tracking in spans."""
        tracer = TracerV9("test")
        tracer.enable()
        tracer.sampling_strategy = SamplingStrategy.ALWAYS

        ctx = tracer.start_span("failing_op")
        try:
            raise ValueError("Test error")
        except Exception as e:
            tracer.end_span(ctx, error=e)

        metrics = tracer.get_metrics()
        self.assertGreater(metrics["errors_per_minute"], 0)

    def test_prometheus_export(self):
        """Test Prometheus format export."""
        tracer = TracerV9("test_service")
        tracer.enable()
        tracer.sampling_strategy = SamplingStrategy.ALWAYS

        for i in range(10):
            ctx = tracer.start_span(f"op_{i}")
            tracer.end_span(ctx)

        prom = tracer.export_prometheus_format()
        self.assertIn("test_service_requests_total", prom)
        self.assertIn("test_service_errors_total", prom)
        self.assertIn("test_service_latency_p50ms", prom)

    def test_sampling_strategies(self):
        """Test different sampling strategies."""
        tracer = TracerV9("test")
        tracer.enable()

        # NEVER strategy - no sampling
        tracer.sampling_strategy = SamplingStrategy.NEVER
        for _ in range(100):
            ctx = tracer.start_span("test")
            tracer.end_span(ctx)
        self.assertEqual(len(tracer.spans), 0)

        # ALWAYS strategy - sample everything
        tracer.sampling_strategy = SamplingStrategy.ALWAYS
        for _ in range(10):
            ctx = tracer.start_span("test")
            tracer.end_span(ctx)
        self.assertGreater(len(tracer.spans), 0)


class TestObservabilityEngineV9(unittest.TestCase):
    """Test unified observability engine."""

    def test_singleton_pattern(self):
        """Test singleton pattern enforcement."""
        engine1 = ObservabilityEngineV9("test1")
        engine2 = ObservabilityEngineV9("test2")
        self.assertIs(engine1, engine2)

    def test_enable_disable(self):
        """Test enable/disable functionality."""
        engine = ObservabilityEngineV9("test")
        self.assertFalse(engine.enabled)

        engine.enable()
        self.assertTrue(engine.enabled)
        self.assertTrue(engine.tracer.enabled)

        engine.disable()
        self.assertFalse(engine.enabled)
        self.assertFalse(engine.tracer.enabled)

    def test_trace_decorator(self):
        """Test trace decorator functionality."""
        engine = ObservabilityEngineV9("test")
        engine.enable()
        engine.tracer.sampling_strategy = SamplingStrategy.ALWAYS

        @engine.trace_decorator("decorated_function")
        def test_func(x, y):
            return x + y

        result = test_func(2, 3)
        self.assertEqual(result, 5)

        metrics = engine.tracer.get_metrics()
        self.assertGreater(metrics["requests_per_minute"], 0)

    def test_custom_metrics(self):
        """Test custom gauge and counter metrics."""
        engine = ObservabilityEngineV9("test")
        engine.enable()

        engine.record_gauge("memory_usage_mb", 256.5, {"instance": "worker-1"})
        engine.increment_counter("api_calls", 5)

        metrics = engine.get_full_metrics()
        self.assertIn("memory_usage_mb", metrics["custom_gauges"])
        self.assertIn("api_calls", metrics["custom_counters"])

    def test_full_metrics_export(self):
        """Test full metrics snapshot export."""
        engine = ObservabilityEngineV9("test")
        engine.enable()

        # Record some activity
        engine.tracer.sampling_strategy = SamplingStrategy.ALWAYS
        ctx = engine.start_trace("test_op")
        engine.end_trace(ctx)

        metrics = engine.get_full_metrics()
        self.assertIn("service", metrics)
        self.assertIn("tracing", metrics)
        self.assertIn("slos", metrics)
        self.assertIn("health", metrics)
        self.assertIn("timestamp", metrics)

    def test_json_export(self):
        """Test JSON export format."""
        engine = ObservabilityEngineV9("test")
        json_str = engine.export_json()
        data = json.loads(json_str)
        self.assertIn("service", data)


class TestBackwardCompatibility(unittest.TestCase):
    """Test backward compatibility with previous versions."""

    def test_global_instance_access(self):
        """Test global singleton access."""
        self.assertIsNotNone(OBSERVABILITY_V9)
        self.assertIsInstance(OBSERVABILITY_V9, ObservabilityEngineV9)

    def test_enable_disable_functions(self):
        """Test convenience functions."""
        # These should not raise exceptions
        enable_observability_v9()
        disable_observability_v9()

    def test_zero_overhead_when_disabled(self):
        """Verify zero overhead when disabled."""
        engine = ObservabilityEngineV9("test")
        engine.disable()

        # Operations should work but have no effect
        ctx = engine.start_trace("should_not_record")
        engine.end_trace(ctx)
        engine.record_gauge("should_not_record", 1.0)
        engine.increment_counter("should_not_record")

        metrics = engine.get_full_metrics()
        self.assertFalse(metrics["enabled"])


class TestThreadSafety(unittest.TestCase):
    """Test thread safety of all components."""

    def test_concurrent_tracing(self):
        """Test concurrent tracing operations."""
        engine = ObservabilityEngineV9("concurrent_test")
        engine.enable()
        engine.tracer.sampling_strategy = SamplingStrategy.ALWAYS

        def worker():
            for i in range(50):
                ctx = engine.start_trace(f"worker_op_{i}")
                engine.end_trace(ctx)

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        metrics = engine.tracer.get_metrics()
        self.assertEqual(metrics["requests_per_minute"], 500)

    def test_concurrent_slo_recording(self):
        """Test concurrent SLO event recording."""
        engine = SLOEngine()
        engine.register_slo(SLOConfig("concurrent_slo", 0.999))

        def record_events():
            for i in range(100):
                engine.record_event("concurrent_slo", is_good=(i % 10 != 0))

        threads = [threading.Thread(target=record_events) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        status = engine.get_slo_status("concurrent_slo")
        self.assertEqual(status.total_events, 1000)


if __name__ == "__main__":
    unittest.main(verbosity=2)
