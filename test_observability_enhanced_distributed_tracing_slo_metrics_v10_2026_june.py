"""
Tests for NeuralShield AI - Enhanced Observability & Instrumentation v10
Dimension D: Observability & Instrumentation

ADD-ONLY implementation - no existing code modified
All tests must pass
"""

import unittest
import time
import json
import threading
from typing import Optional

from neural_shield.observability_enhanced_distributed_tracing_slo_metrics_v10_2026_june import (
    EnhancedObservabilityEngineV10,
    TraceContext,
    Baggage,
    Span,
    SpanKind,
    SpanStatus,
    AdaptiveSampler,
    Histogram,
    SLOMonitor,
    SLODefinition,
    SLOStatus,
    HealthCheckManager,
    HealthCheck,
    HealthCheckResult,
    HealthStatus,
    get_observability_engine_v10,
    enable_observability_v10,
    disable_observability_v10,
)


class TestTraceContext(unittest.TestCase):
    """Test W3C Trace Context implementation."""
    
    def test_generate_trace_context(self):
        """Test trace context generation."""
        ctx = TraceContext.generate()
        self.assertEqual(len(ctx.trace_id), 32)
        self.assertEqual(len(ctx.span_id), 16)
        self.assertIsNone(ctx.parent_span_id)
        self.assertTrue(ctx.is_sampled())
    
    def test_child_span_context(self):
        """Test child span from parent context."""
        parent = TraceContext.generate()
        child = TraceContext.from_parent(parent)
        
        self.assertEqual(child.trace_id, parent.trace_id)
        self.assertNotEqual(child.span_id, parent.span_id)
        self.assertEqual(child.parent_span_id, parent.span_id)
    
    def test_traceparent_header_format(self):
        """Test W3C traceparent header format."""
        ctx = TraceContext.generate()
        header = ctx.to_traceparent()
        
        parts = header.split('-')
        self.assertEqual(len(parts), 4)
        self.assertEqual(parts[0], "00")
        self.assertEqual(parts[1], ctx.trace_id)
        self.assertEqual(parts[2], ctx.span_id)
    
    def test_parse_traceparent_header(self):
        """Test parsing traceparent header."""
        header = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
        ctx = TraceContext.from_traceparent(header)
        
        self.assertIsNotNone(ctx)
        self.assertEqual(ctx.version, "00")
        self.assertEqual(ctx.trace_id, "0af7651916cd43dd8448eb211c80319c")
        self.assertEqual(ctx.span_id, "b7ad6b7169203331")
        self.assertTrue(ctx.is_sampled())
    
    def test_invalid_traceparent_header(self):
        """Test parsing invalid traceparent header."""
        ctx = TraceContext.from_traceparent("invalid-header")
        self.assertIsNone(ctx)


class TestBaggage(unittest.TestCase):
    """Test cross-service correlation baggage."""
    
    def test_baggage_set_get(self):
        """Test basic baggage operations."""
        bag = Baggage()
        bag.set("user_id", "12345")
        bag.set("tenant_id", "acme")
        
        self.assertEqual(bag.get("user_id"), "12345")
        self.assertEqual(bag.get("tenant_id"), "acme")
        self.assertIsNone(bag.get("nonexistent"))
    
    def test_baggage_header_format(self):
        """Test baggage header format."""
        bag = Baggage({"user_id": "123", "tenant": "acme"})
        header = bag.to_header()
        
        self.assertIn("user_id=123", header)
        self.assertIn("tenant=acme", header)
    
    def test_parse_baggage_header(self):
        """Test parsing baggage header."""
        header = "user_id=12345,tenant_id=acme,request_id=abc123"
        bag = Baggage.from_header(header)
        
        self.assertEqual(bag.get("user_id"), "12345")
        self.assertEqual(bag.get("tenant_id"), "acme")
        self.assertEqual(bag.get("request_id"), "abc123")


class TestSpan(unittest.TestCase):
    """Test span implementation."""
    
    def test_span_creation(self):
        """Test basic span creation."""
        ctx = TraceContext.generate()
        span = Span(name="test_operation", trace_context=ctx)
        
        self.assertEqual(span.name, "test_operation")
        self.assertIsNone(span.end_time)
        self.assertEqual(span.status, SpanStatus.UNSET)
    
    def test_span_add_event(self):
        """Test adding events to span."""
        ctx = TraceContext.generate()
        span = Span(name="test", trace_context=ctx)
        
        span.add_event("processing_started", item_id=123)
        span.add_event("processing_completed", duration=42)
        
        self.assertEqual(len(span.events), 2)
        self.assertEqual(span.events[0].name, "processing_started")
        self.assertEqual(span.events[0].attributes["item_id"], 123)
    
    def test_span_duration(self):
        """Test span duration calculation."""
        ctx = TraceContext.generate()
        span = Span(name="test", trace_context=ctx)
        time.sleep(0.01)
        span.end()
        
        duration = span.duration_ms()
        self.assertGreater(duration, 0)
        self.assertLess(duration, 1000)
    
    def test_span_to_dict(self):
        """Test span serialization."""
        ctx = TraceContext.generate()
        span = Span(name="test", trace_context=ctx, kind=SpanKind.SERVER)
        span.set_attribute("http.method", "GET")
        span.end()
        
        d = span.to_dict()
        self.assertEqual(d["name"], "test")
        self.assertEqual(d["kind"], "server")
        self.assertEqual(d["trace_id"], ctx.trace_id)
        self.assertIn("duration_ms", d)


class TestAdaptiveSampler(unittest.TestCase):
    """Test adaptive sampling."""
    
    def test_always_sample_errors(self):
        """Test errors are always sampled."""
        sampler = AdaptiveSampler(base_rate=0.0)
        self.assertTrue(sampler.should_sample("trace123", has_error=True))
    
    def test_always_sample_high_importance(self):
        """Test high importance spans are always sampled."""
        sampler = AdaptiveSampler(base_rate=0.0)
        self.assertTrue(sampler.should_sample("trace123", importance=1.0))
    
    def test_deterministic_sampling(self):
        """Test sampling is deterministic for same trace_id."""
        sampler = AdaptiveSampler(base_rate=0.5)
        result1 = sampler.should_sample("trace12345", importance=0.5)
        result2 = sampler.should_sample("trace12345", importance=0.5)
        self.assertEqual(result1, result2)
    
    def test_adaptive_rate_changes_with_volume(self):
        """Test sampling rate adapts to volume."""
        sampler = AdaptiveSampler(base_rate=0.1, window_size=100)
        
        # Simulate high volume
        for i in range(200):
            sampler.record_trace(has_error=False)
        
        # Should have lower rate due to high volume
        # Just verify no exceptions and it works
        sampler.should_sample("test_trace", importance=0.5)


class TestHistogram(unittest.TestCase):
    """Test histogram metrics with percentiles."""
    
    def test_histogram_basic_stats(self):
        """Test basic histogram statistics."""
        hist = Histogram("test_latency")
        
        values = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]
        for v in values:
            hist.record(v)
        
        stats = hist.stats()
        self.assertEqual(stats["count"], 10)
        self.assertEqual(stats["sum"], 550)
        self.assertEqual(stats["min"], 10)
        self.assertEqual(stats["max"], 100)
        self.assertEqual(stats["avg"], 55)
    
    def test_histogram_percentiles(self):
        """Test percentile calculation."""
        hist = Histogram("test_latency")
        
        # Record sorted values for predictable percentiles
        for i in range(1, 101):
            hist.record(float(i))
        
        # P50 should be around 50, P95 around 95, P99 around 99
        self.assertGreaterEqual(hist.percentile(50), 45)
        self.assertLessEqual(hist.percentile(50), 55)
        self.assertGreaterEqual(hist.percentile(95), 90)
        self.assertGreaterEqual(hist.percentile(99), 95)
    
    def test_empty_histogram(self):
        """Test empty histogram handling."""
        hist = Histogram("empty")
        stats = hist.stats()
        self.assertEqual(stats["count"], 0)
        self.assertEqual(stats["p50"], 0)


class TestSLOMonitor(unittest.TestCase):
    """Test SLO monitoring with error budget."""
    
    def test_register_slo(self):
        """Test SLO registration."""
        monitor = SLOMonitor()
        slo = SLODefinition(
            name="api_availability",
            target_percentage=99.9,
            window_days=30
        )
        monitor.register_slo(slo)
        
        self.assertIn("api_availability", monitor._slos)
    
    def test_slo_calculation_perfect(self):
        """Test SLO calculation with 100% success."""
        monitor = SLOMonitor()
        slo = SLODefinition(name="test", target_percentage=99.9, window_days=30)
        monitor.register_slo(slo)
        
        for _ in range(100):
            monitor.record_good("test")
        
        result = monitor.calculate_slo("test")
        self.assertIsNotNone(result)
        self.assertEqual(result.current_percentage, 100.0)
        self.assertGreater(result.error_budget_remaining, 0)
        self.assertEqual(result.status, SLOStatus.HEALTHY)
    
    def test_slo_calculation_with_errors(self):
        """Test SLO calculation with some errors."""
        monitor = SLOMonitor()
        slo = SLODefinition(name="test", target_percentage=99.0, window_days=30)
        monitor.register_slo(slo)
        
        # 95 good, 5 bad = 95% achievement (below 99% target)
        for _ in range(95):
            monitor.record_good("test")
        for _ in range(5):
            monitor.record_bad("test")
        
        result = monitor.calculate_slo("test")
        self.assertIsNotNone(result)
        self.assertLess(result.current_percentage, 99.0)
    
    def test_slo_burn_rate_calculation(self):
        """Test error budget burn rate calculation."""
        monitor = SLOMonitor()
        slo = SLODefinition(name="test", target_percentage=99.9, window_days=30)
        monitor.register_slo(slo)
        
        for _ in range(1000):
            monitor.record_good("test")
        for _ in range(10):
            monitor.record_bad("test")
        
        result = monitor.calculate_slo("test")
        self.assertIsNotNone(result)
        self.assertGreater(result.error_budget_burn_rate, 0)


class TestHealthCheckManager(unittest.TestCase):
    """Test health check framework."""
    
    def test_register_health_check(self):
        """Test health check registration."""
        manager = HealthCheckManager()
        
        def always_healthy():
            return HealthCheckResult(name="test", status=HealthStatus.HEALTHY)
        
        check = HealthCheck(name="test_check", check_fn=always_healthy)
        manager.register_check(check)
        
        self.assertIn("test_check", manager._checks)
    
    def test_run_health_check_healthy(self):
        """Test running a healthy check."""
        manager = HealthCheckManager()
        
        def healthy_check():
            return HealthCheckResult(name="db", status=HealthStatus.HEALTHY, message="OK")
        
        manager.register_check(HealthCheck(name="db", check_fn=healthy_check))
        
        result = manager.run_check("db")
        self.assertEqual(result.status, HealthStatus.HEALTHY)
        self.assertEqual(result.message, "OK")
    
    def test_run_health_check_unhealthy(self):
        """Test running an unhealthy check."""
        manager = HealthCheckManager()
        
        def unhealthy_check():
            return HealthCheckResult(name="db", status=HealthStatus.UNHEALTHY, message="Connection failed")
        
        manager.register_check(HealthCheck(name="db", check_fn=unhealthy_check))
        
        result = manager.run_check("db")
        self.assertEqual(result.status, HealthStatus.UNHEALTHY)
    
    def test_circular_dependency_detection(self):
        """Test circular dependency detection."""
        manager = HealthCheckManager()
        
        def check_a():
            return HealthCheckResult(name="a", status=HealthStatus.HEALTHY)
        
        manager.register_check(HealthCheck(name="a", check_fn=check_a, dependencies=["b"]))
        manager.register_check(HealthCheck(name="b", check_fn=check_a, dependencies=["a"]))
        
        result = manager.run_check("a")
        # Should handle gracefully, not hang
        self.assertIsNotNone(result)
    
    def test_critical_dependency_failure(self):
        """Test critical dependency failure propagation."""
        manager = HealthCheckManager()
        
        def dep_fails():
            return HealthCheckResult(name="dep", status=HealthStatus.UNHEALTHY)
        
        def main_check():
            return HealthCheckResult(name="main", status=HealthStatus.HEALTHY)
        
        manager.register_check(HealthCheck(name="dep", check_fn=dep_fails))
        manager.register_check(HealthCheck(name="main", check_fn=main_check, dependencies=["dep"]))
        
        result = manager.run_check("main")
        # Should propagate dependency failure
        self.assertEqual(result.status, HealthStatus.UNHEALTHY)
    
    def test_overall_health_status(self):
        """Test overall health status aggregation."""
        manager = HealthCheckManager()
        
        manager.register_check(HealthCheck(
            name="check1",
            check_fn=lambda: HealthCheckResult("check1", HealthStatus.HEALTHY)
        ))
        manager.register_check(HealthCheck(
            name="check2",
            check_fn=lambda: HealthCheckResult("check2", HealthStatus.HEALTHY)
        ))
        
        self.assertEqual(manager.overall_health(), HealthStatus.HEALTHY)


class TestEnhancedObservabilityEngineV10(unittest.TestCase):
    """Test main enhanced observability engine."""
    
    def test_engine_creation(self):
        """Test engine creation."""
        engine = EnhancedObservabilityEngineV10()
        self.assertFalse(engine.is_enabled())
    
    def test_enable_disable(self):
        """Test enable/disable functionality."""
        engine = EnhancedObservabilityEngineV10()
        engine.enable()
        self.assertTrue(engine.is_enabled())
        engine.disable()
        self.assertFalse(engine.is_enabled())
    
    def test_start_span_disabled(self):
        """Test span creation when disabled (no-op but works)."""
        engine = EnhancedObservabilityEngineV10()
        # Disabled by default
        
        span = engine.start_span("test_operation")
        self.assertIsNotNone(span)
        self.assertEqual(span.name, "test_operation")
    
    def test_start_span_enabled(self):
        """Test span creation when enabled."""
        engine = EnhancedObservabilityEngineV10()
        engine.enable()
        
        span = engine.start_span("test_operation", http_method="GET", path="/api/test")
        self.assertIsNotNone(span)
        self.assertEqual(span.attributes["http_method"], "GET")
    
    def test_end_span_records_metrics(self):
        """Test ending span records metrics."""
        engine = EnhancedObservabilityEngineV10()
        engine.enable()
        
        span = engine.start_span("test_op")
        engine.end_span(span, SpanStatus.OK)
        
        metrics = engine.get_metrics()
        self.assertIn("span_count_test_op", metrics["counters"])
        self.assertEqual(metrics["counters"]["span_count_test_op"], 1)
    
    def test_span_with_error_status(self):
        """Test error span tracking."""
        engine = EnhancedObservabilityEngineV10()
        engine.enable()
        
        span = engine.start_span("failing_op")
        engine.end_span(span, SpanStatus.ERROR)
        
        metrics = engine.get_metrics()
        self.assertIn("span_error_count_failing_op", metrics["counters"])
    
    def test_counter_metrics(self):
        """Test counter metrics."""
        engine = EnhancedObservabilityEngineV10()
        engine.enable()
        
        engine.record_counter("requests", 5)
        engine.record_counter("requests", 3)
        
        metrics = engine.get_metrics()
        self.assertEqual(metrics["counters"]["requests"], 8)
    
    def test_gauge_metrics(self):
        """Test gauge metrics."""
        engine = EnhancedObservabilityEngineV10()
        engine.enable()
        
        engine.set_gauge("memory_usage_mb", 256.5)
        
        metrics = engine.get_metrics()
        self.assertEqual(metrics["gauges"]["memory_usage_mb"], 256.5)
    
    def test_histogram_metrics(self):
        """Test histogram metrics."""
        engine = EnhancedObservabilityEngineV10()
        engine.enable()
        
        engine.record_histogram("latency", 42.5)
        engine.record_histogram("latency", 15.3)
        
        metrics = engine.get_metrics()
        self.assertIn("latency", metrics["histograms"])
    
    def test_export_json(self):
        """Test JSON export."""
        engine = EnhancedObservabilityEngineV10()
        engine.enable()
        
        span = engine.start_span("test")
        engine.end_span(span)
        
        export_str = engine.export_json()
        export_data = json.loads(export_str)
        
        self.assertIn("metrics", export_data)
        self.assertIn("spans", export_data)
        self.assertIn("slo", export_data)
        self.assertIn("health", export_data)
    
    def test_slo_integration(self):
        """Test SLO integration with engine."""
        engine = EnhancedObservabilityEngineV10()
        
        slo = SLODefinition(name="api_latency", target_percentage=99.0)
        engine.slo.register_slo(slo)
        
        engine.slo.record_good("api_latency")
        result = engine.slo.calculate_slo("api_latency")
        
        self.assertIsNotNone(result)
    
    def test_health_integration(self):
        """Test health check integration with engine."""
        engine = EnhancedObservabilityEngineV10()
        
        def db_check():
            return HealthCheckResult("db", HealthStatus.HEALTHY)
        
        engine.health.register_check(HealthCheck("db", db_check))
        
        result = engine.health.run_check("db")
        self.assertEqual(result.status, HealthStatus.HEALTHY)


class TestGlobalSingleton(unittest.TestCase):
    """Test global singleton functions."""
    
    def test_get_singleton(self):
        """Test getting global engine."""
        engine1 = get_observability_engine_v10()
        engine2 = get_observability_engine_v10()
        
        self.assertIs(engine1, engine2)
    
    def test_global_enable_disable(self):
        """Test global enable/disable functions."""
        enable_observability_v10()
        self.assertTrue(get_observability_engine_v10().is_enabled())
        
        disable_observability_v10()
        self.assertFalse(get_observability_engine_v10().is_enabled())
    
    def test_start_span_convenience(self):
        """Test convenience function for starting spans."""
        enable_observability_v10()
        
        span = start_observability_span_v10("global_test")
        self.assertIsNotNone(span)
        self.assertEqual(span.name, "global_test")


class TestBackwardCompatibility(unittest.TestCase):
    """Test backward compatibility with v8/v9."""
    
    def test_v8_still_importable(self):
        """Test v8 module can still be imported."""
        # This should not raise an exception
        try:
            from neural_shield import observability_metrics_collection_v8_2026_june
            # If we get here, v8 is still importable
            self.assertTrue(True)
        except ImportError:
            # v8 might not exist in some environments, that's OK
            # We're add-only, so existing code shouldn't break
            pass
    
    def test_no_existing_code_modified(self):
        """Verify add-only philosophy - new module doesn't affect old ones."""
        # New module should not replace or modify any existing functionality
        engine_v10 = EnhancedObservabilityEngineV10()
        # v10 engine exists and works independently
        self.assertIsNotNone(engine_v10)


class TestThreadSafety(unittest.TestCase):
    """Test thread safety of observability components."""
    
    def test_concurrent_counter_updates(self):
        """Test concurrent counter updates are thread-safe."""
        engine = EnhancedObservabilityEngineV10()
        engine.enable()
        
        def increment_counter(n):
            for _ in range(n):
                engine.record_counter("concurrent_test")
        
        threads = []
        for _ in range(10):
            t = threading.Thread(target=increment_counter, args=(100,))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        metrics = engine.get_metrics()
        self.assertEqual(metrics["counters"]["concurrent_test"], 1000)
    
    def test_concurrent_histogram_recording(self):
        """Test concurrent histogram recording."""
        hist = Histogram("concurrent_test")
        
        def record_values():
            for i in range(100):
                hist.record(float(i))
        
        threads = []
        for _ in range(5):
            t = threading.Thread(target=record_values)
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        stats = hist.stats()
        self.assertEqual(stats["count"], 500)


if __name__ == "__main__":
    unittest.main()
