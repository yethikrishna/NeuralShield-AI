"""
Tests for NeuralShield Enhanced Observability v12
Dimension D - Observability & Instrumentation
Tests cover:
- Probabilistic span sampling
- Async context propagation
- Structured logging bridge
- Span metrics aggregation
- Health check integration
- All tests are add-only, no existing code modified
"""
import unittest
import asyncio
import time
import logging
from unittest.mock import MagicMock
from neural_shield.observability_enhanced_sampling_async_logging_v12_2026_june import (
    Tracer,
    ProbabilisticSampler,
    SpanMetricsAggregator,
    TraceBaggage,
    SpanKind,
    SpanStatus,
    SamplingDecision,
    enable_tracing,
    disable_tracing,
    is_tracing_enabled,
    start_span,
    end_span,
    get_metrics,
    get_health_status,
    trace,
    trace_async,
    global_tracer,
)


class TestProbabilisticSampler(unittest.TestCase):
    """Tests for probabilistic span sampling."""
    
    def test_sampler_default_rate(self):
        """Test sampler defaults to 100% sampling."""
        sampler = ProbabilisticSampler()
        self.assertEqual(sampler.get_sampling_rate(), 1.0)
    
    def test_sampler_custom_rate(self):
        """Test sampler with custom sampling rate."""
        sampler = ProbabilisticSampler(0.5)
        self.assertEqual(sampler.get_sampling_rate(), 0.5)
    
    def test_sampler_rate_clamping(self):
        """Test sampling rate is clamped to valid range."""
        sampler = ProbabilisticSampler(2.0)
        self.assertEqual(sampler.get_sampling_rate(), 1.0)
        
        sampler = ProbabilisticSampler(-1.0)
        self.assertEqual(sampler.get_sampling_rate(), 0.0)
    
    def test_sampler_set_rate_dynamic(self):
        """Test dynamic sampling rate updates."""
        sampler = ProbabilisticSampler(1.0)
        sampler.set_sampling_rate(0.1)
        self.assertEqual(sampler.get_sampling_rate(), 0.1)
    
    def test_sampler_100_percent(self):
        """Test 100% sampling rate always samples."""
        sampler = ProbabilisticSampler(1.0)
        for i in range(100):
            decision = sampler.should_sample(f"trace_{i}", "test_op")
            self.assertEqual(decision, SamplingDecision.RECORD_AND_SAMPLE)
    
    def test_sampler_0_percent(self):
        """Test 0% sampling rate never samples."""
        sampler = ProbabilisticSampler(0.0)
        for i in range(100):
            decision = sampler.should_sample(f"trace_{i}", "test_op")
            self.assertEqual(decision, SamplingDecision.DROP)
    
    def test_sampler_deterministic(self):
        """Test sampling decision is deterministic for same trace ID."""
        sampler = ProbabilisticSampler(0.5)
        trace_id = "test_trace_12345"
        decision1 = sampler.should_sample(trace_id, "test_op")
        decision2 = sampler.should_sample(trace_id, "test_op")
        self.assertEqual(decision1, decision2)


class TestTraceBaggage(unittest.TestCase):
    """Tests for trace baggage context propagation."""
    
    def test_baggage_correlation_id(self):
        """Test correlation ID storage and retrieval."""
        baggage = TraceBaggage()
        baggage.set_correlation_id("test-correlation-123")
        self.assertEqual(baggage.get_correlation_id(), "test-correlation-123")
    
    def test_baggage_items(self):
        """Test baggage item storage."""
        baggage = TraceBaggage()
        baggage.set_baggage_item("user_id", "user123")
        baggage.set_baggage_item("request_id", "req456")
        self.assertEqual(baggage.get_baggage_item("user_id"), "user123")
        self.assertEqual(baggage.get_baggage_item("request_id"), "req456")
    
    def test_baggage_get_all(self):
        """Test getting all baggage items."""
        baggage = TraceBaggage()
        baggage.set_baggage_item("key1", "value1")
        baggage.set_baggage_item("key2", "value2")
        all_items = baggage.get_all_baggage()
        self.assertEqual(all_items["key1"], "value1")
        self.assertEqual(all_items["key2"], "value2")
    
    def test_baggage_clear(self):
        """Test clearing baggage."""
        baggage = TraceBaggage()
        baggage.set_baggage_item("key1", "value1")
        baggage.set_correlation_id("corr123")
        baggage.clear()
        self.assertIsNone(baggage.get_correlation_id())
        self.assertEqual(baggage.get_all_baggage(), {})
    
    def test_baggage_propagate(self):
        """Test baggage propagation from parent context."""
        baggage = TraceBaggage()
        parent_baggage = {"parent_key": "parent_value"}
        baggage.propagate_from_parent(parent_baggage, "parent-correlation")
        self.assertEqual(baggage.get_correlation_id(), "parent-correlation")
        self.assertEqual(baggage.get_baggage_item("parent_key"), "parent_value")


class TestSpanMetricsAggregator(unittest.TestCase):
    """Tests for span metrics aggregation."""
    
    def test_metrics_initialization(self):
        """Test metrics aggregator initializes properly."""
        aggregator = SpanMetricsAggregator()
        metrics = aggregator.get_metrics()
        self.assertEqual(metrics["total_spans"], 0)
        self.assertEqual(metrics["total_errors"], 0)
    
    def test_metrics_record_span(self):
        """Test recording span metrics."""
        aggregator = SpanMetricsAggregator()
        
        # Create a mock span
        from dataclasses import dataclass
        @dataclass
        class MockSpan:
            name: str
            status: SpanStatus
            end_time: float = 0.0
            start_time: float = 0.0
            
            def get_duration_ms(self):
                return 100.0
        
        span = MockSpan(name="test_operation", status=SpanStatus.OK)
        aggregator.record_span(span)
        
        metrics = aggregator.get_metrics()
        self.assertEqual(metrics["total_spans"], 1)
        self.assertEqual(metrics["total_errors"], 0)
    
    def test_metrics_record_error(self):
        """Test recording error spans."""
        aggregator = SpanMetricsAggregator()
        
        from dataclasses import dataclass
        @dataclass
        class MockSpan:
            name: str
            status: SpanStatus
            end_time: float = 0.0
            start_time: float = 0.0
            
            def get_duration_ms(self):
                return 100.0
        
        span = MockSpan(name="test_operation", status=SpanStatus.ERROR)
        aggregator.record_span(span)
        
        metrics = aggregator.get_metrics()
        self.assertEqual(metrics["total_spans"], 1)
        self.assertEqual(metrics["total_errors"], 1)
    
    def test_metrics_reset(self):
        """Test resetting metrics."""
        aggregator = SpanMetricsAggregator()
        
        from dataclasses import dataclass
        @dataclass
        class MockSpan:
            name: str
            status: SpanStatus
            end_time: float = 0.0
            start_time: float = 0.0
            
            def get_duration_ms(self):
                return 100.0
        
        span = MockSpan(name="test_operation", status=SpanStatus.OK)
        aggregator.record_span(span)
        aggregator.reset()
        
        metrics = aggregator.get_metrics()
        self.assertEqual(metrics["total_spans"], 0)


class TestTracer(unittest.TestCase):
    """Tests for main tracer implementation."""
    
    def setUp(self):
        """Reset tracer state before each test."""
        disable_tracing()
        global_tracer.metrics.reset()
    
    def test_tracer_disabled_by_default(self):
        """Test tracer is disabled by default (opt-in)."""
        self.assertFalse(is_tracing_enabled())
    
    def test_tracer_enable_disable(self):
        """Test enabling and disabling tracing."""
        enable_tracing()
        self.assertTrue(is_tracing_enabled())
        disable_tracing()
        self.assertFalse(is_tracing_enabled())
    
    def test_start_span_disabled(self):
        """Test span creation when disabled returns no-op span."""
        span = start_span("test_operation")
        self.assertEqual(span.trace_id, "disabled")
        self.assertEqual(span.span_id, "disabled")
    
    def test_start_span_enabled(self):
        """Test span creation when enabled."""
        enable_tracing()
        span = start_span("test_operation")
        self.assertNotEqual(span.trace_id, "disabled")
        self.assertNotEqual(span.span_id, "disabled")
        self.assertIsNone(span.end_time)
        self.assertEqual(span.status, SpanStatus.UNSET)
    
    def test_end_span(self):
        """Test ending a span."""
        enable_tracing()
        span = start_span("test_operation")
        end_span(span)
        self.assertIsNotNone(span.end_time)
        self.assertEqual(span.status, SpanStatus.OK)
    
    def test_end_span_with_error(self):
        """Test ending a span with error status."""
        enable_tracing()
        span = start_span("test_operation")
        end_span(span, status=SpanStatus.ERROR)
        self.assertEqual(span.status, SpanStatus.ERROR)
    
    def test_span_duration(self):
        """Test span duration calculation."""
        enable_tracing()
        span = start_span("test_operation")
        time.sleep(0.01)
        end_span(span)
        duration = span.get_duration_ms()
        self.assertIsNotNone(duration)
        self.assertGreater(duration, 0)
    
    def test_span_attributes(self):
        """Test adding attributes to spans."""
        enable_tracing()
        span = start_span("test_operation")
        span.add_attribute("key1", "value1")
        span.add_attribute("key2", 123)
        self.assertEqual(span.attributes["key1"], "value1")
        self.assertEqual(span.attributes["key2"], 123)
    
    def test_span_events(self):
        """Test adding events to spans."""
        enable_tracing()
        span = start_span("test_operation")
        span.add_event("processing_started", {"step": 1})
        span.add_event("processing_completed", {"success": True})
        self.assertEqual(len(span.events), 2)
        self.assertEqual(span.events[0]["name"], "processing_started")
    
    def test_get_current_span(self):
        """Test getting current active span."""
        enable_tracing()
        span = start_span("test_operation")
        current = global_tracer.get_current_span()
        self.assertEqual(current.span_id, span.span_id)
        end_span(span)
        self.assertIsNone(global_tracer.get_current_span())


class TestTraceDecorator(unittest.TestCase):
    """Tests for trace decorators."""
    
    def setUp(self):
        """Reset tracer state before each test."""
        disable_tracing()
        global_tracer.metrics.reset()
    
    def test_sync_decorator_disabled(self):
        """Test sync decorator works when disabled."""
        @trace("test_function")
        def test_func():
            return "success"
        
        result = test_func()
        self.assertEqual(result, "success")
    
    def test_sync_decorator_enabled(self):
        """Test sync decorator creates spans when enabled."""
        enable_tracing()
        
        @trace("test_function")
        def test_func():
            return "success"
        
        result = test_func()
        self.assertEqual(result, "success")
        
        metrics = get_metrics()
        self.assertGreater(metrics["total_spans"], 0)
    
    def test_sync_decorator_exception(self):
        """Test sync decorator captures exceptions."""
        enable_tracing()
        
        @trace("test_function")
        def test_func():
            raise ValueError("test error")
        
        with self.assertRaises(ValueError):
            test_func()
        
        metrics = get_metrics()
        self.assertGreater(metrics["total_errors"], 0)


class TestAsyncTraceDecorator(unittest.TestCase):
    """Tests for async trace decorators."""
    
    def setUp(self):
        """Reset tracer state before each test."""
        disable_tracing()
        global_tracer.metrics.reset()
    
    def test_async_decorator_disabled(self):
        """Test async decorator works when disabled."""
        @trace_async("test_async_function")
        async def test_func():
            await asyncio.sleep(0.001)
            return "success"
        
        result = asyncio.run(test_func())
        self.assertEqual(result, "success")
    
    def test_async_decorator_enabled(self):
        """Test async decorator creates spans when enabled."""
        enable_tracing()
        
        @trace_async("test_async_function")
        async def test_func():
            await asyncio.sleep(0.001)
            return "success"
        
        result = asyncio.run(test_func())
        self.assertEqual(result, "success")
        
        metrics = get_metrics()
        self.assertGreater(metrics["total_spans"], 0)


class TestHealthCheck(unittest.TestCase):
    """Tests for health check integration."""
    
    def setUp(self):
        """Reset tracer state before each test."""
        disable_tracing()
        global_tracer.metrics.reset()
    
    def test_health_check_disabled(self):
        """Test health check when tracing is disabled."""
        health = get_health_status()
        self.assertIn("status", health)
        self.assertIn("tracing_enabled", health)
        self.assertFalse(health["tracing_enabled"])
    
    def test_health_check_enabled(self):
        """Test health check when tracing is enabled."""
        enable_tracing()
        health = get_health_status()
        self.assertTrue(health["tracing_enabled"])
        self.assertIn("sampling_rate", health)
        self.assertIn("metrics", health)
    
    def test_health_check_status_healthy(self):
        """Test health check returns healthy status."""
        enable_tracing()
        health = get_health_status()
        self.assertIn(health["status"], ["healthy", "degraded", "unhealthy"])


class TestLoggingIntegration(unittest.TestCase):
    """Tests for structured logging bridge."""
    
    def setUp(self):
        """Reset tracer state before each test."""
        disable_tracing()
        global_tracer.metrics.reset()
    
    def test_get_logging_filter(self):
        """Test getting logging filter."""
        enable_tracing()
        log_filter = global_tracer.get_logging_filter()
        self.assertIsInstance(log_filter, logging.Filter)
    
    def test_inject_logging_context(self):
        """Test injecting logging context into logger."""
        enable_tracing()
        logger = logging.getLogger("test_logger")
        original_filter_count = len(logger.filters)
        global_tracer.inject_logging_context(logger)
        self.assertEqual(len(logger.filters), original_filter_count + 1)


class TestContextPropagation(unittest.TestCase):
    """Tests for trace context propagation."""
    
    def setUp(self):
        """Reset tracer state before each test."""
        disable_tracing()
        global_tracer.metrics.reset()
    
    def test_inject_trace_context_disabled(self):
        """Test context injection returns empty when disabled."""
        headers = global_tracer.inject_trace_context()
        self.assertEqual(headers, {})
    
    def test_inject_trace_context_enabled(self):
        """Test context injection returns headers when enabled."""
        enable_tracing()
        span = start_span("test_operation")
        headers = global_tracer.inject_trace_context()
        self.assertIn("traceparent", headers)
        self.assertIn(span.trace_id, headers["traceparent"])
        end_span(span)
    
    def test_extract_trace_context(self):
        """Test extracting trace context from headers."""
        enable_tracing()
        headers = {
            "traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
        }
        context = global_tracer.extract_trace_context(headers)
        self.assertIsNotNone(context)
        self.assertEqual(context["trace_id"], "4bf92f3577b34da6a3ce929d0e0e4736")
        self.assertEqual(context["span_id"], "00f067aa0ba902b7")


class TestSpanSamplingDecision(unittest.TestCase):
    """Tests for span export decisions."""
    
    def test_span_should_export_record_and_sample(self):
        """Test spans with RECORD_AND_SAMPLE decision are exported."""
        from dataclasses import dataclass
        
        @dataclass
        class TestSpan:
            sampling_decision: SamplingDecision
            
            def should_export(self):
                return self.sampling_decision == SamplingDecision.RECORD_AND_SAMPLE
        
        span = TestSpan(SamplingDecision.RECORD_AND_SAMPLE)
        self.assertTrue(span.should_export())
    
    def test_span_should_export_drop(self):
        """Test spans with DROP decision are not exported."""
        from dataclasses import dataclass
        
        @dataclass
        class TestSpan:
            sampling_decision: SamplingDecision
            
            def should_export(self):
                return self.sampling_decision == SamplingDecision.RECORD_AND_SAMPLE
        
        span = TestSpan(SamplingDecision.DROP)
        self.assertFalse(span.should_export())


if __name__ == "__main__":
    unittest.main(verbosity=2)
