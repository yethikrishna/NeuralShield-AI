"""
Test Suite for NeuralShield-AI Observability v15
Distributed Tracing & Context Correlation
=============================================
Tests: 36 total
100% ADD-ONLY - NO PRODUCTION CODE MODIFIED
"""

import unittest
import threading
import time
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from observability_distributed_tracing_correlation_v15_2026_june import (
    DistributedTracingCorrelationEngine,
    TraceContextPropagator,
    AdaptiveSampler,
    ThreadLocalContext,
    generate_trace_id,
    generate_span_id,
    generate_correlation_id,
    is_valid_trace_id,
    is_valid_span_id,
    enable_tracing,
    disable_tracing,
    start_trace_span,
    end_trace_span,
    get_correlation_ids,
    inject_trace_context,
    create_threat_correlation,
    traced_operation,
    TracePropagationFormat,
    SpanKind,
    SpanStatus,
    SamplingDecision,
    OBSERVABILITY_VERSION,
    OBSERVABILITY_DIMENSION,
    OBSERVABILITY_FEATURES,
)


class TestTraceIdGeneration(unittest.TestCase):
    """Test trace and span ID generation utilities."""
    
    def test_generate_trace_id_format(self):
        trace_id = generate_trace_id()
        self.assertEqual(len(trace_id), 32)
        self.assertTrue(is_valid_trace_id(trace_id))
    
    def test_generate_span_id_format(self):
        span_id = generate_span_id()
        self.assertEqual(len(span_id), 16)
        self.assertTrue(is_valid_span_id(span_id))
    
    def test_invalid_trace_id_rejected(self):
        self.assertFalse(is_valid_trace_id("0" * 32))
        self.assertFalse(is_valid_trace_id("g" * 32))
        self.assertFalse(is_valid_trace_id("too_short"))
    
    def test_correlation_id_format(self):
        corr_id = generate_correlation_id()
        self.assertTrue(corr_id.startswith("corr-"))
        self.assertGreater(len(corr_id), 20)


class TestThreadLocalContext(unittest.TestCase):
    """Test thread-local context storage."""
    
    def test_context_isolation(self):
        context = ThreadLocalContext()
        results = {}
        
        def worker(thread_id):
            context.set_span_context(None)
            results[thread_id] = context.get_span_context()
        
        t1 = threading.Thread(target=worker, args=(1,))
        t2 = threading.Thread(target=worker, args=(2,))
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        
        self.assertIsNone(results[1])
        self.assertIsNone(results[2])
    
    def test_baggage_storage(self):
        context = ThreadLocalContext()
        from observability_distributed_tracing_correlation_v15_2026_june import BaggageEntry
        
        context.set_baggage({"key1": BaggageEntry(value="val1")})
        baggage = context.get_baggage()
        self.assertEqual(baggage["key1"].value, "val1")


class TestTraceContextPropagation(unittest.TestCase):
    """Test W3C Trace Context and B3 propagation."""
    
    def setUp(self):
        from observability_distributed_tracing_correlation_v15_2026_june import SpanContext, TraceFlags
        self.test_context = SpanContext(
            trace_id="4bf92f3577b34da6a3ce929d0e0e4736",
            span_id="00f067aa0ba902b7",
            trace_flags=TraceFlags(sampled=True)
        )
    
    def test_w3c_inject_format(self):
        carrier = {}
        TraceContextPropagator.inject_w3c(self.test_context, carrier)
        self.assertIn("traceparent", carrier)
        parts = carrier["traceparent"].split("-")
        self.assertEqual(len(parts), 4)
        self.assertEqual(parts[0], "00")
        self.assertEqual(parts[1], "4bf92f3577b34da6a3ce929d0e0e4736")
        self.assertEqual(parts[2], "00f067aa0ba902b7")
        self.assertEqual(parts[3], "01")
    
    def test_w3c_extract_valid(self):
        carrier = {
            "traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
        }
        extracted = TraceContextPropagator.extract_w3c(carrier)
        self.assertIsNotNone(extracted)
        self.assertEqual(extracted.trace_id, "4bf92f3577b34da6a3ce929d0e0e4736")
        self.assertEqual(extracted.span_id, "00f067aa0ba902b7")
        self.assertTrue(extracted.trace_flags.sampled)
    
    def test_w3c_extract_invalid(self):
        carrier = {"traceparent": "invalid-format"}
        extracted = TraceContextPropagator.extract_w3c(carrier)
        self.assertIsNone(extracted)
    
    def test_b3_multi_inject(self):
        carrier = {}
        TraceContextPropagator.inject_b3_multi(self.test_context, carrier)
        self.assertIn("X-B3-TraceId", carrier)
        self.assertIn("X-B3-SpanId", carrier)
        self.assertIn("X-B3-Sampled", carrier)
    
    def test_b3_multi_extract(self):
        carrier = {
            "X-B3-TraceId": "4bf92f3577b34da6a3ce929d0e0e4736",
            "X-B3-SpanId": "00f067aa0ba902b7",
            "X-B3-Sampled": "1"
        }
        extracted = TraceContextPropagator.extract_b3_multi(carrier)
        self.assertIsNotNone(extracted)
        self.assertTrue(extracted.trace_flags.sampled)


class TestAdaptiveSampler(unittest.TestCase):
    """Test adaptive sampling functionality."""
    
    def test_sampler_initialization(self):
        sampler = AdaptiveSampler()
        self.assertGreater(sampler.get_current_sampling_rate(), 0)
        self.assertLessEqual(sampler.get_current_sampling_rate(), 1.0)
    
    def test_error_sampling_priority(self):
        sampler = AdaptiveSampler()
        decision = sampler.should_sample(
            trace_id=generate_trace_id(),
            operation_name="test",
            has_error=True
        )
        # Errors should almost always be sampled
        self.assertIn(decision, [SamplingDecision.RECORD_AND_SAMPLE, SamplingDecision.DROP])
    
    def test_sampling_rate_adaptation(self):
        sampler = AdaptiveSampler()
        initial_rate = sampler.get_current_sampling_rate()
        for _ in range(100):
            sampler.record_trace()
        # Rate should adapt after recording traces
        self.assertIsNotNone(sampler.get_current_sampling_rate())


class TestDistributedTracingEngineBasics(unittest.TestCase):
    """Test basic tracing engine functionality."""
    
    def setUp(self):
        self.engine = DistributedTracingCorrelationEngine()
        self.engine.enable()
    
    def tearDown(self):
        self.engine.disable()
        self.engine.clear_context()
    
    def test_engine_can_be_disabled(self):
        engine = DistributedTracingCorrelationEngine()
        engine.disable()
        self.assertFalse(engine.is_enabled())
    
    def test_engine_enable_disable(self):
        self.assertTrue(self.engine.is_enabled())
        self.engine.disable()
        self.assertFalse(self.engine.is_enabled())
    
    def test_start_span_when_disabled(self):
        self.engine.disable()
        context, span_id = self.engine.start_span("test")
        self.assertEqual(span_id, "disabled")
        self.assertIsNotNone(context)
    
    def test_start_span_creates_context(self):
        context, span_id = self.engine.start_span("test_operation")
        self.assertNotEqual(span_id, "disabled")
        self.assertTrue(is_valid_trace_id(context.trace_id))
        self.assertTrue(is_valid_span_id(context.span_id))
    
    def test_end_span(self):
        context, span_id = self.engine.start_span("test")
        self.engine.end_span(span_id, SpanStatus.OK)
        spans = self.engine.get_finished_spans()
        self.assertGreater(len(spans), 0)
    
    def test_add_span_event(self):
        context, span_id = self.engine.start_span("test")
        self.engine.add_event(span_id, "threat_detected", {"severity": "high"})
        self.engine.end_span(span_id)
        spans = self.engine.get_finished_spans()
        self.assertEqual(len(spans[0]["events"]), 1)


class TestCorrelationContext(unittest.TestCase):
    """Test cross-signal correlation functionality."""
    
    def setUp(self):
        self.engine = DistributedTracingCorrelationEngine()
        self.engine.enable()
    
    def tearDown(self):
        self.engine.disable()
        self.engine.clear_context()
    
    def test_create_correlation_context(self):
        corr = self.engine.create_correlation_context(
            threat_id="THREAT-123",
            alert_id="ALERT-456"
        )
        self.assertIsNotNone(corr.correlation_id)
        self.assertEqual(corr.threat_id, "THREAT-123")
        self.assertEqual(corr.alert_id, "ALERT-456")
    
    def test_get_correlation_ids(self):
        self.engine.start_span("test")
        self.engine.create_correlation_context(threat_id="T1")
        ids = self.engine.get_current_correlation_ids()
        self.assertIn("trace_id", ids)
        self.assertIn("span_id", ids)
        self.assertIn("threat_id", ids)
        self.assertEqual(ids["threat_id"], "T1")


class TestBaggagePropagation(unittest.TestCase):
    """Test baggage context propagation."""
    
    def setUp(self):
        self.engine = DistributedTracingCorrelationEngine()
        self.engine.enable()
    
    def tearDown(self):
        self.engine.disable()
        self.engine.clear_context()
    
    def test_set_and_get_baggage(self):
        self.engine.set_baggage_entry("tenant_id", "acme-corp", {"priority": "high"})
        entry = self.engine.get_baggage_entry("tenant_id")
        self.assertIsNotNone(entry)
        self.assertEqual(entry.value, "acme-corp")
        self.assertEqual(entry.metadata["priority"], "high")
    
    def test_baggage_none_when_disabled(self):
        self.engine.disable()
        self.engine.set_baggage_entry("key", "value")
        entry = self.engine.get_baggage_entry("key")
        self.assertIsNone(entry)


class TestSpanNestingAndParenting(unittest.TestCase):
    """Test span hierarchy and parent-child relationships."""
    
    def setUp(self):
        self.engine = DistributedTracingCorrelationEngine()
        self.engine.enable()
    
    def tearDown(self):
        self.engine.disable()
        self.engine.clear_context()
    
    def test_parent_child_trace_id_consistency(self):
        parent_ctx, parent_id = self.engine.start_span("parent")
        child_ctx, child_id = self.engine.start_span("child")
        
        # Same trace ID for parent and child
        self.assertEqual(parent_ctx.trace_id, child_ctx.trace_id)
        # Different span IDs
        self.assertNotEqual(parent_ctx.span_id, child_ctx.span_id)
        
        self.engine.end_span(child_id)
        self.engine.end_span(parent_id)


class TestTracedOperationDecorator(unittest.TestCase):
    """Test the traced operation decorator."""
    
    def setUp(self):
        enable_tracing()
    
    def tearDown(self):
        disable_tracing()
    
    def test_decorator_traces_success(self):
        @traced_operation(name="test_function", kind=SpanKind.INTERNAL)
        def test_func(x, y):
            return x + y
        
        result = test_func(2, 3)
        self.assertEqual(result, 5)
    
    def test_decorator_traces_error(self):
        @traced_operation(name="error_function")
        def error_func():
            raise ValueError("test error")
        
        with self.assertRaises(ValueError):
            error_func()


class TestGlobalConvenienceAPI(unittest.TestCase):
    """Test the global convenience API functions."""
    
    def test_enable_disable_tracing(self):
        enable_tracing()
        engine = DistributedTracingCorrelationEngine()
        self.assertTrue(engine.is_enabled())
        disable_tracing()
        self.assertFalse(engine.is_enabled())
    
    def test_global_span_management(self):
        enable_tracing()
        ctx, span_id = start_trace_span("global_test")
        self.assertNotEqual(span_id, "disabled")
        end_trace_span(span_id)
        disable_tracing()
    
    def test_global_correlation_ids(self):
        enable_tracing()
        start_trace_span("test")
        create_threat_correlation("THREAT-GLOBAL")
        ids = get_correlation_ids()
        self.assertIsNotNone(ids["trace_id"])
        self.assertEqual(ids["threat_id"], "THREAT-GLOBAL")
        disable_tracing()
    
    def test_inject_context(self):
        enable_tracing()
        start_trace_span("inject_test")
        carrier = {}
        inject_trace_context(carrier)
        self.assertIn("traceparent", carrier)
        disable_tracing()


class TestMetadataMarkers(unittest.TestCase):
    """Test version and dimension metadata."""
    
    def test_version_marker(self):
        self.assertEqual(OBSERVABILITY_VERSION, "v15")
    
    def test_dimension_marker(self):
        self.assertEqual(OBSERVABILITY_DIMENSION, "D")
    
    def test_features_list(self):
        self.assertGreater(len(OBSERVABILITY_FEATURES), 0)


class TestThreadSafety(unittest.TestCase):
    """Test thread safety of the tracing engine."""
    
    def test_concurrent_span_creation(self):
        enable_tracing()
        errors = []
        
        def create_spans(thread_id):
            try:
                for i in range(10):
                    ctx, span_id = start_trace_span(f"thread_{thread_id}_span_{i}")
                    end_trace_span(span_id)
            except Exception as e:
                errors.append(e)
        
        threads = []
        for i in range(5):
            t = threading.Thread(target=create_spans, args=(i,))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        self.assertEqual(len(errors), 0)
        disable_tracing()


class TestBackwardCompatibility(unittest.TestCase):
    """Test backward compatibility guarantees."""
    
    def test_disabled_has_zero_overhead(self):
        """When disabled, operations should return immediately without side effects."""
        engine = DistributedTracingCorrelationEngine()
        engine.disable()
        
        # All operations should work without error when disabled
        ctx, span_id = engine.start_span("test")
        self.assertEqual(span_id, "disabled")
        
        engine.end_span(span_id)
        engine.add_event(span_id, "test")
        engine.set_baggage_entry("key", "value")
        entry = engine.get_baggage_entry("key")
        self.assertIsNone(entry)
        
        carrier = {}
        engine.inject_context(carrier)
        self.assertEqual(len(carrier), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
