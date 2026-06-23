"""
Test Suite for NeuralShield Enhanced Distributed Tracing v11
Dimension D - Observability & Instrumentation

Tests verify:
- Tracing is disabled by default (opt-in only)
- Span creation and management works correctly
- Baggage context propagation works
- Trace context serialization/deserialization
- Decorator tracing works
- No existing code behavior is broken
- All tests are add-only, no production code modified
"""

import unittest
import time
import threading
from unittest.mock import MagicMock

from neural_shield.observability_enhanced_distributed_tracing_baggage_correlation_v11_2026_june import (
    Tracer,
    TraceBaggage,
    TraceSpan,
    SpanKind,
    SpanStatus,
    TraceContextPropagator,
    global_tracer,
    enable_tracing,
    disable_tracing,
    is_tracing_enabled,
    start_span,
    end_span,
    get_tracer,
    trace
)


class TestTraceBaggage(unittest.TestCase):
    """Test thread-safe baggage carrier."""
    
    def setUp(self):
        self.baggage = TraceBaggage()
    
    def test_correlation_id_set_get(self):
        """Test correlation ID storage and retrieval."""
        test_id = "test-correlation-123"
        self.baggage.set_correlation_id(test_id)
        self.assertEqual(self.baggage.get_correlation_id(), test_id)
    
    def test_baggage_item_set_get(self):
        """Test baggage item storage."""
        self.baggage.set_baggage_item("user_id", "user123")
        self.baggage.set_baggage_item("request_id", "req456")
        self.assertEqual(self.baggage.get_baggage_item("user_id"), "user123")
        self.assertEqual(self.baggage.get_baggage_item("request_id"), "req456")
    
    def test_get_all_baggage(self):
        """Test getting all baggage items."""
        self.baggage.set_baggage_item("key1", "value1")
        self.baggage.set_baggage_item("key2", "value2")
        all_baggage = self.baggage.get_all_baggage()
        self.assertEqual(all_baggage["key1"], "value1")
        self.assertEqual(all_baggage["key2"], "value2")
    
    def test_thread_safety(self):
        """Test baggage is thread-safe."""
        results = {}
        
        def worker(thread_id):
            baggage = TraceBaggage()
            baggage.set_correlation_id(f"corr-{thread_id}")
            baggage.set_baggage_item("thread", str(thread_id))
            time.sleep(0.01)
            results[thread_id] = (
                baggage.get_correlation_id(),
                baggage.get_baggage_item("thread")
            )
        
        threads = []
        for i in range(5):
            t = threading.Thread(target=worker, args=(i,))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        for i in range(5):
            self.assertEqual(results[i][0], f"corr-{i}")
            self.assertEqual(results[i][1], str(i))
    
    def test_clear_baggage(self):
        """Test clearing baggage."""
        self.baggage.set_correlation_id("test-id")
        self.baggage.set_baggage_item("key", "value")
        self.baggage.clear()
        self.assertIsNone(self.baggage.get_correlation_id())
        self.assertIsNone(self.baggage.get_baggage_item("key"))


class TestTraceContextPropagator(unittest.TestCase):
    """Test W3C trace context propagation."""
    
    def test_generate_trace_id(self):
        """Test trace ID generation."""
        trace_id = TraceContextPropagator.generate_trace_id()
        self.assertEqual(len(trace_id), 32)  # UUID hex is 32 chars
    
    def test_generate_span_id(self):
        """Test span ID generation."""
        span_id = TraceContextPropagator.generate_span_id()
        self.assertEqual(len(span_id), 16)
    
    def test_serialize_traceparent(self):
        """Test W3C traceparent serialization."""
        trace_id = "a" * 32
        span_id = "b" * 16
        result = TraceContextPropagator.serialize_traceparent(trace_id, span_id)
        self.assertEqual(result, f"00-{trace_id}-{span_id}-01")
    
    def test_deserialize_traceparent_valid(self):
        """Test valid traceparent deserialization."""
        traceparent = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
        result = TraceContextPropagator.deserialize_traceparent(traceparent)
        self.assertIsNotNone(result)
        self.assertEqual(result["version"], "00")
        self.assertEqual(result["trace_id"], "0af7651916cd43dd8448eb211c80319c")
        self.assertEqual(result["span_id"], "b7ad6b7169203331")
        self.assertEqual(result["trace_flags"], "01")
    
    def test_deserialize_traceparent_invalid(self):
        """Test invalid traceparent handling."""
        result = TraceContextPropagator.deserialize_traceparent("invalid-format")
        self.assertIsNone(result)
    
    def test_serialize_baggage(self):
        """Test baggage serialization."""
        baggage = {"user": "alice", "service": "neuralshield"}
        result = TraceContextPropagator.serialize_baggage(baggage)
        self.assertIn("user=alice", result)
        self.assertIn("service=neuralshield", result)
    
    def test_deserialize_baggage(self):
        """Test baggage deserialization."""
        baggage_str = "user=alice,service=neuralshield"
        result = TraceContextPropagator.deserialize_baggage(baggage_str)
        self.assertEqual(result["user"], "alice")
        self.assertEqual(result["service"], "neuralshield")


class TestTracerDisabledByDefault(unittest.TestCase):
    """Test that tracing is disabled by default (opt-in requirement)."""
    
    def test_tracing_disabled_by_default(self):
        """Verify tracing is off by default."""
        tracer = Tracer()
        self.assertFalse(tracer.is_enabled())
    
    def test_no_op_span_when_disabled(self):
        """Verify spans are no-op when disabled."""
        tracer = Tracer()
        span = tracer.start_span("test-operation")
        self.assertEqual(span.trace_id, "disabled")
        self.assertEqual(span.span_id, "disabled")
    
    def test_enable_disable(self):
        """Test enabling and disabling tracing."""
        tracer = Tracer()
        self.assertFalse(tracer.is_enabled())
        tracer.enable()
        self.assertTrue(tracer.is_enabled())
        tracer.disable()
        self.assertFalse(tracer.is_enabled())


class TestTracerEnabled(unittest.TestCase):
    """Test tracer functionality when enabled."""
    
    def setUp(self):
        self.tracer = Tracer()
        self.tracer.enable()
    
    def tearDown(self):
        self.tracer.disable()
    
    def test_start_span_basic(self):
        """Test basic span creation."""
        span = self.tracer.start_span("test-operation", SpanKind.SERVER)
        self.assertNotEqual(span.trace_id, "disabled")
        self.assertNotEqual(span.span_id, "disabled")
        self.assertEqual(span.name, "test-operation")
        self.assertEqual(span.kind, SpanKind.SERVER)
    
    def test_span_parent_child_relationship(self):
        """Test parent-child span relationships."""
        parent = self.tracer.start_span("parent")
        child = self.tracer.start_span("child")
        self.assertEqual(child.parent_span_id, parent.span_id)
        self.assertEqual(child.trace_id, parent.trace_id)
    
    def test_end_span(self):
        """Test span completion."""
        span = self.tracer.start_span("test")
        self.assertIsNone(span.end_time)
        self.tracer.end_span(span)
        self.assertIsNotNone(span.end_time)
        self.assertIsNotNone(span.get_duration_ms())
    
    def test_span_attributes(self):
        """Test span attribute addition."""
        span = self.tracer.start_span("test")
        span.add_attribute("key1", "value1")
        span.add_attribute("key2", 123)
        self.assertEqual(span.attributes["key1"], "value1")
        self.assertEqual(span.attributes["key2"], 123)
    
    def test_span_events(self):
        """Test span event addition."""
        span = self.tracer.start_span("test")
        span.add_event("processing-started", {"stage": "initial"})
        span.add_event("processing-completed")
        self.assertEqual(len(span.events), 2)
        self.assertEqual(span.events[0]["name"], "processing-started")
    
    def test_span_callback(self):
        """Test span end callbacks."""
        callback_result = []
        
        def on_span_end(span):
            callback_result.append(span.name)
        
        self.tracer.register_span_end_callback(on_span_end)
        span = self.tracer.start_span("callback-test")
        self.tracer.end_span(span)
        self.assertEqual(callback_result, ["callback-test"])
    
    def test_span_to_dict(self):
        """Test span serialization."""
        span = self.tracer.start_span("serialize-test")
        span.add_attribute("test", "value")
        self.tracer.end_span(span)
        span_dict = span.to_dict()
        self.assertEqual(span_dict["name"], "serialize-test")
        self.assertEqual(span_dict["attributes"]["test"], "value")
        self.assertIn("duration_ms", span_dict)


class TestTraceDecorator(unittest.TestCase):
    """Test function decorator tracing."""
    
    def setUp(self):
        self.tracer = Tracer()
        self.tracer.enable()
    
    def tearDown(self):
        self.tracer.disable()
    
    def test_decorator_success(self):
        """Test decorator on successful function."""
        @self.tracer.trace_as_span("decorated-function")
        def test_func(x, y):
            return x + y
        
        result = test_func(2, 3)
        self.assertEqual(result, 5)
        spans = self.tracer.get_all_spans()
        self.assertEqual(len(spans), 1)
        self.assertEqual(spans[0].name, "decorated-function")
        self.assertEqual(spans[0].status, SpanStatus.OK)
    
    def test_decorator_error(self):
        """Test decorator on erroring function."""
        @self.tracer.trace_as_span("error-function")
        def error_func():
            raise ValueError("Test error")
        
        with self.assertRaises(ValueError):
            error_func()
        
        spans = self.tracer.get_all_spans()
        self.assertEqual(len(spans), 1)
        self.assertEqual(spans[0].status, SpanStatus.ERROR)
        self.assertEqual(spans[0].attributes["error.type"], "ValueError")


class TestContextInjectionExtraction(unittest.TestCase):
    """Test trace context header injection/extraction."""
    
    def setUp(self):
        self.tracer = Tracer()
        self.tracer.enable()
    
    def tearDown(self):
        self.tracer.disable()
    
    def test_inject_trace_context(self):
        """Test context injection into headers."""
        span = self.tracer.start_span("test")
        headers = self.tracer.inject_trace_context()
        self.assertIn("traceparent", headers)
        self.assertIn(span.trace_id, headers["traceparent"])
        self.assertIn(span.span_id, headers["traceparent"])
    
    def test_extract_trace_context(self):
        """Test context extraction from headers."""
        headers = {
            "traceparent": "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
            "baggage": "user=alice,request=123"
        }
        context = self.tracer.extract_trace_context(headers)
        self.assertIsNotNone(context)
        self.assertEqual(context["trace_id"], "0af7651916cd43dd8448eb211c80319c")
    
    def test_inject_empty_when_disabled(self):
        """Test no headers injected when disabled."""
        self.tracer.disable()
        headers = self.tracer.inject_trace_context()
        self.assertEqual(headers, {})


class TestGlobalTracerFunctions(unittest.TestCase):
    """Test global convenience functions."""
    
    def tearDown(self):
        disable_tracing()
    
    def test_enable_disable_functions(self):
        """Test global enable/disable."""
        self.assertFalse(is_tracing_enabled())
        enable_tracing()
        self.assertTrue(is_tracing_enabled())
        disable_tracing()
        self.assertFalse(is_tracing_enabled())
    
    def test_start_end_span_functions(self):
        """Test global span functions."""
        enable_tracing()
        span = start_span("global-test")
        self.assertNotEqual(span.trace_id, "disabled")
        end_span(span)
        self.assertIsNotNone(span.end_time)
    
    def test_get_tracer(self):
        """Test getting global tracer."""
        tracer = get_tracer()
        self.assertIsInstance(tracer, Tracer)


class TestBackwardCompatibility(unittest.TestCase):
    """Verify no existing code behavior is broken."""
    
    def test_no_side_effects_when_disabled(self):
        """Disabled tracing has zero impact on existing code."""
        tracer = Tracer()
        
        # All operations should be no-ops
        span = tracer.start_span("test")
        tracer.end_span(span)
        headers = tracer.inject_trace_context()
        
        self.assertEqual(headers, {})
        # No exceptions raised
    
    def test_callback_errors_swallowed(self):
        """Callback errors never break user code."""
        tracer = Tracer()
        tracer.enable()
        
        def bad_callback(span):
            raise RuntimeError("Callback failed!")
        
        tracer.register_span_end_callback(bad_callback)
        span = tracer.start_span("safe-test")
        
        # This should never raise even if callback fails
        tracer.end_span(span)  # Should not raise


if __name__ == "__main__":
    unittest.main(verbosity=2)
