"""
Test Suite for NeuralShield Enhanced Distributed Tracing (Dimension D - Observability V7)
Tests are ADD-ONLY - no existing tests are modified
All existing tests will continue to pass
"""

import unittest
import time
import threading
from neural_shield.observability_enhanced_distributed_tracing_v7_2026_june import (
    EnhancedTracer,
    TraceContext,
    SpanKind,
    SpanStatus,
    traced,
    GLOBAL_TRACER
)


class TestEnhancedDistributedTracing(unittest.TestCase):
    """Test enhanced distributed tracing capabilities."""
    
    def setUp(self):
        """Set up test tracer."""
        self.tracer = EnhancedTracer(service_name="test_service")
    
    def test_tracer_disabled_by_default(self):
        """Test that tracing is disabled by default (OPT-IN)."""
        self.assertFalse(self.tracer.is_enabled())
    
    def test_enable_disable_tracer(self):
        """Test enabling and disabling tracer."""
        self.tracer.enable()
        self.assertTrue(self.tracer.is_enabled())
        
        self.tracer.disable()
        self.assertFalse(self.tracer.is_enabled())
    
    def test_noop_span_when_disabled(self):
        """Test that no-op spans are returned when tracing is disabled."""
        span = self.tracer.start_span("test_span")
        self.assertEqual(span.trace_id, "noop")
        self.assertEqual(span.span_id, "noop")
    
    def test_start_span_when_enabled(self):
        """Test starting a real span when enabled."""
        self.tracer.enable()
        span = self.tracer.start_span("test_span", category="security")
        
        self.assertNotEqual(span.trace_id, "noop")
        self.assertNotEqual(span.span_id, "noop")
        self.assertEqual(span.name, "test_span")
        self.assertEqual(span.attributes.get("category"), "security")
    
    def test_span_duration(self):
        """Test span duration calculation."""
        self.tracer.enable()
        span = self.tracer.start_span("timed_span")
        time.sleep(0.01)
        span.end()
        
        self.assertIsNotNone(span.duration_ms)
        self.assertGreater(span.duration_ms, 0)
    
    def test_span_status(self):
        """Test setting span status."""
        self.tracer.enable()
        span = self.tracer.start_span("status_test")
        
        self.assertEqual(span.status, SpanStatus.UNSET)
        
        span.set_status(SpanStatus.OK)
        self.assertEqual(span.status, SpanStatus.OK)
        
        span.set_status(SpanStatus.ERROR)
        self.assertEqual(span.status, SpanStatus.ERROR)
    
    def test_span_events(self):
        """Test adding events to span."""
        self.tracer.enable()
        span = self.tracer.start_span("event_test")
        
        span.add_event("processing_started", step=1)
        span.add_event("processing_completed", step=2)
        
        self.assertEqual(len(span.events), 2)
        self.assertEqual(span.events[0].name, "processing_started")
        self.assertEqual(span.events[0].attributes["step"], 1)
    
    def test_span_attributes(self):
        """Test setting span attributes."""
        self.tracer.enable()
        span = self.tracer.start_span("attr_test")
        
        span.set_attribute("user_id", "12345")
        span.set_attribute("risk_level", "high")
        
        self.assertEqual(span.attributes["user_id"], "12345")
        self.assertEqual(span.attributes["risk_level"], "high")
    
    def test_parent_child_span_relationship(self):
        """Test parent-child span relationships."""
        self.tracer.enable()
        parent = self.tracer.start_span("parent_span")
        
        child = self.tracer.start_span(
            "child_span",
            parent_trace_id=parent.trace_id,
            parent_span_id=parent.span_id
        )
        
        self.assertEqual(child.parent_span_id, parent.span_id)
        self.assertEqual(child.trace_id, parent.trace_id)
    
    def test_trace_context_thread_local(self):
        """Test thread-local trace context."""
        self.tracer.enable()
        
        span = self.tracer.start_span("context_test")
        TraceContext.set_current_span(span)
        
        self.assertEqual(TraceContext.get_current_span(), span)
        self.assertEqual(TraceContext.get_trace_id(), span.trace_id)
    
    def test_trace_context_isolation(self):
        """Test that trace context is thread-isolated."""
        self.tracer.enable()
        results = {}
        
        def thread_1():
            span1 = self.tracer.start_span("thread1_span")
            TraceContext.set_current_span(span1)
            results["thread1"] = TraceContext.get_trace_id()
        
        def thread_2():
            span2 = self.tracer.start_span("thread2_span")
            TraceContext.set_current_span(span2)
            results["thread2"] = TraceContext.get_trace_id()
        
        t1 = threading.Thread(target=thread_1)
        t2 = threading.Thread(target=thread_2)
        
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        
        self.assertNotEqual(results["thread1"], results["thread2"])
    
    def test_get_trace(self):
        """Test retrieving all spans in a trace."""
        self.tracer.enable()
        
        parent = self.tracer.start_span("parent")
        child1 = self.tracer.start_span(
            "child1",
            parent_trace_id=parent.trace_id,
            parent_span_id=parent.span_id
        )
        child2 = self.tracer.start_span(
            "child2",
            parent_trace_id=parent.trace_id,
            parent_span_id=parent.span_id
        )
        
        trace_spans = self.tracer.get_trace(parent.trace_id)
        self.assertEqual(len(trace_spans), 3)
    
    def test_trace_summary(self):
        """Test trace summary generation."""
        self.tracer.enable()
        
        span = self.tracer.start_span("summary_test")
        span.set_status(SpanStatus.ERROR)
        span.end()
        
        summary = self.tracer.get_trace_summary(span.trace_id)
        self.assertEqual(summary["error_count"], 1)
        self.assertEqual(summary["service"], "test_service")
    
    def test_export_spans(self):
        """Test exporting spans as dictionaries."""
        self.tracer.enable()
        
        span = self.tracer.start_span("export_test", attr="value")
        span.add_event("test_event")
        span.end()
        
        exported = self.tracer.export_spans(span.trace_id)
        self.assertEqual(len(exported), 1)
        self.assertEqual(exported[0]["name"], "export_test")
        self.assertEqual(exported[0]["attributes"]["attr"], "value")
    
    def test_clear_trace(self):
        """Test clearing trace data."""
        self.tracer.enable()
        
        span = self.tracer.start_span("clear_test")
        trace_id = span.trace_id
        
        self.assertGreater(len(self.tracer.get_trace(trace_id)), 0)
        
        self.tracer.clear_trace(trace_id)
        self.assertEqual(len(self.tracer.get_trace(trace_id)), 0)
    
    def test_traced_decorator_disabled(self):
        """Test traced decorator when disabled (no impact)."""
        GLOBAL_TRACER.disable()
        
        @traced("decorated_function")
        def test_func():
            return "success"
        
        result = test_func()
        self.assertEqual(result, "success")
    
    def test_traced_decorator_enabled(self):
        """Test traced decorator when enabled."""
        GLOBAL_TRACER.enable()
        
        @traced("decorated_function", category="test")
        def test_func():
            return "success"
        
        result = test_func()
        self.assertEqual(result, "success")
        
        GLOBAL_TRACER.disable()
    
    def test_traced_decorator_error_propagation(self):
        """Test that errors propagate through traced decorator."""
        GLOBAL_TRACER.enable()
        
        @traced("error_function")
        def error_func():
            raise ValueError("test error")
        
        with self.assertRaises(ValueError):
            error_func()
        
        GLOBAL_TRACER.disable()
    
    def test_span_kinds(self):
        """Test all span kinds."""
        self.tracer.enable()
        
        for kind in SpanKind:
            span = self.tracer.start_span(f"span_{kind.value}", kind=kind)
            self.assertEqual(span.kind, kind)
    
    def test_max_spans_per_trace_limit(self):
        """Test that trace span limit is enforced."""
        self.tracer.enable()
        self.tracer.max_spans_per_trace = 10
        
        trace_id = self.tracer._generate_trace_id()
        
        for i in range(20):
            self.tracer.start_span(
                f"span_{i}",
                parent_trace_id=trace_id
            )
        
        spans = self.tracer.get_trace(trace_id)
        self.assertLessEqual(len(spans), 10)
    
    def test_span_links(self):
        """Test span linking functionality."""
        self.tracer.enable()
        
        span1 = self.tracer.start_span("span1")
        span2 = self.tracer.start_span("span2")
        
        span1.add_link(span2.trace_id, span2.span_id, relation="causes")
        
        self.assertEqual(len(span1.links), 1)
        self.assertEqual(span1.links[0].trace_id, span2.trace_id)


class TestTracingBackwardCompatibility(unittest.TestCase):
    """Test that tracing doesn't break existing behavior."""
    
    def test_no_impact_when_disabled(self):
        """Verify zero impact when tracing is disabled."""
        tracer = EnhancedTracer()
        
        # All operations should work without side effects
        span = tracer.start_span("test")
        span.add_event("event")
        span.set_attribute("key", "value")
        span.set_status(SpanStatus.OK)
        span.end()
        
        # Export should work but return empty/noop data
        exported = tracer.export_spans()
        self.assertIsInstance(exported, list)
        
        # Trace retrieval works
        trace = tracer.get_trace("any_id")
        self.assertEqual(trace, [])
    
    def test_global_tracer_safe(self):
        """Test that global tracer is safe to use."""
        # Should never raise exceptions
        try:
            GLOBAL_TRACER.enable()
            GLOBAL_TRACER.disable()
            GLOBAL_TRACER.is_enabled()
        except Exception:
            self.fail("Global tracer raised an exception")


if __name__ == "__main__":
    unittest.main()
