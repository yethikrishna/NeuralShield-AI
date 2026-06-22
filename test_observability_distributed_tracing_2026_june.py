"""
Test Suite for NeuralShield-AI Distributed Tracing & Span Context Module
June 2026 - Production Grade Tests
Covers all tracing functionality: span creation, nesting, decorators,
exporting, analysis, and disabled-mode no-op behavior.
All tests are ADD-ONLY - no production code is modified.
"""
import unittest
import time
import json
import tempfile
import os
import threading
from neural_shield.observability_distributed_tracing_span_context_2026_june import (
    enable_tracing,
    disable_tracing,
    reset_tracing,
    get_traces,
    export_traces_json,
    Tracer,
    TracingState,
    TraceExporter,
    TraceAnalyzer,
    trace,
    SpanKind,
    SpanStatus,
)
class TestTracingState(unittest.TestCase):
    """Tests for the global tracing state management."""
    
    def setUp(self):
        reset_tracing()
        disable_tracing()
    
    def test_tracing_disabled_by_default(self):
        """Tracing should be DISABLED by default - zero overhead."""
        self.assertFalse(TracingState.is_enabled())
    
    def test_enable_disable_tracing(self):
        """Can enable and disable tracing correctly."""
        enable_tracing()
        self.assertTrue(TracingState.is_enabled())
        disable_tracing()
        self.assertFalse(TracingState.is_enabled())
    
    def test_sampling_rate_bounds(self):
        """Sampling rate should be clamped between 0 and 1."""
        enable_tracing(sampling_rate=2.0)  # Should clamp to 1.0
        self.assertTrue(TracingState.is_enabled())
        enable_tracing(sampling_rate=-1.0)  # Should clamp to 0.0
        self.assertTrue(TracingState.is_enabled())
    
    def test_reset_clears_state(self):
        """Reset should clear all spans and thread-local state."""
        enable_tracing()
        span = Tracer.start_span("test")
        Tracer.end_span(span)
        self.assertGreater(len(TracingState.get_completed_spans()), 0)
        reset_tracing()
        self.assertEqual(len(TracingState.get_completed_spans()), 0)
class TestSpanCreation(unittest.TestCase):
    """Tests for basic span creation and management."""
    
    def setUp(self):
        reset_tracing()
        enable_tracing()
    
    def tearDown(self):
        disable_tracing()
        reset_tracing()
    
    def test_create_basic_span(self):
        """Can create and end a basic span."""
        span = Tracer.start_span("test_operation", kind=SpanKind.INTERNAL)
        self.assertEqual(span.name, "test_operation")
        self.assertNotEqual(span.trace_id, "disabled")
        self.assertIsNotNone(span.span_id)
        self.assertIsNone(span.parent_span_id)
        Tracer.end_span(span)
        self.assertIsNotNone(span.end_time)
        self.assertGreater(span.duration_ms(), 0.0)
    
    def test_span_with_tags(self):
        """Spans can have tags attached."""
        span = Tracer.start_span("tagged_span", user_id="test123", priority="high")
        span.set_tag("custom_tag", "value")
        self.assertEqual(span.tags["user_id"], "test123")
        self.assertEqual(span.tags["priority"], "high")
        self.assertEqual(span.tags["custom_tag"], "value")
        Tracer.end_span(span)
    
    def test_span_with_events(self):
        """Spans can have timestamped events."""
        span = Tracer.start_span("event_span")
        span.add_event("processing_started", stage=1)
        span.add_event("data_loaded", records=100)
        self.assertEqual(len(span.events), 2)
        self.assertEqual(span.events[0].name, "processing_started")
        self.assertEqual(span.events[0].attributes["stage"], 1)
        Tracer.end_span(span)
    
    def test_span_with_baggage(self):
        """Spans can have baggage for context propagation."""
        span = Tracer.start_span("baggage_span")
        span.set_baggage("request_id", "req-12345")
        span.set_baggage("tenant_id", "tenant-abc")
        self.assertEqual(span.baggage["request_id"], "req-12345")
        Tracer.end_span(span)
    
    def test_span_status_ok(self):
        """Spans can end with OK status."""
        span = Tracer.start_span("success_span")
        Tracer.end_span(span, SpanStatus.OK, "completed successfully")
        self.assertEqual(span.status, SpanStatus.OK)
        self.assertEqual(span.status_description, "completed successfully")
    
    def test_span_status_error(self):
        """Spans can end with ERROR status."""
        span = Tracer.start_span("error_span")
        Tracer.end_span(span, SpanStatus.ERROR, "something went wrong")
        self.assertEqual(span.status, SpanStatus.ERROR)
        self.assertEqual(span.status_description, "something went wrong")
class TestNestedSpans(unittest.TestCase):
    """Tests for parent-child span relationships and nesting."""
    
    def setUp(self):
        reset_tracing()
        enable_tracing()
    
    def tearDown(self):
        disable_tracing()
        reset_tracing()
    
    def test_explicit_parent_span(self):
        """Can explicitly set parent span relationship."""
        parent = Tracer.start_span("parent_operation")
        child = Tracer.start_span("child_operation", parent=parent)
        
        self.assertEqual(child.trace_id, parent.trace_id)
        self.assertEqual(child.parent_span_id, parent.span_id)
        
        Tracer.end_span(child)
        Tracer.end_span(parent)
    
    def test_thread_local_nesting(self):
        """Automatic nesting via thread-local current span."""
        @trace
        def outer_function():
            inner_function()
        
        @trace
        def inner_function():
            pass
        
        outer_function()
        
        spans = TracingState.get_completed_spans()
        self.assertEqual(len(spans), 2)
        
        # Find parent and child
        outer = next(s for s in spans if "outer_function" in s.name)
        inner = next(s for s in spans if "inner_function" in s.name)
        
        self.assertEqual(inner.parent_span_id, outer.span_id)
        self.assertEqual(inner.trace_id, outer.trace_id)
    
    def test_custom_trace_id(self):
        """Can use custom trace ID for cross-service correlation."""
        custom_trace_id = "custom-trace-id-12345"
        span = Tracer.start_span("correlated_span", trace_id=custom_trace_id)
        self.assertEqual(span.trace_id, custom_trace_id)
        Tracer.end_span(span)
class TestTraceDecorator(unittest.TestCase):
    """Tests for the @trace function decorator."""
    
    def setUp(self):
        reset_tracing()
        enable_tracing()
    
    def tearDown(self):
        disable_tracing()
        reset_tracing()
    
    def test_decorator_creates_span(self):
        """Decorator creates a span for function execution."""
        @trace
        def my_function(x, y):
            return x + y
        
        result = my_function(2, 3)
        self.assertEqual(result, 5)
        
        spans = TracingState.get_completed_spans()
        self.assertEqual(len(spans), 1)
        self.assertIn("my_function", spans[0].name)
        self.assertEqual(spans[0].status, SpanStatus.OK)
    
    def test_decorator_with_custom_name(self):
        """Decorator supports custom span names."""
        @trace(name="custom_operation_name")
        def my_function():
            return True
        
        my_function()
        spans = TracingState.get_completed_spans()
        self.assertEqual(spans[0].name, "custom_operation_name")
    
    def test_decorator_captures_exceptions(self):
        """Decorator captures exceptions and marks span as ERROR."""
        @trace
        def failing_function():
            raise ValueError("test error")
        
        with self.assertRaises(ValueError):
            failing_function()
        
        spans = TracingState.get_completed_spans()
        self.assertEqual(len(spans), 1)
        self.assertEqual(spans[0].status, SpanStatus.ERROR)
        self.assertIn("test error", spans[0].status_description)
        self.assertEqual(spans[0].tags["error.type"], "ValueError")
    
    def test_decorator_with_kind(self):
        """Decorator supports specifying span kind."""
        @trace(kind=SpanKind.CLIENT)
        def client_call():
            return "response"
        
        client_call()
        spans = TracingState.get_completed_spans()
        self.assertEqual(spans[0].kind, SpanKind.CLIENT)
    
    def test_decorator_with_initial_tags(self):
        """Decorator supports initial tags."""
        @trace(component="api", version="v1")
        def api_call():
            return "ok"
        
        api_call()
        spans = TracingState.get_completed_spans()
        self.assertEqual(spans[0].tags["component"], "api")
        self.assertEqual(spans[0].tags["version"], "v1")
class TestDisabledMode(unittest.TestCase):
    """Tests for no-op behavior when tracing is disabled."""
    
    def setUp(self):
        reset_tracing()
        disable_tracing()
    
    def test_disabled_creates_no_spans(self):
        """When disabled, no spans are recorded."""
        @trace
        def my_function():
            return True
        
        for _ in range(10):
            my_function()
        
        spans = TracingState.get_completed_spans()
        self.assertEqual(len(spans), 0)
    
    def test_disabled_span_is_noop(self):
        """When disabled, span creation returns minimal no-op span."""
        span = Tracer.start_span("should_not_be_recorded")
        self.assertEqual(span.trace_id, "disabled")
        self.assertEqual(span.span_id, "disabled")
        Tracer.end_span(span)  # Should not crash
    
    def test_disabled_performance(self):
        """Disabled mode should have near-zero overhead."""
        @trace
        def fast_function():
            return 42
        
        start = time.perf_counter()
        for _ in range(10000):
            fast_function()
        duration = time.perf_counter() - start
        
        # 10k calls should be near-instant (< 50ms)
        self.assertLess(duration, 0.05)
class TestTraceExporting(unittest.TestCase):
    """Tests for span export functionality."""
    
    def setUp(self):
        reset_tracing()
        enable_tracing()
    
    def tearDown(self):
        disable_tracing()
        reset_tracing()
    
    def test_export_to_dict(self):
        """Can export spans to dictionary format."""
        span1 = Tracer.start_span("first")
        Tracer.end_span(span1)
        span2 = Tracer.start_span("second")
        Tracer.end_span(span2)
        
        data = TraceExporter.to_dict(clear=False)
        self.assertEqual(data["span_count"], 2)
        self.assertEqual(len(data["spans"]), 2)
        self.assertIn("exported_at", data)
    
    def test_export_to_json_file(self):
        """Can export spans to JSON file."""
        span = Tracer.start_span("json_export_test")
        span.set_tag("export_test", True)
        Tracer.end_span(span)
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            filepath = f.name
        
        try:
            TraceExporter.to_json(filepath)
            
            with open(filepath, 'r') as f:
                data = json.load(f)
            
            self.assertEqual(data["span_count"], 1)
            self.assertEqual(data["spans"][0]["name"], "json_export_test")
        finally:
            os.unlink(filepath)
    
    def test_export_clears_spans(self):
        """Export with clear=True removes spans from memory."""
        span = Tracer.start_span("to_clear")
        Tracer.end_span(span)
        
        self.assertEqual(len(TracingState.get_completed_spans()), 1)
        TraceExporter.to_dict(clear=True)
        self.assertEqual(len(TracingState.get_completed_spans()), 0)
class TestTraceAnalysis(unittest.TestCase):
    """Tests for trace analysis and summary functionality."""
    
    def setUp(self):
        reset_tracing()
        enable_tracing()
    
    def tearDown(self):
        disable_tracing()
        reset_tracing()
    
    def test_trace_summary(self):
        """Can generate trace summary statistics."""
        # Create some spans
        for i in range(5):
            span = Tracer.start_span(f"operation_{i}")
            time.sleep(0.001)
            Tracer.end_span(span)
        
        summary = TraceAnalyzer.get_trace_summary()
        self.assertIn("summary", summary)
        self.assertEqual(summary["summary"]["total_spans"], 5)
        self.assertEqual(summary["summary"]["total_traces"], 5)  # Each is separate
        self.assertIn("slowest_spans", summary)
        self.assertIn("largest_traces", summary)
    
    def test_error_rate_calculation(self):
        """Summary correctly calculates error rates."""
        # 3 OK, 1 ERROR
        for _ in range(3):
            span = Tracer.start_span("success")
            Tracer.end_span(span, SpanStatus.OK)
        
        span = Tracer.start_span("failure")
        Tracer.end_span(span, SpanStatus.ERROR)
        
        summary = TraceAnalyzer.get_trace_summary()
        self.assertEqual(summary["summary"]["error_count"], 1)
        self.assertEqual(summary["summary"]["error_rate"], 0.25)
    
    def test_empty_trace_summary(self):
        """Empty trace summary returns appropriate message."""
        summary = TraceAnalyzer.get_trace_summary()
        self.assertEqual(summary["message"], "No traces available")
class TestThreadSafety(unittest.TestCase):
    """Tests for thread-safe tracing behavior."""
    
    def setUp(self):
        reset_tracing()
        enable_tracing()
    
    def tearDown(self):
        disable_tracing()
        reset_tracing()
    
    def test_concurrent_tracing(self):
        """Tracing works correctly across multiple threads."""
        def thread_worker(thread_id):
            @trace(name=f"thread_{thread_id}_work")
            def work():
                time.sleep(0.001)
                return thread_id
            
            for _ in range(10):
                work()
        
        threads = []
        for i in range(5):
            t = threading.Thread(target=thread_worker, args=(i,))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        spans = TracingState.get_completed_spans()
        self.assertEqual(len(spans), 50)  # 5 threads × 10 calls
class TestPublicAPI(unittest.TestCase):
    """Tests for the public API functions."""
    
    def setUp(self):
        reset_tracing()
    
    def test_public_api_functions(self):
        """All public API functions work correctly."""
        # Enable via public API
        enable_tracing()
        self.assertTrue(TracingState.is_enabled())
        
        # Create some traces
        @trace
        def test_fn():
            return True
        
        test_fn()
        
        # Get metrics via public API
        metrics = get_traces()
        self.assertIn("summary", metrics)
        
        # Export via public API
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            filepath = f.name
        
        try:
            export_traces_json(filepath)
            self.assertTrue(os.path.exists(filepath))
        finally:
            os.unlink(filepath)
        
        # Reset via public API
        reset_tracing()
        self.assertEqual(len(TracingState.get_completed_spans()), 0)
        
        # Disable via public API
        disable_tracing()
        self.assertFalse(TracingState.is_enabled())
class TestSampling(unittest.TestCase):
    """Tests for trace sampling functionality."""
    
    def test_sampling_at_zero(self):
        """Sampling rate 0 means no traces are recorded."""
        reset_tracing()
        enable_tracing(sampling_rate=0.0)
        
        @trace
        def sampled_function():
            return True
        
        for _ in range(100):
            sampled_function()
        
        spans = TracingState.get_completed_spans()
        self.assertEqual(len(spans), 0)
        
        disable_tracing()
        reset_tracing()
if __name__ == "__main__":
    unittest.main(verbosity=2)
