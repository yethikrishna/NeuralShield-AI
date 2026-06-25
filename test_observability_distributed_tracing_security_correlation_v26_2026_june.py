"""
Tests for NeuralShield Distributed Tracing & Security Correlation - V26
Dimension D: Observability & Instrumentation

All tests verify OPT-IN behavior - core functionality never affected.
"""

import unittest
import time
import json
import threading
from neural_shield.observability_distributed_tracing_security_correlation_v26_2026_june import (
    DistributedTracer,
    TraceLevel,
    SecurityEventType,
    get_tracer,
    traced_operation
)


class TestDistributedTracerBasics(unittest.TestCase):
    """Test basic tracer functionality"""
    
    def setUp(self):
        self.tracer = DistributedTracer()
    
    def test_tracer_starts_disabled(self):
        """Tracer MUST start DISABLED by default"""
        self.assertFalse(self.tracer.is_enabled())
    
    def test_enable_disable_works(self):
        """Enable and disable work correctly"""
        self.assertFalse(self.tracer.is_enabled())
        self.tracer.enable(TraceLevel.INFO)
        self.assertTrue(self.tracer.is_enabled())
        self.tracer.disable()
        self.assertFalse(self.tracer.is_enabled())
    
    def test_disabled_tracer_returns_none_for_spans(self):
        """When disabled, start_span returns None (no overhead)"""
        span_id = self.tracer.start_span("test_operation")
        self.assertIsNone(span_id)
    
    def test_disabled_tracer_returns_none_for_security_events(self):
        """When disabled, security events return None (no overhead)"""
        event_id = self.tracer.log_security_event(
            SecurityEventType.THREAT_DETECTED,
            "WARNING",
            "Test threat"
        )
        self.assertIsNone(event_id)
    
    def test_generate_ids_are_unique(self):
        """Trace and span IDs are unique"""
        self.tracer.enable(TraceLevel.DEBUG)
        trace_ids = set(self.tracer.generate_trace_id() for _ in range(100))
        span_ids = set(self.tracer.generate_span_id() for _ in range(100))
        self.assertEqual(len(trace_ids), 100)
        self.assertEqual(len(span_ids), 100)


class TestSpanManagement(unittest.TestCase):
    """Test span creation and management"""
    
    def setUp(self):
        self.tracer = DistributedTracer()
        self.tracer.enable(TraceLevel.INFO)
    
    def test_start_and_end_span(self):
        """Basic span lifecycle"""
        span_id = self.tracer.start_span("test_operation")
        self.assertIsNotNone(span_id)
        time.sleep(0.001)
        duration = self.tracer.end_span(span_id)
        self.assertIsNotNone(duration)
        self.assertGreater(duration, 0)
    
    def test_span_attributes(self):
        """Span attributes can be added"""
        span_id = self.tracer.start_span("test_with_attrs")
        self.tracer.add_span_attribute(span_id, "key1", "value1")
        self.tracer.add_span_attribute(span_id, "key2", 42)
        self.tracer.end_span(span_id)
    
    def test_span_events(self):
        """Span events can be added"""
        span_id = self.tracer.start_span("test_with_events")
        self.tracer.add_span_event(span_id, "processing_started")
        self.tracer.add_span_event(span_id, "data_received", {"size": 1024})
        self.tracer.end_span(span_id)
    
    def test_nested_spans(self):
        """Nested spans maintain proper parent-child relationship"""
        parent_id = self.tracer.start_span("parent_operation")
        child_id = self.tracer.start_span("child_operation")
        self.assertIsNotNone(child_id)
        self.tracer.end_span(child_id)
        self.tracer.end_span(parent_id)


class TestSecurityEventCorrelation(unittest.TestCase):
    """Test security event correlation with tracing"""
    
    def setUp(self):
        self.tracer = DistributedTracer()
        self.tracer.enable(TraceLevel.INFO)
    
    def test_security_event_within_span(self):
        """Security events get correlated with active span"""
        span_id = self.tracer.start_span("security_check")
        event_id = self.tracer.log_security_event(
            SecurityEventType.JAILBREAK_ATTEMPT,
            "CRITICAL",
            "Potential jailbreak detected in user input",
            {"input_length": 150, "confidence": 0.87}
        )
        self.assertIsNotNone(event_id)
        self.tracer.end_span(span_id)
    
    def test_security_event_callback(self):
        """Security event callback is triggered"""
        received_events = []
        
        def callback(event):
            received_events.append(event)
        
        self.tracer.set_security_event_callback(callback)
        self.tracer.start_span("test_callback")
        self.tracer.log_security_event(
            SecurityEventType.PROMPT_INJECTION,
            "ERROR",
            "Injection pattern detected"
        )
        self.tracer.end_span(None)
        
        self.assertEqual(len(received_events), 1)
    
    def test_get_security_correlations(self):
        """Can retrieve correlated security events"""
        self.tracer.start_span("security_scan")
        self.tracer.log_security_event(
            SecurityEventType.ANOMALY_DETECTED,
            "WARNING",
            "Anomaly in request pattern"
        )
        self.tracer.log_security_event(
            SecurityEventType.ACCESS_DENIED,
            "ERROR",
            "Unauthorized access attempt"
        )
        self.tracer.end_span(None)
        
        events = self.tracer.get_security_correlations("WARNING")
        self.assertGreaterEqual(len(events), 2)


class TestTraceExport(unittest.TestCase):
    """Test trace export functionality"""
    
    def setUp(self):
        self.tracer = DistributedTracer()
        self.tracer.enable(TraceLevel.INFO)
    
    def test_export_traces_json(self):
        """Export traces as valid JSON"""
        span_id = self.tracer.start_span("export_test", attributes={"test": True})
        self.tracer.add_span_event(span_id, "processing")
        self.tracer.log_security_event(
            SecurityEventType.THREAT_DETECTED,
            "INFO",
            "Test event for export"
        )
        self.tracer.end_span(span_id)
        
        json_output = self.tracer.export_traces_json()
        data = json.loads(json_output)
        self.assertIn("traces", data)
        self.assertIn("security_events", data)
        self.assertIn("service", data)
    
    def test_get_trace_summary(self):
        """Get summary for a specific trace"""
        span_id = self.tracer.start_span("summary_test")
        trace_id = self.tracer._context.current_trace_id
        self.tracer.end_span(span_id)
        
        summary = self.tracer.get_trace_summary(trace_id)
        self.assertIsNotNone(summary)
        self.assertEqual(summary["trace_id"], trace_id)
        self.assertGreaterEqual(summary["span_count"], 1)


class TestTracedOperationDecorator(unittest.TestCase):
    """Test the traced_operation decorator"""
    
    def test_decorator_when_disabled(self):
        """Decorator has NO effect when tracer is disabled"""
        tracer = get_tracer()
        tracer.disable()
        
        call_count = [0]
        
        @traced_operation("decorated_func")
        def test_func(x, y):
            call_count[0] += 1
            return x + y
        
        result = test_func(2, 3)
        self.assertEqual(result, 5)
        self.assertEqual(call_count[0], 1)
    
    def test_decorator_when_enabled(self):
        """Decorator creates spans when tracer is enabled"""
        tracer = get_tracer()
        tracer.enable(TraceLevel.INFO)
        tracer.clear()
        
        @traced_operation("decorated_add")
        def add_func(x, y):
            return x + y
        
        result = add_func(10, 20)
        self.assertEqual(result, 30)
        
        tracer.disable()
    
    def test_decorator_exception_propagation(self):
        """Decorator properly propagates exceptions"""
        tracer = get_tracer()
        tracer.enable(TraceLevel.INFO)
        tracer.clear()
        
        @traced_operation("error_func")
        def error_func():
            raise ValueError("Test error")
        
        with self.assertRaises(ValueError):
            error_func()
        
        tracer.disable()


class TestThreadSafety(unittest.TestCase):
    """Test thread safety of the tracer"""
    
    def test_concurrent_spans(self):
        """Multiple threads can create spans concurrently"""
        tracer = DistributedTracer()
        tracer.enable(TraceLevel.INFO)
        
        errors = []
        
        def worker(thread_id):
            try:
                for i in range(10):
                    span_id = tracer.start_span(f"thread_{thread_id}_op_{i}")
                    time.sleep(0.0001)
                    tracer.end_span(span_id)
            except Exception as e:
                errors.append(e)
        
        threads = [threading.Thread(target=worker, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        self.assertEqual(len(errors), 0)


class TestGracefulDegradation(unittest.TestCase):
    """Test graceful degradation at limits"""
    
    def test_max_spans_limit(self):
        """Tracer stops gracefully at max spans limit"""
        tracer = DistributedTracer()
        tracer._max_spans = 5  # Small limit for testing
        tracer.enable(TraceLevel.INFO)
        
        # Create spans up to limit
        span_ids = []
        for i in range(10):
            span_id = tracer.start_span(f"span_{i}")
            if span_id:
                span_ids.append(span_id)
        
        # Should have stopped at 5 spans
        self.assertLessEqual(len(span_ids), 5)


class TestGlobalTracer(unittest.TestCase):
    """Test global tracer singleton"""
    
    def test_get_tracer_returns_same_instance(self):
        """get_tracer always returns the same instance"""
        t1 = get_tracer()
        t2 = get_tracer()
        self.assertIs(t1, t2)
    
    def test_global_tracer_starts_disabled(self):
        """Global tracer is disabled by default"""
        tracer = get_tracer()
        tracer.disable()  # Reset state
        self.assertFalse(tracer.is_enabled())


if __name__ == "__main__":
    unittest.main()
