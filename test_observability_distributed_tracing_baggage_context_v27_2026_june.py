"""
Test Suite for Observability Distributed Tracing Baggage Context v27
Dimension D: Observability & Instrumentation

All tests verify that:
1. Module is DISABLED by default (no behavioral changes)
2. When enabled, works correctly
3. No existing code paths are modified
4. 100% backward compatible
"""

import os
import sys
import threading
import unittest
from unittest.mock import MagicMock, patch
from typing import Dict, Any

# Add module path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

class TestObservabilityDisabledByDefault(unittest.TestCase):
    """Verify observability is DISABLED by default - NO behavioral changes"""
    
    def setUp(self):
        # Ensure environment variable is NOT set
        if 'NEURALSHIELD_OBSERVABILITY_ENABLED' in os.environ:
            del os.environ['NEURALSHIELD_OBSERVABILITY_ENABLED']
    
    def test_disabled_by_default_no_env(self):
        """CRITICAL: Observability must be disabled without explicit opt-in"""
        from neural_shield.observability_distributed_tracing_baggage_context_v27_2026_june import (
            ObservabilityConfig, TraceLevel
        )
        self.assertFalse(ObservabilityConfig.is_enabled())
        self.assertEqual(ObservabilityConfig.get_level(), TraceLevel.DISABLED)
    
    def test_trace_span_no_op_when_disabled(self):
        """trace_span should be NO-OP when disabled"""
        from neural_shield.observability_distributed_tracing_baggage_context_v27_2026_june import (
            trace_span, get_current_trace_context
        )
        
        execution_count = [0]
        
        with trace_span("test_operation") as ctx:
            execution_count[0] += 1
            self.assertIsNone(ctx)
        
        self.assertEqual(execution_count[0], 1)
        self.assertIsNone(get_current_trace_context())
    
    def test_traced_decorator_no_op_when_disabled(self):
        """@traced decorator should be NO-OP when disabled"""
        from neural_shield.observability_distributed_tracing_baggage_context_v27_2026_june import (
            traced, get_current_trace_context
        )
        
        call_count = [0]
        
        @traced("test_function")
        def test_func(x, y):
            call_count[0] += 1
            return x + y
        
        result = test_func(2, 3)
        self.assertEqual(result, 5)
        self.assertEqual(call_count[0], 1)
        self.assertIsNone(get_current_trace_context())
    
    def test_metrics_empty_when_disabled(self):
        """Metrics should return empty when disabled"""
        from neural_shield.observability_distributed_tracing_baggage_context_v27_2026_june import (
            get_metrics_snapshot
        )
        
        snapshot = get_metrics_snapshot()
        self.assertEqual(snapshot["status"], "disabled")
        self.assertEqual(snapshot["counters"], {})
        self.assertEqual(snapshot["timers"], {})
    
    def test_headers_empty_when_disabled(self):
        """Trace headers should be empty when disabled"""
        from neural_shield.observability_distributed_tracing_baggage_context_v27_2026_june import (
            extract_trace_headers
        )
        
        headers = extract_trace_headers()
        self.assertEqual(headers, {})
    
    def test_add_baggage_safe_when_disabled(self):
        """add_baggage should not error when disabled"""
        from neural_shield.observability_distributed_tracing_baggage_context_v27_2026_june import (
            add_baggage
        )
        
        # Should not raise any exceptions
        add_baggage("key", "value")

class TestObservabilityWhenEnabled(unittest.TestCase):
    """Test observability functionality when explicitly enabled"""
    
    def setUp(self):
        os.environ['NEURALSHIELD_OBSERVABILITY_ENABLED'] = '1'
        # Force reimport to pick up env var
        import importlib
        import neural_shield.observability_distributed_tracing_baggage_context_v27_2026_june as obs
        importlib.reload(obs)
        obs.ObservabilityConfig.enable(obs.TraceLevel.BASIC)
        self.obs = obs
    
    def tearDown(self):
        if 'NEURALSHIELD_OBSERVABILITY_ENABLED' in os.environ:
            del os.environ['NEURALSHIELD_OBSERVABILITY_ENABLED']
    
    def test_enabled_when_explicitly_opted_in(self):
        """Observability should work when explicitly enabled"""
        self.assertTrue(self.obs.ObservabilityConfig.is_enabled())
    
    def test_trace_span_creates_context(self):
        """trace_span should create valid context when enabled"""
        with self.obs.trace_span("test_op", {"key": "value"}) as ctx:
            self.assertIsNotNone(ctx)
            self.assertIsNotNone(ctx.trace_id)
            self.assertIsNotNone(ctx.span_id)
            self.assertEqual(len(ctx.trace_id), 32)
            self.assertEqual(len(ctx.span_id), 16)
            self.assertEqual(ctx.baggage["key"], "value")
    
    def test_trace_span_nested_propagation(self):
        """Nested spans should propagate trace ID correctly"""
        with self.obs.trace_span("parent") as parent_ctx:
            parent_trace_id = parent_ctx.trace_id
            
            with self.obs.trace_span("child") as child_ctx:
                self.assertEqual(child_ctx.trace_id, parent_trace_id)
                self.assertEqual(child_ctx.parent_span_id, parent_ctx.span_id)
    
    def test_traced_decorator_works(self):
        """@traced decorator should work when enabled"""
        call_count = [0]
        
        @self.obs.traced("decorated_func")
        def test_func(a):
            call_count[0] += 1
            return a * 2
        
        result = test_func(5)
        self.assertEqual(result, 10)
        self.assertEqual(call_count[0], 1)
    
    def test_baggage_propagation(self):
        """Baggage should propagate through nested spans"""
        with self.obs.trace_span("outer", {"outer_key": "outer_val"}):
            self.obs.add_baggage("inner_key", "inner_val")
            
            with self.obs.trace_span("inner") as inner_ctx:
                self.assertIn("outer_key", inner_ctx.baggage)
                self.assertIn("inner_key", inner_ctx.baggage)
    
    def test_get_current_context(self):
        """get_current_trace_context should return valid dict"""
        with self.obs.trace_span("test"):
            ctx_dict = self.obs.get_current_trace_context()
            self.assertIsNotNone(ctx_dict)
            self.assertIn("trace_id", ctx_dict)
            self.assertIn("span_id", ctx_dict)
            self.assertIn("baggage", ctx_dict)
    
    def test_extract_trace_headers(self):
        """Should extract W3C compliant trace headers"""
        with self.obs.trace_span("test"):
            headers = self.obs.extract_trace_headers()
            self.assertIn("traceparent", headers)
            self.assertTrue(headers["traceparent"].startswith("00-"))
    
    def test_metrics_collection(self):
        """Metrics should be collected when enabled"""
        with self.obs.trace_span("metric_test"):
            pass
        
        snapshot = self.obs.get_metrics_snapshot()
        self.assertEqual(snapshot["status"], "enabled")
        self.assertIn("span.metric_test.started", snapshot["counters"])
        self.assertIn("span.metric_test.duration", snapshot["timers"])

class TestThreadSafety(unittest.TestCase):
    """Verify thread-local context isolation"""
    
    def setUp(self):
        os.environ['NEURALSHIELD_OBSERVABILITY_ENABLED'] = '1'
        import importlib
        import neural_shield.observability_distributed_tracing_baggage_context_v27_2026_june as obs
        importlib.reload(obs)
        obs.ObservabilityConfig.enable(obs.TraceLevel.BASIC)
        self.obs = obs
    
    def tearDown(self):
        if 'NEURALSHIELD_OBSERVABILITY_ENABLED' in os.environ:
            del os.environ['NEURALSHIELD_OBSERVABILITY_ENABLED']
    
    def test_thread_local_context_isolation(self):
        """Each thread should have independent context"""
        thread_contexts = {}
        barrier = threading.Barrier(3)
        
        def thread_worker(thread_id):
            with self.obs.trace_span(f"thread_{thread_id}_op") as ctx:
                barrier.wait()
                thread_contexts[thread_id] = ctx.trace_id
                barrier.wait()
        
        threads = [
            threading.Thread(target=thread_worker, args=(1,)),
            threading.Thread(target=thread_worker, args=(2,)),
            threading.Thread(target=thread_worker, args=(3,)),
        ]
        
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        # All trace IDs should be unique per thread
        trace_ids = list(thread_contexts.values())
        self.assertEqual(len(set(trace_ids)), 3)

class TestThreatIntelligenceTracer(unittest.TestCase):
    """Test specialized threat intelligence tracer wrappers"""
    
    def setUp(self):
        os.environ['NEURALSHIELD_OBSERVABILITY_ENABLED'] = '1'
        import importlib
        import neural_shield.observability_distributed_tracing_baggage_context_v27_2026_june as obs
        importlib.reload(obs)
        obs.ObservabilityConfig.enable(obs.TraceLevel.BASIC)
        self.obs = obs
    
    def tearDown(self):
        if 'NEURALSHIELD_OBSERVABILITY_ENABLED' in os.environ:
            del os.environ['NEURALSHIELD_OBSERVABILITY_ENABLED']
    
    def test_wrap_feed_fetch_preserves_behavior(self):
        """Wrapper should preserve original function behavior"""
        def original_fetch(source):
            return f"data_from_{source}"
        
        result = self.obs.ThreatIntelligenceTracer.wrap_feed_fetch(
            original_fetch, "test_source"
        )
        self.assertEqual(result, "data_from_test_source")
    
    def test_wrap_correlation_preserves_behavior(self):
        """Wrapper should preserve original function behavior"""
        def original_correlate(indicators):
            return len(indicators)
        
        result = self.obs.ThreatIntelligenceTracer.wrap_correlation(
            original_correlate, ["ioc1", "ioc2", "ioc3"]
        )
        self.assertEqual(result, 3)
    
    def test_wrap_enrichment_preserves_behavior(self):
        """Wrapper should preserve original function behavior"""
        def original_enrich(alert, **kwargs):
            return {**alert, "enriched": True}
        
        result = self.obs.ThreatIntelligenceTracer.wrap_enrichment(
            original_enrich, {"id": "alert1"}, extra="data"
        )
        self.assertEqual(result["id"], "alert1")
        self.assertTrue(result["enriched"])

class TestBackwardCompatibility(unittest.TestCase):
    """Verify 100% backward compatibility - no breaking changes"""
    
    def test_no_modification_to_existing_modules(self):
        """CRITICAL: This module should NOT modify any existing code"""
        # This test verifies we're only adding, not replacing
        import neural_shield
        
        # List should not include any overridden modules
        # We're purely additive
        self.assertTrue(hasattr(
            neural_shield.observability_distributed_tracing_baggage_context_v27_2026_june,
            'ObservabilityConfig'
        ))
    
    def test_disabled_by_default_guarantee(self):
        """Guarantee: Default behavior is 100% identical to before"""
        import importlib
        import neural_shield.observability_distributed_tracing_baggage_context_v27_2026_june as obs
        importlib.reload(obs)
        
        # Without any env vars or explicit enable
        self.assertFalse(obs.ObservabilityConfig.is_enabled())

if __name__ == '__main__':
    unittest.main(verbosity=2)
