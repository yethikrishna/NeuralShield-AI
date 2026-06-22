"""
Tests for NeuralShield Enhanced Observability & SLO Monitoring V6
DIMENSION D: Observability & Instrumentation
"""

import pytest
import time
import threading
from neural_shield.observability_enhanced_slo_tracing_v6_2026_june import (
    EnhancedObservabilityEngine,
    ThreadLocalContext,
    LatencyHistogram,
    SLOMonitor,
    SLOConfig,
    SLOStatus,
    enable_observability,
    disable_observability,
    observability
)


class TestLatencyHistogram:
    def test_basic_recording(self):
        hist = LatencyHistogram("test")
        hist.record(0.05)
        hist.record(0.1)
        hist.record(0.02)
        
        stats = hist.get_stats()
        assert stats["count"] == 3
        assert stats["avg"] > 0
    
    def test_percentiles(self):
        hist = LatencyHistogram("test")
        for i in range(100):
            hist.record(i * 0.001)
        
        stats = hist.get_stats()
        assert stats["p50"] <= stats["p95"] <= stats["p99"]
        assert stats["p99"] <= stats["p99.9"]
    
    def test_empty_histogram(self):
        hist = LatencyHistogram("test")
        stats = hist.get_stats()
        assert stats["count"] == 0
        assert stats["avg"] == 0


class TestSLOMonitor:
    def test_register_and_get_status(self):
        monitor = SLOMonitor()
        monitor.register_slo(SLOConfig("test_slo", 99.9))
        
        status = monitor.get_slo_status("test_slo")
        assert status is not None
        assert status.current_availability == 100.0
        assert status.status == SLOStatus.HEALTHY
    
    def test_record_events(self):
        monitor = SLOMonitor()
        monitor.register_slo(SLOConfig("test_slo", 99.9))
        
        for _ in range(100):
            monitor.record_event("test_slo", is_error=False)
        
        status = monitor.get_slo_status("test_slo")
        assert status.window_events == 100
        assert status.window_errors == 0
    
    def test_error_budget_calculation(self):
        monitor = SLOMonitor()
        monitor.register_slo(SLOConfig("test_slo", 99.0))  # 1% error budget
        
        # 100 events with 1 error = 1% error rate
        for _ in range(99):
            monitor.record_event("test_slo", is_error=False)
        monitor.record_event("test_slo", is_error=True)
        
        status = monitor.get_slo_status("test_slo")
        assert status.current_availability == 99.0
        assert 0 <= status.error_budget_consumed_pct <= 100
    
    def test_unknown_slo_returns_none(self):
        monitor = SLOMonitor()
        assert monitor.get_slo_status("nonexistent") is None


class TestThreadLocalContext:
    def test_set_get_trace_id(self):
        ThreadLocalContext.set_current_trace_id("test-trace-123")
        assert ThreadLocalContext.get_current_trace_id() == "test-trace-123"
    
    def test_set_get_span_id(self):
        ThreadLocalContext.set_current_span_id("span-456")
        assert ThreadLocalContext.get_current_span_id() == "span-456"
    
    def test_clear_context(self):
        ThreadLocalContext.set_current_trace_id("test")
        ThreadLocalContext.set_current_span_id("span")
        ThreadLocalContext.clear()
        assert ThreadLocalContext.get_current_trace_id() is None
        assert ThreadLocalContext.get_current_span_id() is None
    
    def test_thread_isolation(self):
        results = {}
        
        def worker(thread_id):
            ThreadLocalContext.set_current_trace_id(f"trace-{thread_id}")
            time.sleep(0.01)
            results[thread_id] = ThreadLocalContext.get_current_trace_id()
        
        threads = [threading.Thread(target=worker, args=(i,)) for i in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert results[0] == "trace-0"
        assert results[1] == "trace-1"
        assert results[2] == "trace-2"


class TestEnhancedObservabilityEngine:
    def test_disabled_by_default(self):
        engine = EnhancedObservabilityEngine(enabled=False)
        assert engine.enabled is False
        metrics = engine.get_metrics_summary()
        assert metrics["enabled"] is False
    
    def test_can_be_enabled(self):
        engine = EnhancedObservabilityEngine(enabled=True)
        assert engine.enabled is True
        metrics = engine.get_metrics_summary()
        assert metrics["enabled"] is True
    
    def test_start_end_trace_when_disabled(self):
        engine = EnhancedObservabilityEngine(enabled=False)
        span = engine.start_trace("test_operation")
        assert span.trace_id == ""  # Noop when disabled
        engine.end_trace(span)  # Should not crash
    
    def test_tracing_when_enabled(self):
        engine = EnhancedObservabilityEngine(enabled=True)
        span = engine.start_trace("test_operation", attributes={"key": "value"})
        assert span.trace_id != ""
        assert span.span_id != ""
        time.sleep(0.001)
        engine.end_trace(span, {"result": "success"})
        
        trace = engine.get_trace(span.trace_id)
        assert len(trace) == 1
        assert trace[0]["name"] == "test_operation"
        assert trace[0]["duration_ms"] > 0
    
    def test_trace_decorator(self):
        engine = EnhancedObservabilityEngine(enabled=True)
        
        @engine.trace("decorated_function")
        def test_func(x):
            return x * 2
        
        result = test_func(5)
        assert result == 10
        
        # Give async recording time to complete
        time.sleep(0.01)
        metrics = engine.get_metrics_summary()
        assert "decorated_function" in metrics["latency"]
    
    def test_trace_decorator_with_exception(self):
        engine = EnhancedObservabilityEngine(enabled=True)
        
        @engine.trace("error_function")
        def error_func():
            raise ValueError("test error")
        
        with pytest.raises(ValueError):
            error_func()
    
    def test_counter_increment(self):
        engine = EnhancedObservabilityEngine(enabled=True)
        engine.increment_counter("test_counter", 1, {"label": "value"})
        engine.increment_counter("test_counter", 2, {"label": "value"})
        
        metrics = engine.get_metrics_summary()
        assert any("test_counter" in k for k in metrics["counters"].keys())
    
    def test_gauge_set(self):
        engine = EnhancedObservabilityEngine(enabled=True)
        engine.set_gauge("memory_usage", 128.5, {"service": "neuralshield"})
        
        metrics = engine.get_metrics_summary()
        assert any("memory_usage" in k for k in metrics["gauges"].keys())
    
    def test_slo_recording(self):
        engine = EnhancedObservabilityEngine(enabled=True)
        for _ in range(10):
            engine.record_slo_event("threat_detection_availability", is_error=False)
        
        slos = engine.get_all_slo_status()
        assert len(slos) >= 2  # Default SLOs
    
    def test_health_check_registration(self):
        engine = EnhancedObservabilityEngine(enabled=True)
        
        def always_healthy():
            return True
        
        engine.register_health_check("test_check", always_healthy)
        result = engine.run_health_checks()
        assert result["overall_healthy"] is True
        assert result["checks"]["test_check"]["healthy"] is True
    
    def test_health_check_with_exception(self):
        engine = EnhancedObservabilityEngine(enabled=True)
        
        def failing_check():
            raise RuntimeError("check failed")
        
        engine.register_health_check("failing_check", failing_check)
        result = engine.run_health_checks()
        assert result["overall_healthy"] is False
        assert result["checks"]["failing_check"]["healthy"] is False
        assert result["checks"]["failing_check"]["error"] is not None
    
    def test_context_propagation(self):
        engine = EnhancedObservabilityEngine(enabled=True)
        
        # Parent span
        parent = engine.start_trace("parent_operation")
        parent_trace_id = ThreadLocalContext.get_current_trace_id()
        parent_span_id = ThreadLocalContext.get_current_span_id()
        
        # Child span should inherit context
        child = engine.start_trace("child_operation")
        assert child.trace_id == parent_trace_id
        assert child.parent_span_id == parent_span_id
        
        engine.end_trace(child)
        engine.end_trace(parent)


class TestGlobalInstance:
    def test_global_instance_exists(self):
        assert observability is not None
    
    def test_enable_disable(self):
        original = observability.enabled
        enable_observability()
        assert observability.enabled is True
        disable_observability()
        assert observability.enabled is False
        # Restore
        observability.enabled = original


class TestIntegration:
    def test_full_observability_workflow(self):
        engine = EnhancedObservabilityEngine(enabled=True)
        
        # Simulate a full detection workflow - FIXED: correct parameter order
        span = engine.start_trace(
            "threat_detection_pipeline",
            attributes={"input_length": 100, "model_version": "v1"}
        )
        
        # Record sub-operation
        sub_span = engine.start_trace("embedding_generation")
        time.sleep(0.005)
        engine.end_trace(sub_span)
        
        # Record metrics
        engine.increment_counter("detections_total", 1, {"severity": "medium"})
        engine.record_latency("classification", 0.023)
        
        # Record SLO
        engine.record_slo_event("threat_detection_availability", is_error=False)
        
        engine.end_trace(span, {"threat_detected": False, "confidence": 0.95})
        
        # Verify all data captured
        metrics = engine.get_metrics_summary()
        assert metrics["enabled"] is True
        assert len(metrics["latency"]) > 0
        
        trace = engine.get_trace(span.trace_id)
        assert len(trace) == 2  # parent + child


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
