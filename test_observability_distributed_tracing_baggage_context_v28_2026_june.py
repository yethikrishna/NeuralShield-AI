"""
Test Suite: Observability Distributed Tracing with Baggage Context v28
DIMENSION D - Observability & Instrumentation

Tests for distributed tracing, baggage propagation, and health checks.
All tests verify OPT-IN behavior - disabled by default.
"""

import os
import pytest
import threading
import time
from neural_shield.observability_distributed_tracing_baggage_context_v28_2026_june import (
    Tracer,
    BaggageContext,
    BaggageKey,
    Span,
    traced,
    HealthChecker,
    HealthCheck,
    HealthCheckStatus,
)


class TestBaggageContext:
    """Tests for thread-local baggage context propagation"""

    def setup_method(self):
        BaggageContext.clear()

    def test_baggage_set_get(self):
        """Test basic baggage set and get operations"""
        BaggageContext.set("test-key", "test-value")
        assert BaggageContext.get("test-key") == "test-value"

    def test_baggage_get_default(self):
        """Test baggage get with default value"""
        assert BaggageContext.get("nonexistent", "default") == "default"

    def test_baggage_get_all(self):
        """Test getting all baggage values"""
        BaggageContext.set("key1", "value1")
        BaggageContext.set("key2", "value2")
        all_baggage = BaggageContext.get_all()
        assert all_baggage["key1"] == "value1"
        assert all_baggage["key2"] == "value2"

    def test_baggage_clear(self):
        """Test clearing all baggage"""
        BaggageContext.set("key1", "value1")
        BaggageContext.clear()
        assert BaggageContext.get("key1") is None

    def test_baggage_from_headers(self):
        """Test extracting baggage from HTTP headers"""
        headers = {
            "x-trace-id": "trace-123",
            "x-request-id": "req-456",
        }
        BaggageContext.from_headers(headers)
        assert BaggageContext.get("x-trace-id") == "trace-123"
        assert BaggageContext.get("x-request-id") == "req-456"

    def test_baggage_to_headers(self):
        """Test converting baggage to HTTP headers"""
        BaggageContext.set("x-trace-id", "trace-123")
        headers = BaggageContext.to_headers()
        assert headers["x-trace-id"] == "trace-123"

    def test_baggage_thread_isolation(self):
        """Test that baggage is thread-local"""
        def thread1_func():
            BaggageContext.set("thread-key", "thread1-value")
            time.sleep(0.01)
            return BaggageContext.get("thread-key")

        def thread2_func():
            BaggageContext.set("thread-key", "thread2-value")
            time.sleep(0.01)
            return BaggageContext.get("thread-key")

        t1 = threading.Thread(target=lambda: thread1_func())
        t2 = threading.Thread(target=lambda: thread2_func())
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        # Main thread should not see either
        assert BaggageContext.get("thread-key") is None


class TestTracer:
    """Tests for OPT-IN distributed tracer"""

    def setup_method(self):
        Tracer.disable()
        os.environ.pop("NEURALSHIELD_TRACING_ENABLED", None)
        BaggageContext.clear()

    def test_tracer_disabled_by_default(self):
        """Test that tracing is DISABLED by default (OPT-IN)"""
        assert not Tracer.is_enabled()

    def test_tracer_enable_requires_env(self):
        """Test that enabling requires both flag and env var"""
        Tracer.enable()
        assert not Tracer.is_enabled()  # Still needs env var
        
        os.environ["NEURALSHIELD_TRACING_ENABLED"] = "1"
        assert Tracer.is_enabled()

    def test_start_span_disabled_returns_none(self):
        """Test that start_span returns None when disabled"""
        span = Tracer.start_span("test-operation")
        assert span is None

    def test_start_span_enabled(self):
        """Test span creation when tracing is enabled"""
        Tracer.enable()
        os.environ["NEURALSHIELD_TRACING_ENABLED"] = "1"
        
        span = Tracer.start_span("test-operation")
        assert span is not None
        assert span.name == "test-operation"
        assert span.span_id is not None
        assert span.trace_id is not None

    def test_span_duration_calculation(self):
        """Test span duration calculation"""
        span = Span(name="test")
        time.sleep(0.01)
        span.end()
        assert span.duration_ms is not None
        assert span.duration_ms > 0

    def test_span_add_event(self):
        """Test adding events to span"""
        span = Span(name="test")
        span.add_event("processing-started", {"stage": "input"})
        assert len(span.events) == 1
        assert span.events[0]["name"] == "processing-started"

    def test_span_set_attribute(self):
        """Test setting span attributes"""
        span = Span(name="test")
        span.set_attribute("user_id", "12345")
        assert span.attributes["user_id"] == "12345"

    def test_end_span_records_metrics(self):
        """Test that ending spans records metrics"""
        Tracer.enable()
        os.environ["NEURALSHIELD_TRACING_ENABLED"] = "1"
        
        span = Tracer.start_span("test-metrics")
        Tracer.end_span(span)
        
        metrics = Tracer.get_percentiles("test-metrics")
        assert metrics["count"] == 1

    def test_percentile_calculation(self):
        """Test latency percentile calculation"""
        Tracer.enable()
        os.environ["NEURALSHIELD_TRACING_ENABLED"] = "1"
        
        for i in range(100):
            span = Tracer.start_span("percentile-test")
            time.sleep(0.001)
            Tracer.end_span(span)
        
        percentiles = Tracer.get_percentiles("percentile-test")
        assert "p50" in percentiles
        assert "p90" in percentiles
        assert "p95" in percentiles
        assert "p99" in percentiles
        assert percentiles["count"] == 100

    def test_get_trace_groups_spans(self):
        """Test getting all spans for a trace"""
        Tracer.enable()
        os.environ["NEURALSHIELD_TRACING_ENABLED"] = "1"
        
        trace_id = "test-trace-123"
        span1 = Tracer.start_span("child1", trace_id=trace_id)
        Tracer.end_span(span1)
        span2 = Tracer.start_span("child2", trace_id=trace_id)
        Tracer.end_span(span2)
        
        trace_spans = Tracer.get_trace(trace_id)
        assert len(trace_spans) == 2

    def test_traced_decorator_disabled_noop(self):
        """Test that @traced decorator is no-op when disabled"""
        call_count = 0
        
        @traced("test-function")
        def test_func():
            nonlocal call_count
            call_count += 1
            return "success"
        
        result = test_func()
        assert result == "success"
        assert call_count == 1
        # No spans should be recorded
        assert Tracer.get_percentiles("test-function") == {}

    def test_traced_decorator_enabled(self):
        """Test that @traced decorator works when enabled"""
        Tracer.enable()
        os.environ["NEURALSHIELD_TRACING_ENABLED"] = "1"
        
        @traced("decorated-function")
        def test_func():
            return "success"
        
        result = test_func()
        assert result == "success"
        
        metrics = Tracer.get_percentiles("decorated-function")
        assert metrics["count"] == 1

    def test_traced_decorator_propagates_exceptions(self):
        """Test that @traced decorator propagates exceptions"""
        Tracer.enable()
        os.environ["NEURALSHIELD_TRACING_ENABLED"] = "1"
        
        @traced("error-function")
        def error_func():
            raise ValueError("test error")
        
        with pytest.raises(ValueError):
            error_func()


class TestHealthChecker:
    """Tests for health check framework"""

    def setup_method(self):
        HealthChecker._checks = {}

    def test_register_and_run_check(self):
        """Test registering and running a health check"""
        def check_ok():
            return (HealthCheckStatus.HEALTHY, "All systems go")
        
        HealthChecker.register_check("test-check", check_ok)
        result = HealthChecker.run_check("test-check")
        
        assert result.name == "test-check"
        assert result.status == HealthCheckStatus.HEALTHY
        assert result.duration_ms >= 0

    def test_check_with_details(self):
        """Test health check with additional details"""
        def check_with_details():
            return (HealthCheckStatus.HEALTHY, "OK", {"cpu": 45, "memory": 60})
        
        HealthChecker.register_check("detailed-check", check_with_details)
        result = HealthChecker.run_check("detailed-check")
        
        assert result.details["cpu"] == 45
        assert result.details["memory"] == 60

    def test_check_degraded(self):
        """Test degraded health status"""
        def check_degraded():
            return (HealthCheckStatus.DEGRADED, "High latency detected")
        
        HealthChecker.register_check("degraded-check", check_degraded)
        result = HealthChecker.run_check("degraded-check")
        
        assert result.status == HealthCheckStatus.DEGRADED

    def test_check_unhealthy(self):
        """Test unhealthy health status"""
        def check_unhealthy():
            return (HealthCheckStatus.UNHEALTHY, "Database connection failed")
        
        HealthChecker.register_check("unhealthy-check", check_unhealthy)
        result = HealthChecker.run_check("unhealthy-check")
        
        assert result.status == HealthCheckStatus.UNHEALTHY

    def test_check_exception_handling(self):
        """Test that check exceptions are caught"""
        def failing_check():
            raise RuntimeError("Check crashed")
        
        HealthChecker.register_check("failing-check", failing_check)
        result = HealthChecker.run_check("failing-check")
        
        assert result.status == HealthCheckStatus.UNHEALTHY
        assert "Check failed" in result.message

    def test_run_all_checks(self):
        """Test running all registered checks"""
        HealthChecker.register_check("check1", lambda: (HealthCheckStatus.HEALTHY, "OK"))
        HealthChecker.register_check("check2", lambda: (HealthCheckStatus.HEALTHY, "OK"))
        
        results = HealthChecker.run_all_checks()
        assert len(results) == 2
        assert "check1" in results
        assert "check2" in results

    def test_overall_status_healthy(self):
        """Test overall status when all healthy"""
        HealthChecker.register_check("check1", lambda: (HealthCheckStatus.HEALTHY, "OK"))
        HealthChecker.register_check("check2", lambda: (HealthCheckStatus.HEALTHY, "OK"))
        
        assert HealthChecker.get_overall_status() == HealthCheckStatus.HEALTHY

    def test_overall_status_degraded(self):
        """Test overall status when one is degraded"""
        HealthChecker.register_check("check1", lambda: (HealthCheckStatus.HEALTHY, "OK"))
        HealthChecker.register_check("check2", lambda: (HealthCheckStatus.DEGRADED, "Slow"))
        
        assert HealthChecker.get_overall_status() == HealthCheckStatus.DEGRADED

    def test_overall_status_unhealthy(self):
        """Test overall status when one is unhealthy"""
        HealthChecker.register_check("check1", lambda: (HealthCheckStatus.HEALTHY, "OK"))
        HealthChecker.register_check("check2", lambda: (HealthCheckStatus.UNHEALTHY, "Failed"))
        
        assert HealthChecker.get_overall_status() == HealthCheckStatus.UNHEALTHY


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
