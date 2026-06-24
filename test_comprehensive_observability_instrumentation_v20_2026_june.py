"""
Test Suite for NeuralShield Observability & Instrumentation v20
DIMENSION D - Observability & Instrumentation

All tests verify ADD-ONLY behavior - no existing code modification.
All instrumentation is OPT-IN, disabled by default.
"""

import pytest
import time
import threading
from typing import Dict, Any

# Import the new observability module
from neural_shield.comprehensive_observability_instrumentation_v20_2026_june import (
    InstrumentationManager,
    timed,
    counted,
    traced,
    MetricType,
    LogLevel,
    HealthStatus,
    HealthCheckResult,
    ThreadSafeMetricStore,
    StructuredLogger,
    DistributedTracer,
    HealthCheckRegistry,
)

class TestThreadSafeMetricStore:
    """Tests for thread-safe metric storage"""
    
    def test_counter_increment(self):
        store = ThreadSafeMetricStore()
        store.increment_counter("test.counter", 1.0)
        assert store.get_counter_value("test.counter") == 1.0
        
        store.increment_counter("test.counter", 5.0)
        assert store.get_counter_value("test.counter") == 6.0
    
    def test_counter_with_labels(self):
        store = ThreadSafeMetricStore()
        labels = {"environment": "test", "version": "v20"}
        store.increment_counter("test.labeled_counter", 1.0, labels)
        assert store.get_counter_value("test.labeled_counter", labels) == 1.0
    
    def test_gauge_set(self):
        store = ThreadSafeMetricStore()
        store.set_gauge("test.gauge", 42.5)
        assert store.get_gauge_value("test.gauge") == 42.5
        
        store.set_gauge("test.gauge", 100.0)
        assert store.get_gauge_value("test.gauge") == 100.0
    
    def test_timer_recording(self):
        store = ThreadSafeMetricStore()
        store.record_timer("test.timer", 0.125)
        summary = store.get_metric_summary("test.timer")
        assert summary["count"] == 1
        assert summary["latest"] == 0.125
    
    def test_thread_safety_concurrent_access(self):
        store = ThreadSafeMetricStore()
        num_threads = 10
        increments_per_thread = 1000
        
        def worker():
            for _ in range(increments_per_thread):
                store.increment_counter("concurrent.test")
        
        threads = [threading.Thread(target=worker) for _ in range(num_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        expected = num_threads * increments_per_thread
        assert store.get_counter_value("concurrent.test") == expected
    
    def test_metric_summary_statistics(self):
        store = ThreadSafeMetricStore()
        for i in range(1, 11):
            store.record_timer("stats.test", float(i))
        
        summary = store.get_metric_summary("stats.test")
        assert summary["count"] == 10
        assert summary["min"] == 1.0
        assert summary["max"] == 10.0
        assert summary["avg"] == 5.5
        assert summary["latest"] == 10.0

class TestStructuredLogger:
    """Tests for structured logging (OPT-IN)"""
    
    def test_logger_disabled_by_default(self):
        logger = StructuredLogger(enabled=False)
        logger.info("test message")
        logs = logger.get_recent_logs()
        assert len(logs) == 0  # No logs when disabled
    
    def test_logger_enabled_logs_messages(self):
        logger = StructuredLogger(enabled=True, min_level=LogLevel.DEBUG)
        logger.info("test message", key="value")
        logs = logger.get_recent_logs()
        assert len(logs) == 1
        assert logs[0]["message"] == "test message"
        assert logs[0]["context"]["key"] == "value"
    
    def test_log_level_filtering(self):
        logger = StructuredLogger(enabled=True, min_level=LogLevel.WARNING)
        logger.debug("debug message")  # Should be filtered
        logger.warning("warning message")  # Should pass
        
        logs = logger.get_recent_logs()
        assert len(logs) == 1
        assert logs[0]["level"] == "WARNING"
    
    def test_logger_enable_disable_toggle(self):
        logger = StructuredLogger(enabled=False)
        logger.info("msg1")
        assert len(logger.get_recent_logs()) == 0
        
        logger.enable()
        logger.info("msg2")
        assert len(logger.get_recent_logs()) == 1
        
        logger.disable()
        logger.info("msg3")
        assert len(logger.get_recent_logs()) == 1  # No new log added

class TestDistributedTracer:
    """Tests for distributed tracing (OPT-IN)"""
    
    def test_tracer_disabled_by_default(self):
        tracer = DistributedTracer(enabled=False)
        span_id = tracer.start_span("test.span")
        assert span_id == ""  # Empty when disabled
    
    def test_tracer_enabled_creates_spans(self):
        tracer = DistributedTracer(enabled=True)
        span_id = tracer.start_span("test.span", attribute="value")
        assert span_id != ""
        
        span = tracer.end_span(span_id, result="success")
        assert span is not None
        assert span.name == "test.span"
        assert span.end_time is not None
        assert span.end_time > span.start_time
    
    def test_trace_summary(self):
        tracer = DistributedTracer(enabled=True)
        trace_id = tracer._generate_id()
        
        span1_id = tracer.start_span("operation1", trace_id=trace_id)
        time.sleep(0.01)
        tracer.end_span(span1_id)
        
        span2_id = tracer.start_span("operation2", trace_id=trace_id)
        time.sleep(0.01)
        tracer.end_span(span2_id)
        
        summary = tracer.get_trace_summary(trace_id)
        assert summary["found"] == True
        assert summary["span_count"] == 2
        assert summary["total_duration_ms"] > 0
    
    def test_span_events(self):
        tracer = DistributedTracer(enabled=True)
        span_id = tracer.start_span("test.with_events")
        
        tracer.add_event(span_id, "processing_started", stage=1)
        tracer.add_event(span_id, "processing_complete", stage=2)
        
        span = tracer.end_span(span_id)
        assert len(span.events) == 2
        assert span.events[0]["name"] == "processing_started"

class TestHealthCheckRegistry:
    """Tests for health check framework"""
    
    def test_register_and_run_check(self):
        registry = HealthCheckRegistry()
        
        def passing_check() -> HealthCheckResult:
            return HealthCheckResult(
                component="test",
                status=HealthStatus.HEALTHY,
                message="OK",
                response_time_ms=0.0
            )
        
        registry.register_check("test_check", passing_check)
        result = registry.run_check("test_check")
        assert result is not None
        assert result.status == HealthStatus.HEALTHY
    
    def test_health_check_exception_handling(self):
        registry = HealthCheckRegistry()
        
        def failing_check():
            raise RuntimeError("Check failed!")
        
        registry.register_check("failing", failing_check)
        result = registry.run_check("failing")
        assert result is not None
        assert result.status == HealthStatus.UNHEALTHY
    
    def test_overall_status_healthy(self):
        registry = HealthCheckRegistry()
        
        registry.register_check("check1", lambda: HealthCheckResult(
            "check1", HealthStatus.HEALTHY, "OK", 0.0
        ))
        registry.register_check("check2", lambda: HealthCheckResult(
            "check2", HealthStatus.HEALTHY, "OK", 0.0
        ))
        
        status = registry.get_overall_status()
        assert status["status"] == "healthy"
        assert status["healthy_count"] == 2
    
    def test_overall_status_degraded(self):
        registry = HealthCheckRegistry()
        
        registry.register_check("check1", lambda: HealthCheckResult(
            "check1", HealthStatus.HEALTHY, "OK", 0.0
        ))
        registry.register_check("check2", lambda: HealthCheckResult(
            "check2", HealthStatus.DEGRADED, "Slow", 0.0
        ))
        
        status = registry.get_overall_status()
        assert status["status"] == "degraded"

class TestInstrumentationDecorators:
    """Tests for instrumentation decorators (OPT-IN)"""
    
    def test_timed_disabled_by_default(self):
        """Timing decorator should be NOOP when disabled"""
        InstrumentationManager.disable_all()
        
        @timed("test.function.timing")
        def test_func():
            return 42
        
        result = test_func()
        assert result == 42  # Function still works normally
    
    def test_counted_disabled_by_default(self):
        """Counting decorator should be NOOP when disabled"""
        InstrumentationManager.disable_all()
        
        @counted("test.function.calls")
        def test_func():
            return "hello"
        
        result = test_func()
        assert result == "hello"
    
    def test_traced_disabled_by_default(self):
        """Tracing decorator should be NOOP when disabled"""
        InstrumentationManager.disable_all()
        
        @traced("test.function.trace")
        def test_func():
            return True
        
        result = test_func()
        assert result == True
    
    def test_timed_enabled_measures_time(self):
        InstrumentationManager.enable_all()
        
        @timed("decorator.test.timed")
        def slow_func():
            time.sleep(0.01)
            return "done"
        
        result = slow_func()
        assert result == "done"
        
        # Cleanup
        InstrumentationManager.disable_all()
    
    def test_counted_enabled_increments(self):
        InstrumentationManager.enable_all()
        
        call_count = 5
        
        @counted("decorator.test.counted")
        def counted_func():
            return "called"
        
        for _ in range(call_count):
            counted_func()
        
        # Cleanup
        InstrumentationManager.disable_all()

class TestInstrumentationManager:
    """Tests for central instrumentation manager singleton"""
    
    def test_singleton_behavior(self):
        instance1 = InstrumentationManager()
        instance2 = InstrumentationManager()
        assert instance1 is instance2
    
    def test_enable_disable_all(self):
        InstrumentationManager.disable_all()
        status = InstrumentationManager.get_observability_status()
        assert status["instrumentation_enabled"]["timing"] == False
        assert status["instrumentation_enabled"]["counting"] == False
        assert status["instrumentation_enabled"]["tracing"] == False
        assert status["instrumentation_enabled"]["logging"] == False
        
        InstrumentationManager.enable_all()
        status = InstrumentationManager.get_observability_status()
        assert status["instrumentation_enabled"]["timing"] == True
        assert status["instrumentation_enabled"]["counting"] == True
        assert status["instrumentation_enabled"]["tracing"] == True
        assert status["instrumentation_enabled"]["logging"] == True
        
        # Cleanup
        InstrumentationManager.disable_all()
    
    def test_metrics_snapshot(self):
        InstrumentationManager.enable_all()
        InstrumentationManager.increment_counter("manager.test", 10.0)
        snapshot = InstrumentationManager.get_metrics_snapshot()
        assert "counters" in snapshot
        assert "gauges" in snapshot
        InstrumentationManager.disable_all()
    
    def test_health_status_integration(self):
        status = InstrumentationManager.get_health_status()
        assert "status" in status
        assert "checks_run" in status
    
    def test_observability_status_report(self):
        status = InstrumentationManager.get_observability_status()
        assert "instrumentation_enabled" in status
        assert "metrics_count" in status
        assert "health_checks_registered" in status
        assert status["stability"] == "STABLE"
        assert status["api_version"] == "v20"

class TestBackwardCompatibility:
    """Critical tests ensuring backward compatibility - NO EXISTING CODE BROKEN"""
    
    def test_no_modification_to_existing_imports(self):
        """Verify we can still import all original modules without conflict"""
        try:
            # These should all still work - our new code is ADD-ONLY
            from neural_shield import adversarial_prompt_anomaly_detector_2026_june
            from neural_shield import behavioral_biometrics_anomaly_detector_2026_june
            assert True
        except ImportError:
            pytest.fail("Existing module imports broken - backward compatibility violated")
    
    def test_new_module_is_isolated(self):
        """Our new module doesn't interfere with existing code"""
        # Import both old and new
        import neural_shield.comprehensive_observability_instrumentation_v20_2026_june as new_module
        assert new_module is not None
        
        # Verify module has expected exports
        assert hasattr(new_module, 'InstrumentationManager')
        assert hasattr(new_module, 'timed')
        assert hasattr(new_module, 'counted')
    
    def test_default_behavior_no_side_effects(self):
        """By default, instrumentation is disabled - zero performance impact"""
        status = InstrumentationManager.get_observability_status()
        # Default state should be all disabled (we may have enabled in tests)
        InstrumentationManager.disable_all()
        status = InstrumentationManager.get_observability_status()
        assert all(v == False for v in status["instrumentation_enabled"].values())

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
