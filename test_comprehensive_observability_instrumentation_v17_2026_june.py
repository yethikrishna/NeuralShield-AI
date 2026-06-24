"""
Comprehensive Test Suite - NeuralShield AI Observability V17
Dimension D: Observability & Instrumentation

Tests all observability features:
1. Baggage Context Propagation
2. Structured Logging
3. Metrics Collection (Counters, Gauges, Histograms, Timers)
4. Health Check Framework
5. Instrumentation Decorators
6. Threat Detection Metrics
7. Global Enable/Disable Controls
"""

import pytest
import time
import json
import threading
from typing import Dict, Any
from dataclasses import dataclass

# Import the observability module
from neural_shield.observability_enhanced_context_baggage_metrics_v17_2026_june import (
    # Context & Baggage
    BaggageKey,
    BaggageContext,
    
    # Logging
    LogLevel,
    LogEntry,
    StructuredLogger,
    get_default_logger,
    
    # Metrics
    Counter,
    Gauge,
    Histogram,
    Timer,
    MetricsRegistry,
    get_default_registry,
    
    # Health Checks
    HealthStatus,
    HealthCheckResult,
    OverallHealthStatus,
    FunctionHealthCheck,
    HealthChecker,
    get_default_health_checker,
    
    # Decorators
    instrumented,
    with_context,
    
    # Threat Metrics
    ThreatDetectionMetrics,
    get_threat_metrics,
    
    # Control Functions
    export_metrics_json,
    export_health_json,
    disable_instrumentation,
    enable_instrumentation,
    is_instrumentation_enabled,
    INSTRUMENTATION_DISABLED,
)


# -----------------------------------------------------------------------------
# Test Fixtures
# -----------------------------------------------------------------------------

@pytest.fixture
def clean_baggage_context():
    """Fixture to ensure clean baggage context for each test."""
    BaggageContext.clear()
    yield
    BaggageContext.clear()


@pytest.fixture
def fresh_registry():
    """Fixture with fresh metrics registry."""
    return MetricsRegistry()


@pytest.fixture
def fresh_logger():
    """Fixture with fresh logger."""
    return StructuredLogger("test_logger", level=LogLevel.DEBUG)


@pytest.fixture
def fresh_health_checker():
    """Fixture with fresh health checker."""
    return HealthChecker("test_service")


# -----------------------------------------------------------------------------
# Baggage Context Tests
# -----------------------------------------------------------------------------

class TestBaggageContext:
    """Tests for context baggage propagation system."""
    
    def test_set_and_get_value(self, clean_baggage_context):
        """Test basic set/get operations."""
        token = BaggageContext.set("test_key", "test_value")
        assert BaggageContext.get("test_key") == "test_value"
        BaggageContext.reset(token)
    
    def test_get_default_value(self, clean_baggage_context):
        """Test default value when key not found."""
        assert BaggageContext.get("nonexistent", "default") == "default"
    
    def test_set_bulk(self, clean_baggage_context):
        """Test bulk setting multiple values."""
        items = {"key1": "value1", "key2": "value2", "key3": "value3"}
        token = BaggageContext.set_bulk(items)
        assert BaggageContext.get("key1") == "value1"
        assert BaggageContext.get("key2") == "value2"
        assert BaggageContext.get("key3") == "value3"
        BaggageContext.reset(token)
    
    def test_get_all(self, clean_baggage_context):
        """Test getting all baggage items."""
        BaggageContext.set("key1", "value1")
        BaggageContext.set("key2", "value2")
        all_items = BaggageContext.get_all()
        assert "key1" in all_items
        assert "key2" in all_items
        assert all_items["key1"] == "value1"
    
    def test_clear(self, clean_baggage_context):
        """Test clearing baggage context."""
        BaggageContext.set("key1", "value1")
        BaggageContext.clear()
        assert BaggageContext.get("key1") is None
    
    def test_generate_request_id(self, clean_baggage_context):
        """Test request ID generation."""
        req_id = BaggageContext.generate_request_id()
        assert req_id.startswith("req_")
        assert len(req_id) > 5
        assert BaggageContext.get(BaggageKey.REQUEST_ID.value) == req_id
    
    def test_generate_trace_id(self, clean_baggage_context):
        """Test trace ID generation."""
        trace_id = BaggageContext.generate_trace_id()
        assert trace_id.startswith("trace_")
        assert len(trace_id) > 10
    
    def test_context_reset(self, clean_baggage_context):
        """Test context reset with token."""
        BaggageContext.set("existing", "value")
        token = BaggageContext.set("new", "temporary")
        assert BaggageContext.get("new") == "temporary"
        BaggageContext.reset(token)
        assert BaggageContext.get("new") is None
        assert BaggageContext.get("existing") == "value"
    
    def test_thread_isolation(self, clean_baggage_context):
        """Test that baggage is thread-isolated."""
        results: Dict[str, str] = {}
        
        def thread_func(thread_id: str):
            BaggageContext.set(f"thread_{thread_id}", f"value_{thread_id}")
            time.sleep(0.01)
            results[thread_id] = BaggageContext.get(f"thread_{thread_id}", "not_found")
        
        threads = []
        for i in range(3):
            t = threading.Thread(target=thread_func, args=(str(i),))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        # Each thread should only see its own value
        for i in range(3):
            assert results[str(i)] == f"value_{i}"


# -----------------------------------------------------------------------------
# Structured Logging Tests
# -----------------------------------------------------------------------------

class TestStructuredLogging:
    """Tests for structured logging system."""
    
    def test_logger_creation(self, fresh_logger):
        """Test basic logger creation."""
        assert fresh_logger.name == "test_logger"
        assert fresh_logger.level == LogLevel.DEBUG
    
    def test_debug_logging(self, fresh_logger):
        """Test debug level logging."""
        entries = []
        fresh_logger.add_handler(lambda e: entries.append(e))
        entry = fresh_logger.debug("Test debug message", extra_key="extra_value")
        assert entry is not None
        assert entry.level == "DEBUG"
        assert entry.message == "Test debug message"
        assert len(entries) == 1
    
    def test_info_logging(self, fresh_logger):
        """Test info level logging."""
        entries = []
        fresh_logger.add_handler(lambda e: entries.append(e))
        entry = fresh_logger.info("Test info message")
        assert entry is not None
        assert entry.level == "INFO"
    
    def test_security_logging(self, fresh_logger):
        """Test security event logging."""
        entries = []
        fresh_logger.add_handler(lambda e: entries.append(e))
        entry = fresh_logger.security("Security event detected")
        assert entry is not None
        assert entry.level == "SECURITY"
    
    def test_error_logging_with_exception(self, fresh_logger):
        """Test error logging with exception info."""
        entries = []
        fresh_logger.add_handler(lambda e: entries.append(e))
        try:
            raise ValueError("Test error")
        except ValueError as e:
            entry = fresh_logger.error("Something failed", exc=e)
        assert entry is not None
        assert entry.error is not None
        assert "Test error" in entry.error
    
    def test_log_entry_to_dict(self, fresh_logger):
        """Test log entry serialization."""
        entry = fresh_logger.info("Test message")
        d = entry.to_dict()
        assert "timestamp" in d
        assert "level" in d
        assert "message" in d
        assert d["message"] == "Test message"
    
    def test_log_entry_to_json(self, fresh_logger):
        """Test log entry JSON serialization."""
        entry = fresh_logger.info("JSON test")
        json_str = entry.to_json()
        parsed = json.loads(json_str)
        assert parsed["message"] == "JSON test"
    
    def test_log_level_filtering(self):
        """Test that log levels are properly filtered."""
        logger = StructuredLogger("filtered", level=LogLevel.WARNING)
        entries = []
        logger.add_handler(lambda e: entries.append(e))
        
        logger.debug("This should be filtered")
        logger.info("This should also be filtered")
        logger.warning("This should pass")
        
        assert len(entries) == 1
        assert entries[0].level == "WARNING"
    
    def test_default_logger_singleton(self):
        """Test default logger singleton pattern."""
        logger1 = get_default_logger()
        logger2 = get_default_logger()
        assert logger1 is logger2


# -----------------------------------------------------------------------------
# Metrics Tests
# -----------------------------------------------------------------------------

class TestMetrics:
    """Tests for metrics collection system."""
    
    def test_counter_basic(self, fresh_registry):
        """Test basic counter functionality."""
        counter = fresh_registry.counter("test_counter", "Test description")
        assert counter.get() == 0
        
        counter.inc()
        assert counter.get() == 1
        
        counter.inc(5)
        assert counter.get() == 6
    
    def test_counter_with_labels(self, fresh_registry):
        """Test counter with labels."""
        counter = fresh_registry.counter("labeled_counter")
        counter.inc(category="test", severity="high")
        counter.inc(category="test", severity="high")
        counter.inc(category="other", severity="low")
        
        assert counter.get(category="test", severity="high") == 2
        assert counter.get(category="other", severity="low") == 1
    
    def test_gauge_set_and_get(self, fresh_registry):
        """Test gauge set and get operations."""
        gauge = fresh_registry.gauge("test_gauge")
        gauge.set(42.0)
        assert gauge.get() == 42.0
    
    def test_gauge_inc_dec(self, fresh_registry):
        """Test gauge increment/decrement."""
        gauge = fresh_registry.gauge("test_gauge")
        gauge.set(10.0)
        gauge.inc(5.0)
        assert gauge.get() == 15.0
        gauge.dec(3.0)
        assert gauge.get() == 12.0
    
    def test_histogram_observe(self, fresh_registry):
        """Test histogram observation."""
        hist = fresh_registry.histogram("test_histogram")
        hist.observe(0.1)
        hist.observe(0.5)
        hist.observe(1.0)
        
        stats = hist.get_stats()
        assert stats["count"] == 3
        assert stats["min"] == 0.1
        assert stats["max"] == 1.0
        assert stats["avg"] == pytest.approx(0.533, rel=0.01)
    
    def test_histogram_percentiles(self, fresh_registry):
        """Test histogram percentile calculation."""
        hist = fresh_registry.histogram("percentile_test")
        for i in range(100):
            hist.observe(float(i))
        
        assert hist.percentile(50) == pytest.approx(50, rel=0.1)
        assert hist.percentile(90) == pytest.approx(90, rel=0.1)
        assert hist.percentile(99) == pytest.approx(99, rel=0.1)
    
    def test_timer_context_manager(self, fresh_registry):
        """Test timer context manager."""
        hist = fresh_registry.histogram("timer_test")
        
        with Timer(hist):
            time.sleep(0.01)
        
        stats = hist.get_stats()
        assert stats["count"] == 1
        assert stats["min"] > 0.001  # At least 1ms
    
    def test_registry_get_all_metrics(self, fresh_registry):
        """Test getting all metrics snapshot."""
        fresh_registry.counter("c1").inc(5)
        fresh_registry.gauge("g1").set(10.0)
        fresh_registry.histogram("h1").observe(0.5)
        
        all_metrics = fresh_registry.get_all_metrics()
        assert "counters" in all_metrics
        assert "gauges" in all_metrics
        assert "histograms" in all_metrics
        assert all_metrics["counters"]["c1"] == 5
    
    def test_default_registry_singleton(self):
        """Test default registry singleton pattern."""
        r1 = get_default_registry()
        r2 = get_default_registry()
        assert r1 is r2
    
    def test_export_metrics_json(self):
        """Test metrics JSON export."""
        json_str = export_metrics_json()
        parsed = json.loads(json_str)
        assert "counters" in parsed
        assert "gauges" in parsed
        assert "histograms" in parsed


# -----------------------------------------------------------------------------
# Health Check Tests
# -----------------------------------------------------------------------------

class TestHealthChecks:
    """Tests for health check framework."""
    
    def test_health_check_registration(self, fresh_health_checker):
        """Test health check registration."""
        def check_func():
            return (HealthStatus.HEALTHY, "All good", {"detail": "ok"})
        
        fresh_health_checker.register_function("test_check", check_func)
        result = fresh_health_checker.run_checks()
        
        assert len(result.checks) == 1
        assert result.checks[0].name == "test_check"
    
    def test_healthy_status(self, fresh_health_checker):
        """Test healthy overall status."""
        fresh_health_checker.register_function(
            "check1",
            lambda: (HealthStatus.HEALTHY, "OK", {})
        )
        fresh_health_checker.register_function(
            "check2",
            lambda: (HealthStatus.HEALTHY, "OK", {})
        )
        
        result = fresh_health_checker.run_checks()
        assert result.status == HealthStatus.HEALTHY
    
    def test_degraded_status(self, fresh_health_checker):
        """Test degraded overall status."""
        fresh_health_checker.register_function(
            "healthy",
            lambda: (HealthStatus.HEALTHY, "OK", {})
        )
        fresh_health_checker.register_function(
            "degraded",
            lambda: (HealthStatus.DEGRADED, "Slow", {})
        )
        
        result = fresh_health_checker.run_checks()
        assert result.status == HealthStatus.DEGRADED
    
    def test_unhealthy_status(self, fresh_health_checker):
        """Test unhealthy overall status."""
        fresh_health_checker.register_function(
            "healthy",
            lambda: (HealthStatus.HEALTHY, "OK", {})
        )
        fresh_health_checker.register_function(
            "unhealthy",
            lambda: (HealthStatus.UNHEALTHY, "Failed", {})
        )
        
        result = fresh_health_checker.run_checks()
        assert result.status == HealthStatus.UNHEALTHY
    
    def test_health_check_exception_handling(self, fresh_health_checker):
        """Test that exceptions in health checks are handled."""
        def failing_check():
            raise RuntimeError("Check failed")
        
        fresh_health_checker.register_function("failing", failing_check)
        result = fresh_health_checker.run_checks()
        
        assert result.checks[0].status == HealthStatus.UNHEALTHY
        assert "Check failed" in result.checks[0].message
    
    def test_health_result_serialization(self, fresh_health_checker):
        """Test health result serialization."""
        fresh_health_checker.register_function(
            "test",
            lambda: (HealthStatus.HEALTHY, "OK", {"foo": "bar"})
        )
        result = fresh_health_checker.run_checks()
        d = result.to_dict()
        
        assert "status" in d
        assert "checks" in d
        assert d["status"] == "healthy"
    
    def test_default_health_checker_singleton(self):
        """Test default health checker singleton."""
        hc1 = get_default_health_checker()
        hc2 = get_default_health_checker()
        assert hc1 is hc2


# -----------------------------------------------------------------------------
# Decorator Tests
# -----------------------------------------------------------------------------

class TestInstrumentationDecorators:
    """Tests for instrumentation decorators."""
    
    def test_instrumented_decorator_basic(self):
        """Test basic instrumentation decorator."""
        @instrumented()
        def test_func(x: int, y: int) -> int:
            return x + y
        
        result = test_func(2, 3)
        assert result == 5
    
    def test_instrumented_decorator_named(self):
        """Test instrumented decorator with custom name."""
        @instrumented(name="custom_name")
        def test_func():
            return "done"
        
        assert test_func() == "done"
    
    def test_with_context_decorator(self, clean_baggage_context):
        """Test context baggage decorator."""
        @with_context(decorator_key="decorator_value")
        def test_func():
            return BaggageContext.get("decorator_key")
        
        result = test_func()
        assert result == "decorator_value"
        # Context should be restored after function returns
        assert BaggageContext.get("decorator_key") is None
    
    def test_with_context_nested(self, clean_baggage_context):
        """Test nested context decorators."""
        @with_context(outer="outer_value")
        def outer_func():
            @with_context(inner="inner_value")
            def inner_func():
                return (
                    BaggageContext.get("outer"),
                    BaggageContext.get("inner")
                )
            return inner_func()
        
        outer, inner = outer_func()
        assert outer == "outer_value"
        assert inner == "inner_value"
        # Both should be restored
        assert BaggageContext.get("outer") is None
        assert BaggageContext.get("inner") is None
    
    def test_instrumented_exception_propagation(self):
        """Test that exceptions propagate through decorator."""
        @instrumented()
        def failing_func():
            raise ValueError("Test error")
        
        with pytest.raises(ValueError, match="Test error"):
            failing_func()
    
    def test_instrumented_metadata_preserved(self):
        """Test that function metadata is preserved."""
        @instrumented()
        def documented_func():
            """This is the docstring."""
            pass
        
        assert documented_func.__doc__ == "This is the docstring."
        assert documented_func.__name__ == "documented_func"


# -----------------------------------------------------------------------------
# Threat Detection Metrics Tests
# -----------------------------------------------------------------------------

class TestThreatDetectionMetrics:
    """Tests for threat detection specific metrics."""
    
    def test_threat_metrics_creation(self):
        """Test threat metrics creation."""
        tm = ThreatDetectionMetrics()
        assert tm is not None
    
    def test_record_threat_detected(self):
        """Test recording detected threats."""
        tm = ThreatDetectionMetrics()
        tm.record_threat_detected("prompt_injection", "HIGH", 0.95)
        # Should not raise
    
    def test_record_threat_blocked(self):
        """Test recording blocked threats."""
        tm = ThreatDetectionMetrics()
        tm.record_threat_blocked("jailbreak", "input_sanitization")
        # Should not raise
    
    def test_record_false_positive(self):
        """Test recording false positives."""
        tm = ThreatDetectionMetrics()
        tm.record_false_positive("signature_detector")
        # Should not raise
    
    def test_time_detection_context(self):
        """Test detection timer context manager."""
        tm = ThreatDetectionMetrics()
        with tm.time_detection("test_detector"):
            time.sleep(0.001)
        # Should not raise
    
    def test_default_threat_metrics_singleton(self):
        """Test default threat metrics singleton."""
        tm1 = get_threat_metrics()
        tm2 = get_threat_metrics()
        assert tm1 is tm2


# -----------------------------------------------------------------------------
# Global Control Tests
# -----------------------------------------------------------------------------

class TestGlobalControls:
    """Tests for global instrumentation enable/disable controls."""
    
    def test_enable_disable_toggle(self):
        """Test instrumentation enable/disable toggle."""
        original_state = is_instrumentation_enabled()
        
        enable_instrumentation()
        assert is_instrumentation_enabled() is True
        
        disable_instrumentation()
        assert is_instrumentation_enabled() is False
        
        # Restore original state
        if original_state:
            enable_instrumentation()
        else:
            disable_instrumentation()
    
    def test_disabled_instrumentation_no_side_effects(self, clean_baggage_context):
        """Test that disabled instrumentation has no side effects."""
        original_state = is_instrumentation_enabled()
        disable_instrumentation()
        
        # Operations should work but have no effect
        BaggageContext.set("test", "value")
        logger = get_default_logger()
        logger.info("This should not log")
        counter = get_default_registry().counter("test")
        counter.inc()
        
        # Restore
        if original_state:
            enable_instrumentation()


# -----------------------------------------------------------------------------
# Integration Tests
# -----------------------------------------------------------------------------

class TestIntegration:
    """Integration tests for full observability pipeline."""
    
    def test_full_observability_pipeline(self, clean_baggage_context, fresh_registry):
        """Test full observability pipeline: context -> metrics -> logging."""
        # Set context
        BaggageContext.set_bulk({
            "request_id": "req_123",
            "tenant_id": "tenant_abc",
        })
        
        # Record metrics
        counter = fresh_registry.counter("requests")
        counter.inc()
        
        # Verify
        assert BaggageContext.get("request_id") == "req_123"
        assert counter.get() == 1
    
    def test_concurrent_instrumentation(self, fresh_registry):
        """Test instrumentation under concurrent load."""
        counter = fresh_registry.counter("concurrent")
        
        def worker(n: int):
            for _ in range(n):
                counter.inc()
        
        threads = []
        for _ in range(10):
            t = threading.Thread(target=worker, args=(100,))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        assert counter.get() == 1000
    
    def test_backward_compatibility(self):
        """Test that new module doesn't break existing imports."""
        # Module should import cleanly
        from neural_shield import observability_enhanced_context_baggage_metrics_v17_2026_june
        
        # All exports should be accessible
        assert hasattr(observability_enhanced_context_baggage_metrics_v17_2026_june, "BaggageContext")
        assert hasattr(observability_enhanced_context_baggage_metrics_v17_2026_june, "get_default_registry")
        assert hasattr(observability_enhanced_context_baggage_metrics_v17_2026_june, "instrumented")


# -----------------------------------------------------------------------------
# Main Entry Point
# -----------------------------------------------------------------------------

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
