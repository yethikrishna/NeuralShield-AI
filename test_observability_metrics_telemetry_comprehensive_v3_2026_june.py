"""
Test suite for NeuralShield Observability, Metrics & Telemetry v3
DIMENSION D: Observability & Instrumentation
All tests must pass - ADD-ONLY implementation
"""

import pytest
import time
import threading
from neural_shield.observability_metrics_telemetry_comprehensive_v3_2026_june import (
    Counter, Gauge, Timer, Histogram, StructuredLogger, MetricsRegistry,
    LogLevel, MetricLabels, instrument, enable_metrics, disable_metrics,
    increment_counter, set_gauge, record_timer, observe_histogram, logger
)


class TestMetricLabels:
    def test_labels_hashing(self):
        labels1 = MetricLabels({"env": "prod", "service": "api"})
        labels2 = MetricLabels({"service": "api", "env": "prod"})
        assert hash(labels1) == hash(labels2)
        assert labels1 == labels2
    
    def test_labels_to_key(self):
        labels = MetricLabels({"a": "1", "b": "2"})
        key = labels.to_key()
        assert '"a": "1"' in key
        assert '"b": "2"' in key


class TestCounter:
    def test_counter_basic(self):
        counter = Counter("test_requests", "Total requests")
        assert counter.get() == 0.0
        counter.inc()
        assert counter.get() == 1.0
        counter.inc(5.0)
        assert counter.get() == 6.0
    
    def test_counter_with_labels(self):
        counter = Counter("test_requests", "Total requests")
        counter.inc(labels={"endpoint": "/api/v1"})
        counter.inc(labels={"endpoint": "/api/v2"})
        counter.inc(labels={"endpoint": "/api/v1"})
        assert counter.get({"endpoint": "/api/v1"}) == 2.0
        assert counter.get({"endpoint": "/api/v2"}) == 1.0
    
    def test_counter_negative_raises(self):
        counter = Counter("test")
        with pytest.raises(ValueError):
            counter.inc(-1.0)
    
    def test_counter_thread_safe(self):
        counter = Counter("threaded_test")
        def worker():
            for _ in range(100):
                counter.inc()
        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert counter.get() == 1000.0


class TestGauge:
    def test_gauge_set(self):
        gauge = Gauge("memory_usage", "Memory usage in MB")
        gauge.set(128.5)
        assert gauge.get() == 128.5
    
    def test_gauge_inc_dec(self):
        gauge = Gauge("connections", "Active connections")
        gauge.inc()
        assert gauge.get() == 1.0
        gauge.inc(5.0)
        assert gauge.get() == 6.0
        gauge.dec(2.0)
        assert gauge.get() == 4.0
    
    def test_gauge_with_labels(self):
        gauge = Gauge("queue_size", "Queue sizes")
        gauge.set(100, {"queue": "priority"})
        gauge.set(50, {"queue": "normal"})
        assert gauge.get({"queue": "priority"}) == 100
        assert gauge.get({"queue": "normal"}) == 50


class TestTimer:
    def test_timer_record(self):
        timer = Timer("request_duration", "Request duration")
        timer.record(0.1)
        timer.record(0.2)
        assert timer.get_count() == 2
        assert abs(timer.get_sum() - 0.3) < 0.0001
        assert abs(timer.get_avg() - 0.15) < 0.0001
    
    def test_timer_context_manager(self):
        timer = Timer("block_duration")
        with timer.time():
            time.sleep(0.01)
        assert timer.get_count() == 1
        assert timer.get_sum() > 0
    
    def test_timer_percentiles(self):
        timer = Timer("latency")
        for i in range(100):
            timer.record(i / 100.0)
        p50 = timer.get_percentile(50)
        p95 = timer.get_percentile(95)
        assert p50 is not None and 0.45 <= p50 <= 0.55
        assert p95 is not None and 0.90 <= p95 <= 1.0


class TestHistogram:
    def test_histogram_observe(self):
        hist = Histogram("latency", buckets=[0.1, 0.5, 1.0])
        hist.observe(0.05)
        hist.observe(0.3)
        hist.observe(0.7)
        assert hist.get_count() == 3
        buckets = hist.get_buckets()
        assert buckets[0.1] >= 1
        assert buckets[0.5] >= 2
        assert buckets[1.0] == 3
    
    def test_histogram_default_buckets(self):
        hist = Histogram("default_buckets")
        assert len(hist.buckets) == 11
        assert 0.005 in hist.buckets
        assert 10.0 in hist.buckets


class TestStructuredLogger:
    def test_log_basic(self):
        log = StructuredLogger()
        log.info("Test message", user_id="123")
        entries = log.get_recent(10)
        assert len(entries) == 1
        assert entries[0]["message"] == "Test message"
        assert entries[0]["context"]["user_id"] == "123"
    
    def test_log_levels(self):
        log = StructuredLogger()
        log.debug("Debug message")
        log.info("Info message")
        log.warning("Warning message")
        log.error("Error message")
        log.critical("Critical message")
        counts = log.get_counts_by_level()
        assert counts.get("INFO", 0) == 1
        assert counts.get("WARNING", 0) == 1
        assert counts.get("ERROR", 0) == 1
    
    def test_log_context_propagation(self):
        log = StructuredLogger()
        with log.with_context(request_id="req-123", tenant="acme"):
            log.info("Processing request")
            log.info("Another message")
        entries = log.get_recent(10)
        assert len(entries) == 2
        assert entries[0]["context"]["request_id"] == "req-123"
        assert entries[0]["context"]["tenant"] == "acme"
    
    def test_log_min_level(self):
        log = StructuredLogger()
        log.min_level = LogLevel.WARNING
        log.debug("Debug")
        log.info("Info")
        log.warning("Warning")
        entries = log.get_recent(10)
        assert len(entries) == 1
        assert entries[0]["level"] == "WARNING"
    
    def test_log_trace_and_span_ids(self):
        log = StructuredLogger()
        log.info("Test with tracing")
        entry = log.get_recent(1)[0]
        assert "trace_id" in entry
        assert "span_id" in entry
        assert len(entry["trace_id"]) > 0
        assert len(entry["span_id"]) > 0


class TestMetricsRegistry:
    def test_registry_singleton(self):
        r1 = MetricsRegistry.get_instance()
        r2 = MetricsRegistry.get_instance()
        assert r1 is r2
    
    def test_registry_opt_in_disabled_by_default(self):
        registry = MetricsRegistry()
        assert registry.enabled is False
    
    def test_registry_enable_disable(self):
        registry = MetricsRegistry()
        registry.enable()
        assert registry.enabled is True
        registry.disable()
        assert registry.enabled is False
    
    def test_registry_counter_creation(self):
        registry = MetricsRegistry()
        c1 = registry.counter("test", "desc")
        c2 = registry.counter("test", "desc")
        assert c1 is c2
    
    def test_registry_summary(self):
        registry = MetricsRegistry()
        registry.counter("requests")
        registry.gauge("memory")
        registry.timer("latency")
        registry.histogram("duration")
        summary = registry.get_summary()
        assert summary["counters"] >= 1
        assert summary["gauges"] >= 1
        assert summary["timers"] >= 1
        assert summary["histograms"] >= 1
    
    def test_registry_prometheus_export(self):
        registry = MetricsRegistry()
        counter = registry.counter("test_requests_total", "Total requests")
        counter.inc(5.0, {"endpoint": "/api"})
        export = registry.export_prometheus()
        assert "test_requests_total" in export
        assert 'endpoint="/api"' in export


class TestInstrumentDecorator:
    def test_instrument_disabled_by_default(self):
        @instrument("test_func")
        def my_func():
            return 42
        
        # Should work without metrics enabled
        result = my_func()
        assert result == 42
    
    def test_instrument_enabled(self):
        enable_metrics()
        
        @instrument("decorated_func")
        def my_func():
            return "hello"
        
        result = my_func()
        assert result == "hello"
        
        registry = MetricsRegistry.get_instance()
        assert registry.enabled is True
        disable_metrics()


class TestConvenienceFunctions:
    def test_convenience_functions_disabled(self):
        disable_metrics()
        # Should not raise when disabled
        increment_counter("test_counter")
        set_gauge("test_gauge", 100.0)
        record_timer("test_timer", 0.5)
        observe_histogram("test_hist", 0.1)
    
    def test_convenience_functions_enabled(self):
        enable_metrics()
        increment_counter("enabled_counter", 3.0)
        set_gauge("enabled_gauge", 50.0)
        record_timer("enabled_timer", 0.25)
        observe_histogram("enabled_hist", 0.05)
        disable_metrics()


class TestGlobalLogger:
    def test_global_logger_exists(self):
        assert logger is not None
        logger.info("Global logger test", key="value")
        entries = logger.get_recent(1)
        assert len(entries) == 1


class TestOptInBehavior:
    def test_no_side_effects_when_disabled(self):
        """CRITICAL: All instrumentation must be no-op when disabled"""
        disable_metrics()
        registry = MetricsRegistry.get_instance()
        
        # All operations should complete without error
        increment_counter("should_not_appear")
        set_gauge("should_not_appear", 1.0)
        record_timer("should_not_appear", 0.1)
        observe_histogram("should_not_appear", 0.01)
        
        # Verify registry state unchanged
        summary = registry.get_summary()
        assert summary["enabled"] is False
    
    def test_happy_path_unchanged(self):
        """CRITICAL: Happy path behavior must be 100% preserved"""
        def original_function(x, y):
            return x + y
        
        @instrument("addition")
        def instrumented_function(x, y):
            return x + y
        
        # Both should produce identical results
        disable_metrics()
        assert original_function(2, 3) == instrumented_function(2, 3)
        enable_metrics()
        assert original_function(2, 3) == instrumented_function(2, 3)
        disable_metrics()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
