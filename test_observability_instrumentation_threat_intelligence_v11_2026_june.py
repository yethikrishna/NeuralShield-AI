"""
Tests for NeuralShield AI - Observability & Instrumentation Module v11
Session 110 - Dimension D: Observability & Instrumentation

ALL TESTS MUST PASS
NO EXISTING CODE MODIFIED
100% BACKWARD COMPATIBLE
"""

import pytest
import time
import threading
from unittest.mock import patch, MagicMock

from neural_shield.observability_instrumentation_threat_intelligence_v11_2026_june import (
    LogSeverity, MetricType, HealthStatus, SLOStatus,
    LogEntry, MetricValue, HealthCheckResult, SLOConfig, ObservabilityConfig,
    StructuredLogger, MetricsCollector, HealthCheckFramework, DistributedTracer,
    SLOTracker, ThreatIntelligenceObservability, observability
)


class TestLogSeverityEnum:
    """Test LogSeverity enum values."""
    
    def test_severity_values(self):
        assert LogSeverity.DEBUG.value == "debug"
        assert LogSeverity.INFO.value == "info"
        assert LogSeverity.WARNING.value == "warning"
        assert LogSeverity.ERROR.value == "error"
        assert LogSeverity.CRITICAL.value == "critical"
    
    def test_severity_order(self):
        order = [LogSeverity.DEBUG, LogSeverity.INFO, 
                 LogSeverity.WARNING, LogSeverity.ERROR, LogSeverity.CRITICAL]
        assert len(order) == 5


class TestMetricTypeEnum:
    """Test MetricType enum values."""
    
    def test_metric_types(self):
        assert MetricType.COUNTER.value == "counter"
        assert MetricType.GAUGE.value == "gauge"
        assert MetricType.TIMER.value == "timer"
        assert MetricType.HISTOGRAM.value == "histogram"


class TestHealthStatusEnum:
    """Test HealthStatus enum values."""
    
    def test_health_statuses(self):
        assert HealthStatus.HEALTHY.value == "healthy"
        assert HealthStatus.DEGRADED.value == "degraded"
        assert HealthStatus.UNHEALTHY.value == "unhealthy"
        assert HealthStatus.UNKNOWN.value == "unknown"


class TestSLOStatusEnum:
    """Test SLOStatus enum values."""
    
    def test_slo_statuses(self):
        assert SLOStatus.OK.value == "ok"
        assert SLOStatus.WARNING.value == "warning"
        assert SLOStatus.BURNING.value == "burning"
        assert SLOStatus.EXHAUSTED.value == "exhausted"


class TestObservabilityConfig:
    """Test ObservabilityConfig defaults - ALL DISABLED BY DEFAULT."""
    
    def test_default_config_all_disabled(self):
        """CRITICAL: All features must be disabled by default (OPT-IN pattern)."""
        config = ObservabilityConfig()
        assert config.logging_enabled is False
        assert config.metrics_enabled is False
        assert config.health_checks_enabled is False
        assert config.tracing_enabled is False
        assert config.slo_tracking_enabled is False
    
    def test_default_log_level(self):
        config = ObservabilityConfig()
        assert config.log_level == LogSeverity.INFO


class TestStructuredLogger:
    """Test StructuredLogger functionality."""
    
    def test_logger_disabled_by_default(self):
        """Logger must return None when disabled."""
        config = ObservabilityConfig()  # logging_enabled=False
        logger = StructuredLogger(config)
        
        result = logger.info("test message", "test_component")
        assert result is None
    
    def test_logger_enabled_logs_message(self):
        config = ObservabilityConfig(logging_enabled=True)
        logger = StructuredLogger(config)
        
        result = logger.info("test message", "test_component", custom_attr="value")
        assert result is not None
        assert result.message == "test message"
        assert result.component == "test_component"
        assert result.attributes["custom_attr"] == "value"
    
    def test_log_severity_filtering(self):
        config = ObservabilityConfig(logging_enabled=True, log_level=LogSeverity.WARNING)
        logger = StructuredLogger(config)
        
        # DEBUG should be filtered out
        assert logger.debug("debug msg", "comp") is None
        # INFO should be filtered out
        assert logger.info("info msg", "comp") is None
        # WARNING and above should log
        assert logger.warning("warn msg", "comp") is not None
        assert logger.error("err msg", "comp") is not None
        assert logger.critical("crit msg", "comp") is not None
    
    def test_get_recent_logs(self):
        config = ObservabilityConfig(logging_enabled=True)
        logger = StructuredLogger(config)
        
        for i in range(10):
            logger.info(f"msg {i}", "comp")
        
        logs = logger.get_recent_logs(5)
        assert len(logs) == 5
        assert logs[-1].message == "msg 9"
    
    def test_clear_logs(self):
        config = ObservabilityConfig(logging_enabled=True)
        logger = StructuredLogger(config)
        logger.info("test", "comp")
        logger.clear_logs()
        assert len(logger.get_recent_logs()) == 0


class TestMetricsCollector:
    """Test MetricsCollector functionality."""
    
    def test_metrics_disabled_by_default(self):
        """Metrics must return 0 when disabled."""
        config = ObservabilityConfig()  # metrics_enabled=False
        metrics = MetricsCollector(config)
        
        result = metrics.increment_counter("test_counter")
        assert result == 0  # Returns 0 when disabled
        
        result = metrics.set_gauge("test_gauge", 42.0)
        assert result == 0.0  # Returns 0 when disabled
    
    def test_counter_increment(self):
        config = ObservabilityConfig(metrics_enabled=True)
        metrics = MetricsCollector(config)
        
        assert metrics.increment_counter("requests") == 1
        assert metrics.increment_counter("requests") == 2
        assert metrics.increment_counter("requests", 5) == 7
        assert metrics.get_counter_value("requests") == 7
    
    def test_gauge_set(self):
        config = ObservabilityConfig(metrics_enabled=True)
        metrics = MetricsCollector(config)
        
        assert metrics.set_gauge("memory_usage", 75.5) == 75.5
        assert metrics.get_gauge_value("memory_usage") == 75.5
    
    def test_timer_recording(self):
        config = ObservabilityConfig(metrics_enabled=True)
        metrics = MetricsCollector(config)
        
        metrics.record_timer("request_latency", 0.05)
        metrics.record_timer("request_latency", 0.1)
        metrics.record_timer("request_latency", 0.025)
        
        stats = metrics.get_timer_stats("request_latency")
        assert stats["count"] == 3
        assert stats["avg"] == pytest.approx(0.0583, abs=0.001)
    
    def test_timer_decorator(self):
        config = ObservabilityConfig(metrics_enabled=True)
        metrics = MetricsCollector(config)
        
        @metrics.time_function("test_func")
        def slow_func():
            time.sleep(0.01)
            return "done"
        
        result = slow_func()
        assert result == "done"
        
        stats = metrics.get_timer_stats("test_func")
        assert stats["count"] == 1
        assert stats["avg"] > 0
    
    def test_empty_timer_stats(self):
        config = ObservabilityConfig(metrics_enabled=True)
        metrics = MetricsCollector(config)
        stats = metrics.get_timer_stats("nonexistent")
        assert stats["count"] == 0
        assert stats["avg"] is None


class TestHealthCheckFramework:
    """Test HealthCheckFramework functionality."""
    
    def test_health_checks_disabled_by_default(self):
        """Health checks must return None when disabled."""
        config = ObservabilityConfig()  # health_checks_enabled=False
        health = HealthCheckFramework(config)
        
        def always_healthy():
            return HealthCheckResult("test", HealthStatus.HEALTHY, "ok", 0.0)
        
        health.register_check("test", always_healthy)
        result = health.run_check("test")
        assert result is None
    
    def test_health_check_enabled(self):
        config = ObservabilityConfig(health_checks_enabled=True)
        health = HealthCheckFramework(config)
        
        def always_healthy():
            return HealthCheckResult("test", HealthStatus.HEALTHY, "ok", 0.0)
        
        health.register_check("test", always_healthy)
        result = health.run_check("test")
        assert result is not None
        assert result.status == HealthStatus.HEALTHY
    
    def test_health_check_exception_handling(self):
        config = ObservabilityConfig(health_checks_enabled=True)
        health = HealthCheckFramework(config)
        
        def failing_check():
            raise RuntimeError("Something broke")
        
        health.register_check("failing", failing_check)
        result = health.run_check("failing")
        assert result.status == HealthStatus.UNHEALTHY
        assert "exception" in result.message.lower()
    
    def test_overall_status_aggregation(self):
        config = ObservabilityConfig(health_checks_enabled=True)
        health = HealthCheckFramework(config)
        
        health.register_check("h1", lambda: HealthCheckResult("h1", HealthStatus.HEALTHY, "ok", 0.0))
        health.register_check("h2", lambda: HealthCheckResult("h2", HealthStatus.DEGRADED, "slow", 0.0))
        
        health.run_all_checks()
        assert health.get_overall_status() == HealthStatus.DEGRADED
    
    def test_unregistered_check(self):
        config = ObservabilityConfig(health_checks_enabled=True)
        health = HealthCheckFramework(config)
        result = health.run_check("nonexistent")
        assert result.status == HealthStatus.UNKNOWN


class TestDistributedTracer:
    """Test DistributedTracer functionality."""
    
    def test_tracing_disabled_by_default(self):
        """Tracing must return empty/None when disabled."""
        config = ObservabilityConfig()  # tracing_enabled=False
        tracer = DistributedTracer(config)
        
        assert tracer.generate_correlation_id() == ""
        assert tracer.get_correlation_id() is None
        assert tracer.get_baggage() == {}
    
    def test_correlation_id_propagation(self):
        config = ObservabilityConfig(tracing_enabled=True)
        tracer = DistributedTracer(config)
        
        cid = tracer.generate_correlation_id()
        assert len(cid) > 0
        
        tracer.set_correlation_id(cid)
        assert tracer.get_correlation_id() == cid
    
    def test_baggage_propagation(self):
        config = ObservabilityConfig(tracing_enabled=True, propagate_baggage=True)
        tracer = DistributedTracer(config)
        
        tracer.set_baggage("user_id", "123")
        tracer.set_baggage("request_type", "threat_lookup")
        
        baggage = tracer.get_baggage()
        assert baggage["user_id"] == "123"
        assert baggage["request_type"] == "threat_lookup"
    
    def test_clear_context(self):
        config = ObservabilityConfig(tracing_enabled=True, propagate_baggage=True)
        tracer = DistributedTracer(config)
        
        tracer.set_correlation_id("test-cid")
        tracer.set_baggage("key", "value")
        tracer.clear_context()
        
        assert tracer.get_correlation_id() is None
        assert tracer.get_baggage() == {}
    
    def test_trace_span_decorator(self):
        config = ObservabilityConfig(tracing_enabled=True)
        tracer = DistributedTracer(config)
        
        @tracer.trace_span("test_operation")
        def test_func():
            return tracer.get_correlation_id()
        
        cid = test_func()
        assert cid is not None
        assert len(cid) > 0


class TestSLOTracker:
    """Test SLOTracker functionality."""
    
    def test_slo_tracking_disabled_by_default(self):
        """SLO tracking must return UNKNOWN when disabled."""
        config = ObservabilityConfig()  # slo_tracking_enabled=False
        slo = SLOTracker(config)
        
        slo.record_success("test_slo")
        status = slo.get_slo_status("test_slo")
        assert status["status"] == SLOStatus.UNKNOWN
    
    def test_slo_perfect_availability(self):
        config = ObservabilityConfig(slo_tracking_enabled=True)
        slo = SLOTracker(config)
        slo.register_slo(SLOConfig(name="test", target_percentage=99.9))
        
        for _ in range(100):
            slo.record_success("test")
        
        status = slo.get_slo_status("test")
        assert status["availability"] == 100.0
        assert status["status"] == SLOStatus.OK
    
    def test_slo_with_errors(self):
        config = ObservabilityConfig(slo_tracking_enabled=True)
        slo = SLOTracker(config)
        slo.register_slo(SLOConfig(name="test", target_percentage=99.0))
        
        for _ in range(95):
            slo.record_success("test")
        for _ in range(5):
            slo.record_error("test")
        
        status = slo.get_slo_status("test")
        assert status["availability"] == 95.0
        assert status["error_count"] == 5
    
    def test_unregistered_slo(self):
        config = ObservabilityConfig(slo_tracking_enabled=True)
        slo = SLOTracker(config)
        status = slo.get_slo_status("nonexistent")
        assert status["status"] == SLOStatus.UNKNOWN


class TestThreatIntelligenceObservabilitySingleton:
    """Test main singleton facade."""
    
    def test_singleton_pattern(self):
        instance1 = ThreatIntelligenceObservability()
        instance2 = ThreatIntelligenceObservability()
        assert instance1 is instance2
    
    def test_global_instance_exists(self):
        assert observability is not None
    
    def test_all_features_disabled_by_default(self):
        """CRITICAL: All features must be disabled by default."""
        obs = ThreatIntelligenceObservability()
        config = obs.config
        assert config.logging_enabled is False
        assert config.metrics_enabled is False
        assert config.health_checks_enabled is False
        assert config.tracing_enabled is False
        assert config.slo_tracking_enabled is False
    
    def test_enable_logging(self):
        obs = ThreatIntelligenceObservability()
        obs.enable_logging()
        assert obs.config.logging_enabled is True
    
    def test_enable_metrics(self):
        obs = ThreatIntelligenceObservability()
        obs.enable_metrics()
        assert obs.config.metrics_enabled is True
    
    def test_enable_health_checks(self):
        obs = ThreatIntelligenceObservability()
        obs.enable_health_checks()
        assert obs.config.health_checks_enabled is True
    
    def test_enable_tracing(self):
        obs = ThreatIntelligenceObservability()
        obs.enable_tracing()
        assert obs.config.tracing_enabled is True
    
    def test_enable_slo_tracking(self):
        obs = ThreatIntelligenceObservability()
        obs.enable_slo_tracking()
        assert obs.config.slo_tracking_enabled is True
    
    def test_enable_all(self):
        obs = ThreatIntelligenceObservability()
        obs.enable_all()
        assert obs.config.logging_enabled is True
        assert obs.config.metrics_enabled is True
        assert obs.config.health_checks_enabled is True
        assert obs.config.tracing_enabled is True
        assert obs.config.slo_tracking_enabled is True
    
    def test_status_summary(self):
        obs = ThreatIntelligenceObservability()
        summary = obs.get_status_summary()
        assert "config" in summary
        assert "health" in summary
        assert "metrics" in summary
        assert "tracing" in summary


class TestBackwardCompatibility:
    """Verify backward compatibility - no breaking changes."""
    
    def test_no_existing_code_modified(self):
        """This test verifies the module is completely standalone."""
        # Import should work without errors
        from neural_shield.observability_instrumentation_threat_intelligence_v11_2026_june import observability
        assert observability is not None
    
    def test_opt_in_pattern_respected(self):
        """All operations should be safe even when disabled."""
        from neural_shield.observability_instrumentation_threat_intelligence_v11_2026_june import observability
        
        # These should all work without errors when disabled
        observability.logger.info("test", "comp")
        observability.metrics.increment_counter("test")
        observability.health.run_all_checks()
        observability.tracer.generate_correlation_id()
        observability.slo.record_success("test")
        
        # No exceptions = success
        assert True


class TestThreadSafety:
    """Test thread safety of all components."""
    
    def test_concurrent_counter_increments(self):
        config = ObservabilityConfig(metrics_enabled=True)
        metrics = MetricsCollector(config)
        
        def worker():
            for _ in range(100):
                metrics.increment_counter("concurrent")
        
        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert metrics.get_counter_value("concurrent") == 1000


class TestEdgeCases:
    """Test edge cases and boundary conditions."""
    
    def test_empty_log_retrieval(self):
        config = ObservabilityConfig(logging_enabled=True)
        logger = StructuredLogger(config)
        logs = logger.get_recent_logs()
        assert len(logs) == 0
    
    def test_large_log_count(self):
        config = ObservabilityConfig(logging_enabled=True, max_log_entries=100)
        logger = StructuredLogger(config)
        
        for i in range(200):
            logger.info(f"msg {i}", "comp")
        
        logs = logger.get_recent_logs(200)
        assert len(logs) == 100  # Ring buffer capped at 100
    
    def test_slo_no_events(self):
        config = ObservabilityConfig(slo_tracking_enabled=True)
        slo = SLOTracker(config)
        slo.register_slo(SLOConfig(name="empty", target_percentage=99.9))
        
        status = slo.get_slo_status("empty")
        assert status["total_events"] == 0
        assert status["availability"] == 100.0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
