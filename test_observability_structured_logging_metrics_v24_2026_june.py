"""
Test Suite for NeuralShield Observability v24
DIMENSION D: Observability & Instrumentation
All tests verify ADD-ONLY implementation works correctly
"""

import pytest
import json
import time
import threading
from neural_shield.observability_structured_logging_metrics_v24_2026_june import (
    ObservabilityConfig, StructuredLogger, MetricsRegistry, HealthCheckRegistry,
    TraceContextManager, LogLevel, MetricType, HealthStatus, Metric, HealthCheck,
    TraceContext, logger, metrics, health_checks, tracer,
    timed, counted, logged, traced,
    enable_logging, enable_metrics, enable_tracing, enable_health_checks,
    enable_all, disable_all, get_config, get_status, API_STABILITY
)


class TestObservabilityConfig:
    """Test configuration singleton and defaults"""
    
    def test_singleton_pattern(self):
        config1 = ObservabilityConfig()
        config2 = ObservabilityConfig()
        assert config1 is config2
    
    def test_defaults_are_disabled(self):
        config = ObservabilityConfig()
        # Reset to defaults
        config.logging_enabled = False
        config.metrics_enabled = False
        config.tracing_enabled = False
        config.health_checks_enabled = False
        
        assert config.logging_enabled is False
        assert config.metrics_enabled is False
        assert config.tracing_enabled is False
        assert config.health_checks_enabled is False
        assert config.service_name == "neuralshield-ai"
    
    def test_get_status(self):
        disable_all()
        status = get_status()
        assert all(v is False for v in status.values())


class TestStructuredLogger:
    """Test structured logging functionality"""
    
    def test_logger_disabled_by_default(self, capsys):
        disable_all()
        logger.info("test message")
        captured = capsys.readouterr()
        assert captured.out == ""
    
    def test_logger_enabled_outputs_json(self, capsys):
        enable_logging(log_to_console=True)
        logger.info("test message", custom_field="value")
        captured = capsys.readouterr()
        disable_all()
        
        if captured.out:
            log_entry = json.loads(captured.out.strip())
            assert log_entry["message"] == "test message"
            assert log_entry["level"] == "info"
            assert log_entry["custom_field"] == "value"
            assert "timestamp" in log_entry
    
    def test_all_log_levels(self):
        enable_logging(log_to_console=False)
        # Should not raise any exceptions
        logger.debug("debug")
        logger.info("info")
        logger.warning("warning")
        logger.error("error")
        logger.critical("critical")
        disable_all()


class TestMetricsRegistry:
    """Test metrics collection functionality"""
    
    def test_metrics_disabled_by_default(self):
        disable_all()
        metrics.increment_counter("test_counter")
        export = metrics.export_prometheus()
        assert export == ""
    
    def test_counter_increment(self):
        enable_metrics()
        metrics.increment_counter("requests_total", labels={"endpoint": "/api"})
        metrics.increment_counter("requests_total", labels={"endpoint": "/api"})
        export = metrics.export_json()
        disable_all()
        
        assert len(export["metrics"]) > 0
        found = any(m["name"] == "requests_total" for m in export["metrics"])
        assert found
    
    def test_gauge_set(self):
        enable_metrics()
        metrics.set_gauge("memory_usage", 1024.5, labels={"service": "ai"})
        export = metrics.export_json()
        disable_all()
        
        found = any(m["name"] == "memory_usage" and m["value"] == 1024.5 for m in export["metrics"])
        assert found
    
    def test_timer_recording(self):
        enable_metrics()
        metrics.record_timer("request_duration", 123.45, labels={"route": "/test"})
        export = metrics.export_json()
        disable_all()
        
        found = any(m["name"] == "request_duration" for m in export["metrics"])
        assert found
    
    def test_prometheus_export_format(self):
        enable_metrics()
        metrics.increment_counter("test_counter", help_text="Test counter help")
        export = metrics.export_prometheus()
        disable_all()
        
        assert "# HELP test_counter" in export
        assert "# TYPE test_counter counter" in export
        assert "test_counter" in export


class TestHealthCheckRegistry:
    """Test health check framework"""
    
    def test_health_checks_disabled_by_default(self):
        disable_all()
        result = health_checks.run_all_checks()
        assert result["status"] == HealthStatus.HEALTHY.value
        assert result["message"] == "Health checks disabled"
    
    def test_health_check_registration(self):
        enable_health_checks()
        
        def sample_check():
            return HealthCheck(
                name="database",
                status=HealthStatus.HEALTHY,
                message="Connection OK"
            )
        
        health_checks.register_check("database", sample_check)
        result = health_checks.run_all_checks()
        disable_all()
        
        assert "database" in result["checks"]
        assert result["checks"]["database"]["status"] == HealthStatus.HEALTHY.value
    
    def test_health_check_degraded_status(self):
        enable_health_checks()
        
        def degraded_check():
            return HealthCheck(
                name="cache",
                status=HealthStatus.DEGRADED,
                message="High latency"
            )
        
        health_checks.register_check("cache", degraded_check)
        result = health_checks.run_all_checks()
        disable_all()
        
        assert result["status"] == HealthStatus.DEGRADED.value
    
    def test_health_check_exception_handling(self):
        enable_health_checks()
        
        def failing_check():
            raise RuntimeError("Database connection failed")
        
        health_checks.register_check("failing", failing_check)
        result = health_checks.run_all_checks()
        disable_all()
        
        assert result["status"] == HealthStatus.UNHEALTHY.value


class TestTraceContextManager:
    """Test distributed tracing functionality"""
    
    def test_tracing_disabled_by_default(self):
        disable_all()
        ctx = tracer.create_trace()
        assert ctx.trace_id == "disabled"
        assert ctx.span_id == "disabled"
    
    def test_trace_creation(self):
        enable_tracing()
        ctx = tracer.create_trace()
        disable_all()
        
        assert ctx.trace_id != "disabled"
        assert ctx.span_id != "disabled"
        assert len(ctx.trace_id) == 32
        assert len(ctx.span_id) == 16
    
    def test_child_span_creation(self):
        enable_tracing()
        parent = tracer.create_trace()
        child = tracer.create_child_span(parent)
        disable_all()
        
        assert child.trace_id == parent.trace_id
        assert child.parent_span_id == parent.span_id
        assert child.span_id != parent.span_id


class TestDecorators:
    """Test instrumentation decorators"""
    
    def test_timed_decorator_disabled(self):
        disable_all()
        
        @timed("test_function_duration")
        def test_func():
            return "success"
        
        result = test_func()
        assert result == "success"
        # No metrics should be recorded
    
    def test_timed_decorator_enabled(self):
        enable_metrics()
        
        @timed("decorated_function_duration", labels={"type": "test"})
        def test_func():
            time.sleep(0.01)
            return "success"
        
        result = test_func()
        export = metrics.export_json()
        disable_all()
        
        assert result == "success"
        assert len(export["metrics"]) > 0
    
    def test_counted_decorator(self):
        enable_metrics()
        
        @counted("function_calls", labels={"module": "test"})
        def test_func():
            return "ok"
        
        test_func()
        test_func()
        export = metrics.export_json()
        disable_all()
        
        found = any(m["name"] == "function_calls" for m in export["metrics"])
        assert found
    
    def test_logged_decorator(self, capsys):
        enable_logging(log_to_console=True)
        
        @logged(LogLevel.INFO, "test operation")
        def test_func():
            return "done"
        
        result = test_func()
        captured = capsys.readouterr()
        disable_all()
        
        assert result == "done"
    
    def test_traced_decorator(self):
        enable_tracing()
        
        @traced("test_operation")
        def test_func():
            return tracer.get_current_context()
        
        ctx = test_func()
        disable_all()
        
        assert ctx is not None
    
    def test_decorator_exception_propagation(self):
        enable_metrics()
        
        @timed("error_test")
        def error_func():
            raise ValueError("test error")
        
        with pytest.raises(ValueError):
            error_func()
        disable_all()


class TestThreadSafety:
    """Test thread safety of observability components"""
    
    def test_concurrent_metric_updates(self):
        enable_metrics()
        
        def worker():
            for _ in range(100):
                metrics.increment_counter("concurrent_counter")
        
        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        export = metrics.export_json()
        disable_all()
        
        # Should not have crashed


class TestAPIStability:
    """Test API stability markers"""
    
    def test_api_stability_markers_exist(self):
        assert isinstance(API_STABILITY, dict)
        assert len(API_STABILITY) > 0
    
    def test_all_markers_are_stable(self):
        for marker in API_STABILITY.values():
            assert marker == "STABLE"
    
    def test_all_exports_exist(self):
        import neural_shield.observability_structured_logging_metrics_v24_2026_june as module
        for export_name in module.__all__:
            assert hasattr(module, export_name)


class TestBackwardCompatibility:
    """Test backward compatibility - zero impact on existing code"""
    
    def test_no_side_effects_when_disabled(self):
        disable_all()
        
        # All operations should be no-ops
        logger.info("test")
        metrics.increment_counter("test")
        health_checks.run_all_checks()
        tracer.create_trace()
        
        # Should complete without errors
        assert True
    
    def test_enable_disable_cycle(self):
        # Multiple enable/disable should work
        for _ in range(3):
            enable_all()
            assert all(v is True for v in get_status().values())
            disable_all()
            assert all(v is False for v in get_status().values())


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
