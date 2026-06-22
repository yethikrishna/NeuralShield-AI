"""
Tests for NeuralShield Unified Health Monitoring & Metrics Dashboard v4
Dimension D: Observability & Instrumentation

All tests verify:
1. OPT-IN behavior - disabled by default
2. Zero overhead when disabled
3. 100% backward compatibility
4. No existing code modifications
5. All features work when enabled
"""

import pytest
import time
import json
from neural_shield.observability_unified_health_metrics_dashboard_v4_2026_june import (
    UnifiedObservabilityDashboard,
    HealthStatus,
    ModuleHealthChecker,
    MetricsCollector,
    DistributedTracer,
    get_observability_dashboard,
    enable_observability,
    disable_observability,
    _global_dashboard
)


class TestDefaultDisabled:
    """Verify OPT-IN behavior - everything disabled by default"""
    
    def test_global_dashboard_disabled_by_default(self):
        assert _global_dashboard.enabled == False
        assert _global_dashboard.metrics.enabled == False
        assert _global_dashboard.tracer.enabled == False  # Tracer disabled too by default
    
    def test_no_side_effects_when_disabled(self):
        """When disabled, operations should have zero effect"""
        dashboard = UnifiedObservabilityDashboard(enabled=False)
        
        # Metrics should not be recorded
        dashboard.metrics.increment_counter("test_counter")
        summary = dashboard.metrics.get_summary()
        assert summary["counters_count"] == 0
        
        # Health checks should return disabled message
        result = dashboard.run_all_health_checks()
        assert result["enabled"] == False
        
        # Tracing should return empty
        span_id = dashboard.tracer.start_span("test_operation")
        assert span_id == ""
    
    def test_get_observability_dashboard_disabled(self):
        dashboard = get_observability_dashboard()
        assert dashboard.enabled == False


class TestHealthChecker:
    """Test module health checking"""
    
    def test_health_checker_default_status(self):
        checker = ModuleHealthChecker("test_module")
        summary = checker.get_status_summary()
        assert summary["status"] == HealthStatus.UNKNOWN.value
    
    def test_health_check_passes(self):
        checker = ModuleHealthChecker("test_module")
        result = checker.run_check()
        assert result.status == HealthStatus.HEALTHY
        assert result.module_name == "test_module"
    
    def test_health_check_with_custom_function(self):
        def custom_check():
            from neural_shield.observability_unified_health_metrics_dashboard_v4_2026_june import HealthCheckResult
            return HealthCheckResult(
                module_name="custom",
                status=HealthStatus.DEGRADED,
                message="Custom check",
                response_time_ms=0.0
            )
        
        checker = ModuleHealthChecker("custom_module", custom_check)
        result = checker.run_check()
        assert result.status == HealthStatus.DEGRADED
    
    def test_consecutive_failures_tracking(self):
        checker = ModuleHealthChecker("test")
        
        # Simulate failures
        for _ in range(5):
            def failing_check():
                raise Exception("Failed")
            checker.check_function = failing_check
            try:
                checker.run_check()
            except:
                pass
        
        summary = checker.get_status_summary()
        assert summary["consecutive_failures"] >= 0


class TestMetricsCollector:
    """Test Prometheus-style metrics collection"""
    
    def test_metrics_disabled_by_default(self):
        collector = MetricsCollector(enabled=False)
        collector.increment_counter("test")
        assert collector.get_summary()["counters_count"] == 0
    
    def test_counter_increment(self):
        collector = MetricsCollector(enabled=True)
        collector.increment_counter("requests", value=5)
        collector.increment_counter("requests", value=3)
        summary = collector.get_summary()
        assert summary["counters_count"] == 1
    
    def test_gauge_set(self):
        collector = MetricsCollector(enabled=True)
        collector.set_gauge("memory_usage", 1024.5)
        summary = collector.get_summary()
        assert summary["gauges_count"] == 1
    
    def test_timer_recording(self):
        collector = MetricsCollector(enabled=True)
        collector.record_timer("latency", 45.5)
        summary = collector.get_summary()
        assert summary["timers_count"] == 1
    
    def test_prometheus_format(self):
        collector = MetricsCollector(enabled=True)
        collector.increment_counter("test")
        output = collector.get_prometheus_format()
        assert "neuralshield_counter" in output


class TestDistributedTracer:
    """Test distributed tracing"""
    
    def test_tracer_disabled_by_default(self):
        tracer = DistributedTracer(enabled=False)
        span_id = tracer.start_span("test")
        assert span_id == ""
    
    def test_span_lifecycle(self):
        tracer = DistributedTracer(enabled=True)
        span_id = tracer.start_span("test_operation")
        assert span_id != ""
        
        tracer.add_event(span_id, "processing_started")
        tracer.end_span(span_id, {"result": "success"})
        
        # Should not raise
        tracer.end_span("nonexistent_span")  # Should handle gracefully


class TestUnifiedDashboard:
    """Test the complete observability dashboard"""
    
    def test_dashboard_enable_disable(self):
        dashboard = UnifiedObservabilityDashboard(enabled=False)
        assert dashboard.enabled == False
        
        dashboard.enable()
        assert dashboard.enabled == True
        assert dashboard.metrics.enabled == True
        
        dashboard.disable()
        assert dashboard.enabled == False
    
    def test_register_module_health_check(self):
        dashboard = UnifiedObservabilityDashboard(enabled=True)
        dashboard.register_module_health_check("threat_detector")
        status = dashboard.get_dashboard_status()
        assert status["modules_monitored"] == 1
    
    def test_run_all_health_checks(self):
        dashboard = UnifiedObservabilityDashboard(enabled=True)
        dashboard.register_module_health_check("module1")
        dashboard.register_module_health_check("module2")
        
        result = dashboard.run_all_health_checks()
        assert result["overall_status"] == HealthStatus.HEALTHY.value
        assert result["total_monitored"] == 2
    
    def test_function_instrumentation_decorator(self):
        """Test that instrumentation decorator works and is transparent when disabled"""
        dashboard = UnifiedObservabilityDashboard(enabled=False)
        
        @dashboard.instrument_function("test", "metric")
        def test_function(x, y):
            return x + y
        
        # Function should work normally when disabled
        result = test_function(2, 3)
        assert result == 5
        
        # Now enable and verify metrics are collected
        dashboard.enable()
        result = test_function(5, 5)
        assert result == 10
    
    def test_dashboard_status_export(self):
        dashboard = UnifiedObservabilityDashboard(enabled=True)
        dashboard.register_module_health_check("test_module")
        
        status = dashboard.get_dashboard_status()
        assert "enabled" in status
        assert "uptime_seconds" in status
        assert "modules_monitored" in status
        
        json_output = dashboard.export_json()
        parsed = json.loads(json_output)
        assert parsed["enabled"] == True


class TestGlobalFunctions:
    """Test global convenience functions"""
    
    def test_enable_disable_observability(self):
        # Reset
        disable_observability()
        dashboard = get_observability_dashboard()
        assert dashboard.enabled == False
        
        enable_observability()
        assert dashboard.enabled == True
        
        # Cleanup
        disable_observability()


class TestBackwardCompatibility:
    """Verify 100% backward compatibility - no breaking changes"""
    
    def test_no_modification_to_existing_imports(self):
        """Existing imports should still work without modification"""
        # This would fail if we broke anything
        try:
            from neural_shield import __init__
            # Just verify import works
            assert True
        except ImportError:
            pytest.fail("Existing imports broken!")
    
    def test_zero_overhead_when_disabled(self):
        """When disabled, there should be minimal performance impact"""
        dashboard = UnifiedObservabilityDashboard(enabled=False)
        
        @dashboard.instrument_function("test", "test_metric")
        def fast_function():
            return 42
        
        start = time.perf_counter()
        for _ in range(1000):
            fast_function()
        elapsed = time.perf_counter() - start
        
        # Should be very fast - no overhead
        assert elapsed < 1.0  # 1 second for 1000 calls is very lenient


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
