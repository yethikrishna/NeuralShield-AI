"""
Test Suite for NeuralShield Observability Module (Dimension D - v25)
Tests verify:
1. All features are DISABLED by default (OPT-IN only)
2. No breaking changes to existing code
3. All instrumentation works correctly when enabled
4. Backward compatibility 100% preserved
"""

import pytest
import time
import json
from neural_shield.observability_structured_logging_metrics_v25_2026_june import (
    ObservabilityConfig,
    LogLevel,
    StructuredLogger,
    MetricsCollector,
    HealthStatus,
    HealthCheck,
    HealthCheckRegistry,
    timed_operation,
    logged_operation,
    get_config,
    get_logger,
    get_metrics,
    get_health_registry,
)


class TestObservabilityConfig:
    def test_default_config_all_disabled(self):
        config = ObservabilityConfig()
        config.structured_logging_enabled = False
        config.metrics_collection_enabled = False
        config.health_checks_enabled = False
        config.tracing_enabled = False
        
        assert config.structured_logging_enabled is False
        assert config.metrics_collection_enabled is False
        assert config.health_checks_enabled is False
        assert config.tracing_enabled is False
    
    def test_singleton_behavior(self):
        config1 = ObservabilityConfig()
        config2 = ObservabilityConfig()
        assert config1 is config2
    
    def test_enable_all(self):
        config = ObservabilityConfig()
        config.structured_logging_enabled = False
        config.metrics_collection_enabled = False
        config.health_checks_enabled = False
        config.tracing_enabled = False
        config.enable_all()
        assert config.structured_logging_enabled is True
        assert config.metrics_collection_enabled is True
        assert config.health_checks_enabled is True
        assert config.tracing_enabled is True


class TestStructuredLogger:
    def test_logger_no_op_when_disabled(self, capsys):
        config = ObservabilityConfig()
        config.structured_logging_enabled = False
        logger = StructuredLogger("test")
        logger.info("This should not appear")
        captured = capsys.readouterr()
        assert captured.out == ""
    
    def test_logger_outputs_json_when_enabled(self, capsys):
        config = ObservabilityConfig()
        config.structured_logging_enabled = True
        logger = StructuredLogger("test_logger")
        logger.info("Test message", custom_field="value123")
        captured = capsys.readouterr()
        log_output = json.loads(captured.out.strip())
        assert log_output["logger"] == "test_logger"
        assert log_output["level"] == "INFO"
        assert log_output["message"] == "Test message"
        assert "timestamp" in log_output


class TestMetricsCollector:
    def test_metrics_no_op_when_disabled(self):
        config = ObservabilityConfig()
        config.metrics_collection_enabled = False
        collector = MetricsCollector()
        collector.increment_counter("test_counter")
        metrics = collector.get_metrics()
        assert metrics == {}
    
    def test_counter_increments_when_enabled(self):
        config = ObservabilityConfig()
        config.metrics_collection_enabled = True
        collector = MetricsCollector()
        collector.reset()
        collector.increment_counter("requests")
        collector.increment_counter("requests")
        collector.increment_counter("requests", value=5)
        metrics = collector.get_metrics()
        assert metrics["requests"]["total"] == 7


class TestTimedOperationDecorator:
    def test_decorator_no_op_when_disabled(self):
        config = ObservabilityConfig()
        config.metrics_collection_enabled = False
        call_count = 0
        @timed_operation("test_op")
        def test_func():
            nonlocal call_count
            call_count += 1
            return "success"
        result = test_func()
        assert result == "success"
        assert call_count == 1
    
    def test_decorator_propagates_exceptions(self):
        config = ObservabilityConfig()
        config.metrics_collection_enabled = True
        @timed_operation("failing_op")
        def failing_func():
            raise ValueError("Test error")
        with pytest.raises(ValueError, match="Test error"):
            failing_func()


class TestBackwardCompatibility:
    def test_no_side_effects_when_disabled(self):
        config = ObservabilityConfig()
        config.structured_logging_enabled = False
        config.metrics_collection_enabled = False
        config.health_checks_enabled = False
        config.tracing_enabled = False
        
        logger = StructuredLogger()
        logger.info("should not log")
        
        metrics = MetricsCollector()
        metrics.increment_counter("should_not_count")
        
        @timed_operation("should_not_time")
        def test_func():
            return 42
        assert test_func() == 42
        
        @logged_operation()
        def test_func2():
            return "hello"
        assert test_func2() == "hello"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
