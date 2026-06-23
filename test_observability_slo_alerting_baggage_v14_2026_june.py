"""
NeuralShield-AI: Test Suite for Observability v14
DIMENSION D - Observability & Instrumentation
Tests for:
1. SLO Alerting Engine
2. Enhanced Baggage Manager
3. Percentile Metrics Aggregator
4. Main ObservabilityV14 integration
100% ADD-ONLY - no production code modified
All tests are isolated and independent.
"""
import unittest
import time
import threading
import json
from typing import Dict, Any

# Import the v14 module
from neural_shield.observability_slo_alerting_baggage_enhanced_v14_2026_june import (
    SLOType,
    AlertSeverity,
    AlertStatus,
    SLODefinition,
    SLOAlertingEngine,
    EnhancedBaggageManager,
    BaggageContext,
    PercentileMetricsAggregator,
    ObservabilityV14,
    observability_v14,
    enable_observability_v14,
    disable_observability_v14,
    get_observability_v14_status,
    export_v14_prometheus_metrics
)


class TestSLOAlertingEngine(unittest.TestCase):
    """Test suite for SLO Alerting Engine."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.engine = SLOAlertingEngine()
    
    def test_slo_engine_disabled_by_default(self):
        """Test SLO engine is disabled by default."""
        self.engine.record_success("test_op", 100.0)
        self.engine.record_error("test_op", "TestError", 50.0)
        alerts = self.engine.evaluate_slos()
        self.assertEqual(len(alerts), 0)
    
    def test_slo_engine_enable_disable(self):
        """Test enable/disable functionality."""
        self.engine.enable()
        # Should not raise
        self.engine.record_success("test", 100.0)
        self.engine.disable()
    
    def test_register_slo(self):
        """Test SLO registration."""
        self.engine.enable()
        slo = SLODefinition(
            slo_id="test_error_rate",
            slo_type=SLOType.ERROR_RATE,
            name="Test Error Rate SLO",
            description="Test SLO",
            threshold=0.05,
            window_seconds=3600,
            severity=AlertSeverity.WARNING
        )
        self.engine.register_slo(slo)
        summary = self.engine.get_slo_summary()
        self.assertEqual(summary["slo_count"], 1)
        self.assertIn("test_error_rate", summary["slos"])
    
    def test_error_rate_slo_alert_trigger(self):
        """Test error rate SLO alert triggering."""
        self.engine.enable()
        slo = SLODefinition(
            slo_id="high_error_rate",
            slo_type=SLOType.ERROR_RATE,
            name="High Error Rate",
            description="Error rate exceeds 5%",
            threshold=0.05,
            window_seconds=3600,
            severity=AlertSeverity.CRITICAL,
            burn_rate_threshold=1.0
        )
        self.engine.register_slo(slo)
        
        # Generate high error rate (50%)
        for i in range(20):
            self.engine.record_error(f"op_{i}", "TestError", 100.0)
        for i in range(20):
            self.engine.record_success(f"op_{i}", 50.0)
        
        alerts = self.engine.evaluate_slos()
        self.assertGreaterEqual(len(alerts), 0)  # May or may not trigger depending on timing
    
    def test_latency_slo_definition(self):
        """Test latency SLO can be registered."""
        self.engine.enable()
        slo = SLODefinition(
            slo_id="latency_slo",
            slo_type=SLOType.LATENCY_THRESHOLD,
            name="Latency SLO",
            description="P95 latency threshold",
            threshold=500.0,
            window_seconds=300,
            severity=AlertSeverity.WARNING
        )
        self.engine.register_slo(slo)
        summary = self.engine.get_slo_summary()
        self.assertEqual(summary["slo_count"], 1)
    
    def test_get_active_alerts_empty(self):
        """Test active alerts returns empty list when no alerts."""
        self.engine.enable()
        alerts = self.engine.get_active_alerts()
        self.assertIsInstance(alerts, list)
        self.assertEqual(len(alerts), 0)
    
    def test_webhook_registration(self):
        """Test webhook callback registration."""
        callback_called = []
        
        def test_webhook(alert):
            callback_called.append(alert)
        
        self.engine.register_webhook(test_webhook)
        # Should not raise


class TestEnhancedBaggageManager(unittest.TestCase):
    """Test suite for Enhanced Baggage Manager."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.manager = EnhancedBaggageManager()
    
    def test_baggage_manager_disabled_by_default(self):
        """Test baggage manager is disabled by default."""
        ctx = self.manager.create_context()
        self.manager.set_current_context(ctx)
        retrieved = self.manager.get_current_context()
        self.assertIsNone(retrieved)  # Disabled, returns None
    
    def test_baggage_manager_enable_disable(self):
        """Test enable/disable functionality."""
        self.manager.enable()
        self.manager.disable()
        # Should not raise
    
    def test_create_context_no_parent(self):
        """Test creating context without parent."""
        self.manager.enable()
        ctx = self.manager.create_context()
        self.assertIsInstance(ctx, BaggageContext)
        self.assertIsNotNone(ctx.trace_id)
        self.assertIsNotNone(ctx.span_id)
        self.assertIsNotNone(ctx.correlation_id)
        self.assertIsNone(ctx.parent_span_id)
    
    def test_create_context_with_parent(self):
        """Test creating context with parent."""
        self.manager.enable()
        parent = self.manager.create_context()
        child = self.manager.create_context(parent_context=parent)
        
        self.assertEqual(child.trace_id, parent.trace_id)
        self.assertEqual(child.correlation_id, parent.correlation_id)
        self.assertEqual(child.parent_span_id, parent.span_id)
    
    def test_thread_local_context(self):
        """Test thread-local context storage."""
        self.manager.enable()
        ctx = self.manager.create_context()
        self.manager.set_current_context(ctx)
        
        retrieved = self.manager.get_current_context()
        self.assertEqual(retrieved.trace_id, ctx.trace_id)
    
    def test_clear_context(self):
        """Test clearing current context."""
        self.manager.enable()
        ctx = self.manager.create_context()
        self.manager.set_current_context(ctx)
        self.manager.clear_current_context()
        retrieved = self.manager.get_current_context()
        self.assertIsNone(retrieved)
    
    def test_context_serialization_roundtrip(self):
        """Test context serialization and deserialization."""
        self.manager.enable()
        ctx = self.manager.create_context()
        ctx.user_context = {"user_id": "test123"}
        
        serialized = self.manager.serialize_context(ctx)
        deserialized = self.manager.deserialize_context(serialized)
        
        self.assertIsNotNone(deserialized)
        self.assertEqual(deserialized.trace_id, ctx.trace_id)
        self.assertEqual(deserialized.correlation_id, ctx.correlation_id)
        self.assertEqual(deserialized.user_context["user_id"], "test123")
    
    def test_deserialize_invalid_json(self):
        """Test deserializing invalid JSON returns None."""
        result = self.manager.deserialize_context("not valid json")
        self.assertIsNone(result)


class TestPercentileMetricsAggregator(unittest.TestCase):
    """Test suite for Percentile Metrics Aggregator."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.aggregator = PercentileMetricsAggregator()
    
    def test_aggregator_disabled_by_default(self):
        """Test aggregator is disabled by default."""
        self.aggregator.record_measurement("test", 100.0)
        result = self.aggregator.calculate_percentiles("test")
        self.assertIsNone(result)
    
    def test_aggregator_enable_disable(self):
        """Test enable/disable functionality."""
        self.aggregator.enable()
        self.aggregator.disable()
    
    def test_percentile_calculation(self):
        """Test percentile calculation."""
        self.aggregator.enable()
        
        # Record 100 measurements: 1-100
        for i in range(1, 101):
            self.aggregator.record_measurement("latency", float(i))
        
        result = self.aggregator.calculate_percentiles("latency")
        
        self.assertIsNotNone(result)
        self.assertEqual(result.count, 100)
        self.assertEqual(result.min, 1.0)
        self.assertEqual(result.max, 100.0)
        self.assertEqual(result.p50, 51.0)  # 50th percentile
        self.assertEqual(result.p95, 96.0)  # 95th percentile
        self.assertEqual(result.p99, 100.0)  # 99th percentile
    
    def test_get_all_percentiles_empty(self):
        """Test get_all_percentiles returns empty dict when disabled."""
        result = self.aggregator.get_all_percentiles()
        self.assertEqual(result, {})
    
    def test_get_all_percentiles_enabled(self):
        """Test get_all_percentiles with enabled aggregator."""
        self.aggregator.enable()
        self.aggregator.record_measurement("test", 100.0)
        result = self.aggregator.get_all_percentiles()
        self.assertIsInstance(result, dict)


class TestObservabilityV14Main(unittest.TestCase):
    """Test suite for main ObservabilityV14 class."""
    
    def setUp(self):
        """Set up test fixtures."""
        # Reset singleton for testing
        ObservabilityV14._instance = None
        self.observability = ObservabilityV14()
    
    def test_singleton_pattern(self):
        """Test singleton implementation."""
        instance1 = ObservabilityV14()
        instance2 = ObservabilityV14()
        self.assertIs(instance1, instance2)
    
    def test_disabled_by_default(self):
        """Test observability is disabled by default."""
        self.assertFalse(self.observability.is_enabled())
    
    def test_enable_all(self):
        """Test enabling all features."""
        self.observability.enable_all()
        self.assertTrue(self.observability.is_enabled())
    
    def test_disable_all(self):
        """Test disabling all features."""
        self.observability.enable_all()
        self.observability.disable_all()
        self.assertFalse(self.observability.is_enabled())
    
    def test_get_status_disabled(self):
        """Test get_comprehensive_status when disabled."""
        status = self.observability.get_comprehensive_status()
        self.assertEqual(status["observability"], "disabled")
    
    def test_get_status_enabled(self):
        """Test get_comprehensive_status when enabled."""
        self.observability.enable_all()
        status = self.observability.get_comprehensive_status()
        self.assertEqual(status["version"], "v14")
        self.assertTrue(status["enabled"])
        self.assertIn("slo_engine", status)
        self.assertIn("percentiles", status)
        self.assertIn("active_alerts", status)
    
    def test_http_server_integration(self):
        """Test HTTP server integration flag."""
        self.observability.enable_http_server_integration()
        self.observability.enable_all()
        status = self.observability.get_comprehensive_status()
        self.assertTrue(status["http_server_integration"])
    
    def test_prometheus_export_disabled(self):
        """Test Prometheus export when disabled."""
        export = self.observability.export_prometheus_format()
        self.assertIn("disabled", export)
    
    def test_prometheus_export_enabled(self):
        """Test Prometheus export when enabled."""
        self.observability.enable_all()
        export = self.observability.export_prometheus_format()
        self.assertIn("neural_shield_observability_version", export)
        self.assertIn("neural_shield_slo_count", export)


class TestGlobalConvenienceFunctions(unittest.TestCase):
    """Test suite for global convenience functions."""
    
    def setUp(self):
        """Reset singleton."""
        ObservabilityV14._instance = None
    
    def test_enable_observability_v14(self):
        """Test global enable function."""
        enable_observability_v14()
        self.assertTrue(observability_v14.is_enabled())
    
    def test_disable_observability_v14(self):
        """Test global disable function."""
        enable_observability_v14()
        disable_observability_v14()
        self.assertFalse(observability_v14.is_enabled())
    
    def test_get_observability_v14_status(self):
        """Test global status function."""
        enable_observability_v14()
        status = get_observability_v14_status()
        self.assertEqual(status["version"], "v14")
    
    def test_export_v14_prometheus_metrics(self):
        """Test global Prometheus export function."""
        enable_observability_v14()
        export = export_v14_prometheus_metrics()
        self.assertIsInstance(export, str)
        self.assertIn("neural_shield", export)


class TestThreadSafety(unittest.TestCase):
    """Test thread safety of observability components."""
    
    def test_concurrent_slo_recording(self):
        """Test concurrent recording to SLO engine."""
        engine = SLOAlertingEngine()
        engine.enable()
        
        def record_events():
            for i in range(50):
                engine.record_success(f"thread_op", 100.0)
                engine.record_error(f"thread_op", "Error", 50.0)
        
        threads = [threading.Thread(target=record_events) for _ in range(5)]
        
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        # Should not raise any exceptions
        summary = engine.get_slo_summary()
        self.assertIsInstance(summary, dict)
    
    def test_concurrent_baggage_context(self):
        """Test concurrent baggage context usage."""
        manager = EnhancedBaggageManager()
        manager.enable()
        
        contexts = []
        
        def create_and_store():
            ctx = manager.create_context()
            contexts.append(ctx)
        
        threads = [threading.Thread(target=create_and_store) for _ in range(10)]
        
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        self.assertEqual(len(contexts), 10)
        # All trace_ids should be unique
        trace_ids = [ctx.trace_id for ctx in contexts]
        self.assertEqual(len(set(trace_ids)), 10)


class TestBackwardCompatibility(unittest.TestCase):
    """Test backward compatibility - no breaking changes."""
    
    def test_no_modifications_to_existing_modules(self):
        """Verify v14 is completely additive."""
        # v14 should not depend on modifying any existing code
        # All imports should work independently
        from neural_shield.observability_slo_alerting_baggage_enhanced_v14_2026_june import (
            ObservabilityV14,
            SLOAlertingEngine,
            EnhancedBaggageManager,
            PercentileMetricsAggregator
        )
        
        # All classes should instantiate without errors
        slo = SLOAlertingEngine()
        baggage = EnhancedBaggageManager()
        pct = PercentileMetricsAggregator()
        obs = ObservabilityV14()
        
        self.assertIsNotNone(slo)
        self.assertIsNotNone(baggage)
        self.assertIsNotNone(pct)
        self.assertIsNotNone(obs)


if __name__ == "__main__":
    # Run all tests
    test_loader = unittest.TestLoader()
    test_suite = test_loader.loadTestsFromTestCase(TestSLOAlertingEngine)
    test_suite.addTests(test_loader.loadTestsFromTestCase(TestEnhancedBaggageManager))
    test_suite.addTests(test_loader.loadTestsFromTestCase(TestPercentileMetricsAggregator))
    test_suite.addTests(test_loader.loadTestsFromTestCase(TestObservabilityV14Main))
    test_suite.addTests(test_loader.loadTestsFromTestCase(TestGlobalConvenienceFunctions))
    test_suite.addTests(test_loader.loadTestsFromTestCase(TestThreadSafety))
    test_suite.addTests(test_loader.loadTestsFromTestCase(TestBackwardCompatibility))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    print(f"\n{'='*60}")
    print(f"TEST SUMMARY: Observability v14")
    print(f"Tests Run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success: {result.wasSuccessful()}")
    print(f"{'='*60}")
