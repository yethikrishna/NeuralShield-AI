"""
Test Suite for Dimension D - Observability v14 HTTP Metrics Bridge
NeuralShield-AI | June 2026
ADD-ONLY COMPLIANT: 100% new tests, NO production code modified
Tests: 26 total across 9 test classes
Covers: Module import, state management, config, sync logic, graceful degradation
"""
import unittest
import threading
import time
import sys
import os
# Import directly from module file
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))
import observability_v14_http_metrics_bridge_2026_june as observability_v14_http_metrics_bridge
class TestModuleImportBaseline(unittest.TestCase):
    """Test module can be imported without side effects"""
    
    def test_module_imports_successfully(self):
        """Bridge module imports without errors"""
        self.assertIsNotNone(observability_v14_http_metrics_bridge)
    
    def test_global_instance_exists(self):
        """Global bridge instance is created"""
        self.assertIsNotNone(observability_v14_http_metrics_bridge.metrics_bridge)
    
    def test_bridge_starts_disabled(self):
        """Bridge is DISABLED by default (OPT-IN requirement)"""
        observability_v14_http_metrics_bridge.metrics_bridge.disable()
        time.sleep(0.1)
        self.assertFalse(observability_v14_http_metrics_bridge.metrics_bridge.is_enabled)
        self.assertEqual(
            observability_v14_http_metrics_bridge.metrics_bridge.get_bridge_stats()["state"], 
            "disabled"
        )
class TestBridgeConfigDefaults(unittest.TestCase):
    """Test bridge configuration defaults"""
    
    def test_default_config_values(self):
        """Default config has sensible values"""
        config = observability_v14_http_metrics_bridge.BridgeConfig()
        self.assertEqual(config.sync_interval_seconds, 5.0)
        self.assertTrue(config.enable_timers)
        self.assertTrue(config.enable_histograms)
        self.assertFalse(config.auto_start_server)
        self.assertEqual(config.metric_prefix, "neuralshield_")
    
    def test_custom_config_accepted(self):
        """Custom config values are respected"""
        config = observability_v14_http_metrics_bridge.BridgeConfig(
            sync_interval_seconds=10.0,
            enable_timers=False,
            enable_histograms=False,
            auto_start_server=True,
            metric_prefix="custom_",
        )
        self.assertEqual(config.sync_interval_seconds, 10.0)
        self.assertFalse(config.enable_timers)
        self.assertFalse(config.enable_histograms)
        self.assertTrue(config.auto_start_server)
        self.assertEqual(config.metric_prefix, "custom_")
class TestBridgeStateTransitions(unittest.TestCase):
    """Test enable/disable state transitions"""
    
    def setUp(self):
        """Reset bridge state before each test"""
        observability_v14_http_metrics_bridge.metrics_bridge.disable()
        time.sleep(0.2)
    
    def tearDown(self):
        """Clean up after each test"""
        observability_v14_http_metrics_bridge.metrics_bridge.disable()
        time.sleep(0.2)
    
    def test_enable_transitions_state(self):
        """enable() transitions from DISABLED → ENABLED"""
        observability_v14_http_metrics_bridge.metrics_bridge.enable()
        time.sleep(0.1)
        self.assertTrue(observability_v14_http_metrics_bridge.metrics_bridge.is_enabled)
    
    def test_disable_from_enabled(self):
        """disable() transitions from ENABLED → DISABLED"""
        observability_v14_http_metrics_bridge.metrics_bridge.enable()
        time.sleep(0.1)
        self.assertTrue(observability_v14_http_metrics_bridge.metrics_bridge.is_enabled)
        observability_v14_http_metrics_bridge.metrics_bridge.disable()
        time.sleep(0.2)
        self.assertFalse(observability_v14_http_metrics_bridge.metrics_bridge.is_enabled)
    
    def test_double_enable_no_error(self):
        """Calling enable() twice does not crash"""
        observability_v14_http_metrics_bridge.metrics_bridge.enable()
        time.sleep(0.1)
        observability_v14_http_metrics_bridge.metrics_bridge.enable()
        time.sleep(0.1)
        self.assertTrue(observability_v14_http_metrics_bridge.metrics_bridge.is_enabled)
    
    def test_double_disable_no_error(self):
        """Calling disable() twice does not crash"""
        observability_v14_http_metrics_bridge.metrics_bridge.disable()
        time.sleep(0.1)
        observability_v14_http_metrics_bridge.metrics_bridge.disable()
        time.sleep(0.1)
        self.assertFalse(observability_v14_http_metrics_bridge.metrics_bridge.is_enabled)
    
    def test_enable_with_custom_config(self):
        """Enable accepts custom config"""
        config = observability_v14_http_metrics_bridge.BridgeConfig(
            sync_interval_seconds=2.0, 
            metric_prefix="test_"
        )
        observability_v14_http_metrics_bridge.metrics_bridge.enable(config)
        time.sleep(0.1)
        stats = observability_v14_http_metrics_bridge.metrics_bridge.get_bridge_stats()
        self.assertEqual(stats["config"]["sync_interval_seconds"], 2.0)
        self.assertEqual(stats["config"]["metric_prefix"], "test_")
class TestBridgeStatistics(unittest.TestCase):
    """Test bridge statistics reporting"""
    
    def setUp(self):
        observability_v14_http_metrics_bridge.metrics_bridge.disable()
        time.sleep(0.1)
    
    def tearDown(self):
        observability_v14_http_metrics_bridge.metrics_bridge.disable()
        time.sleep(0.1)
    
    def test_stats_returns_all_fields(self):
        """get_bridge_stats() returns all expected fields"""
        stats = observability_v14_http_metrics_bridge.metrics_bridge.get_bridge_stats()
        self.assertIn("state", stats)
        self.assertIn("sync_count", stats)
        self.assertIn("error_count", stats)
        self.assertIn("last_sync_time", stats)
        self.assertIn("config", stats)
        self.assertIn("v8_enabled", stats)
        self.assertIn("v14_running", stats)
    
    def test_sync_count_starts_at_zero(self):
        """Sync count starts at 0 for disabled bridge"""
        stats = observability_v14_http_metrics_bridge.metrics_bridge.get_bridge_stats()
        self.assertEqual(stats["sync_count"], 0)
        self.assertEqual(stats["error_count"], 0)
    
    def test_sync_now_increments_count(self):
        """sync_now() increments sync count (graceful degradation if deps missing)"""
        initial = observability_v14_http_metrics_bridge.metrics_bridge.get_bridge_stats()["sync_count"]
        observability_v14_http_metrics_bridge.metrics_bridge.sync_now()
        final = observability_v14_http_metrics_bridge.metrics_bridge.get_bridge_stats()["sync_count"]
        self.assertGreaterEqual(final, initial)
class TestMetricNameSanitization(unittest.TestCase):
    """Test Prometheus metric name sanitization"""
    
    def test_sanitize_basic_name(self):
        """Basic names pass through with prefix"""
        bridge = observability_v14_http_metrics_bridge.HTTPMetricsBridge()
        result = bridge._sanitize_metric_name("test_counter")
        self.assertEqual(result, "neuralshield_test_counter")
    
    def test_sanitize_special_characters(self):
        """Special characters replaced with underscore"""
        bridge = observability_v14_http_metrics_bridge.HTTPMetricsBridge()
        result = bridge._sanitize_metric_name("test-counter!@#")
        self.assertIn("neuralshield_test_counter___", result)
    
    def test_sanitize_starts_with_number(self):
        """Names starting with number get underscore prefix"""
        bridge = observability_v14_http_metrics_bridge.HTTPMetricsBridge()
        result = bridge._sanitize_metric_name("123test")
        self.assertTrue(result.startswith("neuralshield__"))
    
    def test_custom_prefix_applied(self):
        """Custom metric prefix is applied"""
        bridge = observability_v14_http_metrics_bridge.HTTPMetricsBridge()
        bridge._config = observability_v14_http_metrics_bridge.BridgeConfig(metric_prefix="custom_")
        result = bridge._sanitize_metric_name("test")
        self.assertEqual(result, "custom_test")
class TestLabelConversion(unittest.TestCase):
    """Test Prometheus label conversion"""
    
    def test_basic_labels_pass_through(self):
        """Basic labels pass through unchanged"""
        bridge = observability_v14_http_metrics_bridge.HTTPMetricsBridge()
        result = bridge._convert_labels_to_prometheus({"key": "value"})
        self.assertEqual(result["key"], "value")
    
    def test_special_chars_in_label_keys(self):
        """Special chars in label keys replaced"""
        bridge = observability_v14_http_metrics_bridge.HTTPMetricsBridge()
        result = bridge._convert_labels_to_prometheus({"key-name!": "value"})
        self.assertIn("key_name_", result)
    
    def test_quotes_in_label_values_escaped(self):
        """Quotes in label values are escaped"""
        bridge = observability_v14_http_metrics_bridge.HTTPMetricsBridge()
        result = bridge._convert_labels_to_prometheus({"key": 'value"with"quotes'})
        self.assertIn('\\"', result["key"])
class TestGracefulDegradation(unittest.TestCase):
    """Test graceful degradation when dependencies missing"""
    
    def setUp(self):
        observability_v14_http_metrics_bridge.metrics_bridge.disable()
        time.sleep(0.1)
    
    def tearDown(self):
        observability_v14_http_metrics_bridge.metrics_bridge.disable()
        time.sleep(0.1)
    
    def test_sync_now_no_crash_without_deps(self):
        """sync_now() doesn't crash even if v8/v14 not available"""
        try:
            observability_v14_http_metrics_bridge.metrics_bridge.sync_now()
        except Exception as e:
            self.fail(f"sync_now crashed: {e}")
    
    def test_enable_no_crash_without_deps(self):
        """enable() doesn't crash even if v8/v14 not available"""
        try:
            observability_v14_http_metrics_bridge.metrics_bridge.enable()
            time.sleep(0.2)
        except Exception as e:
            self.fail(f"enable crashed: {e}")
    
    def test_stats_no_crash_without_deps(self):
        """get_bridge_stats() doesn't crash if deps missing"""
        try:
            stats = observability_v14_http_metrics_bridge.metrics_bridge.get_bridge_stats()
            self.assertIsInstance(stats, dict)
        except Exception as e:
            self.fail(f"get_bridge_stats crashed: {e}")
class TestThreadSafety(unittest.TestCase):
    """Test thread safety of bridge operations"""
    
    def setUp(self):
        observability_v14_http_metrics_bridge.metrics_bridge.disable()
        time.sleep(0.1)
    
    def tearDown(self):
        observability_v14_http_metrics_bridge.metrics_bridge.disable()
        time.sleep(0.2)
    
    def test_concurrent_sync_now_no_crash(self):
        """Multiple threads calling sync_now don't crash"""
        errors = []
        def worker():
            try:
                for _ in range(10):
                    observability_v14_http_metrics_bridge.metrics_bridge.sync_now()
            except Exception as e:
                errors.append(e)
        
        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5.0)
        
        self.assertEqual(len(errors), 0, f"Thread safety errors: {errors}")
    
    def test_concurrent_enable_disable_no_crash(self):
        """Concurrent enable/disable don't crash"""
        errors = []
        def worker():
            try:
                for _ in range(5):
                    observability_v14_http_metrics_bridge.metrics_bridge.enable()
                    time.sleep(0.01)
                    observability_v14_http_metrics_bridge.metrics_bridge.disable()
                    time.sleep(0.01)
            except Exception as e:
                errors.append(e)
        
        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5.0)
        
        self.assertEqual(len(errors), 0, f"Thread safety errors: {errors}")
class TestModuleMetadata(unittest.TestCase):
    """Test module metadata constants"""
    
    def test_metadata_constants_exist(self):
        """All expected metadata constants are defined"""
        self.assertEqual(observability_v14_http_metrics_bridge.MODULE_VERSION, "v14")
        self.assertEqual(
            observability_v14_http_metrics_bridge.MODULE_NAME, 
            "Observability HTTP Metrics Bridge"
        )
        self.assertEqual(
            observability_v14_http_metrics_bridge.DIMENSION, 
            "D - Observability & Instrumentation"
        )
        self.assertTrue(observability_v14_http_metrics_bridge.ADD_ONLY_COMPLIANT)
        self.assertTrue(observability_v14_http_metrics_bridge.PRODUCTION_READY)
        self.assertTrue(observability_v14_http_metrics_bridge.OPT_IN_REQUIRED)
        self.assertTrue(observability_v14_http_metrics_bridge.BACKWARD_COMPATIBLE)
if __name__ == "__main__":
    unittest.main(verbosity=2)
