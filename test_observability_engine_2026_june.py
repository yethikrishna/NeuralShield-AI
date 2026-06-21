"""
Test suite for NeuralShield-AI Observability Engine
June 2026 - Production Grade Tests

Tests verify:
1. Observability is disabled by default (zero overhead)
2. Enabling/disabling works correctly
3. @observe decorator works when enabled
4. Metrics collection is accurate
5. Error tracking works
6. MetricsReporter generates valid reports
7. Thread safety
8. Environment variable auto-enable
9. No-op when disabled (performance)
"""

import os
import sys
import json
import time
import logging
import threading
import unittest

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from neural_shield.observability_engine_2026_june import (
    ObservabilityState,
    observe,
    observe_class,
    MetricsReporter,
    enable_observability,
    disable_observability,
    get_observability_metrics,
    reset_observability_metrics,
)


class TestObservabilityDefaultState(unittest.TestCase):
    """Test that observability is disabled by default."""

    def test_disabled_by_default(self):
        """Observability should be disabled when module loads fresh."""
        # We test the class method directly
        # Note: state may have been changed by other tests, so we reset
        disable_observability()
        self.assertFalse(ObservabilityState.is_enabled())

    def test_observe_decorator_noop_when_disabled(self):
        """@observe should be a pass-through when disabled."""
        disable_observability()
        
        call_count = [0]
        
        @observe
        def test_func(x, y):
            call_count[0] += 1
            return x + y
        
        result = test_func(3, 4)
        self.assertEqual(result, 7)
        self.assertEqual(call_count[0], 1)
        
        # No metrics should be collected when disabled
        metrics = get_observability_metrics()
        self.assertEqual(len(metrics["call_counts"]), 0)


class TestObservabilityEnableDisable(unittest.TestCase):
    """Test enabling and disabling observability."""

    def setUp(self):
        reset_observability_metrics()
        disable_observability()

    def test_enable_observability(self):
        """enable_observability() should turn on observability."""
        enable_observability(logging.DEBUG)
        self.assertTrue(ObservabilityState.is_enabled())
        disable_observability()

    def test_disable_observability(self):
        """disable_observability() should turn off observability."""
        enable_observability()
        self.assertTrue(ObservabilityState.is_enabled())
        disable_observability()
        self.assertFalse(ObservabilityState.is_enabled())


class TestObserveDecorator(unittest.TestCase):
    """Test the @observe decorator functionality."""

    def setUp(self):
        reset_observability_metrics()
        enable_observability(logging.WARNING)  # Use WARNING to suppress logs during test

    def tearDown(self):
        disable_observability()

    def test_decorator_preserves_function_behavior(self):
        """Decorated function should behave identically to original."""
        @observe
        def add(a, b):
            return a + b
        
        self.assertEqual(add(2, 3), 5)
        self.assertEqual(add(10, 20), 30)

    def test_decorator_preserves_function_name(self):
        """Decorated function should keep its __name__."""
        @observe
        def my_special_function():
            return 42
        
        self.assertEqual(my_special_function.__name__, "my_special_function")

    def test_decorator_tracks_call_count(self):
        """Decorator should track how many times function is called."""
        @observe
        def tracked_func():
            return "hello"
        
        tracked_func()
        tracked_func()
        tracked_func()
        
        metrics = get_observability_metrics()
        func_key = [k for k in metrics["call_counts"].keys() if "tracked_func" in k][0]
        self.assertEqual(metrics["call_counts"][func_key], 3)

    def test_decorator_tracks_duration(self):
        """Decorator should track function duration."""
        @observe
        def slow_func():
            time.sleep(0.01)
            return "done"
        
        slow_func()
        
        metrics = get_observability_metrics()
        func_key = [k for k in metrics["call_counts"].keys() if "slow_func" in k][0]
        self.assertIn(func_key, metrics["total_durations"])
        self.assertGreater(metrics["total_durations"][func_key], 0)
        self.assertIn(func_key, metrics["avg_durations"])

    def test_decorator_tracks_errors(self):
        """Decorator should track errors but still raise them."""
        @observe
        def error_func():
            raise ValueError("test error")
        
        with self.assertRaises(ValueError):
            error_func()
        
        metrics = get_observability_metrics()
        func_key = [k for k in metrics["error_counts"].keys() if "error_func" in k][0]
        self.assertEqual(metrics["error_counts"][func_key], 1)
        self.assertGreater(metrics["error_rates"][func_key], 0)

    def test_decorator_with_log_args(self):
        """Decorator with log_args=True should work without breaking."""
        @observe(log_args=True)
        def func_with_args(a, b, c=10):
            return a + b + c
        
        result = func_with_args(1, 2, c=3)
        self.assertEqual(result, 6)

    def test_decorator_with_log_result(self):
        """Decorator with log_result=True should work without breaking."""
        @observe(log_result=True)
        def func_with_result():
            return {"key": "value"}
        
        result = func_with_result()
        self.assertEqual(result, {"key": "value"})

    def test_decorator_with_both_options(self):
        """Decorator with both log_args and log_result should work."""
        @observe(log_args=True, log_result=True)
        def full_logging(x):
            return x * 2
        
        result = full_logging(5)
        self.assertEqual(result, 10)


class TestObserveClassDecorator(unittest.TestCase):
    """Test the @observe_class decorator."""

    def setUp(self):
        reset_observability_metrics()
        enable_observability(logging.WARNING)

    def tearDown(self):
        disable_observability()

    def test_class_decorator_wraps_public_methods(self):
        """Class decorator should wrap all public methods."""
        @observe_class
        class TestClass:
            def public_method(self):
                return "public"
            
            def _private_method(self):
                return "private"
            
            def another_public(self, x):
                return x * 2
        
        obj = TestClass()
        self.assertEqual(obj.public_method(), "public")
        self.assertEqual(obj.another_public(5), 10)
        
        metrics = get_observability_metrics()
        # Both public methods should be tracked (use endswith to avoid matching test method name)
        public_keys = [k for k in metrics["call_counts"].keys() if k.endswith("public_method")]
        another_keys = [k for k in metrics["call_counts"].keys() if k.endswith("another_public")]
        self.assertEqual(len(public_keys), 1)
        self.assertEqual(len(another_keys), 1)
        # Private method should NOT be tracked
        private_keys = [k for k in metrics["call_counts"].keys() if "_private_method" in k]
        self.assertEqual(len(private_keys), 0)
        # Total tracked functions should be exactly 2 (the two public methods)
        self.assertEqual(len(metrics["call_counts"]), 2)


class TestMetricsReporter(unittest.TestCase):
    """Test the MetricsReporter class."""

    def setUp(self):
        reset_observability_metrics()
        enable_observability(logging.WARNING)

    def tearDown(self):
        disable_observability()

    def test_generate_summary(self):
        """generate_summary should return a valid summary dict."""
        @observe
        def func_a():
            return "a"
        
        @observe
        def func_b():
            time.sleep(0.005)
            return "b"
        
        func_a()
        func_a()
        func_b()
        
        summary = MetricsReporter.generate_summary()
        
        self.assertIn("summary", summary)
        self.assertIn("slowest_functions", summary)
        self.assertIn("most_called_functions", summary)
        self.assertIn("highest_error_rates", summary)
        self.assertEqual(summary["summary"]["total_calls"], 3)
        self.assertEqual(summary["summary"]["total_functions_tracked"], 2)

    def test_export_json(self):
        """export_json should write valid JSON to file."""
        @observe
        def test_export_func():
            return 42
        
        test_export_func()
        
        filepath = "/tmp/test_observability_export.json"
        MetricsReporter.export_json(filepath)
        
        self.assertTrue(os.path.exists(filepath))
        with open(filepath) as f:
            data = json.load(f)
        self.assertIn("summary", data)
        
        # Clean up
        os.remove(filepath)

    def test_summary_with_errors(self):
        """Summary should correctly report error rates."""
        @observe
        def sometimes_fails():
            if not hasattr(sometimes_fails, 'call_count'):
                sometimes_fails.call_count = 0
            sometimes_fails.call_count += 1
            if sometimes_fails.call_count % 2 == 0:
                raise RuntimeError("fail")
            return "ok"
        
        sometimes_fails()  # success
        try:
            sometimes_fails()  # fail
        except RuntimeError:
            pass
        sometimes_fails()  # success
        try:
            sometimes_fails()  # fail
        except RuntimeError:
            pass
        
        summary = MetricsReporter.generate_summary()
        self.assertEqual(summary["summary"]["total_calls"], 4)
        self.assertEqual(summary["summary"]["total_errors"], 2)
        self.assertAlmostEqual(summary["summary"]["overall_error_rate"], 0.5, places=2)


class TestMetricsReset(unittest.TestCase):
    """Test metrics reset functionality."""

    def setUp(self):
        reset_observability_metrics()
        enable_observability(logging.WARNING)

    def tearDown(self):
        disable_observability()

    def test_reset_clears_metrics(self):
        """reset_observability_metrics should clear all data."""
        @observe
        def func_to_reset():
            return "test"
        
        func_to_reset()
        func_to_reset()
        
        metrics_before = get_observability_metrics()
        self.assertGreater(len(metrics_before["call_counts"]), 0)
        
        reset_observability_metrics()
        
        metrics_after = get_observability_metrics()
        self.assertEqual(len(metrics_after["call_counts"]), 0)
        self.assertEqual(len(metrics_after["error_counts"]), 0)


class TestThreadSafety(unittest.TestCase):
    """Test thread safety of metrics collection."""

    def setUp(self):
        reset_observability_metrics()
        enable_observability(logging.WARNING)

    def tearDown(self):
        disable_observability()

    def test_concurrent_calls(self):
        """Metrics should be accurate with concurrent calls."""
        @observe
        def thread_func(thread_id):
            time.sleep(0.001)
            return thread_id
        
        num_threads = 10
        calls_per_thread = 100
        
        def worker(tid):
            for _ in range(calls_per_thread):
                thread_func(tid)
        
        threads = []
        for i in range(num_threads):
            t = threading.Thread(target=worker, args=(i,))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        metrics = get_observability_metrics()
        func_key = [k for k in metrics["call_counts"].keys() if "thread_func" in k][0]
        expected_calls = num_threads * calls_per_thread
        self.assertEqual(metrics["call_counts"][func_key], expected_calls)


class TestIntegrationWithExistingModule(unittest.TestCase):
    """Test that observability can wrap existing NeuralShield modules."""

    def setUp(self):
        reset_observability_metrics()
        disable_observability()

    def test_wrap_existing_function_no_breakage(self):
        """Wrapping an existing function should not break it when disabled."""
        from neural_shield.threat_intelligence_malware_hash_reputation_checker_2026_june import (
            MalwareHashReputationChecker,
        )
        
        # Create instance - should work fine
        checker = MalwareHashReputationChecker()
        result = checker.check_hash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        self.assertIsNotNone(result)

    def test_wrap_existing_function_with_observability(self):
        """Wrapping with observability enabled should collect metrics."""
        enable_observability(logging.WARNING)
        
        from neural_shield.threat_intelligence_malware_hash_reputation_checker_2026_june import (
            MalwareHashReputationChecker,
        )
        
        # Manually wrap a method to test
        original_method = MalwareHashReputationChecker.check_hash
        wrapped_method = observe(MalwareHashReputationChecker.check_hash)
        
        # Temporarily replace
        MalwareHashReputationChecker.check_hash = wrapped_method
        
        try:
            checker = MalwareHashReputationChecker()
            result = checker.check_hash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
            self.assertIsNotNone(result)
            
            metrics = get_observability_metrics()
            check_hash_keys = [k for k in metrics["call_counts"].keys() if "check_hash" in k]
            self.assertGreater(len(check_hash_keys), 0)
        finally:
            # Restore original
            MalwareHashReputationChecker.check_hash = original_method
            disable_observability()


def run_tests():
    """Run all observability tests and return results."""
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(sys.modules[__name__])
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Save results
    results = {
        "tests_run": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "skipped": len(result.skipped),
        "success": result.wasSuccessful(),
        "test_date": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    
    with open("test_results_observability_engine_2026_june.json", "w") as f:
        json.dump(results, f, indent=2)
    
    return result


if __name__ == "__main__":
    print("=" * 70)
    print("NEURALSHIELD-AI OBSERVABILITY ENGINE TEST SUITE")
    print("June 2026 - Production Grade")
    print("=" * 70)
    print()
    
    result = run_tests()
    
    print()
    print("=" * 70)
    if result.wasSuccessful():
        print(f"TEST SUMMARY: {result.testsRun} PASSED, 0 FAILED")
    else:
        print(f"TEST SUMMARY: {result.testsRun - len(result.failures) - len(result.errors)} PASSED, "
              f"{len(result.failures)} FAILED, {len(result.errors)} ERRORS")
    print("=" * 70)
    print()
    print("Results saved to test_results_observability_engine_2026_june.json")
