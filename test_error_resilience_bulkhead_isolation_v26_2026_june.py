"""
Test Suite for NeuralShield Error Resilience - Bulkhead Isolation v26
Dimension E: Error Resilience - ADD-ONLY implementation

Tests verify:
1. Bulkhead compartment basic functionality
2. Isolation between compartments
3. Circuit breaker / trip functionality
4. Fallback mechanisms
5. Metrics collection
6. Thread safety

All tests are ADD-ONLY - no modification to existing tests
"""

import unittest
import time
import threading
import sys
import os

# Add source directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from error_resilience_bulkhead_isolation_model_inference_v26_2026_june import (
    BulkheadCompartment,
    BulkheadConfig,
    BulkheadState,
    BulkheadTrippedError,
    ModelInferenceBulkheadManager,
    get_model_bulkhead_manager,
    bulkheaded_inference,
    safe_empty_fallback,
    safe_deny_fallback
)


class TestBulkheadConfig(unittest.TestCase):
    """Test bulkhead configuration"""

    def test_default_config(self):
        """Test default configuration values"""
        config = BulkheadConfig()
        self.assertEqual(config.max_concurrent_requests, 10)
        self.assertEqual(config.max_queue_size, 100)
        self.assertEqual(config.request_timeout_seconds, 30.0)
        self.assertEqual(config.failure_threshold, 5)

    def test_custom_config(self):
        """Test custom configuration"""
        config = BulkheadConfig(
            max_concurrent_requests=5,
            request_timeout_seconds=10.0
        )
        self.assertEqual(config.max_concurrent_requests, 5)
        self.assertEqual(config.request_timeout_seconds, 10.0)


class TestBulkheadCompartment(unittest.TestCase):
    """Test bulkhead compartment functionality"""

    def setUp(self):
        self.bulkhead = BulkheadCompartment(
            name="test",
            config=BulkheadConfig(max_concurrent_requests=2)
        )

    def tearDown(self):
        self.bulkhead.shutdown()

    def test_successful_execution(self):
        """Test successful function execution"""
        def success_func(x):
            return x * 2

        result = self.bulkhead.execute(success_func, 5)
        self.assertEqual(result, 10)

    def test_metrics_on_success(self):
        """Test metrics update on successful execution"""
        def success_func(x):
            return x

        self.bulkhead.execute(success_func, "test")
        metrics = self.bulkhead.get_metrics()
        
        self.assertEqual(metrics["completed_requests"], 1)
        self.assertEqual(metrics["failed_requests"], 0)
        self.assertEqual(metrics["state"], "healthy")

    def test_exception_propagation(self):
        """Test that exceptions propagate correctly"""
        def failing_func(x):
            raise ValueError("Test error")

        with self.assertRaises(ValueError):
            self.bulkhead.execute(failing_func, None)

    def test_metrics_on_failure(self):
        """Test metrics update on failure"""
        def failing_func(x):
            raise ValueError("Test error")

        try:
            self.bulkhead.execute(failing_func, None)
        except ValueError:
            pass

        metrics = self.bulkhead.get_metrics()
        self.assertEqual(metrics["failed_requests"], 1)

    def test_fallback_on_failure(self):
        """Test fallback function on failure"""
        def failing_func(x):
            raise ValueError("Test error")

        def fallback(e):
            return {"fallback": True, "error": str(e)}

        result = self.bulkhead.execute(failing_func, None, fallback)
        self.assertTrue(result["fallback"])
        self.assertIn("Test error", result["error"])

    def test_timeout_execution(self):
        """Test execution timeout"""
        config = BulkheadConfig(
            max_concurrent_requests=2,
            request_timeout_seconds=0.1
        )
        bulkhead = BulkheadCompartment(name="timeout_test", config=config)
        
        def slow_func(x):
            time.sleep(1.0)
            return x

        with self.assertRaises(Exception):  # TimeoutError or wrapped
            bulkhead.execute(slow_func, None)
        
        bulkhead.shutdown()

    def test_reset(self):
        """Test bulkhead reset functionality"""
        def failing_func(x):
            raise ValueError("Test error")

        for _ in range(3):
            try:
                self.bulkhead.execute(failing_func, None)
            except ValueError:
                pass

        metrics_before = self.bulkhead.get_metrics()
        self.assertGreater(metrics_before["failed_requests"], 0)
        
        self.bulkhead.reset()
        
        metrics_after = self.bulkhead.get_metrics()
        self.assertEqual(metrics_after["failed_requests"], 0)
        self.assertEqual(metrics_after["state"], "healthy")


class TestBulkheadCircuitBreaker(unittest.TestCase):
    """Test bulkhead circuit breaker functionality"""

    def test_circuit_breaker_trip(self):
        """Test that circuit breaker trips after threshold failures"""
        config = BulkheadConfig(
            max_concurrent_requests=2,
            failure_threshold=3,
            failure_window_seconds=60.0,
            recovery_timeout_seconds=1.0
        )
        bulkhead = BulkheadCompartment(name="circuit_test", config=config)

        def failing_func(x):
            raise ValueError("Controlled failure")

        # Trigger failures
        for i in range(3):
            try:
                bulkhead.execute(failing_func, None)
            except ValueError:
                pass

        # Now circuit should be tripped
        with self.assertRaises(BulkheadTrippedError):
            bulkhead.execute(failing_func, None)

        metrics = bulkhead.get_metrics()
        self.assertEqual(metrics["state"], "tripped")
        self.assertTrue(metrics["tripped"])
        
        bulkhead.shutdown()

    def test_fallback_when_tripped(self):
        """Test fallback works when circuit is tripped"""
        config = BulkheadConfig(
            max_concurrent_requests=2,
            failure_threshold=2,
            recovery_timeout_seconds=1.0
        )
        bulkhead = BulkheadCompartment(name="fallback_test", config=config)

        def failing_func(x):
            raise ValueError("Failure")

        def fallback(e):
            return {"safe": True, "fallback_used": True}

        # Trigger trip
        for _ in range(2):
            try:
                bulkhead.execute(failing_func, None)
            except ValueError:
                pass

        # Should use fallback now
        result = bulkhead.execute(failing_func, None, fallback)
        self.assertTrue(result["fallback_used"])
        self.assertTrue(result["safe"])
        
        bulkhead.shutdown()

    def test_circuit_recovery(self):
        """Test circuit recovers after timeout"""
        config = BulkheadConfig(
            max_concurrent_requests=2,
            failure_threshold=2,
            failure_window_seconds=60.0,
            recovery_timeout_seconds=0.2
        )
        bulkhead = BulkheadCompartment(name="recovery_test", config=config)

        def failing_func(x):
            raise ValueError("Failure")

        # Trigger trip
        for _ in range(2):
            try:
                bulkhead.execute(failing_func, None)
            except ValueError:
                pass

        # Verify tripped
        metrics = bulkhead.get_metrics()
        self.assertEqual(metrics["state"], "tripped")

        # Wait for recovery
        time.sleep(0.3)

        # Should be recovered now
        metrics = bulkhead.get_metrics()
        self.assertEqual(metrics["state"], "healthy")
        
        bulkhead.shutdown()


class TestBulkheadIsolation(unittest.TestCase):
    """Test that bulkheads are properly isolated"""

    def test_separate_compartments(self):
        """Test failures in one compartment don't affect others"""
        bulkhead1 = BulkheadCompartment(
            name="compartment1",
            config=BulkheadConfig(failure_threshold=2, recovery_timeout_seconds=10)
        )
        bulkhead2 = BulkheadCompartment(
            name="compartment2",
            config=BulkheadConfig(failure_threshold=10)
        )

        def failing_func(x):
            raise ValueError("Failure")

        def success_func(x):
            return x

        # Trip compartment 1
        for _ in range(2):
            try:
                bulkhead1.execute(failing_func, None)
            except ValueError:
                pass

        # Compartment 1 should be tripped
        self.assertEqual(bulkhead1.get_metrics()["state"], "tripped")
        
        # Compartment 2 should still be healthy
        self.assertEqual(bulkhead2.get_metrics()["state"], "healthy")
        
        # Compartment 2 should still work
        result = bulkhead2.execute(success_func, 42)
        self.assertEqual(result, 42)

        bulkhead1.shutdown()
        bulkhead2.shutdown()


class TestModelInferenceBulkheadManager(unittest.TestCase):
    """Test the bulkhead manager for model inference"""

    def setUp(self):
        self.manager = ModelInferenceBulkheadManager()

    def tearDown(self):
        self.manager.shutdown_all()

    def test_category_isolation(self):
        """Test different categories get different bulkheads"""
        def inference(x):
            return {"result": x}

        result1 = self.manager.execute_inference(
            "prompt_injection", inference, "test1"
        )
        result2 = self.manager.execute_inference(
            "jailbreak_detection", inference, "test2"
        )

        self.assertEqual(result1["result"], "test1")
        self.assertEqual(result2["result"], "test2")

        metrics = self.manager.get_all_metrics()
        self.assertIn("prompt_injection", metrics)
        self.assertIn("jailbreak_detection", metrics)

    def test_health_summary(self):
        """Test health summary generation"""
        def inference(x):
            return x

        self.manager.execute_inference("prompt_injection", inference, "test")
        
        health = self.manager.get_health_summary()
        self.assertIn("overall_health", health)
        self.assertIn("total_bulkheads", health)
        self.assertGreaterEqual(health["total_bulkheads"], 1)

    def test_unknown_category_uses_default(self):
        """Test unknown categories use default config"""
        def inference(x):
            return x

        result = self.manager.execute_inference(
            "unknown_category_12345", inference, "test"
        )
        self.assertEqual(result, "test")

        metrics = self.manager.get_all_metrics()
        self.assertIn("unknown_category_12345", metrics)


class TestBulkheadDecorator(unittest.TestCase):
    """Test the bulkhead decorator"""

    @classmethod
    def setUpClass(cls):
        # Clear any existing manager
        mgr = get_model_bulkhead_manager()
        mgr.shutdown_all()

    def test_decorator_basic(self):
        """Test basic decorator functionality"""
        @bulkheaded_inference("prompt_injection")
        def my_inference(data):
            return {"processed": data, "success": True}

        result = my_inference("test_input")
        self.assertTrue(result["success"])
        self.assertEqual(result["processed"], "test_input")

    def test_decorator_with_fallback(self):
        """Test decorator with fallback function"""
        def my_fallback(e):
            return {"fallback": True, "error": str(e)}

        @bulkheaded_inference("jailbreak_detection", fallback=my_fallback)
        def failing_inference(data):
            raise ValueError("Inference failed")

        result = failing_inference("test")
        self.assertTrue(result["fallback"])


class TestFallbackFunctions(unittest.TestCase):
    """Test built-in fallback functions"""

    def test_safe_empty_fallback(self):
        """Test safe empty fallback"""
        error = ValueError("Test error")
        result = safe_empty_fallback(error)
        
        self.assertTrue(result["safe"])
        self.assertEqual(result["risk_score"], 0.0)
        self.assertTrue(result["bulkhead_protection"])

    def test_safe_deny_fallback(self):
        """Test safe deny fallback"""
        error = ValueError("Test error")
        result = safe_deny_fallback(error)
        
        self.assertFalse(result["safe"])
        self.assertEqual(result["risk_score"], 1.0)
        self.assertEqual(result["action"], "block")
        self.assertTrue(result["bulkhead_protection"])


class TestThreadSafety(unittest.TestCase):
    """Test thread safety of bulkhead operations"""

    def test_concurrent_executions(self):
        """Test multiple threads can use bulkhead safely"""
        bulkhead = BulkheadCompartment(
            name="thread_test",
            config=BulkheadConfig(max_concurrent_requests=4)
        )

        def worker(x):
            time.sleep(0.01)
            return x * 2

        results = []
        threads = []
        
        for i in range(10):
            t = threading.Thread(
                target=lambda: results.append(bulkhead.execute(worker, i))
            )
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        self.assertEqual(len(results), 10)
        self.assertIn(0, results)  # 0 * 2
        self.assertIn(18, results)  # 9 * 2
        
        bulkhead.shutdown()


def run_tests():
    """Run all tests"""
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(sys.modules[__name__])
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
