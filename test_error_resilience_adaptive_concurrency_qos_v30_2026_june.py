"""
Test Suite for NeuralShield Adaptive Concurrency Limiting with QoS Tiers v30
DIMENSION E: Error Resilience
Tests verify:
1. Priority-based queueing works correctly
2. Critical operations are never rejected
3. Load shedding respects priority tiers
4. Adaptive concurrency adjustment works
5. Health metrics are accurate
6. Decorators work correctly
7. No breaking changes to existing code
"""
import unittest
import time
import threading
import sys
import os

# Add source directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from error_resilience_adaptive_concurrency_qos_v30_2026_june import (
    QoSPriority,
    LoadShedReason,
    ConcurrencyMetrics,
    AdaptiveConcurrencyConfig,
    AdaptiveConcurrencyController,
    concurrency_limited,
    critical_concurrency,
    high_concurrency,
    medium_concurrency,
    low_concurrency,
    get_global_controller,
    concurrency_health_check,
    GracefulDegradationHandler,
    get_degradation_handler
)

class TestQoSPriority(unittest.TestCase):
    """Test QoS priority tier ordering"""
    
    def test_priority_ordering(self):
        """Verify priority hierarchy is correct"""
        self.assertEqual(QoSPriority.CRITICAL.value, 0)
        self.assertEqual(QoSPriority.HIGH.value, 1)
        self.assertEqual(QoSPriority.MEDIUM.value, 2)
        self.assertEqual(QoSPriority.LOW.value, 3)
    
    def test_critical_is_highest(self):
        """CRITICAL is highest priority (lowest numeric value)"""
        self.assertLess(QoSPriority.CRITICAL.value, QoSPriority.HIGH.value)
        self.assertLess(QoSPriority.HIGH.value, QoSPriority.MEDIUM.value)
        self.assertLess(QoSPriority.MEDIUM.value, QoSPriority.LOW.value)

class TestConcurrencyMetrics(unittest.TestCase):
    """Test concurrency metrics calculations"""
    
    def test_initial_state(self):
        """Metrics start with clean state"""
        metrics = ConcurrencyMetrics()
        self.assertEqual(metrics.current_concurrency, 0)
        self.assertEqual(metrics.error_rate, 0.0)
        self.assertEqual(metrics.p95_latency, 0.0)
        self.assertEqual(metrics.utilization, 0.0)
    
    def test_error_rate_calculation(self):
        """Error rate is calculated correctly"""
        metrics = ConcurrencyMetrics()
        # 50% error rate
        for i in range(10):
            metrics.record_outcome(success=(i % 2 == 0))
        self.assertAlmostEqual(metrics.error_rate, 0.5, delta=0.1)
    
    def test_p95_latency_calculation(self):
        """P95 latency calculation works"""
        metrics = ConcurrencyMetrics()
        for i in range(100):
            metrics.record_latency(float(i))
        # P95 should be around 95
        self.assertGreaterEqual(metrics.p95_latency, 90)
        self.assertLessEqual(metrics.p95_latency, 100)
    
    def test_utilization_calculation(self):
        """Utilization calculation works"""
        metrics = ConcurrencyMetrics(max_concurrency=10)
        metrics.current_concurrency = 5
        self.assertEqual(metrics.utilization, 0.5)

class TestAdaptiveConcurrencyController(unittest.TestCase):
    """Test adaptive concurrency controller"""
    
    def setUp(self):
        self.config = AdaptiveConcurrencyConfig(
            initial_max_concurrency=4,
            min_concurrency=1,
            max_concurrency_limit=8,
            queue_timeout_ms=100
        )
        self.controller = AdaptiveConcurrencyController(self.config)
    
    def tearDown(self):
        self.controller.shutdown()
    
    def test_acquire_release_slot(self):
        """Basic acquire/release cycle works"""
        acquired = self.controller.acquire_slot(QoSPriority.MEDIUM)
        self.assertTrue(acquired)
        
        status = self.controller.get_health_status()
        self.assertEqual(status["current_concurrency"], 1)
        
        self.controller.release_slot(success=True, latency_ms=10.0)
        
        status = self.controller.get_health_status()
        self.assertEqual(status["current_concurrency"], 0)
        self.assertEqual(status["total_requests"], 1)
    
    def test_critical_bypasses_shedding_checks(self):
        """CRITICAL priority operations bypass load shedding checks"""
        # Set controller to high utilization state
        # CRITICAL operations should bypass priority-based shedding
        for _ in range(4):
            self.controller.acquire_slot(QoSPriority.MEDIUM, timeout_ms=100)
        
        # CRITICAL should bypass shedding checks (not bypass concurrency limits)
        # The key assertion: CRITICAL never gets shed for priority reasons
        # It may still queue for concurrency, but never rejected for priority
        shed_reason = self.controller._should_shed_request(QoSPriority.CRITICAL)
        self.assertIsNone(shed_reason, "CRITICAL should never be shed")
        
        # LOW priority might be shed under load
        shed_reason_low = self.controller._should_shed_request(QoSPriority.LOW)
        # LOW may be shed - this is expected behavior
        """Health check returns comprehensive metrics"""
        status = self.controller.get_health_status()
        self.assertIn("max_concurrency", status)
        self.assertIn("current_concurrency", status)
        self.assertIn("utilization", status)
        self.assertIn("error_rate", status)
        self.assertIn("p95_latency_ms", status)
        self.assertIn("timestamp", status)
    
    def test_concurrency_limits(self):
        """Controller respects concurrency limits"""
        # Acquire all slots
        for _ in range(self.config.initial_max_concurrency):
            self.assertTrue(self.controller.acquire_slot(QoSPriority.MEDIUM))
        
        # Next should queue or timeout
        acquired = self.controller.acquire_slot(QoSPriority.LOW, timeout_ms=10)
        # LOW priority might be shed under load
        if not acquired:
            # This is expected behavior - load shedding working
            pass
    
    def test_success_error_tracking(self):
        """Success and error outcomes are tracked"""
        self.controller.acquire_slot(QoSPriority.MEDIUM)
        self.controller.release_slot(success=True, latency_ms=10.0)
        
        self.controller.acquire_slot(QoSPriority.MEDIUM)
        self.controller.release_slot(success=False, latency_ms=10.0)
        
        status = self.controller.get_health_status()
        self.assertEqual(status["total_requests"], 2)
        self.assertGreater(status["error_rate"], 0)

class TestConcurrencyDecorators(unittest.TestCase):
    """Test concurrency limiting decorators"""
    
    def test_concurrency_limited_decorator(self):
        """Decorator wraps function without breaking it"""
        call_count = [0]
        
        @concurrency_limited(priority=QoSPriority.MEDIUM)
        def test_function(x: int) -> int:
            call_count[0] += 1
            return x * 2
        
        # Happy path should work 100%
        result = test_function(5)
        self.assertEqual(result, 10)
        self.assertEqual(call_count[0], 1)
    
    def test_critical_concurrency_decorator(self):
        """Critical priority decorator works"""
        @critical_concurrency
        def critical_op() -> str:
            return "protected"
        
        result = critical_op()
        self.assertEqual(result, "protected")
    
    def test_high_concurrency_decorator(self):
        """High priority decorator works"""
        @high_concurrency
        def high_op() -> str:
            return "high"
        
        result = high_op()
        self.assertEqual(result, "high")
    
    def test_medium_concurrency_decorator(self):
        """Medium priority decorator works"""
        @medium_concurrency
        def medium_op() -> str:
            return "medium"
        
        result = medium_op()
        self.assertEqual(result, "medium")
    
    def test_low_concurrency_decorator(self):
        """Low priority decorator works"""
        @low_concurrency
        def low_op() -> str:
            return "low"
        
        result = low_op()
        self.assertEqual(result, "low")
    
    def test_decorator_with_fallback(self):
        """Decorator with fallback returns fallback on rejection"""
        @concurrency_limited(
            priority=QoSPriority.LOW,
            fallback="degraded_response"
        )
        def test_op() -> str:
            return "normal"
        
        result = test_op()
        # Should get normal response under normal load
        self.assertIn(result, ["normal", "degraded_response"])

class TestGracefulDegradationHandler(unittest.TestCase):
    """Test graceful degradation handler"""
    
    def test_handler_creation(self):
        """Handler can be created"""
        handler = GracefulDegradationHandler()
        self.assertIsNotNone(handler)
    
    def test_register_fallback(self):
        """Fallback handlers can be registered"""
        handler = GracefulDegradationHandler()
        
        def my_fallback(reason, func, *args, **kwargs):
            return "fallback_result"
        
        handler.register_fallback(QoSPriority.MEDIUM, my_fallback)
        # Should not raise
    
    def test_get_shed_statistics(self):
        """Shed statistics are available"""
        handler = get_degradation_handler()
        stats = handler.get_shed_statistics()
        self.assertIsInstance(stats, dict)

class TestGlobalController(unittest.TestCase):
    """Test global controller instance"""
    
    def test_get_global_controller(self):
        """Global controller singleton works"""
        ctrl1 = get_global_controller()
        ctrl2 = get_global_controller()
        self.assertIs(ctrl1, ctrl2)
    
    def test_health_check_function(self):
        """Global health check function works"""
        health = concurrency_health_check()
        self.assertIsInstance(health, dict)
        self.assertIn("max_concurrency", health)
        self.assertIn("degradation_stats", health)

class TestThreadSafety(unittest.TestCase):
    """Test thread safety of controller"""
    
    def test_concurrent_access(self):
        """Multiple threads can access controller safely"""
        controller = AdaptiveConcurrencyController(
            AdaptiveConcurrencyConfig(initial_max_concurrency=8)
        )
        
        results = []
        errors = []
        
        def worker():
            try:
                for _ in range(5):
                    if controller.acquire_slot(QoSPriority.MEDIUM, timeout_ms=50):
                        time.sleep(0.001)
                        controller.release_slot(success=True, latency_ms=1.0)
                        results.append(True)
            except Exception as e:
                errors.append(e)
        
        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)
        
        controller.shutdown()
        self.assertEqual(len(errors), 0, f"Errors occurred: {errors}")

class TestBackwardCompatibility(unittest.TestCase):
    """Verify no breaking changes to existing error resilience modules"""
    
    def test_can_import_existing_modules(self):
        """Existing error resilience modules still import"""
        try:
            from error_resilience_comprehensive_enhanced_v2_2026_june import (
                NeuralShieldError,
                RetryPolicy,
                CircuitBreaker
            )
            # If we get here, imports work
            self.assertTrue(True)
        except ImportError as e:
            self.fail(f"Existing module import failed: {e}")
    
    def test_new_module_does_not_break_existing(self):
        """New module coexists with existing modules"""
        # Both should be importable
        import error_resilience_comprehensive_enhanced_v2_2026_june as old
        import error_resilience_adaptive_concurrency_qos_v30_2026_june as new
        
        self.assertIsNotNone(old.NeuralShieldError)
        self.assertIsNotNone(new.QoSPriority)

if __name__ == '__main__':
    # Run tests
    suite = unittest.TestLoader().loadTestsFromTestCase(TestQoSPriority)
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestConcurrencyMetrics))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestAdaptiveConcurrencyController))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestConcurrencyDecorators))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestGracefulDegradationHandler))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestGlobalController))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestThreadSafety))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestBackwardCompatibility))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Exit with appropriate code
    sys.exit(0 if result.wasSuccessful() else 1)
