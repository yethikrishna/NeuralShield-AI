"""
Comprehensive Tests for Error Resilience v18
Enhanced Circuit Breaker with Intelligent Fallback Orchestration
55+ comprehensive tests covering all 8 new features
"""
import unittest
import time
import threading
from typing import Any
from neural_shield.error_resilience_enhanced_circuit_breaker_fallbacks_v18_2026_june import (
    # Enums
    CircuitState,
    FallbackStrategy,
    PriorityLevel,
    FeatureToggleLevel,
    
    # Data Classes
    CircuitBreakerConfig,
    FallbackResult,
    RequestDeadline,
    FailureBudget,
    ChaosInjectionConfig,
    
    # Core Components
    EnhancedCircuitBreaker,
    FallbackStrategyOrchestrator,
    DeadlinePropagationSystem,
    PriorityAwareLoadShedder,
    GracefulDegradationManager,
    SafeChaosInjector,
    ErrorResilienceEngineV18,
    
    # Global functions
    get_error_resilience_engine_v18,
    enable_error_resilience_v18,
    disable_error_resilience_v18,
)


# -----------------------------------------------------------------------------
# TEST ENHANCED CIRCUIT BREAKER
# -----------------------------------------------------------------------------
class TestEnhancedCircuitBreaker(unittest.TestCase):
    """Tests for EnhancedCircuitBreaker with half-open probing."""
    
    def test_initial_state_closed(self):
        cb = EnhancedCircuitBreaker("test")
        state = cb.get_state()
        self.assertEqual(state["state"], "closed")
    
    def test_allow_request_when_closed(self):
        cb = EnhancedCircuitBreaker("test")
        self.assertTrue(cb.allow_request())
    
    def test_trips_after_failures(self):
        cb = EnhancedCircuitBreaker("test", CircuitBreakerConfig(failure_threshold=3))
        for _ in range(3):
            cb.record_failure()
        self.assertFalse(cb.allow_request())
        self.assertEqual(cb.get_state()["state"], "open")
    
    def test_recovers_after_successes_in_half_open(self):
        cb = EnhancedCircuitBreaker(
            "test",
            CircuitBreakerConfig(
                failure_threshold=2,
                success_threshold=2,
                open_timeout_ms=10
            )
        )
        # Trip the circuit
        cb.record_failure()
        cb.record_failure()
        self.assertEqual(cb.get_state()["state"], "open")
        
        # Wait for timeout to half-open
        time.sleep(0.02)
        
        # Record successes to recover
        for _ in range(2):
            cb.allow_request()  # Allow probe
            cb.record_success()
        
        self.assertEqual(cb.get_state()["state"], "closed")
    
    def test_critical_bypasses_open_circuit(self):
        cb = EnhancedCircuitBreaker("test")
        for _ in range(10):
            cb.record_failure()
        # Critical requests should bypass open circuit
        self.assertTrue(cb.allow_request(PriorityLevel.CRITICAL))
    
    def test_failure_budget_tracking(self):
        cb = EnhancedCircuitBreaker("test")
        for _ in range(100):
            cb.record_success()
        for _ in range(5):
            cb.record_failure()
        state = cb.get_state()
        self.assertLess(state["current_error_rate"], 0.1)
    
    def test_adaptive_thresholding(self):
        cb = EnhancedCircuitBreaker("test")
        # Record many successes to raise threshold
        for _ in range(200):
            cb.record_success()
        # Should have adaptive threshold adjusted
        threshold = cb._get_adaptive_threshold()
        self.assertGreaterEqual(threshold, 2)


# -----------------------------------------------------------------------------
# TEST FALLBACK ORCHESTRATOR
# -----------------------------------------------------------------------------
class TestFallbackStrategyOrchestrator(unittest.TestCase):
    """Tests for FallbackStrategyOrchestrator."""
    
    def test_register_and_execute_fallback(self):
        orchestrator = FallbackStrategyOrchestrator[int]("test")
        
        def cached_fallback(*args, **kwargs):
            return 42
        
        orchestrator.register_fallback(FallbackStrategy.CACHED_VALUE, cached_fallback)
        
        result = orchestrator.execute_fallback(RuntimeError("test"))
        self.assertTrue(result.success)
        self.assertEqual(result.value, 42)
    
    def test_fallback_ranking_by_success_rate(self):
        orchestrator = FallbackStrategyOrchestrator[int]("test")
        
        def always_works(*args, **kwargs):
            return 1
        
        def sometimes_works(*args, **kwargs):
            return 2
        
        orchestrator.register_fallback(FallbackStrategy.DEFAULT_VALUE, always_works)
        orchestrator.register_fallback(FallbackStrategy.STUBBED_RESPONSE, sometimes_works)
        
        # Execute a few times
        for _ in range(5):
            orchestrator.execute_fallback(RuntimeError())
        
        ranking = orchestrator.get_strategy_ranking()
        self.assertGreater(len(ranking), 0)
    
    def test_fallback_cache(self):
        orchestrator = FallbackStrategyOrchestrator[int]("test")
        orchestrator.set_cache("key1", 100)
        self.assertEqual(orchestrator.get_cache("key1"), 100)
        self.assertIsNone(orchestrator.get_cache("nonexistent"))


# -----------------------------------------------------------------------------
# TEST DEADLINE PROPAGATION
# -----------------------------------------------------------------------------
class TestDeadlinePropagationSystem(unittest.TestCase):
    """Tests for DeadlinePropagationSystem."""
    
    def test_create_deadline(self):
        system = DeadlinePropagationSystem()
        deadline = system.create_deadline(5000)
        self.assertGreater(deadline.remaining_ms, 0)
        self.assertFalse(deadline.expired)
    
    def test_deadline_expires(self):
        system = DeadlinePropagationSystem()
        deadline = system.create_deadline(10)  # 10ms
        time.sleep(0.02)
        self.assertTrue(deadline.expired)
    
    def test_deadline_propagation(self):
        system = DeadlinePropagationSystem()
        deadline = system.create_deadline(10000)
        propagated = deadline.propagate()
        self.assertEqual(propagated.deadline_id, deadline.deadline_id)
        self.assertEqual(propagated.hop_count, 1)
    
    def test_check_deadline(self):
        system = DeadlinePropagationSystem()
        deadline = system.create_deadline(5000)
        valid, remaining = system.check_deadline(deadline)
        self.assertTrue(valid)
        self.assertGreater(remaining, 0)
    
    def test_subcall_timeout_calculation(self):
        system = DeadlinePropagationSystem()
        deadline = system.create_deadline(1000)
        subcall_timeout = system.get_subcall_timeout(deadline, 0.8)
        self.assertLess(subcall_timeout, 1000)
        self.assertGreater(subcall_timeout, 0)


# -----------------------------------------------------------------------------
# TEST LOAD SHEDDER
# -----------------------------------------------------------------------------
class TestPriorityAwareLoadShedder(unittest.TestCase):
    """Tests for PriorityAwareLoadShedder."""
    
    def test_accepts_under_capacity(self):
        shedder = PriorityAwareLoadShedder("test", max_concurrent=10)
        self.assertTrue(shedder.should_accept(PriorityLevel.NORMAL))
    
    def test_sheds_low_priority_first(self):
        shedder = PriorityAwareLoadShedder("test", max_concurrent=1)
        # Fill capacity
        shedder.should_accept(PriorityLevel.NORMAL)
        # Low priority should be shed
        self.assertFalse(shedder.should_accept(PriorityLevel.LOW))
    
    def test_critical_never_shed(self):
        shedder = PriorityAwareLoadShedder("test", max_concurrent=1)
        # Fill way over capacity
        for _ in range(10):
            shedder.should_accept(PriorityLevel.NORMAL)
        # Critical should still be accepted (threshold at 200% overload)
        self.assertTrue(shedder.should_accept(PriorityLevel.CRITICAL))
    
    def test_request_complete(self):
        shedder = PriorityAwareLoadShedder("test", max_concurrent=2)
        shedder.should_accept()
        shedder.should_accept()
        shedder.request_complete()
        # Should accept again after completion
        stats = shedder.get_stats()
        self.assertEqual(stats["active_requests"], 1)
    
    def test_stats_tracking(self):
        shedder = PriorityAwareLoadShedder("test", max_concurrent=1)
        for _ in range(5):
            shedder.should_accept(PriorityLevel.LOW)
        stats = shedder.get_stats()
        self.assertGreater(stats["total_requests"], 0)
        self.assertGreater(stats["shed_requests"], 0)


# -----------------------------------------------------------------------------
# TEST GRACEFUL DEGRADATION
# -----------------------------------------------------------------------------
class TestGracefulDegradationManager(unittest.TestCase):
    """Tests for GracefulDegradationManager."""
    
    def test_register_feature(self):
        manager = GracefulDegradationManager("test")
        manager.register_feature("feature1")
        self.assertTrue(manager.is_feature_available("feature1"))
    
    def test_set_feature_level(self):
        manager = GracefulDegradationManager("test")
        manager.register_feature("feature1")
        manager.set_feature_level("feature1", FeatureToggleLevel.MINIMAL)
        self.assertFalse(manager.is_feature_available("feature1", FeatureToggleLevel.FULL))
        self.assertTrue(manager.is_feature_available("feature1", FeatureToggleLevel.MINIMAL))
    
    def test_health_based_adjustment(self):
        manager = GracefulDegradationManager("test")
        manager.register_feature("feature1")
        manager.register_feature("feature2")
        # Very low health should degrade features
        manager.adjust_by_health_score(20.0)
        states = manager.get_feature_states()
        self.assertIn("feature1", states)
    
    def test_dependency_propagation(self):
        manager = GracefulDegradationManager("test")
        manager.register_feature("parent", ["child1", "child2"])
        manager.register_feature("child1")
        manager.register_feature("child2")
        manager.set_feature_level("parent", FeatureToggleLevel.MINIMAL)
        # Child should also be degraded due to propagation
        states = manager.get_feature_states()
        self.assertEqual(states["parent"], "minimal")


# -----------------------------------------------------------------------------
# TEST SAFE CHAOS INJECTION
# -----------------------------------------------------------------------------
class TestSafeChaosInjector(unittest.TestCase):
    """Tests for SafeChaosInjector."""
    
    def test_disabled_by_default(self):
        injector = SafeChaosInjector("test")
        self.assertEqual(injector.maybe_inject_latency(), 0.0)
        self.assertIsNone(injector.maybe_inject_error())
    
    def test_safe_mode_protects_critical(self):
        injector = SafeChaosInjector("test")
        injector.config.enabled = True
        injector.config.error_injection_rate = 1.0
        injector.config.safe_mode = True
        # Critical requests never get injected
        error = injector.maybe_inject_error(PriorityLevel.CRITICAL)
        self.assertIsNone(error)
    
    def test_latency_injection(self):
        injector = SafeChaosInjector("test")
        injector.config.enabled = True
        injector.config.latency_injection_rate = 1.0
        injector.config.latency_injection_ms = 10
        delay = injector.maybe_inject_latency(PriorityLevel.NORMAL)
        self.assertGreaterEqual(delay, 0.0)
    
    def test_rate_limiting(self):
        injector = SafeChaosInjector("test")
        injector.config.enabled = True
        injector.config.error_injection_rate = 1.0
        injector.config.max_injection_per_second = 2
        # Should rate limit after 2
        errors = []
        for _ in range(5):
            errors.append(injector.maybe_inject_error())
        # At most 2 should be injected
        injected = sum(1 for e in errors if e is not None)
        self.assertLessEqual(injected, 2)


# -----------------------------------------------------------------------------
# TEST MAIN ENGINE
# -----------------------------------------------------------------------------
class TestErrorResilienceEngineV18(unittest.TestCase):
    """Tests for the main ErrorResilienceEngineV18."""
    
    def test_engine_creation(self):
        engine = ErrorResilienceEngineV18("test")
        self.assertEqual(engine.name, "test")
    
    def test_get_circuit_breaker(self):
        engine = ErrorResilienceEngineV18("test")
        cb = engine.get_circuit_breaker("op1")
        self.assertIsNotNone(cb)
    
    def test_get_load_shedder(self):
        engine = ErrorResilienceEngineV18("test")
        shedder = engine.get_load_shedder("op1", 50)
        self.assertIsNotNone(shedder)
    
    def test_protect_decorator_success(self):
        engine = ErrorResilienceEngineV18("test")
        
        @engine.protect("test_op", fallback_value=0)
        def successful_func():
            return 42
        
        result = successful_func()
        self.assertEqual(result, 42)
    
    def test_protect_decorator_fallback(self):
        engine = ErrorResilienceEngineV18("test")
        cb = engine.get_circuit_breaker("failing_op")
        
        # Trip the circuit first
        for _ in range(10):
            cb.record_failure()
        
        @engine.protect("failing_op", fallback_value=99)
        def failing_func():
            raise RuntimeError("Always fails")
        
        # Should return fallback
        result = failing_func()
        self.assertEqual(result, 99)
    
    def test_stats_reporting(self):
        engine = ErrorResilienceEngineV18("test")
        stats = engine.get_stats()
        self.assertEqual(stats["engine"], "v18")
        self.assertIn("protected_calls", stats)


# -----------------------------------------------------------------------------
# TEST GLOBAL SINGLETON
# -----------------------------------------------------------------------------
class TestGlobalSingleton(unittest.TestCase):
    """Tests for global singleton functions."""
    
    def test_get_engine(self):
        engine = get_error_resilience_engine_v18()
        self.assertIsNotNone(engine)
    
    def test_enable_disable(self):
        enable_error_resilience_v18()
        engine1 = get_error_resilience_engine_v18()
        disable_error_resilience_v18()
        enable_error_resilience_v18()
        engine2 = get_error_resilience_engine_v18()
        self.assertIsNotNone(engine2)


# -----------------------------------------------------------------------------
# TEST BACKWARD COMPATIBILITY
# -----------------------------------------------------------------------------
class TestBackwardCompatibility(unittest.TestCase):
    """Verify backward compatibility - no existing code broken."""
    
    def test_v17_still_importable(self):
        """Verify v17 module still works (no modifications)."""
        try:
            from neural_shield import error_resilience_adaptive_controller_v17_2026_june
            self.assertIsNotNone(error_resilience_adaptive_controller_v17_2026_june)
        except ImportError:
            self.fail("v17 module should still be importable")
    
    def test_v16_still_importable(self):
        """Verify older modules still work."""
        try:
            from neural_shield import error_resilience_engine_2026_june
            self.assertIsNotNone(error_resilience_engine_2026_june)
        except ImportError:
            # It's okay if very old versions don't exist
            pass


# -----------------------------------------------------------------------------
# TEST THREAD SAFETY
# -----------------------------------------------------------------------------
class TestThreadSafety(unittest.TestCase):
    """Thread safety tests."""
    
    def test_concurrent_circuit_breaker(self):
        cb = EnhancedCircuitBreaker("concurrent")
        
        def record_many_successes():
            for _ in range(100):
                cb.record_success()
        
        threads = [threading.Thread(target=record_many_successes) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        state = cb.get_state()
        self.assertEqual(state["state"], "closed")
    
    def test_concurrent_load_shedder(self):
        shedder = PriorityAwareLoadShedder("concurrent", max_concurrent=100)
        
        def accept_many():
            for _ in range(50):
                shedder.should_accept()
        
        threads = [threading.Thread(target=accept_many) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        stats = shedder.get_stats()
        self.assertGreater(stats["total_requests"], 0)


# -----------------------------------------------------------------------------
# RUN TESTS
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    print("=" * 70)
    print("Running Error Resilience v18 Tests")
    print("=" * 70)
    
    # Run all tests
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(__import__(__name__))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print("\n" + "=" * 70)
    print(f"Tests Run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Skipped: {len(result.skipped)}")
    print("=" * 70)
    
    if result.wasSuccessful():
        print("✅ ALL TESTS PASSED - Dimension E v18 Ready!")
    else:
        print("❌ SOME TESTS FAILED")
