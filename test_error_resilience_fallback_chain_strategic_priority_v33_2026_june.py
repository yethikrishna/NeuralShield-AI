"""
Test suite for NeuralShield AI - Strategic Priority Fallback Chain v33
DIMENSION E: ERROR RESILIENCE - Test Coverage Expansion

All tests verify:
1. Happy path behavior is preserved
2. Backward compatibility maintained
3. New error resilience features work correctly
4. No existing code is broken
"""

import unittest
import time
import threading
from neural_shield.error_resilience_fallback_chain_strategic_priority_degradation_v33_2026_june import (
    StrategicFallbackChain,
    FallbackStrategy,
    DegradationLevel,
    FallbackPriority,
    HealthStatus,
    HealthScore,
    DegradationTracker,
    strategic_fallback,
)


class TestHealthScore(unittest.TestCase):
    """Tests for HealthScore health monitoring."""
    
    def test_health_score_initial_state(self):
        """Test initial health score is 1.0 (healthy)."""
        hs = HealthScore("test_service")
        self.assertEqual(hs.get_health_score(), 1.0)
        self.assertEqual(hs.get_health_status(), HealthStatus.HEALTHY)
    
    def test_health_score_records_success(self):
        """Test success recording works."""
        hs = HealthScore("test_service")
        hs.record_success(100.0)
        self.assertEqual(hs.consecutive_successes, 1)
        self.assertEqual(hs.consecutive_failures, 0)
        self.assertEqual(hs.get_health_score(), 1.0)
    
    def test_health_score_records_failure(self):
        """Test failure recording works."""
        hs = HealthScore("test_service")
        hs.record_failure(100.0)
        self.assertEqual(hs.consecutive_failures, 1)
        self.assertEqual(hs.consecutive_successes, 0)
        self.assertLess(hs.get_health_score(), 1.0)
    
    def test_health_status_transitions(self):
        """Test health status transitions correctly."""
        hs = HealthScore("test_service")
        
        # All healthy
        for _ in range(10):
            hs.record_success(50.0)
        self.assertEqual(hs.get_health_status(), HealthStatus.HEALTHY)
        
        # Some failures - should degrade from healthy
        for _ in range(5):
            hs.record_failure(50.0)
        status = hs.get_health_status()
        # Should not be HEALTHY anymore
        self.assertNotEqual(status, HealthStatus.HEALTHY)
    
    def test_consecutive_failure_penalty(self):
        """Test consecutive failures apply penalty."""
        hs = HealthScore("test_service")
        for _ in range(10):
            hs.record_failure(50.0)
        
        score = hs.get_health_score()
        self.assertLess(score, 0.5)  # Should be significantly penalized


class TestDegradationTracker(unittest.TestCase):
    """Tests for DegradationTracker SLO monitoring."""
    
    def test_initial_degradation_level(self):
        """Test initial level is FULL."""
        dt = DegradationTracker()
        self.assertEqual(dt.get_current_level(), DegradationLevel.FULL)
    
    def test_set_degradation_level(self):
        """Test degradation level changes."""
        dt = DegradationTracker()
        dt.set_degradation_level(DegradationLevel.MINIMAL)
        self.assertEqual(dt.get_current_level(), DegradationLevel.MINIMAL)
    
    def test_request_tracking(self):
        """Test request tracking for SLO."""
        dt = DegradationTracker()
        dt.record_request(was_degraded=False)
        dt.record_request(was_degraded=True)
        dt.record_request(was_degraded=False, failed=True)
        
        self.assertEqual(dt.total_requests, 3)
        self.assertEqual(dt.degraded_requests, 1)
        self.assertEqual(dt.failed_requests, 1)
        self.assertLess(dt.get_availability(), 1.0)


class TestFallbackStrategy(unittest.TestCase):
    """Tests for FallbackStrategy metadata."""
    
    def test_fallback_strategy_creation(self):
        """Test strategy creation with defaults."""
        def dummy_handler():
            return "fallback"
        
        strategy = FallbackStrategy(
            name="test_fallback",
            handler=dummy_handler
        )
        
        self.assertEqual(strategy.name, "test_fallback")
        self.assertEqual(strategy.priority, FallbackPriority.MEDIUM)
        self.assertEqual(strategy.success_count, 0)
        self.assertEqual(strategy.failure_count, 0)
    
    def test_fallback_strategy_custom_priority(self):
        """Test custom priority setting."""
        def dummy_handler():
            return "fallback"
        
        strategy = FallbackStrategy(
            name="high_priority",
            handler=dummy_handler,
            priority=FallbackPriority.HIGHEST
        )
        
        self.assertEqual(strategy.priority, FallbackPriority.HIGHEST)


class TestStrategicFallbackChain(unittest.TestCase):
    """Tests for StrategicFallbackChain core functionality."""
    
    def test_happy_path_primary_succeeds(self):
        """Test happy path - primary succeeds, no fallback activated."""
        chain = StrategicFallbackChain("test_chain")
        
        def primary_operation():
            return "primary_success"
        
        chain.register_primary_operation(primary_operation)
        
        result, was_degraded, strategy_used = chain.execute()
        
        self.assertEqual(result, "primary_success")
        self.assertFalse(was_degraded)
        self.assertEqual(strategy_used, "primary")
        self.assertEqual(chain.fallback_activations, 0)
    
    def test_primary_fails_fallback_succeeds(self):
        """Test fallback activation when primary fails."""
        chain = StrategicFallbackChain("test_chain")
        
        def failing_primary():
            raise ValueError("Primary failed")
        
        def fallback_handler():
            return "fallback_success"
        
        chain.register_primary_operation(failing_primary)
        chain.add_fallback_strategy(FallbackStrategy(
            name="fallback_1",
            handler=fallback_handler,
            priority=FallbackPriority.HIGHEST
        ))
        
        result, was_degraded, strategy_used = chain.execute()
        
        self.assertEqual(result, "fallback_success")
        self.assertTrue(was_degraded)
        self.assertEqual(strategy_used, "fallback_1")
        self.assertEqual(chain.fallback_activations, 1)
        self.assertEqual(chain.successful_fallbacks, 1)
    
    def test_priority_ordering(self):
        """Test fallbacks are executed in priority order."""
        chain = StrategicFallbackChain("test_chain")
        execution_order = []
        
        def failing_primary():
            raise ValueError("Primary failed")
        
        def make_fallback(name: str, should_fail: bool):
            def fallback():
                execution_order.append(name)
                if should_fail:
                    raise ValueError(f"{name} failed")
                return f"{name}_success"
            return fallback
        
        chain.register_primary_operation(failing_primary)
        
        # Add in reverse priority order to test sorting
        chain.add_fallback_strategy(FallbackStrategy(
            name="low_priority",
            handler=make_fallback("low_priority", True),
            priority=FallbackPriority.LOW
        ))
        chain.add_fallback_strategy(FallbackStrategy(
            name="medium_priority",
            handler=make_fallback("medium_priority", True),
            priority=FallbackPriority.MEDIUM
        ))
        chain.add_fallback_strategy(FallbackStrategy(
            name="high_priority",
            handler=make_fallback("high_priority", False),
            priority=FallbackPriority.HIGH
        ))
        
        chain.execute()
        
        # Should execute HIGH first, then MEDIUM, then LOW
        # But since high succeeds, only high runs
        self.assertEqual(execution_order, ["high_priority"])
    
    def test_all_fallbacks_fail(self):
        """Test proper error when all fallbacks fail."""
        chain = StrategicFallbackChain("test_chain")
        
        def failing_primary():
            raise ValueError("Primary failed")
        
        def failing_fallback():
            raise ValueError("Fallback failed")
        
        chain.register_primary_operation(failing_primary)
        chain.add_fallback_strategy(FallbackStrategy(
            name="fallback_1",
            handler=failing_fallback
        ))
        
        with self.assertRaises(RuntimeError) as context:
            chain.execute()
        
        self.assertIn("All fallback strategies failed", str(context.exception))
        self.assertEqual(chain.failed_fallbacks, 1)
    
    def test_degradation_level_escalation(self):
        """Test degradation level escalates on failures."""
        chain = StrategicFallbackChain("test_chain")
        
        def failing_primary():
            raise ValueError("Primary failed")
        
        def failing_fallback():
            raise ValueError("Fallback failed")
        
        chain.register_primary_operation(failing_primary)
        chain.add_fallback_strategy(FallbackStrategy(
            name="fallback_1",
            handler=failing_fallback
        ))
        
        initial_level = chain._degradation_tracker.get_current_level()
        
        try:
            chain.execute()
        except RuntimeError:
            pass
        
        new_level = chain._degradation_tracker.get_current_level()
        self.assertNotEqual(initial_level, new_level)
    
    def test_statistics_collection(self):
        """Test statistics are properly collected."""
        chain = StrategicFallbackChain("test_chain")
        
        def failing_primary():
            raise ValueError("Primary failed")
        
        def fallback_handler():
            return "success"
        
        chain.register_primary_operation(failing_primary)
        chain.add_fallback_strategy(FallbackStrategy(
            name="fallback_1",
            handler=fallback_handler
        ))
        
        # Execute a few times
        for _ in range(5):
            chain.execute()
        
        stats = chain.get_statistics()
        
        self.assertEqual(stats["fallback_activations"], 5)
        self.assertEqual(stats["successful_fallbacks"], 5)
        self.assertEqual(stats["failed_fallbacks"], 0)
        self.assertEqual(stats["total_requests"], 5)
        self.assertGreater(len(stats["strategy_statistics"]), 0)
    
    def test_health_statuses_reporting(self):
        """Test health status reporting works."""
        chain = StrategicFallbackChain("test_chain")
        
        def primary():
            return "ok"
        
        chain.register_primary_operation(primary)
        chain.execute()
        
        health_statuses = chain.get_health_statuses()
        self.assertIn("primary", health_statuses)
        self.assertEqual(health_statuses["primary"], "healthy")


class TestStrategicFallbackDecorator(unittest.TestCase):
    """Tests for @strategic_fallback decorator."""
    
    def test_decorator_happy_path(self):
        """Test decorator works on happy path."""
        chain = StrategicFallbackChain("decorator_test")
        
        @strategic_fallback(chain)
        def my_function():
            return "decorator_success"
        
        result = my_function()
        self.assertEqual(result, "decorator_success")
    
    def test_decorator_with_fallback(self):
        """Test decorator activates fallback."""
        chain = StrategicFallbackChain("decorator_test")
        
        def fallback_handler():
            return "fallback_result"
        
        chain.add_fallback_strategy(FallbackStrategy(
            name="decorator_fallback",
            handler=fallback_handler
        ))
        
        @strategic_fallback(chain)
        def my_function():
            raise ValueError("Decorated function failed")
        
        result = my_function()
        self.assertEqual(result, "fallback_result")


class TestThreadSafety(unittest.TestCase):
    """Tests for thread safety of error resilience components."""
    
    def test_concurrent_chain_execution(self):
        """Test chain works correctly under concurrent execution."""
        chain = StrategicFallbackChain("concurrent_test")
        results = []
        errors = []
        
        def primary_op():
            time.sleep(0.001)  # Small delay to encourage context switching
            return "success"
        
        chain.register_primary_operation(primary_op)
        
        def worker():
            try:
                result, _, _ = chain.execute()
                results.append(result)
            except Exception as e:
                errors.append(e)
        
        threads = [threading.Thread(target=worker) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        self.assertEqual(len(errors), 0)
        self.assertEqual(len(results), 20)
        self.assertEqual(chain._degradation_tracker.total_requests, 20)


class TestDegradationLevelFiltering(unittest.TestCase):
    """Tests for degradation level-based strategy filtering."""
    
    def test_strategy_filtered_by_degradation_level(self):
        """Test strategies are filtered based on current degradation level."""
        chain = StrategicFallbackChain("degradation_test")
        
        def failing_primary():
            raise ValueError("Primary failed")
        
        def fallback_for_full():
            return "full_level_fallback"
        
        def fallback_for_minimal():
            return "minimal_level_fallback"
        
        chain.register_primary_operation(failing_primary)
        
        # Strategy only for FULL level
        chain.add_fallback_strategy(FallbackStrategy(
            name="full_only",
            handler=fallback_for_full,
            priority=FallbackPriority.HIGHEST,
            supported_degradation_levels=[DegradationLevel.FULL]
        ))
        
        # Strategy for MINIMAL level and above
        chain.add_fallback_strategy(FallbackStrategy(
            name="minimal_and_above",
            handler=fallback_for_minimal,
            priority=FallbackPriority.HIGH,
            supported_degradation_levels=[DegradationLevel.MINIMAL, DegradationLevel.MODERATE]
        ))
        
        # At FULL level, should use full_only
        result, _, strategy = chain.execute()
        self.assertEqual(strategy, "full_only")


if __name__ == "__main__":
    unittest.main()
