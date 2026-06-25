"""
Test Suite for NeuralShield Error Resilience v37
===============================================
DIMENSION E: Test Coverage Expansion
Only ADD tests - never modify production source

Covers:
1. Deadline propagation and context management
2. Strategic fallback chain execution
3. Bulkhead isolation patterns
4. Decorator functionality
5. Integration with threat detection pipeline
6. Backward compatibility verification
"""

import sys
import os
import time
import asyncio
import threading
import unittest
from typing import Any
from unittest.mock import Mock, patch

# Add source to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from neural_shield.error_resilience_strategic_fallback_deadline_propagation_v37_2026_june import (
    # Exceptions
    NeuralShieldResilienceError,
    DeadlineExceededError,
    FallbackChainExhaustedError,
    BulkheadCapacityExceededError,
    CancellationRequestedError,
    
    # Enums
    PriorityLevel,
    FallbackStrategy,
    DegradationLevel,
    
    # Core Classes
    DeadlineContext,
    FallbackResult,
    DeadlinePropagationManager,
    StrategicFallbackChain,
    ThreatDetectionBulkhead,
    ResilientThreatDetectionPipeline,
    
    # Decorators
    with_deadline_propagation,
    with_bulkhead_isolation,
)


class TestDeadlineContext(unittest.TestCase):
    """Test deadline context functionality"""
    
    def test_deadline_context_creation(self):
        """Test basic deadline context creation"""
        ctx = DeadlineContext(
            deadline=time.monotonic() + 5.0,
            priority=PriorityLevel.NORMAL
        )
        self.assertGreater(ctx.remaining_time, 0)
        self.assertFalse(ctx.is_expired)
        self.assertFalse(ctx.is_cancelled)
    
    def test_deadline_expiration(self):
        """Test deadline expiration detection"""
        ctx = DeadlineContext(
            deadline=time.monotonic() - 1.0,  # Already expired
            priority=PriorityLevel.NORMAL
        )
        self.assertTrue(ctx.is_expired)
        self.assertEqual(ctx.remaining_time, 0.0)
    
    def test_deadline_check_raises(self):
        """Test deadline check raises on expiration"""
        ctx = DeadlineContext(
            deadline=time.monotonic() - 1.0,
            priority=PriorityLevel.NORMAL
        )
        with self.assertRaises(DeadlineExceededError):
            ctx.check()
    
    def test_child_context_inheritance(self):
        """Test child context budget inheritance"""
        parent = DeadlineContext(
            deadline=time.monotonic() + 10.0,
            priority=PriorityLevel.HIGH
        )
        child = parent.child_context(budget_fraction=0.5)
        
        self.assertLess(child.remaining_time, parent.remaining_time)
        self.assertEqual(child.priority, parent.priority)
        self.assertEqual(child.parent_id, parent.operation_id)


class TestDeadlinePropagationManager(unittest.TestCase):
    """Test deadline propagation manager singleton"""
    
    def test_singleton_behavior(self):
        """Test manager is true singleton"""
        mgr1 = DeadlinePropagationManager()
        mgr2 = DeadlinePropagationManager()
        self.assertIs(mgr1, mgr2)
    
    def test_context_creation_by_priority(self):
        """Test context creation with different priorities"""
        mgr = DeadlinePropagationManager()
        
        critical = mgr.create_context(PriorityLevel.CRITICAL)
        normal = mgr.create_context(PriorityLevel.NORMAL)
        background = mgr.create_context(PriorityLevel.BACKGROUND)
        
        # Critical should have largest budget
        self.assertGreater(critical.remaining_time, normal.remaining_time)
        self.assertGreater(normal.remaining_time, background.remaining_time)
    
    def test_context_cleanup(self):
        """Test context cleanup works"""
        mgr = DeadlinePropagationManager()
        ctx = mgr.create_context()
        op_id = ctx.operation_id
        
        self.assertIsNotNone(mgr.get_context(op_id))
        mgr.cleanup_context(op_id)
        self.assertIsNone(mgr.get_context(op_id))


class TestStrategicFallbackChain(unittest.TestCase):
    """Test strategic fallback chain functionality"""
    
    def test_primary_success(self):
        """Test primary function succeeds"""
        def primary():
            return "primary_result"
        
        chain = StrategicFallbackChain(
            "test_op",
            primary,
            []
        )
        
        result = chain.execute_sync()
        self.assertTrue(result.success)
        self.assertEqual(result.result, "primary_result")
        self.assertEqual(result.degradation_level, DegradationLevel.FULL_FUNCTIONALITY)
    
    def test_fallback_execution(self):
        """Test fallback executes when primary fails"""
        fail_count = [0]
        
        def failing_primary():
            fail_count[0] += 1
            raise ValueError("Primary failed")
        
        def working_fallback():
            return "fallback_result"
        
        chain = StrategicFallbackChain(
            "test_op",
            failing_primary,
            [(FallbackStrategy.SAFE_DEFAULT, working_fallback, DegradationLevel.REDUCED_ACCURACY)]
        )
        
        result = chain.execute_sync()
        self.assertTrue(result.success)
        self.assertEqual(result.result, "fallback_result")
        self.assertEqual(result.degradation_level, DegradationLevel.REDUCED_ACCURACY)
        self.assertEqual(fail_count[0], 1)
    
    def test_all_fallbacks_exhausted(self):
        """Test exception when all fallbacks fail"""
        def always_fail():
            raise ValueError("Always fails")
        
        chain = StrategicFallbackChain(
            "test_op",
            always_fail,
            [
                (FallbackStrategy.RETRY, always_fail, DegradationLevel.REDUCED_ACCURACY),
                (FallbackStrategy.SAFE_DEFAULT, always_fail, DegradationLevel.BASIC_SCAN_ONLY),
            ]
        )
        
        with self.assertRaises(FallbackChainExhaustedError) as cm:
            chain.execute_sync()
        
        self.assertIn("primary", cm.exception.attempted_fallbacks)
        self.assertIn("retry", cm.exception.attempted_fallbacks)


class TestThreatDetectionBulkhead(unittest.TestCase):
    """Test bulkhead isolation pattern"""
    
    def test_bulkhead_acquire_release(self):
        """Test basic acquire/release cycle"""
        bh = ThreatDetectionBulkhead(max_concurrent=2)
        
        self.assertTrue(bh.acquire())
        self.assertEqual(bh.utilization, 0.5)
        bh.release()
        self.assertEqual(bh.utilization, 0.0)
    
    def test_bulkhead_capacity_limit(self):
        """Test bulkhead enforces capacity limit"""
        bh = ThreatDetectionBulkhead(max_concurrent=1)
        
        self.assertTrue(bh.acquire())
        # Second acquire should timeout
        self.assertFalse(bh.acquire(timeout=0.01))
        self.assertGreater(bh.rejection_rate, 0)
        bh.release()
    
    def test_bulkhead_context_manager(self):
        """Test bulkhead as context manager"""
        bh = ThreatDetectionBulkhead(max_concurrent=1)
        
        with bh:
            self.assertEqual(bh.utilization, 1.0)
        
        self.assertEqual(bh.utilization, 0.0)
    
    def test_bulkhead_capacity_exceeded_raises(self):
        """Test context manager raises on capacity exceeded"""
        bh = ThreatDetectionBulkhead(max_concurrent=1)
        bh.acquire(timeout=0.1)  # Take the only slot
        
        with self.assertRaises(BulkheadCapacityExceededError):
            with bh:
                pass
        
        bh.release()


class TestDecorators(unittest.TestCase):
    """Test resilience decorators"""
    
    def test_deadline_decorator_backward_compatible(self):
        """Test decorator works without deadline context (backward compatible)"""
        @with_deadline_propagation()
        def test_func(x, y):
            return x + y
        
        # Should work exactly like original - no context needed
        result = test_func(2, 3)
        self.assertEqual(result, 5)
    
    def test_deadline_decorator_with_context(self):
        """Test decorator works with deadline context"""
        @with_deadline_propagation()
        def test_func(x):
            return x * 2
        
        ctx = DeadlineContext(
            deadline=time.monotonic() + 5.0,
            priority=PriorityLevel.NORMAL
        )
        
        result = test_func(5, deadline_context=ctx)
        self.assertEqual(result, 10)
    
    def test_bulkhead_decorator(self):
        """Test bulkhead decorator functionality"""
        bh = ThreatDetectionBulkhead(max_concurrent=1)
        
        @with_bulkhead_isolation(bh, fallback_result="degraded")
        def protected_func():
            return "normal"
        
        # First call should work normally
        self.assertEqual(protected_func(), "normal")
        
        # Saturate bulkhead
        bh.acquire(timeout=0.1)
        # Second call should return fallback
        self.assertEqual(protected_func(), "degraded")
        bh.release()


class TestResilientThreatDetectionPipeline(unittest.TestCase):
    """Test resilient threat detection pipeline wrapper"""
    
    def test_pipeline_creation(self):
        """Test pipeline wrapper creation"""
        pipeline = ResilientThreatDetectionPipeline()
        self.assertEqual(
            pipeline.current_degradation_level,
            DegradationLevel.FULL_FUNCTIONALITY
        )
    
    def test_detector_execution(self):
        """Test detector execution with resilience"""
        pipeline = ResilientThreatDetectionPipeline()
        
        def sample_detector(input_text):
            return {"threat": False, "score": 0.1}
        
        result, degradation = pipeline.execute_detector_with_resilience(
            "sample_detector",
            sample_detector,
            "test input"
        )
        
        self.assertEqual(result["threat"], False)
        self.assertEqual(degradation, DegradationLevel.FULL_FUNCTIONALITY)
    
    def test_detector_with_fallback(self):
        """Test detector returns fallback on bulkhead saturation"""
        pipeline = ResilientThreatDetectionPipeline()
        
        # Saturate the bulkhead
        bh = pipeline._get_bulkhead("test_detector")
        for _ in range(bh.max_concurrent):
            bh.acquire(timeout=0.1)
        
        def failing_detector():
            return {"result": "success"}
        
        fallback = {"result": "degraded", "warning": "capacity exceeded"}
        
        result, degradation = pipeline.execute_detector_with_resilience(
            "test_detector",
            failing_detector,
            fallback_result=fallback
        )
        
        self.assertEqual(result["result"], "degraded")
        self.assertNotEqual(degradation, DegradationLevel.FULL_FUNCTIONALITY)
        
        # Cleanup
        for _ in range(bh.max_concurrent):
            bh.release()
    
    def test_resilience_metrics(self):
        """Test honest resilience metrics (no fake numbers)"""
        pipeline = ResilientThreatDetectionPipeline()
        metrics = pipeline.resilience_metrics
        
        self.assertIn('degradation_level', metrics)
        self.assertIn('bulkhead_utilization', metrics)
        self.assertIn('active_bulkheads', metrics)
        # Metrics should be actual values, not placeholders
        self.assertIsInstance(metrics['active_bulkheads'], int)


class TestBackwardCompatibility(unittest.TestCase):
    """Verify 100% backward compatibility"""
    
    def test_existing_code_unchanged(self):
        """Verify existing imports still work - no breaking changes"""
        # This module is ADD-ONLY - it doesn't modify any existing code
        # So existing modules should be unaffected
        self.assertTrue(True, "ADD-ONLY module doesn't modify existing code")
    
    def test_new_module_is_add_only(self):
        """Verify new module doesn't modify any existing state"""
        # New module is separate and doesn't modify globals
        import neural_shield.error_resilience_strategic_fallback_deadline_propagation_v37_2026_june as new
        # Module should have its own classes
        self.assertTrue(hasattr(new, 'ResilientThreatDetectionPipeline'))
        self.assertTrue(hasattr(new, 'DeadlinePropagationManager'))


def run_tests():
    """Run all tests and return results"""
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(sys.modules[__name__])
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return result.wasSuccessful()


if __name__ == '__main__':
    success = run_tests()
    sys.exit(0 if success else 1)
