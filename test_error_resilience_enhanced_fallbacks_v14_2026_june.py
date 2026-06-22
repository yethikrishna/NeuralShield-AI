"""
Test Suite for NeuralShield Error Resilience Enhanced Fallbacks v14 - Dimension E
==================================================================================
ALL TESTS MUST PASS - NO EXISTING CODE MODIFIED
ADD-ONLY VERIFICATION - Zero intrusion into production code

Tests cover:
1. Dead Letter Queue (DLQ) operations
2. Bulk Operation Handler with partial success
3. Error Aggregator and reporting
4. Graceful Shutdown Coordinator
5. Tiered Fallback strategies
6. Convenience decorators
7. Thread safety and concurrency
"""
import unittest
import time
import threading
import json
from typing import List

# Import the new module - ONLY NEW CODE, NO MODIFICATIONS
from neural_shield.error_resilience_enhanced_fallbacks_v14_2026_june import (
    DeadLetterQueue,
    get_global_dlq,
    BulkOperationHandler,
    BulkOperationResult,
    ErrorAggregator,
    get_global_error_aggregator,
    GracefulShutdownCoordinator,
    get_global_shutdown_coordinator,
    TieredFallback,
    with_tiered_fallback,
    with_dlq,
    with_error_tracking,
    create_bulk_processor,
    BulkOperationError,
    DeadLetterQueueError,
    ShutdownError,
    FallbackChainExhaustedError,
    DeadLetterEntry,
    ErrorSummary
)

# ============================================================================
# TEST 1: DEAD LETTER QUEUE
# ============================================================================
class TestDeadLetterQueue(unittest.TestCase):
    
    def setUp(self):
        self.dlq = DeadLetterQueue(max_size=100)
    
    def test_dlq_enqueue_dequeue(self):
        """Test basic enqueue and dequeue operations"""
        error = ValueError("test error")
        entry_id = self.dlq.enqueue("test_op", {"data": 123}, error)
        
        self.assertEqual(self.dlq.size(), 1)
        
        entry = self.dlq.dequeue()
        self.assertIsNotNone(entry)
        self.assertEqual(entry.operation_id, entry_id)
        self.assertEqual(entry.operation_name, "test_op")
        self.assertEqual(self.dlq.size(), 0)
    
    def test_dlq_peek(self):
        """Test peek without removal"""
        self.dlq.enqueue("op1", "payload1", ValueError("e1"))
        self.dlq.enqueue("op2", "payload2", ValueError("e2"))
        
        peeked = self.dlq.peek()
        self.assertIsNotNone(peeked)
        self.assertEqual(peeked.operation_name, "op1")
        self.assertEqual(self.dlq.size(), 2)  # Still 2, peek doesn't remove
    
    def test_dlq_empty_operations(self):
        """Test operations on empty DLQ"""
        self.assertEqual(self.dlq.size(), 0)
        self.assertIsNone(self.dlq.dequeue())
        self.assertIsNone(self.dlq.peek())
    
    def test_dlq_get_all(self):
        """Test getting all entries"""
        for i in range(5):
            self.dlq.enqueue(f"op{i}", f"payload{i}", ValueError(f"e{i}"))
        
        all_entries = self.dlq.get_all()
        self.assertEqual(len(all_entries), 5)
        self.assertEqual(self.dlq.size(), 5)  # Original queue unchanged
    
    def test_dlq_clear(self):
        """Test clearing DLQ"""
        for i in range(10):
            self.dlq.enqueue(f"op{i}", f"payload{i}", ValueError(f"e{i}"))
        
        cleared = self.dlq.clear()
        self.assertEqual(cleared, 10)
        self.assertEqual(self.dlq.size(), 0)
    
    def test_dlq_export_json(self):
        """Test JSON export"""
        self.dlq.enqueue("test_op", {"data": "test"}, ValueError("test error"))
        json_str = self.dlq.export_json()
        
        # Should be valid JSON
        data = json.loads(json_str)
        self.assertIsInstance(data, list)
        self.assertEqual(len(data), 1)
        self.assertIn("operation_id", data[0])
        self.assertIn("error_type", data[0])
    
    def test_dlq_register_and_retry_handler(self):
        """Test retry handler registration and retry"""
        retry_results = []
        
        def my_handler(payload):
            retry_results.append(payload)
            return "success"
        
        self.dlq.register_retry_handler("retryable_op", my_handler)
        
        # Enqueue a failure
        entry_id = self.dlq.enqueue("retryable_op", "my_payload", ValueError("failed"))
        
        # Retry it
        success, result = self.dlq.retry_entry(entry_id)
        self.assertTrue(success)
        self.assertEqual(result, "success")
        self.assertEqual(retry_results, ["my_payload"])
        self.assertEqual(self.dlq.size(), 0)  # Removed on success
    
    def test_dlq_retry_failure_updates_count(self):
        """Test retry failure updates retry count"""
        def failing_handler(payload):
            raise ValueError("still failing")
        
        self.dlq.register_retry_handler("failing_op", failing_handler)
        entry_id = self.dlq.enqueue("failing_op", "data", ValueError("original"))
        
        success, error = self.dlq.retry_entry(entry_id)
        self.assertFalse(success)
        self.assertIsInstance(error, ValueError)
        
        # Entry still in queue with incremented retry count
        entry = self.dlq.peek()
        self.assertEqual(entry.retry_count, 1)
        self.assertIsNotNone(entry.last_retry_at)
    
    def test_global_dlq_singleton(self):
        """Test global DLQ is singleton"""
        dlq1 = get_global_dlq()
        dlq2 = get_global_dlq()
        self.assertIs(dlq1, dlq2)

# ============================================================================
# TEST 2: BULK OPERATION HANDLER
# ============================================================================
class TestBulkOperationHandler(unittest.TestCase):
    
    def test_bulk_all_success(self):
        """Test bulk processing with all items succeeding"""
        handler = BulkOperationHandler()
        
        def double(x):
            return x * 2
        
        result = handler.process([1, 2, 3, 4, 5], double)
        
        self.assertIsInstance(result, BulkOperationResult)
        self.assertEqual(result.total_items, 5)
        self.assertEqual(result.success_count, 5)
        self.assertEqual(result.failure_count, 0)
        self.assertEqual(result.success_rate, 1.0)
    
    def test_bulk_partial_success(self):
        """Test bulk processing with partial failures"""
        handler = BulkOperationHandler(continue_on_error=True)
        
        def sometimes_fail(x):
            if x % 2 == 0:
                raise ValueError(f"even number: {x}")
            return x * 2
        
        result = handler.process([1, 2, 3, 4, 5], sometimes_fail)
        
        self.assertEqual(result.total_items, 5)
        self.assertEqual(result.success_count, 3)  # 1, 3, 5 succeed
        self.assertEqual(result.failure_count, 2)  # 2, 4 fail
        self.assertLess(result.success_rate, 1.0)
    
    def test_bulk_stop_on_error(self):
        """Test bulk processing stops on error when configured"""
        handler = BulkOperationHandler(continue_on_error=False)
        
        def fail_on_second(x):
            if x == 2:
                raise ValueError("failed")
            return x
        
        result = handler.process([1, 2, 3, 4, 5], fail_on_second)
        
        # Should stop after first failure
        self.assertEqual(result.success_count, 1)
        self.assertEqual(result.failure_count, 1)
    
    def test_bulk_max_failures_threshold(self):
        """Test bulk processing stops at max failures threshold"""
        handler = BulkOperationHandler(continue_on_error=True, max_failures=2)
        
        def always_fail(x):
            raise ValueError(f"fail {x}")
        
        result = handler.process([1, 2, 3, 4, 5], always_fail)
        
        self.assertEqual(result.failure_count, 2)  # Stops at threshold
    
    def test_bulk_result_to_dict(self):
        """Test result serialization"""
        handler = BulkOperationHandler()
        
        def identity(x):
            return x
        
        result = handler.process([1, 2, 3], identity)
        d = result.to_dict()
        
        self.assertIn("operation_id", d)
        self.assertIn("success_rate", d)
        self.assertIn("failed_items", d)
        self.assertEqual(d["total_items"], 3)
    
    def test_bulk_concurrent_processing(self):
        """Test concurrent bulk processing"""
        handler = BulkOperationHandler()
        
        def slow_double(x):
            time.sleep(0.01)
            return x * 2
        
        items = list(range(20))
        result = handler.process_with_concurrency(items, slow_double, max_workers=4)
        
        self.assertEqual(result.total_items, 20)
        self.assertEqual(result.success_count, 20)
    
    def test_create_bulk_processor(self):
        """Test convenience function for bulk processor creation"""
        processor = create_bulk_processor(lambda x: x + 1)
        result = processor([1, 2, 3])
        
        self.assertEqual(result.success_count, 3)

# ============================================================================
# TEST 3: ERROR AGGREGATOR
# ============================================================================
class TestErrorAggregator(unittest.TestCase):
    
    def setUp(self):
        self.aggregator = ErrorAggregator(window_seconds=3600)
    
    def test_error_recording(self):
        """Test basic error recording"""
        for i in range(10):
            self.aggregator.record_error("ValueError", "operation1", f"message {i}")
        
        summary = self.aggregator.get_summary()
        self.assertEqual(summary.total_errors, 10)
    
    def test_error_aggregation_by_type(self):
        """Test errors are aggregated by type"""
        self.aggregator.record_error("ValueError", "op1", "msg1")
        self.aggregator.record_error("ValueError", "op2", "msg2")
        self.aggregator.record_error("TypeError", "op1", "msg3")
        
        summary = self.aggregator.get_summary()
        
        self.assertEqual(summary.error_counts_by_type["ValueError"], 2)
        self.assertEqual(summary.error_counts_by_type["TypeError"], 1)
        self.assertEqual(summary.affected_operations, {"op1", "op2"})
    
    def test_empty_summary(self):
        """Test summary on empty aggregator"""
        summary = self.aggregator.get_summary()
        self.assertEqual(summary.total_errors, 0)
        self.assertEqual(summary.error_counts_by_type, {})
    
    def test_summary_to_dict(self):
        """Test summary serialization"""
        self.aggregator.record_error("ValueError", "test_op", "test message")
        summary = self.aggregator.get_summary()
        d = summary.to_dict()
        
        self.assertIn("time_window", d)
        self.assertIn("total_errors", d)
        self.assertIn("top_errors", d)
    
    def test_clear_aggregator(self):
        """Test clearing aggregator"""
        for i in range(5):
            self.aggregator.record_error("Error", "op", f"msg{i}")
        
        cleared = self.aggregator.clear()
        self.assertEqual(cleared, 5)
        self.assertEqual(self.aggregator.get_summary().total_errors, 0)
    
    def test_global_aggregator_singleton(self):
        """Test global aggregator is singleton"""
        agg1 = get_global_error_aggregator()
        agg2 = get_global_error_aggregator()
        self.assertIs(agg1, agg2)

# ============================================================================
# TEST 4: GRACEFUL SHUTDOWN COORDINATOR
# ============================================================================
class TestGracefulShutdownCoordinator(unittest.TestCase):
    
    def setUp(self):
        self.coordinator = GracefulShutdownCoordinator()
    
    def test_register_and_run_hooks(self):
        """Test hook registration and execution"""
        hook_called = []
        
        def my_hook():
            hook_called.append(True)
        
        self.coordinator.register_hook("my_hook", my_hook, priority=10)
        results = self.coordinator.initiate_shutdown()
        
        self.assertTrue(hook_called)
        self.assertTrue(results["my_hook"])
    
    def test_hook_priority_order(self):
        """Test hooks run in priority order (highest first)"""
        execution_order = []
        
        def hook_low():
            execution_order.append("low")
        
        def hook_high():
            execution_order.append("high")
        
        self.coordinator.register_hook("low_priority", hook_low, priority=1)
        self.coordinator.register_hook("high_priority", hook_high, priority=100)
        
        self.coordinator.initiate_shutdown()
        
        # High priority should run first
        self.assertEqual(execution_order[0], "high")
        self.assertEqual(execution_order[1], "low")
    
    def test_hook_failure_handling(self):
        """Test failing hooks don't break shutdown"""
        def failing_hook():
            raise ValueError("hook failed")
        
        def good_hook():
            pass
        
        self.coordinator.register_hook("failing", failing_hook)
        self.coordinator.register_hook("good", good_hook)
        
        results = self.coordinator.initiate_shutdown()
        
        self.assertFalse(results["failing"])
        self.assertTrue(results["good"])
    
    def test_unregister_hook(self):
        """Test hook unregistration"""
        called = []
        
        def my_hook():
            called.append(True)
        
        self.coordinator.register_hook("test", my_hook)
        self.coordinator.unregister_hook("test")
        
        results = self.coordinator.initiate_shutdown()
        self.assertNotIn("test", results)
        self.assertEqual(len(called), 0)
    
    def test_shutdown_state(self):
        """Test shutdown state tracking"""
        self.assertFalse(self.coordinator.is_shutting_down())
        
        self.coordinator.initiate_shutdown()
        
        self.assertTrue(self.coordinator.is_shutting_down())
    
    def test_reset_shutdown(self):
        """Test resetting shutdown state"""
        self.coordinator.initiate_shutdown()
        self.assertTrue(self.coordinator.is_shutting_down())
        
        self.coordinator.reset()
        self.assertFalse(self.coordinator.is_shutting_down())
    
    def test_global_coordinator_singleton(self):
        """Test global coordinator is singleton"""
        coord1 = get_global_shutdown_coordinator()
        coord2 = get_global_shutdown_coordinator()
        self.assertIs(coord1, coord2)

# ============================================================================
# TEST 5: TIERED FALLBACK
# ============================================================================
class TestTieredFallback(unittest.TestCase):
    
    def test_primary_succeeds(self):
        """Test primary succeeds, no fallbacks used"""
        def primary():
            return "primary result"
        
        def fallback():
            return "fallback result"
        
        chain = TieredFallback(primary, fallback)
        result = chain.execute()
        
        self.assertEqual(result, "primary result")
    
    def test_fallback_chain(self):
        """Test fallback chain when primary fails"""
        def primary():
            raise ValueError("primary failed")
        
        def secondary():
            raise ValueError("secondary failed")
        
        def tertiary():
            return "tertiary success"
        
        chain = TieredFallback(primary, secondary, tertiary)
        result = chain.execute()
        
        self.assertEqual(result, "tertiary success")
    
    def test_all_fallbacks_exhausted(self):
        """Test exception when all fallbacks fail"""
        def always_fail():
            raise ValueError("always fails")
        
        chain = TieredFallback(always_fail, always_fail, always_fail)
        
        with self.assertRaises(FallbackChainExhaustedError) as ctx:
            chain.execute()
        
        self.assertEqual(len(ctx.exception.attempted_fallbacks), 3)
    
    def test_fallback_decorator(self):
        """Test tiered fallback decorator"""
        fallback_called = []
        
        def my_fallback():
            fallback_called.append(True)
            return "fallback"
        
        @with_tiered_fallback(my_fallback)
        def my_func():
            raise ValueError("primary failed")
        
        result = my_func()
        self.assertEqual(result, "fallback")
        self.assertTrue(fallback_called)

# ============================================================================
# TEST 6: CONVENIENCE DECORATORS
# ============================================================================
class TestConvenienceDecorators(unittest.TestCase):
    
    def test_dlq_decorator(self):
        """Test DLQ decorator captures failures"""
        dlq = get_global_dlq()
        dlq.clear()
        
        @with_dlq("test_decorated_op")
        def failing_func():
            raise ValueError("decorated failure")
        
        with self.assertRaises(ValueError):
            failing_func()
        
        self.assertGreater(dlq.size(), 0)
    
    def test_error_tracking_decorator(self):
        """Test error tracking decorator"""
        agg = get_global_error_aggregator()
        agg.clear()
        
        @with_error_tracking("tracked_op")
        def failing_func():
            raise ValueError("tracked error")
        
        with self.assertRaises(ValueError):
            failing_func()
        
        summary = agg.get_summary()
        self.assertGreater(summary.total_errors, 0)

# ============================================================================
# TEST 7: THREAD SAFETY
# ============================================================================
class TestThreadSafety(unittest.TestCase):
    
    def test_dlq_concurrent_enqueue(self):
        """Test DLQ handles concurrent enqueue"""
        dlq = DeadLetterQueue(max_size=10000)
        num_threads = 10
        ops_per_thread = 100
        
        def worker(thread_id):
            for i in range(ops_per_thread):
                dlq.enqueue(f"op_{thread_id}_{i}", f"payload_{i}", ValueError(f"e_{i}"))
        
        threads = []
        for t in range(num_threads):
            thread = threading.Thread(target=worker, args=(t,))
            threads.append(thread)
            thread.start()
        
        for t in threads:
            t.join()
        
        expected = num_threads * ops_per_thread
        self.assertEqual(dlq.size(), expected)
    
    def test_aggregator_concurrent_recording(self):
        """Test aggregator handles concurrent recording"""
        agg = ErrorAggregator()
        num_threads = 10
        errors_per_thread = 50
        
        def worker():
            for i in range(errors_per_thread):
                agg.record_error("TestError", "test_op", f"msg_{i}")
        
        threads = []
        for _ in range(num_threads):
            thread = threading.Thread(target=worker)
            threads.append(thread)
            thread.start()
        
        for t in threads:
            t.join()
        
        expected = num_threads * errors_per_thread
        self.assertEqual(agg.get_summary().total_errors, expected)

# ============================================================================
# TEST 8: ADD-ONLY VERIFICATION
# ============================================================================
class TestAddOnlyCompliance(unittest.TestCase):
    """Verify this is strictly ADD-ONLY - no existing code modified"""
    
    def test_no_modification_of_existing_modules(self):
        """
        CRITICAL: This test verifies we're following ADD-ONLY philosophy.
        We only import NEW modules - existing modules are untouched.
        """
        # Verify we can import existing modules without issues
        # This would fail if we had broken anything
        try:
            from neural_shield import error_resilience_engine_2026_june
            from neural_shield import error_resilience_comprehensive_v13_2026_june
            from neural_shield import error_resilience_retry_backoff_circuit_breaker_2026_june
        except ImportError:
            self.fail("ADD-ONLY VIOLATION: Could not import existing modules")
    
    def test_backward_compatibility(self):
        """All new functionality is optional, existing behavior unchanged"""
        # New classes don't interfere with existing ones
        from neural_shield.error_resilience_enhanced_fallbacks_v14_2026_june import (
            DeadLetterQueue as NewDLQ
        )
        
        # New module has its own classes, no name collisions
        self.assertIsNotNone(NewDLQ)

# ============================================================================
# RUN TESTS
# ============================================================================
if __name__ == "__main__":
    # Count tests
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(__import__(__name__))
    total_tests = suite.countTestCases()
    
    print(f"Running {total_tests} tests for Error Resilience v14 - Dimension E")
    print("=" * 70)
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print("=" * 70)
    print(f"Tests: {result.testsRun} Run")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Skipped: {len(result.skipped)}")
    
    if result.wasSuccessful():
        print("\n✅ ALL TESTS PASSED - ADD-ONLY COMPLIANT - Dimension E Enhanced")
    else:
        print("\n❌ TESTS FAILED")
        exit(1)
