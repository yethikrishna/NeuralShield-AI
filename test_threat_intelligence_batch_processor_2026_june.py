"""
Test suite for Threat Intelligence Batch Processor
June 2026 - Production Grade Tests
Verifies all batch processing functionality works correctly.
"""
import unittest
import time
import threading
from neural_shield.threat_intelligence_batch_processor_2026_june import (
    ThreatIntelligenceBatchProcessor,
    BatchStatus,
    IOCType,
    BatchJob,
    BatchResult
)
class TestThreatIntelligenceBatchProcessor(unittest.TestCase):
    """Test suite for ThreatIntelligenceBatchProcessor"""
    def setUp(self):
        """Set up test processor"""
        self.processor = ThreatIntelligenceBatchProcessor(
            max_workers=2,
            max_retries=1,
            rate_limit_per_second=50.0
        )
    def tearDown(self):
        """Clean up after tests"""
        self.processor.shutdown(wait=True)
    def test_simple_batch_processing(self):
        """Test basic batch processing works"""
        def mock_processor(value: str, ioc_type: IOCType):
            return {"processed": True, "value": value, "type": ioc_type.value}
        
        items = ["192.168.1.1", "google.com", "https://example.com"]
        job = self.processor.process_batch_sync(items, mock_processor)
        
        self.assertEqual(job.total_items, 3)
        self.assertEqual(len(job.results), 3)
        self.assertTrue(all(r.success for r in job.results))
        self.assertEqual(job.status, BatchStatus.COMPLETED)
    def test_ioc_type_detection(self):
        """Test IOC type auto-detection"""
        detect = ThreatIntelligenceBatchProcessor._detect_ioc_type
        
        self.assertEqual(detect("192.168.1.1"), IOCType.IP_ADDRESS)
        self.assertEqual(detect("d41d8cd98f00b204e9800998ecf8427e"), IOCType.FILE_HASH)
        self.assertEqual(detect("user@example.com"), IOCType.EMAIL)
        self.assertEqual(detect("https://example.com"), IOCType.URL)
        self.assertEqual(detect("google.com"), IOCType.DOMAIN)
    def test_progress_callback(self):
        """Test progress callback is called for each item"""
        callback_results = []
        
        def progress_callback(result: BatchResult):
            callback_results.append(result)
        
        def mock_processor(value: str, ioc_type: IOCType):
            return {"ok": True}
        
        items = ["item1.com", "item2.com", "item3.com"]
        self.processor.process_batch_sync(items, mock_processor, progress_callback)
        
        # Give callbacks time to execute
        time.sleep(0.2)
        self.assertEqual(len(callback_results), 3)
    def test_error_handling_and_retries(self):
        """Test error handling with retry logic"""
        call_counts = {}
        
        def flaky_processor(value: str, ioc_type: IOCType):
            call_counts[value] = call_counts.get(value, 0) + 1
            if call_counts[value] < 2:  # Fail first time
                raise RuntimeError("Transient error")
            return {"success": True, "attempts": call_counts[value]}
        
        items = ["fail-once.com"]
        job = self.processor.process_batch_sync(items, flaky_processor)
        
        self.assertEqual(len(job.results), 1)
        self.assertTrue(job.results[0].success)
        self.assertEqual(job.results[0].retry_count, 1)
        self.assertEqual(call_counts["fail-once.com"], 2)  # Called twice (1 fail + 1 success)
    def test_permanent_failure(self):
        """Test permanent failures are properly recorded"""
        def always_fail(value: str, ioc_type: IOCType):
            raise ValueError("Permanent error")
        
        items = ["bad-item.com"]
        job = self.processor.process_batch_sync(items, always_fail)
        
        self.assertEqual(len(job.results), 1)
        self.assertFalse(job.results[0].success)
        self.assertIsNotNone(job.results[0].error)
        self.assertEqual(job.status, BatchStatus.PARTIAL)
        self.assertEqual(len(job.errors), 1)
    def test_job_statistics(self):
        """Test job statistics calculation"""
        def mock_processor(value: str, ioc_type: IOCType):
            time.sleep(0.01)
            return {"ok": True}
        
        items = [f"item{i}.com" for i in range(5)]
        job = self.processor.process_batch_sync(items, mock_processor)
        
        stats = job.get_statistics()
        self.assertEqual(stats["total_items"], 5)
        self.assertEqual(stats["successful"], 5)
        self.assertEqual(stats["failed"], 0)
        self.assertEqual(stats["success_rate_percent"], 100.0)
        self.assertGreater(stats["avg_processing_time_ms"], 0)
        self.assertGreater(stats["total_processing_time_ms"], 0)
    def test_global_statistics(self):
        """Test global processor statistics"""
        def mock_processor(value: str, ioc_type: IOCType):
            return {"ok": True}
        
        initial_stats = self.processor.get_global_statistics()
        
        items = ["a.com", "b.com", "c.com"]
        self.processor.process_batch_sync(items, mock_processor)
        
        final_stats = self.processor.get_global_statistics()
        self.assertEqual(final_stats["total_items_processed"], initial_stats["total_items_processed"] + 3)
        self.assertEqual(final_stats["total_jobs_completed"], initial_stats["total_jobs_completed"] + 1)
    def test_parallel_processing(self):
        """Test items are processed in parallel (faster than sequential)"""
        def slow_processor(value: str, ioc_type: IOCType):
            time.sleep(0.1)  # 100ms per item
            return {"ok": True}
        
        items = [f"item{i}.com" for i in range(4)]
        
        start = time.time()
        job = self.processor.process_batch_sync(items, slow_processor)
        elapsed = time.time() - start
        
        # With 2 workers, 4 items at 100ms each should take ~200ms, not 400ms
        self.assertLess(elapsed, 0.35)  # Allow some overhead
        self.assertEqual(len(job.results), 4)
    def test_rate_limiting(self):
        """Test rate limiting prevents processing too fast"""
        limited_processor = ThreatIntelligenceBatchProcessor(
            max_workers=1,
            rate_limit_per_second=10.0  # 10 per second = 100ms minimum between
        )
        
        def mock_processor(value: str, ioc_type: IOCType):
            return {"ok": True}
        
        items = [f"item{i}.com" for i in range(3)]
        
        start = time.time()
        job = limited_processor.process_batch_sync(items, mock_processor)
        elapsed = time.time() - start
        
        # 3 items with 100ms interval = at least 200ms total
        self.assertGreaterEqual(elapsed, 0.18)
        self.assertEqual(len(job.results), 3)
        
        limited_processor.shutdown()
    def test_job_cancellation(self):
        """Test job cancellation works"""
        def slow_processor(value: str, ioc_type: IOCType):
            time.sleep(0.5)
            return {"ok": True}
        
        items = [f"item{i}.com" for i in range(10)]
        job_id = self.processor.create_job(items, slow_processor)
        
        # Cancel immediately
        cancelled = self.processor.cancel_job(job_id)
        self.assertTrue(cancelled)
        
        job = self.processor.get_job_status(job_id)
        self.assertEqual(job.status, BatchStatus.CANCELLED)
    def test_context_manager(self):
        """Test context manager properly cleans up"""
        def mock_processor(value: str, ioc_type: IOCType):
            return {"ok": True}
        
        with ThreatIntelligenceBatchProcessor(max_workers=2) as proc:
            job = proc.process_batch_sync(["test.com"], mock_processor)
            self.assertEqual(len(job.results), 1)
        
        # Workers should be stopped after context exit
        self.assertEqual(len(proc._workers), 0)
    def test_explicit_ioc_types(self):
        """Test processing with explicit IOC type tuples"""
        received_types = []
        
        def mock_processor(value: str, ioc_type: IOCType):
            received_types.append((value, ioc_type))
            return {"ok": True}
        
        items = [
            ("10.0.0.1", IOCType.IP_ADDRESS),
            ("malware.exe", IOCType.FILE_HASH),
        ]
        job = self.processor.process_batch_sync(items, mock_processor)
        
        self.assertEqual(len(received_types), 2)
        self.assertEqual(received_types[0][1], IOCType.IP_ADDRESS)
        self.assertEqual(received_types[1][1], IOCType.FILE_HASH)
    def test_no_processor_error(self):
        """Test error when no processor function provided"""
        proc = ThreatIntelligenceBatchProcessor()  # No default processor
        with self.assertRaises(ValueError):
            proc.create_job(["test.com"])
        proc.shutdown()
    def test_wait_for_job_timeout(self):
        """Test timeout on wait_for_job"""
        def very_slow_processor(value: str, ioc_type: IOCType):
            time.sleep(5.0)
            return {"ok": True}
        
        job_id = self.processor.create_job(["slow.com"], very_slow_processor)
        
        with self.assertRaises(TimeoutError):
            self.processor.wait_for_job(job_id, timeout=0.5)
    def test_empty_batch(self):
        """Test processing empty item list"""
        def mock_processor(value: str, ioc_type: IOCType):
            return {"ok": True}
        
        job = self.processor.process_batch_sync([], mock_processor)
        self.assertEqual(job.total_items, 0)
        self.assertEqual(len(job.results), 0)
    def test_batch_result_attributes(self):
        """Test BatchResult has all expected fields"""
        def mock_processor(value: str, ioc_type: IOCType):
            return {"data": "test"}
        
        job = self.processor.process_batch_sync(["test-item.com"], mock_processor)
        result = job.results[0]
        
        self.assertIsNotNone(result.item_id)
        self.assertEqual(result.input_value, "test-item.com")
        self.assertIsInstance(result.ioc_type, IOCType)
        self.assertTrue(result.success)
        self.assertEqual(result.result, {"data": "test"})
        self.assertIsNone(result.error)
        self.assertGreater(result.processing_time_ms, 0)
        self.assertIsInstance(result.timestamp, float)
if __name__ == "__main__":
    print("Running Threat Intelligence Batch Processor Tests...")
    unittest.main(verbosity=2)
