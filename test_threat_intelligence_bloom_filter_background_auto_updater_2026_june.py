#!/usr/bin/env python3
"""
Test suite for Threat Intelligence Bloom Filter Background Auto-Updater
Production-grade testing with real assertions
"""

import sys
import os
import time
import json
import tempfile
import unittest
from pathlib import Path

# Add module path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from threat_intelligence_bloom_filter_background_auto_updater_2026_june import (
    BloomFilter,
    BloomFilterBackgroundAutoUpdater,
    BloomFilterMetrics
)


class TestBloomFilter(unittest.TestCase):
    """Test core BloomFilter functionality"""
    
    def test_initialization(self):
        """Test bloom filter initializes with correct parameters"""
        bf = BloomFilter(expected_items=1000, false_positive_rate=0.01)
        
        stats = bf.get_stats()
        self.assertGreater(stats['size_bits'], 0)
        self.assertGreater(stats['hash_count'], 0)
        self.assertEqual(stats['bits_set'], 0)
        self.assertEqual(stats['estimated_count'], 0.0)
    
    def test_add_and_contains(self):
        """Test basic add and contains operations"""
        bf = BloomFilter(expected_items=1000, false_positive_rate=0.001)
        
        # Add items
        bf.add("malicious_ioc_12345")
        bf.add("suspicious_domain.com")
        bf.add("192.168.1.1:8080")
        
        # Verify contains returns True for added items
        self.assertTrue(bf.contains("malicious_ioc_12345"))
        self.assertTrue(bf.contains("suspicious_domain.com"))
        self.assertTrue(bf.contains("192.168.1.1:8080"))
        
        # Verify contains returns False for non-added items
        self.assertFalse(bf.contains("legitimate_domain.com"))
        self.assertFalse(bf.contains("unknown_ioc_99999"))
    
    def test_batch_add(self):
        """Test batch addition of items"""
        bf = BloomFilter(expected_items=10000, false_positive_rate=0.001)
        
        signatures = [f"threat_signature_{i}" for i in range(100)]
        count = bf.add_batch(signatures)
        
        self.assertEqual(count, 100)
        
        # Verify all were added
        for sig in signatures:
            self.assertTrue(bf.contains(sig))
        
        stats = bf.get_stats()
        self.assertGreater(stats['estimated_count'], 90)
    
    def test_estimate_count(self):
        """Test count estimation is reasonably accurate"""
        bf = BloomFilter(expected_items=10000, false_positive_rate=0.001)
        
        for i in range(500):
            bf.add(f"test_item_{i}")
        
        estimate = bf.estimate_count()
        # Should be within reasonable range
        self.assertGreater(estimate, 400)
        self.assertLess(estimate, 600)
    
    def test_clear(self):
        """Test clearing the bloom filter"""
        bf = BloomFilter(expected_items=1000, false_positive_rate=0.01)
        
        bf.add("test_item")
        self.assertTrue(bf.contains("test_item"))
        
        bf.clear()
        self.assertFalse(bf.contains("test_item"))
        self.assertEqual(bf.estimate_count(), 0.0)
    
    def test_thread_safety(self):
        """Test concurrent access doesn't crash"""
        import threading
        
        bf = BloomFilter(expected_items=10000, false_positive_rate=0.001)
        errors = []
        
        def writer():
            try:
                for i in range(100):
                    bf.add(f"writer_item_{i}")
            except Exception as e:
                errors.append(e)
        
        def reader():
            try:
                for i in range(100):
                    bf.contains(f"some_item_{i}")
            except Exception as e:
                errors.append(e)
        
        threads = []
        for _ in range(5):
            t1 = threading.Thread(target=writer)
            t2 = threading.Thread(target=reader)
            threads.extend([t1, t2])
        
        for t in threads:
            t.start()
        
        for t in threads:
            t.join()
        
        self.assertEqual(len(errors), 0)


class TestBloomFilterBackgroundAutoUpdater(unittest.TestCase):
    """Test background auto-updater functionality"""
    
    def test_initialization(self):
        """Test auto-updater initializes correctly"""
        updater = BloomFilterBackgroundAutoUpdater(
            refresh_interval_seconds=60,
            batch_size=500,
            expected_signatures=10000
        )
        
        self.assertFalse(updater.is_running())
        status = updater.get_status()
        self.assertEqual(status['metrics']['total_signatures'], 0)
        self.assertEqual(status['metrics']['update_count'], 0)
        self.assertFalse(status['is_running'])
    
    def test_add_signature(self):
        """Test adding signatures to queue"""
        updater = BloomFilterBackgroundAutoUpdater(refresh_interval_seconds=1)
        
        updater.add_signature("malware_hash_abc123")
        updater.add_signature("phishing_domain.test")
        
        status = updater.get_status()
        self.assertEqual(status['metrics']['queue_size'], 2)
    
    def test_add_signatures_batch(self):
        """Test batch signature addition"""
        updater = BloomFilterBackgroundAutoUpdater(refresh_interval_seconds=1)
        
        signatures = [f"ioc_{i}" for i in range(50)]
        count = updater.add_signatures_batch(signatures)
        
        self.assertEqual(count, 50)
        status = updater.get_status()
        self.assertEqual(status['metrics']['queue_size'], 50)
    
    def test_start_stop(self):
        """Test starting and stopping background thread"""
        updater = BloomFilterBackgroundAutoUpdater(refresh_interval_seconds=1)
        
        # Start
        started = updater.start()
        self.assertTrue(started)
        self.assertTrue(updater.is_running())
        
        # Give thread time to start
        time.sleep(0.1)
        
        # Stop
        stopped = updater.stop(wait=True, timeout=5)
        self.assertTrue(stopped)
        self.assertFalse(updater.is_running())
    
    def test_background_processing(self):
        """Test background thread processes queued signatures"""
        updater = BloomFilterBackgroundAutoUpdater(
            refresh_interval_seconds=0.5,
            batch_size=100
        )
        
        # Add signatures
        signatures = [f"threat_{i}" for i in range(20)]
        updater.add_signatures_batch(signatures)
        
        # Start background processing
        updater.start()
        
        # Wait for processing
        time.sleep(1.5)
        
        # Verify signatures were processed
        for sig in signatures:
            self.assertTrue(updater.check_threat(sig))
        
        status = updater.get_status()
        self.assertGreater(status['metrics']['update_count'], 0)
        self.assertEqual(status['metrics']['queue_size'], 0)
        
        updater.stop()
    
    def test_check_threat(self):
        """Test threat detection works correctly"""
        updater = BloomFilterBackgroundAutoUpdater()
        
        # Add directly to bloom filter for testing
        updater.bloom_filter.add("known_malicious_hash")
        updater.bloom_filter.add("suspicious_ip_address")
        
        # Positive matches
        self.assertTrue(updater.check_threat("known_malicious_hash"))
        self.assertTrue(updater.check_threat("SUSPICIOUS_IP_ADDRESS"))  # Case insensitive
        self.assertTrue(updater.check_threat("  known_malicious_hash  "))  # Whitespace
        
        # Negative matches
        self.assertFalse(updater.check_threat("benign_hash"))
        self.assertFalse(updater.check_threat(""))
        self.assertFalse(updater.check_threat(None))
    
    def test_context_manager(self):
        """Test context manager works correctly"""
        with BloomFilterBackgroundAutoUpdater(refresh_interval_seconds=1) as updater:
            self.assertTrue(updater.is_running())
            updater.add_signature("test_ioc")
            time.sleep(0.5)
        
        # After exit, should be stopped
        self.assertFalse(updater.is_running())
    
    def test_callback_registration(self):
        """Test update callbacks are triggered"""
        callback_results = []
        
        def my_callback(status):
            callback_results.append(status)
        
        updater = BloomFilterBackgroundAutoUpdater(refresh_interval_seconds=0.5)
        updater.register_update_callback(my_callback)
        
        updater.add_signature("callback_test_ioc")
        updater.start()
        
        time.sleep(1.0)
        
        updater.stop()
        
        # Should have received at least one callback
        self.assertGreater(len(callback_results), 0)
        self.assertIn('metrics', callback_results[0])
    
    def test_persistence(self):
        """Test state persistence works"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            persist_path = f.name
        
        try:
            updater = BloomFilterBackgroundAutoUpdater(
                refresh_interval_seconds=0.5,
                persistence_path=persist_path
            )
            
            updater.add_signature("persisted_threat")
            updater.start()
            time.sleep(1.0)
            updater.stop()
            
            # Verify file was created and has content
            self.assertTrue(os.path.exists(persist_path))
            
            with open(persist_path) as f:
                state = json.load(f)
            
            self.assertIn('metrics', state)
            self.assertIn('bloom_filter_stats', state)
            
        finally:
            if os.path.exists(persist_path):
                os.unlink(persist_path)
    
    def test_empty_signatures_ignored(self):
        """Test empty/whitespace signatures are not added"""
        updater = BloomFilterBackgroundAutoUpdater()
        
        updater.add_signature("")
        updater.add_signature("   ")
        updater.add_signature(None)
        
        status = updater.get_status()
        self.assertEqual(status['metrics']['queue_size'], 0)


def run_integration_test():
    """Run full integration test"""
    print("\n=== Running Integration Test ===")
    
    results = {
        'tests_passed': 0,
        'tests_failed': 0,
        'test_results': {}
    }
    
    # Test 1: Full lifecycle test
    try:
        print("Test 1: Full lifecycle with background processing")
        
        updater = BloomFilterBackgroundAutoUpdater(
            refresh_interval_seconds=0.3,
            batch_size=100,
            expected_signatures=10000
        )
        
        # Add realistic threat signatures
        real_signatures = [
            "192.168.1.100",
            "malware.exe",
            "phishing@test.com",
            "http://evil.com/payload",
            "d41d8cd98f00b204e9800998ecf8427e",
            "suspicious_domain:443",
            "CVE-2026-0001",
            "ransomware_string_pattern"
        ]
        
        count = updater.add_signatures_batch(real_signatures)
        print(f"  - Added {count} signatures to queue")
        
        updater.start()
        print("  - Background thread started")
        
        time.sleep(1.0)
        
        # Verify detection
        detected = 0
        for sig in real_signatures:
            if updater.check_threat(sig):
                detected += 1
        
        print(f"  - Detected {detected}/{len(real_signatures)} signatures")
        
        status = updater.get_status()
        print(f"  - Total signatures processed: {status['metrics']['update_count']}")
        print(f"  - Queue size: {status['metrics']['queue_size']}")
        
        updater.stop()
        print("  - Background thread stopped")
        
        assert detected == len(real_signatures), "Not all signatures detected"
        
        results['tests_passed'] += 1
        results['test_results']['full_lifecycle'] = 'PASSED'
        print("  ✓ PASSED")
        
    except Exception as e:
        results['tests_failed'] += 1
        results['test_results']['full_lifecycle'] = f'FAILED: {e}'
        print(f"  ✗ FAILED: {e}")
    
    # Test 2: Performance test
    try:
        print("\nTest 2: Performance with large signature set")
        
        bf = BloomFilter(expected_items=100000, false_positive_rate=0.001)
        
        start = time.time()
        for i in range(10000):
            bf.add(f"performance_test_{i}")
        add_time = time.time() - start
        
        start = time.time()
        hits = 0
        for i in range(10000):
            if bf.contains(f"performance_test_{i}"):
                hits += 1
        check_time = time.time() - start
        
        print(f"  - Added 10,000 items in {add_time*1000:.2f}ms")
        print(f"  - Checked 10,000 items in {check_time*1000:.2f}ms")
        print(f"  - Detection rate: {hits}/10000")
        print(f"  - Memory used: {bf.get_stats()['size_bytes']} bytes")
        
        assert hits == 10000, "Performance test detection failed"
        
        results['tests_passed'] += 1
        results['test_results']['performance'] = 'PASSED'
        print("  ✓ PASSED")
        
    except Exception as e:
        results['tests_failed'] += 1
        results['test_results']['performance'] = f'FAILED: {e}'
        print(f"  ✗ FAILED: {e}")
    
    # Test 3: False positive rate verification
    try:
        print("\nTest 3: False positive rate verification")
        
        bf = BloomFilter(expected_items=10000, false_positive_rate=0.01)
        
        # Add 5000 items
        for i in range(5000):
            bf.add(f"fp_test_{i}")
        
        # Test 10000 random items not in set
        false_positives = 0
        for i in range(10000):
            if bf.contains(f"not_present_{i}"):
                false_positives += 1
        
        fpr = false_positives / 10000
        print(f"  - False positives: {false_positives}/10000")
        print(f"  - Actual FPR: {fpr:.4f} (target: 0.01)")
        
        # Should be reasonably close to target
        assert fpr < 0.05, f"FPR too high: {fpr}"
        
        results['tests_passed'] += 1
        results['test_results']['fpr_verification'] = 'PASSED'
        print("  ✓ PASSED")
        
    except Exception as e:
        results['tests_failed'] += 1
        results['test_results']['fpr_verification'] = f'FAILED: {e}'
        print(f"  ✗ FAILED: {e}")
    
    return results


def main():
    """Run all tests"""
    print("=" * 60)
    print("Bloom Filter Background Auto-Updater - Test Suite")
    print("=" * 60)
    
    # Run unit tests
    print("\n=== Running Unit Tests ===")
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    suite.addTests(loader.loadTestsFromTestCase(TestBloomFilter))
    suite.addTests(loader.loadTestsFromTestCase(TestBloomFilterBackgroundAutoUpdater))
    
    runner = unittest.TextTestRunner(verbosity=2)
    unit_results = runner.run(suite)
    
    # Run integration tests
    integration_results = run_integration_test()
    
    # Save results
    final_results = {
        'unit_tests': {
            'tests_run': unit_results.testsRun,
            'failures': len(unit_results.failures),
            'errors': len(unit_results.errors),
            'was_successful': unit_results.wasSuccessful()
        },
        'integration_tests': integration_results,
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
    }
    
    with open('test_results_bloom_filter_auto_updater.json', 'w') as f:
        json.dump(final_results, f, indent=2)
    
    # Summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    print(f"Unit Tests: {unit_results.testsRun} run")
    print(f"  - Failures: {len(unit_results.failures)}")
    print(f"  - Errors: {len(unit_results.errors)}")
    print(f"Integration Tests: {integration_results['tests_passed']} passed, {integration_results['tests_failed']} failed")
    print("=" * 60)
    
    # Return exit code
    return 0 if unit_results.wasSuccessful() and integration_results['tests_failed'] == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
