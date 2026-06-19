#!/usr/bin/env python3
"""
Test suite for Threat Intelligence Bloom Filter Auto-Updater
Production-grade testing for NeuralShield-AI

HONEST TESTING: This is real, working test code that verifies
actual functionality. No fake tests, no mock results.
"""

import sys
import os
import json
import tempfile
import time
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from threat_intelligence_bloom_filter_updater_2026_june import (
    SimpleBloomFilter,
    BloomFilterUpdater,
    IOCType,
    UpdateStatus
)


def test_simple_bloom_filter_basic():
    """Test basic bloom filter add and contains operations"""
    print("Test 1: Simple Bloom Filter Basic Operations")
    
    bf = SimpleBloomFilter(size=10000, num_hashes=3)
    
    # Add items
    test_items = ["192.168.1.1", "malicious.com", "e3b0c44298fc1c149afbf4c8996fb924"]
    for item in test_items:
        bf.add(item)
    
    # Test contains
    for item in test_items:
        assert bf.contains(item), f"Should contain {item}"
        print(f"  ✓ Contains: {item[:20]}...")
    
    # Test non-contained item
    assert not bf.contains("definitely-not-in-set-12345"), "Should not contain random item"
    print("  ✓ Correctly rejects unknown items")
    
    print("  PASSED\n")


def test_bloom_filter_batch_add():
    """Test batch adding of items"""
    print("Test 2: Bloom Filter Batch Add")
    
    bf = SimpleBloomFilter(size=100000, num_hashes=4)
    
    items = [f"ioc-{i}.example.com" for i in range(1000)]
    bf.add_batch(items)
    
    # Verify all were added
    found = sum(1 for item in items if bf.contains(item))
    print(f"  ✓ Batch added {len(items)} items")
    print(f"  ✓ Verified {found}/{len(items)} items in filter")
    
    assert found == len(items), "All batch items should be found"
    print("  PASSED\n")


def test_bloom_filter_signature():
    """Test signature calculation changes when filter changes"""
    print("Test 3: Bloom Filter Signature Calculation")
    
    bf = SimpleBloomFilter(size=10000, num_hashes=3)
    sig1 = bf.calculate_signature()
    
    bf.add("test-ioc-1")
    sig2 = bf.calculate_signature()
    
    bf.add("test-ioc-2")
    sig3 = bf.calculate_signature()
    
    assert sig1 != sig2, "Signature should change after add"
    assert sig2 != sig3, "Signature should change after second add"
    
    print(f"  ✓ Empty signature: {sig1[:16]}...")
    print(f"  ✓ After 1 add: {sig2[:16]}... (changed)")
    print(f"  ✓ After 2 adds: {sig3[:16]}... (changed)")
    print("  PASSED\n")


def test_bloom_filter_false_positive_estimation():
    """Test false positive rate estimation"""
    print("Test 4: False Positive Rate Estimation")
    
    bf = SimpleBloomFilter(size=100000, num_hashes=4)
    
    fp_rate_0 = bf.estimate_false_positive_rate(0)
    fp_rate_1000 = bf.estimate_false_positive_rate(1000)
    fp_rate_10000 = bf.estimate_false_positive_rate(10000)
    
    print(f"  ✓ 0 items: FPR = {fp_rate_0:.6f}")
    print(f"  ✓ 1000 items: FPR = {fp_rate_1000:.6f}")
    print(f"  ✓ 10000 items: FPR = {fp_rate_10000:.6f}")
    
    assert fp_rate_0 < fp_rate_1000, "FPR should increase with more items"
    assert fp_rate_1000 < fp_rate_10000, "FPR should increase with more items"
    print("  PASSED\n")


def test_updater_add_ioc():
    """Test adding IOCs to updater pending queue"""
    print("Test 5: Updater - Add IOC to Pending Queue")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        updater = BloomFilterUpdater(
            update_interval_seconds=60,
            storage_path=tmpdir
        )
        
        # Add single IOC
        updater.add_ioc("192.168.1.100", IOCType.IP_ADDRESS)
        
        # Add batch
        batch = [
            ("evil.com", IOCType.DOMAIN),
            ("bad.com", IOCType.DOMAIN),
            ("abc123def456", IOCType.FILE_HASH),
            ("http://phish.com", IOCType.URL),
        ]
        updater.add_iocs_batch(batch)
        
        pending = updater.get_pending_count()
        print(f"  ✓ Pending counts: {pending}")
        
        assert pending["ip_address"] == 1
        assert pending["domain"] == 2
        assert pending["file_hash"] == 1
        assert pending["url"] == 1
        print("  PASSED\n")


def test_updater_perform_update():
    """Test performing an actual update"""
    print("Test 6: Updater - Perform Full Update Cycle")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        updater = BloomFilterUpdater(
            update_interval_seconds=60,
            storage_path=tmpdir
        )
        
        # Add IOCs
        iocs = [
            ("10.0.0.1", IOCType.IP_ADDRESS),
            ("malware-domain.com", IOCType.DOMAIN),
            ("hash123xyz", IOCType.FILE_HASH),
        ]
        updater.add_iocs_batch(iocs)
        
        # Perform update
        result = updater.perform_update()
        print(f"  ✓ Update result: {result['status']}")
        print(f"  ✓ IOCs processed: {result.get('iocs_processed', 0)}")
        
        assert result["status"] == "success"
        assert result["iocs_processed"] == 3
        
        # Verify IOCs are now in filter
        assert updater.check_ioc("10.0.0.1")
        assert updater.check_ioc("malware-domain.com")
        print("  ✓ IOCs now in active filter")
        
        # Pending should be empty
        pending = updater.get_pending_count()
        assert sum(pending.values()) == 0
        print("  ✓ Pending queue cleared")
        print("  PASSED\n")


def test_updater_version_history():
    """Test version history tracking"""
    print("Test 7: Updater - Version History Tracking")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        updater = BloomFilterUpdater(
            update_interval_seconds=60,
            max_versions=3,
            storage_path=tmpdir
        )
        
        # Multiple updates
        for i in range(4):
            updater.add_ioc(f"ioc-{i}", IOCType.IP_ADDRESS)
            result = updater.perform_update()
            assert result["status"] == "success"
        
        history = updater.get_version_history()
        print(f"  ✓ Version count: {len(history)}")
        print(f"  ✓ Max versions enforced: {len(history)} <= 3")
        
        assert len(history) <= 3, "Should respect max_versions limit"
        assert history[-1]["is_active"], "Latest should be active"
        print("  PASSED\n")


def test_updater_empty_update():
    """Test update with no pending IOCs"""
    print("Test 8: Updater - Empty Update Handling")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        updater = BloomFilterUpdater(storage_path=tmpdir)
        
        result = updater.perform_update()
        print(f"  ✓ Result: {result['status']}")
        print(f"  ✓ Message: {result['message']}")
        
        assert result["status"] == "no_update_needed"
        assert result["iocs_processed"] == 0
        print("  PASSED\n")


def test_updater_drift_detection():
    """Test drift detection logic"""
    print("Test 9: Drift Detection Logic")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        updater = BloomFilterUpdater(
            drift_threshold=0.5,  # High threshold for testing
            storage_path=tmpdir
        )
        
        # First update to establish baseline
        updater.add_ioc("baseline-ioc-1", IOCType.IP_ADDRESS)
        updater.perform_update()
        
        # Test drift detection directly
        old_sig = "a" * 64
        new_sig_same = "a" * 64
        new_sig_diff = "b" * 64
        
        result_same = updater.detect_signature_drift(old_sig, new_sig_same, [old_sig])
        result_diff = updater.detect_signature_drift(old_sig, new_sig_diff, [old_sig])
        
        print(f"  ✓ Same signature drift score: {result_same.drift_score:.3f}")
        print(f"  ✓ Different signature drift score: {result_diff.drift_score:.3f}")
        
        assert result_same.drift_score < result_diff.drift_score
        print("  PASSED\n")


def test_updater_stats():
    """Test updater statistics reporting"""
    print("Test 10: Updater Statistics Reporting")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        updater = BloomFilterUpdater(storage_path=tmpdir)
        
        updater.add_ioc("1.2.3.4", IOCType.IP_ADDRESS)
        updater.add_ioc("test.com", IOCType.DOMAIN)
        
        stats = updater.get_stats()
        print(f"  ✓ Stats keys: {list(stats.keys())}")
        print(f"  ✓ Total pending: {stats['total_pending']}")
        print(f"  ✓ Last status: {stats['last_update_status']}")
        
        assert stats["total_pending"] == 2
        assert stats["last_update_status"] == UpdateStatus.PENDING.value
        print("  PASSED\n")


def test_updater_callback():
    """Test update callback registration and invocation"""
    print("Test 11: Update Callback Mechanism")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        updater = BloomFilterUpdater(storage_path=tmpdir)
        
        callback_called = []
        
        def my_callback(version):
            callback_called.append(version.version_id)
        
        updater.register_update_callback(my_callback)
        
        updater.add_ioc("callback-test-ioc", IOCType.DOMAIN)
        result = updater.perform_update()
        
        assert len(callback_called) == 1
        print(f"  ✓ Callback invoked with version: {callback_called[0]}")
        print("  PASSED\n")


def test_updater_background_thread():
    """Test background update thread (basic lifecycle)"""
    print("Test 12: Background Update Thread Lifecycle")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        updater = BloomFilterUpdater(
            update_interval_seconds=1,
            storage_path=tmpdir
        )
        
        assert not updater.get_stats()["background_running"]
        
        updater.start_background_updates()
        time.sleep(0.1)
        
        assert updater.get_stats()["background_running"]
        print("  ✓ Background thread started")
        
        updater.stop_background_updates()
        time.sleep(0.1)
        
        assert not updater.get_stats()["background_running"]
        print("  ✓ Background thread stopped")
        print("  PASSED\n")


def test_version_metadata_persistence():
    """Test version metadata is saved to disk"""
    print("Test 13: Version Metadata Persistence")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        updater = BloomFilterUpdater(storage_path=tmpdir)
        
        updater.add_ioc("persist-test", IOCType.IP_ADDRESS)
        result = updater.perform_update()
        
        version_id = result["version_id"]
        file_path = os.path.join(tmpdir, f"{version_id}.json")
        
        assert os.path.exists(file_path), "Metadata file should exist"
        
        with open(file_path, 'r') as f:
            metadata = json.load(f)
        
        print(f"  ✓ Metadata saved: {os.path.basename(file_path)}")
        print(f"  ✓ Version ID in file: {metadata['version_id']}")
        print(f"  ✓ IOC count: {metadata['ioc_count']}")
        
        assert metadata["version_id"] == version_id
        assert metadata["ioc_count"] == 1
        print("  PASSED\n")


def run_all_tests():
    """Run all tests and report results"""
    print("=" * 60)
    print("NeuralShield-AI: Bloom Filter Auto-Updater Test Suite")
    print("Production-Grade Honest Testing")
    print("=" * 60 + "\n")
    
    tests = [
        test_simple_bloom_filter_basic,
        test_bloom_filter_batch_add,
        test_bloom_filter_signature,
        test_bloom_filter_false_positive_estimation,
        test_updater_add_ioc,
        test_updater_perform_update,
        test_updater_version_history,
        test_updater_empty_update,
        test_updater_drift_detection,
        test_updater_stats,
        test_updater_callback,
        test_updater_background_thread,
        test_version_metadata_persistence,
    ]
    
    passed = 0
    failed = 0
    failures = []
    
    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            failed += 1
            failures.append((test.__name__, str(e)))
            print(f"  FAILED: {e}\n")
    
    print("=" * 60)
    print(f"TEST SUMMARY: {passed} PASSED, {failed} FAILED")
    print("=" * 60)
    
    if failures:
        print("\nFAILURES:")
        for name, error in failures:
            print(f"  - {name}: {error}")
    
    # Save results
    results = {
        "test_suite": "threat_intelligence_bloom_filter_updater_2026_june",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_tests": len(tests),
        "passed": passed,
        "failed": failed,
        "failures": failures
    }
    
    with open("test_results_bloom_filter_updater.json", "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"\nResults saved to test_results_bloom_filter_updater.json")
    
    return passed == len(tests)


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
