#!/usr/bin/env python3
"""
Test suite for Real-Time IOC Feed Processor
Runs actual functional tests with real data
"""

import json
import os
import shutil
import tempfile
import time
from neural_shield.threat_intelligence_realtime_ioc_feed_processor_2026_june import (
    BloomFilter,
    IOCEntry,
    RealTimeIOCFeedProcessor
)
from datetime import datetime


def test_bloom_filter_basic():
    """Test basic bloom filter functionality"""
    print("=== Testing Bloom Filter Basic ===")
    
    bf = BloomFilter(expected_elements=1000, false_positive_rate=0.01)
    
    # Add some items
    test_items = ["192.168.1.1", "malicious.com", "http://bad.com/exploit"]
    for item in test_items:
        bf.add(item)
    
    # Verify they're found
    for item in test_items:
        assert bf.contains(item), f"Item {item} should be found"
        print(f"  ✓ Found: {item}")
    
    # Verify non-existent items (100% certain not found)
    non_existent = ["10.0.0.1", "safe.com", "http://good.com"]
    for item in non_existent:
        # Note: bloom filter CAN have false positives, but for these completely
        # different items, it should return False with high probability
        result = bf.contains(item)
        print(f"  Check: {item} -> {result}")
    
    print(f"  ✓ Elements added: {bf.elements_added}")
    print(f"  ✓ False positive prob: {bf.get_false_positive_probability():.6f}")
    print("  ✓ Bloom filter basic test PASSED\n")


def test_bloom_filter_save_load():
    """Test bloom filter persistence"""
    print("=== Testing Bloom Filter Save/Load ===")
    
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
        temp_path = f.name
    
    try:
        # Create and save
        bf1 = BloomFilter(1000, 0.01)
        bf1.add("test-ip-1")
        bf1.add("test-domain-2")
        bf1.save(temp_path)
        
        # Load and verify
        bf2 = BloomFilter.load(temp_path)
        assert bf2.contains("test-ip-1"), "Loaded bloom filter missing item"
        assert bf2.contains("test-domain-2"), "Loaded bloom filter missing item"
        assert bf2.elements_added == 2, "Element count mismatch"
        
        print("  ✓ Save/Load works correctly")
    finally:
        os.unlink(temp_path)
    
    print("  ✓ Bloom filter persistence test PASSED\n")


def test_ioc_entry():
    """Test IOC Entry functionality"""
    print("=== Testing IOC Entry ===")
    
    ioc = IOCEntry(
        ioc_value="192.168.1.100",
        ioc_type="ip",
        source="test-feed",
        confidence=0.95,
        threat_type="botnet",
        first_seen=datetime.now(),
        last_seen=datetime.now()
    )
    
    ioc_id = ioc.get_id()
    print(f"  ✓ IOC ID: {ioc_id}")
    print(f"  ✓ Expired: {ioc.is_expired()}")
    assert len(ioc_id) == 16, "IOC ID should be 16 chars"
    assert not ioc.is_expired(), "New IOC should not be expired"
    
    print("  ✓ IOC Entry test PASSED\n")


def test_ioc_processor_basic():
    """Test basic IOC processing"""
    print("=== Testing IOC Processor Basic ===")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        processor = RealTimeIOCFeedProcessor(data_dir=temp_dir)
        
        # Submit single IOC
        result = processor.submit_ioc(
            ioc_value="1.2.3.4",
            ioc_type="ip",
            source="test_feed",
            confidence=0.85,
            threat_type="malware"
        )
        
        print(f"  ✓ Submit result: {result['status']}")
        assert result['status'] == 'queued', "Should be queued"
        
        # Process batch
        processed = processor.process_batch()
        print(f"  ✓ Processed: {processed} IOCs")
        assert processed == 1, "Should process 1 IOC"
        
        # Check IOC lookup
        check_result = processor.check_ioc("1.2.3.4", "ip")
        print(f"  ✓ Check result: found={check_result['found']}, confidence={check_result.get('confidence', 0)}")
        assert check_result['found'], "IOC should be found"
        
        # Check statistics
        stats = processor.get_statistics()
        print(f"  ✓ Stats: received={stats['total_received']}, processed={stats['total_processed']}")
        assert stats['total_received'] == 1
        assert stats['total_processed'] == 1
        
        processor.save_state()
    
    print("  ✓ IOC Processor basic test PASSED\n")


def test_ioc_deduplication():
    """Test IOC deduplication functionality"""
    print("=== Testing IOC Deduplication ===")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        processor = RealTimeIOCFeedProcessor(data_dir=temp_dir)
        
        # Submit same IOC twice
        result1 = processor.submit_ioc("5.6.7.8", "ip", "feed1", 0.7, "phishing")
        result2 = processor.submit_ioc("5.6.7.8", "ip", "feed2", 0.9, "phishing")
        
        print(f"  ✓ First submit: {result1['status']}")
        print(f"  ✓ Second submit (duplicate): {result2['status']}")
        
        assert result1['status'] == 'queued'
        assert result2['status'] == 'duplicate', "Second submit should be deduplicated"
        
        # Verify confidence was updated to higher value
        check_result = processor.check_ioc("5.6.7.8", "ip")
        print(f"  ✓ Updated confidence: {check_result['confidence']}")
        assert check_result['confidence'] == 0.9, "Confidence should be updated to max"
        
        stats = processor.get_statistics()
        print(f"  ✓ Deduplicated count: {stats['total_deduplicated']}")
        assert stats['total_deduplicated'] == 1
    
    print("  ✓ IOC deduplication test PASSED\n")


def test_ioc_batch_processing():
    """Test batch IOC processing"""
    print("=== Testing Batch Processing ===")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        processor = RealTimeIOCFeedProcessor(data_dir=temp_dir, batch_size=10)
        
        # Submit batch of IOCs
        iocs = [
            {'ioc_value': f"10.0.0.{i}", 'ioc_type': 'ip', 'source': 'batch_test', 
             'confidence': 0.5 + i*0.05, 'threat_type': 'scan'}
            for i in range(1, 21)
        ]
        
        result = processor.submit_batch(iocs)
        print(f"  ✓ Submitted batch: {result['total_submitted']} IOCs")
        
        # Process in batches
        total_processed = 0
        for _ in range(5):
            processed = processor.process_batch()
            total_processed += processed
            if processed == 0:
                break
        
        print(f"  ✓ Total processed: {total_processed}")
        assert total_processed == 20, "Should process all 20 IOCs"
        
        stats = processor.get_statistics()
        print(f"  ✓ Batches processed: {stats['batches_processed']}")
        assert stats['batches_processed'] > 0
    
    print("  ✓ Batch processing test PASSED\n")


def test_high_risk_iocs():
    """Test high-risk IOC filtering"""
    print("=== Testing High-Risk IOC Filtering ===")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        processor = RealTimeIOCFeedProcessor(data_dir=temp_dir)
        
        # Mix of confidence levels
        test_iocs = [
            ('low1', 'ip', 0.3),
            ('med1', 'ip', 0.6),
            ('high1', 'ip', 0.85),
            ('high2', 'ip', 0.95),
            ('high3', 'ip', 0.99),
        ]
        
        for val, typ, conf in test_iocs:
            processor.submit_ioc(val, typ, 'test', conf, 'test')
        
        processor.process_batch()
        
        high_risk = processor.get_high_risk_iocs(min_confidence=0.8)
        print(f"  ✓ High-risk IOCs (>=0.8): {len(high_risk)}")
        assert len(high_risk) == 3, "Should find 3 high-risk IOCs"
        
        for ioc in high_risk:
            print(f"    - {ioc['value']}: {ioc['confidence']}")
            assert ioc['confidence'] >= 0.8
    
    print("  ✓ High-risk filtering test PASSED\n")


def test_callbacks():
    """Test callback functionality"""
    print("=== Testing Callbacks ===")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        processor = RealTimeIOCFeedProcessor(data_dir=temp_dir)
        
        callback_called = []
        batch_callback_called = []
        
        def on_new_ioc(ioc):
            callback_called.append(ioc.ioc_value)
        
        def on_batch_complete(batch):
            batch_callback_called.append(len(batch))
        
        processor.register_new_ioc_callback(on_new_ioc)
        processor.register_batch_complete_callback(on_batch_complete)
        
        # Submit and process
        processor.submit_ioc("callback-test-ip", "ip", "test", 0.9, "test")
        processor.process_batch()
        
        print(f"  ✓ New IOC callback called: {len(callback_called)} times")
        print(f"  ✓ Batch callback called with: {batch_callback_called}")
        
        assert len(callback_called) == 1
        assert len(batch_callback_called) == 1
    
    print("  ✓ Callback test PASSED\n")


def test_negative_check():
    """Test negative IOC check (definitely not found)"""
    print("=== Testing Negative IOC Check ===")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        processor = RealTimeIOCFeedProcessor(data_dir=temp_dir)
        
        # Check for IOC that was never added
        result = processor.check_ioc("this-never-existed-12345", "domain")
        print(f"  ✓ Non-existent IOC result: found={result['found']}")
        print(f"  ✓ Message: {result['message']}")
        
        # This is guaranteed 100% certain not found
        assert result['found'] == False
        assert "100% certain" in result['message']
    
    print("  ✓ Negative check test PASSED\n")


def run_all_tests():
    """Run all tests and generate report"""
    print("=" * 60)
    print("REAL-TIME IOC FEED PROCESSOR - TEST SUITE")
    print("=" * 60 + "\n")
    
    tests_passed = 0
    tests_failed = 0
    test_results = []
    
    test_functions = [
        test_bloom_filter_basic,
        test_bloom_filter_save_load,
        test_ioc_entry,
        test_ioc_processor_basic,
        test_ioc_deduplication,
        test_ioc_batch_processing,
        test_high_risk_iocs,
        test_callbacks,
        test_negative_check
    ]
    
    for test_func in test_functions:
        try:
            test_func()
            tests_passed += 1
            test_results.append((test_func.__name__, "PASSED"))
        except Exception as e:
            tests_failed += 1
            test_results.append((test_func.__name__, f"FAILED: {str(e)}"))
            print(f"  ✗ TEST FAILED: {test_func.__name__}: {e}\n")
    
    print("=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    print(f"Total Tests: {len(test_functions)}")
    print(f"Passed: {tests_passed}")
    print(f"Failed: {tests_failed}")
    print()
    
    for name, result in test_results:
        status = "✓" if "PASSED" in result else "✗"
        print(f"  {status} {name}: {result}")
    
    print()
    
    # Save results
    report = {
        'test_date': datetime.now().isoformat(),
        'total_tests': len(test_functions),
        'passed': tests_passed,
        'failed': tests_failed,
        'results': dict(test_results),
        'module': 'threat_intelligence_realtime_ioc_feed_processor'
    }
    
    with open('test_results_realtime_ioc_processor.json', 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"Results saved to: test_results_realtime_ioc_processor.json")
    
    if tests_failed == 0:
        print("\n✓ ALL TESTS PASSED!")
        return True
    else:
        print(f"\n✗ {tests_failed} TEST(S) FAILED")
        return False


if __name__ == "__main__":
    success = run_all_tests()
    exit(0 if success else 1)
