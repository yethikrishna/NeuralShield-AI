#!/usr/bin/env python3
"""
Test Suite for Threat Intelligence IOC Batch Deduplication Enhanced Cache Optimizer
NeuralShield-AI Production Grade Tests

Comprehensive tests covering:
1. Basic deduplication functionality
2. IOC type detection and normalization
3. Enrichment caching behavior
4. Temporal decay functionality
5. Batch processing performance
6. Edge cases and error handling
7. Statistics and metrics
"""
import json
import time
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from neural_shield.threat_intelligence_ioc_batch_deduplication_enhanced_cache_2026_june import (
    IOCBatchDeduplicationCacheOptimizer,
    IOCType,
    DeduplicationLevel,
    IOCNormalizer,
    IOCFingerprintGenerator,
    TemporalDecayEngine,
    BatchProcessorConfig
)


def run_tests():
    """Execute all tests and generate results report"""
    test_results = {
        "test_suite": "IOC Batch Deduplication Enhanced Cache Optimizer",
        "timestamp": time.time(),
        "tests_passed": 0,
        "tests_failed": 0,
        "test_cases": {},
        "performance_metrics": {}
    }
    
    print("=" * 70)
    print("NeuralShield-AI: IOC Batch Deduplication Enhanced Cache Tests")
    print("=" * 70)
    
    # Test 1: IOC Normalization
    print("\n[Test 1] IOC Normalization")
    try:
        # Domain normalization
        domain_norm = IOCNormalizer.normalize("EXAMPLE.COM.", IOCType.DOMAIN)
        assert domain_norm == "example.com", f"Expected 'example.com', got '{domain_norm}'"
        
        # Hash normalization
        hash_norm = IOCNormalizer.normalize("A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4", IOCType.MD5)
        assert hash_norm == "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4", f"Hash normalization failed"
        
        # IP normalization
        ip_norm = IOCNormalizer.normalize("192.168.001.001", IOCType.IPV4)
        assert ip_norm == "192.168.1.1", f"IP normalization failed: {ip_norm}"
        
        print("  ✓ IOC normalization working correctly")
        test_results["tests_passed"] += 1
        test_results["test_cases"]["ioc_normalization"] = "PASSED"
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results["tests_failed"] += 1
        test_results["test_cases"]["ioc_normalization"] = f"FAILED: {str(e)}"
    
    # Test 2: IOC Type Detection
    print("\n[Test 2] IOC Type Detection")
    try:
        assert IOCNormalizer.detect_type("192.168.1.1") == IOCType.IPV4
        assert IOCNormalizer.detect_type("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4") == IOCType.MD5
        assert IOCNormalizer.detect_type("https://example.com/path") == IOCType.URL
        assert IOCNormalizer.detect_type("user@example.com") == IOCType.EMAIL
        assert IOCNormalizer.detect_type("example.com") == IOCType.DOMAIN
        
        print("  ✓ IOC type detection working correctly")
        test_results["tests_passed"] += 1
        test_results["test_cases"]["ioc_type_detection"] = "PASSED"
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results["tests_failed"] += 1
        test_results["test_cases"]["ioc_type_detection"] = f"FAILED: {str(e)}"
    
    # Test 3: Fingerprint Generation
    print("\n[Test 3] Fingerprint Generation")
    try:
        fp1 = IOCFingerprintGenerator.generate_fingerprint("example.com", IOCType.DOMAIN, DeduplicationLevel.NORMALIZED)
        fp2 = IOCFingerprintGenerator.generate_fingerprint("EXAMPLE.COM", IOCType.DOMAIN, DeduplicationLevel.NORMALIZED)
        assert fp1 == fp2, "Normalized fingerprints should match"
        
        fp3 = IOCFingerprintGenerator.generate_fingerprint("example.com", IOCType.DOMAIN, DeduplicationLevel.EXACT)
        fp4 = IOCFingerprintGenerator.generate_fingerprint("EXAMPLE.COM", IOCType.DOMAIN, DeduplicationLevel.EXACT)
        assert fp3 != fp4, "Exact fingerprints should differ for case differences"
        
        print("  ✓ Fingerprint generation working correctly")
        test_results["tests_passed"] += 1
        test_results["test_cases"]["fingerprint_generation"] = "PASSED"
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results["tests_failed"] += 1
        test_results["test_cases"]["fingerprint_generation"] = f"FAILED: {str(e)}"
    
    # Test 4: Temporal Decay Engine
    print("\n[Test 4] Temporal Decay Engine")
    try:
        decay = TemporalDecayEngine(half_life_hours=1.0)
        
        # Fresh IOC should have high relevance
        relevance = decay.calculate_relevance_score(time.time())
        assert relevance > 0.99, f"Fresh relevance too low: {relevance}"
        
        # Should consider duplicates within threshold
        assert decay.should_consider_duplicate(time.time(), time.time()) == True
        
        print("  ✓ Temporal decay engine working correctly")
        test_results["tests_passed"] += 1
        test_results["test_cases"]["temporal_decay"] = "PASSED"
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results["tests_failed"] += 1
        test_results["test_cases"]["temporal_decay"] = f"FAILED: {str(e)}"
    
    # Test 5: Basic Batch Deduplication
    print("\n[Test 5] Basic Batch Deduplication")
    try:
        config = BatchProcessorConfig(enable_concurrent_processing=False)
        processor = IOCBatchDeduplicationCacheOptimizer(config)
        
        # Test with duplicates
        test_iocs = [
            "192.168.1.1",
            "192.168.1.1",  # Duplicate
            "example.com",
            "EXAMPLE.COM",  # Should normalize to same
            "https://test.com/path",
            "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
        ]
        
        result = processor.process_batch(test_iocs, deduplication_level=DeduplicationLevel.NORMALIZED)
        
        assert result.total_input_count == 6, f"Expected 6 inputs, got {result.total_input_count}"
        assert result.unique_count == 4, f"Expected 4 unique, got {result.unique_count}"
        assert result.duplicate_count == 2, f"Expected 2 duplicates, got {result.duplicate_count}"
        assert result.deduplication_rate > 0, "Deduplication rate should be positive"
        
        print(f"  ✓ Batch deduplication: {result.duplicate_count} duplicates removed from {result.total_input_count} inputs")
        print(f"    Deduplication rate: {result.deduplication_rate * 100:.1f}%")
        print(f"    Processing time: {result.processing_time_seconds * 1000:.2f}ms")
        
        test_results["tests_passed"] += 1
        test_results["test_cases"]["basic_deduplication"] = "PASSED"
        test_results["performance_metrics"]["basic_processing_ms"] = result.processing_time_seconds * 1000
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results["tests_failed"] += 1
        test_results["test_cases"]["basic_deduplication"] = f"FAILED: {str(e)}"
    
    # Test 6: Enrichment Caching
    print("\n[Test 6] Enrichment Caching")
    try:
        config = BatchProcessorConfig(enable_concurrent_processing=False)
        processor = IOCBatchDeduplicationCacheOptimizer(config)
        
        # Cache an enrichment result
        enrichment_data = {
            "malicious": True,
            "threat_score": 85,
            "source": "virustotal",
            "detections": 15
        }
        
        cache_key = processor.cache_enrichment_result(
            "192.168.1.1", "ipv4", enrichment_data, ttl_seconds=3600
        )
        
        # Retrieve cached data
        cached = processor.get_cached_enrichment("192.168.1.1", IOCType.IPV4)
        assert cached is not None, "Should retrieve cached enrichment"
        assert cached["malicious"] == True, "Cached data mismatch"
        assert cached["threat_score"] == 85, "Cached data mismatch"
        
        # Process batch with enrichment cache hits
        test_iocs = ["192.168.1.1", "10.0.0.1"]
        result = processor.process_batch(test_iocs)
        
        assert result.enrichment_cache_hits == 1, f"Expected 1 cache hit, got {result.enrichment_cache_hits}"
        assert result.enrichment_cache_misses == 1, f"Expected 1 cache miss, got {result.enrichment_cache_misses}"
        
        print(f"  ✓ Enrichment caching: {result.enrichment_cache_hits} hits, {result.enrichment_cache_misses} misses")
        test_results["tests_passed"] += 1
        test_results["test_cases"]["enrichment_caching"] = "PASSED"
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results["tests_failed"] += 1
        test_results["test_cases"]["enrichment_caching"] = f"FAILED: {str(e)}"
    
    # Test 7: Dictionary Input with Metadata
    print("\n[Test 7] Dictionary Input with Metadata")
    try:
        config = BatchProcessorConfig(enable_concurrent_processing=False)
        processor = IOCBatchDeduplicationCacheOptimizer(config)
        
        test_iocs = [
            {"value": "192.168.1.1", "type": "ipv4", "source": "honeypot", "confidence": 0.95},
            {"value": "example.com", "type": "domain", "source": "dns_logs"},
            {"value": "192.168.1.1", "type": "ipv4", "source": "firewall"}  # Duplicate
        ]
        
        result = processor.process_batch(test_iocs, auto_detect_types=False)
        
        assert result.total_input_count == 3
        assert result.duplicate_count == 1
        
        # Check metadata preserved
        for ioc in result.deduplicated_iocs:
            if ioc.value == "192.168.1.1":
                assert ioc.source == "honeypot"
                assert ioc.confidence == 0.95
        
        print("  ✓ Dictionary input with metadata working correctly")
        test_results["tests_passed"] += 1
        test_results["test_cases"]["dict_input_metadata"] = "PASSED"
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results["tests_failed"] += 1
        test_results["test_cases"]["dict_input_metadata"] = f"FAILED: {str(e)}"
    
    # Test 8: Statistics Tracking
    print("\n[Test 8] Statistics Tracking")
    try:
        config = BatchProcessorConfig(enable_concurrent_processing=False)
        processor = IOCBatchDeduplicationCacheOptimizer(config)
        
        # Process multiple batches
        for i in range(5):
            processor.process_batch([f"10.0.0.{i}", f"10.0.0.{i+1}"])
        
        stats = processor.get_statistics()
        
        assert stats["total_batches_processed"] == 5
        assert stats["total_iocs_processed"] == 10
        assert stats["total_duplicates_removed"] >= 0
        assert "average_processing_time_ms" in stats
        assert "cache_hit_rate_percent" in stats
        
        print(f"  ✓ Statistics tracking: {stats['total_batches_processed']} batches processed")
        print(f"    Avg processing time: {stats['average_processing_time_ms']:.2f}ms")
        
        test_results["tests_passed"] += 1
        test_results["test_cases"]["statistics_tracking"] = "PASSED"
        test_results["performance_metrics"]["avg_processing_ms"] = stats["average_processing_time_ms"]
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results["tests_failed"] += 1
        test_results["test_cases"]["statistics_tracking"] = f"FAILED: {str(e)}"
    
    # Test 9: Input Validation and Error Handling
    print("\n[Test 9] Input Validation and Error Handling")
    try:
        config = BatchProcessorConfig(enable_concurrent_processing=False)
        processor = IOCBatchDeduplicationCacheOptimizer(config)
        
        test_iocs = [
            "192.168.1.1",
            "",  # Empty - should be skipped
            None,  # None - should be skipped
            "x" * 5000  # Too long - should be skipped
        ]
        
        result = processor.process_batch(test_iocs)
        
        assert len(result.warnings) >= 2, f"Expected warnings for invalid inputs"
        assert result.total_input_count == 1, f"Only valid IOC should count: {result.total_input_count}"
        
        print(f"  ✓ Input validation: {len(result.warnings)} warnings generated correctly")
        test_results["tests_passed"] += 1
        test_results["test_cases"]["input_validation"] = "PASSED"
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results["tests_failed"] += 1
        test_results["test_cases"]["input_validation"] = f"FAILED: {str(e)}"
    
    # Test 10: Large Batch Performance
    print("\n[Test 10] Large Batch Performance")
    try:
        config = BatchProcessorConfig(enable_concurrent_processing=False)
        processor = IOCBatchDeduplicationCacheOptimizer(config)
        
        # Generate 1000 IOCs with some duplicates
        large_batch = []
        for i in range(1000):
            large_batch.append(f"192.168.{i//256}.{i%256}")
            if i % 5 == 0:  # Add duplicates
                large_batch.append(f"192.168.{i//256}.{i%256}")
        
        start = time.time()
        result = processor.process_batch(large_batch)
        elapsed = time.time() - start
        
        throughput = len(large_batch) / elapsed if elapsed > 0 else 0
        
        assert result.total_input_count > 0
        assert result.processing_time_seconds > 0
        
        print(f"  ✓ Large batch performance: {result.total_input_count} IOCs in {elapsed*1000:.1f}ms")
        print(f"    Throughput: {throughput:.0f} IOCs/second")
        print(f"    Deduplication rate: {result.deduplication_rate * 100:.1f}%")
        
        test_results["tests_passed"] += 1
        test_results["test_cases"]["large_batch_performance"] = "PASSED"
        test_results["performance_metrics"]["throughput_iocs_per_sec"] = round(throughput, 0)
        test_results["performance_metrics"]["large_batch_ms"] = elapsed * 1000
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results["tests_failed"] += 1
        test_results["test_cases"]["large_batch_performance"] = f"FAILED: {str(e)}"
    
    # Test 11: Cache Eviction
    print("\n[Test 11] Cache Eviction")
    try:
        config = BatchProcessorConfig(
            max_cache_size=10,
            enable_concurrent_processing=False
        )
        processor = IOCBatchDeduplicationCacheOptimizer(config)
        
        # Fill cache beyond limit
        for i in range(20):
            processor.cache_enrichment_result(f"10.0.0.{i}", "ipv4", {"test": i})
        
        stats = processor.get_statistics()
        assert stats["current_enrichment_cache_size"] <= 10, "Cache should respect max size"
        
        print(f"  ✓ Cache eviction working, size limited to {stats['current_enrichment_cache_size']}")
        test_results["tests_passed"] += 1
        test_results["test_cases"]["cache_eviction"] = "PASSED"
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results["tests_failed"] += 1
        test_results["test_cases"]["cache_eviction"] = f"FAILED: {str(e)}"
    
    # Cleanup
    processor.shutdown()
    
    # Summary
    print("\n" + "=" * 70)
    total_tests = test_results["tests_passed"] + test_results["tests_failed"]
    pass_rate = (test_results["tests_passed"] / total_tests * 100) if total_tests > 0 else 0
    print(f"TEST SUMMARY: {test_results['tests_passed']}/{total_tests} passed ({pass_rate:.1f}%)")
    print("=" * 70)
    
    test_results["pass_rate_percent"] = round(pass_rate, 1)
    
    # Save results
    with open("test_results_ioc_batch_deduplication_enhanced_cache.json", "w") as f:
        json.dump(test_results, f, indent=2)
    
    print(f"\nResults saved to test_results_ioc_batch_deduplication_enhanced_cache.json")
    
    return test_results


if __name__ == "__main__":
    results = run_tests()
    sys.exit(0 if results["tests_failed"] == 0 else 1)
