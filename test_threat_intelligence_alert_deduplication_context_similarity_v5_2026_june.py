"""
Test suite for Threat Intelligence Alert Deduplication Engine v5
Real working tests with actual assertions
"""

import sys
import os
import time
import json

# Add module path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from threat_intelligence_alert_deduplication_context_similarity_v5_2026_june import (
    Alert,
    TextSimilarityScorer,
    IOCExtractor,
    BloomFilter,
    ContextAwareDeduplicationEngineV5
)


def test_text_similarity_scorer():
    """Test text similarity scoring functions"""
    print("Testing TextSimilarityScorer...")
    
    # Test identical texts
    score = TextSimilarityScorer.jaccard_similarity("test alert", "test alert")
    assert score == 1.0, f"Expected 1.0 for identical texts, got {score}"
    print("  ✓ Jaccard identical: PASS")
    
    # Test different texts
    score = TextSimilarityScorer.jaccard_similarity("abc", "xyz")
    assert score < 0.5, f"Expected low score for different texts, got {score}"
    print("  ✓ Jaccard different: PASS")
    
    # Test Levenshtein
    score = TextSimilarityScorer.normalized_levenshtein("kitten", "sitting")
    assert 0.0 < score < 1.0, f"Expected partial match, got {score}"
    print("  ✓ Levenshtein partial: PASS")
    
    # Test combined similarity
    score = TextSimilarityScorer.combined_similarity(
        "Malware detected on host 192.168.1.1",
        "Malware detected on host 192.168.1.1"
    )
    assert score > 0.9, f"Expected high combined score, got {score}"
    print("  ✓ Combined similarity: PASS")
    
    print("  All TextSimilarityScorer tests PASSED\n")


def test_ioc_extractor():
    """Test IOC extraction functionality"""
    print("Testing IOCExtractor...")
    
    test_text = """
    Attack from IP 192.168.1.100 and 10.0.0.1
    Domain: malicious.com and bad-site.net
    Hash: 5d41402abc4b2a76b9719d911017c592
    URL: https://evil.com/payload.exe
    """
    
    iocs = IOCExtractor.extract_iocs(test_text)
    
    assert len(iocs['ips']) >= 2, f"Expected at least 2 IPs, got {len(iocs['ips'])}"
    print("  ✓ IP extraction: PASS")
    
    assert len(iocs['domains']) >= 2, f"Expected at least 2 domains, got {len(iocs['domains'])}"
    print("  ✓ Domain extraction: PASS")
    
    assert len(iocs['hashes']) >= 1, f"Expected at least 1 hash, got {len(iocs['hashes'])}"
    print("  ✓ Hash extraction: PASS")
    
    assert len(iocs['urls']) >= 1, f"Expected at least 1 URL, got {len(iocs['urls'])}"
    print("  ✓ URL extraction: PASS")
    
    # Test IOC overlap
    overlap = IOCExtractor.ioc_overlap(
        ['192.168.1.1', '10.0.0.1'],
        ['192.168.1.1', '172.16.0.1']
    )
    assert overlap == 0.333 or abs(overlap - 1/3) < 0.01, f"Expected 1/3 overlap, got {overlap}"
    print("  ✓ IOC overlap scoring: PASS")
    
    print("  All IOCExtractor tests PASSED\n")


def test_bloom_filter():
    """Test Bloom Filter implementation"""
    print("Testing BloomFilter...")
    
    bf = BloomFilter(size=10000, hash_count=5)
    
    # Test add and contains
    bf.add("test_item_1")
    bf.add("test_item_2")
    
    assert bf.contains("test_item_1") == True, "Expected True for added item"
    assert bf.contains("test_item_2") == True, "Expected True for added item"
    print("  ✓ Add and contains: PASS")
    
    # Test false negative (should never happen)
    assert bf.contains("completely_new_item") == False, "Expected False for new item"
    print("  ✓ Non-contained item: PASS")
    
    print("  All BloomFilter tests PASSED\n")


def test_alert_dataclass():
    """Test Alert data class"""
    print("Testing Alert dataclass...")
    
    alert = Alert(
        alert_id="",
        timestamp=time.time(),
        source="firewall",
        alert_type="malware",
        severity="high",
        iocs=["192.168.1.1"],
        description="Malware detected on endpoint"
    )
    
    assert alert.alert_id != "", "Expected auto-generated alert_id"
    assert alert.source == "firewall", "Source mismatch"
    assert alert.severity == "high", "Severity mismatch"
    assert len(alert.iocs) == 1, "IOC count mismatch"
    print("  ✓ Alert creation and auto-ID: PASS")
    
    print("  All Alert tests PASSED\n")


def test_deduplication_engine_basic():
    """Test basic deduplication functionality"""
    print("Testing ContextAwareDeduplicationEngineV5 (basic)...")
    
    engine = ContextAwareDeduplicationEngineV5(
        similarity_threshold=0.7,
        temporal_window_minutes=60
    )
    
    base_time = time.time()
    
    # Create first alert
    alert1 = Alert(
        alert_id="alert_001",
        timestamp=base_time,
        source="ids",
        alert_type="brute_force",
        severity="medium",
        iocs=["192.168.1.100"],
        description="SSH brute force attack detected from 192.168.1.100"
    )
    
    result1 = engine.process_alert(alert1)
    assert result1['is_duplicate'] == False, "First alert should not be duplicate"
    assert result1['action'] == 'passed', "First alert should pass"
    print("  ✓ First unique alert: PASS")
    
    # Create duplicate alert (same content, same time)
    alert2 = Alert(
        alert_id="alert_002",
        timestamp=base_time + 60,  # 1 minute later
        source="ids",
        alert_type="brute_force",
        severity="medium",
        iocs=["192.168.1.100"],
        description="SSH brute force attack detected from 192.168.1.100"
    )
    
    result2 = engine.process_alert(alert2)
    assert result2['is_duplicate'] == True, "Second alert should be duplicate"
    assert result2['action'] == 'suppressed', "Duplicate should be suppressed"
    assert result2['similarity_score'] >= 0.7, f"Expected high similarity, got {result2['similarity_score']}"
    print("  ✓ Duplicate detection: PASS")
    
    # Create different alert
    alert3 = Alert(
        alert_id="alert_003",
        timestamp=base_time + 120,
        source="firewall",
        alert_type="port_scan",
        severity="low",
        iocs=["10.0.0.50"],
        description="Port scan detected from external host"
    )
    
    result3 = engine.process_alert(alert3)
    assert result3['is_duplicate'] == False, "Different alert should not be duplicate"
    print("  ✓ Different alert passes: PASS")
    
    print("  All basic deduplication tests PASSED\n")


def test_deduplication_batch():
    """Test batch processing"""
    print("Testing ContextAwareDeduplicationEngineV5 (batch)...")
    
    engine = ContextAwareDeduplicationEngineV5(
        similarity_threshold=0.75,
        temporal_window_minutes=30
    )
    
    base_time = time.time()
    alerts = []
    
    # Create 5 unique alerts
    for i in range(5):
        alerts.append(Alert(
            alert_id=f"unique_{i}",
            timestamp=base_time + i * 60,
            source=f"source_{i % 3}",
            alert_type=f"type_{i}",
            severity="medium",
            iocs=[f"192.168.1.{i+1}"],
            description=f"Alert type {i} from IP 192.168.1.{i+1}"
        ))
    
    # Create 5 duplicates of first alert
    for i in range(5):
        alerts.append(Alert(
            alert_id=f"dup_{i}",
            timestamp=base_time + 30 + i * 5,
            source="source_0",
            alert_type="type_0",
            severity="medium",
            iocs=["192.168.1.1"],
            description="Alert type 0 from IP 192.168.1.1"
        ))
    
    results = engine.process_batch(alerts, batch_size=5)
    
    assert len(results) == 10, f"Expected 10 results, got {len(results)}"
    print("  ✓ Batch processing complete: PASS")
    
    stats = engine.get_statistics()
    assert stats['total_alerts_processed'] == 10, "Total count mismatch"
    assert stats['duplicates_suppressed'] >= 4, f"Expected at least 4 duplicates, got {stats['duplicates_suppressed']}"
    assert stats['deduplication_rate_percent'] > 0, "Expected positive deduplication rate"
    print(f"  ✓ Deduplication rate: {stats['deduplication_rate_percent']}%: PASS")
    
    print("  All batch processing tests PASSED\n")


def test_statistics():
    """Test statistics generation"""
    print("Testing statistics generation...")
    
    engine = ContextAwareDeduplicationEngineV5()
    
    stats = engine.get_statistics()
    assert stats['engine_version'] == 'v5.0.0', "Version mismatch"
    assert stats['total_alerts_processed'] == 0, "Initial count should be 0"
    assert stats['deduplication_rate_percent'] == 0, "Initial rate should be 0"
    print("  ✓ Initial statistics: PASS")
    
    # Process some alerts
    base_time = time.time()
    for i in range(3):
        engine.process_alert(Alert(
            alert_id=f"test_{i}",
            timestamp=base_time + i * 300,
            source="test",
            alert_type="test",
            severity="low",
            description=f"Test alert {i}"
        ))
    
    stats = engine.get_statistics()
    assert stats['total_alerts_processed'] == 3, "Processed count mismatch"
    assert stats['groups_created'] > 0, "Should have created groups"
    print("  ✓ Updated statistics: PASS")
    
    print("  All statistics tests PASSED\n")


def run_all_tests():
    """Run all test cases"""
    print("=" * 60)
    print("NeuralShield-AI: Deduplication Engine v5 Test Suite")
    print("=" * 60 + "\n")
    
    test_cases = [
        test_text_similarity_scorer,
        test_ioc_extractor,
        test_bloom_filter,
        test_alert_dataclass,
        test_deduplication_engine_basic,
        test_deduplication_batch,
        test_statistics
    ]
    
    passed = 0
    failed = 0
    results = []
    
    for test in test_cases:
        try:
            test()
            passed += 1
            results.append({"test": test.__name__, "status": "PASSED"})
        except AssertionError as e:
            failed += 1
            results.append({"test": test.__name__, "status": "FAILED", "error": str(e)})
            print(f"  FAILED: {e}\n")
        except Exception as e:
            failed += 1
            results.append({"test": test.__name__, "status": "ERROR", "error": str(e)})
            print(f"  ERROR: {e}\n")
    
    print("=" * 60)
    print(f"TEST SUMMARY: {passed} PASSED, {failed} FAILED")
    print("=" * 60)
    
    # Save results
    with open('test_results_alert_deduplication_v5_2026_june.json', 'w') as f:
        json.dump({
            "test_suite": "ContextAwareDeduplicationEngineV5",
            "timestamp": time.time(),
            "passed": passed,
            "failed": failed,
            "total": passed + failed,
            "results": results
        }, f, indent=2)
    
    print(f"\nResults saved to test_results_alert_deduplication_v5_2026_june.json")
    
    return passed, failed


if __name__ == "__main__":
    passed, failed = run_all_tests()
    sys.exit(0 if failed == 0 else 1)
