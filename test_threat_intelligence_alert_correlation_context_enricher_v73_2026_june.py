#!/usr/bin/env python3
"""
Test suite for Threat Intelligence Alert Correlation & Context Enrichment Engine v73
Production-grade tests with real assertions
"""

import sys
import time
import json

sys.path.insert(0, '/home/user/autonomous-developer/NeuralShield-AI')

from neural_shield.threat_intelligence_alert_correlation_context_enricher_v73_2026_june import (
    Alert,
    BloomFilter,
    SemanticSimilarityEngine,
    ThreatIntelligenceCorrelationEngine
)


def test_bloom_filter_basic():
    """Test Bloom Filter basic functionality"""
    print("Testing Bloom Filter basic functionality...")
    
    bf = BloomFilter(size=10000, hash_count=5)
    
    # Test add and contains
    bf.add("test_alert_123")
    assert bf.contains("test_alert_123") == True, "Bloom filter should contain added item"
    assert bf.contains("nonexistent_item") == False, "Bloom filter should not contain unadded item"
    
    # Test false positive rate calculation
    fp_rate = bf.calculate_false_positive_rate(100)
    assert 0 <= fp_rate <= 1, "False positive rate should be between 0 and 1"
    
    print("  ✓ Bloom Filter basic tests passed")
    return True


def test_semantic_similarity():
    """Test Semantic Similarity Engine"""
    print("Testing Semantic Similarity Engine...")
    
    engine = SemanticSimilarityEngine()
    
    # Test Jaccard similarity - identical texts
    sim1 = engine.jaccard_similarity("Ransomware detected encrypting files", 
                                    "Ransomware detected encrypting files")
    assert sim1 == 1.0, "Identical texts should have similarity 1.0"
    
    # Test similar texts
    sim2 = engine.jaccard_similarity("Ransomware detected encrypting system files",
                                    "Ransomware detected encrypting user files")
    assert sim2 > 0.5, "Similar texts should have high similarity"
    
    # Test different texts
    sim3 = engine.jaccard_similarity("Ransomware encryption detected",
                                    "Phishing email received from external")
    assert sim3 < 0.5, "Different texts should have low similarity"
    
    # Test Levenshtein distance
    dist = engine.levenshtein_distance("kitten", "sitting")
    assert dist == 3, "Levenshtein distance should be correct"
    
    print("  ✓ Semantic Similarity tests passed")
    return True


def test_alert_enrichment():
    """Test alert context enrichment"""
    print("Testing Alert Context Enrichment...")
    
    engine = ThreatIntelligenceCorrelationEngine()
    
    # Create test alert with ransomware pattern
    alert = Alert(
        alert_id="",
        source="edr",
        severity="high",
        timestamp=time.time(),
        description="Ransomware detected: process encrypting files and demanding bitcoin ransom",
        indicator_type="process",
        indicator_value="malware.exe"
    )
    
    enriched = engine.enrich_alert_context(alert)
    
    assert enriched.enriched == True, "Alert should be marked as enriched"
    assert enriched.confidence > 0.5, "Confidence should be calibrated"
    assert "mitre_techniques" in enriched.context, "Should have MITRE techniques"
    assert "threat_patterns" in enriched.context, "Should have threat patterns"
    assert "ransomware" in enriched.context.get("threat_patterns", []), "Should detect ransomware pattern"
    
    print("  ✓ Alert Enrichment tests passed")
    return True


def test_false_positive_reduction():
    """Test false positive reduction"""
    print("Testing False Positive Reduction...")
    
    engine = ThreatIntelligenceCorrelationEngine()
    
    # Test known FP pattern
    fp_alert = Alert(
        alert_id="",
        source="test",
        severity="low",
        timestamp=time.time(),
        description="This is a test alert - expected behavior during maintenance window",
        indicator_type="ip",
        indicator_value="192.168.1.1"
    )
    
    _, is_fp = engine.reduce_false_positives(fp_alert)
    assert is_fp == True, "Test alert should be detected as false positive"
    
    # Test legitimate alert
    legit_alert = Alert(
        alert_id="",
        source="edr",
        severity="critical",
        timestamp=time.time(),
        description="Suspicious process attempting to encrypt system files",
        indicator_type="process",
        indicator_value="suspicious.exe"
    )
    
    _, is_fp2 = engine.reduce_false_positives(legit_alert)
    assert is_fp2 == False, "Legitimate alert should not be flagged as FP"
    
    print("  ✓ False Positive Reduction tests passed")
    return True


def test_alert_deduplication():
    """Test alert deduplication"""
    print("Testing Alert Deduplication...")
    
    engine = ThreatIntelligenceCorrelationEngine()
    
    base_time = time.time()
    
    # Create first alert
    alert1 = Alert(
        alert_id="",
        source="siem",
        severity="high",
        timestamp=base_time,
        description="Suspicious login attempt detected",
        indicator_type="ip",
        indicator_value="192.168.1.100"
    )
    
    result1 = engine.process_alert(alert1)
    assert result1["processed"] == True
    assert result1["duplicate"] == False
    
    # Create duplicate alert (same indicator, same source, within window)
    alert2 = Alert(
        alert_id="",
        source="siem",
        severity="high",
        timestamp=base_time + 30,  # 30 seconds later
        description="Suspicious login attempt detected",
        indicator_type="ip",
        indicator_value="192.168.1.100"
    )
    
    result2 = engine.process_alert(alert2)
    assert result2["duplicate"] == True, "Duplicate alert should be detected"
    
    print("  ✓ Alert Deduplication tests passed")
    return True


def test_alert_correlation():
    """Test alert correlation"""
    print("Testing Alert Correlation...")
    
    engine = ThreatIntelligenceCorrelationEngine(correlation_window_minutes=10)
    
    base_time = time.time()
    
    # Process first alert
    alert1 = Alert(
        alert_id="",
        source="edr",
        severity="high",
        timestamp=base_time,
        description="Ransomware process detected encrypting files",
        indicator_type="process",
        indicator_value="encrypt.exe"
    )
    engine.process_alert(alert1)
    
    # Process second related alert (same time window, similar pattern)
    alert2 = Alert(
        alert_id="",
        source="siem",
        severity="critical",
        timestamp=base_time + 60,  # 1 minute later
        description="Ransomware activity: multiple files encrypted on host",
        indicator_type="host",
        indicator_value="SERVER-01"
    )
    result2 = engine.process_alert(alert2)
    
    # Check metrics
    metrics = engine.get_performance_metrics()
    assert metrics["total_alerts_processed"] >= 2, "Should have processed alerts"
    assert metrics["alerts_enriched"] >= 2, "Should have enriched alerts"
    
    # Get correlation summary
    summary = engine.get_correlation_summary()
    assert isinstance(summary, list), "Summary should be a list"
    
    print("  ✓ Alert Correlation tests passed")
    return True


def test_performance_metrics():
    """Test performance metrics tracking"""
    print("Testing Performance Metrics...")
    
    engine = ThreatIntelligenceCorrelationEngine()
    
    # Process several alerts
    for i in range(10):
        alert = Alert(
            alert_id="",
            source=f"source_{i % 3}",
            severity=["low", "medium", "high", "critical"][i % 4],
            timestamp=time.time() + i,
            description=f"Test alert {i} with pattern matching",
            indicator_type="ip",
            indicator_value=f"10.0.0.{i}"
        )
        engine.process_alert(alert)
    
    metrics = engine.get_performance_metrics()
    
    assert metrics["total_alerts_processed"] == 10, "Should have processed 10 alerts"
    assert metrics["alerts_enriched"] == 10, "All alerts should be enriched"
    assert metrics["average_processing_time_ms"] > 0, "Should have processing time"
    assert 0 <= metrics["false_positive_rate"] <= 1, "FP rate should be valid"
    assert "engine_version" in metrics, "Should have version info"
    
    print("  ✓ Performance Metrics tests passed")
    return True


def run_all_tests():
    """Run all tests and generate report"""
    print("=" * 70)
    print("Threat Intelligence Alert Correlation Engine v73 - Test Suite")
    print("=" * 70)
    
    tests = [
        test_bloom_filter_basic,
        test_semantic_similarity,
        test_alert_enrichment,
        test_false_positive_reduction,
        test_alert_deduplication,
        test_alert_correlation,
        test_performance_metrics
    ]
    
    results = []
    start_time = time.time()
    
    for test_func in tests:
        try:
            result = test_func()
            results.append((test_func.__name__, result, None))
        except Exception as e:
            results.append((test_func.__name__, False, str(e)))
            print(f"  ✗ FAILED: {e}")
    
    elapsed = time.time() - start_time
    
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    
    passed = sum(1 for _, r, _ in results if r)
    total = len(results)
    
    print(f"Passed: {passed}/{total}")
    print(f"Failed: {total - passed}")
    print(f"Total time: {elapsed:.3f}s")
    
    print("\nDetailed results:")
    for name, result, error in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"  {status}: {name}")
        if error:
            print(f"       Error: {error}")
    
    # Save test results
    test_results = {
        "test_version": "v73",
        "timestamp": time.time(),
        "total_tests": total,
        "passed": passed,
        "failed": total - passed,
        "elapsed_seconds": round(elapsed, 3),
        "results": [{"name": n, "passed": r, "error": e} for n, r, e in results]
    }
    
    with open("/home/user/autonomous-developer/NeuralShield-AI/test_results_threat_intelligence_alert_correlation_context_enricher_v73_2026_june.json", "w") as f:
        json.dump(test_results, f, indent=2)
    
    print(f"\nTest results saved to JSON file")
    
    return passed == total


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
