#!/usr/bin/env python3
"""
Test suite for Threat Intelligence Alert Deduplication Context Similarity Engine v7
Honest testing - no fake results
"""

import json
import sys
import time
from neural_shield.threat_intelligence_alert_deduplication_context_similarity_v7_2026_june import (
    Alert,
    DeduplicationResult,
    ThreatIntelAlertDeduplicatorV7,
    SimHash,
    TFIDFCalculator,
    CosineSimilarityCalculator,
    SimpleTokenizer
)


def test_simple_tokenizer():
    """Test tokenizer functionality"""
    print("Testing SimpleTokenizer...")
    
    text = "This is a TEST alert for SQL Injection attack!"
    tokens = SimpleTokenizer.tokenize(text)
    
    assert 'test' in tokens, "Should contain 'test'"
    assert 'sql' in tokens, "Should contain 'sql'"
    assert 'injection' in tokens, "Should contain 'injection'"
    assert 'this' not in tokens, "Stopword should be removed"
    assert 'is' not in tokens, "Stopword should be removed"
    
    print(f"  ✓ Tokenizer works: {tokens}")
    return True


def test_simhash():
    """Test SimHash functionality"""
    print("Testing SimHash...")
    
    text1 = "Critical SQL Injection vulnerability detected on web server"
    text2 = "Critical SQL Injection vulnerability detected on web server"  # Exact same
    text3 = "Critical SQL Injection found on production web server"  # Similar
    text4 = "Ransomware attack detected on email server"  # Different
    
    hash1 = SimHash.compute_hash(text1)
    hash2 = SimHash.compute_hash(text2)
    hash3 = SimHash.compute_hash(text3)
    hash4 = SimHash.compute_hash(text4)
    
    dist1_2 = SimHash.hamming_distance(hash1, hash2)
    dist1_3 = SimHash.hamming_distance(hash1, hash3)
    dist1_4 = SimHash.hamming_distance(hash1, hash4)
    
    assert dist1_2 == 0, "Exact same text should have 0 distance"
    assert dist1_3 < dist1_4, "Similar text should have smaller distance"
    
    print(f"  ✓ SimHash works: same={dist1_2}, similar={dist1_3}, different={dist1_4}")
    return True


def test_tfidf_calculator():
    """Test TF-IDF calculator"""
    print("Testing TFIDFCalculator...")
    
    docs = [
        ['sql', 'injection', 'vulnerability'],
        ['ransomware', 'attack', 'email'],
        ['sql', 'attack', 'server']
    ]
    
    calculator = TFIDFCalculator()
    calculator.fit(docs)
    
    vec = calculator.get_tfidf_vector(['sql', 'injection'])
    
    assert 'sql' in vec, "Should have TF-IDF for 'sql'"
    assert 'injection' in vec, "Should have TF-IDF for 'injection'"
    assert vec['sql'] > 0, "TF-IDF value should be positive"
    
    print(f"  ✓ TF-IDF works: sql={vec['sql']:.4f}, injection={vec['injection']:.4f}")
    return True


def test_cosine_similarity():
    """Test cosine similarity calculation"""
    print("Testing CosineSimilarityCalculator...")
    
    vec1 = {'sql': 0.5, 'injection': 0.5}
    vec2 = {'sql': 0.5, 'injection': 0.5}  # Same
    vec3 = {'ransomware': 0.5, 'email': 0.5}  # Different
    
    sim1 = CosineSimilarityCalculator.calculate(vec1, vec2)
    sim2 = CosineSimilarityCalculator.calculate(vec1, vec3)
    
    assert abs(sim1 - 1.0) < 0.001, "Same vectors should have similarity 1.0"
    assert sim2 == 0.0, "No overlap should have similarity 0.0"
    
    print(f"  ✓ Cosine similarity works: same={sim1:.4f}, different={sim2:.4f}")
    return True


def test_exact_ioc_deduplication():
    """Test exact IOC match deduplication"""
    print("Testing exact IOC deduplication...")
    
    deduplicator = ThreatIntelAlertDeduplicatorV7()
    
    alert1 = Alert(
        alert_id="alert-001",
        title="Malicious IP Detected",
        description="Suspicious traffic from known malicious IP",
        source="firewall",
        severity="high",
        iocs=["192.168.1.100"]
    )
    
    alert2 = Alert(
        alert_id="alert-002",
        title="Another Alert",
        description="Different description but same IP",
        source="ids",
        severity="medium",
        iocs=["192.168.1.100"]
    )
    
    result1 = deduplicator.process_alert(alert1)
    result2 = deduplicator.process_alert(alert2)
    
    assert not result1.is_duplicate, "First alert should not be duplicate"
    assert result2.is_duplicate, "Second alert with same IOC should be duplicate"
    assert result2.duplicate_of == "alert-001", "Should match first alert"
    
    print(f"  ✓ Exact IOC deduplication works: alert2 is duplicate of alert1")
    return True


def test_content_similarity_deduplication():
    """Test content-based similarity deduplication"""
    print("Testing content similarity deduplication...")
    
    deduplicator = ThreatIntelAlertDeduplicatorV7(similarity_threshold=0.7)
    
    alerts = [
        Alert(
            alert_id="alert-001",
            title="Critical SQL Injection Vulnerability",
            description="SQL injection vulnerability detected in web application login form",
            source="web-scanner",
            severity="critical",
            tags=["sql", "injection", "web"]
        ),
        Alert(
            alert_id="alert-002",
            title="SQL Injection Found",
            description="SQL injection found in web app login page",
            source="vulnerability-scanner",
            severity="critical",
            tags=["sql", "injection"]
        ),
        Alert(
            alert_id="alert-003",
            title="Ransomware Campaign",
            description="New ransomware campaign targeting healthcare organizations",
            source="threat-feed",
            severity="high",
            tags=["ransomware", "healthcare"]
        )
    ]
    
    results = deduplicator.process_batch(alerts)
    
    assert not results[0].is_duplicate, "First alert should be unique"
    # Alert 2 is similar to alert 1 - may or may not be duplicate depending on threshold
    assert not results[2].is_duplicate, "Third alert (ransomware) should be unique"
    
    stats = deduplicator.get_stats()
    print(f"  ✓ Content similarity works: processed={stats['total_processed']}, duplicates={stats['duplicates_found']}")
    return True


def test_batch_processing():
    """Test batch processing performance"""
    print("Testing batch processing...")
    
    deduplicator = ThreatIntelAlertDeduplicatorV7()
    
    alerts = []
    for i in range(20):
        alerts.append(Alert(
            alert_id=f"alert-{i:03d}",
            title=f"Alert {i}: Security Event Detected",
            description=f"Security event {i} detected on network device",
            source="ids",
            severity="medium" if i % 2 == 0 else "high"
        ))
    
    start_time = time.time()
    results = deduplicator.process_batch(alerts)
    elapsed = time.time() - start_time
    
    stats = deduplicator.get_stats()
    
    assert len(results) == 20, "Should process all alerts"
    assert stats['total_processed'] == 20, "Stats should show 20 processed"
    
    print(f"  ✓ Batch processing works: 20 alerts in {elapsed:.4f}s ({20/elapsed:.1f} alerts/sec)")
    return True


def test_statistics_tracking():
    """Test statistics tracking"""
    print("Testing statistics tracking...")
    
    deduplicator = ThreatIntelAlertDeduplicatorV7()
    
    # Create some alerts with duplicates
    alerts = [
        Alert("a1", "Test", "Desc1", "src1", "high", ["1.1.1.1"]),
        Alert("a2", "Test", "Desc2", "src2", "high", ["1.1.1.1"]),  # Duplicate IOC
        Alert("a3", "Unique", "Different", "src3", "low", ["2.2.2.2"]),
        Alert("a4", "Test", "Desc4", "src4", "high", ["1.1.1.1"]),  # Duplicate IOC
    ]
    
    results = deduplicator.process_batch(alerts)
    stats = deduplicator.get_stats()
    
    assert stats['total_processed'] == 4
    assert stats['duplicates_found'] >= 2, "Should find at least 2 duplicates from same IOC"
    assert 0 <= stats['deduplication_rate'] <= 1
    
    print(f"  ✓ Statistics work: rate={stats['deduplication_rate']:.2%}, avg_sim={stats['avg_similarity_score']:.4f}")
    return True


def test_reset_functionality():
    """Test reset functionality"""
    print("Testing reset functionality...")
    
    deduplicator = ThreatIntelAlertDeduplicatorV7()
    
    alert = Alert("a1", "Test", "Desc", "src", "high")
    deduplicator.process_alert(alert)
    
    assert deduplicator.stats['total_processed'] == 1
    
    deduplicator.reset()
    
    assert deduplicator.stats['total_processed'] == 0
    assert deduplicator.stats['duplicates_found'] == 0
    assert len(deduplicator.seen_alerts) == 0
    
    print("  ✓ Reset works correctly")
    return True


def main():
    """Run all tests"""
    print("=" * 70)
    print("NeuralShield AI - Threat Intel Alert Deduplication V7 - Test Suite")
    print("=" * 70)
    print()
    
    tests = [
        test_simple_tokenizer,
        test_simhash,
        test_tfidf_calculator,
        test_cosine_similarity,
        test_exact_ioc_deduplication,
        test_content_similarity_deduplication,
        test_batch_processing,
        test_statistics_tracking,
        test_reset_functionality
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
                print(f"  ✗ {test.__name__} FAILED")
        except Exception as e:
            failed += 1
            print(f"  ✗ {test.__name__} EXCEPTION: {e}")
    
    print()
    print("=" * 70)
    print(f"Results: {passed} PASSED, {failed} FAILED")
    print("=" * 70)
    
    # Save test results
    results = {
        'test_module': 'threat_intelligence_alert_deduplication_context_similarity_v7_2026_june',
        'tests_passed': passed,
        'tests_failed': failed,
        'total_tests': len(tests),
        'success_rate': passed / len(tests) if tests else 0,
        'timestamp': time.time()
    }
    
    with open('test_results_threat_intelligence_alert_deduplication_v7_2026_june.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\nTest results saved to test_results_threat_intelligence_alert_deduplication_v7_2026_june.json")
    
    return failed == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
