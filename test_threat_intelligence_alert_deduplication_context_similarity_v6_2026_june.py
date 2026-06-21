"""
Test Suite for Threat Intelligence Alert Deduplication Engine v6
Comprehensive tests for entity normalization, clustering, and deduplication
"""

import json
import time
import sys
sys.path.insert(0, '.')

from neural_shield.threat_intelligence_alert_deduplication_context_similarity_v6_2026_june import (
    AlertDeduplicationEngineV6,
    Alert,
    AlertEntity,
    EntityType,
    EntityNormalizer,
    SimplifiedHDBSCAN,
    create_alert_deduplicator,
    verify_deduplicator
)


def test_entity_normalization():
    """Test entity extraction and normalization"""
    print("=== Test 1: Entity Normalization ===")
    
    text = "Alert: 192.168.1.100 accessed malicious-domain.com with hash d41d8cd98f00b204e9800998ecf8427e"
    entities = EntityNormalizer.extract_entities(text)
    
    print(f"  Extracted {len(entities)} entities")
    for e in entities:
        print(f"    - {e.entity_type.value}: {e.normalized_value} (fp: {e.fingerprint})")
    
    # Verify we found expected entities
    ip_found = any(e.entity_type == EntityType.IP_ADDRESS for e in entities)
    domain_found = any(e.entity_type == EntityType.DOMAIN for e in entities)
    hash_found = any(e.entity_type == EntityType.FILE_HASH for e in entities)
    
    assert ip_found, "IP address should be extracted"
    assert domain_found, "Domain should be extracted"
    assert hash_found, "File hash should be extracted"
    
    print("  ✓ Entity normalization works correctly!")
    return True


def test_similarity_clustering():
    """Test HDBSCAN-based similarity clustering"""
    print("\n=== Test 2: Similarity Clustering ===")
    
    clusterer = SimplifiedHDBSCAN(min_cluster_size=2)
    
    # Create similar alerts
    alerts = [
        Alert(
            alert_id=f"alert_{i}",
            title=f"Brute Force Attack Detected",
            description=f"IP 10.0.0.{i} failed login attempts",
            source="firewall",
            severity="high"
        )
        for i in range(3)
    ]
    
    # Add truly dissimilar alerts (completely different content)
    alerts.extend([
        Alert(
            alert_id="alert_malware_1",
            title="Malware Detected on Endpoint",
            description="Trojan horse virus found, hash: abc123def456",
            source="edr_system",
            severity="critical"
        ),
        Alert(
            alert_id="alert_exfil_1",
            title="Data Exfiltration Attempt",
            description="Large outbound transfer to unknown external server",
            source="dlp_system",
            severity="critical"
        ),
    ])
    
    clusters = clusterer.cluster_alerts(alerts, similarity_threshold=0.7)
    
    print(f"  Total alerts: {len(alerts)}")
    print(f"  Clusters created: {len(clusters)}")
    for i, cluster in enumerate(clusters):
        print(f"    Cluster {i}: {cluster.cluster_size} alerts, sim={cluster.similarity_score}")
    
    # Should have at least 2 clusters
    assert len(clusters) >= 2, "Should create multiple clusters"
    
    print("  ✓ Similarity clustering works correctly!")
    return True


def test_full_deduplication_pipeline():
    """Test full two-stage deduplication pipeline"""
    print("\n=== Test 3: Full Deduplication Pipeline ===")
    
    engine = create_alert_deduplicator(time_window_minutes=60)
    
    # Create test alerts with duplicates
    base_time = time.time()
    
    alerts = [
        # Duplicate group 1: Same IP, same attack
        Alert(
            alert_id="dup1_1",
            title="SSH Brute Force",
            description="192.168.1.50 failed SSH login",
            source="firewall",
            severity="high",
            timestamp=base_time
        ),
        Alert(
            alert_id="dup1_2",
            title="SSH Brute Force Attack",
            description="192.168.1.50 multiple failed logins",
            source="firewall",
            severity="high",
            timestamp=base_time + 60
        ),
        Alert(
            alert_id="dup1_3",
            title="Brute Force Detected",
            description="Source IP 192.168.1.50 SSH attack",
            source="firewall",
            severity="high",
            timestamp=base_time + 120
        ),
        # Duplicate group 2: Different IP
        Alert(
            alert_id="dup2_1",
            title="RDP Brute Force",
            description="10.0.0.25 failed RDP login",
            source="ids",
            severity="medium",
            timestamp=base_time + 30
        ),
        Alert(
            alert_id="dup2_2",
            title="RDP Attack Detected",
            description="10.0.0.25 RDP brute force",
            source="ids",
            severity="medium",
            timestamp=base_time + 90
        ),
        # Unique alert
        Alert(
            alert_id="unique_1",
            title="Data Exfiltration",
            description="Large outbound transfer to external IP",
            source="dlp",
            severity="critical",
            timestamp=base_time + 60
        ),
        # Outside time window
        Alert(
            alert_id="window_1",
            title="Late Alert",
            description="Outside time window",
            source="other",
            severity="low",
            timestamp=base_time + 7200  # 2 hours later
        ),
        Alert(
            alert_id="window_2",
            title="Another Late Alert",
            description="Also outside window",
            source="other",
            severity="low",
            timestamp=base_time + 7260
        ),
    ]
    
    result = engine.deduplicate(alerts)
    
    print(f"  Original alerts: {result.original_count}")
    print(f"  Unique alerts: {result.unique_count}")
    print(f"  Deduplication rate: {result.deduplication_rate:.1%}")
    print(f"  Clusters: {len(result.clusters)}")
    print(f"  Processing time: {result.processing_time_ms}ms")
    
    # Verify deduplication worked
    assert result.original_count == 8, "Should have 8 original alerts"
    assert result.unique_count < result.original_count, "Should reduce alert count"
    assert result.deduplication_rate > 0, "Should have positive deduplication rate"
    
    print(f"  ✓ Full deduplication pipeline works! ({result.original_count} → {result.unique_count}, {result.deduplication_rate:.1%} reduction)")
    return True


def test_empty_input():
    """Test handling of empty input"""
    print("\n=== Test 4: Empty Input Handling ===")
    
    engine = create_alert_deduplicator()
    result = engine.deduplicate([])
    
    assert result.original_count == 0
    assert result.unique_count == 0
    assert len(result.deduplicated_alerts) == 0
    
    print("  ✓ Empty input handled correctly!")
    return True


def test_single_alert():
    """Test handling of single alert"""
    print("\n=== Test 5: Single Alert Handling ===")
    
    engine = create_alert_deduplicator()
    alert = Alert(
        alert_id="single_001",
        title="Single Alert",
        description="Only one alert",
        source="test",
        severity="low"
    )
    
    result = engine.deduplicate([alert])
    
    assert result.original_count == 1
    assert result.unique_count == 1
    assert result.deduplication_rate == 0.0
    
    print("  ✓ Single alert handled correctly!")
    return True


def test_time_window_isolation():
    """Test that alerts outside time window are not deduplicated together"""
    print("\n=== Test 6: Time Window Isolation ===")
    
    engine = create_alert_deduplicator(time_window_minutes=1)  # 1 minute window
    base_time = time.time()
    
    # Create identical alerts but far apart in time
    alerts = [
        Alert(
            alert_id="early",
            title="Same Attack",
            description="192.168.1.1 attack",
            source="fw",
            severity="high",
            timestamp=base_time
        ),
        Alert(
            alert_id="late",
            title="Same Attack",
            description="192.168.1.1 attack",
            source="fw",
            severity="high",
            timestamp=base_time + 120  # 2 minutes later
        ),
    ]
    
    result = engine.deduplicate(alerts)
    
    # Should NOT deduplicate since they're in different time windows
    assert result.unique_count == 2, "Alerts in different windows should not be deduplicated"
    
    print(f"  ✓ Time window isolation works correctly! ({result.original_count} → {result.unique_count})")
    return True


def run_all_tests():
    """Run all tests and generate report"""
    print("=" * 60)
    print("Alert Deduplication Engine v6 - Production Test Suite")
    print("=" * 60)
    
    tests = [
        test_entity_normalization,
        test_similarity_clustering,
        test_full_deduplication_pipeline,
        test_empty_input,
        test_single_alert,
        test_time_window_isolation,
    ]
    
    results = []
    for test in tests:
        try:
            result = test()
            results.append((test.__name__, result, None))
        except Exception as e:
            results.append((test.__name__, False, str(e)))
            print(f"  ✗ FAILED: {e}")
    
    print("\n" + "=" * 60)
    passed = sum(1 for _, r, _ in results if r)
    total = len(results)
    print(f"TEST SUMMARY: {passed} passed, {total - passed} failed")
    print("=" * 60)
    
    # Save results
    report = {
        "test_date": time.strftime("%Y-%m-%d %H:%M:%S"),
        "total_tests": total,
        "passed": passed,
        "failed": total - passed,
        "results": [
            {"test": name, "passed": passed, "error": error}
            for name, passed, error in results
        ]
    }
    
    with open("test_results_alert_deduplication_v6_2026_june.json", "w") as f:
        json.dump(report, f, indent=2)
    
    print(f"\nTest results saved to test_results_alert_deduplication_v6_2026_june.json")
    
    return passed == total


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
