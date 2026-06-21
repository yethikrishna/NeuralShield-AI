#!/usr/bin/env python3
"""
Test suite for Threat Intelligence Alert Correlation & Context Enrichment Engine v64
Production-grade tests with comprehensive coverage
"""

import json
import time
import sys
import os

# Add neural_shield to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from threat_intelligence_alert_correlation_context_enricher_v64_2026_june import (
    AlertCorrelationContextEnricherV64,
    Alert,
    AlertSeverity,
    BloomFilter,
    GeolocationCache,
    AssetRiskContextProvider,
    CorrelationConfidence
)


def test_bloom_filter_basic():
    """Test basic bloom filter functionality"""
    print("Testing BloomFilter...")
    bf = BloomFilter(size_bits=10000, num_hashes=5)
    
    # Test add and check
    bf.add("test-ioc-1")
    bf.add("test-ioc-2")
    
    assert bf.might_contain("test-ioc-1") == True, "Bloom filter should contain added item"
    assert bf.might_contain("test-ioc-2") == True, "Bloom filter should contain added item"
    assert bf.might_contain("test-ioc-3") == False, "Bloom filter should not contain unadded item"
    
    # Test false positive rate calculation
    fp_rate = bf.estimated_false_positive_rate()
    assert 0 <= fp_rate <= 1, f"False positive rate should be between 0 and 1, got {fp_rate}"
    
    print("  ✓ BloomFilter basic tests passed")
    return True


def test_geolocation_cache():
    """Test geolocation cache functionality"""
    print("Testing GeolocationCache...")
    geo = GeolocationCache(max_cache_size=10, ttl_seconds=3600)
    
    # Test lookup
    result = geo.lookup("192.168.1.1")
    assert result["country"] == "US", f"Expected US, got {result['country']}"
    assert "threat_score" in result, "Should have threat_score"
    
    # Test unknown IP
    unknown = geo.lookup("255.255.255.255")
    assert unknown["country"] == "UNKNOWN", "Unknown IP should return UNKNOWN"
    
    print("  ✓ GeolocationCache tests passed")
    return True


def test_asset_risk_provider():
    """Test asset risk context provider"""
    print("Testing AssetRiskContextProvider...")
    asset_provider = AssetRiskContextProvider()
    
    # Test known asset
    context = asset_provider.get_asset_context("asset-001")
    assert context["criticality"] == "critical", "Asset 001 should be critical"
    
    # Test risk multiplier
    multiplier = asset_provider.calculate_asset_risk_multiplier("asset-001")
    assert multiplier == 1.0, f"Critical asset should have multiplier 1.0, got {multiplier}"
    
    # Test unknown asset
    unknown = asset_provider.get_asset_context("asset-999")
    assert unknown["criticality"] == "low", "Unknown asset should have low criticality"
    
    print("  ✓ AssetRiskContextProvider tests passed")
    return True


def test_alert_processing_basic():
    """Test basic alert processing"""
    print("Testing basic alert processing...")
    enricher = AlertCorrelationContextEnricherV64(
        correlation_window_seconds=3600,
        min_correlation_score=0.3
    )
    
    # Create test alert
    alert = Alert(
        alert_id="alert-001",
        timestamp=time.time(),
        source="firewall",
        title="Suspicious Network Connection",
        description="External IP attempting connection",
        severity=AlertSeverity.HIGH,
        iocs=["192.168.1.1", "malicious-domain.com"],
        mitre_techniques=["T1046", "T1071"],
        source_ip="192.168.1.1",
        asset_id="asset-001"
    )
    
    # Process alert
    result = enricher.process_alert(alert)
    
    # Verify results
    assert result["enriched"] == True, "Alert should be enriched"
    assert result["confidence_score"] > 0, "Should have confidence score"
    assert result["correlation"]["correlated"] == True, "Should be correlated"
    assert "processing_time_ms" in result, "Should have processing time"
    
    print("  ✓ Basic alert processing passed")
    return True


def test_alert_correlation():
    """Test alert correlation functionality"""
    print("Testing alert correlation...")
    enricher = AlertCorrelationContextEnricherV64(
        correlation_window_seconds=3600,
        min_correlation_score=0.15,
        enable_bloom_filter=False  # Disable for correlation test
    )
    
    base_time = time.time()
    
    # Create first alert
    alert1 = Alert(
        alert_id="alert-correlate-001",
        timestamp=base_time,
        source="ids",
        title="Port Scan Detected",
        description="Network scanning activity",
        severity=AlertSeverity.MEDIUM,
        iocs=["172.16.0.1"],
        mitre_techniques=["T1046"],
        source_ip="172.16.0.1"
    )
    
    result1 = enricher.process_alert(alert1)
    group_id = result1["correlation"]["group_id"]
    
    # Create second related alert (same IOC)
    alert2 = Alert(
        alert_id="alert-correlate-002",
        timestamp=base_time + 60,  # 1 minute later
        source="firewall",
        title="Follow-up Connection",
        description="Connection from same IP",
        severity=AlertSeverity.HIGH,
        iocs=["172.16.0.1"],  # Same IOC for correlation
        mitre_techniques=["T1071"],
        source_ip="172.16.0.1"
    )
    
    result2 = enricher.process_alert(alert2)
    
    # Verify correlation
    assert result2["correlation"]["group_id"] == group_id, "Alerts should be in same group"
    assert result2["correlation"]["matched_alerts"] >= 2, "Group should have multiple alerts"
    
    print("  ✓ Alert correlation tests passed")
    return True


def test_ioc_deduplication():
    """Test IOC deduplication with bloom filter"""
    print("Testing IOC deduplication...")
    enricher = AlertCorrelationContextEnricherV64(enable_bloom_filter=True)
    
    # Create alerts with duplicate IOCs
    alert1 = Alert(
        alert_id="dedup-test-001",
        timestamp=time.time(),
        source="test",
        title="Test Alert 1",
        description="Test",
        severity=AlertSeverity.LOW,
        iocs=["duplicate-ioc-1", "unique-ioc-1"]
    )
    
    alert2 = Alert(
        alert_id="dedup-test-002",
        timestamp=time.time(),
        source="test",
        title="Test Alert 2",
        description="Test",
        severity=AlertSeverity.LOW,
        iocs=["duplicate-ioc-1", "unique-ioc-2"]
    )
    
    enricher.process_alert(alert1)
    enricher.process_alert(alert2)
    
    metrics = enricher.get_metrics()
    assert metrics["metrics"]["iocs_deduplicated"] > 0, "Should have deduplicated IOCs"
    
    print("  ✓ IOC deduplication tests passed")
    return True


def test_confidence_calibration():
    """Test false positive confidence calibration"""
    print("Testing confidence calibration...")
    enricher = AlertCorrelationContextEnricherV64()
    
    # High confidence alert
    high_alert = Alert(
        alert_id="conf-high-001",
        timestamp=time.time(),
        source="edr",
        title="Critical Malware Detected",
        description="Malware execution detected",
        severity=AlertSeverity.CRITICAL,
        iocs=["malware-hash-123"],
        mitre_techniques=["T1055", "T1003"],
        asset_id="asset-001",
        confidence_score=0.9
    )
    
    result = enricher.process_alert(high_alert)
    assert result["confidence_score"] > 0.5, "High confidence alert should maintain high score"
    
    print("  ✓ Confidence calibration tests passed")
    return True


def test_performance_metrics():
    """Test performance metrics tracking"""
    print("Testing performance metrics...")
    enricher = AlertCorrelationContextEnricherV64()
    
    # Process multiple alerts
    for i in range(10):
        alert = Alert(
            alert_id=f"metric-test-{i}",
            timestamp=time.time(),
            source="test",
            title=f"Test Alert {i}",
            description="Metrics test",
            severity=AlertSeverity.LOW,
            iocs=[f"ioc-{i}"]
        )
        enricher.process_alert(alert)
    
    metrics = enricher.get_metrics()
    
    assert metrics["metrics"]["total_alerts_processed"] == 10, "Should have processed 10 alerts"
    assert metrics["metrics"]["alerts_enriched"] == 10, "All alerts should be enriched"
    assert metrics["active_alerts"] == 10, "Should have 10 active alerts"
    assert metrics["version"] == "v64", "Should be version v64"
    
    print("  ✓ Performance metrics tests passed")
    return True


def test_correlation_confidence_levels():
    """Test correlation confidence level calculation"""
    print("Testing correlation confidence levels...")
    enricher = AlertCorrelationContextEnricherV64()
    
    # Process alerts that should form high confidence group
    base_time = time.time()
    
    for i in range(5):
        alert = Alert(
            alert_id=f"conf-level-{i}",
            timestamp=base_time + i * 10,
            source="ids",
            title=f"Related Alert {i}",
            description="Part of attack chain",
            severity=AlertSeverity.HIGH,
            iocs=["shared-ioc-attack"],
            mitre_techniques=["T1046", "T1059"]
        )
        enricher.process_alert(alert)
    
    metrics = enricher.get_metrics()
    assert metrics["correlation_groups"] >= 1, "Should have correlation groups"
    
    print("  ✓ Correlation confidence levels tests passed")
    return True


def run_all_tests():
    """Run all tests and generate report"""
    print("=" * 70)
    print("NeuralShield-AI: Alert Correlation & Context Enrichment v64 - Test Suite")
    print("=" * 70)
    print()
    
    tests = [
        ("Bloom Filter", test_bloom_filter_basic),
        ("Geolocation Cache", test_geolocation_cache),
        ("Asset Risk Provider", test_asset_risk_provider),
        ("Basic Alert Processing", test_alert_processing_basic),
        ("Alert Correlation", test_alert_correlation),
        ("IOC Deduplication", test_ioc_deduplication),
        ("Confidence Calibration", test_confidence_calibration),
        ("Performance Metrics", test_performance_metrics),
        ("Correlation Confidence Levels", test_correlation_confidence_levels),
    ]
    
    results = []
    start_time = time.time()
    
    for test_name, test_func in tests:
        try:
            success = test_func()
            results.append((test_name, success, None))
        except Exception as e:
            results.append((test_name, False, str(e)))
            print(f"  ✗ FAILED: {e}")
    
    total_time = time.time() - start_time
    
    # Summary
    print()
    print("=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    
    passed = sum(1 for _, s, _ in results if s)
    failed = len(results) - passed
    
    for test_name, success, error in results:
        status = "✓ PASS" if success else "✗ FAIL"
        print(f"  {status} - {test_name}")
        if error:
            print(f"      Error: {error}")
    
    print()
    print(f"Total: {passed}/{len(results)} tests passed")
    print(f"Total time: {total_time:.3f}s")
    print()
    
    # Write test results to JSON
    test_results = {
        "test_suite": "Alert Correlation & Context Enrichment v64",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_tests": len(results),
        "passed": passed,
        "failed": failed,
        "success_rate": round(passed / len(results) * 100, 2),
        "total_time_seconds": round(total_time, 3),
        "results": [
            {"test": name, "passed": success, "error": error}
            for name, success, error in results
        ]
    }
    
    with open("test_results_alert_correlation_context_enricher_v64_2026_june.json", "w") as f:
        json.dump(test_results, f, indent=2)
    
    print(f"Test results written to test_results_alert_correlation_context_enricher_v64_2026_june.json")
    
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
