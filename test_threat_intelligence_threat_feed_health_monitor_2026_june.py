"""
Test Suite for Threat Intelligence Threat Feed Health Monitor
Production-grade testing of all functionality
"""

import json
import sys
from datetime import datetime

# Add the module path
sys.path.insert(0, '/home/user/autonomous-developer/NeuralShield-AI')

from neural_shield.threat_intelligence_threat_feed_health_monitor_2026_june import (
    ThreatFeedHealthMonitor,
    FeedPullResult,
    FeedStatus,
    HealthIssueType
)


def run_tests():
    """Run all production tests."""
    print("=" * 70)
    print("THREAT FEED HEALTH MONITOR - PRODUCTION TEST SUITE")
    print("=" * 70)
    print(f"Test started: {datetime.utcnow().isoformat()}")
    
    test_results = []
    all_passed = True
    
    # Test 1: Monitor Initialization
    print("\n[TEST 1] Monitor Initialization")
    try:
        monitor = ThreatFeedHealthMonitor()
        assert len(monitor.feeds) == 5
        print("  ✓ Monitor initialized with 5 default feeds")
        test_results.append(("Initialization", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Initialization", False))
        all_passed = False
    
    # Test 2: Register New Feed
    print("\n[TEST 2] Register New Feed")
    try:
        monitor = ThreatFeedHealthMonitor()
        monitor.register_feed(
            feed_id="custom_feed_001",
            feed_name="Custom Threat Feed",
            feed_url="https://example.com/feed",
            expected_interval_seconds=600,
            minimum_records=50
        )
        assert "custom_feed_001" in monitor.feeds
        print("  ✓ New feed registered successfully")
        test_results.append(("Feed Registration", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Feed Registration", False))
        all_passed = False
    
    # Test 3: Record Successful Pull
    print("\n[TEST 3] Record Successful Pull")
    try:
        monitor = ThreatFeedHealthMonitor()
        result = FeedPullResult(
            success=True,
            latency_ms=450,
            record_count=150
        )
        monitor.record_pull_result("abuse_ch_feodo", result)
        health = monitor.get_feed_health("abuse_ch_feodo")
        assert health is not None
        assert health.uptime_percent == 100.0
        print("  ✓ Successful pull recorded and metrics updated")
        test_results.append(("Successful Pull Recording", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Successful Pull Recording", False))
        all_passed = False
    
    # Test 4: Record Failed Pull
    print("\n[TEST 4] Record Failed Pull")
    try:
        monitor = ThreatFeedHealthMonitor()
        result = FeedPullResult(
            success=False,
            latency_ms=1000,
            record_count=0,
            error_message="Connection timeout"
        )
        monitor.record_pull_result("abuse_ch_urlhaus", result)
        health = monitor.get_feed_health("abuse_ch_urlhaus")
        assert health.consecutive_failures == 1
        print("  ✓ Failed pull recorded correctly")
        test_results.append(("Failed Pull Recording", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Failed Pull Recording", False))
        all_passed = False
    
    # Test 5: High Latency Detection
    print("\n[TEST 5] High Latency Detection")
    try:
        monitor = ThreatFeedHealthMonitor()
        for _ in range(5):
            monitor.simulate_feed_pull(
                feed_id="emerging_threats",
                success=True,
                latency_ms=20000,  # Well above 15s threshold
                record_count=1000
            )
        health = monitor.get_feed_health("emerging_threats")
        assert HealthIssueType.LATENCY_HIGH in health.issues
        print("  ✓ High latency correctly detected")
        test_results.append(("High Latency Detection", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("High Latency Detection", False))
        all_passed = False
    
    # Test 6: Consecutive Failures → OFFLINE Status
    print("\n[TEST 6] Consecutive Failures → OFFLINE Status")
    try:
        monitor = ThreatFeedHealthMonitor()
        # 6 consecutive failures (threshold is 5)
        for i in range(6):
            monitor.simulate_feed_pull(
                feed_id="spamhaus_drop",
                success=False,
                latency_ms=500,
                record_count=0,
                error_message=f"Connection failed attempt {i+1}"
            )
        health = monitor.get_feed_health("spamhaus_drop")
        assert health.status == FeedStatus.OFFLINE
        assert health.consecutive_failures >= 5
        print("  ✓ OFFLINE status correctly triggered after 5 failures")
        test_results.append(("Offline Status Detection", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Offline Status Detection", False))
        all_passed = False
    
    # Test 7: Overall Health Score Calculation
    print("\n[TEST 7] Overall Health Score Calculation")
    try:
        monitor = ThreatFeedHealthMonitor()
        score = monitor.get_overall_health_score()
        assert 0 <= score <= 100
        print(f"  ✓ Overall health score calculated: {score:.1f}/100")
        test_results.append(("Health Score Calculation", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Health Score Calculation", False))
        all_passed = False
    
    # Test 8: Health Report Generation
    print("\n[TEST 8] Health Report Generation")
    try:
        monitor = ThreatFeedHealthMonitor()
        monitor.register_feed(
            feed_id="test_feed",
            feed_name="Test Feed",
            feed_url="https://test.com"
        )
        report = monitor.generate_health_report()
        assert "overall_health_score" in report
        assert "total_feeds_monitored" in report
        assert "feeds_by_status" in report
        assert "feeds" in report
        assert report["total_feeds_monitored"] == 6  # 5 default + 1 custom
        print("  ✓ Comprehensive health report generated")
        print(f"    - Feeds monitored: {report['total_feeds_monitored']}")
        print(f"    - Health score: {report['overall_health_score']:.1f}")
        test_results.append(("Health Report Generation", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Health Report Generation", False))
        all_passed = False
    
    # Test 9: Get all feeds health
    print("\n[TEST 9] Get All Feeds Health")
    try:
        all_health = monitor.get_all_feeds_health()
        assert len(all_health) >= 5
        for feed_id, health in all_health.items():
            assert health.feed_id == feed_id
            assert hasattr(health, 'status')
            assert hasattr(health, 'uptime_percent')
        print(f"  ✓ Retrieved health for {len(all_health)} feeds")
        test_results.append(("All Feeds Health Retrieval", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("All Feeds Health Retrieval", False))
        all_passed = False
    
    # Test 10: Incomplete data detection
    print("\n[TEST 10] Incomplete Data Detection")
    try:
        # Feed expects min 10 records, only provide 1 (well below threshold)
        for _ in range(5):
            monitor.simulate_feed_pull(
                feed_id="alien_otx",
                success=True,
                latency_ms=800,
                record_count=1  # Way below minimum of 10
            )
        health = monitor.get_feed_health("alien_otx")
        assert health.data_completeness_score < 0.8
        assert HealthIssueType.DATA_INCOMPLETE in health.issues
        print("  ✓ Incomplete data correctly detected")
        test_results.append(("Incomplete Data Detection", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Incomplete Data Detection", False))
        all_passed = False
    
    # Test 11: Uptime percentage calculation
    print("\n[TEST 11] Uptime Percentage Calculation")
    try:
        monitor = ThreatFeedHealthMonitor()
        monitor.register_feed("custom_feed_001", "Test", "url")
        # 9 successes, 1 failure = 90% uptime
        for _ in range(9):
            monitor.simulate_feed_pull("custom_feed_001", success=True)
        for _ in range(1):
            monitor.simulate_feed_pull("custom_feed_001", success=False)
        health = monitor.get_feed_health("custom_feed_001")
        assert abs(health.uptime_percent - 90.0) < 0.1  # Allow small float error
        print(f"  ✓ Uptime calculated correctly: {health.uptime_percent:.1f}%")
        test_results.append(("Uptime Calculation", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Uptime Calculation", False))
        all_passed = False
    
    # Test 12: Latency percentile calculation
    print("\n[TEST 12] Latency Percentile Calculation")
    try:
        monitor = ThreatFeedHealthMonitor()
        # Consistent latency around 600ms
        for i in range(20):
            monitor.simulate_feed_pull(
                "abuse_ch_feodo",
                success=True,
                latency_ms=500 + (i * 10),
                record_count=100
            )
        health = monitor.get_feed_health("abuse_ch_feodo")
        assert health.avg_latency_ms > 0
        assert health.p95_latency_ms >= health.avg_latency_ms
        assert health.p99_latency_ms >= health.p95_latency_ms
        print("  ✓ Latency percentiles calculated:")
        print(f"    - Avg: {health.avg_latency_ms:.1f}ms")
        print(f"    - P95: {health.p95_latency_ms:.1f}ms")
        print(f"    - P99: {health.p99_latency_ms:.1f}ms")
        test_results.append(("Latency Percentiles", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Latency Percentiles", False))
        all_passed = False
    
    # Test 13: Metrics serialization
    print("\n[TEST 13] Metrics to_dict() Serialization")
    try:
        health = monitor.get_feed_health("abuse_ch_feodo")
        data = health.to_dict()
        # Verify JSON serialization works
        json_str = json.dumps(data)
        assert "feed_id" in data
        assert "status" in data
        assert "uptime_percent" in data
        print("  ✓ Metrics successfully serialized to JSON-compatible dict")
        test_results.append(("Metrics Serialization", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Metrics Serialization", False))
        all_passed = False
    
    # Summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    
    passed_count = 0
    for name, passed in test_results:
        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"  {status} - {name}")
        if passed:
            passed_count += 1
    
    print(f"\nTotal: {passed_count}/{len(test_results)} tests passed")
    
    if all_passed:
        print("\n✅ ALL TESTS PASSED - Production ready!")
    else:
        print(f"\n❌ {len(test_results) - passed_count} TEST(S) FAILED")
    
    # Save results
    result_data = {
        "test_timestamp": datetime.utcnow().isoformat(),
        "total_tests": len(test_results),
        "passed_tests": passed_count,
        "all_passed": all_passed,
        "results": [{"name": n, "passed": p} for n, p in test_results]
    }
    
    with open("/home/user/autonomous-developer/NeuralShield-AI/test_results_threat_feed_health_monitor.json", "w") as f:
        json.dump(result_data, f, indent=2)
    
    print(f"\nTest results saved to test_results_threat_feed_health_monitor.json")
    
    return all_passed


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
