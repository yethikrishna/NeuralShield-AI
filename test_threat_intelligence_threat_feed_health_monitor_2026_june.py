#!/usr/bin/env python3
"""
Test suite for Threat Intelligence Threat Feed Health Monitor
Production-grade testing with real assertions
"""

import sys
import json
from datetime import datetime, timedelta
from neural_shield.threat_intelligence_threat_feed_health_monitor_2026_june import (
    ThreatFeedHealthMonitor,
    FeedConfiguration,
    FeedHealthStatus,
    FeedQualityIssue
)


def run_tests():
    print("=" * 60)
    print("THREAT FEED HEALTH MONITOR - TEST SUITE")
    print("=" * 60)
    
    test_results = {
        "passed": 0,
        "failed": 0,
        "tests": []
    }

    # Test 1: Basic initialization
    print("\n[TEST 1] Basic Initialization")
    try:
        monitor = ThreatFeedHealthMonitor()
        assert monitor is not None
        assert len(monitor.get_all_feeds_health()) == 0
        print("  ✓ Monitor initialized correctly")
        test_results["passed"] += 1
        test_results["tests"].append({"test": "initialization", "status": "passed"})
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        test_results["failed"] += 1
        test_results["tests"].append({"test": "initialization", "status": "failed", "error": str(e)})

    # Test 2: Feed registration
    print("\n[TEST 2] Feed Registration")
    try:
        monitor = ThreatFeedHealthMonitor()
        config = FeedConfiguration(
            feed_name="test_abusech_feed",
            feed_url="https://feeds.abuse.ch/urlhaus/",
            expected_update_interval_minutes=15
        )
        monitor.register_feed(config)
        assert "test_abusech_feed" in monitor.get_all_feeds_health()
        print("  ✓ Feed registered successfully")
        test_results["passed"] += 1
        test_results["tests"].append({"test": "feed_registration", "status": "passed"})
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        test_results["failed"] += 1
        test_results["tests"].append({"test": "feed_registration", "status": "failed", "error": str(e)})

    # Test 3: Healthy feed check
    print("\n[TEST 3] Healthy Feed Detection")
    try:
        monitor = ThreatFeedHealthMonitor()
        config = FeedConfiguration(feed_name="healthy_feed", feed_url="test://healthy")
        monitor.register_feed(config)
        
        sample_feed_data = [
            {"ioc": "192.168.1.1", "type": "ip", "timestamp": datetime.utcnow().timestamp()},
            {"ioc": "10.0.0.1", "type": "ip", "timestamp": datetime.utcnow().timestamp()},
            {"ioc": "malware.com", "type": "domain", "timestamp": datetime.utcnow().timestamp()}
        ]
        
        metrics = monitor.check_feed_health(
            feed_name="healthy_feed",
            feed_data=sample_feed_data,
            response_time_ms=150.0,
            pull_successful=True
        )
        
        assert metrics.status == FeedHealthStatus.HEALTHY
        assert metrics.entry_count == 3
        assert metrics.success_rate == 100.0
        assert metrics.duplicate_count == 0
        print("  ✓ Healthy feed correctly identified")
        test_results["passed"] += 1
        test_results["tests"].append({"test": "healthy_feed", "status": "passed"})
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        test_results["failed"] += 1
        test_results["tests"].append({"test": "healthy_feed", "status": "failed", "error": str(e)})

    # Test 4: Duplicate detection
    print("\n[TEST 4] Duplicate Entry Detection")
    try:
        monitor = ThreatFeedHealthMonitor()
        config = FeedConfiguration(feed_name="dup_feed", feed_url="test://dup")
        monitor.register_feed(config)
        
        duplicate_entry = {"ioc": "192.168.1.1", "type": "ip", "timestamp": 1234567890}
        sample_feed_data = [
            duplicate_entry,
            duplicate_entry,  # Exact duplicate
            {"ioc": "10.0.0.1", "type": "ip", "timestamp": 1234567890}
        ]
        
        metrics = monitor.check_feed_health(
            feed_name="dup_feed",
            feed_data=sample_feed_data,
            response_time_ms=200.0,
            pull_successful=True
        )
        
        assert metrics.duplicate_count == 1
        assert FeedQualityIssue.DUPLICATE_ENTRIES in metrics.quality_issues
        print(f"  ✓ Duplicate detection working: found {metrics.duplicate_count} duplicates")
        test_results["passed"] += 1
        test_results["tests"].append({"test": "duplicate_detection", "status": "passed"})
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        test_results["failed"] += 1
        test_results["tests"].append({"test": "duplicate_detection", "status": "failed", "error": str(e)})

    # Test 5: Missing fields detection
    print("\n[TEST 5] Missing Required Fields Detection")
    try:
        monitor = ThreatFeedHealthMonitor()
        config = FeedConfiguration(
            feed_name="missing_fields_feed", 
            feed_url="test://missing",
            required_fields=["ioc", "type", "timestamp"]
        )
        monitor.register_feed(config)
        
        # Entry missing 'timestamp' field
        sample_feed_data = [
            {"ioc": "192.168.1.1", "type": "ip"}  # Missing timestamp
        ]
        
        metrics = monitor.check_feed_health(
            feed_name="missing_fields_feed",
            feed_data=sample_feed_data,
            response_time_ms=100.0,
            pull_successful=True
        )
        
        assert FeedQualityIssue.MISSING_FIELDS in metrics.quality_issues
        assert metrics.status == FeedHealthStatus.DEGRADED
        print("  ✓ Missing fields correctly detected")
        test_results["passed"] += 1
        test_results["tests"].append({"test": "missing_fields", "status": "passed"})
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        test_results["failed"] += 1
        test_results["tests"].append({"test": "missing_fields", "status": "failed", "error": str(e)})

    # Test 6: Failure tracking and offline detection
    print("\n[TEST 6] Consecutive Failure / Offline Detection")
    try:
        monitor = ThreatFeedHealthMonitor()
        config = FeedConfiguration(feed_name="failing_feed", feed_url="test://failing")
        monitor.register_feed(config)
        
        # Simulate 3 consecutive failures
        for i in range(3):
            metrics = monitor.check_feed_health(
                feed_name="failing_feed",
                feed_data=None,
                response_time_ms=None,
                pull_successful=False,
                error_message=f"Connection timeout (attempt {i+1})"
            )
        
        assert metrics.consecutive_failures == 3
        assert metrics.status == FeedHealthStatus.OFFLINE
        assert metrics.success_rate < 100
        print(f"  ✓ Offline detection working after {metrics.consecutive_failures} failures")
        test_results["passed"] += 1
        test_results["tests"].append({"test": "offline_detection", "status": "passed"})
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        test_results["failed"] += 1
        test_results["tests"].append({"test": "offline_detection", "status": "failed", "error": str(e)})

    # Test 7: Stale data detection
    print("\n[TEST 7] Stale Data Detection")
    try:
        monitor = ThreatFeedHealthMonitor()
        config = FeedConfiguration(
            feed_name="stale_feed", 
            feed_url="test://stale",
            freshness_threshold_critical_minutes=60
        )
        monitor.register_feed(config)
        
        # Data from 24 hours ago (very stale)
        stale_timestamp = (datetime.utcnow() - timedelta(hours=24)).timestamp()
        sample_feed_data = [
            {"ioc": "192.168.1.1", "type": "ip", "timestamp": stale_timestamp}
        ]
        
        metrics = monitor.check_feed_health(
            feed_name="stale_feed",
            feed_data=sample_feed_data,
            response_time_ms=100.0,
            pull_successful=True
        )
        
        assert metrics.data_freshness_minutes > 60
        assert metrics.status == FeedHealthStatus.STALE
        print(f"  ✓ Stale data detected: {metrics.data_freshness_minutes:.1f} minutes old")
        test_results["passed"] += 1
        test_results["tests"].append({"test": "stale_detection", "status": "passed"})
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        test_results["failed"] += 1
        test_results["tests"].append({"test": "stale_detection", "status": "failed", "error": str(e)})

    # Test 8: Latency tracking
    print("\n[TEST 8] Latency History and Averaging")
    try:
        monitor = ThreatFeedHealthMonitor()
        config = FeedConfiguration(feed_name="latency_feed", feed_url="test://latency")
        monitor.register_feed(config)
        
        sample_data = [{"ioc": "192.168.1.1", "type": "ip", "timestamp": datetime.utcnow().timestamp()}]
        
        # Record varying latencies
        latencies = [100.0, 200.0, 300.0, 400.0, 500.0]
        for lat in latencies:
            monitor.check_feed_health(
                feed_name="latency_feed",
                feed_data=sample_data,
                response_time_ms=lat,
                pull_successful=True
            )
        
        metrics = monitor.get_feed_health("latency_feed")
        expected_avg = sum(latencies) / len(latencies)
        assert abs(metrics.average_latency_ms - expected_avg) < 0.01
        print(f"  ✓ Latency averaging correct: avg={metrics.average_latency_ms:.1f}ms")
        test_results["passed"] += 1
        test_results["tests"].append({"test": "latency_tracking", "status": "passed"})
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        test_results["failed"] += 1
        test_results["tests"].append({"test": "latency_tracking", "status": "failed", "error": str(e)})

    # Test 9: Health summary generation
    print("\n[TEST 9] Health Summary Report")
    try:
        monitor = ThreatFeedHealthMonitor()
        
        # Register multiple feeds with different statuses
        monitor.register_feed(FeedConfiguration(feed_name="feed1", feed_url="test://1"))
        monitor.register_feed(FeedConfiguration(feed_name="feed2", feed_url="test://2"))
        
        sample_data = [{"ioc": "192.168.1.1", "type": "ip", "timestamp": datetime.utcnow().timestamp()}]
        
        monitor.check_feed_health("feed1", sample_data, 100.0, True)
        monitor.check_feed_health("feed2", sample_data, 150.0, True)
        
        summary = monitor.get_health_summary()
        assert summary["total_feeds_monitored"] == 2
        assert "status_breakdown" in summary
        assert "average_latency_all_feeds_ms" in summary
        print("  ✓ Health summary generated correctly")
        test_results["passed"] += 1
        test_results["tests"].append({"test": "health_summary", "status": "passed"})
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        test_results["failed"] += 1
        test_results["tests"].append({"test": "health_summary", "status": "failed", "error": str(e)})

    # Test 10: Full health report
    print("\n[TEST 10] Human-Readable Health Report")
    try:
        monitor = ThreatFeedHealthMonitor()
        monitor.register_feed(FeedConfiguration(feed_name="report_feed", feed_url="test://report"))
        sample_data = [{"ioc": "192.168.1.1", "type": "ip", "timestamp": datetime.utcnow().timestamp()}]
        monitor.check_feed_health("report_feed", sample_data, 100.0, True)
        
        report = monitor.generate_health_report()
        assert isinstance(report, str)
        assert len(report) > 0
        assert "THREAT FEED HEALTH MONITOR" in report
        print("  ✓ Full health report generated")
        test_results["passed"] += 1
        test_results["tests"].append({"test": "health_report", "status": "passed"})
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        test_results["failed"] += 1
        test_results["tests"].append({"test": "health_report", "status": "failed", "error": str(e)})

    # Print final results
    print("\n" + "=" * 60)
    print("TEST RESULTS SUMMARY")
    print("=" * 60)
    print(f"Passed: {test_results['passed']}")
    print(f"Failed: {test_results['failed']}")
    print(f"Total:  {test_results['passed'] + test_results['failed']}")
    print(f"Success Rate: {(test_results['passed']/(test_results['passed']+test_results['failed'])*100):.1f}%")
    
    # Save results
    with open("test_results_threat_feed_health_monitor.json", "w") as f:
        json.dump(test_results, f, indent=2)
    
    print("\nTest results saved to test_results_threat_feed_health_monitor.json")
    
    return test_results["failed"] == 0


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
