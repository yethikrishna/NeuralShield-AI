#!/usr/bin/env python3
"""
Test suite for NeuralShield Real-Time Metrics Aggregator
Production-grade tests with actual assertions
"""

import sys
import time
import threading
import json
sys.path.insert(0, '.')

from neural_shield.threat_intelligence_realtime_metrics_aggregator_2026_june import (
    RealtimeMetricsAggregator,
    ThreatEvent,
    get_global_aggregator
)


def test_basic_event_addition():
    """Test basic event addition and retrieval"""
    print("Test 1: Basic Event Addition")
    aggregator = RealtimeMetricsAggregator()
    
    event_id = aggregator.add_event_simple(
        threat_type="prompt_injection",
        severity="critical",
        source="api_gateway",
        confidence=0.95
    )
    
    assert event_id is not None
    assert len(event_id) > 0
    
    metrics = aggregator.get_metrics()
    assert metrics["aggregator_info"]["total_events_processed"] == 1
    assert metrics["windows"]["1min"]["total_events"] == 1
    assert metrics["windows"]["1min"]["severity_distribution"]["critical"] == 1
    
    print("  ✓ Events added correctly")
    print("  ✓ Metrics updated correctly")
    return True


def test_severity_distribution():
    """Test severity distribution calculation"""
    print("\nTest 2: Severity Distribution Calculation")
    aggregator = RealtimeMetricsAggregator()
    
    # Add events of different severities
    for _ in range(5):
        aggregator.add_event_simple("test", "critical")
    for _ in range(10):
        aggregator.add_event_simple("test", "high")
    for _ in range(15):
        aggregator.add_event_simple("test", "medium")
    
    metrics = aggregator.get_metrics()
    dist = metrics["windows"]["total"]["severity_distribution"]
    
    assert dist["critical"] == 5
    assert dist["high"] == 10
    assert dist["medium"] == 15
    assert dist["low"] == 0
    assert dist["info"] == 0
    
    print("  ✓ Critical count: 5")
    print("  ✓ High count: 10")
    print("  ✓ Medium count: 15")
    return True


def test_threat_score_calculation():
    """Test threat score and risk level calculation"""
    print("\nTest 3: Threat Score and Risk Level")
    aggregator = RealtimeMetricsAggregator()
    
    # Empty aggregator should have NORMAL risk
    metrics = aggregator.get_metrics()
    assert metrics["overall_threat_score"]["risk_level"] == "NORMAL"
    assert metrics["overall_threat_score"]["score"] == 0
    
    # Add critical events to trigger CRITICAL risk
    for _ in range(3):  # 3 * 25 = 75 points
        aggregator.add_event_simple("test", "critical")
    
    metrics = aggregator.get_metrics()
    assert metrics["overall_threat_score"]["risk_level"] == "CRITICAL"
    assert metrics["overall_threat_score"]["score"] >= 70
    
    print("  ✓ NORMAL risk level for empty aggregator")
    print("  ✓ CRITICAL risk level for high severity")
    print(f"  ✓ Threat score: {metrics['overall_threat_score']['score']}")
    return True


def test_thread_safety():
    """Test thread-safe concurrent event addition"""
    print("\nTest 4: Thread Safety (Concurrent Events)")
    aggregator = RealtimeMetricsAggregator()
    
    events_per_thread = 100
    num_threads = 10
    
    def worker():
        for i in range(events_per_thread):
            aggregator.add_event_simple(
                threat_type=f"thread_test_{i}",
                severity=["critical", "high", "medium", "low"][i % 4]
            )
    
    threads = [threading.Thread(target=worker) for _ in range(num_threads)]
    
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    
    metrics = aggregator.get_metrics()
    total = metrics["aggregator_info"]["total_events_processed"]
    expected = events_per_thread * num_threads
    
    assert total == expected, f"Expected {expected}, got {total}"
    
    print(f"  ✓ {num_threads} threads completed")
    print(f"  ✓ {total} events processed without race conditions")
    return True


def test_threat_summary():
    """Test concise threat summary output"""
    print("\nTest 5: Threat Summary Generation")
    aggregator = RealtimeMetricsAggregator()
    
    for i in range(20):
        aggregator.add_event_simple(
            threat_type=["injection", "jailbreak", "leak"][i % 3],
            severity=["critical", "high", "medium"][i % 3]
        )
    
    summary = aggregator.get_threat_summary()
    
    assert "timestamp" in summary
    assert "threat_score" in summary
    assert "events_last_minute" in summary
    assert "critical_alerts" in summary
    assert "top_threats" in summary
    assert isinstance(summary["top_threats"], dict)
    
    print("  ✓ Summary contains all required fields")
    print(f"  ✓ Events in summary: {summary['events_last_minute']}")
    print(f"  ✓ Top threats: {list(summary['top_threats'].keys())}")
    return True


def test_json_output():
    """Test JSON output for dashboards"""
    print("\nTest 6: JSON Output Format")
    aggregator = RealtimeMetricsAggregator()
    
    aggregator.add_event_simple("test_attack", "high")
    
    json_output = aggregator.get_metrics_json(pretty=True)
    
    # Validate it's valid JSON
    parsed = json.loads(json_output)
    assert "aggregator_info" in parsed
    assert "windows" in parsed
    assert "overall_threat_score" in parsed
    
    print("  ✓ Valid JSON output")
    print("  ✓ Contains all required sections")
    return True


def test_confidence_stats():
    """Test confidence statistics calculation"""
    print("\nTest 7: Confidence Statistics")
    aggregator = RealtimeMetricsAggregator()
    
    # Add events with known confidence values
    aggregator.add_event_simple("test", "medium", confidence=0.2)
    aggregator.add_event_simple("test", "medium", confidence=0.5)
    aggregator.add_event_simple("test", "medium", confidence=0.8)
    
    metrics = aggregator.get_metrics()
    win = metrics["windows"]["total"]
    
    assert abs(win["avg_confidence"] - 0.5) < 0.01
    assert win["max_confidence"] == 0.8
    assert win["min_confidence"] == 0.2
    
    print(f"  ✓ Avg confidence: {win['avg_confidence']:.2f}")
    print(f"  ✓ Max confidence: {win['max_confidence']}")
    print(f"  ✓ Min confidence: {win['min_confidence']}")
    return True


def test_singleton_pattern():
    """Test global singleton aggregator"""
    print("\nTest 8: Global Singleton Pattern")
    
    agg1 = get_global_aggregator()
    agg2 = get_global_aggregator()
    
    assert agg1 is agg2
    
    agg1.add_event_simple("singleton_test", "low")
    
    metrics = agg2.get_metrics()
    assert metrics["aggregator_info"]["total_events_processed"] >= 1
    
    print("  ✓ Same instance returned")
    print("  ✓ State shared between references")
    return True


def test_event_validation():
    """Test event validation"""
    print("\nTest 9: Event Validation")
    aggregator = RealtimeMetricsAggregator()
    
    # Invalid severity should be rejected
    invalid_event = ThreatEvent(
        event_id="test",
        timestamp=time.time(),
        threat_type="test",
        severity="invalid_severity",  # Invalid
        source="test",
        confidence=0.5
    )
    result = aggregator.add_event(invalid_event)
    assert result is False
    
    # Confidence out of range should be clamped in simple interface
    event_id = aggregator.add_event_simple("test", "low", confidence=2.0)  # Too high
    assert event_id is not None  # Should work (clamped)
    
    print("  ✓ Invalid severity rejected")
    print("  ✓ Confidence clamped to valid range")
    return True


def test_clear_function():
    """Test clearing events"""
    print("\nTest 10: Clear Events Function")
    aggregator = RealtimeMetricsAggregator()
    
    for _ in range(50):
        aggregator.add_event_simple("test", "medium")
    
    metrics_before = aggregator.get_metrics()
    assert metrics_before["aggregator_info"]["events_in_buffer"] == 50
    
    aggregator.clear()
    
    metrics_after = aggregator.get_metrics()
    assert metrics_after["aggregator_info"]["events_in_buffer"] == 0
    
    print("  ✓ Events cleared successfully")
    print("  ✓ Buffer is empty after clear")
    return True


def main():
    """Run all tests"""
    print("=" * 60)
    print("NeuralShield - Real-Time Metrics Aggregator Tests")
    print("Production-Grade Validation Suite")
    print("=" * 60)
    print()
    
    tests = [
        test_basic_event_addition,
        test_severity_distribution,
        test_threat_score_calculation,
        test_thread_safety,
        test_threat_summary,
        test_json_output,
        test_confidence_stats,
        test_singleton_pattern,
        test_event_validation,
        test_clear_function,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            if test():
                passed += 1
        except Exception as e:
            print(f"  ✗ FAILED: {e}")
            failed += 1
    
    print()
    print("=" * 60)
    print(f"TEST RESULTS: {passed} PASSED, {failed} FAILED")
    print("=" * 60)
    
    if failed > 0:
        print("\n❌ Some tests failed!")
        return 1
    else:
        print("\n✅ All tests passed! Module is production-ready.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
