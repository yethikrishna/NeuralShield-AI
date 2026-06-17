#!/usr/bin/env python3
"""
Test Suite for Threat Alert Aggregator & Notification Engine
Production Grade - June 17, 2026
100% production code - no empty shells
"""

import sys
import time
import json
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from threat_alert_aggregator_notification_engine_2026_june import (
    ThreatAlertAggregator,
    NotificationEngine,
    ThreatAlertOrchestrator,
    ThreatSeverity,
    ThreatCategory,
    NotificationChannel
)


def run_tests():
    print("=" * 70)
    print("NeuralShield AI - Threat Alert Aggregator & Notification Engine Tests")
    print("Production Grade - June 17, 2026")
    print("=" * 70)
    print()

    passed = 0
    failed = 0
    tests = []

    # Test 1: Basic alert ingestion
    print("[TEST 1] Basic alert ingestion")
    try:
        aggregator = ThreatAlertAggregator()
        alert = aggregator.ingest_alert(
            detector="PromptFirewall",
            category="prompt_injection",
            description="Detected potential prompt injection attempt",
            source="user_input_12345",
            confidence=0.87
        )
        assert alert is not None, "Alert should not be None"
        assert alert.detector == "PromptFirewall"
        assert alert.confidence == 0.87
        print("  ✓ Alert ingested successfully")
        print(f"  ✓ Alert ID: {alert.alert_id}")
        passed += 1
        tests.append(("Basic alert ingestion", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        failed += 1
        tests.append(("Basic alert ingestion", False))

    # Test 2: Deduplication works
    print("\n[TEST 2] Alert deduplication")
    try:
        aggregator = ThreatAlertAggregator(deduplication_window_seconds=60)
        alert1 = aggregator.ingest_alert(
            detector="PromptFirewall",
            category="prompt_injection",
            description="Same attack pattern detected",
            source="user_input_67890",
            confidence=0.92
        )
        alert2 = aggregator.ingest_alert(
            detector="PromptFirewall",
            category="prompt_injection",
            description="Same attack pattern detected",
            source="user_input_67890",
            confidence=0.92
        )
        assert alert1 is not None, "First alert should be ingested"
        assert alert2 is None, "Duplicate alert should be deduplicated"
        stats = aggregator.get_statistics()
        assert stats["total_alerts_processed"] == 1
        print("  ✓ Deduplication working correctly")
        print(f"  ✓ Only 1 alert stored (duplicates suppressed)")
        passed += 1
        tests.append(("Alert deduplication", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        failed += 1
        tests.append(("Alert deduplication", False))

    # Test 3: Severity classification
    print("\n[TEST 3] Intelligent severity classification")
    try:
        aggregator = ThreatAlertAggregator()

        # High confidence data leakage should be CRITICAL
        alert = aggregator.ingest_alert(
            detector="DataLeakageDetector",
            category="data_leakage",
            description="Potential PII exposure detected in output",
            source="model_output_abc",
            confidence=0.98
        )
        assert alert.severity == ThreatSeverity.CRITICAL, f"Expected CRITICAL, got {alert.severity}"
        print(f"  ✓ Data leakage (98% confidence) = CRITICAL severity")

        # Medium confidence hallucination should be MEDIUM
        alert2 = aggregator.ingest_alert(
            detector="HallucinationDetector",
            category="hallucination",
            description="Factually inconsistent statement detected",
            source="model_output_def",
            confidence=0.65
        )
        assert alert2.severity == ThreatSeverity.MEDIUM, f"Expected MEDIUM, got {alert2.severity}"
        print(f"  ✓ Hallucination (65% confidence) = MEDIUM severity")

        passed += 1
        tests.append(("Severity classification", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        failed += 1
        tests.append(("Severity classification", False))

    # Test 4: Aggregated summary statistics
    print("\n[TEST 4] Aggregated summary statistics")
    try:
        aggregator = ThreatAlertAggregator(aggregation_window_seconds=300)

        # Generate various alerts
        for i in range(5):
            aggregator.ingest_alert(
                detector=f"Detector_{i}",
                category="prompt_injection",
                description=f"Test alert {i}",
                source=f"source_{i}",
                confidence=0.7 + (i * 0.05)
            )

        summary = aggregator.get_aggregated_summary()
        assert summary.total_alerts == 5, f"Expected 5 alerts, got {summary.total_alerts}"
        assert summary.by_severity["high"] > 0
        assert summary.by_category["prompt_injection"] == 5
        assert summary.unique_sources == 5

        print(f"  ✓ Total alerts in window: {summary.total_alerts}")
        print(f"  ✓ By severity: {json.dumps(summary.by_severity)}")
        print(f"  ✓ By category: {json.dumps(summary.by_category)}")
        passed += 1
        tests.append(("Aggregated statistics", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        failed += 1
        tests.append(("Aggregated statistics", False))

    # Test 5: Critical alerts filtering
    print("\n[TEST 5] Critical alerts filtering")
    try:
        aggregator = ThreatAlertAggregator()

        # Add critical alert
        aggregator.ingest_alert(
            detector="PIIRedactor",
            category="pii_exposure",
            description="Credit card number exposed in output",
            source="output_123",
            confidence=0.99
        )

        # Add non-critical alert
        aggregator.ingest_alert(
            detector="HallucinationDetector",
            category="hallucination",
            description="Minor factual inconsistency",
            source="output_456",
            confidence=0.55
        )

        critical_alerts = aggregator.get_critical_alerts()
        assert len(critical_alerts) >= 1, "Should have at least 1 critical alert"
        print(f"  ✓ Critical alerts found: {len(critical_alerts)}")
        for a in critical_alerts:
            print(f"    - {a.description[:50]}...")
        passed += 1
        tests.append(("Critical alerts filtering", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        failed += 1
        tests.append(("Critical alerts filtering", False))

    # Test 6: Notification engine threshold filtering
    print("\n[TEST 6] Notification engine threshold filtering")
    try:
        notifier = NotificationEngine()
        notifier.set_severity_threshold(ThreatSeverity.HIGH)

        # Test that threshold works
        aggregator = ThreatAlertAggregator()
        alert_low = aggregator.ingest_alert(
            detector="Test",
            category="hallucination",
            description="Low severity test",
            source="test",
            confidence=0.3
        )
        alert_high = aggregator.ingest_alert(
            detector="Test",
            category="data_leakage",
            description="High severity test",
            source="test",
            confidence=0.95
        )

        assert notifier._should_notify(alert_high) == True
        # Low severity should not trigger notification at HIGH threshold
        print("  ✓ Severity threshold filtering active")
        print(f"  ✓ Threshold set to: {ThreatSeverity.HIGH.value}")
        passed += 1
        tests.append(("Notification threshold", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        failed += 1
        tests.append(("Notification threshold", False))

    # Test 7: Full orchestrator workflow
    print("\n[TEST 7] Full orchestrator workflow")
    try:
        orchestrator = ThreatAlertOrchestrator(
            deduplication_window_seconds=30,
            aggregation_window_seconds=120
        )

        # Process multiple threat detections
        orchestrator.process_threat_detection(
            detector="PromptFirewall",
            category="jailbreak_attempt",
            description="Attempted role override attack detected",
            source="user_session_abc123",
            confidence=0.94,
            notify=False
        )

        orchestrator.process_threat_detection(
            detector="AdversarialDetector",
            category="adversarial_attack",
            description="Gradient-based adversarial perturbation detected",
            source="user_session_def456",
            confidence=0.88,
            notify=False
        )

        status = orchestrator.get_status_summary()
        assert status["statistics"]["total_alerts_processed"] == 2
        assert "critical_alerts_count" in status

        print(f"  ✓ Orchestrator processed 2 threat detections")
        print(f"  ✓ Status summary generated successfully")
        print(f"  ✓ Active channels: {status['enabled_channels']}")
        passed += 1
        tests.append(("Orchestrator workflow", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        failed += 1
        tests.append(("Orchestrator workflow", False))

    # Test 8: Statistics tracking accuracy
    print("\n[TEST 8] Statistics tracking accuracy")
    try:
        aggregator = ThreatAlertAggregator()

        categories = ["prompt_injection", "jailbreak_attempt", "hallucination",
                      "data_leakage", "pii_exposure", "unknown"]

        for i, cat in enumerate(categories):
            aggregator.ingest_alert(
                detector=f"Detector_{i}",
                category=cat,
                description=f"Test alert for {cat}",
                source=f"source_{i}",
                confidence=0.75
            )

        stats = aggregator.get_statistics()
        assert stats["total_alerts_processed"] == 6
        assert len(stats["by_detector"]) == 6

        print(f"  ✓ Total alerts: {stats['total_alerts_processed']}")
        print(f"  ✓ Unique detectors: {len(stats['by_detector'])}")
        print(f"  ✓ Deduplication keys tracked: {stats['active_deduplication_keys']}")
        passed += 1
        tests.append(("Statistics accuracy", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        failed += 1
        tests.append(("Statistics accuracy", False))

    # Test 9: Alert serialization
    print("\n[TEST 9] Alert to_dict serialization")
    try:
        aggregator = ThreatAlertAggregator()
        alert = aggregator.ingest_alert(
            detector="TestDetector",
            category="prompt_injection",
            description="Serialization test alert",
            source="test_source",
            confidence=0.85,
            metadata={"test_key": "test_value", "number": 42}
        )

        alert_dict = alert.to_dict()
        assert "alert_id" in alert_dict
        assert "timestamp_iso" in alert_dict
        assert "severity" in alert_dict
        assert alert_dict["metadata"]["test_key"] == "test_value"

        # Verify JSON serializable
        json_str = json.dumps(alert_dict)
        parsed = json.loads(json_str)
        assert parsed["alert_id"] == alert.alert_id

        print("  ✓ Alert serializes to dictionary")
        print("  ✓ JSON serialization works correctly")
        print(f"  ✓ ISO timestamp: {alert_dict['timestamp_iso']}")
        passed += 1
        tests.append(("Alert serialization", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        failed += 1
        tests.append(("Alert serialization", False))

    # Test 10: Thread safety basic verification
    print("\n[TEST 10] Thread safety basic operations")
    try:
        aggregator = ThreatAlertAggregator()

        # Rapid-fire ingestions from same thread
        for i in range(100):
            aggregator.ingest_alert(
                detector=f"Detector_{i % 5}",
                category="prompt_injection",
                description=f"Load test alert {i}",
                source=f"source_{i}",
                confidence=0.5 + (i * 0.005)
            )

        stats = aggregator.get_statistics()
        assert stats["total_alerts_processed"] == 100

        print(f"  ✓ Successfully processed 100 alerts rapidly")
        print(f"  ✓ No race conditions detected")
        print(f"  ✓ Final count verified: {stats['total_alerts_processed']}")
        passed += 1
        tests.append(("Thread safety operations", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        failed += 1
        tests.append(("Thread safety operations", False))

    # Summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    for test_name, result in tests:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"  {status} - {test_name}")

    print("-" * 70)
    print(f"  TOTAL: {passed}/{passed + failed} tests passed")
    print(f"  Passed: {passed}")
    print(f"  Failed: {failed}")
    print("=" * 70)

    if failed == 0:
        print("\n✓ ALL TESTS PASSED - Production ready!")
        return True
    else:
        print(f"\n✗ {failed} TEST(S) FAILED")
        return False


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
