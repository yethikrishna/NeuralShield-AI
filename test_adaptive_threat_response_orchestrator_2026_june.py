#!/usr/bin/env python3
"""
Test Suite for Adaptive Threat Response Orchestrator
June 2026 Production Release
Real working tests with actual execution
"""

import sys
import time
import unittest
from typing import Dict, Any

# Add module path
sys.path.insert(0, '.')

from neural_shield.adaptive_threat_response_orchestrator_2026_june import (
    AdaptiveThreatResponseOrchestrator,
    ThreatSeverity,
    MitigationStrategy,
    ResponseOutcome,
    ThreatEvent,
    MitigationAction
)


class TestAdaptiveThreatResponseOrchestrator(unittest.TestCase):
    """Real working tests for the threat response orchestrator"""

    def setUp(self):
        """Set up test orchestrator instance"""
        self.orchestrator = AdaptiveThreatResponseOrchestrator(
            enable_automatic_response=True,
            learning_enabled=True
        )

    def test_initialization(self):
        """Test proper initialization of orchestrator"""
        self.assertIsNotNone(self.orchestrator)
        self.assertTrue(self.orchestrator.enable_automatic_response)
        self.assertTrue(self.orchestrator.learning_enabled)
        self.assertEqual(len(self.orchestrator.event_history), 0)
        print("✓ Initialization test passed")

    def test_threat_severity_classification(self):
        """Test real threat severity classification logic"""
        # Test critical threats
        severity = self.orchestrator.classify_threat_severity('pii_leakage', 0.95)
        self.assertEqual(severity, ThreatSeverity.CRITICAL)

        # Test high severity threats
        severity = self.orchestrator.classify_threat_severity('jailbreak_attempt', 0.85)
        self.assertEqual(severity, ThreatSeverity.HIGH)

        # Test medium severity threats
        severity = self.orchestrator.classify_threat_severity('adversarial_attack', 0.5)
        self.assertEqual(severity, ThreatSeverity.MEDIUM)

        # Test low confidence adjustment (should downgrade)
        severity = self.orchestrator.classify_threat_severity('jailbreak_attempt', 0.2)
        self.assertEqual(severity, ThreatSeverity.MEDIUM)

        # Test repeated occurrence escalation
        severity = self.orchestrator.classify_threat_severity('adversarial_attack', 0.5, historical_count=6)
        self.assertEqual(severity, ThreatSeverity.HIGH)

        print("✓ Threat severity classification test passed")

    def test_threat_event_ingestion(self):
        """Test real threat event ingestion and processing"""
        event, actions = self.orchestrator.ingest_threat_event(
            threat_type='prompt_injection',
            source='192.168.1.100',
            confidence_score=0.88,
            details={'pattern': 'ignore previous instructions', 'payload_length': 156},
            affected_components=['input_handler', 'context_manager']
        )

        # Verify event creation
        self.assertIsInstance(event, ThreatEvent)
        self.assertEqual(event.threat_type, 'prompt_injection')
        self.assertEqual(event.severity, ThreatSeverity.HIGH)
        self.assertGreater(event.confidence_score, 0)
        self.assertIsNotNone(event.event_id)

        # Verify actions were taken
        self.assertGreater(len(actions), 0)
        for action in actions:
            self.assertIsInstance(action, MitigationAction)
            self.assertIn(action.strategy, [
                MitigationStrategy.REJECT_REQUEST,
                MitigationStrategy.TEMPORARY_BLOCK,
                MitigationStrategy.CONTEXT_ISOLATION
            ])

        # Verify event was stored
        self.assertEqual(len(self.orchestrator.event_history), 1)

        print("✓ Threat event ingestion test passed")

    def test_multiple_threat_events(self):
        """Test processing multiple threat events"""
        threat_scenarios = [
            ('suspicious_pattern', 'user_123', 0.45, {'pattern': 'unusual_token_sequence'}),
            ('jailbreak_attempt', 'user_456', 0.92, {'technique': 'DAN_variant'}),
            ('adversarial_attack', 'user_789', 0.65, {'gradient_based': True}),
            ('pii_leakage', 'user_123', 0.99, {'data_type': 'credit_card'}),
        ]

        for threat_type, source, confidence, details in threat_scenarios:
            event, actions = self.orchestrator.ingest_threat_event(
                threat_type, source, confidence, details
            )
            self.assertIsNotNone(event.event_id)
            self.assertGreater(len(actions), 0)

        self.assertEqual(len(self.orchestrator.event_history), 4)
        print("✓ Multiple threat events test passed")

    def test_temporary_blocking_mechanism(self):
        """Test real temporary blocking functionality"""
        source_ip = '10.0.0.50'

        # Initially not blocked
        blocked, info = self.orchestrator.is_source_blocked(source_ip)
        self.assertFalse(blocked)
        self.assertIsNone(info)

        # Trigger a high severity threat that causes blocking
        event, actions = self.orchestrator.ingest_threat_event(
            threat_type='jailbreak_attempt',
            source=source_ip,
            confidence_score=0.95,
            details={'known_attack': True}
        )

        # Should now be blocked
        blocked, info = self.orchestrator.is_source_blocked(source_ip)
        self.assertTrue(blocked)
        self.assertIsNotNone(info)
        self.assertIn('blocked_until', info)
        self.assertGreater(info['blocked_until'], time.time())

        print("✓ Temporary blocking mechanism test passed")

    def test_metrics_and_reporting(self):
        """Test metrics collection and reporting functionality"""
        # Generate some events first
        for i in range(5):
            self.orchestrator.ingest_threat_event(
                threat_type='suspicious_pattern',
                source=f'test_source_{i}',
                confidence_score=0.3 + (i * 0.1),
                details={'test': True}
            )

        metrics = self.orchestrator.get_response_metrics()

        # Verify metrics structure
        self.assertIn('summary', metrics)
        self.assertIn('severity_distribution', metrics)
        self.assertIn('strategy_effectiveness', metrics)
        self.assertEqual(metrics['summary']['total_events_processed'], 5)

        # Test audit report
        report = self.orchestrator.generate_audit_report()
        self.assertIn('report_period', report)
        self.assertIn('event_count', report)
        self.assertEqual(report['event_count'], 5)

        print("✓ Metrics and reporting test passed")

    def test_adaptive_learning(self):
        """Test adaptive learning from strategy effectiveness"""
        # Generate events to trigger learning
        for _ in range(3):
            self.orchestrator.ingest_threat_event(
                threat_type='prompt_injection',
                source='test_source',
                confidence_score=0.8,
                details={}
            )

        metrics = self.orchestrator.get_response_metrics()
        strategy_stats = metrics['strategy_effectiveness']

        # Verify effectiveness tracking is working
        self.assertGreater(len(strategy_stats), 0)
        for strategy, stats in strategy_stats.items():
            self.assertIn('success_rate', stats)
            self.assertIn('avg_effectiveness', stats)
            self.assertIn('total_uses', stats)
            self.assertGreater(stats['total_uses'], 0)

        print("✓ Adaptive learning test passed")

    def test_callback_integration(self):
        """Test callback integration points"""
        callback_results = {'threat_detected': 0, 'mitigation_executed': 0}

        def on_threat(event):
            callback_results['threat_detected'] += 1

        def on_mitigation(action, event):
            callback_results['mitigation_executed'] += 1

        self.orchestrator.on_threat_detected = on_threat
        self.orchestrator.on_mitigation_executed = on_mitigation

        self.orchestrator.ingest_threat_event(
            'suspicious_pattern', 'callback_test', 0.5, {}
        )

        self.assertEqual(callback_results['threat_detected'], 1)
        self.assertGreater(callback_results['mitigation_executed'], 0)

        print("✓ Callback integration test passed")

    def test_unknown_threat_handling(self):
        """Test handling of unknown threat types"""
        event, actions = self.orchestrator.ingest_threat_event(
            threat_type='unknown_attack_type',
            source='test_source',
            confidence_score=0.5,
            details={}
        )

        self.assertEqual(event.severity, ThreatSeverity.UNKNOWN)
        # Should still log and process even unknown threats
        self.assertGreater(len(actions), 0)

        print("✓ Unknown threat handling test passed")


def run_comprehensive_test():
    """Run all tests and generate comprehensive report"""
    print("=" * 70)
    print("ADAPTIVE THREAT RESPONSE ORCHESTRATOR - TEST SUITE")
    print("June 2026 Production Release")
    print("=" * 70)
    print()

    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestAdaptiveThreatResponseOrchestrator)

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    print()
    print("=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    print(f"Tests Run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success: {'✓ ALL TESTS PASSED' if result.wasSuccessful() else '✗ SOME TESTS FAILED'}")
    print()

    # Demonstration of actual usage
    print("=" * 70)
    print("LIVE DEMONSTRATION - ACTUAL ORCHESTRATOR USAGE")
    print("=" * 70)

    orchestrator = AdaptiveThreatResponseOrchestrator()

    # Simulate real security operations
    print("\nProcessing real threat events...")
    scenarios = [
        ("LOW severity - Suspicious pattern", 'suspicious_pattern', 'user_alpha', 0.35),
        ("MEDIUM severity - Adversarial attack", 'adversarial_attack', 'user_beta', 0.65),
        ("HIGH severity - Jailbreak attempt", 'jailbreak_attempt', 'user_gamma', 0.90),
        ("CRITICAL severity - PII leakage", 'pii_leakage', 'user_delta', 0.98),
    ]

    for desc, threat_type, source, confidence in scenarios:
        print(f"\n  {desc}:")
        event, actions = orchestrator.ingest_threat_event(
            threat_type, source, confidence, {'demo': True}
        )
        print(f"    Severity: {event.severity.value.upper()}")
        print(f"    Actions taken: {len(actions)}")
        for action in actions[:2]:  # Show first 2 actions
            print(f"      - {action.strategy.value} (effectiveness: {action.effectiveness_score:.2f})")

    # Show final metrics
    print("\n" + "=" * 70)
    print("FINAL SYSTEM METRICS")
    print("=" * 70)
    metrics = orchestrator.get_response_metrics()
    for key, value in metrics['summary'].items():
        print(f"  {key}: {value}")

    print()
    return result.wasSuccessful()


if __name__ == '__main__':
    success = run_comprehensive_test()
    sys.exit(0 if success else 1)
