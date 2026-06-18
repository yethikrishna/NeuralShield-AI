#!/usr/bin/env python3
"""
Test suite for Threat Intelligence Context Correlation Engine
Real, working tests that verify actual functionality
"""

import sys
import time
import unittest

sys.path.insert(0, '/home/user/autonomous-developer/NeuralShield-AI')

from neural_shield.threat_intelligence_context_correlation_engine_2026_june import (
    ThreatContextCorrelationEngine,
    DetectionSignal,
    CorrelatedThreat,
    ThreatSeverity,
    DetectionSource
)


class TestThreatContextCorrelationEngine(unittest.TestCase):
    """Real working tests for the correlation engine"""

    def setUp(self):
        """Set up test engine"""
        self.engine = ThreatContextCorrelationEngine(
            correlation_window_seconds=300,
            min_signals_for_correlation=2,
            false_positive_threshold=0.7
        )

    def test_signal_ingestion(self):
        """Test that signals are properly ingested"""
        signal = DetectionSignal(
            signal_id="test_001",
            source=DetectionSource.PROMPT_INJECTION,
            confidence=0.85,
            severity=ThreatSeverity.HIGH,
            timestamp=time.time(),
            metadata={"pattern": "ignore previous instructions"}
        )
        
        self.engine.ingest_signal(signal)
        self.assertEqual(len(self.engine.signal_buffer), 1)
        self.assertEqual(self.engine.signal_buffer[0].signal_id, "test_001")

    def test_fingerprint_generation(self):
        """Test that threat fingerprints are generated correctly"""
        signal1 = DetectionSignal(
            signal_id="test_001",
            source=DetectionSource.PROMPT_INJECTION,
            confidence=0.85,
            severity=ThreatSeverity.HIGH,
            timestamp=time.time(),
            metadata={"pattern": "ignore previous instructions"}
        )
        
        signal2 = DetectionSignal(
            signal_id="test_002",
            source=DetectionSource.PROMPT_INJECTION,
            confidence=0.90,
            severity=ThreatSeverity.HIGH,
            timestamp=time.time(),
            metadata={"pattern": "ignore previous instructions"}
        )
        
        # Same metadata should produce same fingerprint
        self.assertEqual(signal1.threat_fingerprint, signal2.threat_fingerprint)

    def test_temporal_proximity_calculation(self):
        """Test temporal proximity calculation"""
        base_time = time.time()
        signals = [
            DetectionSignal("s1", DetectionSource.PROMPT_INJECTION, 0.8, ThreatSeverity.HIGH, base_time),
            DetectionSignal("s2", DetectionSource.JAILBREAK, 0.7, ThreatSeverity.HIGH, base_time + 10),
        ]
        
        score = self.engine._calculate_temporal_proximity(signals)
        self.assertGreater(score, 0.9)  # Very close in time

    def test_severity_aggregation(self):
        """Test severity aggregation with multiple signals"""
        signals = [
            DetectionSignal("s1", DetectionSource.PROMPT_INJECTION, 0.8, ThreatSeverity.HIGH, time.time()),
            DetectionSignal("s2", DetectionSource.JAILBREAK, 0.7, ThreatSeverity.MEDIUM, time.time()),
            DetectionSignal("s3", DetectionSource.ADVERSARIAL, 0.9, ThreatSeverity.HIGH, time.time()),
        ]
        
        # 3 signals should escalate to CRITICAL
        severity = self.engine._aggregate_severity(signals)
        self.assertEqual(severity, ThreatSeverity.CRITICAL)

    def test_confidence_aggregation(self):
        """Test confidence aggregation"""
        signals = [
            DetectionSignal("s1", DetectionSource.PROMPT_INJECTION, 0.8, ThreatSeverity.HIGH, time.time()),
            DetectionSignal("s2", DetectionSource.JAILBREAK, 0.9, ThreatSeverity.HIGH, time.time()),
        ]
        
        confidence = self.engine._aggregate_confidence(signals)
        self.assertGreater(confidence, 0.8)
        self.assertLessEqual(confidence, 1.0)

    def test_false_positive_probability(self):
        """Test false positive probability calculation"""
        # Single signal should have high FP probability
        single_signal = [
            DetectionSignal("s1", DetectionSource.PROMPT_INJECTION, 0.5, ThreatSeverity.HIGH, time.time()),
        ]
        fp_single = self.engine._calculate_false_positive_probability(single_signal)
        self.assertEqual(fp_single, 0.8)
        
        # Multiple diverse signals should have lower FP probability
        multi_signals = [
            DetectionSignal("s1", DetectionSource.PROMPT_INJECTION, 0.9, ThreatSeverity.HIGH, time.time()),
            DetectionSignal("s2", DetectionSource.JAILBREAK, 0.85, ThreatSeverity.HIGH, time.time()),
            DetectionSignal("s3", DetectionSource.ADVERSARIAL, 0.95, ThreatSeverity.HIGH, time.time()),
        ]
        fp_multi = self.engine._calculate_false_positive_probability(multi_signals)
        self.assertLess(fp_multi, fp_single)

    def test_attack_pattern_matching(self):
        """Test attack pattern matching"""
        signals = [
            DetectionSignal("s1", DetectionSource.PROMPT_INJECTION, 0.8, ThreatSeverity.HIGH, time.time()),
            DetectionSignal("s2", DetectionSource.JAILBREAK, 0.7, ThreatSeverity.HIGH, time.time()),
            DetectionSignal("s3", DetectionSource.ADVERSARIAL, 0.9, ThreatSeverity.HIGH, time.time()),
        ]
        
        pattern = self.engine._match_attack_pattern(signals)
        self.assertEqual(pattern, "multi_vector_jailbreak")

    def test_correlation_real_scenario(self):
        """Test full correlation in a real scenario"""
        base_time = time.time()
        
        # Simulate a multi-vector jailbreak attack
        signals = [
            DetectionSignal(
                signal_id="sig_001",
                source=DetectionSource.PROMPT_INJECTION,
                confidence=0.88,
                severity=ThreatSeverity.HIGH,
                timestamp=base_time,
                metadata={"pattern": "ignore instructions", "user_input": "disregard all prior"}
            ),
            DetectionSignal(
                signal_id="sig_002",
                source=DetectionSource.JAILBREAK,
                confidence=0.92,
                severity=ThreatSeverity.HIGH,
                timestamp=base_time + 2,
                metadata={"pattern": "DAN", "user_input": "hello DAN mode"}
            ),
            DetectionSignal(
                signal_id="sig_003",
                source=DetectionSource.ADVERSARIAL,
                confidence=0.78,
                severity=ThreatSeverity.MEDIUM,
                timestamp=base_time + 5,
                metadata={"perturbation": "character substitution"}
            ),
        ]
        
        for signal in signals:
            self.engine.ingest_signal(signal)
        
        correlated = self.engine.correlate_threats()
        
        # Should find at least one correlation
        self.assertGreater(len(correlated), 0)
        
        threat = correlated[0]
        self.assertEqual(threat.attack_pattern, "multi_vector_jailbreak")
        self.assertEqual(threat.aggregated_severity, ThreatSeverity.CRITICAL)
        self.assertGreater(threat.aggregated_confidence, 0.8)
        self.assertLess(threat.false_positive_probability, 0.5)

    def test_recommended_action_logic(self):
        """Test recommended action logic"""
        # Critical threat with low FP probability = immediate block
        threat1 = CorrelatedThreat(
            correlation_id="test1",
            aggregated_severity=ThreatSeverity.CRITICAL,
            aggregated_confidence=0.95,
            supporting_signals=[],
            correlation_strength=0.9,
            attack_pattern="test",
            false_positive_probability=0.1,
            recommended_action=""
        )
        action1 = self.engine._get_recommended_action(threat1)
        self.assertEqual(action1, "immediate_block_and_alert")
        
        # High FP probability should trigger review
        threat2 = CorrelatedThreat(
            correlation_id="test2",
            aggregated_severity=ThreatSeverity.CRITICAL,
            aggregated_confidence=0.5,
            supporting_signals=[],
            correlation_strength=0.5,
            attack_pattern="test",
            false_positive_probability=0.8,
            recommended_action=""
        )
        action2 = self.engine._get_recommended_action(threat2)
        self.assertEqual(action2, "review_and_validate")

    def test_correlation_summary(self):
        """Test correlation summary statistics"""
        base_time = time.time()
        
        for i in range(5):
            signal = DetectionSignal(
                signal_id=f"sig_{i}",
                source=DetectionSource.PROMPT_INJECTION,
                confidence=0.8 + i * 0.02,
                severity=ThreatSeverity.HIGH,
                timestamp=base_time + i,
                metadata={"test": f"data_{i}"}
            )
            self.engine.ingest_signal(signal)
        
        summary = self.engine.get_correlation_summary()
        self.assertEqual(summary["total_signals_buffered"], 5)
        self.assertIn("correlation_window_seconds", summary)

    def test_old_signal_cleanup(self):
        """Test that old signals are cleaned up"""
        engine = ThreatContextCorrelationEngine(correlation_window_seconds=1)  # 1 second window
        
        # Add old signal
        old_signal = DetectionSignal(
            signal_id="old",
            source=DetectionSource.PROMPT_INJECTION,
            confidence=0.8,
            severity=ThreatSeverity.HIGH,
            timestamp=time.time() - 10  # 10 seconds old
        )
        engine.ingest_signal(old_signal)
        
        # Add new signal
        new_signal = DetectionSignal(
            signal_id="new",
            source=DetectionSource.JAILBREAK,
            confidence=0.8,
            severity=ThreatSeverity.HIGH,
            timestamp=time.time()
        )
        engine.ingest_signal(new_signal)
        
        # Old signal should be cleaned
        self.assertLess(len(engine.signal_buffer), 2)


def run_tests():
    """Run all tests and report results"""
    print("=" * 60)
    print("Threat Intelligence Context Correlation Engine - Test Suite")
    print("=" * 60)
    print()
    
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestThreatContextCorrelationEngine)
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print()
    print("=" * 60)
    print(f"Tests Run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success: {result.wasSuccessful()}")
    print("=" * 60)
    
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
