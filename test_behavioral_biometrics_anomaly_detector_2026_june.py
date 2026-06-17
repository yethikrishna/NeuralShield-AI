"""
Test Suite for Behavioral Biometrics Anomaly Detector
June 2026 Production Release

Tests cover:
- Baseline profile creation
- Typing pattern anomaly detection
- Bot behavior detection
- Environmental fingerprint checks
- Risk level assessment
- Integration with NeuralShield framework
"""

import unittest
import time
import sys
import os

# Add module path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from neural_shield.behavioral_biometrics_anomaly_detector_2026_june import (
    BehavioralBiometricsAnomalyDetector,
    AnomalyType,
    RiskLevel,
    InteractionEvent,
    BehavioralFinding,
)


class TestBehavioralBiometricsAnomalyDetector(unittest.TestCase):
    """Test cases for Behavioral Biometrics Anomaly Detector."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.detector = BehavioralBiometricsAnomalyDetector(sensitivity=0.7)
        self.user_id = "test_user_001"
        self.session_id = "session_abc123"
    
    def test_detector_initialization(self):
        """Test detector initializes correctly."""
        self.assertEqual(self.detector.sensitivity, 0.7)
        self.assertIsInstance(self.detector.user_baselines, dict)
        self.assertGreater(self.detector.anomaly_threshold, 0)
        print("✓ Detector initialization test passed")
    
    def test_baseline_creation_from_events(self):
        """Test baseline profile creation from interaction events."""
        events = self._generate_normal_typing_events(count=50)
        baseline = self.detector.create_baseline_from_events(
            self.user_id,
            events,
            metadata={"user_agents": ["Chrome/125.0"], "ip_ranges": ["192.168.1."]}
        )
        
        self.assertEqual(baseline.user_id, self.user_id)
        self.assertGreater(baseline.sample_count, 0)
        self.assertGreater(baseline.avg_keystroke_interval_ms, 0)
        self.assertIn(self.user_id, self.detector.user_baselines)
        print("✓ Baseline creation test passed")
    
    def test_normal_behavior_no_anomaly(self):
        """Test that normal behavior matching baseline is not flagged."""
        # Create baseline with normal behavior
        baseline_events = self._generate_normal_typing_events(count=100)
        self.detector.create_baseline_from_events(self.user_id, baseline_events)
        
        # Test with similar normal behavior
        test_events = self._generate_normal_typing_events(count=30)
        result = self.detector.analyze_session(
            self.user_id,
            self.session_id,
            test_events
        )
        
        self.assertEqual(result.user_id, self.user_id)
        self.assertEqual(result.session_id, self.session_id)
        self.assertIsNotNone(result.baseline_profile_hash)
        self.assertLess(result.overall_anomaly_score, 0.5)
        print("✓ Normal behavior detection test passed")
    
    def test_typing_pattern_anomaly_detection(self):
        """Test detection of typing pattern shifts."""
        # Create baseline with normal human typing
        baseline_events = self._generate_normal_typing_events(count=100)
        self.detector.create_baseline_from_events(self.user_id, baseline_events)
        
        # Test with extremely fast typing (bot-like)
        fast_events = self._generate_fast_bot_typing(count=30)
        result = self.detector.analyze_session(
            self.user_id,
            self.session_id,
            fast_events
        )
        
        typing_findings = [
            f for f in result.findings
            if f.anomaly_type == AnomalyType.TYPING_PATTERN_SHIFT
        ]
        
        self.assertGreater(len(typing_findings), 0)
        self.assertGreater(result.overall_anomaly_score, 0.2)
        print("✓ Typing pattern anomaly detection test passed")
    
    def test_bot_behavior_detection(self):
        """Test detection of bot-like perfectly regular timing."""
        # Create baseline
        baseline_events = self._generate_normal_typing_events(count=50)
        self.detector.create_baseline_from_events(self.user_id, baseline_events)
        
        # Generate perfectly regular bot events
        bot_events = self._generate_perfectly_regular_events(count=20)
        result = self.detector.analyze_session(
            self.user_id,
            self.session_id,
            bot_events
        )
        
        bot_findings = [
            f for f in result.findings
            if f.anomaly_type == AnomalyType.BOT_LIKE_BEHAVIOR
        ]
        
        self.assertGreater(len(bot_findings), 0)
        print("✓ Bot behavior detection test passed")
    
    def test_environmental_fingerprint_change(self):
        """Test detection of environmental fingerprint changes."""
        baseline_events = self._generate_normal_typing_events(count=50)
        self.detector.create_baseline_from_events(
            self.user_id,
            baseline_events,
            metadata={
                "user_agents": ["Chrome/125.0 Windows"],
                "ip_ranges": ["192.168.1."]
            }
        )
        
        # Test with different environment
        test_events = self._generate_normal_typing_events(count=20)
        result = self.detector.analyze_session(
            self.user_id,
            self.session_id,
            test_events,
            environmental_data={
                "user_agent": "Firefox/126.0 Linux",
                "ip_address": "10.0.0.1"
            }
        )
        
        env_findings = [
            f for f in result.findings
            if f.anomaly_type in (AnomalyType.USER_AGENT_SHIFT, AnomalyType.IP_GEOLOCATION_JUMP)
        ]
        
        self.assertGreater(len(env_findings), 0)
        print("✓ Environmental fingerprint change test passed")
    
    def test_risk_level_assessment(self):
        """Test risk level assessment logic."""
        baseline_events = self._generate_normal_typing_events(count=50)
        self.detector.create_baseline_from_events(self.user_id, baseline_events)
        
        # Test with various patterns
        normal_result = self.detector.analyze_session(
            self.user_id,
            "normal_session",
            self._generate_normal_typing_events(count=20)
        )
        
        # Risk levels should be properly assigned
        self.assertIn(normal_result.overall_risk_level, RiskLevel)
        self.assertGreaterEqual(normal_result.overall_anomaly_score, 0.0)
        self.assertLessEqual(normal_result.overall_anomaly_score, 1.0)
        print("✓ Risk level assessment test passed")
    
    def test_recommendations_generation(self):
        """Test security recommendations are generated."""
        baseline_events = self._generate_normal_typing_events(count=50)
        self.detector.create_baseline_from_events(self.user_id, baseline_events)
        
        bot_events = self._generate_perfectly_regular_events(count=20)
        result = self.detector.analyze_session(
            self.user_id,
            self.session_id,
            bot_events
        )
        
        self.assertIsInstance(result.recommendations, list)
        self.assertGreater(len(result.recommendations), 0)
        print("✓ Recommendations generation test passed")
    
    def test_confidence_values_valid(self):
        """Test all confidence values are in valid range [0, 1]."""
        baseline_events = self._generate_normal_typing_events(count=50)
        self.detector.create_baseline_from_events(self.user_id, baseline_events)
        
        test_events = self._generate_fast_bot_typing(count=30)
        result = self.detector.analyze_session(
            self.user_id,
            self.session_id,
            test_events
        )
        
        for finding in result.findings:
            self.assertGreaterEqual(finding.confidence, 0.0)
            self.assertLessEqual(finding.confidence, 1.0)
            self.assertGreaterEqual(finding.baseline_deviation, 0.0)
        
        print("✓ Confidence values validation test passed")
    
    def test_integration_with_neural_shield(self):
        """Test module integrates properly with NeuralShield package."""
        from neural_shield import BehavioralBiometricsAnomalyDetector as ImportedDetector
        self.assertIsNotNone(ImportedDetector)
        
        instance = ImportedDetector(sensitivity=0.8)
        self.assertEqual(instance.sensitivity, 0.8)
        print("✓ NeuralShield integration test passed")
    
    def _generate_normal_typing_events(self, count: int) -> list:
        """Generate realistic human typing events."""
        import random
        events = []
        base_time = time.time() - 3600
        
        for i in range(count):
            # Human typing: variable intervals 50-300ms
            interval = random.uniform(0.05, 0.3)
            base_time += interval
            
            events.append(InteractionEvent(
                timestamp=base_time,
                event_type="keystroke",
                key_code=random.randint(65, 90),
                duration_ms=random.uniform(20, 80)
            ))
            
            # Occasional backspace
            if random.random() < 0.08:
                base_time += random.uniform(0.1, 0.3)
                events.append(InteractionEvent(
                    timestamp=base_time,
                    event_type="keystroke",
                    key_code=8,  # Backspace
                    duration_ms=30
                ))
        
        return events
    
    def _generate_fast_bot_typing(self, count: int) -> list:
        """Generate unnaturally fast bot typing."""
        import random
        events = []
        base_time = time.time()
        
        for i in range(count):
            # Very fast, consistent typing
            base_time += 0.02
            events.append(InteractionEvent(
                timestamp=base_time,
                event_type="keystroke",
                key_code=65 + (i % 26),
                duration_ms=10
            ))
        
        return events
    
    def _generate_perfectly_regular_events(self, count: int) -> list:
        """Generate perfectly timed events (bot signature)."""
        events = []
        base_time = time.time()
        exact_interval = 0.1  # Perfectly regular
        
        for i in range(count):
            base_time += exact_interval
            events.append(InteractionEvent(
                timestamp=base_time,
                event_type="keystroke",
                key_code=65 + (i % 26)
            ))
        
        return events


def run_all_tests():
    """Run all tests and report results."""
    print("=" * 60)
    print("Behavioral Biometrics Anomaly Detector - Test Suite")
    print("June 2026 Production Release")
    print("=" * 60)
    print()
    
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestBehavioralBiometricsAnomalyDetector)
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print()
    print("=" * 60)
    print(f"Tests Run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Skipped: {len(result.skipped)}")
    
    if result.wasSuccessful():
        print("✓ ALL TESTS PASSED - Production Ready ✓")
    else:
        print("✗ SOME TESTS FAILED")
    print("=" * 60)
    
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
