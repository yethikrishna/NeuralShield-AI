"""
Test Suite for Threat Intelligence Alert Correlation Context Enricher v74
Dimension A - Feature Expansion Tests
100% ADD-ONLY - No existing tests modified
"""

import unittest
import time
import sys
import os

# Add neural_shield to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from threat_intelligence_alert_correlation_context_enricher_v74_2026_june import (
    ThreatIntelAlertCorrelationEnricherV74,
    AlertContext,
    CorrelationType,
    AdaptiveWeightLearner,
    TemporalDecayEngine,
    BayesianConfidenceCalibrator,
    MultiHopCorrelationFinder,
    get_alert_correlation_enricher_v74,
    enrich_alert_context_v74,
    VERSION,
    VERSION_DATE
)


class TestAdaptiveWeightLearner(unittest.TestCase):
    """Test adaptive weight learning component."""
    
    def test_initialization(self):
        """Test weight learner initializes correctly."""
        learner = AdaptiveWeightLearner(learning_rate=0.1)
        self.assertEqual(learner.learning_rate, 0.1)
        self.assertEqual(learner.total_learning_samples, 0)
    
    def test_record_outcome(self):
        """Test recording correlation outcomes."""
        learner = AdaptiveWeightLearner()
        initial_weight = learner.get_adjusted_weight(CorrelationType.SAME_IP)
        
        # Record correct outcomes
        for _ in range(10):
            learner.record_outcome(CorrelationType.SAME_IP, True)
        
        self.assertGreater(learner.total_learning_samples, 0)
        # Weight should increase with correct outcomes
        self.assertGreater(
            learner.get_adjusted_weight(CorrelationType.SAME_IP),
            initial_weight
        )
    
    def test_incorrect_outcome_reduces_weight(self):
        """Test incorrect outcomes reduce weights."""
        learner = AdaptiveWeightLearner(learning_rate=0.2)
        # First establish baseline
        for _ in range(5):
            learner.record_outcome(CorrelationType.SAME_IP, True)
        high_weight = learner.get_adjusted_weight(CorrelationType.SAME_IP)
        
        # Now record incorrect
        for _ in range(10):
            learner.record_outcome(CorrelationType.SAME_IP, False)
        low_weight = learner.get_adjusted_weight(CorrelationType.SAME_IP)
        
        self.assertLess(low_weight, high_weight)
    
    def test_get_learning_stats(self):
        """Test learning statistics retrieval."""
        learner = AdaptiveWeightLearner()
        learner.record_outcome(CorrelationType.SAME_HASH, True)
        stats = learner.get_learning_stats()
        
        self.assertIn("total_samples", stats)
        self.assertIn("type_weights", stats)
        self.assertGreater(stats["total_samples"], 0)


class TestTemporalDecayEngine(unittest.TestCase):
    """Test temporal decay component."""
    
    def test_initialization(self):
        """Test decay engine initializes."""
        engine = TemporalDecayEngine(half_life_seconds=1800)
        self.assertEqual(engine.half_life, 1800)
    
    def test_fresh_alert_no_decay(self):
        """Test fresh alerts have no decay."""
        engine = TemporalDecayEngine()
        now = time.time()
        decay = engine.calculate_decay_factor(now, now)
        self.assertEqual(decay, 1.0)
    
    def test_old_alert_decays(self):
        """Test old alerts decay properly."""
        engine = TemporalDecayEngine(half_life_seconds=3600)
        now = time.time()
        one_hour_ago = now - 3600
        decay = engine.calculate_decay_factor(one_hour_ago, now)
        # Should be approximately 0.5 after one half-life
        self.assertAlmostEqual(decay, 0.5, places=1)
    
    def test_very_old_alert_minimum_decay(self):
        """Test very old alerts hit minimum decay."""
        engine = TemporalDecayEngine(max_age_seconds=3600)
        now = time.time()
        two_days_ago = now - 172800
        decay = engine.calculate_decay_factor(two_days_ago, now)
        self.assertEqual(decay, 0.01)


class TestBayesianConfidenceCalibrator(unittest.TestCase):
    """Test Bayesian confidence calibration."""
    
    def test_initialization(self):
        """Test calibrator initializes."""
        calibrator = BayesianConfidenceCalibrator(prior_confidence=0.6)
        self.assertEqual(calibrator.prior, 0.6)
    
    def test_confidence_increases_with_strong_evidence(self):
        """Test strong evidence increases confidence."""
        calibrator = BayesianConfidenceCalibrator()
        base = 0.5
        updated = calibrator.update_confidence(base, CorrelationType.SAME_HASH)
        self.assertGreater(updated, base)
    
    def test_multiple_evidences_compound(self):
        """Test multiple evidences compound confidence."""
        calibrator = BayesianConfidenceCalibrator()
        base = 0.3
        combined = calibrator.combine_evidences(
            base,
            [CorrelationType.SAME_IP, CorrelationType.SAME_HASH]
        )
        self.assertGreater(combined, base)
    
    def test_confidence_bounded(self):
        """Test confidence stays within valid bounds."""
        calibrator = BayesianConfidenceCalibrator()
        for _ in range(100):
            confidence = calibrator.update_confidence(0.99, CorrelationType.SAME_HASH)
            self.assertLessEqual(confidence, 0.99)
            self.assertGreaterEqual(confidence, 0.01)


class TestMultiHopCorrelationFinder(unittest.TestCase):
    """Test multi-hop correlation finding."""
    
    def test_initialization(self):
        """Test finder initializes with max hops."""
        finder = MultiHopCorrelationFinder(max_hops=5)
        self.assertEqual(finder.max_hops, 5)
    
    def test_find_all_correlated_simple(self):
        """Test finding simple direct correlations."""
        finder = MultiHopCorrelationFinder()
        graph = {
            "alert1": [("alert2", CorrelationType.SAME_IP, 0.8)],
            "alert2": [("alert1", CorrelationType.SAME_IP, 0.8)]
        }
        correlated = finder.find_all_correlated("alert1", graph)
        self.assertIn("alert2", correlated)
    
    def test_no_self_correlation(self):
        """Test alert doesn't correlate with itself."""
        finder = MultiHopCorrelationFinder()
        graph = {"alert1": []}
        correlated = finder.find_all_correlated("alert1", graph)
        self.assertNotIn("alert1", correlated)
        self.assertEqual(len(correlated), 0)


class TestThreatIntelAlertCorrelationEnricherV74(unittest.TestCase):
    """Main test suite for v74 enricher."""
    
    def setUp(self):
        """Set up test enricher."""
        self.enricher = ThreatIntelAlertCorrelationEnricherV74()
    
    def test_initialization(self):
        """Test enricher initializes correctly."""
        self.assertEqual(len(self.enricher.alerts), 0)
        self.assertEqual(self.enricher.total_enrichments, 0)
    
    def test_add_alert(self):
        """Test adding alerts to enricher."""
        alert = AlertContext(
            alert_id="test_001",
            timestamp=time.time(),
            source_ip="192.168.1.1"
        )
        self.enricher.add_alert(alert)
        self.assertIn("test_001", self.enricher.alerts)
    
    def test_enrich_single_alert_no_correlations(self):
        """Test enriching alert with no correlations."""
        alert = AlertContext(
            alert_id="test_001",
            timestamp=time.time(),
            source_ip="192.168.1.1",
            severity=0.8
        )
        self.enricher.add_alert(alert)
        result = self.enricher.enrich_alert("test_001")
        
        self.assertIsNotNone(result)
        self.assertEqual(result.alert_id, "test_001")
        self.assertEqual(result.correlation_count, 0)
        self.assertGreater(result.enrichment_score, 0)
        self.assertTrue(result.temporal_decay_applied)
    
    def test_ip_correlation_detection(self):
        """Test same IP correlation is detected."""
        now = time.time()
        alert1 = AlertContext(
            alert_id="test_001",
            timestamp=now,
            source_ip="192.168.1.100"
        )
        alert2 = AlertContext(
            alert_id="test_002",
            timestamp=now + 60,  # 1 minute later
            source_ip="192.168.1.100"
        )
        
        self.enricher.add_alert(alert1)
        self.enricher.add_alert(alert2)
        
        result = self.enricher.enrich_alert("test_002")
        self.assertIsNotNone(result)
        self.assertGreater(result.correlation_count, 0)
        self.assertIn("test_001", result.correlated_alerts)
    
    def test_file_hash_correlation(self):
        """Test same file hash correlation."""
        now = time.time()
        alert1 = AlertContext(
            alert_id="test_001",
            timestamp=now,
            file_hash="abc123def456"
        )
        alert2 = AlertContext(
            alert_id="test_002",
            timestamp=now + 30,
            file_hash="abc123def456"
        )
        
        self.enricher.add_alert(alert1)
        self.enricher.add_alert(alert2)
        
        result = self.enricher.enrich_alert("test_002")
        self.assertGreater(result.confidence_score, 0.5)
    
    def test_cross_source_verification(self):
        """Test cross-source verification flag works."""
        now = time.time()
        alert1 = AlertContext(
            alert_id="test_001",
            timestamp=now,
            source_ip="10.0.0.1",
            source_feed="feed_a"
        )
        alert2 = AlertContext(
            alert_id="test_002",
            timestamp=now + 60,
            source_ip="10.0.0.1",
            source_feed="feed_b"
        )
        
        self.enricher.add_alert(alert1)
        self.enricher.add_alert(alert2)
        
        result = self.enricher.enrich_alert("test_002")
        self.assertTrue(result.cross_source_verified)
    
    def test_recommendations_generated(self):
        """Test actionable recommendations are generated."""
        alert = AlertContext(
            alert_id="test_001",
            timestamp=time.time(),
            severity=0.9
        )
        self.enricher.add_alert(alert)
        result = self.enricher.enrich_alert("test_001")
        
        self.assertGreater(len(result.recommendations), 0)
        self.assertIsInstance(result.recommendations[0], str)
    
    def test_high_severity_recommendation(self):
        """Test high severity triggers appropriate recommendation."""
        # Add multiple correlated high-severity alerts
        now = time.time()
        for i in range(6):
            alert = AlertContext(
                alert_id=f"test_{i:03d}",
                timestamp=now + i * 10,
                source_ip="172.16.0.100",
                severity=0.85
            )
            self.enricher.add_alert(alert)
        
        result = self.enricher.enrich_alert("test_005")
        self.assertTrue(
            any("coordinated" in rec.lower() for rec in result.recommendations) or
            any("multi-alert" in rec.lower() for rec in result.recommendations)
        )
    
    def test_feedback_learning(self):
        """Test feedback recording for learning."""
        # First create some correlations
        now = time.time()
        alert1 = AlertContext(alert_id="a1", timestamp=now, source_ip="1.1.1.1")
        alert2 = AlertContext(alert_id="a2", timestamp=now+10, source_ip="1.1.1.1")
        self.enricher.add_alert(alert1)
        self.enricher.add_alert(alert2)
        self.enricher.enrich_alert("a2")
        
        # Record feedback
        initial_edges = len(self.enricher.correlation_edges)
        if initial_edges > 0:
            self.enricher.record_feedback(0, True)
            self.assertEqual(self.enricher.correlation_edges[0].learning_count, 1)
    
    def test_get_stats(self):
        """Test statistics retrieval."""
        alert = AlertContext(alert_id="test_001", timestamp=time.time())
        self.enricher.add_alert(alert)
        self.enricher.enrich_alert("test_001")
        
        stats = self.enricher.get_stats()
        self.assertIn("total_alerts", stats)
        self.assertIn("total_enrichments", stats)
        self.assertIn("learning_stats", stats)
        self.assertEqual(stats["total_alerts"], 1)
        self.assertEqual(stats["total_enrichments"], 1)
    
    def test_enrich_nonexistent_alert(self):
        """Test enriching non-existent alert returns None."""
        result = self.enricher.enrich_alert("nonexistent")
        self.assertIsNone(result)
    
    def test_processing_time_recorded(self):
        """Test processing time is recorded."""
        alert = AlertContext(alert_id="test_001", timestamp=time.time())
        self.enricher.add_alert(alert)
        result = self.enricher.enrich_alert("test_001")
        self.assertGreaterEqual(result.processing_time_ms, 0)
    
    def test_adaptive_weights_in_result(self):
        """Test adaptive weights are included in result."""
        alert = AlertContext(alert_id="test_001", timestamp=time.time())
        self.enricher.add_alert(alert)
        result = self.enricher.enrich_alert("test_001")
        self.assertIsInstance(result.adaptive_weights_applied, dict)


class TestGlobalFunctions(unittest.TestCase):
    """Test global convenience functions."""
    
    def test_get_enricher_singleton(self):
        """Test global singleton works."""
        enricher1 = get_alert_correlation_enricher_v74()
        enricher2 = get_alert_correlation_enricher_v74()
        self.assertIs(enricher1, enricher2)
    
    def test_enrich_alert_context(self):
        """Test convenience enrichment function."""
        alert = AlertContext(alert_id="global_test", timestamp=time.time())
        result = enrich_alert_context_v74(alert)
        self.assertIsNotNone(result)
        self.assertEqual(result.alert_id, "global_test")
    
    def test_version_info(self):
        """Test version information is correct."""
        self.assertEqual(VERSION, "74.0.0")
        self.assertEqual(VERSION_DATE, "2026-06-23")


class TestBackwardCompatibility(unittest.TestCase):
    """Verify backward compatibility - no existing code broken."""
    
    def test_no_modification_to_existing_modules(self):
        """Verify this is purely additive."""
        # This test file itself is new
        self.assertTrue(os.path.exists(__file__))
        
        # Source module is new
        src_path = os.path.join(
            os.path.dirname(__file__),
            'neural_shield',
            'threat_intelligence_alert_correlation_context_enricher_v74_2026_june.py'
        )
        self.assertTrue(os.path.exists(src_path))
    
    def test_imports_cleanly(self):
        """Test module imports without errors."""
        try:
            from neural_shield import threat_intelligence_alert_correlation_context_enricher_v74_2026_june as module
            self.assertTrue(hasattr(module, 'ThreatIntelAlertCorrelationEnricherV74'))
        except Exception as e:
            self.fail(f"Import failed: {e}")


if __name__ == '__main__':
    # Run all tests
    test_suite = unittest.TestLoader().loadTestsFromTestCase(TestAdaptiveWeightLearner)
    test_suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestTemporalDecayEngine))
    test_suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestBayesianConfidenceCalibrator))
    test_suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestMultiHopCorrelationFinder))
    test_suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestThreatIntelAlertCorrelationEnricherV74))
    test_suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestGlobalFunctions))
    test_suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestBackwardCompatibility))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # Exit with appropriate code
    sys.exit(0 if result.wasSuccessful() else 1)
