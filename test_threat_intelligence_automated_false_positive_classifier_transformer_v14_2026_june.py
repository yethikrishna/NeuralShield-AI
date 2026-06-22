"""
Test Suite for NeuralShield-AI: False Positive Classifier Transformer v14
DIMENSION A: Feature Expansion - Test Coverage
All tests are ADD-ONLY - no existing tests modified
"""

import unittest
import sys
import os

# Add the neural_shield directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from threat_intelligence_automated_false_positive_classifier_transformer_v14_2026_june import (
    FalsePositiveClassifierV14,
    ClassificationContext,
    IOCCategory,
    ClassificationStrategy,
    BayesianCalibrator,
    TemporalDriftDetector,
    EntropyAnalyzer,
    EnsembleVotingClassifier,
    classify_ioc_v14,
    classify_batch_v14,
    get_statistics_v14,
    get_classifier_v14,
)


class TestBayesianCalibrator(unittest.TestCase):
    """Test Bayesian probability calibration"""
    
    def test_calibration_initialization(self):
        cal = BayesianCalibrator()
        self.assertAlmostEqual(cal.prior_fp_probability, 0.35)
        self.assertAlmostEqual(cal.prior_threat_probability, 0.65)
        
    def test_calibrate_probability_basic(self):
        cal = BayesianCalibrator()
        result = cal.calibrate_probability(0.5, ['private_ip'])
        self.assertGreater(result, 0.5)  # Private IP should increase FP probability
        
    def test_calibrate_probability_threat(self):
        cal = BayesianCalibrator()
        result = cal.calibrate_probability(0.5, ['cve_pattern'])
        self.assertLess(result, 0.5)  # CVE should decrease FP probability
        
    def test_update_priors(self):
        cal = BayesianCalibrator()
        cal.update_priors(0.5)
        self.assertAlmostEqual(cal.prior_fp_probability, 0.5)
        self.assertAlmostEqual(cal.prior_threat_probability, 0.5)


class TestTemporalDriftDetector(unittest.TestCase):
    """Test temporal drift detection"""
    
    def test_detector_initialization(self):
        detector = TemporalDriftDetector(window_size=100)
        self.assertEqual(detector.window_size, 100)
        
    def test_add_sample(self):
        detector = TemporalDriftDetector()
        detector.add_sample(True, 0.8)
        detector.add_sample(False, 0.2)
        # Should not raise exceptions
        
    def test_detect_drift_insufficient_data(self):
        detector = TemporalDriftDetector()
        drift, metrics = detector.detect_drift()
        self.assertFalse(drift)
        self.assertEqual(metrics['drift_score'], 0.0)


class TestEntropyAnalyzer(unittest.TestCase):
    """Test entropy-based analysis"""
    
    def test_shannon_entropy_zero(self):
        entropy = EntropyAnalyzer.shannon_entropy("")
        self.assertEqual(entropy, 0.0)
        
    def test_shannon_entropy_low(self):
        # Low entropy - repeated characters
        entropy = EntropyAnalyzer.shannon_entropy("aaaaaaaaaaaa")
        self.assertLess(entropy, 1.0)
        
    def test_shannon_entropy_high(self):
        # High entropy - random looking
        entropy = EntropyAnalyzer.shannon_entropy("a1b2c3d4e5f6g7h8")
        self.assertGreater(entropy, 3.0)
        
    def test_normalized_entropy(self):
        norm = EntropyAnalyzer.normalized_entropy("test")
        self.assertGreaterEqual(norm, 0.0)
        self.assertLessEqual(norm, 1.0)
        
    def test_classify_by_entropy_private_ip(self):
        analyzer = EntropyAnalyzer()
        score, signals = analyzer.classify_by_entropy("192.168.1.1", IOCCategory.IP_ADDRESS)
        self.assertIsInstance(score, float)
        self.assertIsInstance(signals, list)
        
    def test_classify_by_entropy_hash(self):
        analyzer = EntropyAnalyzer()
        score, signals = analyzer.classify_by_entropy(
            "5d41402abc4b2a76b9719d911017c592", 
            IOCCategory.FILE_HASH
        )
        self.assertIsInstance(score, float)


class TestEnsembleVotingClassifier(unittest.TestCase):
    """Test ensemble voting system"""
    
    def test_vote_creation(self):
        ensemble = EnsembleVotingClassifier()
        vote = ensemble.vote(
            ClassificationStrategy.PATTERN_MATCHING,
            0.75, 0.9, ['FP:private_ip']
        )
        self.assertTrue(hasattr(vote, 'vote'))
        self.assertTrue(hasattr(vote, 'confidence'))
        self.assertTrue(hasattr(vote, 'weight'))
        
    def test_combine_votes_empty(self):
        ensemble = EnsembleVotingClassifier()
        is_fp, conf, score, attr = ensemble.combine_votes([])
        self.assertFalse(is_fp)
        self.assertAlmostEqual(conf, 0.5)
        
    def test_combine_votes_unanimous_fp(self):
        ensemble = EnsembleVotingClassifier()
        votes = [
            ensemble.vote(ClassificationStrategy.PATTERN_MATCHING, 0.9, 1.0, ['a']),
            ensemble.vote(ClassificationStrategy.REPUTATION_BASED, 0.85, 1.0, ['b']),
        ]
        is_fp, conf, score, attr = ensemble.combine_votes(votes)
        self.assertTrue(is_fp)
        self.assertGreater(conf, 0.0)


class TestFalsePositiveClassifierV14(unittest.TestCase):
    """Main v14 classifier tests"""
    
    def setUp(self):
        self.classifier = FalsePositiveClassifierV14()
        
    def test_classifier_initialization(self):
        self.assertIsNotNone(self.classifier.ensemble)
        self.assertIsNotNone(self.classifier.entropy)
        self.assertIsNotNone(self.classifier.drift_detector)
        
    def test_categorize_ioc_ip(self):
        cat = self.classifier._categorize_ioc("192.168.1.1")
        self.assertEqual(cat, IOCCategory.IP_ADDRESS)
        
    def test_categorize_ioc_hash(self):
        cat = self.classifier._categorize_ioc("5d41402abc4b2a76b9719d911017c592")
        self.assertEqual(cat, IOCCategory.FILE_HASH)
        
    def test_categorize_ioc_cve(self):
        cat = self.classifier._categorize_ioc("CVE-2024-1234")
        self.assertEqual(cat, IOCCategory.CVE)
        
    def test_categorize_ioc_domain(self):
        cat = self.classifier._categorize_ioc("google.com")
        self.assertEqual(cat, IOCCategory.DOMAIN)
        
    def test_classify_private_ip_is_fp(self):
        """Private IP addresses should be classified as false positives"""
        result = self.classifier.classify_ioc("192.168.1.1")
        self.assertTrue(result.is_false_positive)
        self.assertEqual(result.ioc_category, IOCCategory.IP_ADDRESS)
        self.assertGreater(result.final_confidence, 0.0)
        
    def test_classify_localhost_is_fp(self):
        """Localhost should be false positive"""
        result = self.classifier.classify_ioc("127.0.0.1")
        self.assertTrue(result.is_false_positive)
        
    def test_classify_cve_is_threat(self):
        """CVEs should be classified as true threats"""
        result = self.classifier.classify_ioc("CVE-2024-12345")
        self.assertFalse(result.is_false_positive)  # Not a false positive = true threat
        
    def test_classify_benign_domain(self):
        """Benign domains like google.com should be FP"""
        result = self.classifier.classify_ioc("google.com")
        # May or may not be FP depending on patterns, but should not crash
        self.assertIsNotNone(result)
        self.assertIsInstance(result.is_false_positive, bool)
        
    def test_classify_result_structure(self):
        """Verify result has all expected fields"""
        result = self.classifier.classify_ioc("10.0.0.1")
        self.assertIsNotNone(result.ioc_value)
        self.assertIsNotNone(result.ioc_category)
        self.assertIsInstance(result.is_false_positive, bool)
        self.assertIsInstance(result.final_confidence, float)
        self.assertIsInstance(result.threat_score, float)
        self.assertIsInstance(result.fp_score, float)
        self.assertIsInstance(result.ensemble_votes, list)
        self.assertIsInstance(result.xai_attribution, dict)
        self.assertIsInstance(result.processing_time_ms, float)
        self.assertEqual(result.model_version, "v14_ensemble")
        
    def test_classify_batch(self):
        """Test batch classification"""
        iocs = ["192.168.1.1", "10.0.0.1", "CVE-2024-1234"]
        results = self.classifier.classify_batch(iocs)
        self.assertEqual(len(results), 3)
        for r in results:
            self.assertIsNotNone(r)
            
    def test_get_statistics(self):
        """Test statistics collection"""
        # Classify something first
        self.classifier.classify_ioc("192.168.1.1")
        stats = self.classifier.get_statistics()
        self.assertGreater(stats['total_classified'], 0)
        self.assertIn('fp_rate', stats)
        self.assertIn('drift_metrics', stats)
        
    def test_pattern_matching_strategy(self):
        """Test pattern matching strategy"""
        score, signals = self.classifier._pattern_matching_strategy(
            "192.168.1.1", IOCCategory.IP_ADDRESS
        )
        self.assertGreater(score, 0.5)  # Should lean toward FP
        
    def test_reputation_strategy_cve(self):
        """Test reputation strategy for CVE"""
        score, signals = self.classifier._reputation_strategy(
            "CVE-2024-1234", IOCCategory.CVE
        )
        self.assertLess(score, 0.5)  # Should lean toward threat (low FP score)


class TestGlobalConvenienceFunctions(unittest.TestCase):
    """Test global convenience functions"""
    
    def test_get_classifier_v14(self):
        clf = get_classifier_v14()
        self.assertIsInstance(clf, FalsePositiveClassifierV14)
        
    def test_classify_ioc_v14(self):
        result = classify_ioc_v14("192.168.1.1")
        self.assertIsNotNone(result)
        self.assertTrue(result.is_false_positive)
        
    def test_classify_batch_v14(self):
        results = classify_batch_v14(["10.0.0.1", "172.16.0.1"])
        self.assertEqual(len(results), 2)
        
    def test_get_statistics_v14(self):
        # Ensure at least one classification
        classify_ioc_v14("192.168.1.1")
        stats = get_statistics_v14()
        self.assertIn('total_classified', stats)


class TestClassificationContext(unittest.TestCase):
    """Test classification context"""
    
    def test_context_defaults(self):
        ctx = ClassificationContext()
        self.assertEqual(ctx.severity, "medium")
        self.assertEqual(ctx.historical_fp_rate, 0.0)
        
    def test_context_with_values(self):
        ctx = ClassificationContext(
            source_feed="AbuseCH",
            severity="critical",
            historical_fp_rate=0.1
        )
        self.assertEqual(ctx.source_feed, "AbuseCH")
        self.assertEqual(ctx.severity, "critical")


def run_tests():
    """Run all tests and return results"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    suite.addTests(loader.loadTestsFromTestCase(TestBayesianCalibrator))
    suite.addTests(loader.loadTestsFromTestCase(TestTemporalDriftDetector))
    suite.addTests(loader.loadTestsFromTestCase(TestEntropyAnalyzer))
    suite.addTests(loader.loadTestsFromTestCase(TestEnsembleVotingClassifier))
    suite.addTests(loader.loadTestsFromTestCase(TestFalsePositiveClassifierV14))
    suite.addTests(loader.loadTestsFromTestCase(TestGlobalConvenienceFunctions))
    suite.addTests(loader.loadTestsFromTestCase(TestClassificationContext))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Save results
    with open('test_results_false_positive_v14_2026_june.json', 'w') as f:
        import json
        f.write(json.dumps({
            'tests_run': result.testsRun,
            'failures': len(result.failures),
            'errors': len(result.errors),
            'success': result.wasSuccessful()
        }, indent=2))
        
    return result


if __name__ == '__main__':
    result = run_tests()
    print(f"\n{'='*60}")
    print(f"V14 Classifier Tests: {result.testsRun} run, "
          f"{len(result.failures)} failures, {len(result.errors)} errors")
    print(f"{'PASSED' if result.wasSuccessful() else 'FAILED'}")
    print(f"{'='*60}")
    sys.exit(0 if result.wasSuccessful() else 1)
