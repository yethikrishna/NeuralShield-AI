"""
Test Suite for NeuralShield-AI: Transformer V6 False Positive Classifier
June 2026 Production-Grade Tests

Comprehensive tests covering:
- Multi-head attention computation
- Threat alert data structures
- Feature extraction for benign/malicious alerts
- Single and batch classification
- Ensemble voting with 7 sub-models
- Explanation generation
- Online learning with feedback
- Performance metrics tracking
- Model state export
- Edge cases and boundary conditions
"""
import sys
import os
import json
import time
import unittest

# Add module path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from threat_intelligence_automated_false_positive_classifier_transformer_v6_2026_june import (
    TransformerV6FalsePositiveClassifier,
    ThreatAlert,
    ClassificationOutput,
    AlertSeverity,
    ClassificationResult,
    MultiHeadAttentionLayer
)


class TestMultiHeadAttentionLayer(unittest.TestCase):
    """Test multi-head attention functionality"""
    
    def test_attention_basic_computation(self):
        """Test basic attention weight computation"""
        attention = MultiHeadAttentionLayer(num_heads=4)
        
        features = {"feature1": 0.8, "feature2": 0.2, "feature3": 0.5}
        context = [
            {"feature1": 0.7, "feature2": 0.3, "feature3": 0.6},
            {"feature1": 0.9, "feature2": 0.1, "feature3": 0.4}
        ]
        
        weighted = attention.compute_attention(features, context)
        
        self.assertIsInstance(weighted, dict)
        self.assertEqual(len(weighted), len(features))
        for key in features:
            self.assertIn(key, weighted)
    
    def test_attention_with_empty_context(self):
        """Test attention with empty context"""
        attention = MultiHeadAttentionLayer()
        
        features = {"feature1": 0.5, "feature2": 0.5}
        weighted = attention.compute_attention(features, [])
        
        self.assertIsInstance(weighted, dict)
        self.assertEqual(len(weighted), 2)


class TestThreatAlert(unittest.TestCase):
    """Test ThreatAlert data class"""
    
    def test_alert_auto_generates_id(self):
        """Test alert auto-generates ID if not provided"""
        alert = ThreatAlert(
            alert_id="",
            alert_type="network",
            message="Test alert",
            source="192.168.1.1",
            destination="10.0.0.1",
            severity=AlertSeverity.MEDIUM
        )
        
        self.assertNotEqual(alert.alert_id, "")
        self.assertEqual(len(alert.alert_id), 16)  # MD5 hex truncated
    
    def test_alert_preserves_provided_id(self):
        """Test alert preserves provided ID"""
        alert = ThreatAlert(
            alert_id="custom_id_123",
            alert_type="network",
            message="Test",
            source="1.1.1.1",
            destination="2.2.2.2",
            severity=AlertSeverity.HIGH
        )
        
        self.assertEqual(alert.alert_id, "custom_id_123")


class TestTransformerV6Classifier(unittest.TestCase):
    """Main classifier tests"""
    
    def setUp(self):
        """Set up test classifier"""
        self.classifier = TransformerV6FalsePositiveClassifier(
            confidence_threshold=0.7,
            fp_probability_threshold=0.65,
            enable_online_learning=True
        )
    
    def test_classifier_initialization(self):
        """Test classifier initializes correctly"""
        self.assertEqual(self.classifier.confidence_threshold, 0.7)
        self.assertEqual(self.classifier.fp_probability_threshold, 0.65)
        self.assertTrue(self.classifier.enable_online_learning)
        self.assertIsNotNone(self.classifier.attention)
        self.assertGreater(len(self.classifier.feature_weights), 0)
    
    def test_feature_extraction_benign_alert(self):
        """Test feature extraction for known benign alert"""
        alert = ThreatAlert(
            alert_id="test1",
            alert_type="endpoint",
            message="Windows Update scheduled task running backup sync",
            source="192.168.1.100",
            destination="10.0.0.50",
            severity=AlertSeverity.LOW
        )
        
        features = self.classifier._extract_features(alert)
        
        self.assertGreater(features["msg_contains_benign_keyword"], 0)
        self.assertEqual(features["source_internal_ip"], 1.0)
        self.assertEqual(features["severity_low"], 1.0)
    
    def test_feature_extraction_malicious_alert(self):
        """Test feature extraction for known malicious alert"""
        alert = ThreatAlert(
            alert_id="test2",
            alert_type="endpoint",
            message="Mimikatz credential dump detected with Invoke-Mimikatz",
            source="8.8.8.8",
            destination="192.168.1.100",
            severity=AlertSeverity.CRITICAL
        )
        
        features = self.classifier._extract_features(alert)
        
        self.assertEqual(features["msg_contains_attack_keyword"], 1.0)
        self.assertEqual(features["source_internal_ip"], 0.0)
        self.assertEqual(features["severity_critical"], 1.0)
    
    def test_classify_benign_alert(self):
        """Test classification of known false positive alert"""
        alert = ThreatAlert(
            alert_id="fp_test",
            alert_type="network",
            message="Windows Update automatic sync health check monitoring",
            source="192.168.1.50",
            destination="10.0.0.1",
            severity=AlertSeverity.INFO
        )
        
        result = self.classifier.classify_alert(alert)
        
        self.assertIsInstance(result, ClassificationOutput)
        self.assertGreater(result.false_positive_probability, 0)
        self.assertGreater(result.confidence_score, 0)
        self.assertGreater(len(result.explanation), 0)
    
    def test_classify_malicious_alert(self):
        """Test classification of known true positive alert"""
        alert = ThreatAlert(
            alert_id="tp_test",
            alert_type="endpoint",
            message="Mimikatz credential dump detected PowerShell execution",
            source="1.2.3.4",
            destination="192.168.1.100",
            severity=AlertSeverity.CRITICAL
        )
        
        result = self.classifier.classify_alert(alert)
        
        self.assertIsInstance(result, ClassificationOutput)
        # Malicious alerts should have LOW false positive probability
        self.assertLess(result.false_positive_probability, 0.8)
    
    def test_batch_classification(self):
        """Test batch classification of multiple alerts"""
        alerts = [
            ThreatAlert(
                alert_id=f"batch_{i}",
                alert_type="network",
                message=f"Test alert {i}",
                source=f"192.168.1.{i}",
                destination="10.0.0.1",
                severity=AlertSeverity.MEDIUM
            )
            for i in range(5)
        ]
        
        results = self.classifier.classify_batch(alerts)
        
        self.assertEqual(len(results), 5)
        for result in results:
            self.assertIsInstance(result, ClassificationOutput)
    
    def test_ensemble_classification(self):
        """Test ensemble classification with 7 sub-models"""
        alert = ThreatAlert(
            alert_id="ensemble_test",
            alert_type="network",
            message="Windows Update backup sync",
            source="192.168.1.1",
            destination="10.0.0.1",
            severity=AlertSeverity.LOW
        )
        
        features = self.classifier._extract_features(alert)
        fp_prob, sub_scores = self.classifier._ensemble_classify(features)
        
        self.assertGreaterEqual(fp_prob, 0.0)
        self.assertLessEqual(fp_prob, 1.0)
        self.assertEqual(len(sub_scores), 7)  # 7 sub-models
        for name, score in sub_scores.items():
            self.assertGreaterEqual(score, 0.0)
            self.assertLessEqual(score, 1.0)
    
    def test_explanation_generation(self):
        """Test explanation generation"""
        alert = ThreatAlert(
            alert_id="explain_test",
            alert_type="network",
            message="Windows Update scheduled backup",
            source="192.168.1.1",
            destination="10.0.0.1",
            severity=AlertSeverity.LOW
        )
        
        result = self.classifier.classify_alert(alert)
        
        self.assertGreater(len(result.explanation), 0)
        for explanation in result.explanation:
            self.assertIsInstance(explanation, str)
            self.assertGreater(len(explanation), 0)
    
    def test_online_learning_feedback(self):
        """Test online learning with feedback"""
        alert = ThreatAlert(
            alert_id="feedback_test",
            alert_type="network",
            message="Test alert for feedback",
            source="192.168.1.1",
            destination="10.0.0.1",
            severity=AlertSeverity.MEDIUM
        )
        
        initial_feedback = self.classifier.stats["feedback_count"]
        
        # Provide feedback that this was actually a false positive
        self.classifier.provide_feedback(alert, is_actually_false_positive=True)
        
        self.assertEqual(self.classifier.stats["feedback_count"], initial_feedback + 1)
        self.assertEqual(len(self.classifier.feedback_data), 1)
    
    def test_filter_false_positives(self):
        """Test filtering false positives from alert list"""
        alerts = [
            ThreatAlert(
                alert_id="fp1",
                alert_type="network",
                message="Windows Update backup sync health check",
                source="192.168.1.1",
                destination="10.0.0.1",
                severity=AlertSeverity.LOW
            ),
            ThreatAlert(
                alert_id="tp1",
                alert_type="endpoint",
                message="Mimikatz credential dump detected",
                source="1.2.3.4",
                destination="192.168.1.100",
                severity=AlertSeverity.CRITICAL
            )
        ]
        
        filtered, fps = self.classifier.filter_false_positives(alerts, min_confidence=0.0)
        
        self.assertIsInstance(filtered, list)
        self.assertIsInstance(fps, list)
        self.assertEqual(len(filtered) + len(fps), len(alerts))
    
    def test_performance_metrics(self):
        """Test performance metrics tracking"""
        # Classify some alerts
        for i in range(3):
            alert = ThreatAlert(
                alert_id=f"perf_{i}",
                alert_type="network",
                message=f"Test {i}",
                source="192.168.1.{i}",
                destination="10.0.0.1",
                severity=AlertSeverity.MEDIUM
            )
            self.classifier.classify_alert(alert)
        
        metrics = self.classifier.get_performance_metrics()
        
        self.assertEqual(metrics["model_version"], "transformer_v6")
        self.assertEqual(metrics["total_alerts_classified"], 3)
        self.assertIn("false_positive_rate", metrics)
        self.assertIn("true_positive_rate", metrics)
        self.assertIn("average_confidence", metrics)
    
    def test_internal_ip_detection(self):
        """Test internal/private IP detection"""
        internal_ips = ["192.168.1.1", "10.0.0.50", "172.16.0.1", "127.0.0.1"]
        external_ips = ["8.8.8.8", "1.1.1.1", "203.0.113.1"]
        
        for ip in internal_ips:
            self.assertTrue(self.classifier._is_internal_ip(ip), f"Should detect {ip} as internal")
        
        for ip in external_ips:
            self.assertFalse(self.classifier._is_internal_ip(ip), f"Should detect {ip} as external")
    
    def test_export_model_state(self):
        """Test model state export"""
        state_json = self.classifier.export_model_state()
        
        self.assertIsInstance(state_json, str)
        state = json.loads(state_json)
        
        self.assertIn("feature_weights", state)
        self.assertIn("baseline_frequencies", state)
        self.assertIn("performance_metrics", state)
        self.assertIn("exported_at", state)


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and boundary conditions"""
    
    def setUp(self):
        self.classifier = TransformerV6FalsePositiveClassifier()
    
    def test_empty_message(self):
        """Test classification with empty message"""
        alert = ThreatAlert(
            alert_id="empty_msg",
            alert_type="network",
            message="",
            source="192.168.1.1",
            destination="10.0.0.1",
            severity=AlertSeverity.MEDIUM
        )
        
        result = self.classifier.classify_alert(alert)
        self.assertIsInstance(result, ClassificationOutput)
        self.assertGreater(result.confidence_score, 0)
    
    def test_empty_metadata(self):
        """Test classification with empty metadata"""
        alert = ThreatAlert(
            alert_id="empty_meta",
            alert_type="network",
            message="Test alert",
            source="192.168.1.1",
            destination="10.0.0.1",
            severity=AlertSeverity.MEDIUM,
            metadata={}
        )
        
        result = self.classifier.classify_alert(alert)
        self.assertIsInstance(result, ClassificationOutput)
    
    def test_special_characters_message(self):
        """Test message with special characters"""
        alert = ThreatAlert(
            alert_id="special_chars",
            alert_type="network",
            message="!!!***@@@###$$$%%%^^^&&&",
            source="192.168.1.1",
            destination="10.0.0.1",
            severity=AlertSeverity.MEDIUM
        )
        
        result = self.classifier.classify_alert(alert)
        self.assertIsInstance(result, ClassificationOutput)
    
    def test_unknown_source(self):
        """Test classification with unknown external source"""
        alert = ThreatAlert(
            alert_id="unknown_src",
            alert_type="network",
            message="Suspicious connection",
            source="203.0.113.255",
            destination="192.168.1.100",
            severity=AlertSeverity.HIGH
        )
        
        result = self.classifier.classify_alert(alert)
        self.assertIsInstance(result, ClassificationOutput)


def run_tests():
    """Run all tests and generate report"""
    print("=" * 70)
    print("NeuralShield-AI: Transformer V6 False Positive Classifier - Test Suite")
    print("June 2026 Production-Grade Tests")
    print("=" * 70)
    print()
    
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    suite.addTests(loader.loadTestsFromTestCase(TestMultiHeadAttentionLayer))
    suite.addTests(loader.loadTestsFromTestCase(TestThreatAlert))
    suite.addTests(loader.loadTestsFromTestCase(TestTransformerV6Classifier))
    suite.addTests(loader.loadTestsFromTestCase(TestEdgeCases))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print()
    print("=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    print(f"Tests Run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Skipped: {len(result.skipped)}")
    print()
    
    if result.wasSuccessful():
        print("✅ ALL TESTS PASSED - Production Ready!")
        status = "PASSED"
    else:
        print("❌ SOME TESTS FAILED")
        status = "FAILED"
    
    # Save test results
    test_results = {
        "test_timestamp": time.time(),
        "test_datetime": time.strftime("%Y-%m-%d %H:%M:%S"),
        "tests_run": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "skipped": len(result.skipped),
        "status": status,
        "classifier_version": "transformer_v6"
    }
    
    with open("test_results_transformer_v6_false_positive_classifier.json", "w") as f:
        json.dump(test_results, f, indent=2)
    
    print(f"\nTest results saved to: test_results_transformer_v6_false_positive_classifier.json")
    print()
    
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
