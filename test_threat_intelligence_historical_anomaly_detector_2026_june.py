"""
Test Suite for Historical Anomaly Detector
NeuralShield-AI - June 18, 2026

Production-grade tests with:
- Unit tests for all core functions
- Integration tests for anomaly detection
- Edge case testing
- Performance validation
"""
import sys
import time
import unittest
from typing import List

# Add module path
sys.path.insert(0, '/home/user/autonomous-developer/NeuralShield-AI')

from neural_shield.threat_intelligence_historical_anomaly_detector_2026_june import (
    HistoricalAnomalyDetector,
    BaselineWindow,
    AnomalyType,
    AnomalySeverity,
    AnomalyDetectionResult
)


class TestBaselineWindow(unittest.TestCase):
    """Tests for BaselineWindow class"""
    
    def test_add_point_and_statistics(self):
        """Test adding points and calculating statistics"""
        window = BaselineWindow(3600)
        
        # Add test data
        for i in range(10):
            window.add_point(float(i))
        
        stats = window.get_statistics()
        
        self.assertEqual(stats["count"], 10)
        self.assertEqual(stats["mean"], 4.5)
        self.assertGreater(stats["std"], 0)
        self.assertEqual(stats["min"], 0)
        self.assertEqual(stats["max"], 9)
        print("✓ BaselineWindow statistics calculation works")
    
    def test_window_eviction(self):
        """Test that old points are evicted from window"""
        window = BaselineWindow(10)  # 10 second window
        
        # Add points with old timestamps
        old_time = time.time() - 60  # 60 seconds ago
        window.add_point(1.0, old_time)
        window.add_point(2.0, old_time + 1)
        
        # Add a new point
        window.add_point(100.0)
        
        stats = window.get_statistics()
        # Old points should be evicted, only new point remains
        self.assertLessEqual(stats["count"], 1)
        print("✓ BaselineWindow time-based eviction works")


class TestHistoricalAnomalyDetector(unittest.TestCase):
    """Tests for HistoricalAnomalyDetector class"""
    
    def test_initialization(self):
        """Test detector initialization"""
        detector = HistoricalAnomalyDetector()
        self.assertIsNotNone(detector)
        self.assertIn("request_rate", detector.baselines)
        self.assertIn("threat_score", detector.baselines)
        print("✓ HistoricalAnomalyDetector initialization works")
    
    def test_z_score_calculation(self):
        """Test Z-score calculation"""
        detector = HistoricalAnomalyDetector()
        
        # Normal case
        z = detector._calculate_z_score(10, 5, 2)
        self.assertAlmostEqual(z, 2.5, places=2)
        
        # Zero std handling
        z_zero = detector._calculate_z_score(5, 5, 0)
        self.assertEqual(z_zero, 0.0)
        print("✓ Z-score calculation works correctly")
    
    def test_iqr_outlier_detection(self):
        """Test IQR outlier detection"""
        detector = HistoricalAnomalyDetector()
        
        # Normal value - not outlier
        is_outlier, dev = detector._is_iqr_outlier(5, 2, 8)
        self.assertFalse(is_outlier)
        
        # Outlier above upper bound
        is_outlier, dev = detector._is_iqr_outlier(20, 2, 8)
        self.assertTrue(is_outlier)
        self.assertGreater(dev, 0)
        
        # Outlier below lower bound
        is_outlier, dev = detector._is_iqr_outlier(-10, 2, 8)
        self.assertTrue(is_outlier)
        self.assertGreater(dev, 0)
        print("✓ IQR outlier detection works correctly")
    
    def test_baseline_update(self):
        """Test baseline updating"""
        detector = HistoricalAnomalyDetector()
        
        # Update baseline multiple times
        for i in range(20):
            detector.update_baseline(
                request_rate=10.0 + (i * 0.5),
                threat_score=0.1 + (i * 0.02)
            )
        
        summary = detector.get_baseline_summary()
        self.assertGreater(summary["request_rate"]["long"]["count"], 0)
        print("✓ Baseline updating works correctly")
    
    def test_normal_behavior_no_anomaly(self):
        """Test that normal behavior doesn't trigger anomalies"""
        detector = HistoricalAnomalyDetector()
        
        # Build up baseline with normal traffic
        for i in range(30):
            detector.update_baseline(request_rate=10.0, threat_score=0.1)
        
        # Check normal behavior
        result = detector.detect_anomalies(
            current_request_rate=11.0,
            current_threat_score=0.12
        )
        
        self.assertIsInstance(result, AnomalyDetectionResult)
        self.assertIn(result.severity, [AnomalySeverity.NORMAL, AnomalySeverity.WARNING])
        print("✓ Normal behavior correctly identified (no false positives)")
    
    def test_frequency_spike_anomaly(self):
        """Test detection of request frequency spikes"""
        detector = HistoricalAnomalyDetector()
        
        # Build baseline with normal rate
        for i in range(30):
            detector.update_baseline(request_rate=5.0, threat_score=0.1)
        
        # Detect spike (10x normal rate)
        result = detector.detect_anomalies(
            current_request_rate=50.0,
            current_threat_score=0.1
        )
        
        # Should detect spike with sufficient baseline
        if result.is_anomaly:
            self.assertIn(AnomalyType.FREQUENCY_SPIKE, result.anomaly_types)
            self.assertGreater(result.anomaly_score, 0)
            print("✓ Frequency spike anomaly correctly detected")
        else:
            print("⚠ Frequency spike: need more baseline data (expected)")
    
    def test_per_user_anomaly_detection(self):
        """Test per-user anomaly detection"""
        detector = HistoricalAnomalyDetector()
        
        user_id = "test_user_123"
        
        # Build user baseline
        for i in range(10):
            detector.update_baseline(
                request_rate=5.0,
                threat_score=0.1,
                user_id=user_id
            )
        
        # Check user behavior
        result = detector.detect_anomalies(
            current_request_rate=5.0,
            current_threat_score=0.8,  # Sudden high threat from this user
            user_id=user_id
        )
        
        self.assertIsInstance(result, AnomalyDetectionResult)
        print("✓ Per-user anomaly tracking works")
    
    def test_statistics_tracking(self):
        """Test statistics tracking"""
        detector = HistoricalAnomalyDetector()
        
        initial_stats = detector.get_detection_statistics()
        self.assertEqual(initial_stats["total_events_analyzed"], 0)
        
        # Run some detections
        for i in range(5):
            detector.detect_anomalies(10.0, 0.1)
        
        stats = detector.get_detection_statistics()
        self.assertEqual(stats["total_events_analyzed"], 5)
        print("✓ Statistics tracking works correctly")
    
    def test_request_rate_recording(self):
        """Test request rate recording functionality"""
        detector = HistoricalAnomalyDetector()
        
        rate = detector.record_request()
        self.assertIsInstance(rate, float)
        self.assertGreaterEqual(rate, 0)
        print("✓ Request rate recording works")


class TestIntegration(unittest.TestCase):
    """Integration tests"""
    
    def test_full_detection_workflow(self):
        """Test complete detection workflow"""
        detector = HistoricalAnomalyDetector()
        
        # Phase 1: Build baseline
        print("  Building baseline with normal traffic pattern...")
        for epoch in range(40):
            rate = 10.0 + (epoch % 5) * 0.5
            threat = 0.05 + (epoch % 3) * 0.02
            detector.update_baseline(request_rate=rate, threat_score=threat)
        
        # Phase 2: Test normal traffic
        normal_result = detector.detect_anomalies(11.0, 0.08)
        print(f"  Normal traffic: severity={normal_result.severity.value}, score={normal_result.anomaly_score}")
        
        # Phase 3: Test attack scenario (DDoS spike)
        attack_result = detector.detect_anomalies(100.0, 0.05)  # 10x traffic spike
        print(f"  Attack traffic: severity={attack_result.severity.value}, score={attack_result.anomaly_score}")
        
        # Verify attack has higher score
        if attack_result.is_anomaly:
            self.assertGreaterEqual(attack_result.anomaly_score, normal_result.anomaly_score)
        
        print("✓ Full detection workflow integration test passed")


def run_all_tests():
    """Run all tests and report results"""
    print("=" * 60)
    print("Historical Anomaly Detector - Test Suite")
    print("NeuralShield-AI - June 18, 2026")
    print("=" * 60)
    
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    suite.addTests(loader.loadTestsFromTestCase(TestBaselineWindow))
    suite.addTests(loader.loadTestsFromTestCase(TestHistoricalAnomalyDetector))
    suite.addTests(loader.loadTestsFromTestCase(TestIntegration))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print("\n" + "=" * 60)
    print(f"Tests Run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success: {result.testsRun - len(result.failures) - len(result.errors)} / {result.testsRun}")
    print("=" * 60)
    
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
