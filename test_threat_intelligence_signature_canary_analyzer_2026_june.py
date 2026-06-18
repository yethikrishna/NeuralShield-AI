#!/usr/bin/env python3
"""
Test Suite for Threat Intelligence Signature Canary Analyzer
June 2026 - Production Grade Tests
Tests all canary deployment, health analysis, phase management, and rollback functionality.
"""
import sys
import time
import unittest
from pathlib import Path

# Add neural_shield to path
sys.path.insert(0, str(Path(__file__).parent))

from neural_shield.threat_intelligence_signature_canary_analyzer_2026_june import (
    ThreatIntelSignatureCanaryAnalyzer,
    CanaryMetrics,
    CanaryPhase,
    CanaryHealthStatus,
    DeploymentDecision
)


class TestCanaryMetrics(unittest.TestCase):
    """Test CanaryMetrics calculations."""

    def test_false_positive_rate_calculation(self):
        """Test FPR calculation works correctly."""
        metrics = CanaryMetrics(
            false_positives=5,
            true_negatives=95
        )
        self.assertEqual(metrics.calculate_fpr(), 0.05)

    def test_fpr_with_no_negatives(self):
        """Test FPR handles edge case with no negatives."""
        metrics = CanaryMetrics(false_positives=0, true_negatives=0)
        self.assertEqual(metrics.calculate_fpr(), 0.0)

    def test_precision_calculation(self):
        """Test precision calculation."""
        metrics = CanaryMetrics(true_positives=90, false_positives=10)
        self.assertEqual(metrics.calculate_precision(), 0.9)

    def test_precision_with_no_predictions(self):
        """Test precision handles edge case."""
        metrics = CanaryMetrics(true_positives=0, false_positives=0)
        self.assertEqual(metrics.calculate_precision(), 1.0)

    def test_recall_calculation(self):
        """Test recall calculation."""
        metrics = CanaryMetrics(true_positives=80, false_negatives=20)
        self.assertEqual(metrics.calculate_recall(), 0.8)


class TestCanaryDeploymentLifecycle(unittest.TestCase):
    """Test canary deployment lifecycle operations."""

    def setUp(self):
        self.analyzer = ThreatIntelSignatureCanaryAnalyzer()

    def test_start_canary_deployment(self):
        """Test starting a new canary deployment."""
        canary_id = self.analyzer.start_canary_deployment(
            signature_version_id="sig_test_001",
            signature_name="Test YARA Rule - Malware Detection",
            start_phase=CanaryPhase.SHADOW
        )
        
        self.assertIsNotNone(canary_id)
        self.assertTrue(canary_id.startswith("canary_"))
        
        summary = self.analyzer.get_canary_summary(canary_id)
        self.assertIsNotNone(summary)
        self.assertEqual(summary["signature_version_id"], "sig_test_001")
        self.assertEqual(summary["current_phase"], "shadow")

    def test_start_canary_with_config_overrides(self):
        """Test starting canary with custom configuration."""
        canary_id = self.analyzer.start_canary_deployment(
            signature_version_id="sig_test_002",
            signature_name="Custom Config Test",
            config_overrides={
                "fpr_threshold": 0.02,
                "latency_threshold_ms": 50.0,
                "auto_advance": False
            }
        )
        
        summary = self.analyzer.get_canary_summary(canary_id)
        self.assertIsNotNone(summary)
        self.assertFalse(summary["auto_advance_enabled"])

    def test_record_canary_metrics(self):
        """Test recording metrics for canary."""
        canary_id = self.analyzer.start_canary_deployment(
            signature_version_id="sig_test_003",
            signature_name="Metrics Test"
        )
        
        metrics = CanaryMetrics(
            total_events_analyzed=1000,
            true_positives=45,
            false_positives=2,
            true_negatives=950,
            false_negatives=3,
            avg_latency_ms=15.5,
            max_latency_ms=45.0,
            cpu_usage_percent=2.5,
            memory_usage_mb=128.0,
            matches_per_second=150.0,
            error_count=0
        )
        
        result = self.analyzer.record_canary_metrics(canary_id, metrics)
        self.assertTrue(result)
        
        summary = self.analyzer.get_canary_summary(canary_id)
        self.assertEqual(summary["metrics_samples_collected"], 1)

    def test_record_metrics_invalid_canary(self):
        """Test recording metrics for non-existent canary."""
        metrics = CanaryMetrics(total_events_analyzed=100)
        result = self.analyzer.record_canary_metrics("invalid_canary_id", metrics)
        self.assertFalse(result)


class TestCanaryHealthAnalysis(unittest.TestCase):
    """Test canary health analysis and decision engine."""

    def setUp(self):
        self.analyzer = ThreatIntelSignatureCanaryAnalyzer()

    def test_healthy_canary_analysis(self):
        """Test analysis of a healthy performing canary."""
        canary_id = self.analyzer.start_canary_deployment(
            signature_version_id="sig_healthy_001",
            signature_name="Healthy Signature Test"
        )
        
        # Record healthy metrics
        for i in range(10):
            metrics = CanaryMetrics(
                total_events_analyzed=1000,
                true_positives=45,
                false_positives=3,  # 0.3% FPR - well below 5% threshold
                true_negatives=950,
                false_negatives=2,
                avg_latency_ms=12.0,
                error_count=0
            )
            self.analyzer.record_canary_metrics(canary_id, metrics)
            time.sleep(0.01)
        
        result = self.analyzer.analyze_canary_health(canary_id)
        
        self.assertIsNotNone(result)
        self.assertEqual(result.health_status, CanaryHealthStatus.HEALTHY)
        self.assertIn(result.deployment_decision, [DeploymentDecision.PROCEED, DeploymentDecision.EXTEND_CANARY])
        self.assertGreater(result.health_score, 80.0)
        self.assertEqual(len(result.issues_found), 0)

    def test_high_fpr_triggers_rollback(self):
        """Test that high false positive rate triggers rollback recommendation."""
        canary_id = self.analyzer.start_canary_deployment(
            signature_version_id="sig_bad_fpr_001",
            signature_name="High FPR Test",
            config_overrides={"fpr_threshold": 0.05}
        )
        
        # Record metrics with 10% FPR
        for i in range(5):
            metrics = CanaryMetrics(
                total_events_analyzed=1000,
                true_positives=10,
                false_positives=90,  # 9% FPR - exceeds threshold
                true_negatives=900,
                false_negatives=0,
                avg_latency_ms=10.0,
                error_count=0
            )
            self.analyzer.record_canary_metrics(canary_id, metrics)
        
        result = self.analyzer.analyze_canary_health(canary_id)
        
        self.assertIsNotNone(result)
        self.assertEqual(result.health_status, CanaryHealthStatus.CRITICAL)
        self.assertEqual(result.deployment_decision, DeploymentDecision.ROLLBACK)
        self.assertLess(result.health_score, 70.0)
        self.assertTrue(any("False positive rate" in issue for issue in result.issues_found))

    def test_high_latency_triggers_rollback(self):
        """Test that excessive latency triggers rollback."""
        canary_id = self.analyzer.start_canary_deployment(
            signature_version_id="sig_slow_001",
            signature_name="High Latency Test",
            config_overrides={"latency_threshold_ms": 50.0}
        )
        
        for i in range(5):
            metrics = CanaryMetrics(
                total_events_analyzed=1000,
                true_positives=50,
                false_positives=1,
                true_negatives=948,
                false_negatives=1,
                avg_latency_ms=150.0,  # Exceeds 50ms threshold
                error_count=0
            )
            self.analyzer.record_canary_metrics(canary_id, metrics)
        
        result = self.analyzer.analyze_canary_health(canary_id)
        
        self.assertIsNotNone(result)
        self.assertEqual(result.deployment_decision, DeploymentDecision.ROLLBACK)
        self.assertTrue(any("latency" in issue.lower() for issue in result.issues_found))

    def test_no_metrics_returns_unknown(self):
        """Test analysis with no metrics collected."""
        canary_id = self.analyzer.start_canary_deployment(
            signature_version_id="sig_empty_001",
            signature_name="Empty Metrics Test"
        )
        
        result = self.analyzer.analyze_canary_health(canary_id)
        
        self.assertIsNotNone(result)
        self.assertEqual(result.health_status, CanaryHealthStatus.UNKNOWN)
        self.assertEqual(result.deployment_decision, DeploymentDecision.PAUSE)

    def test_invalid_canary_analysis(self):
        """Test analysis of non-existent canary."""
        result = self.analyzer.analyze_canary_health("nonexistent_canary")
        self.assertIsNone(result)


class TestCanaryPhaseManagement(unittest.TestCase):
    """Test phase advancement and rollback."""

    def setUp(self):
        self.analyzer = ThreatIntelSignatureCanaryAnalyzer()

    def test_advance_canary_phase(self):
        """Test advancing through deployment phases."""
        canary_id = self.analyzer.start_canary_deployment(
            signature_version_id="sig_phase_001",
            signature_name="Phase Advancement Test",
            start_phase=CanaryPhase.SHADOW
        )
        
        # Advance to next phase
        success, msg = self.analyzer.advance_canary_phase(canary_id)
        self.assertTrue(success)
        self.assertIn("Advanced to phase", msg)
        
        summary = self.analyzer.get_canary_summary(canary_id)
        self.assertEqual(summary["current_phase"], "canary_1pct")

    def test_advance_to_specific_phase(self):
        """Test advancing to a specific target phase."""
        canary_id = self.analyzer.start_canary_deployment(
            signature_version_id="sig_phase_002",
            signature_name="Target Phase Test",
            start_phase=CanaryPhase.SHADOW
        )
        
        success, msg = self.analyzer.advance_canary_phase(
            canary_id,
            target_phase=CanaryPhase.CANARY_25_PERCENT
        )
        self.assertTrue(success)
        
        summary = self.analyzer.get_canary_summary(canary_id)
        self.assertEqual(summary["current_phase"], "canary_25pct")

    def test_cannot_regress_phase(self):
        """Test cannot go back to earlier phase."""
        canary_id = self.analyzer.start_canary_deployment(
            signature_version_id="sig_phase_003",
            signature_name="Regression Test",
            start_phase=CanaryPhase.CANARY_5_PERCENT
        )
        
        success, msg = self.analyzer.advance_canary_phase(
            canary_id,
            target_phase=CanaryPhase.SHADOW
        )
        self.assertFalse(success)
        self.assertIn("Cannot regress", msg)

    def test_rollback_canary(self):
        """Test manual canary rollback."""
        canary_id = self.analyzer.start_canary_deployment(
            signature_version_id="sig_rollback_001",
            signature_name="Rollback Test",
            start_phase=CanaryPhase.CANARY_25_PERCENT
        )
        
        success, msg = self.analyzer.rollback_canary(
            canary_id,
            reason="Production issues detected in monitoring"
        )
        self.assertTrue(success)
        
        summary = self.analyzer.get_canary_summary(canary_id)
        self.assertEqual(summary["current_phase"], "rolled_back")

    def test_rollback_invalid_canary(self):
        """Test rollback of non-existent canary."""
        success, msg = self.analyzer.rollback_canary("invalid_id")
        self.assertFalse(success)


class TestCanaryReporting(unittest.TestCase):
    """Test canary reporting and export."""

    def setUp(self):
        self.analyzer = ThreatIntelSignatureCanaryAnalyzer()

    def test_get_canary_summary(self):
        """Test getting canary deployment summary."""
        canary_id = self.analyzer.start_canary_deployment(
            signature_version_id="sig_report_001",
            signature_name="Summary Test"
        )
        
        summary = self.analyzer.get_canary_summary(canary_id)
        self.assertIsNotNone(summary)
        self.assertIn("canary_id", summary)
        self.assertIn("signature_name", summary)
        self.assertIn("current_phase", summary)
        self.assertIn("metrics_samples_collected", summary)

    def test_get_summary_invalid_canary(self):
        """Test summary for non-existent canary."""
        summary = self.analyzer.get_canary_summary("invalid_id")
        self.assertIsNone(summary)

    def test_export_canary_report(self):
        """Test exporting full canary report."""
        canary_id = self.analyzer.start_canary_deployment(
            signature_version_id="sig_export_001",
            signature_name="Export Report Test"
        )
        
        # Record some metrics
        metrics = CanaryMetrics(total_events_analyzed=100)
        self.analyzer.record_canary_metrics(canary_id, metrics)
        
        report = self.analyzer.export_canary_report(canary_id)
        self.assertIsNotNone(report)
        self.assertIn("report_generated", report)
        self.assertIn("canary_summary", report)
        self.assertIn("deployment_log", report)
        self.assertGreater(len(report["deployment_log"]), 0)


def run_tests():
    """Run all tests and return results."""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    suite.addTests(loader.loadTestsFromTestCase(TestCanaryMetrics))
    suite.addTests(loader.loadTestsFromTestCase(TestCanaryDeploymentLifecycle))
    suite.addTests(loader.loadTestsFromTestCase(TestCanaryHealthAnalysis))
    suite.addTests(loader.loadTestsFromTestCase(TestCanaryPhaseManagement))
    suite.addTests(loader.loadTestsFromTestCase(TestCanaryReporting))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result


if __name__ == "__main__":
    print("=" * 70)
    print("Threat Intelligence Signature Canary Analyzer - Test Suite")
    print("June 2026 - Production Grade")
    print("=" * 70)
    print()
    
    result = run_tests()
    
    print()
    print("=" * 70)
    print(f"Tests Run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success: {'PASS' if result.wasSuccessful() else 'FAIL'}")
    print("=" * 70)
    
    sys.exit(0 if result.wasSuccessful() else 1)
