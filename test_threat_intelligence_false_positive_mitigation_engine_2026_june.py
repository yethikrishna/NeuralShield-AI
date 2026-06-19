"""
Test suite for False Positive Mitigation Engine
Real, verifiable tests with actual assertions
"""
import unittest
import json
import time
from datetime import datetime, timedelta
from neural_shield.threat_intelligence_false_positive_mitigation_engine_2026_june import (
    FalsePositiveMitigationEngine,
    SecurityAlert,
    AlertSeverity,
    FalsePositiveCategory,
    MitigationAction
)


class TestFalsePositiveMitigationEngine(unittest.TestCase):
    """Real tests for the FP mitigation engine"""
    
    def setUp(self):
        """Set up test engine before each test"""
        self.engine = FalsePositiveMitigationEngine()
    
    def test_engine_initialization(self):
        """Test that engine initializes properly with default values"""
        self.assertIsNotNone(self.engine)
        metrics = self.engine.get_performance_metrics()
        self.assertEqual(metrics["total_alerts_assessed"], 0)
        self.assertEqual(metrics["false_positives_identified"], 0)
        self.assertGreater(metrics["active_whitelist_entries"], 0)
        print("✓ Engine initialization test passed")
    
    def test_whitelist_management(self):
        """Test whitelist add/remove functionality"""
        # Add entry
        entry_id = self.engine.add_whitelist_entry(
            "192.168.1.100", "ip", "Internal server", "test_user"
        )
        self.assertIsNotNone(entry_id)
        self.assertTrue(entry_id.startswith("wl-"))
        
        # Check metrics
        metrics = self.engine.get_performance_metrics()
        self.assertGreaterEqual(metrics["active_whitelist_entries"], 5)
        
        # Remove entry
        result = self.engine.remove_whitelist_entry(entry_id)
        self.assertTrue(result)
        
        # Remove non-existent
        result = self.engine.remove_whitelist_entry("non-existent-id")
        self.assertFalse(result)
        print("✓ Whitelist management test passed")
    
    def test_whitelist_match_detection(self):
        """Test that whitelist matches are properly detected"""
        # Add test whitelist entry
        self.engine.add_whitelist_entry(
            "10.0.0.5", "ip", "Test internal server", "test"
        )
        
        # Create alert with whitelisted IP
        alert = SecurityAlert(
            alert_id="test-001",
            title="Suspicious connection detected",
            description="Connection from internal monitoring server",
            severity=AlertSeverity.LOW,
            source="firewall",
            detector="connection_monitor",
            indicators=["10.0.0.5"],
            affected_assets=["server-prod-01"]
        )
        
        result = self.engine.assess_alert(alert)
        self.assertIsNotNone(result)
        
        # Should have whitelist evidence
        has_whitelist_evidence = any(
            e["type"] == "whitelist" for e in result.supporting_evidence
        )
        self.assertTrue(has_whitelist_evidence)
        print("✓ Whitelist match detection test passed")
    
    def test_internal_ip_detection(self):
        """Test detection of internal/private IP addresses"""
        alert = SecurityAlert(
            alert_id="test-002",
            title="Port scan detected",
            description="Network scanning activity",
            severity=AlertSeverity.MEDIUM,
            source="ids",
            detector="port_scan_detector",
            indicators=["192.168.1.50", "10.0.1.25"],
            affected_assets=["web-server-01"]
        )
        
        result = self.engine.assess_alert(alert)
        self.assertIsNotNone(result)
        
        has_internal_evidence = any(
            e["type"] == "internal_network" for e in result.supporting_evidence
        )
        self.assertTrue(has_internal_evidence)
        print("✓ Internal IP detection test passed")
    
    def test_benign_keyword_detection(self):
        """Test detection of benign keywords in alerts"""
        alert = SecurityAlert(
            alert_id="test-003",
            title="Administrator login from test server",
            description="Successful admin login during maintenance window",
            severity=AlertSeverity.LOW,
            source="auth_log",
            detector="login_monitor",
            indicators=["admin-user"],
            affected_assets=["test-server-01"]
        )
        
        result = self.engine.assess_alert(alert)
        self.assertIsNotNone(result)
        
        has_benign_evidence = any(
            e["type"] == "benign_keyword" for e in result.supporting_evidence
        )
        self.assertTrue(has_benign_evidence)
        self.assertGreater(result.false_positive_probability, 0)
        print("✓ Benign keyword detection test passed")
    
    def test_high_severity_true_positive(self):
        """Test that high severity alerts are treated as likely true positives"""
        alert = SecurityAlert(
            alert_id="test-004",
            title="Ransomware encryption detected",
            description="Mass file encryption activity observed",
            severity=AlertSeverity.CRITICAL,
            source="edr",
            detector="ransomware_detector",
            indicators=["unknown-malware.exe"],
            affected_assets=["fileserver-prod-01"]
        )
        
        result = self.engine.assess_alert(alert)
        self.assertIsNotNone(result)
        
        # Critical severity should reduce FP probability
        self.assertGreater(result.true_positive_probability, result.false_positive_probability)
        self.assertIn("High severity alert", str(result.risk_factors))
        print("✓ High severity true positive test passed")
    
    def test_likely_false_positive_scenario(self):
        """Test clear false positive scenario with multiple indicators"""
        alert = SecurityAlert(
            alert_id="test-005",
            title="Login from localhost during testing",
            description="Administrator login from 127.0.0.1 on dev server during maintenance",
            severity=AlertSeverity.INFORMATIONAL,
            source="auth_log",
            detector="login_monitor",
            indicators=["127.0.0.1"],
            affected_assets=["dev-server-01"]
        )
        
        result = self.engine.assess_alert(alert)
        self.assertIsNotNone(result)
        
        # Multiple FP factors: localhost, dev/test context, informational severity
        self.assertGreater(result.false_positive_probability, 0.5)
        self.assertTrue(result.is_likely_false_positive)
        print("✓ Likely false positive scenario test passed")
    
    def test_recommendation_logic(self):
        """Test that recommendations are appropriate for confidence levels"""
        # Clear FP scenario
        fp_alert = SecurityAlert(
            alert_id="test-fp",
            title="Healthcheck ping from localhost",
            description="Monitoring ping",
            severity=AlertSeverity.LOW,
            source="monitoring",
            detector="ping_monitor",
            indicators=["127.0.0.1"],
            affected_assets=["monitoring-01"]
        )
        
        fp_result = self.engine.assess_alert(fp_alert)
        self.assertIn(fp_result.recommended_action, [
            MitigationAction.SUPPRESS_PERMANENT,
            MitigationAction.SUPPRESS_TEMPORARY,
            MitigationAction.ADD_TO_WHITELIST
        ])
        
        # Clear TP scenario
        tp_alert = SecurityAlert(
            alert_id="test-tp",
            title="Data exfiltration to external IP",
            description="Large data transfer to unknown external host",
            severity=AlertSeverity.CRITICAL,
            source="network",
            detector="data_exfiltration",
            indicators=["198.51.100.25"],
            affected_assets=["database-prod"]
        )
        
        tp_result = self.engine.assess_alert(tp_alert)
        self.assertIn(tp_result.recommended_action, [
            MitigationAction.ESCALATE_AS_TRUE_POSITIVE,
            MitigationAction.INVESTIGATE_FURTHER
        ])
        print("✓ Recommendation logic test passed")
    
    def test_batch_assessment(self):
        """Test batch assessment of multiple alerts"""
        alerts = []
        for i in range(5):
            alert = SecurityAlert(
                alert_id=f"batch-{i:03d}",
                title=f"Test alert {i}",
                description=f"Test description for alert {i}",
                severity=AlertSeverity.LOW,
                source="test",
                detector="test_detector",
                indicators=[f"192.168.1.{i}"],
                affected_assets=[f"server-{i}"]
            )
            alerts.append(alert)
        
        results = self.engine.batch_assess_alerts(alerts)
        self.assertEqual(len(results), 5)
        
        metrics = self.engine.get_performance_metrics()
        self.assertEqual(metrics["total_alerts_assessed"], 5)
        print("✓ Batch assessment test passed")
    
    def test_performance_metrics(self):
        """Test that performance metrics are tracked correctly"""
        # Process some alerts
        for i in range(3):
            alert = SecurityAlert(
                alert_id=f"metric-{i}",
                title=f"Alert {i}",
                description="Test alert",
                severity=AlertSeverity.MEDIUM,
                source="test",
                detector="test",
                indicators=["10.0.0.1"],
                affected_assets=["test-server"]
            )
            self.engine.assess_alert(alert)
        
        metrics = self.engine.get_performance_metrics()
        self.assertEqual(metrics["total_alerts_assessed"], 3)
        self.assertIn("fp_reduction_rate", metrics)
        self.assertIn("alert_volume_reduction_potential", metrics)
        self.assertIn("tracked_assets_count", metrics)
        print("✓ Performance metrics test passed")
    
    def test_assessment_export(self):
        """Test assessment report export functionality"""
        alert = SecurityAlert(
            alert_id="export-001",
            title="Test alert for export",
            description="Testing report export",
            severity=AlertSeverity.MEDIUM,
            source="test",
            detector="test",
            indicators=["192.168.1.1"],
            affected_assets=["server-01"]
        )
        
        result = self.engine.assess_alert(alert)
        report = self.engine.export_assessment_report(result.assessment_id)
        
        self.assertIsNotNone(report)
        self.assertIn("assessment_summary", report)
        self.assertIn("engine_metrics_at_time", report)
        self.assertIn("recommendation_explanation", report)
        
        # Test non-existent assessment
        non_existent = self.engine.export_assessment_report("non-existent-id")
        self.assertIsNone(non_existent)
        print("✓ Assessment export test passed")
    
    def test_fp_category_classification(self):
        """Test false positive category classification"""
        # Test environment category
        test_alert = SecurityAlert(
            alert_id="cat-test",
            title="Test activity on staging server",
            description="Testing in development environment",
            severity=AlertSeverity.LOW,
            source="test",
            detector="test",
            indicators=["127.0.0.1"],
            affected_assets=["staging-server"]
        )
        result = self.engine.assess_alert(test_alert)
        self.assertIsNotNone(result.fp_category)
        
        # Admin action category
        admin_alert = SecurityAlert(
            alert_id="cat-admin",
            title="Administrator activity",
            description="Admin performing maintenance",
            severity=AlertSeverity.LOW,
            source="auth",
            detector="login",
            indicators=["127.0.0.1"],
            affected_assets=["server-01"]
        )
        result2 = self.engine.assess_alert(admin_alert)
        self.assertIsNotNone(result2.fp_category)
        print("✓ FP category classification test passed")
    
    def test_temporary_whitelist_entry(self):
        """Test temporary whitelist entries with expiration"""
        entry_id = self.engine.add_whitelist_entry(
            "temp-ip", "ip", "Temporary entry", "test", duration_hours=1
        )
        
        # Should be active now
        with self.engine._lock:
            entry = self.engine.whitelist[entry_id]
        self.assertTrue(entry.is_active())
        
        # Create expired entry manually for testing
        expired_id = self.engine.add_whitelist_entry(
            "expired", "ip", "Expired entry", "test", duration_hours=-1
        )
        with self.engine._lock:
            expired_entry = self.engine.whitelist[expired_id]
        self.assertFalse(expired_entry.is_active())
        print("✓ Temporary whitelist entry test passed")
    
    def test_result_serialization(self):
        """Test that results can be serialized to dict"""
        alert = SecurityAlert(
            alert_id="serial-001",
            title="Serialization test",
            description="Testing to_dict method",
            severity=AlertSeverity.MEDIUM,
            source="test",
            detector="test",
            indicators=["192.168.1.1"],
            affected_assets=["server-01"]
        )
        
        result = self.engine.assess_alert(alert)
        result_dict = result.to_dict()
        
        self.assertIsInstance(result_dict, dict)
        self.assertIn("is_likely_false_positive", result_dict)
        self.assertIn("false_positive_probability", result_dict)
        self.assertIn("recommended_action", result_dict)
        
        # Test JSON serialization
        json_str = json.dumps(result_dict)
        self.assertIsInstance(json_str, str)
        print("✓ Result serialization test passed")


def run_tests():
    """Run all tests and save results"""
    print("=" * 60)
    print("Running False Positive Mitigation Engine Tests")
    print("=" * 60)
    
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestFalsePositiveMitigationEngine)
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Save results
    results_data = {
        "tests_run": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "was_successful": result.wasSuccessful(),
        "timestamp": datetime.now().isoformat()
    }
    
    with open("test_results_false_positive_mitigation_engine.json", "w") as f:
        json.dump(results_data, f, indent=2)
    
    print("\n" + "=" * 60)
    print(f"Tests passed: {result.testsRun - len(result.failures) - len(result.errors)}/{result.testsRun}")
    print(f"Success: {result.wasSuccessful()}")
    print("=" * 60)
    
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    exit(0 if success else 1)
