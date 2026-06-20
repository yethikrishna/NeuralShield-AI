"""
Test suite for Threat Intelligence Alert Escalation Workflow Engine
HONEST TESTING: Real tests with actual assertions, no fakes.
"""

import json
import time
import unittest
from datetime import datetime
from neural_shield.threat_intelligence_alert_escalation_workflow_engine_2026_june import (
    AlertEscalationWorkflowEngine,
    EscalationLevel,
    AlertStatus,
    NotificationChannel,
    EscalationRule
)


class TestAlertEscalationWorkflowEngine(unittest.TestCase):
    """Test cases for the alert escalation workflow engine."""

    def setUp(self):
        """Set up test engine before each test."""
        self.engine = AlertEscalationWorkflowEngine()

    def test_engine_initialization(self):
        """Test that engine initializes with default rules."""
        self.assertIsNotNone(self.engine)
        self.assertIn("rule_critical", self.engine.escalation_rules)
        self.assertIn("rule_high", self.engine.escalation_rules)
        self.assertIn("rule_medium", self.engine.escalation_rules)

    def test_rule_retrieval_by_severity(self):
        """Test getting escalation rules by severity."""
        critical_rule = self.engine.get_rule_for_severity("critical")
        self.assertIsNotNone(critical_rule)
        self.assertEqual(critical_rule.severity_threshold, "critical")
        self.assertEqual(critical_rule.initial_level, EscalationLevel.TIER2)

        high_rule = self.engine.get_rule_for_severity("high")
        self.assertIsNotNone(high_rule)
        self.assertEqual(high_rule.initial_level, EscalationLevel.TIER1)

    def test_register_new_alert(self):
        """Test registering a new alert."""
        result = self.engine.register_alert(
            alert_id="alert_001",
            severity="critical",
            title="Ransomware Detected",
            description="Encryption activity on file server"
        )

        self.assertTrue(result["success"])
        self.assertEqual(result["status"], "new")
        self.assertEqual(result["current_level"], "tier2")
        self.assertEqual(result["sla_target_minutes"], 15)

    def test_register_duplicate_alert_fails(self):
        """Test that duplicate alert registration fails."""
        self.engine.register_alert("alert_002", "high", "Test Alert")
        result = self.engine.register_alert("alert_002", "high", "Test Alert")
        
        self.assertFalse(result["success"])
        self.assertIn("already registered", result["error"].lower())

    def test_acknowledge_alert(self):
        """Test acknowledging an alert."""
        self.engine.register_alert("alert_003", "high", "Test Alert")
        result = self.engine.acknowledge_alert("alert_003", "analyst_john")

        self.assertTrue(result["success"])
        self.assertEqual(result["status"], "acknowledged")
        self.assertEqual(result["acknowledged_by"], "analyst_john")

    def test_acknowledge_nonexistent_alert_fails(self):
        """Test acknowledging a non-existent alert."""
        result = self.engine.acknowledge_alert("nonexistent", "analyst_john")
        self.assertFalse(result["success"])
        self.assertIn("not found", result["error"].lower())

    def test_manual_escalation(self):
        """Test manual escalation of an alert."""
        self.engine.register_alert("alert_004", "high", "Test Alert")
        result = self.engine.escalate_alert(
            alert_id="alert_004",
            reason="Complex attack requiring senior analyst",
            escalated_by="analyst_john"
        )

        self.assertTrue(result["success"])
        self.assertEqual(result["from_level"], "tier1")
        self.assertEqual(result["to_level"], "tier2")
        self.assertEqual(result["escalated_by"], "analyst_john")

    def test_resolve_alert(self):
        """Test resolving an alert."""
        self.engine.register_alert("alert_005", "medium", "Test Alert")
        result = self.engine.resolve_alert(
            alert_id="alert_005",
            resolution="False positive - legitimate backup activity",
            resolved_by="analyst_jane"
        )

        self.assertTrue(result["success"])
        self.assertEqual(result["status"], "resolved")
        self.assertIsNotNone(result["resolved_at"])

    def test_get_alert_status(self):
        """Test getting alert status and history."""
        self.engine.register_alert("alert_006", "critical", "Test Alert")
        self.engine.acknowledge_alert("alert_006", "analyst_john")
        
        status = self.engine.get_alert_status("alert_006")
        
        self.assertTrue(status["success"])
        self.assertEqual(status["status"], "acknowledged")
        self.assertEqual(status["current_level"], "tier2")
        self.assertIn("sla_metrics", status)
        self.assertIn("escalation_history", status)

    def test_sla_summary_empty(self):
        """Test SLA summary with no alerts."""
        summary = self.engine.get_sla_summary()
        self.assertEqual(summary["total_alerts"], 0)
        self.assertEqual(summary["sla_compliance_rate"], 100.0)

    def test_sla_summary_with_alerts(self):
        """Test SLA summary with processed alerts."""
        self.engine.register_alert("alert_007", "high", "Alert 1")
        self.engine.register_alert("alert_008", "medium", "Alert 2")
        self.engine.acknowledge_alert("alert_007", "analyst")
        self.engine.resolve_alert("alert_007", "Fixed", "analyst")

        summary = self.engine.get_sla_summary()
        
        self.assertEqual(summary["total_alerts"], 2)
        self.assertEqual(summary["alerts_responded"], 1)
        self.assertEqual(summary["alerts_resolved"], 1)
        self.assertGreaterEqual(summary["sla_compliance_rate"], 0)

    def test_custom_escalation_rule(self):
        """Test adding and using custom escalation rules."""
        custom_rule = EscalationRule(
            rule_id="custom_low",
            name="Custom Low Priority",
            severity_threshold="low",
            initial_level=EscalationLevel.TIER1,
            auto_escalate_minutes=120,
            max_escalation_level=EscalationLevel.TIER1,
            notification_channels=[NotificationChannel.EMAIL],
            sla_minutes=120
        )
        
        self.engine.add_escalation_rule(custom_rule)
        retrieved = self.engine.get_rule_for_severity("low")
        
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.rule_id, "custom_low")
        self.assertEqual(retrieved.sla_minutes, 120)

    def test_full_workflow_lifecycle(self):
        """Test complete alert lifecycle: register -> acknowledge -> escalate -> resolve."""
        alert_id = "alert_full_001"
        
        # 1. Register
        reg_result = self.engine.register_alert(
            alert_id, "critical", "Data Breach Detected", "Unauthorized database access"
        )
        self.assertTrue(reg_result["success"])
        
        # 2. Acknowledge
        ack_result = self.engine.acknowledge_alert(alert_id, "soc_analyst_1")
        self.assertTrue(ack_result["success"])
        
        # 3. Escalate
        esc_result = self.engine.escalate_alert(
            alert_id, "Confirmed breach - requires engineering", "soc_analyst_1"
        )
        self.assertTrue(esc_result["success"])
        
        # 4. Resolve
        res_result = self.engine.resolve_alert(
            alert_id, "Contained and remediated - no data exfiltrated", "lead_engineer"
        )
        self.assertTrue(res_result["success"])
        
        # 5. Verify final state
        final_status = self.engine.get_alert_status(alert_id)
        self.assertEqual(final_status["status"], "resolved")
        self.assertGreaterEqual(final_status["escalation_count"], 1)


def run_tests_and_save_results():
    """Run all tests and save results to JSON file."""
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestAlertEscalationWorkflowEngine)
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    results = {
        "test_timestamp": datetime.utcnow().isoformat(),
        "tests_run": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "skipped": len(result.skipped),
        "success": result.wasSuccessful(),
        "failure_details": [str(f[1]) for f in result.failures],
        "error_details": [str(e[1]) for e in result.errors]
    }
    
    with open("test_results_alert_escalation_workflow_engine.json", "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"\n=== TEST RESULTS SAVED ===")
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success: {result.wasSuccessful()}")
    
    return results


if __name__ == "__main__":
    run_tests_and_save_results()
