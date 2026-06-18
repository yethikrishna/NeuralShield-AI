#!/usr/bin/env python3
"""
Test suite for Threat Intelligence SOAR Integration Engine
Production-grade automated tests
"""

import sys
import json
import unittest
from datetime import datetime, timezone

sys.path.insert(0, '/home/user/autonomous-developer/NeuralShield-AI')

from neural_shield.threat_intelligence_soar_integration_engine_2026_june import (
    SOARIntegrationEngine,
    SOARPlatformType,
    AlertSeverity,
    AlertStatus,
    ResponseActionStatus,
    NormalizedAlert,
    SOARCase,
    ResponseAction,
)


class TestSOARIntegrationEngine(unittest.TestCase):
    """Test suite for SOAR Integration Engine."""

    def setUp(self):
        """Set up test fixtures."""
        self.engine = SOARIntegrationEngine()

    def test_engine_initialization(self):
        """Test engine initializes correctly."""
        self.assertIsNotNone(self.engine)
        self.assertEqual(len(self.engine.connectors), 0)
        self.assertEqual(len(self.engine.alerts), 0)
        self.assertEqual(len(self.engine.cases), 0)
        print("✓ Engine initialization test passed")

    def test_register_connector_success(self):
        """Test successful SOAR connector registration."""
        result = self.engine.register_connector(
            connector_id="test_phantom",
            platform_type=SOARPlatformType.SPLUNK_PHANTOM,
            config={
                "base_url": "https://soar.example.com",
                "api_key": "test_api_key_12345",
            },
        )
        self.assertTrue(result)
        self.assertIn("test_phantom", self.engine.connectors)
        print("✓ Connector registration test passed")

    def test_register_connector_duplicate(self):
        """Test duplicate connector registration fails."""
        self.engine.register_connector(
            "test_conn",
            SOARPlatformType.SPLUNK_PHANTOM,
            {"base_url": "https://test.com", "api_key": "key"},
        )
        result = self.engine.register_connector(
            "test_conn",
            SOARPlatformType.SPLUNK_PHANTOM,
            {"base_url": "https://test.com", "api_key": "key2"},
        )
        self.assertFalse(result)
        print("✓ Duplicate connector prevention test passed")

    def test_register_connector_invalid_config(self):
        """Test connector registration fails with invalid config."""
        result = self.engine.register_connector(
            "invalid_conn",
            SOARPlatformType.SPLUNK_PHANTOM,
            {"base_url": "", "api_key": ""},
        )
        self.assertFalse(result)
        print("✓ Invalid connector config rejection test passed")

    def test_remove_connector(self):
        """Test connector removal."""
        self.engine.register_connector(
            "conn_to_remove",
            SOARPlatformType.PALO_ALTO_XSOAR,
            {"base_url": "https://xsoar.com", "api_key": "key"},
        )
        self.assertIn("conn_to_remove", self.engine.connectors)
        
        result = self.engine.remove_connector("conn_to_remove")
        self.assertTrue(result)
        self.assertNotIn("conn_to_remove", self.engine.connectors)
        print("✓ Connector removal test passed")

    def test_normalize_alert_basic(self):
        """Test basic alert normalization."""
        raw_alert = {
            "title": "Suspicious Login Attempt",
            "description": "Multiple failed login attempts from unknown IP",
            "severity": "high",
            "mitre_techniques": ["T1078"],
            "iocs": {"ip": "192.168.1.100", "hash": "abc123"},
        }
        
        normalized = self.engine.normalize_alert(raw_alert, source="test")
        
        self.assertIsInstance(normalized, NormalizedAlert)
        self.assertTrue(normalized.alert_id.startswith("alert_"))
        self.assertEqual(normalized.title, "Suspicious Login Attempt")
        self.assertEqual(normalized.severity, AlertSeverity.HIGH)
        self.assertEqual(normalized.source, "test")
        self.assertEqual(len(normalized.iocs), 2)
        self.assertIn(normalized.alert_id, self.engine.alerts)
        print("✓ Alert normalization test passed")

    def test_normalize_alert_severity_mapping(self):
        """Test severity mapping works for numeric and string values."""
        test_cases = [
            ({"severity": 1}, AlertSeverity.INFORMATIONAL),
            ({"severity": 5}, AlertSeverity.CRITICAL),
            ({"severity": "low"}, AlertSeverity.LOW),
            ({"severity": "unknown"}, AlertSeverity.MEDIUM),  # default
            ({}, AlertSeverity.MEDIUM),  # default
        ]
        
        for raw_input, expected_severity in test_cases:
            normalized = self.engine.normalize_alert(raw_input)
            self.assertEqual(normalized.severity, expected_severity)
        print("✓ Severity mapping test passed")

    def test_create_case_from_alerts(self):
        """Test case creation from multiple alerts."""
        # Create some alerts
        alert1 = self.engine.normalize_alert({
            "title": "Alert 1",
            "severity": "medium",
        })
        alert2 = self.engine.normalize_alert({
            "title": "Alert 2",
            "severity": "high",
        })
        
        case = self.engine.create_case_from_alerts(
            alert_ids=[alert1.alert_id, alert2.alert_id],
            title="Test Consolidated Case",
            auto_escalate=False,
        )
        
        self.assertIsNotNone(case)
        self.assertTrue(case.case_id.startswith("case_"))
        self.assertEqual(len(case.alerts), 2)
        self.assertEqual(case.severity, AlertSeverity.HIGH)  # highest severity
        self.assertIn(case.case_id, self.engine.cases)
        print("✓ Case creation from alerts test passed")

    def test_create_case_invalid_alerts(self):
        """Test case creation fails with invalid alert IDs."""
        case = self.engine.create_case_from_alerts(
            alert_ids=["invalid_id_123"],
            auto_escalate=False,
        )
        self.assertIsNone(case)
        print("✓ Invalid alert ID rejection test passed")

    def test_add_response_action(self):
        """Test adding response actions to a case."""
        # Create alert and case
        alert = self.engine.normalize_alert({"title": "Test Alert"})
        case = self.engine.create_case_from_alerts([alert.alert_id], auto_escalate=False)
        
        # Add response action
        action_id = self.engine.add_response_action(
            case_id=case.case_id,
            action_name="block_ip",
            parameters={"ip_address": "10.0.0.1", "duration_minutes": 30},
        )
        
        self.assertIsNotNone(action_id)
        self.assertTrue(action_id.startswith("action_"))
        self.assertEqual(len(case.actions), 1)
        self.assertEqual(case.actions[0].name, "block_ip")
        print("✓ Add response action test passed")

    def test_add_response_action_invalid_case(self):
        """Test adding action to invalid case fails."""
        action_id = self.engine.add_response_action(
            case_id="invalid_case_id",
            action_name="block_ip",
        )
        self.assertIsNone(action_id)
        print("✓ Invalid case ID rejection test passed")

    def test_add_response_action_invalid_action(self):
        """Test adding unknown action fails."""
        alert = self.engine.normalize_alert({"title": "Test"})
        case = self.engine.create_case_from_alerts([alert.alert_id], auto_escalate=False)
        
        action_id = self.engine.add_response_action(
            case_id=case.case_id,
            action_name="unknown_action_xyz",
        )
        self.assertIsNone(action_id)
        print("✓ Unknown action rejection test passed")

    def test_execute_response_actions(self):
        """Test executing response actions."""
        alert = self.engine.normalize_alert({"title": "Test Alert"})
        case = self.engine.create_case_from_alerts([alert.alert_id], auto_escalate=False)
        
        self.engine.add_response_action(case.case_id, "block_ip", {"ip_address": "1.2.3.4"})
        self.engine.add_response_action(case.case_id, "notify_analyst", {"analyst_email": "sec@example.com"})
        
        result = self.engine.execute_response_actions(case.case_id)
        
        self.assertTrue(result["success"])
        self.assertEqual(result["total_actions"], 2)
        self.assertEqual(result["successful"], 2)
        self.assertEqual(result["failed"], 0)
        
        # Verify actions are marked completed
        for action in case.actions:
            self.assertEqual(action.status, ResponseActionStatus.COMPLETED)
            self.assertIsNotNone(action.result)
        print("✓ Response action execution test passed")

    def test_available_actions(self):
        """Test available actions listing."""
        actions = self.engine.get_available_actions()
        expected_actions = [
            "block_ip", "isolate_host", "quarantine_file", "disable_user",
            "reset_password", "collect_forensics", "notify_analyst", "escalate_case",
        ]
        for action in expected_actions:
            self.assertIn(action, actions)
        self.assertEqual(len(actions), 8)
        print("✓ Available actions listing test passed")

    def test_get_case_summary(self):
        """Test case summary generation."""
        alert = self.engine.normalize_alert({"title": "Test Alert"})
        case = self.engine.create_case_from_alerts([alert.alert_id], auto_escalate=False)
        
        summary = self.engine.get_case_summary(case.case_id)
        
        self.assertIsNotNone(summary)
        self.assertEqual(summary["case_id"], case.case_id)
        self.assertEqual(summary["alert_count"], 1)
        self.assertEqual(summary["action_count"], 0)
        self.assertEqual(summary["severity"], "medium")
        print("✓ Case summary test passed")

    def test_get_case_summary_invalid(self):
        """Test summary for invalid case returns None."""
        summary = self.engine.get_case_summary("nonexistent_case")
        self.assertIsNone(summary)
        print("✓ Invalid case summary test passed")

    def test_connector_status(self):
        """Test connector status reporting."""
        self.engine.register_connector(
            "status_test",
            SOARPlatformType.MICROSOFT_SENTINEL,
            {"base_url": "https://sentinel.com", "api_key": "key"},
        )
        
        status = self.engine.get_connector_status()
        self.assertIn("status_test", status)
        self.assertTrue(status["status_test"]["connected"])
        print("✓ Connector status test passed")

    def test_webhook_signature_verification(self):
        """Test webhook signature verification."""
        payload = b'{"test": "data"}'
        secret = "my_webhook_secret"
        
        import hmac
        import hashlib
        valid_signature = hmac.new(
            secret.encode(), payload, hashlib.sha256
        ).hexdigest()
        
        # Valid signature
        result = self.engine.verify_webhook_signature(payload, valid_signature, secret)
        self.assertTrue(result)
        
        # Invalid signature
        result = self.engine.verify_webhook_signature(payload, "wrong_signature", secret)
        self.assertFalse(result)
        print("✓ Webhook signature verification test passed")

    def test_register_custom_action(self):
        """Test custom action registration."""
        def custom_action(params):
            return {"custom": True, "params": params}
        
        result = self.engine.register_custom_action("custom_test_action", custom_action)
        self.assertTrue(result)
        self.assertIn("custom_test_action", self.engine.get_available_actions())
        
        # Cannot register duplicate
        result2 = self.engine.register_custom_action("custom_test_action", lambda p: {})
        self.assertFalse(result2)
        print("✓ Custom action registration test passed")

    def test_response_action_implementations(self):
        """Test all built-in response action implementations."""
        test_cases = [
            ("block_ip", {"ip_address": "1.2.3.4"}, "firewall_rule_id"),
            ("isolate_host", {"host_id": "host_123"}, "isolation_id"),
            ("quarantine_file", {"file_hash": "abc123"}, "quarantine_id"),
            ("disable_user", {"username": "jdoe"}, "ticket_id"),
            ("reset_password", {"username": "jdoe"}, "notification_sent"),
            ("collect_forensics", {"endpoint_id": "ep_123"}, "evidence_id"),
            ("notify_analyst", {"analyst_email": "sec@test.com"}, "notification_id"),
            ("escalate_case", {"tier": 3}, "escalation_id"),
        ]
        
        for action_name, params, expected_key in test_cases:
            handler = self.engine.response_action_registry[action_name]
            result = handler(params)
            self.assertTrue(result["success"])
            self.assertIn(expected_key, result)
        print("✓ All response action implementations test passed")

    def test_full_integration_workflow(self):
        """Test complete end-to-end workflow."""
        # 1. Register SOAR connector
        self.engine.register_connector(
            "main_soar",
            SOARPlatformType.SPLUNK_PHANTOM,
            {"base_url": "https://phantom.corp.com", "api_key": "prod_key_abc"},
        )
        
        # 2. Normalize multiple alerts
        alerts = []
        for i in range(3):
            alert = self.engine.normalize_alert({
                "title": f"Detection Alert {i+1}",
                "description": f"Suspicious activity detected on host {i+1}",
                "severity": "high",
                "mitre_techniques": ["T1059", "T1027"],
            })
            alerts.append(alert.alert_id)
        
        # 3. Create consolidated case
        case = self.engine.create_case_from_alerts(
            alert_ids=alerts,
            title="Potential Lateral Movement Campaign",
        )
        
        # 4. Add response actions
        self.engine.add_response_action(case.case_id, "block_ip", {"ip_address": "10.20.30.40"})
        self.engine.add_response_action(case.case_id, "isolate_host", {"host_id": "compromised-01"})
        self.engine.add_response_action(case.case_id, "notify_analyst")
        
        # 5. Execute actions
        exec_result = self.engine.execute_response_actions(case.case_id)
        
        # 6. Verify results
        self.assertTrue(exec_result["success"])
        self.assertEqual(exec_result["total_actions"], 3)
        self.assertEqual(exec_result["successful"], 3)
        
        summary = self.engine.get_case_summary(case.case_id)
        self.assertEqual(summary["actions_completed"], 3)
        
        print("✓ Full integration workflow test passed")


def run_tests():
    """Run all tests and generate report."""
    print("=" * 70)
    print("NeuralShield AI - SOAR Integration Engine Test Suite")
    print("=" * 70)
    print(f"Test started: {datetime.now(timezone.utc).isoformat()}")
    print()
    
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestSOARIntegrationEngine)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print()
    print("=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success: {result.testsRun - len(result.failures) - len(result.errors)} / {result.testsRun}")
    print()
    
    if result.wasSuccessful():
        print("✓ ALL TESTS PASSED - Production ready!")
        return True
    else:
        print("✗ SOME TESTS FAILED")
        return False


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
