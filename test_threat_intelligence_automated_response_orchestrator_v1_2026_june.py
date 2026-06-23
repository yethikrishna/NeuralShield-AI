"""
Test suite for Threat Intelligence Automated Response Orchestrator v1.0.0
Dimension A - Feature Expansion (2026 June)

ADD-ONLY IMPLEMENTATION: Tests only, no production code modified
"""

import unittest
import threading
import time
from datetime import datetime

from neural_shield.threat_intelligence_automated_response_orchestrator_v1_2026_june import (
    ThreatSeverity,
    ResponseActionType,
    ActionStatus,
    PolicyMatchMode,
    ThreatContext,
    ResponseAction,
    ResponsePolicy,
    ActionExecutor,
    PolicyEngine,
    ResponseOrchestrator,
    get_orchestrator,
)


class TestThreatSeverityEnum(unittest.TestCase):
    """Test ThreatSeverity enum values and ordering."""

    def test_severity_ordering(self):
        """Test that severity levels are correctly ordered."""
        self.assertTrue(ThreatSeverity.LOW < ThreatSeverity.MEDIUM)
        self.assertTrue(ThreatSeverity.MEDIUM < ThreatSeverity.HIGH)
        self.assertTrue(ThreatSeverity.HIGH < ThreatSeverity.CRITICAL)

    def test_severity_values(self):
        """Test severity integer values."""
        self.assertEqual(ThreatSeverity.LOW.value, 1)
        self.assertEqual(ThreatSeverity.MEDIUM.value, 2)
        self.assertEqual(ThreatSeverity.HIGH.value, 3)
        self.assertEqual(ThreatSeverity.CRITICAL.value, 4)


class TestResponseActionTypeEnum(unittest.TestCase):
    """Test ResponseActionType enum coverage."""

    def test_all_action_types_defined(self):
        """Test that all expected action types are defined."""
        expected_types = {
            "block_ip", "block_domain", "block_user",
            "alert_admin", "alert_security_team",
            "quarantine_resource", "rate_limit", "revoke_token",
            "log_event", "trigger_webhook", "isolate_network",
            "force_password_reset", "enable_mfa", "terminate_session",
            "no_action"
        }
        actual_types = {t.value for t in ResponseActionType}
        self.assertEqual(expected_types, actual_types)


class TestActionStatusEnum(unittest.TestCase):
    """Test ActionStatus enum."""

    def test_status_values(self):
        """Test all status values exist."""
        statuses = {"pending", "executing", "success", "failed", "skipped", "rolled_back"}
        self.assertEqual({s.value for s in ActionStatus}, statuses)


class TestThreatContext(unittest.TestCase):
    """Test ThreatContext data class."""

    def test_threat_context_creation(self):
        """Test creating a threat context with all fields."""
        context = ThreatContext(
            threat_id="t123",
            threat_type="sql_injection",
            severity=ThreatSeverity.HIGH,
            source_ip="192.168.1.1",
            source_domain="evil.com",
            user_id="user_456",
            session_id="sess_789",
            resource_id="res_abc",
            confidence=0.95,
            metadata={"payload": "SELECT * FROM users"}
        )

        self.assertEqual(context.threat_id, "t123")
        self.assertEqual(context.threat_type, "sql_injection")
        self.assertEqual(context.severity, ThreatSeverity.HIGH)
        self.assertEqual(context.source_ip, "192.168.1.1")
        self.assertEqual(context.confidence, 0.95)

    def test_threat_context_defaults(self):
        """Test default values work correctly."""
        context = ThreatContext(
            threat_id="t123",
            threat_type="test",
            severity=ThreatSeverity.LOW
        )

        self.assertIsNone(context.source_ip)
        self.assertEqual(context.confidence, 0.0)
        self.assertEqual(context.metadata, {})
        self.assertIsInstance(context.detection_time, datetime)


class TestResponseAction(unittest.TestCase):
    """Test ResponseAction data class."""

    def test_response_action_creation(self):
        """Test creating a response action."""
        action = ResponseAction(
            action_type=ResponseActionType.BLOCK_IP,
            target="192.168.1.1",
            parameters={"duration": 3600}
        )

        self.assertEqual(action.action_type, ResponseActionType.BLOCK_IP)
        self.assertEqual(action.target, "192.168.1.1")
        self.assertEqual(action.status, ActionStatus.PENDING)
        self.assertIsNotNone(action.action_id)

    def test_response_action_defaults(self):
        """Test default action values."""
        action = ResponseAction()
        self.assertEqual(action.action_type, ResponseActionType.NO_ACTION)
        self.assertEqual(action.status, ActionStatus.PENDING)
        self.assertFalse(action.rollback_supported)


class TestResponsePolicy(unittest.TestCase):
    """Test ResponsePolicy data class."""

    def test_policy_creation(self):
        """Test creating a custom policy."""
        policy = ResponsePolicy(
            name="custom_policy",
            description="Test policy",
            match_mode=PolicyMatchMode.SEVERITY_AT_LEAST,
            match_severity=ThreatSeverity.MEDIUM,
            actions=[ResponseActionType.LOG_EVENT, ResponseActionType.ALERT_ADMIN],
            priority=25
        )

        self.assertEqual(policy.name, "custom_policy")
        self.assertTrue(policy.enabled)
        self.assertEqual(policy.priority, 25)
        self.assertEqual(len(policy.actions), 2)


class TestActionExecutor(unittest.TestCase):
    """Test ActionExecutor class."""

    def test_executor_initialization(self):
        """Test executor initializes with default handlers."""
        executor = ActionExecutor()
        # Should not raise any errors

    def test_default_handler_execution(self):
        """Test default handler executes successfully."""
        executor = ActionExecutor()
        action = ResponseAction(
            action_type=ResponseActionType.BLOCK_IP,
            target="192.168.1.1"
        )

        result = executor.execute(action)
        self.assertEqual(result.status, ActionStatus.SUCCESS)
        self.assertIsNotNone(result.executed_at)
        self.assertIsNotNone(result.completed_at)

    def test_custom_handler_registration(self):
        """Test registering and using a custom handler."""
        executor = ActionExecutor()
        handler_called = []

        def custom_handler(target, params):
            handler_called.append((target, params))
            return True, {"custom": "result"}, None

        executor.register_handler(ResponseActionType.BLOCK_IP, custom_handler)

        action = ResponseAction(
            action_type=ResponseActionType.BLOCK_IP,
            target="10.0.0.1",
            parameters={"test": "value"}
        )

        executor.execute(action)
        self.assertEqual(len(handler_called), 1)
        self.assertEqual(handler_called[0][0], "10.0.0.1")

    def test_failed_action_execution(self):
        """Test handler that returns failure."""
        executor = ActionExecutor()

        def failing_handler(target, params):
            return False, {}, "Test failure message"

        executor.register_handler(ResponseActionType.BLOCK_IP, failing_handler)

        action = ResponseAction(action_type=ResponseActionType.BLOCK_IP)
        result = executor.execute(action)

        self.assertEqual(result.status, ActionStatus.FAILED)
        self.assertEqual(result.error_message, "Test failure message")

    def test_exception_handling(self):
        """Test exceptions during execution are caught."""
        executor = ActionExecutor()

        def exception_handler(target, params):
            raise RuntimeError("Something went wrong")

        executor.register_handler(ResponseActionType.BLOCK_IP, exception_handler)

        action = ResponseAction(action_type=ResponseActionType.BLOCK_IP)
        result = executor.execute(action)

        self.assertEqual(result.status, ActionStatus.FAILED)
        self.assertIn("Something went wrong", result.error_message or "")

    def test_rollback_execution(self):
        """Test rollback functionality."""
        executor = ActionExecutor()
        rollback_called = []

        def rollback_handler(target, params, result):
            rollback_called.append(True)
            return True

        executor.register_handler(
            ResponseActionType.BLOCK_IP,
            lambda t, p: (True, {}, None),
            rollback_handler
        )

        action = ResponseAction(
            action_type=ResponseActionType.BLOCK_IP,
            rollback_supported=True
        )
        executor.execute(action)

        success = executor.rollback(action)
        self.assertTrue(success)
        self.assertEqual(len(rollback_called), 1)
        self.assertEqual(action.status, ActionStatus.ROLLED_BACK)

    def test_rollback_not_supported(self):
        """Test rollback fails when not supported."""
        executor = ActionExecutor()
        action = ResponseAction(rollback_supported=False)
        success = executor.rollback(action)
        self.assertFalse(success)


class TestPolicyEngine(unittest.TestCase):
    """Test PolicyEngine class."""

    def test_default_policies_exist(self):
        """Test that default policies are automatically added."""
        engine = PolicyEngine()
        policies = engine.get_all_policies()
        self.assertGreater(len(policies), 0)

        policy_names = {p.name for p in policies}
        self.assertIn("critical_threat_response", policy_names)
        self.assertIn("high_threat_response", policy_names)
        self.assertIn("medium_threat_response", policy_names)

    def test_add_and_get_policy(self):
        """Test adding and retrieving a policy."""
        engine = PolicyEngine()
        policy = ResponsePolicy(name="test_policy", actions=[ResponseActionType.LOG_EVENT])

        policy_id = engine.add_policy(policy)
        retrieved = engine.get_policy(policy_id)

        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.name, "test_policy")

    def test_remove_policy(self):
        """Test removing a policy."""
        engine = PolicyEngine()
        policy = ResponsePolicy(name="to_remove")
        policy_id = engine.add_policy(policy)

        result = engine.remove_policy(policy_id)
        self.assertTrue(result)

        retrieved = engine.get_policy(policy_id)
        self.assertIsNone(retrieved)

    def test_exact_severity_matching(self):
        """Test exact severity matching mode."""
        engine = PolicyEngine()

        threat = ThreatContext(
            threat_id="t1",
            threat_type="test",
            severity=ThreatSeverity.CRITICAL
        )

        matches = engine.match_threat(threat)
        self.assertGreater(len(matches), 0)

        # Critical policy should match critical threat
        critical_policy = next((p for p, s in matches if p.name == "critical_threat_response"), None)
        self.assertIsNotNone(critical_policy)

    def test_policy_priority_sorting(self):
        """Test policies are sorted by priority."""
        engine = PolicyEngine()
        policies = engine.get_all_policies()

        # Critical should be highest priority (100)
        self.assertEqual(policies[0].name, "critical_threat_response")
        self.assertEqual(policies[1].name, "high_threat_response")
        self.assertEqual(policies[2].name, "medium_threat_response")

    def test_threat_type_filtering(self):
        """Test threat type specific matching."""
        engine = PolicyEngine()

        # Add policy that only matches SQL injection
        sql_policy = ResponsePolicy(
            name="sql_only",
            match_mode=PolicyMatchMode.ANY,
            match_threat_types={"sql_injection"},
            actions=[ResponseActionType.BLOCK_IP],
            priority=200
        )
        engine.add_policy(sql_policy)

        # SQL injection threat should match
        sql_threat = ThreatContext(
            threat_id="t1",
            threat_type="sql_injection",
            severity=ThreatSeverity.HIGH
        )
        matches = engine.match_threat(sql_threat)
        self.assertEqual(matches[0][0].name, "sql_only")

        # XSS threat should NOT match sql_only
        xss_threat = ThreatContext(
            threat_id="t2",
            threat_type="xss",
            severity=ThreatSeverity.HIGH
        )
        matches = engine.match_threat(xss_threat)
        match_names = {p.name for p, s in matches}
        self.assertNotIn("sql_only", match_names)

    def test_action_generation(self):
        """Test generating actions from policy."""
        engine = PolicyEngine()
        policy = engine.get_all_policies()[0]

        threat = ThreatContext(
            threat_id="t1",
            threat_type="test",
            severity=ThreatSeverity.CRITICAL,
            source_ip="192.168.1.1"
        )

        actions = engine.generate_actions(threat, policy)
        self.assertGreater(len(actions), 0)

    def test_target_inference(self):
        """Test target inference based on action type."""
        engine = PolicyEngine()
        policy = ResponsePolicy(
            name="test",
            actions=[ResponseActionType.BLOCK_IP]
        )

        threat = ThreatContext(
            threat_id="t1",
            threat_type="test",
            severity=ThreatSeverity.HIGH,
            source_ip="10.0.0.1"
        )

        actions = engine.generate_actions(threat, policy)
        self.assertEqual(actions[0].target, "10.0.0.1")

    def test_cooldown_mechanism(self):
        """Test cooldown prevents repeated execution."""
        engine = PolicyEngine()
        policy = engine.get_all_policies()[0]

        threat = ThreatContext(
            threat_id="t1",
            threat_type="test",
            severity=ThreatSeverity.CRITICAL
        )

        # First should pass
        first = engine.check_cooldown(policy, threat)
        self.assertTrue(first)

        # Second should be in cooldown
        second = engine.check_cooldown(policy, threat)
        self.assertFalse(second)


class TestResponseOrchestrator(unittest.TestCase):
    """Test ResponseOrchestrator main class."""

    def test_orchestrator_initialization(self):
        """Test orchestrator initializes correctly."""
        orchestrator = ResponseOrchestrator()
        self.assertIsNotNone(orchestrator.policy_engine)
        self.assertIsNotNone(orchestrator.action_executor)
        self.assertTrue(orchestrator._enabled)
        self.assertFalse(orchestrator._dry_run)

    def test_process_threat_basic(self):
        """Test basic threat processing."""
        orchestrator = ResponseOrchestrator()

        threat = ThreatContext(
            threat_id="t1",
            threat_type="intrusion",
            severity=ThreatSeverity.CRITICAL,
            source_ip="192.168.1.100"
        )

        result = orchestrator.process_threat(threat)
        self.assertEqual(result["status"], "completed")
        self.assertGreater(result["successful_actions"], 0)

    def test_dry_run_mode(self):
        """Test dry run mode doesn't execute actions."""
        orchestrator = ResponseOrchestrator()
        orchestrator.set_dry_run(True)

        threat = ThreatContext(
            threat_id="t1",
            threat_type="test",
            severity=ThreatSeverity.HIGH
        )

        result = orchestrator.process_threat(threat)
        self.assertEqual(result["status"], "dry_run")
        self.assertEqual(result["actions_executed"], 0)
        self.assertIn("actions_would_execute", result)

    def test_disabled_orchestrator(self):
        """Test disabled orchestrator does nothing."""
        orchestrator = ResponseOrchestrator()
        orchestrator.set_enabled(False)

        threat = ThreatContext(
            threat_id="t1",
            threat_type="test",
            severity=ThreatSeverity.CRITICAL
        )

        result = orchestrator.process_threat(threat)
        self.assertEqual(result["status"], "disabled")

    def test_audit_logging(self):
        """Test actions are logged to audit trail."""
        orchestrator = ResponseOrchestrator()

        threat = ThreatContext(
            threat_id="t1",
            threat_type="test",
            severity=ThreatSeverity.HIGH
        )

        initial_count = len(orchestrator.get_audit_log())
        orchestrator.process_threat(threat)
        final_count = len(orchestrator.get_audit_log())

        self.assertGreater(final_count, initial_count)

    def test_statistics_tracking(self):
        """Test statistics are correctly tracked."""
        orchestrator = ResponseOrchestrator()

        threat = ThreatContext(
            threat_id="t1",
            threat_type="test",
            severity=ThreatSeverity.HIGH
        )

        orchestrator.process_threat(threat)
        stats = orchestrator.get_statistics()

        self.assertIn("total_actions_executed", stats)
        self.assertIn("by_status", stats)
        self.assertIn("policies_configured", stats)
        self.assertGreater(stats["total_actions_executed"], 0)

    def test_global_singleton(self):
        """Test global singleton works correctly."""
        orchestrator1 = get_orchestrator()
        orchestrator2 = get_orchestrator()

        self.assertIs(orchestrator1, orchestrator2)

    def test_thread_safety(self):
        """Test orchestrator works correctly under concurrent access."""
        orchestrator = ResponseOrchestrator()
        errors = []

        def worker(worker_id):
            try:
                for i in range(10):
                    threat = ThreatContext(
                        threat_id=f"t_{worker_id}_{i}",
                        threat_type="test",
                        severity=ThreatSeverity.MEDIUM
                    )
                    orchestrator.process_threat(threat)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(errors), 0)


class TestIntegrationScenarios(unittest.TestCase):
    """Integration tests for realistic scenarios."""

    def test_critical_attack_response(self):
        """Test full response to a critical attack."""
        orchestrator = ResponseOrchestrator()

        # Simulate detected SQL injection attack
        threat = ThreatContext(
            threat_id="attack_001",
            threat_type="sql_injection",
            severity=ThreatSeverity.CRITICAL,
            source_ip="203.0.113.42",
            user_id="attacker_user",
            session_id="malicious_session",
            confidence=0.99,
            metadata={"payload": "' OR 1=1 --"}
        )

        result = orchestrator.process_threat(threat)

        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["policy"], "critical_threat_response")
        self.assertGreater(result["match_score"], 0)

        # Verify actions were executed
        action_types = {r["type"] for r in result["action_results"]}
        self.assertIn("block_ip", action_types)
        self.assertIn("terminate_session", action_types)
        self.assertIn("alert_security_team", action_types)

    def test_policy_based_custom_response(self):
        """Test custom policy for specific threat types."""
        orchestrator = ResponseOrchestrator()

        # Add custom ransomware policy
        ransomware_policy = ResponsePolicy(
            name="ransomware_response",
            description="Special handling for ransomware",
            match_mode=PolicyMatchMode.SEVERITY_AT_LEAST,
            match_severity=ThreatSeverity.HIGH,
            match_threat_types={"ransomware", "crypto_locker"},
            actions=[
                ResponseActionType.ISOLATE_NETWORK,
                ResponseActionType.QUARANTINE_RESOURCE,
                ResponseActionType.ALERT_SECURITY_TEAM
            ],
            priority=200
        )
        orchestrator.policy_engine.add_policy(ransomware_policy)

        # Process ransomware threat
        threat = ThreatContext(
            threat_id="rw_001",
            threat_type="ransomware",
            severity=ThreatSeverity.CRITICAL,
            resource_id="fileserver_01"
        )

        result = orchestrator.process_threat(threat)

        self.assertEqual(result["policy"], "ransomware_response")
        action_types = {r["type"] for r in result["action_results"]}
        self.assertIn("isolate_network", action_types)
        self.assertIn("quarantine_resource", action_types)


if __name__ == "__main__":
    unittest.main()
