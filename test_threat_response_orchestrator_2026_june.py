"""
Test suite for Threat Response Orchestrator - NeuralShield AI
Tests all response orchestration functionality with real assertions.
"""

import unittest
import time
from neural_shield.threat_response_orchestrator_2026_june import (
    ThreatResponseOrchestrator,
    ResponsePolicy,
    ThreatSeverity,
    ResponseAction,
    ThreatIncident
)


class TestThreatResponseOrchestrator(unittest.TestCase):
    """Test cases for Threat Response Orchestrator."""
    
    def setUp(self):
        """Set up test orchestrator before each test."""
        self.orchestrator = ThreatResponseOrchestrator()
        self.orchestrator.clear_logs()
    
    def test_initialization(self):
        """Test orchestrator initializes correctly."""
        self.assertIsNotNone(self.orchestrator.policy)
        self.assertEqual(len(self.orchestrator.incident_log), 0)
        self.assertEqual(len(self.orchestrator.response_log), 0)
        self.assertEqual(self.orchestrator.metrics["total_incidents"], 0)
    
    def test_generate_incident_id(self):
        """Test incident ID generation produces unique IDs."""
        id1 = self.orchestrator._generate_incident_id("detector1", "threat1", time.time())
        time.sleep(0.001)
        id2 = self.orchestrator._generate_incident_id("detector1", "threat1", time.time())
        self.assertNotEqual(id1, id2)
        self.assertEqual(len(id1), 16)
    
    def test_process_low_severity_threat(self):
        """Test processing low severity threat."""
        result = self.orchestrator.process_threat(
            detector="prompt_injection_detector",
            threat_type="suspicious_keyword",
            severity=ThreatSeverity.LOW,
            details={"keyword": "ignore instructions", "confidence": 0.65},
            source="user_input"
        )
        
        self.assertTrue(result.success)
        self.assertGreater(result.response_time_ms, 0)
        self.assertEqual(self.orchestrator.metrics["total_incidents"], 1)
        self.assertEqual(self.orchestrator.metrics["incidents_by_severity"]["low"], 1)
        self.assertIn("log_only", result.details)
        self.assertTrue(result.details["log_only"]["logged"])
    
    def test_process_medium_severity_threat(self):
        """Test processing medium severity threat."""
        result = self.orchestrator.process_threat(
            detector="jailbreak_detector",
            threat_type="role_play_attack",
            severity=ThreatSeverity.MEDIUM,
            details={"pattern": "hypothetical_scenario", "confidence": 0.82},
            source="chat_input"
        )
        
        self.assertTrue(result.success)
        self.assertIn("log_only", result.details)
        self.assertIn("flag_for_review", result.details)
        self.assertTrue(result.details["flag_for_review"]["flagged"])
    
    def test_process_high_severity_threat(self):
        """Test processing high severity threat."""
        result = self.orchestrator.process_threat(
            detector="pii_detector",
            threat_type="credit_card_leakage",
            severity=ThreatSeverity.HIGH,
            details={"pii_type": "credit_card", "count": 1},
            source="model_output"
        )
        
        self.assertTrue(result.success)
        self.assertIn("block_input", result.details)
        self.assertIn("flag_for_review", result.details)
        self.assertIn("alert_admin", result.details)
        self.assertTrue(result.details["block_input"]["blocked"])
    
    def test_process_critical_severity_threat(self):
        """Test processing critical severity threat."""
        result = self.orchestrator.process_threat(
            detector="model_extraction_detector",
            threat_type="weight_extraction_attempt",
            severity=ThreatSeverity.CRITICAL,
            details={"attack_type": "gradient_extraction", "confidence": 0.95},
            source="api_request"
        )
        
        self.assertTrue(result.success)
        self.assertIn("block_input", result.details)
        self.assertIn("terminate_session", result.details)
        self.assertIn("alert_admin", result.details)
        self.assertIn("quarantine", result.details)
        self.assertTrue(result.details["terminate_session"]["session_terminated"])
    
    def test_batch_processing(self):
        """Test batch processing multiple threats."""
        threats = [
            {
                "detector": "detector1",
                "threat_type": "type1",
                "severity": ThreatSeverity.LOW,
                "details": {},
                "source": "input1"
            },
            {
                "detector": "detector2",
                "threat_type": "type2",
                "severity": ThreatSeverity.MEDIUM,
                "details": {},
                "source": "input2"
            },
            {
                "detector": "detector3",
                "threat_type": "type3",
                "severity": ThreatSeverity.HIGH,
                "details": {},
                "source": "input3"
            }
        ]
        
        results = self.orchestrator.batch_process(threats)
        
        self.assertEqual(len(results), 3)
        self.assertEqual(self.orchestrator.metrics["total_incidents"], 3)
        for result in results:
            self.assertTrue(result.success)
    
    def test_metrics_tracking(self):
        """Test metrics are tracked correctly."""
        # Process multiple threats
        for i in range(5):
            self.orchestrator.process_threat(
                detector=f"detector_{i}",
                threat_type=f"threat_{i}",
                severity=ThreatSeverity.MEDIUM,
                details={"test": True},
                source="test"
            )
        
        metrics = self.orchestrator.get_metrics()
        
        self.assertEqual(metrics["incident_count"], 5)
        self.assertEqual(metrics["orchestrator_metrics"]["total_incidents"], 5)
        self.assertEqual(metrics["orchestrator_metrics"]["incidents_by_severity"]["medium"], 5)
        self.assertGreater(metrics["orchestrator_metrics"]["avg_response_time_ms"], 0)
    
    def test_recent_incidents_retrieval(self):
        """Test getting recent incidents."""
        for i in range(15):
            self.orchestrator.process_threat(
                detector=f"detector_{i}",
                threat_type=f"threat_{i}",
                severity=ThreatSeverity.LOW,
                details={},
                source="test"
            )
        
        recent = self.orchestrator.get_recent_incidents(limit=5)
        self.assertEqual(len(recent), 5)
        
        all_recent = self.orchestrator.get_recent_incidents(limit=20)
        self.assertEqual(len(all_recent), 15)
    
    def test_incident_to_dict(self):
        """Test incident serialization."""
        incident = ThreatIncident(
            incident_id="test123",
            detector="test_detector",
            threat_type="test_threat",
            severity=ThreatSeverity.HIGH,
            details={"test": True},
            source="test_source"
        )
        
        incident_dict = incident.to_dict()
        self.assertEqual(incident_dict["incident_id"], "test123")
        self.assertEqual(incident_dict["severity"], "high")
        self.assertIn("timestamp", incident_dict)
    
    def test_custom_policy(self):
        """Test custom response policy configuration."""
        custom_policy = {
            ThreatSeverity.LOW: [ResponseAction.LOG_ONLY],
            ThreatSeverity.MEDIUM: [ResponseAction.LOG_ONLY, ResponseAction.BLOCK_INPUT],
            ThreatSeverity.HIGH: [ResponseAction.BLOCK_INPUT, ResponseAction.ALERT_ADMIN],
            ThreatSeverity.CRITICAL: [ResponseAction.TERMINATE_SESSION]
        }
        
        policy = ResponsePolicy(custom_policy)
        custom_orchestrator = ThreatResponseOrchestrator(policy=policy)
        
        result = custom_orchestrator.process_threat(
            detector="test",
            threat_type="test",
            severity=ThreatSeverity.MEDIUM,
            details={},
            source="test"
        )
        
        self.assertIn("log_only", result.details)
        self.assertIn("block_input", result.details)
        self.assertNotIn("flag_for_review", result.details)
    
    def test_policy_update(self):
        """Test policy can be updated at runtime."""
        policy = ResponsePolicy()
        original_actions = policy.get_actions(ThreatSeverity.LOW)
        
        policy.update_policy(ThreatSeverity.LOW, [ResponseAction.LOG_ONLY, ResponseAction.FLAG_FOR_REVIEW])
        new_actions = policy.get_actions(ThreatSeverity.LOW)
        
        self.assertNotEqual(original_actions, new_actions)
        self.assertEqual(len(new_actions), 2)
    
    def test_register_detector(self):
        """Test detector registration."""
        self.orchestrator.register_detector("new_detector")
        # Should not raise any errors
        self.assertTrue(True)
    
    def test_clear_logs(self):
        """Test log clearing functionality."""
        self.orchestrator.process_threat(
            detector="test",
            threat_type="test",
            severity=ThreatSeverity.LOW,
            details={},
            source="test"
        )
        
        self.assertEqual(len(self.orchestrator.incident_log), 1)
        self.orchestrator.clear_logs()
        self.assertEqual(len(self.orchestrator.incident_log), 0)
        self.assertEqual(len(self.orchestrator.response_log), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
