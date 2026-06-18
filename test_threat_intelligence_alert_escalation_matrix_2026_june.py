"""
Test suite for Threat Intelligence Alert Escalation Matrix Manager
Production-grade unit and integration tests
"""

import pytest
import asyncio
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock

from neural_shield.threat_intelligence_alert_escalation_matrix_2026_june import (
    AlertSeverity,
    EscalationStatus,
    SLAPolicy,
    Responder,
    EscalationStep,
    AlertEscalationRecord,
    EscalationMatrix,
    AlertEscalationManager
)


class TestAlertSeverity:
    """Test AlertSeverity enum"""
    
    def test_severity_values(self):
        assert AlertSeverity.CRITICAL.value == "CRITICAL"
        assert AlertSeverity.HIGH.value == "HIGH"
        assert AlertSeverity.MEDIUM.value == "MEDIUM"
        assert AlertSeverity.LOW.value == "LOW"
        assert AlertSeverity.INFO.value == "INFO"


class TestEscalationStatus:
    """Test EscalationStatus enum"""
    
    def test_status_values(self):
        assert EscalationStatus.PENDING.value == "PENDING"
        assert EscalationStatus.ACKNOWLEDGED.value == "ACKNOWLEDGED"
        assert EscalationStatus.ESCALATED.value == "ESCALATED"
        assert EscalationStatus.RESOLVED.value == "RESOLVED"
        assert EscalationStatus.AUTO_ESCALATED.value == "AUTO_ESCALATED"


class TestSLAPolicy:
    """Test SLAPolicy dataclass"""
    
    def test_sla_policy_creation(self):
        policy = SLAPolicy(
            severity=AlertSeverity.CRITICAL,
            acknowledge_timeout_minutes=5,
            first_response_timeout_minutes=15,
            resolution_timeout_minutes=240,
            auto_escalate_after_minutes=10
        )
        assert policy.severity == AlertSeverity.CRITICAL
        assert policy.acknowledge_timeout_minutes == 5
    
    def test_get_timeout_seconds(self):
        policy = SLAPolicy(
            severity=AlertSeverity.HIGH,
            acknowledge_timeout_minutes=15,
            first_response_timeout_minutes=30,
            resolution_timeout_minutes=480,
            auto_escalate_after_minutes=30
        )
        assert policy.get_timeout_seconds("acknowledge") == 15 * 60
        assert policy.get_timeout_seconds("first_response") == 30 * 60
        assert policy.get_timeout_seconds("resolution") == 480 * 60
        assert policy.get_timeout_seconds("auto_escalate") == 30 * 60
        assert policy.get_timeout_seconds("unknown") == 3600  # default


class TestResponder:
    """Test Responder dataclass"""
    
    def test_responder_creation(self):
        responder = Responder(
            id="resp_001",
            name="John Doe",
            email="john@example.com",
            phone="+1234567890",
            role="Security Analyst",
            escalation_level=1,
            is_on_call=True
        )
        assert responder.id == "resp_001"
        assert responder.name == "John Doe"
        assert responder.escalation_level == 1
        assert responder.is_on_call == True


class TestEscalationMatrix:
    """Test EscalationMatrix class"""
    
    def test_matrix_initialization(self):
        matrix = EscalationMatrix()
        assert AlertSeverity.CRITICAL in matrix.sla_policies
        assert AlertSeverity.HIGH in matrix.sla_policies
        assert AlertSeverity.MEDIUM in matrix.sla_policies
    
    def test_add_responder(self):
        matrix = EscalationMatrix()
        responder = Responder(
            id="resp_001",
            name="John Doe",
            email="john@example.com",
            phone="+1234567890",
            role="Security Analyst",
            escalation_level=1,
            is_on_call=True
        )
        matrix.add_responder(responder)
        assert "resp_001" in matrix.responders
        assert matrix.responders["resp_001"] == responder
    
    def test_get_on_call_responders(self):
        matrix = EscalationMatrix()
        responder1 = Responder(
            id="resp_001",
            name="John Doe",
            email="john@example.com",
            phone="+1234567890",
            role="Security Analyst",
            escalation_level=1,
            is_on_call=True
        )
        responder2 = Responder(
            id="resp_002",
            name="Jane Smith",
            email="jane@example.com",
            phone="+1234567891",
            role="Security Analyst",
            escalation_level=1,
            is_on_call=False
        )
        matrix.add_responder(responder1)
        matrix.add_responder(responder2)
        
        on_call = matrix.get_on_call_responders(1)
        assert len(on_call) == 1
        assert on_call[0].id == "resp_001"
    
    def test_get_escalation_path(self):
        matrix = EscalationMatrix()
        critical_path = matrix.get_escalation_path(AlertSeverity.CRITICAL)
        assert len(critical_path) == 4  # L1, L2, L3, Executive
        
        high_path = matrix.get_escalation_path(AlertSeverity.HIGH)
        assert len(high_path) == 3  # L1, L2, L3
    
    def test_get_sla_policy(self):
        matrix = EscalationMatrix()
        critical_sla = matrix.get_sla_policy(AlertSeverity.CRITICAL)
        assert critical_sla.acknowledge_timeout_minutes == 5
        assert critical_sla.auto_escalate_after_minutes == 10


class TestAlertEscalationManager:
    """Test AlertEscalationManager class"""
    
    def test_manager_initialization(self):
        manager = AlertEscalationManager()
        assert manager.active_alerts == {}
        assert manager.escalation_history == []
    
    def test_register_alert(self):
        manager = AlertEscalationManager()
        alert_data = manager.register_alert(
            alert_id="alert_001",
            severity=AlertSeverity.CRITICAL,
            title="Ransomware Detected",
            description="Suspicious encryption activity on server SRV-001",
            source="EDR System"
        )
        
        assert "alert_001" in manager.active_alerts
        assert alert_data["severity"] == AlertSeverity.CRITICAL
        assert alert_data["status"] == EscalationStatus.PENDING
        assert alert_data["current_level"] == 1
        assert alert_data["escalation_count"] == 0
    
    def test_acknowledge_alert(self):
        manager = AlertEscalationManager()
        manager.register_alert(
            alert_id="alert_001",
            severity=AlertSeverity.HIGH,
            title="Phishing Campaign",
            description="Multiple users reported phishing emails",
            source="Email Gateway"
        )
        
        result = manager.acknowledge_alert("alert_001", "resp_001")
        assert result == True
        
        alert = manager.active_alerts["alert_001"]
        assert alert["status"] == EscalationStatus.ACKNOWLEDGED
        assert alert["acknowledged_by"] == "resp_001"
        assert alert["acknowledged_at"] is not None
    
    def test_acknowledge_nonexistent_alert(self):
        manager = AlertEscalationManager()
        result = manager.acknowledge_alert("nonexistent", "resp_001")
        assert result == False
    
    def test_resolve_alert(self):
        manager = AlertEscalationManager()
        manager.register_alert(
            alert_id="alert_001",
            severity=AlertSeverity.MEDIUM,
            title="Port Scan Detected",
            description="Port scan from external IP",
            source="Firewall"
        )
        
        result = manager.resolve_alert("alert_001", "resp_001", "False positive - authorized scan")
        assert result == True
        
        alert = manager.active_alerts["alert_001"]
        assert alert["status"] == EscalationStatus.RESOLVED
        assert alert["resolved_at"] is not None
        assert alert["resolution_notes"] == "False positive - authorized scan"
    
    def test_escalate_alert(self):
        manager = AlertEscalationManager()
        manager.register_alert(
            alert_id="alert_001",
            severity=AlertSeverity.CRITICAL,
            title="Data Exfiltration",
            description="Large data transfer to unknown external server",
            source="DLP System"
        )
        
        result = manager.escalate_alert("alert_001", "No response from L1 analyst", "resp_002")
        assert result == True
        
        alert = manager.active_alerts["alert_001"]
        assert alert["current_level"] == 2
        assert alert["escalation_count"] == 1
        assert alert["status"] == EscalationStatus.ESCALATED
        assert len(manager.escalation_history) == 1
        
        escalation_record = manager.escalation_history[0]
        assert escalation_record.alert_id == "alert_001"
        assert escalation_record.from_level == 1
        assert escalation_record.to_level == 2
    
    def test_escalate_to_max_level(self):
        manager = AlertEscalationManager()
        manager.register_alert(
            alert_id="alert_001",
            severity=AlertSeverity.LOW,  # Only has L1 escalation path
            title="Informational",
            description="Routine alert",
            source="Monitor"
        )
        
        # First escalation should work (from 1 to 2)
        result1 = manager.escalate_alert("alert_001", "Test escalation", "system")
        # LOW severity only has 1 level, so second should fail
        result2 = manager.escalate_alert("alert_001", "Test again", "system")
        
        assert result2 == False  # Already at max level
    
    def test_get_alert_status(self):
        manager = AlertEscalationManager()
        manager.register_alert(
            alert_id="alert_001",
            severity=AlertSeverity.HIGH,
            title="Test Alert",
            description="Test",
            source="Test"
        )
        
        status = manager.get_alert_status("alert_001")
        assert status is not None
        assert status["alert_id"] == "alert_001"
        
        assert manager.get_alert_status("nonexistent") is None
    
    def test_get_sla_metrics_empty(self):
        manager = AlertEscalationManager()
        metrics = manager.get_sla_metrics()
        assert metrics["total_alerts_tracked"] == 0
        assert metrics["sla_compliance_rate"] == 100.0
    
    def test_get_sla_metrics_with_alerts(self):
        manager = AlertEscalationManager()
        manager.register_alert(
            alert_id="alert_001",
            severity=AlertSeverity.HIGH,
            title="Test Alert 1",
            description="Test",
            source="Test"
        )
        manager.register_alert(
            alert_id="alert_002",
            severity=AlertSeverity.MEDIUM,
            title="Test Alert 2",
            description="Test",
            source="Test"
        )
        
        manager.acknowledge_alert("alert_001", "resp_001")
        manager.resolve_alert("alert_002", "resp_001", "Resolved")
        
        metrics = manager.get_sla_metrics()
        assert metrics["total_alerts_tracked"] == 2
        assert metrics["resolved_alerts"] == 1
        assert metrics["active_alerts"] == 1
    
    def test_notification_callback(self):
        manager = AlertEscalationManager()
        mock_callback = Mock()
        manager.register_notification_callback(mock_callback)
        
        manager.register_alert(
            alert_id="alert_001",
            severity=AlertSeverity.HIGH,
            title="Test Alert",
            description="Test",
            source="Test"
        )
        
        assert mock_callback.called
        call_args = mock_callback.call_args
        assert call_args[0][1] == "initial"  # notification_type
    
    def test_export_escalation_report(self):
        manager = AlertEscalationManager()
        manager.register_alert(
            alert_id="alert_001",
            severity=AlertSeverity.CRITICAL,
            title="Test Alert",
            description="Test",
            source="Test"
        )
        manager.escalate_alert("alert_001", "Test reason", "system")
        
        report = manager.export_escalation_report()
        assert "generated_at" in report
        assert "metrics" in report
        assert "escalation_history" in report
        assert len(report["escalation_history"]) == 1


class TestIntegration:
    """Integration tests for full workflow"""
    
    def test_full_alert_lifecycle(self):
        """Test complete alert lifecycle: register -> acknowledge -> resolve"""
        manager = AlertEscalationManager()
        
        # 1. Register alert
        manager.register_alert(
            alert_id="alert_001",
            severity=AlertSeverity.HIGH,
            title="Suspicious Login",
            description="Multiple failed login attempts from unknown IP",
            source="IAM System"
        )
        
        alert = manager.get_alert_status("alert_001")
        assert alert["status"] == EscalationStatus.PENDING
        
        # 2. Acknowledge
        manager.acknowledge_alert("alert_001", "analyst_01")
        alert = manager.get_alert_status("alert_001")
        assert alert["status"] == EscalationStatus.ACKNOWLEDGED
        assert alert["acknowledged_by"] == "analyst_01"
        
        # 3. Resolve
        manager.resolve_alert("alert_001", "analyst_01", "IP blocked, user password reset")
        alert = manager.get_alert_status("alert_001")
        assert alert["status"] == EscalationStatus.RESOLVED
        
        metrics = manager.get_sla_metrics()
        assert metrics["resolved_alerts"] == 1
        assert metrics["active_alerts"] == 0
    
    def test_escalation_chain(self):
        """Test multiple escalations for critical alert"""
        manager = AlertEscalationManager()
        
        manager.register_alert(
            alert_id="alert_critical",
            severity=AlertSeverity.CRITICAL,
            title="Active Breach",
            description="Unauthorized access to database server",
            source="HIDS"
        )
        
        # Multiple escalations
        manager.escalate_alert("alert_critical", "No L1 response", "system")
        manager.escalate_alert("alert_critical", "No L2 response", "system")
        manager.escalate_alert("alert_critical", "Executive notification", "manager_01")
        
        alert = manager.get_alert_status("alert_critical")
        assert alert["current_level"] == 4  # Max level for CRITICAL
        assert alert["escalation_count"] == 3
        
        metrics = manager.get_sla_metrics()
        assert metrics["total_escalations"] == 3


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
