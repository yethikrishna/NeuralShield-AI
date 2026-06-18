"""
Test Suite for Threat Intelligence Automated Response Orchestrator
June 18, 2026 - Production Release

Comprehensive tests covering:
- Incident creation and severity calculation
- Playbook triggering and execution
- Response action simulation
- Rate limiting and cooldown
- Incident lifecycle management
- Statistics tracking
"""

import pytest
import time
from datetime import datetime, timedelta
from neural_shield.threat_intelligence_automated_response_orchestrator_2026_june import (
    AutomatedResponseOrchestrator,
    create_response_orchestrator,
    IncidentSeverity,
    ResponseStatus,
    ResponseActionType,
    PlaybookTrigger,
    ThreatIndicator,
    ResponseAction,
    SecurityIncident,
    ResponsePlaybook
)


class TestThreatIndicator:
    """Tests for ThreatIndicator data class"""

    def test_threat_indicator_creation(self):
        """Test basic threat indicator creation"""
        indicator = ThreatIndicator(
            indicator_type="ipv4",
            value="192.168.1.1",
            confidence=0.95,
            source="ids"
        )
        assert indicator.indicator_type == "ipv4"
        assert indicator.value == "192.168.1.1"
        assert indicator.confidence == 0.95
        assert indicator.source == "ids"


class TestResponseAction:
    """Tests for ResponseAction data class"""

    def test_response_action_creation(self):
        """Test basic response action creation"""
        action = ResponseAction(
            action_id="test_action_001",
            action_type=ResponseActionType.BLOCK_IP,
            target="192.168.1.1"
        )
        assert action.action_id == "test_action_001"
        assert action.action_type == ResponseActionType.BLOCK_IP
        assert action.target == "192.168.1.1"
        assert action.status == ResponseStatus.PENDING

    def test_response_action_to_dict(self):
        """Test dictionary serialization"""
        action = ResponseAction(
            action_id="test_001",
            action_type=ResponseActionType.ALERT_ADMIN,
            target="admin-team"
        )
        d = action.to_dict()
        assert d["action_id"] == "test_001"
        assert d["status"] == "pending"


class TestSecurityIncident:
    """Tests for SecurityIncident data class"""

    def test_incident_creation(self):
        """Test basic incident creation"""
        incident = SecurityIncident(
            incident_id="incident_001",
            title="Test Incident",
            description="Test description",
            severity=IncidentSeverity.HIGH
        )
        assert incident.incident_id == "incident_001"
        assert incident.title == "Test Incident"
        assert incident.severity == IncidentSeverity.HIGH
        assert incident.mitigated is False

    def test_incident_summary(self):
        """Test incident summary generation"""
        incident = SecurityIncident(
            incident_id="inc_001",
            title="Test",
            description="Test",
            severity=IncidentSeverity.MEDIUM,
            indicators=[
                ThreatIndicator("ipv4", "1.1.1.1", 0.8, "test"),
                ThreatIndicator("domain", "test.com", 0.7, "test")
            ]
        )
        summary = incident.summary()
        assert summary["incident_id"] == "inc_001"
        assert summary["indicators_count"] == 2
        assert summary["severity"] == "medium"


class TestResponsePlaybook:
    """Tests for ResponsePlaybook"""

    def test_playbook_creation(self):
        """Test playbook creation"""
        playbook = ResponsePlaybook(
            playbook_id="test_pb",
            name="Test Playbook",
            description="Test",
            trigger=PlaybookTrigger.MALWARE_DETECTED,
            min_severity=IncidentSeverity.MEDIUM,
            actions=[ResponseActionType.ALERT_ADMIN]
        )
        assert playbook.playbook_id == "test_pb"
        assert playbook.name == "Test Playbook"

    def test_playbook_should_trigger(self):
        """Test playbook trigger logic"""
        playbook = ResponsePlaybook(
            playbook_id="test",
            name="Test",
            description="Test",
            trigger=PlaybookTrigger.MALWARE_DETECTED,
            min_severity=IncidentSeverity.HIGH,
            actions=[]
        )
        
        # HIGH should trigger
        assert playbook.should_trigger(IncidentSeverity.HIGH) is True
        # CRITICAL should trigger (higher than HIGH)
        assert playbook.should_trigger(IncidentSeverity.CRITICAL) is True
        # MEDIUM should NOT trigger (lower than HIGH)
        assert playbook.should_trigger(IncidentSeverity.MEDIUM) is False


class TestOrchestratorBasics:
    """Basic orchestrator functionality tests"""

    def test_orchestrator_creation(self):
        """Test orchestrator instantiation"""
        orchestrator = create_response_orchestrator()
        assert orchestrator is not None
        assert isinstance(orchestrator, AutomatedResponseOrchestrator)

    def test_orchestrator_with_custom_params(self):
        """Test orchestrator with custom parameters"""
        orchestrator = create_response_orchestrator(
            enable_auto_response=False,
            max_actions_per_minute=5
        )
        assert orchestrator.enable_auto_response is False
        assert orchestrator.max_actions_per_minute == 5

    def test_default_playbooks_exist(self):
        """Test default playbooks are loaded"""
        orchestrator = create_response_orchestrator()
        stats = orchestrator.get_statistics()
        assert stats["playbooks_available"] >= 4


class TestIncidentCreation:
    """Tests for incident creation"""

    def test_incident_creation_basic(self):
        """Test basic incident creation"""
        orchestrator = create_response_orchestrator()
        
        indicators = [
            {"type": "ipv4", "value": "192.168.1.1", "confidence": 0.8, "source": "test"}
        ]
        
        incident = orchestrator.create_incident(
            title="Test Incident",
            description="Test description",
            indicators=indicators
        )
        
        assert incident.incident_id.startswith("incident_")
        assert len(incident.indicators) == 1
        assert incident.mitigated is False

    def test_severity_calculation_critical(self):
        """Test critical severity calculation"""
        orchestrator = create_response_orchestrator()
        
        # 3+ high confidence indicators = CRITICAL
        indicators = [
            {"type": "ipv4", "value": "1.1.1.1", "confidence": 0.96, "source": "test"},
            {"type": "ipv4", "value": "2.2.2.2", "confidence": 0.95, "source": "test"},
            {"type": "ipv4", "value": "3.3.3.3", "confidence": 0.97, "source": "test"}
        ]
        
        incident = orchestrator.create_incident(
            title="Critical Test",
            description="Test",
            indicators=indicators
        )
        
        assert incident.severity == IncidentSeverity.CRITICAL

    def test_severity_calculation_high(self):
        """Test high severity calculation"""
        orchestrator = create_response_orchestrator()
        
        # 2 high confidence indicators = HIGH
        indicators = [
            {"type": "ipv4", "value": "1.1.1.1", "confidence": 0.90, "source": "test"},
            {"type": "ipv4", "value": "2.2.2.2", "confidence": 0.88, "source": "test"}
        ]
        
        incident = orchestrator.create_incident(
            title="High Test",
            description="Test",
            indicators=indicators
        )
        
        assert incident.severity == IncidentSeverity.HIGH

    def test_incident_with_affected_assets(self):
        """Test incident creation with affected assets"""
        orchestrator = create_response_orchestrator()
        
        incident = orchestrator.create_incident(
            title="Test",
            description="Test",
            indicators=[{"type": "ipv4", "value": "1.1.1.1", "confidence": 0.8}],
            affected_assets=["server-01", "workstation-05"]
        )
        
        assert len(incident.affected_assets) == 2
        assert "server-01" in incident.affected_assets


class TestPlaybookTriggering:
    """Tests for automated playbook triggering"""

    def test_playbook_trigger_ransomware(self):
        """Test ransomware playbook triggering"""
        orchestrator = create_response_orchestrator()
        
        indicators = [
            {"type": "sha256", "value": "abc123", "confidence": 0.95, "source": "edr"}
        ]
        
        incident = orchestrator.create_incident(
            title="Ransomware Detected",
            description="Test",
            indicators=indicators,
            affected_assets=["workstation-42"],
            trigger_type=PlaybookTrigger.RANSOMWARE
        )
        
        # Ransomware playbook should create actions
        assert len(incident.response_actions) > 0
        
        # Check for expected ransomware response actions
        action_types = [a.action_type for a in incident.response_actions]
        assert ResponseActionType.NETWORK_ISOLATION in action_types
        assert ResponseActionType.ALERT_ADMIN in action_types

    def test_playbook_trigger_bruteforce(self):
        """Test brute force playbook triggering"""
        orchestrator = create_response_orchestrator()
        
        indicators = [
            {"type": "ipv4", "value": "10.0.0.1", "confidence": 0.85, "source": "fw"}
        ]
        
        incident = orchestrator.create_incident(
            title="Brute Force Attack",
            description="Test",
            indicators=indicators,
            affected_assets=["server-ssh"],
            trigger_type=PlaybookTrigger.BRUTE_FORCE
        )
        
        assert len(incident.response_actions) > 0
        action_types = [a.action_type for a in incident.response_actions]
        assert ResponseActionType.BLOCK_IP in action_types

    def test_playbook_auto_execution(self):
        """Test playbooks auto-execute actions"""
        orchestrator = create_response_orchestrator()
        
        incident = orchestrator.create_incident(
            title="Ransomware",
            description="Test",
            indicators=[{"type": "sha256", "value": "abc", "confidence": 0.95}],
            affected_assets=["ws-01"],
            trigger_type=PlaybookTrigger.RANSOMWARE
        )
        
        # Some actions should be completed (auto-executed)
        completed = [a for a in incident.response_actions if a.status == ResponseStatus.COMPLETED]
        assert len(completed) > 0


class TestActionExecution:
    """Tests for response action execution"""

    def test_manual_action_execution(self):
        """Test manual action execution"""
        orchestrator = create_response_orchestrator(enable_auto_response=False)
        
        incident = orchestrator.create_incident(
            title="Test",
            description="Test",
            indicators=[{"type": "ipv4", "value": "1.1.1.1", "confidence": 0.8}],
            trigger_type=PlaybookTrigger.IOC_MATCH
        )
        
        # Get pending action
        pending_actions = [a for a in incident.response_actions if a.status == ResponseStatus.PENDING]
        if pending_actions:
            action_id = pending_actions[0].action_id
            result = orchestrator.execute_action(incident.incident_id, action_id)
            
            assert result is not None
            assert result.status in [ResponseStatus.COMPLETED, ResponseStatus.FAILED]
            assert result.duration_seconds > 0

    def test_action_execution_nonexistent_incident(self):
        """Test execution on non-existent incident"""
        orchestrator = create_response_orchestrator()
        result = orchestrator.execute_action("nonexistent", "action_001")
        assert result is None


class TestIncidentManagement:
    """Tests for incident lifecycle management"""

    def test_mark_incident_mitigated(self):
        """Test marking incident as mitigated"""
        orchestrator = create_response_orchestrator()
        
        incident = orchestrator.create_incident(
            title="Test",
            description="Test",
            indicators=[{"type": "ipv4", "value": "1.1.1.1", "confidence": 0.8}]
        )
        
        assert incident.mitigated is False
        
        result = orchestrator.mark_incident_mitigated(
            incident.incident_id,
            notes="Successfully contained"
        )
        
        assert result is True
        assert incident.mitigated is True
        assert incident.resolved_at is not None
        assert len(incident.notes) == 1

    def test_mark_nonexistent_incident(self):
        """Test marking non-existent incident"""
        orchestrator = create_response_orchestrator()
        result = orchestrator.mark_incident_mitigated("nonexistent")
        assert result is False

    def test_get_incident(self):
        """Test retrieving incident by ID"""
        orchestrator = create_response_orchestrator()
        
        incident = orchestrator.create_incident(
            title="Test",
            description="Test",
            indicators=[{"type": "ipv4", "value": "1.1.1.1", "confidence": 0.8}]
        )
        
        retrieved = orchestrator.get_incident(incident.incident_id)
        assert retrieved is not None
        assert retrieved.incident_id == incident.incident_id

    def test_get_active_incidents(self):
        """Test getting active (unmitigated) incidents"""
        orchestrator = create_response_orchestrator()
        
        # Create 3 incidents
        for i in range(3):
            orchestrator.create_incident(
                title=f"Test {i}",
                description="Test",
                indicators=[{"type": "ipv4", "value": f"1.1.1.{i}", "confidence": 0.8}]
            )
        
        # Mark one as mitigated
        incidents = orchestrator.get_active_incidents()
        orchestrator.mark_incident_mitigated(incidents[0].incident_id)
        
        # Should have 2 active now
        active = orchestrator.get_active_incidents()
        assert len(active) == 2

    def test_get_active_incidents_by_severity(self):
        """Test filtering active incidents by severity"""
        orchestrator = create_response_orchestrator()
        
        # Create low severity incident
        orchestrator.create_incident(
            title="Low",
            description="Test",
            indicators=[{"type": "ipv4", "value": "1.1.1.1", "confidence": 0.3}]
        )
        
        # Create high severity incident
        orchestrator.create_incident(
            title="High",
            description="Test",
            indicators=[
                {"type": "ipv4", "value": "2.2.2.2", "confidence": 0.95},
                {"type": "ipv4", "value": "3.3.3.3", "confidence": 0.95}
            ]
        )
        
        # Get only HIGH and above
        high_severity = orchestrator.get_active_incidents(min_severity=IncidentSeverity.HIGH)
        assert len(high_severity) == 1
        assert high_severity[0].severity == IncidentSeverity.HIGH


class TestStatistics:
    """Tests for orchestrator statistics"""

    def test_initial_statistics(self):
        """Test initial statistics state"""
        orchestrator = create_response_orchestrator()
        stats = orchestrator.get_statistics()
        
        assert stats["incidents_created"] == 0
        assert stats["actions_executed"] == 0
        assert stats["active_incidents"] == 0
        assert stats["mitigation_rate"] == 0.0
        assert stats["action_success_rate"] == 1.0

    def test_statistics_update_on_incident(self):
        """Test statistics update when incident created"""
        orchestrator = create_response_orchestrator()
        
        orchestrator.create_incident(
            title="Test",
            description="Test",
            indicators=[{"type": "ipv4", "value": "1.1.1.1", "confidence": 0.8}]
        )
        
        stats = orchestrator.get_statistics()
        assert stats["incidents_created"] == 1
        assert stats["active_incidents"] == 1

    def test_mitigation_rate_calculation(self):
        """Test mitigation rate calculation"""
        orchestrator = create_response_orchestrator()
        
        # Create 2 incidents
        inc1 = orchestrator.create_incident(
            title="Test 1", description="Test",
            indicators=[{"type": "ipv4", "value": "1.1.1.1", "confidence": 0.8}]
        )
        orchestrator.create_incident(
            title="Test 2", description="Test",
            indicators=[{"type": "ipv4", "value": "2.2.2.2", "confidence": 0.8}]
        )
        
        # Mitigate one
        orchestrator.mark_incident_mitigated(inc1.incident_id)
        
        stats = orchestrator.get_statistics()
        assert stats["incidents_mitigated"] == 1
        assert stats["mitigation_rate"] == 0.5  # 1/2 mitigated


class TestCustomPlaybook:
    """Tests for custom playbook registration"""

    def test_register_custom_playbook(self):
        """Test registering custom playbook"""
        orchestrator = create_response_orchestrator()
        initial_count = orchestrator.get_statistics()["playbooks_available"]
        
        custom_pb = ResponsePlaybook(
            playbook_id="custom_pb_001",
            name="Custom Playbook",
            description="Custom test",
            trigger=PlaybookTrigger.ANOMALY_DETECTED,
            min_severity=IncidentSeverity.MEDIUM,
            actions=[ResponseActionType.ISOLATE_HOST]
        )
        
        orchestrator.register_custom_playbook(custom_pb)
        
        new_count = orchestrator.get_statistics()["playbooks_available"]
        assert new_count == initial_count + 1


class TestIntegration:
    """Integration tests for full workflow"""

    def test_full_incident_response_workflow(self):
        """Test complete incident response workflow"""
        orchestrator = create_response_orchestrator()
        
        # 1. Create incident with high-confidence indicators
        indicators = [
            {"type": "ipv4", "value": "10.0.0.99", "confidence": 0.96, "source": "ids"},
            {"type": "domain", "value": "bad-domain.xyz", "confidence": 0.92, "source": "dns"},
            {"type": "sha256", "value": "abcdef123456", "confidence": 0.98, "source": "edr"}
        ]
        
        incident = orchestrator.create_incident(
            title="Critical Ransomware Outbreak",
            description="Multiple IOCs detected on critical assets",
            indicators=indicators,
            affected_assets=["fileserver-01", "dc-01", "workstation-42"],
            trigger_type=PlaybookTrigger.RANSOMWARE
        )
        
        # 2. Verify incident created correctly
        assert incident.severity == IncidentSeverity.CRITICAL
        assert len(incident.indicators) == 3
        assert len(incident.affected_assets) == 3
        
        # 3. Verify response actions were created
        assert len(incident.response_actions) > 0
        
        # 4. Mark as mitigated
        result = orchestrator.mark_incident_mitigated(
            incident.incident_id,
            notes="Automated containment successful. All assets isolated."
        )
        assert result is True
        
        # 5. Verify statistics
        stats = orchestrator.get_statistics()
        assert stats["incidents_created"] == 1
        assert stats["incidents_mitigated"] == 1
        assert stats["playbooks_triggered"] >= 1


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
