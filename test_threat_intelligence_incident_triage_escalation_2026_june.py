"""
Test Suite for Threat Intelligence Incident Triage & Escalation Engine
June 18, 2026 - Production Release

Real, working tests that verify:
- Severity scoring calculation
- Automated triage workflow
- SLA compliance tracking
- Escalation chain management
- False positive risk assessment
"""

import pytest
from datetime import datetime, timedelta
import json

from neural_shield.threat_intelligence_incident_triage_escalation_2026_june import (
    IncidentSeverity,
    IncidentStatus,
    IncidentCategory,
    ResponseTeam,
    ThreatIndicator,
    Incident,
    SeverityScoringEngine,
    IncidentTriageEngine,
    IncidentEscalationManager,
    IncidentTriageEscalationEngine,
    create_incident_triage_engine,
    SLAPolicy
)


class TestSeverityScoringEngine:
    """Test multi-factor severity scoring engine"""
    
    def test_calculate_severity_score_basic(self):
        """Test basic severity score calculation"""
        score = SeverityScoringEngine.calculate_severity_score(
            impact_business=3,
            impact_data=3,
            attack_sophistication=3,
            indicator_confidence=0.7,
            affected_assets_count=2,
            time_sensitivity=3,
            historical_precedent=0.7
        )
        
        assert 0 <= score <= 100
        assert isinstance(score, float)
    
    def test_calculate_severity_score_critical(self):
        """Test critical severity score"""
        score = SeverityScoringEngine.calculate_severity_score(
            impact_business=5,
            impact_data=5,
            attack_sophistication=5,
            indicator_confidence=1.0,
            affected_assets_count=10,
            time_sensitivity=5,
            historical_precedent=1.0
        )
        
        assert score >= 80
        severity = SeverityScoringEngine.score_to_severity(score)
        assert severity == IncidentSeverity.CRITICAL
    
    def test_calculate_severity_score_low(self):
        """Test low severity score"""
        score = SeverityScoringEngine.calculate_severity_score(
            impact_business=1,
            impact_data=1,
            attack_sophistication=1,
            indicator_confidence=0.1,
            affected_assets_count=1,
            time_sensitivity=1,
            historical_precedent=0.1
        )
        
        assert score <= 40
        severity = SeverityScoringEngine.score_to_severity(score)
        assert severity in {IncidentSeverity.LOW, IncidentSeverity.INFORMATIONAL}
    
    def test_score_to_severity_mapping(self):
        """Test score to severity enum mapping"""
        assert SeverityScoringEngine.score_to_severity(90) == IncidentSeverity.CRITICAL
        assert SeverityScoringEngine.score_to_severity(75) == IncidentSeverity.HIGH
        assert SeverityScoringEngine.score_to_severity(50) == IncidentSeverity.MEDIUM
        assert SeverityScoringEngine.score_to_severity(25) == IncidentSeverity.LOW
        assert SeverityScoringEngine.score_to_severity(10) == IncidentSeverity.INFORMATIONAL


class TestIncidentTriageEngine:
    """Test automated incident triage engine"""
    
    def test_triage_basic_incident(self):
        """Test triaging a basic incident"""
        triage_engine = IncidentTriageEngine()
        
        incident = Incident(
            title="Suspicious Prompt Injection Attempt",
            description="Multiple injection patterns detected in user input",
            category=IncidentCategory.PROMPT_INJECTION,
            indicators=[
                ThreatIndicator(
                    indicator_type="PATTERN_MATCH",
                    value="ignore previous instructions",
                    confidence=0.85,
                    source="PromptFirewall2026"
                )
            ],
            affected_assets=["llm-production-01"]
        )
        
        result = triage_engine.triage_incident(incident)
        
        assert result is not None
        assert result.incident.status == IncidentStatus.TRIAGED
        assert result.incident.triaged_at is not None
        assert result.assigned_severity is not None
        assert result.recommended_team is not None
        assert len(result.recommended_actions) > 0
    
    def test_triage_data_exfiltration_critical(self):
        """Test critical data exfiltration triage rule"""
        triage_engine = IncidentTriageEngine()
        
        incident = Incident(
            title="Mass Data Exfiltration Detected",
            description="Large-scale data transfer to unknown external endpoint",
            category=IncidentCategory.DATA_EXFILTRATION,
            indicators=[
                ThreatIndicator(
                    indicator_type="NETWORK_FLOW",
                    value="10GB outbound to unknown IP",
                    confidence=0.95,
                    source="NetworkIDS"
                )
            ],
            affected_assets=["db-prod-01", "db-prod-02", "db-prod-03"]
        )
        
        result = triage_engine.triage_incident(incident)
        
        # 3+ affected assets for exfiltration = CRITICAL per rule
        assert result.assigned_severity == IncidentSeverity.CRITICAL
        assert result.recommended_team == ResponseTeam.TIER3_SOC
    
    def test_triage_high_confidence_jailbreak(self):
        """Test high confidence jailbreak triage"""
        triage_engine = IncidentTriageEngine()
        
        incident = Incident(
            title="Advanced Jailbreak Attempt",
            description="Multi-turn roleplay jailbreak with high confidence indicators",
            category=IncidentCategory.JAILBREAK_ATTEMPT,
            indicators=[
                ThreatIndicator(
                    indicator_type="SEMANTIC_MATCH",
                    value="DAN roleplay pattern",
                    confidence=0.95,
                    source="JailbreakDetector"
                )
            ]
        )
        
        result = triage_engine.triage_incident(incident)
        
        # High confidence jailbreak = HIGH severity
        assert result.assigned_severity == IncidentSeverity.HIGH
    
    def test_triage_statistics(self):
        """Test triage statistics tracking"""
        triage_engine = IncidentTriageEngine()
        
        for i in range(5):
            incident = Incident(
                title=f"Test Incident {i}",
                description="Test",
                category=IncidentCategory.PROMPT_INJECTION
            )
            triage_engine.triage_incident(incident)
        
        stats = triage_engine.get_triage_statistics()
        assert stats["total_triaged"] == 5


class TestIncidentEscalationManager:
    """Test incident escalation and SLA management"""
    
    def test_sla_compliance_check(self):
        """Test SLA compliance checking"""
        escalation_manager = IncidentEscalationManager()
        
        incident = Incident(
            title="Test Incident",
            description="Test",
            category=IncidentCategory.PROMPT_INJECTION,
            severity=IncidentSeverity.HIGH,
            created_at=datetime.now() - timedelta(minutes=5),
            acknowledged_at=datetime.now()
        )
        
        compliance = escalation_manager.check_sla_compliance(incident)
        
        # Acknowledged within 15 min SLA for HIGH
        assert compliance.acknowledgement_met is True
        assert len(compliance.sla_breaches) == 0
    
    def test_manual_escalation(self):
        """Test manual incident escalation"""
        escalation_manager = IncidentEscalationManager()
        
        incident = Incident(
            title="Escalation Test",
            description="Test incident for escalation",
            category=IncidentCategory.PROMPT_INJECTION,
            severity=IncidentSeverity.HIGH,
            assigned_team=ResponseTeam.TIER1_SOC
        )
        
        escalation = escalation_manager.escalate_incident(
            incident,
            reason="Complex attack requiring senior analyst",
            escalated_by="analyst-john"
        )
        
        assert escalation is not None
        assert escalation.from_team == ResponseTeam.TIER1_SOC
        assert escalation.to_team == ResponseTeam.TIER2_SOC
        assert incident.status == IncidentStatus.ESCALATED
        assert len(incident.escalation_history) == 1
    
    def test_auto_escalation_detection(self):
        """Test auto-escalation detection logic"""
        escalation_manager = IncidentEscalationManager()
        
        # Create old unacknowledged incident
        incident = Incident(
            title="Stale Incident",
            description="Incident past escalation threshold",
            category=IncidentCategory.PROMPT_INJECTION,
            severity=IncidentSeverity.CRITICAL,
            created_at=datetime.now() - timedelta(hours=1),
            status=IncidentStatus.TRIAGED
        )
        
        # Should auto-escalate for CRITICAL unacknowledged after 30 min
        should_escalate = escalation_manager.should_auto_escalate(incident)
        assert should_escalate is True


class TestIncidentTriageEscalationEngine:
    """Test main facade engine integration"""
    
    def test_process_new_incident_end_to_end(self):
        """Test end-to-end incident processing"""
        engine = create_incident_triage_engine()
        
        indicators = [
            ThreatIndicator(
                indicator_type="REGEX_MATCH",
                value="system prompt override pattern",
                confidence=0.88,
                source="ContextWindowProtector"
            ),
            ThreatIndicator(
                indicator_type="EMBEDDING_SIMILARITY",
                value="known injection embedding",
                confidence=0.92,
                source="SemanticDetector"
            )
        ]
        
        result = engine.process_new_incident(
            title="Multi-Signal Prompt Injection Detected",
            description="Two independent detection signals confirm prompt injection attempt",
            category=IncidentCategory.PROMPT_INJECTION,
            indicators=indicators,
            affected_assets=["api-gateway-01", "llm-inference-02"],
            source_detector="EnsembleDetector"
        )
        
        assert result is not None
        assert result.incident.incident_id.startswith("INC-")
        assert result.incident.severity_score > 0
        assert result.confidence > 0
        assert len(result.recommended_actions) > 0
    
    def test_acknowledge_incident(self):
        """Test incident acknowledgement workflow"""
        engine = create_incident_triage_engine()
        
        result = engine.process_new_incident(
            title="Test Incident",
            description="Test",
            category=IncidentCategory.PROMPT_INJECTION
        )
        
        success = engine.acknowledge_incident(
            result.incident.incident_id,
            acknowledged_by="soc-analyst-01"
        )
        
        assert success is True
        incident = engine.triage_engine.incident_cache[result.incident.incident_id]
        assert incident.acknowledged_at is not None
        assert incident.status == IncidentStatus.ASSIGNED
    
    def test_sla_summary_generation(self):
        """Test SLA summary generation"""
        engine = create_incident_triage_engine()
        
        # Process some incidents
        for i in range(3):
            engine.process_new_incident(
                title=f"Incident {i}",
                description="Test",
                category=IncidentCategory.PROMPT_INJECTION
            )
        
        summary = engine.get_sla_summary()
        
        assert summary["total_incidents"] == 3
        assert "compliance_rate" in summary
        assert 0 <= summary["compliance_rate"] <= 100
    
    def test_export_incidents_json(self):
        """Test JSON export functionality"""
        engine = create_incident_triage_engine()
        
        engine.process_new_incident(
            title="Export Test",
            description="Testing JSON export",
            category=IncidentCategory.PROMPT_INJECTION
        )
        
        json_output = engine.export_incidents_json()
        data = json.loads(json_output)
        
        assert len(data) == 1
        assert "incident_id" in data[0]
        assert "severity" in data[0]
        assert "status" in data[0]
    
    def test_audit_logging(self):
        """Test audit logging functionality"""
        engine = create_incident_triage_engine()
        
        engine.process_new_incident(
            title="Audit Test",
            description="Testing audit logs",
            category=IncidentCategory.PROMPT_INJECTION
        )
        
        assert len(engine.audit_log) >= 1
        assert engine.audit_log[0]["event_type"] == "INCIDENT_TRIAGED"
        assert "timestamp" in engine.audit_log[0]


class TestSLAPolicy:
    """Test SLA policy definitions"""
    
    def test_sla_policies_defined(self):
        """Test all severity levels have SLA policies"""
        for severity in IncidentSeverity:
            assert severity in SLAPolicy.SLA_RESPONSE_TIMES
            sla = SLAPolicy.SLA_RESPONSE_TIMES[severity]
            assert "acknowledgement" in sla
            assert "first_response" in sla
            assert "escalation" in sla
            assert "resolution" in sla
    
    def test_critical_has_strictest_sla(self):
        """Test CRITICAL has strictest (shortest) SLA times"""
        critical = SLAPolicy.SLA_RESPONSE_TIMES[IncidentSeverity.CRITICAL]
        low = SLAPolicy.SLA_RESPONSE_TIMES[IncidentSeverity.LOW]
        
        assert critical["acknowledgement"] < low["acknowledgement"]
        assert critical["resolution"] < low["resolution"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
