"""
Test Suite for NeuralShield-AI MITRE ATT&CK Executive Dashboard Reporter
June 2026 - Production Grade Tests

Verifies all functionality of the executive reporting system.
"""

import pytest
import json
import datetime
from neural_shield.threat_intelligence_mitre_executive_dashboard_2026_june import (
    MITREExecutiveDashboardReporter,
    RiskLevel,
    MITRETactic,
    ThreatEvent,
    ExecutiveSummary,
)


class TestMITREExecutiveDashboardReporter:
    """Test suite for MITRE Executive Dashboard Reporter."""

    def test_initialization(self):
        """Test reporter initialization with default and custom org name."""
        reporter = MITREExecutiveDashboardReporter()
        assert reporter.organization_name == "Enterprise"
        assert len(reporter.threat_events) == 0

        reporter2 = MITREExecutiveDashboardReporter("ACME Corp")
        assert reporter2.organization_name == "ACME Corp"

    def test_add_threat_event_valid(self):
        """Test adding a valid threat event."""
        reporter = MITREExecutiveDashboardReporter()
        event = reporter.add_threat_event(
            technique_id="T1566.001",
            source_ip="192.168.1.100",
            destination="web-server-01",
            description="Spearphishing attachment detected in email",
            confidence_score=0.95,
        )

        assert event is not None
        assert event.technique_id == "T1566.001"
        assert event.risk_level == RiskLevel.CRITICAL
        assert event.source_ip == "192.168.1.100"
        assert event.confidence_score == 0.95
        assert len(reporter.threat_events) == 1

    def test_add_threat_event_invalid_technique(self):
        """Test adding an invalid technique ID returns None."""
        reporter = MITREExecutiveDashboardReporter()
        event = reporter.add_threat_event(
            technique_id="T9999",  # Non-existent technique
            source_ip="10.0.0.1",
            destination="server",
            description="Test",
        )
        assert event is None
        assert len(reporter.threat_events) == 0

    def test_add_threat_event_confidence_clamping(self):
        """Test confidence score is properly clamped to 0-1 range."""
        reporter = MITREExecutiveDashboardReporter()

        # Test value above 1.0
        event1 = reporter.add_threat_event(
            "T1566", "1.1.1.1", "dest", "Test", confidence_score=1.5
        )
        assert event1.confidence_score == 1.0

        # Test value below 0.0
        event2 = reporter.add_threat_event(
            "T1059", "2.2.2.2", "dest", "Test", confidence_score=-0.5
        )
        assert event2.confidence_score == 0.0

    def test_batch_add_events(self):
        """Test batch adding multiple events."""
        reporter = MITREExecutiveDashboardReporter()

        events_data = [
            {"technique_id": "T1566.001", "source_ip": "10.0.0.1", "description": "Phishing 1"},
            {"technique_id": "T1059.001", "source_ip": "10.0.0.2", "description": "PowerShell 1"},
            {"technique_id": "T1555", "source_ip": "10.0.0.3", "description": "Credential access"},
            {"technique_id": "INVALID", "source_ip": "10.0.0.4", "description": "Should fail"},
        ]

        success, failure = reporter.batch_add_events(events_data)
        assert success == 3
        assert failure == 1
        assert len(reporter.threat_events) == 3

    def test_calculate_overall_risk_score_empty(self):
        """Test risk score calculation with no events returns 0."""
        reporter = MITREExecutiveDashboardReporter()
        score = reporter.calculate_overall_risk_score()
        assert score == 0.0

    def test_calculate_overall_risk_score_with_events(self):
        """Test risk score calculation with actual threats."""
        reporter = MITREExecutiveDashboardReporter()

        # Add critical events
        reporter.add_threat_event("T1566.001", "1.1.1.1", "server", "Critical phishing", confidence_score=0.95)
        reporter.add_threat_event("T1486", "2.2.2.2", "server", "Ransomware", confidence_score=0.9)
        reporter.add_threat_event("T1041", "3.3.3.3", "server", "Data exfiltration", confidence_score=0.85)

        score = reporter.calculate_overall_risk_score()
        assert score > 0
        assert score <= 100
        assert isinstance(score, float)

    def test_get_risk_breakdown(self):
        """Test risk level breakdown counting."""
        reporter = MITREExecutiveDashboardReporter()

        # Add events of different risk levels
        reporter.add_threat_event("T1566.001", "1.1.1.1", "srv", "Critical")  # CRITICAL
        reporter.add_threat_event("T1566", "2.2.2.2", "srv", "High")  # HIGH
        reporter.add_threat_event("T1083", "3.3.3.3", "srv", "Medium")  # MEDIUM

        breakdown = reporter.get_risk_breakdown()
        assert breakdown[RiskLevel.CRITICAL] >= 1
        assert breakdown[RiskLevel.HIGH] >= 1
        assert breakdown[RiskLevel.MEDIUM] >= 1

    def test_get_top_tactics(self):
        """Test getting most frequent tactics."""
        reporter = MITREExecutiveDashboardReporter()

        # Add multiple Initial Access events
        reporter.add_threat_event("T1566", "1.1.1.1", "srv", "Phishing 1")
        reporter.add_threat_event("T1566.001", "1.1.1.2", "srv", "Phishing 2")
        reporter.add_threat_event("T1566.002", "1.1.1.3", "srv", "Phishing 3")

        # Add Execution events
        reporter.add_threat_event("T1059", "2.2.2.1", "srv", "Execution 1")

        top_tactics = reporter.get_top_tactics()
        assert len(top_tactics) > 0
        assert top_tactics[0][0] == MITRETactic.INITIAL_ACCESS.value
        assert top_tactics[0][1] == 3

    def test_get_top_techniques(self):
        """Test getting most frequent techniques."""
        reporter = MITREExecutiveDashboardReporter()

        for i in range(5):
            reporter.add_threat_event("T1566", f"10.0.0.{i}", "srv", f"Phishing {i}")

        reporter.add_threat_event("T1059", "20.0.0.1", "srv", "PowerShell")

        top_techniques = reporter.get_top_techniques()
        assert "T1566: Phishing" in top_techniques[0][0]
        assert top_techniques[0][1] == 5

    def test_get_critical_findings(self):
        """Test extraction of critical findings."""
        reporter = MITREExecutiveDashboardReporter()

        # Add critical events
        reporter.add_threat_event("T1566.001", "1.1.1.1", "srv", "Critical 1", confidence_score=0.95)
        reporter.add_threat_event("T1486", "2.2.2.2", "srv", "Critical 2", confidence_score=0.9)

        # Add lower risk events
        reporter.add_threat_event("T1083", "3.3.3.3", "srv", "Medium")

        findings = reporter.get_critical_findings()
        assert len(findings) >= 2
        for finding in findings:
            assert finding.risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH)

    def test_generate_recommendations(self):
        """Test mitigation recommendation generation."""
        reporter = MITREExecutiveDashboardReporter()

        reporter.add_threat_event("T1566", "1.1.1.1", "srv", "Phishing")
        reporter.add_threat_event("T1059", "2.2.2.2", "srv", "Execution")

        recommendations = reporter.generate_recommendations()
        assert len(recommendations) > 0

        # Check structure
        for rec in recommendations:
            assert "category" in rec
            assert "priority" in rec
            assert "recommendation" in rec
            assert "related_threats" in rec

    def test_generate_executive_summary(self):
        """Test full executive summary generation."""
        reporter = MITREExecutiveDashboardReporter("Test Corporation")

        # Populate with realistic threat data
        reporter.add_threat_event("T1566.001", "192.168.1.10", "exchange-01", "Spearphishing campaign", confidence_score=0.92)
        reporter.add_threat_event("T1059.001", "192.168.1.11", "workstation-42", "Malicious PowerShell", confidence_score=0.88)
        reporter.add_threat_event("T1555", "192.168.1.12", "dc-01", "Credential dumping attempt", confidence_score=0.95)
        reporter.add_threat_event("T1486", "192.168.1.13", "fileserver-01", "Ransomware indicators", confidence_score=0.75)
        reporter.add_threat_event("T1041", "192.168.1.14", "db-01", "Suspicious outbound data", confidence_score=0.82)

        summary = reporter.generate_executive_summary(window_hours=24)

        assert isinstance(summary, ExecutiveSummary)
        assert summary.report_id.startswith("RPT-")
        assert summary.total_threats == 5
        assert summary.overall_risk_score > 0
        assert len(summary.critical_findings) > 0
        assert len(summary.recommendations) > 0

    def test_export_json_report(self):
        """Test JSON report export functionality."""
        reporter = MITREExecutiveDashboardReporter("JSON Test Corp")
        reporter.add_threat_event("T1566", "1.1.1.1", "server", "Test event")

        summary = reporter.generate_executive_summary()
        json_report = reporter.export_json_report(summary)

        # Verify valid JSON
        parsed = json.loads(json_report)
        assert "report_id" in parsed
        assert "organization" in parsed
        assert "executive_summary" in parsed
        assert "risk_breakdown" in parsed
        assert "recommendations" in parsed

    def test_generate_text_summary(self):
        """Test human-readable text summary generation."""
        reporter = MITREExecutiveDashboardReporter("Text Corp")
        reporter.add_threat_event("T1566.001", "1.1.1.1", "server", "Critical phishing")
        reporter.add_threat_event("T1486", "2.2.2.2", "server", "Ransomware")

        summary = reporter.generate_executive_summary()
        text_report = reporter.generate_text_summary(summary)

        assert isinstance(text_report, str)
        assert "NEURALSHIELD-AI" in text_report
        assert "Risk Score" in text_report
        assert "CRITICAL FINDINGS" in text_report
        assert "RECOMMENDED ACTIONS" in text_report

    def test_trend_analysis(self):
        """Test trend analysis data generation."""
        reporter = MITREExecutiveDashboardReporter()

        reporter.add_threat_event("T1566", "10.0.0.1", "srv1", "Event 1", confidence_score=0.9)
        reporter.add_threat_event("T1059", "10.0.0.2", "srv2", "Event 2", confidence_score=0.6)
        reporter.add_threat_event("T1083", "10.0.0.3", "srv3", "Event 3", confidence_score=0.3)

        trend = reporter.generate_trend_analysis()

        assert trend["current_period_threats"] == 3
        assert trend["unique_source_ips"] == 3
        assert trend["confidence_distribution"]["high_confidence"] == 1
        assert trend["confidence_distribution"]["medium_confidence"] == 1
        assert trend["confidence_distribution"]["low_confidence"] == 1

    def test_risk_assessment_levels(self):
        """Test risk assessment text for different score ranges."""
        reporter = MITREExecutiveDashboardReporter()

        # Test different score ranges
        assert "SEVERE" in reporter._get_risk_assessment(85)
        assert "HIGH" in reporter._get_risk_assessment(60)
        assert "ELEVATED" in reporter._get_risk_assessment(35)
        assert "LOW" in reporter._get_risk_assessment(10)
        assert "NORMAL" in reporter._get_risk_assessment(0)

    def test_event_id_generation_uniqueness(self):
        """Test that event IDs are unique for different events."""
        reporter = MITREExecutiveDashboardReporter()

        event1 = reporter.add_threat_event("T1566", "1.1.1.1", "srv", "Test 1")
        event2 = reporter.add_threat_event("T1566", "1.1.1.1", "srv", "Test 2")

        assert event1.event_id != event2.event_id

    def test_tactic_weights_application(self):
        """Test that tactic weights properly influence risk scoring."""
        reporter = MITREExecutiveDashboardReporter()

        # Impact has highest weight (2.0), should produce higher score
        reporter.add_threat_event("T1486", "1.1.1.1", "srv", "Ransomware - Impact")
        impact_score = reporter.calculate_overall_risk_score()

        reporter2 = MITREExecutiveDashboardReporter()
        reporter2.add_threat_event("T1083", "1.1.1.1", "srv", "Discovery")
        discovery_score = reporter2.calculate_overall_risk_score()

        # Impact should score higher than Discovery for same confidence
        assert impact_score > discovery_score

    def test_full_integration_workflow(self):
        """Test complete end-to-end workflow simulation."""
        # Simulate a real security operations center workflow
        reporter = MITREExecutiveDashboardReporter("Global Enterprise Security")

        # Simulate SIEM feed ingestion
        siem_events = [
            {"technique_id": "T1566.001", "source_ip": "203.0.113.45", "destination": "email-gateway", "description": "Malicious DOCX attachment", "confidence_score": 0.97},
            {"technique_id": "T1059.001", "source_ip": "192.168.1.107", "destination": "finance-ws", "description": "Obfuscated PowerShell execution", "confidence_score": 0.91},
            {"technique_id": "T1555", "source_ip": "192.168.1.23", "destination": "domain-controller", "description": "Mimikatz credential access", "confidence_score": 0.99},
            {"technique_id": "T1041", "source_ip": "192.168.1.55", "destination": "database-prod", "description": "Large outbound transfer", "confidence_score": 0.84},
            {"technique_id": "T1486", "source_ip": "192.168.1.88", "destination": "file-server", "description": "Ransomware file extension changes", "confidence_score": 0.93},
            {"technique_id": "T1083", "source_ip": "192.168.1.12", "destination": "workstation-12", "description": "Directory enumeration", "confidence_score": 0.72},
            {"technique_id": "T1046", "source_ip": "198.51.100.22", "destination": "dmz-servers", "description": "Port scanning detected", "confidence_score": 0.65},
        ]

        success, failed = reporter.batch_add_events(siem_events)
        assert success == 7
        assert failed == 0

        # Generate executive report
        summary = reporter.generate_executive_summary(window_hours=1)

        # Verify report integrity
        assert summary.total_threats == 7
        assert summary.overall_risk_score > 50  # Should be elevated with critical threats

        # Verify JSON export
        json_report = reporter.export_json_report(summary)
        parsed = json.loads(json_report)
        assert parsed["executive_summary"]["total_threats"] == 7

        # Verify text report
        text_report = reporter.generate_text_summary(summary)
        assert len(text_report) > 500  # Substantial report generated

        print("\n" + "=" * 70)
        print("✓ FULL INTEGRATION TEST PASSED")
        print(f"  Events Processed: {success}")
        print(f"  Overall Risk Score: {summary.overall_risk_score}/100")
        print(f"  Report ID: {summary.report_id}")
        print("=" * 70)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
