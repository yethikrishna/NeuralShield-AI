"""
Test Suite for Threat Intelligence MITRE ATT&CK Executive Report Generator
June 18, 2026 - Production Release

Tests cover:
- Report generation with various finding severities
- Risk scoring calculations
- Compliance alignment assessment
- Mitigation roadmap generation
- Report integrity hashing
"""

import unittest
from datetime import datetime, timedelta
import json

from neural_shield.threat_intelligence_mitre_executive_reporter_2026_june import (
    ThreatIntelligenceMITREExecutiveReporter,
    MITRETechniqueFinding,
    RiskTrend,
    ComplianceGap,
    ReportSeverity,
    MITRETactic,
    ComplianceFramework,
    create_mitre_executive_reporter,
)


class TestMITREExecutiveReporter(unittest.TestCase):
    """Test suite for MITRE Executive Report Generator."""

    def setUp(self):
        """Set up test reporter instance."""
        self.reporter = create_mitre_executive_reporter("Test Organization")

    def test_reporter_initialization(self):
        """Test reporter initialization with organization name."""
        self.assertEqual(self.reporter.organization_name, "Test Organization")
        self.assertEqual(len(self.reporter._findings), 0)
        self.assertEqual(len(self.reporter._risk_trends), 0)
        self.assertEqual(len(self.reporter._compliance_gaps), 0)

    def test_add_finding(self):
        """Test adding MITRE technique findings."""
        finding = MITRETechniqueFinding(
            technique_id="T1059",
            technique_name="Command and Scripting Interpreter",
            tactic=MITRETactic.EXECUTION,
            severity=ReportSeverity.CRITICAL,
            confidence_score=0.95,
            evidence_count=15,
            first_seen=datetime.utcnow() - timedelta(days=7),
            last_seen=datetime.utcnow(),
            affected_assets=["server-01", "workstation-05"],
            mitigation_recommendations=[
                "Enable application whitelisting",
                "Restrict PowerShell execution",
            ],
        )

        self.reporter.add_finding(finding)
        self.assertEqual(len(self.reporter._findings), 1)
        self.assertEqual(self.reporter._findings[0].technique_id, "T1059")

    def test_risk_score_calculation_no_findings(self):
        """Test risk score calculation with no findings."""
        report = self.reporter.generate_executive_report()
        self.assertEqual(report.executive_summary.overall_risk_score, 0.0)

    def test_risk_score_calculation_critical_only(self):
        """Test risk score with only critical findings."""
        finding = MITRETechniqueFinding(
            technique_id="T1059",
            technique_name="Command and Scripting Interpreter",
            tactic=MITRETactic.EXECUTION,
            severity=ReportSeverity.CRITICAL,
            confidence_score=1.0,
            evidence_count=10,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
        )
        self.reporter.add_finding(finding)

        report = self.reporter.generate_executive_report()
        # Critical with 1.0 confidence should give 10.0 score
        self.assertEqual(report.executive_summary.overall_risk_score, 10.0)

    def test_risk_score_calculation_mixed_severities(self):
        """Test risk score with mixed severity findings."""
        # Critical finding
        self.reporter.add_finding(
            MITRETechniqueFinding(
                technique_id="T1059",
                technique_name="Command Execution",
                tactic=MITRETactic.EXECUTION,
                severity=ReportSeverity.CRITICAL,
                confidence_score=1.0,
                evidence_count=5,
                first_seen=datetime.utcnow(),
                last_seen=datetime.utcnow(),
            )
        )

        # Medium finding
        self.reporter.add_finding(
            MITRETechniqueFinding(
                technique_id="T1087",
                technique_name="Account Discovery",
                tactic=MITRETactic.DISCOVERY,
                severity=ReportSeverity.MEDIUM,
                confidence_score=0.8,
                evidence_count=3,
                first_seen=datetime.utcnow(),
                last_seen=datetime.utcnow(),
            )
        )

        report = self.reporter.generate_executive_report()
        # Should be between 4.0 and 10.0
        self.assertGreater(report.executive_summary.overall_risk_score, 4.0)
        self.assertLessEqual(report.executive_summary.overall_risk_score, 10.0)

    def test_top_threat_vectors(self):
        """Test top threat vector identification."""
        # Add multiple findings across different tactics
        for i in range(3):
            self.reporter.add_finding(
                MITRETechniqueFinding(
                    technique_id=f"T100{i}",
                    technique_name=f"Test Technique {i}",
                    tactic=MITRETactic.INITIAL_ACCESS,
                    severity=ReportSeverity.HIGH,
                    confidence_score=0.9,
                    evidence_count=5,
                    first_seen=datetime.utcnow(),
                    last_seen=datetime.utcnow(),
                )
            )

        self.reporter.add_finding(
            MITRETechniqueFinding(
                technique_id="T1059",
                technique_name="Command Execution",
                tactic=MITRETactic.EXECUTION,
                severity=ReportSeverity.CRITICAL,
                confidence_score=1.0,
                evidence_count=10,
                first_seen=datetime.utcnow(),
                last_seen=datetime.utcnow(),
            )
        )

        report = self.reporter.generate_executive_report()
        top_vectors = report.executive_summary.top_threat_vectors

        self.assertGreater(len(top_vectors), 0)
        # Execution should be top due to critical severity multiplier
        self.assertIn("Execution", top_vectors)
        self.assertIn("Initial Access", top_vectors)

    def test_key_recommendations_generation(self):
        """Test generation of prioritized recommendations."""
        # Add critical finding
        self.reporter.add_finding(
            MITRETechniqueFinding(
                technique_id="T1059",
                technique_name="Command Execution",
                tactic=MITRETactic.EXECUTION,
                severity=ReportSeverity.CRITICAL,
                confidence_score=0.95,
                evidence_count=10,
                first_seen=datetime.utcnow(),
                last_seen=datetime.utcnow(),
                mitigation_recommendations=[
                    "Implement application control policies",
                    "Audit PowerShell usage",
                ],
            )
        )

        report = self.reporter.generate_executive_report()
        recommendations = report.executive_summary.key_recommendations

        self.assertGreater(len(recommendations), 0)
        # Should contain immediate action recommendation
        self.assertTrue(
            any("IMMEDIATE" in rec for rec in recommendations)
        )

    def test_compliance_alignment_no_gaps(self):
        """Test compliance score with no gaps identified."""
        report = self.reporter.generate_executive_report()
        # Default high score when no gaps
        self.assertEqual(report.executive_summary.compliance_alignment_score, 95.0)

    def test_compliance_alignment_with_gaps(self):
        """Test compliance score calculation with gaps."""
        self.reporter.add_compliance_gap(
            ComplianceGap(
                framework=ComplianceFramework.NIST_SP_800_53,
                control_id="AC-2",
                control_name="Account Management",
                gap_description="Missing MFA enforcement",
                severity=ReportSeverity.HIGH,
                remediation_steps=["Enable MFA for all accounts"],
            )
        )

        report = self.reporter.generate_executive_report()
        # Should be less than 100 due to penalty
        self.assertLess(report.executive_summary.compliance_alignment_score, 100.0)
        self.assertGreater(report.executive_summary.compliance_alignment_score, 0.0)

    def test_mitigation_roadmap_structure(self):
        """Test mitigation roadmap time-phased structure."""
        self.reporter.add_finding(
            MITRETechniqueFinding(
                technique_id="T1059",
                technique_name="Command Execution",
                tactic=MITRETactic.EXECUTION,
                severity=ReportSeverity.CRITICAL,
                confidence_score=0.9,
                evidence_count=5,
                first_seen=datetime.utcnow(),
                last_seen=datetime.utcnow(),
                mitigation_recommendations=["Fix immediately"],
            )
        )

        self.reporter.add_finding(
            MITRETechniqueFinding(
                technique_id="T1087",
                technique_name="Discovery",
                tactic=MITRETactic.DISCOVERY,
                severity=ReportSeverity.LOW,
                confidence_score=0.7,
                evidence_count=2,
                first_seen=datetime.utcnow(),
                last_seen=datetime.utcnow(),
                mitigation_recommendations=["Long term improvement"],
            )
        )

        report = self.reporter.generate_executive_report()
        roadmap = report.mitigation_roadmap

        # Verify all time phases exist
        self.assertIn("IMMEDIATE (0-3 days)", roadmap)
        self.assertIn("SHORT_TERM (1-2 weeks)", roadmap)
        self.assertIn("MEDIUM_TERM (1-3 months)", roadmap)
        self.assertIn("LONG_TERM (3-12 months)", roadmap)

    def test_report_hash_generation(self):
        """Test report integrity hash generation."""
        report = self.reporter.generate_executive_report()

        # Hash should be 32 character hex string
        self.assertEqual(len(report.report_hash), 32)
        # Verify it's valid hex
        int(report.report_hash, 16)  # Should not raise ValueError

    def test_report_json_export(self):
        """Test JSON export functionality."""
        self.reporter.add_finding(
            MITRETechniqueFinding(
                technique_id="T1059",
                technique_name="Command Execution",
                tactic=MITRETactic.EXECUTION,
                severity=ReportSeverity.HIGH,
                confidence_score=0.85,
                evidence_count=5,
                first_seen=datetime.utcnow(),
                last_seen=datetime.utcnow(),
            )
        )

        report = self.reporter.generate_executive_report()
        json_output = self.reporter.export_report_json(report)

        # Verify valid JSON
        parsed = json.loads(json_output)
        self.assertIn("report_id", parsed)
        self.assertIn("executive_summary", parsed)
        self.assertIn("report_hash", parsed)
        self.assertEqual(parsed["organization"], "Test Organization")

    def test_risk_trend_tracking(self):
        """Test historical risk trend tracking."""
        for i in range(7):
            self.reporter.add_risk_trend(
                RiskTrend(
                    date=datetime.utcnow() - timedelta(days=i),
                    risk_score=5.0 + i * 0.5,
                    finding_count=10 + i,
                    critical_count=2,
                )
            )

        report = self.reporter.generate_executive_report()
        self.assertEqual(len(report.risk_trends), 7)

    def test_severity_counting(self):
        """Test accurate severity counting in executive summary."""
        # Add 2 critical, 3 high, 1 medium
        for _ in range(2):
            self.reporter.add_finding(
                MITRETechniqueFinding(
                    technique_id="T1001",
                    technique_name="Test",
                    tactic=MITRETactic.EXECUTION,
                    severity=ReportSeverity.CRITICAL,
                    confidence_score=0.9,
                    evidence_count=1,
                    first_seen=datetime.utcnow(),
                    last_seen=datetime.utcnow(),
                )
            )

        for _ in range(3):
            self.reporter.add_finding(
                MITRETechniqueFinding(
                    technique_id="T1002",
                    technique_name="Test",
                    tactic=MITRETactic.DISCOVERY,
                    severity=ReportSeverity.HIGH,
                    confidence_score=0.8,
                    evidence_count=1,
                    first_seen=datetime.utcnow(),
                    last_seen=datetime.utcnow(),
                )
            )

        self.reporter.add_finding(
            MITRETechniqueFinding(
                technique_id="T1003",
                technique_name="Test",
                tactic=MITRETactic.COLLECTION,
                severity=ReportSeverity.MEDIUM,
                confidence_score=0.7,
                evidence_count=1,
                first_seen=datetime.utcnow(),
                last_seen=datetime.utcnow(),
            )
        )

        report = self.reporter.generate_executive_report()

        self.assertEqual(report.executive_summary.critical_findings, 2)
        self.assertEqual(report.executive_summary.high_findings, 3)
        self.assertEqual(report.executive_summary.medium_findings, 1)
        self.assertEqual(report.executive_summary.total_findings, 6)

    def test_factory_function(self):
        """Test factory function creates valid instance."""
        reporter = create_mitre_executive_reporter("Acme Corp")
        self.assertIsInstance(reporter, ThreatIntelligenceMITREExecutiveReporter)
        self.assertEqual(reporter.organization_name, "Acme Corp")


if __name__ == "__main__":
    unittest.main(verbosity=2)
