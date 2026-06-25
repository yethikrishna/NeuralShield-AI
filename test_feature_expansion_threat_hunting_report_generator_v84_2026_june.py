"""
Test suite for Threat Hunting Report Generator (v84)
Dimension A - Feature Expansion

Tests verify:
- Report creation and management
- Finding addition with MITRE mapping
- Evidence tracking
- Executive summary generation
- Export functionality (JSON, Markdown)
- All existing tests continue to pass
"""

import os
import sys
import json
import tempfile
import shutil
from pathlib import Path

# Add neural_shield to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from feature_expansion_threat_hunting_report_generator_v84_2026_june import (
    ThreatHuntingReportGenerator,
    SeverityLevel,
    MITRECategory,
    ReportStatus
)


def test_report_creation():
    """Test basic report creation"""
    with tempfile.TemporaryDirectory() as tmpdir:
        generator = ThreatHuntingReportGenerator(output_dir=tmpdir)
        
        report_id = generator.create_report(
            title="Test Threat Hunting Report",
            description="Test report for validation",
            hunt_scope={"time_window": "24h", "assets": ["llm-api-01"]}
        )
        
        assert report_id is not None
        assert report_id.startswith("THR-")
        
        reports = generator.list_reports()
        assert len(reports) == 1
        assert reports[0]["report_id"] == report_id
        assert reports[0]["title"] == "Test Threat Hunting Report"
        
        report = generator.get_report(report_id)
        assert report is not None
        assert report.status == ReportStatus.DRAFT
        assert report.executive_summary.total_findings == 0
        
        print("✓ test_report_creation passed")


def test_add_finding():
    """Test adding findings to a report"""
    with tempfile.TemporaryDirectory() as tmpdir:
        generator = ThreatHuntingReportGenerator(output_dir=tmpdir)
        report_id = generator.create_report("Test Findings Report")
        
        finding_id = generator.add_finding(
            report_id=report_id,
            title="Prompt Injection Attempt Detected",
            description="Multiple obfuscated prompt injection patterns identified in user inputs",
            severity=SeverityLevel.HIGH,
            mitre_technique="T1059",
            mitre_tactic=MITRECategory.EXECUTION,
            confidence=0.89,
            remediation_steps=[
                "Enable enhanced input validation",
                "Deploy contextual analysis",
                "Update signature database"
            ]
        )
        
        assert finding_id is not None
        assert finding_id.startswith("FIND-")
        
        report = generator.get_report(report_id)
        assert len(report.findings) == 1
        assert report.findings[0].finding_id == finding_id
        assert report.findings[0].severity == SeverityLevel.HIGH
        assert report.executive_summary.total_findings == 1
        assert report.executive_summary.high_findings == 1
        assert report.executive_summary.risk_score == 5
        
        print("✓ test_add_finding passed")


def test_add_evidence():
    """Test adding evidence to findings"""
    with tempfile.TemporaryDirectory() as tmpdir:
        generator = ThreatHuntingReportGenerator(output_dir=tmpdir)
        report_id = generator.create_report("Test Evidence Report")
        
        finding_id = generator.add_finding(
            report_id=report_id,
            title="Context Boundary Violation",
            description="System prompt leakage attempt detected",
            severity=SeverityLevel.CRITICAL,
            mitre_technique="T1552",
            mitre_tactic=MITRECategory.CREDENTIAL_ACCESS,
            confidence=0.95
        )
        
        evidence_id = generator.add_evidence(
            report_id=report_id,
            finding_id=finding_id,
            source="Prompt Embedding Analyzer",
            description="Cosine similarity anomaly detected: 0.92 correlation with known attack patterns",
            raw_data="embedding_similarity: 0.92, token_count: 1247",
            confidence=0.95
        )
        
        assert evidence_id is not None
        assert evidence_id.startswith("EVID-")
        
        report = generator.get_report(report_id)
        assert len(report.findings[0].evidence) == 1
        assert report.findings[0].evidence[0].evidence_id == evidence_id
        assert report.executive_summary.critical_findings == 1
        assert report.executive_summary.risk_score == 10
        
        print("✓ test_add_evidence passed")


def test_executive_summary_generation():
    """Test automatic executive summary generation"""
    with tempfile.TemporaryDirectory() as tmpdir:
        generator = ThreatHuntingReportGenerator(output_dir=tmpdir)
        report_id = generator.create_report("Executive Summary Test")
        
        # Add multiple findings of varying severity
        generator.add_finding(
            report_id=report_id,
            title="Critical: System Prompt Leakage",
            severity=SeverityLevel.CRITICAL,
            description="Full system prompt extracted",
            mitre_technique="T1552",
            mitre_tactic=MITRECategory.CREDENTIAL_ACCESS,
            confidence=0.98
        )
        
        generator.add_finding(
            report_id=report_id,
            title="High: Jailbreak Attempt",
            severity=SeverityLevel.HIGH,
            description="DAN-style jailbreak pattern detected",
            mitre_technique="T1498",
            mitre_tactic=MITRECategory.DEFENSE_EVASION,
            confidence=0.85
        )
        
        generator.add_finding(
            report_id=report_id,
            title="Medium: Unusual Query Pattern",
            severity=SeverityLevel.MEDIUM,
            description="Anomalous token sequence detected",
            mitre_technique="T1036",
            mitre_tactic=MITRECategory.DISCOVERY,
            confidence=0.65
        )
        
        report = generator.get_report(report_id)
        
        # Verify counts
        assert report.executive_summary.total_findings == 3
        assert report.executive_summary.critical_findings == 1
        assert report.executive_summary.high_findings == 1
        assert report.executive_summary.medium_findings == 1
        
        # Verify risk score: 10 + 5 + 2 = 17
        assert report.executive_summary.risk_score == 17
        
        # Verify assessment for medium risk (10-24)
        assert "MEDIUM" in report.executive_summary.overall_assessment
        
        # Verify top threats
        assert len(report.executive_summary.top_threats) == 2
        assert "Critical" in report.executive_summary.top_threats[0]
        
        # Verify recommendations
        assert len(report.executive_summary.key_recommendations) > 0
        
        print("✓ test_executive_summary_generation passed")


def test_json_export():
    """Test JSON export functionality"""
    with tempfile.TemporaryDirectory() as tmpdir:
        generator = ThreatHuntingReportGenerator(output_dir=tmpdir)
        report_id = generator.create_report("JSON Export Test")
        
        generator.add_finding(
            report_id=report_id,
            title="Test Finding for Export",
            severity=SeverityLevel.LOW,
            description="Test finding",
            mitre_technique="T1000",
            mitre_tactic=MITRECategory.DISCOVERY,
            confidence=0.5
        )
        
        json_path = generator.export_to_json(report_id)
        
        assert os.path.exists(json_path)
        
        with open(json_path, 'r') as f:
            data = json.load(f)
        
        assert data["report_id"] == report_id
        assert data["title"] == "JSON Export Test"
        assert len(data["findings"]) == 1
        assert data["findings"][0]["severity"] == "LOW"
        assert data["executive_summary"]["total_findings"] == 1
        
        print("✓ test_json_export passed")


def test_markdown_export():
    """Test Markdown export functionality"""
    with tempfile.TemporaryDirectory() as tmpdir:
        generator = ThreatHuntingReportGenerator(output_dir=tmpdir)
        report_id = generator.create_report("Markdown Export Test")
        
        generator.add_finding(
            report_id=report_id,
            title="Test Finding for Markdown",
            severity=SeverityLevel.MEDIUM,
            description="Test finding description",
            mitre_technique="T1001",
            mitre_tactic=MITRECategory.EXECUTION,
            confidence=0.75
        )
        
        md_path = generator.export_to_markdown(report_id)
        
        assert os.path.exists(md_path)
        
        with open(md_path, 'r') as f:
            content = f.read()
        
        assert "# Markdown Export Test" in content
        assert "## Executive Summary" in content
        assert "## Detailed Findings" in content
        assert "Test Finding for Markdown" in content
        assert "## MITRE ATT&CK Coverage" in content
        
        print("✓ test_markdown_export passed")


def test_multiple_findings_mitre_coverage():
    """Test MITRE coverage tracking across multiple tactics"""
    with tempfile.TemporaryDirectory() as tmpdir:
        generator = ThreatHuntingReportGenerator(output_dir=tmpdir)
        report_id = generator.create_report("MITRE Coverage Test")
        
        # Add findings across different tactics
        generator.add_finding(
            report_id=report_id,
            title="Initial Access: Phishing Vector",
            severity=SeverityLevel.HIGH,
            description="Phishing-style prompt detected",
            mitre_technique="T1566",
            mitre_tactic=MITRECategory.INITIAL_ACCESS,
            confidence=0.80
        )
        
        generator.add_finding(
            report_id=report_id,
            title="Execution: Command Injection",
            severity=SeverityLevel.CRITICAL,
            description="Command injection pattern detected",
            mitre_technique="T1059",
            mitre_tactic=MITRECategory.EXECUTION,
            confidence=0.90
        )
        
        generator.add_finding(
            report_id=report_id,
            title="Defense Evasion: Obfuscation",
            severity=SeverityLevel.HIGH,
            description="Base64 obfuscated payload detected",
            mitre_technique="T1027",
            mitre_tactic=MITRECategory.DEFENSE_EVASION,
            confidence=0.85
        )
        
        report = generator.get_report(report_id)
        
        # Verify MITRE coverage
        assert len(report.mitre_coverage) == 3
        assert "Initial Access" in report.mitre_coverage
        assert "Execution" in report.mitre_coverage
        assert "Defense Evasion" in report.mitre_coverage
        assert report.mitre_coverage["Initial Access"] == 1
        
        print("✓ test_multiple_findings_mitre_coverage passed")


def test_invalid_report_id():
    """Test error handling for invalid report IDs"""
    with tempfile.TemporaryDirectory() as tmpdir:
        generator = ThreatHuntingReportGenerator(output_dir=tmpdir)
        
        try:
            generator.add_finding(
                report_id="INVALID-ID",
                title="Test",
                description="Test",
                severity=SeverityLevel.LOW,
                mitre_technique="T1000",
                mitre_tactic=MITRECategory.DISCOVERY
            )
            assert False, "Should have raised ValueError"
        except ValueError as e:
            assert "not found" in str(e)
        
        print("✓ test_invalid_report_id passed")


def test_risk_score_calculation():
    """Test risk score calculation with various severity mixes"""
    with tempfile.TemporaryDirectory() as tmpdir:
        generator = ThreatHuntingReportGenerator(output_dir=tmpdir)
        
        # Test 1: Critical risk (>=50)
        report_id1 = generator.create_report("Critical Risk Test")
        for i in range(6):  # 6 critical = 60
            generator.add_finding(
                report_id=report_id1,
                title=f"Critical Finding {i}",
                severity=SeverityLevel.CRITICAL,
                description="Test",
                mitre_technique="T1000",
                mitre_tactic=MITRECategory.EXECUTION
            )
        report1 = generator.get_report(report_id1)
        assert report1.executive_summary.risk_score == 60
        assert "CRITICAL" in report1.executive_summary.overall_assessment
        
        # Test 2: High risk (25-49)
        report_id2 = generator.create_report("High Risk Test")
        for i in range(5):  # 5 high = 25
            generator.add_finding(
                report_id=report_id2,
                title=f"High Finding {i}",
                severity=SeverityLevel.HIGH,
                description="Test",
                mitre_technique="T1000",
                mitre_tactic=MITRECategory.EXECUTION
            )
        report2 = generator.get_report(report_id2)
        assert report2.executive_summary.risk_score == 25
        assert "HIGH" in report2.executive_summary.overall_assessment
        
        print("✓ test_risk_score_calculation passed")


def test_empty_report():
    """Test behavior with empty report (no findings)"""
    with tempfile.TemporaryDirectory() as tmpdir:
        generator = ThreatHuntingReportGenerator(output_dir=tmpdir)
        report_id = generator.create_report("Empty Report Test")
        
        report = generator.get_report(report_id)
        assert report.executive_summary.total_findings == 0
        assert report.executive_summary.risk_score == 0
        assert "LOW" in report.executive_summary.overall_assessment
        
        # Export should still work
        json_path = generator.export_to_json(report_id)
        assert os.path.exists(json_path)
        
        print("✓ test_empty_report passed")


def test_evidence_without_raw_data():
    """Test evidence creation without raw data"""
    with tempfile.TemporaryDirectory() as tmpdir:
        generator = ThreatHuntingReportGenerator(output_dir=tmpdir)
        report_id = generator.create_report("Evidence Test")
        
        finding_id = generator.add_finding(
            report_id=report_id,
            title="Test Finding",
            severity=SeverityLevel.LOW,
            description="Test",
            mitre_technique="T1000",
            mitre_tactic=MITRECategory.DISCOVERY
        )
        
        evidence_id = generator.add_evidence(
            report_id=report_id,
            finding_id=finding_id,
            source="Test Source",
            description="Test evidence without raw data"
        )
        
        assert evidence_id is not None
        
        report = generator.get_report(report_id)
        assert report.findings[0].evidence[0].raw_data is None
        
        print("✓ test_evidence_without_raw_data passed")


if __name__ == "__main__":
    print("=" * 60)
    print("Running Threat Hunting Report Generator Tests (v84)")
    print("=" * 60)
    
    tests = [
        test_report_creation,
        test_add_finding,
        test_add_evidence,
        test_executive_summary_generation,
        test_json_export,
        test_markdown_export,
        test_multiple_findings_mitre_coverage,
        test_invalid_report_id,
        test_risk_score_calculation,
        test_empty_report,
        test_evidence_without_raw_data
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            print(f"✗ {test.__name__} FAILED: {e}")
            failed += 1
    
    print("=" * 60)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 60)
    
    if failed > 0:
        sys.exit(1)
    else:
        print("\nAll tests passed successfully! ✓")
        sys.exit(0)
