#!/usr/bin/env python3
"""
Test suite for Threat Intelligence MITRE Executive Summary Reporter
June 18, 2026 - Production Tests
Real working tests with actual test data and assertions
"""
import sys
import json
import importlib.util

# Direct module import to bypass __init__.py issues
spec = importlib.util.spec_from_file_location(
    "mitre_reporter",
    "/home/user/autonomous-developer/NeuralShield-AI/neural_shield/threat_intelligence_mitre_executive_summary_reporter_2026_june.py"
)
mitre_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mitre_module)

ThreatIntelligenceMITREExecutiveReporter = mitre_module.ThreatIntelligenceMITREExecutiveReporter
create_mitre_executive_reporter = mitre_module.create_mitre_executive_reporter
ExecutiveReportResult = mitre_module.ExecutiveReportResult
ExecutiveAudience = mitre_module.ExecutiveAudience
ReportPriority = mitre_module.ReportPriority
MITREThreatSummary = mitre_module.MITREThreatSummary
ExecutiveRecommendation = mitre_module.ExecutiveRecommendation


def test_reporter_initialization():
    """Test reporter initialization with different audiences"""
    print("Test 1: Reporter Initialization")
    
    # Test default initialization
    reporter = ThreatIntelligenceMITREExecutiveReporter()
    assert reporter.version == "2026.06.18.prod"
    assert reporter.target_audience == ExecutiveAudience.CISO
    assert len(reporter.mitre_tactics) == 14
    print("  ✓ Default initialization works")
    
    # Test with specific audience
    reporter_board = ThreatIntelligenceMITREExecutiveReporter(ExecutiveAudience.BOARD)
    assert reporter_board.target_audience == ExecutiveAudience.BOARD
    print("  ✓ Custom audience initialization works")
    
    # Test factory function
    reporter_factory = create_mitre_executive_reporter(ExecutiveAudience.CEO)
    assert isinstance(reporter_factory, ThreatIntelligenceMITREExecutiveReporter)
    assert reporter_factory.target_audience == ExecutiveAudience.CEO
    print("  ✓ Factory function works correctly")
    
    print("  ✓ All initialization tests PASSED\n")


def test_report_generation_with_sample_data():
    """Test report generation with realistic threat data"""
    print("Test 2: Report Generation with Sample Threat Data")
    
    reporter = ThreatIntelligenceMITREExecutiveReporter()
    
    # Realistic sample threat data with MITRE mappings
    sample_threats = [
        {
            "mitre_tactic_id": "TA0006",
            "mitre_technique_id": "T1003",
            "mitre_technique_name": "OS Credential Dumping",
            "severity": "critical",
            "category": "credential_access",
            "attack_vector": "phishing",
            "risk_score": 0.95
        },
        {
            "mitre_tactic_id": "TA0001",
            "mitre_technique_id": "T1566",
            "mitre_technique_name": "Phishing",
            "severity": "high",
            "category": "initial_access",
            "attack_vector": "email",
            "risk_score": 0.85
        },
        {
            "mitre_tactic_id": "TA0005",
            "mitre_technique_id": "T1027",
            "mitre_technique_name": "Obfuscated Files",
            "severity": "high",
            "category": "defense_evasion",
            "attack_vector": "malware",
            "risk_score": 0.80
        },
        {
            "mitre_tactic_id": "TA0010",
            "mitre_technique_id": "T1041",
            "mitre_technique_name": "Exfiltration Over C2",
            "severity": "critical",
            "category": "data_exfiltration",
            "attack_vector": "c2_channel",
            "risk_score": 0.98
        },
        {
            "mitre_tactic_id": "TA0002",
            "mitre_technique_id": "T1059",
            "mitre_technique_name": "Command and Scripting",
            "severity": "medium",
            "category": "execution",
            "attack_vector": "powershell",
            "risk_score": 0.65
        },
        {
            "mitre_tactic_id": "TA0007",
            "mitre_technique_id": "T1083",
            "mitre_technique_name": "File and Directory Discovery",
            "severity": "low",
            "category": "discovery",
            "attack_vector": "internal_scan",
            "risk_score": 0.40
        }
    ]
    
    report = reporter.generate_executive_report(sample_threats, period_days=7)
    
    # Verify report structure
    assert isinstance(report, ExecutiveReportResult)
    assert report.total_threats_detected == 6
    assert report.critical_threats == 2
    assert report.high_threats == 2
    print(f"  ✓ Generated report with {report.total_threats_detected} threats")
    print(f"  ✓ Critical: {report.critical_threats}, High: {report.high_threats}")
    
    # Verify security score calculation
    assert 0 <= report.overall_security_score <= 100
    print(f"  ✓ Overall Security Score: {report.overall_security_score}/100")
    
    # Verify risk level
    assert isinstance(report.overall_risk_level, ReportPriority)
    print(f"  ✓ Overall Risk Level: {report.overall_risk_level.value}")
    
    # Verify executive summary exists
    assert len(report.executive_summary) > 0
    print("  ✓ Executive summary generated")
    
    # Verify MITRE summaries
    assert len(report.mitre_threat_summaries) > 0
    print(f"  ✓ Generated {len(report.mitre_threat_summaries)} MITRE tactic summaries")
    
    # Verify top attack vectors
    assert len(report.top_attack_vectors) > 0
    print(f"  ✓ Identified {len(report.top_attack_vectors)} top attack vectors")
    
    print("  ✓ All report generation tests PASSED\n")


def test_mitre_threat_summary_generation():
    """Test MITRE ATT&CK tactic summary generation"""
    print("Test 3: MITRE Threat Summary Generation")
    
    reporter = ThreatIntelligenceMITREExecutiveReporter()
    
    threats = [
        {"mitre_tactic_id": "TA0006", "mitre_technique_id": "T1003", 
         "mitre_technique_name": "Credential Dumping", "severity": "critical",
         "category": "credential", "attack_vector": "phishing", "risk_score": 0.9},
        {"mitre_tactic_id": "TA0006", "mitre_technique_id": "T1110", 
         "mitre_technique_name": "Brute Force", "severity": "high",
         "category": "credential", "attack_vector": "ssh", "risk_score": 0.8},
        {"mitre_tactic_id": "TA0001", "mitre_technique_id": "T1566", 
         "mitre_technique_name": "Phishing", "severity": "medium",
         "category": "initial", "attack_vector": "email", "risk_score": 0.6},
    ]
    
    report = reporter.generate_executive_report(threats)
    
    # Find credential access tactic
    cred_summary = None
    for summary in report.mitre_threat_summaries:
        if summary.tactic_id == "TA0006":
            cred_summary = summary
            break
    
    assert cred_summary is not None
    assert cred_summary.tactic_name == "Credential Access"
    assert cred_summary.threat_count == 2
    assert cred_summary.technique_count == 2
    assert cred_summary.risk_score > 0
    print(f"  ✓ Credential Access tactic: {cred_summary.threat_count} threats, {cred_summary.technique_count} techniques")
    print(f"  ✓ Risk score: {cred_summary.risk_score}")
    
    # Verify sorting (highest risk first)
    risk_scores = [s.risk_score for s in report.mitre_threat_summaries]
    assert risk_scores == sorted(risk_scores, reverse=True)
    print("  ✓ MITRE summaries sorted by risk score descending")
    
    print("  ✓ All MITRE summary tests PASSED\n")


def test_recommendations_generation():
    """Test priority-based recommendation generation"""
    print("Test 4: Recommendations Generation")
    
    reporter = ThreatIntelligenceMITREExecutiveReporter()
    
    # Test with critical threats
    critical_threats = [
        {"mitre_tactic_id": "TA0006", "mitre_technique_id": "T1003",
         "mitre_technique_name": "Credential Dumping", "severity": "critical",
         "category": "credential", "attack_vector": "phishing", "risk_score": 0.95},
    ]
    
    report = reporter.generate_executive_report(critical_threats)
    
    # Verify recommendations exist
    assert len(report.recommendations) > 0
    print(f"  ✓ Generated {len(report.recommendations)} recommendations")
    
    # Verify critical actions
    assert len(report.critical_actions_required) > 0
    print(f"  ✓ Critical actions required: {len(report.critical_actions_required)}")
    
    # Verify all priorities are covered
    priorities_found = set()
    for rec in report.recommendations:
        priorities_found.add(rec.priority)
        assert isinstance(rec, ExecutiveRecommendation)
        assert len(rec.title) > 0
        assert len(rec.description) > 0
    
    print(f"  ✓ Recommendations cover priorities: {[p.value for p in priorities_found]}")
    
    # Verify recommendation structure
    first_rec = report.recommendations[0]
    assert first_rec.priority in [ReportPriority.CRITICAL, ReportPriority.HIGH]
    assert len(first_rec.estimated_effort) > 0
    assert len(first_rec.business_impact) > 0
    assert len(first_rec.implementation_timeline) > 0
    assert len(first_rec.responsible_team) > 0
    print("  ✓ All recommendation fields populated correctly")
    
    print("  ✓ All recommendations tests PASSED\n")


def test_compliance_assessment():
    """Test compliance alignment assessment"""
    print("Test 5: Compliance Assessment")
    
    reporter = ThreatIntelligenceMITREExecutiveReporter()
    
    threats = [
        {"mitre_tactic_id": "TA0006", "mitre_technique_id": "T1003",
         "mitre_technique_name": "Credential Dumping", "severity": "high",
         "category": "credential", "attack_vector": "phishing", "risk_score": 0.85},
        {"mitre_tactic_id": "TA0010", "mitre_technique_id": "T1041",
         "mitre_technique_name": "Data Exfiltration", "severity": "high",
         "category": "exfiltration", "attack_vector": "c2", "risk_score": 0.9},
    ]
    
    report = reporter.generate_executive_report(threats)
    
    # Verify compliance score
    assert 0 <= report.compliance_alignment_score <= 100
    print(f"  ✓ Compliance alignment score: {report.compliance_alignment_score}%")
    
    # Verify compliance gaps are a list
    assert isinstance(report.compliance_gaps, list)
    print(f"  ✓ Identified {len(report.compliance_gaps)} compliance gaps")
    
    print("  ✓ All compliance assessment tests PASSED\n")


def test_kpis_and_resource_guidance():
    """Test KPI calculation and resource guidance generation"""
    print("Test 6: KPIs and Resource Guidance")
    
    reporter = ThreatIntelligenceMITREExecutiveReporter()
    
    threats = [
        {"mitre_tactic_id": "TA0006", "mitre_technique_id": "T1003",
         "mitre_technique_name": "Credential Dumping", "severity": "critical",
         "category": "credential", "attack_vector": "phishing", "risk_score": 0.95},
        {"mitre_tactic_id": "TA0001", "mitre_technique_id": "T1566",
         "mitre_technique_name": "Phishing", "severity": "high",
         "category": "initial", "attack_vector": "email", "risk_score": 0.8},
        {"mitre_tactic_id": "TA0005", "mitre_technique_id": "T1027",
         "mitre_technique_name": "Obfuscation", "severity": "medium",
         "category": "evasion", "attack_vector": "malware", "risk_score": 0.6},
    ]
    
    report = reporter.generate_executive_report(threats, period_days=7)
    
    # Verify KPIs
    kpis = report.key_performance_indicators
    assert "threats_per_day" in kpis
    assert "critical_percentage" in kpis
    assert "high_plus_percentage" in kpis
    assert "detection_coverage_score" in kpis
    assert "mean_time_to_detect_hours" in kpis
    print(f"  ✓ Threats per day: {kpis['threats_per_day']}")
    print(f"  ✓ Critical threats percentage: {kpis['critical_percentage']}%")
    print(f"  ✓ Detection coverage score: {kpis['detection_coverage_score']}")
    
    # Verify resource guidance
    resource = report.resource_allocation_guidance
    assert "immediate" in resource
    assert "short_term" in resource
    assert "budget" in resource
    print(f"  ✓ Immediate resource guidance: {resource['immediate'][:50]}...")
    print(f"  ✓ Budget guidance: {resource['budget']}")
    
    print("  ✓ All KPI and resource guidance tests PASSED\n")


def test_json_export():
    """Test JSON report export functionality"""
    print("Test 7: JSON Report Export")
    
    reporter = ThreatIntelligenceMITREExecutiveReporter()
    
    threats = [
        {"mitre_tactic_id": "TA0006", "mitre_technique_id": "T1003",
         "mitre_technique_name": "Credential Dumping", "severity": "high",
         "category": "credential", "attack_vector": "phishing", "risk_score": 0.85},
    ]
    
    report = reporter.generate_executive_report(threats)
    json_output = reporter.export_report_json(report)
    
    # Verify valid JSON
    parsed = json.loads(json_output)
    assert parsed["report_id"] == report.report_id
    assert parsed["total_threats_detected"] == report.total_threats_detected
    assert parsed["overall_security_score"] == report.overall_security_score
    print("  ✓ JSON export produces valid JSON")
    print(f"  ✓ Report ID preserved: {parsed['report_id']}")
    print(f"  ✓ JSON output length: {len(json_output)} characters")
    
    print("  ✓ All JSON export tests PASSED\n")


def test_empty_and_edge_cases():
    """Test edge cases including empty threat data"""
    print("Test 8: Edge Cases")
    
    reporter = ThreatIntelligenceMITREExecutiveReporter()
    
    # Test with empty threat list
    empty_report = reporter.generate_executive_report([])
    assert empty_report.total_threats_detected == 0
    assert empty_report.critical_threats == 0
    assert empty_report.high_threats == 0
    assert empty_report.overall_security_score == 95.0  # Perfect score for no threats
    print("  ✓ Empty threat list handled correctly")
    print(f"  ✓ Empty list security score: {empty_report.overall_security_score}")
    
    # Test with historical data
    current = [
        {"mitre_tactic_id": "TA0001", "mitre_technique_id": "T1566",
         "mitre_technique_name": "Phishing", "severity": "medium",
         "category": "initial", "attack_vector": "email", "risk_score": 0.6},
    ]
    historical = [
        {"mitre_tactic_id": "TA0001", "mitre_technique_id": "T1566",
         "mitre_technique_name": "Phishing", "severity": "medium",
         "category": "initial", "attack_vector": "email", "risk_score": 0.6},
        {"mitre_tactic_id": "TA0001", "mitre_technique_id": "T1566",
         "mitre_technique_name": "Phishing", "severity": "medium",
         "category": "initial", "attack_vector": "email", "risk_score": 0.6},
    ]
    
    trend_report = reporter.generate_executive_report(current, historical_data=historical)
    assert "DECREASING" in trend_report.trend_summary
    print("  ✓ Historical trend comparison works")
    print(f"  ✓ Trend summary: {trend_report.trend_summary}")
    
    print("  ✓ All edge case tests PASSED\n")


def run_all_tests():
    """Run all test suites"""
    print("=" * 70)
    print("MITRE Executive Summary Reporter - Production Test Suite")
    print("June 18, 2026 - NeuralShield-AI")
    print("=" * 70 + "\n")
    
    try:
        test_reporter_initialization()
        test_report_generation_with_sample_data()
        test_mitre_threat_summary_generation()
        test_recommendations_generation()
        test_compliance_assessment()
        test_kpis_and_resource_guidance()
        test_json_export()
        test_empty_and_edge_cases()
        
        print("=" * 70)
        print("✓ ALL TESTS PASSED - Production Ready")
        print("=" * 70)
        return True
    except AssertionError as e:
        print(f"\n✗ TEST FAILED: {e}")
        return False
    except Exception as e:
        print(f"\n✗ TEST ERROR: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
