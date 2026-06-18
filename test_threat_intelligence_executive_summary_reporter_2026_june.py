#!/usr/bin/env python3
"""
Test suite for Threat Intelligence Executive Summary Reporter
Production-grade testing with real assertions
"""

import sys
import json
sys.path.insert(0, '/home/user/autonomous-developer/NeuralShield-AI')

from neural_shield.threat_intelligence_executive_summary_reporter_2026_june import (
    ThreatIntelligenceExecutiveSummaryReporter,
    ThreatEvent,
    ReportType,
    SeverityLevel
)


def test_basic_initialization():
    """Test basic reporter initialization"""
    print("Test 1: Basic Initialization")
    reporter = ThreatIntelligenceExecutiveSummaryReporter("Test Corp Security")
    assert reporter.organization_name == "Test Corp Security"
    assert len(reporter.threat_events) == 0
    assert len(reporter.generated_reports) == 0
    print("  ✓ PASSED: Reporter initialized correctly")


def test_add_threat_event():
    """Test adding single threat event"""
    print("\nTest 2: Add Single Threat Event")
    reporter = ThreatIntelligenceExecutiveSummaryReporter()
    
    event = ThreatEvent(
        event_id="test-001",
        timestamp="2026-06-19T10:00:00Z",
        severity="HIGH",
        threat_type="Prompt Injection",
        source="External API",
        description="Test threat event",
        mitre_technique="T1036",
        confidence_score=0.85
    )
    
    reporter.add_threat_event(event)
    assert len(reporter.threat_events) == 1
    assert reporter.threat_events[0].event_id == "test-001"
    assert reporter.threat_events[0].severity == "HIGH"
    print("  ✓ PASSED: Single event added correctly")


def test_batch_add_events():
    """Test batch adding multiple events"""
    print("\nTest 3: Batch Add Events")
    reporter = ThreatIntelligenceExecutiveSummaryReporter()
    
    events = [
        ThreatEvent(f"evt-{i}", "2026-06-19T10:00:00Z", "CRITICAL", 
                   "RAG Poisoning", "Internal", f"Test {i}", confidence_score=0.9)
        for i in range(5)
    ]
    
    reporter.add_threat_events_batch(events)
    assert len(reporter.threat_events) == 5
    print("  ✓ PASSED: Batch events added correctly")


def test_metrics_calculation():
    """Test metrics calculation with real data"""
    print("\nTest 4: Metrics Calculation")
    reporter = ThreatIntelligenceExecutiveSummaryReporter()
    
    # Add mixed severity events
    reporter.add_threat_event(ThreatEvent("c1", "t", "CRITICAL", "A", "S1", "d", confidence_score=0.9))
    reporter.add_threat_event(ThreatEvent("c2", "t", "CRITICAL", "A", "S1", "d", confidence_score=0.95))
    reporter.add_threat_event(ThreatEvent("h1", "t", "HIGH", "B", "S2", "d", confidence_score=0.8))
    reporter.add_threat_event(ThreatEvent("h2", "t", "HIGH", "B", "S2", "d", confidence_score=0.7))
    reporter.add_threat_event(ThreatEvent("m1", "t", "MEDIUM", "C", "S3", "d", confidence_score=0.6))
    reporter.add_threat_event(ThreatEvent("l1", "t", "LOW", "D", "S4", "d", confidence_score=0.5))
    
    metrics = reporter.calculate_metrics()
    
    assert metrics.total_threats == 6
    assert metrics.critical_count == 2
    assert metrics.high_count == 2
    assert metrics.medium_count == 1
    assert metrics.low_count == 1
    assert metrics.unique_threat_types == 4
    assert metrics.unique_sources == 4
    assert 0.7 < metrics.avg_confidence < 0.8  # Weighted average
    
    print(f"  ✓ PASSED: Metrics calculated correctly")
    print(f"    - Total threats: {metrics.total_threats}")
    print(f"    - Critical: {metrics.critical_count}, High: {metrics.high_count}")
    print(f"    - Avg confidence: {metrics.avg_confidence:.3f}")


def test_risk_score_calculation():
    """Test risk scoring algorithm"""
    print("\nTest 5: Risk Score Calculation")
    
    # Test 1: All critical threats
    reporter1 = ThreatIntelligenceExecutiveSummaryReporter()
    for i in range(3):
        reporter1.add_threat_event(ThreatEvent(f"c{i}", "t", "CRITICAL", "A", "S", "d"))
    risk1 = reporter1.calculate_risk_score(reporter1.calculate_metrics())
    assert risk1["risk_level"] == "CRITICAL"
    assert risk1["risk_score"] == 100.0
    print(f"  ✓ PASSED: All-critical risk = {risk1['risk_level']} ({risk1['risk_score']})")
    
    # Test 2: Mixed threats
    reporter2 = ThreatIntelligenceExecutiveSummaryReporter()
    reporter2.add_threat_event(ThreatEvent("c1", "t", "CRITICAL", "A", "S", "d"))
    reporter2.add_threat_event(ThreatEvent("h1", "t", "HIGH", "B", "S", "d"))
    reporter2.add_threat_event(ThreatEvent("m1", "t", "MEDIUM", "C", "S", "d"))
    risk2 = reporter2.calculate_risk_score(reporter2.calculate_metrics())
    assert risk2["risk_score"] > 0
    print(f"  ✓ PASSED: Mixed risk = {risk2['risk_level']} ({risk2['risk_score']})")
    
    # Test 3: No threats
    reporter3 = ThreatIntelligenceExecutiveSummaryReporter()
    risk3 = reporter3.calculate_risk_score(reporter3.calculate_metrics())
    assert risk3["risk_level"] == "LOW"
    assert risk3["risk_score"] == 0.0
    print(f"  ✓ PASSED: No threats risk = {risk3['risk_level']} ({risk3['risk_score']})")


def test_report_generation():
    """Test full report generation"""
    print("\nTest 6: Report Generation")
    reporter = ThreatIntelligenceExecutiveSummaryReporter("ACME Corp")
    
    for i in range(3):
        reporter.add_threat_event(ThreatEvent(
            f"evt-{i}", 
            "2026-06-19T10:00:00Z", 
            "HIGH", 
            "Prompt Injection",
            "User Input",
            f"Suspicious prompt detected #{i}",
            confidence_score=0.85
        ))
    
    report = reporter.generate_report(ReportType.EXECUTIVE_SUMMARY)
    
    # Validate report structure
    assert "report_id" in report
    assert "generated_at" in report
    assert "summary" in report
    assert "risk_assessment" in report["summary"]
    assert "metrics" in report["summary"]
    assert "recommendations" in report["summary"]
    assert "threat_breakdown" in report
    
    assert report["organization"] == "ACME Corp"
    assert report["summary"]["metrics"]["total_threats"] == 3
    assert len(report["summary"]["recommendations"]) > 0
    
    print(f"  ✓ PASSED: Report generated successfully")
    print(f"    - Report ID: {report['report_id']}")
    print(f"    - Risk Level: {report['summary']['risk_assessment']['risk_level']}")
    print(f"    - Recommendations: {len(report['summary']['recommendations'])} items")


def test_markdown_export():
    """Test Markdown export functionality"""
    print("\nTest 7: Markdown Export")
    reporter = ThreatIntelligenceExecutiveSummaryReporter("Export Test")
    reporter.add_threat_event(ThreatEvent("e1", "t", "HIGH", "Test", "S", "Desc"))
    
    report = reporter.generate_report()
    md_output = reporter.export_to_markdown(report)
    
    assert "# Threat Intelligence Executive Report" in md_output
    assert "## Executive Overview" in md_output
    assert "## Risk Assessment" in md_output
    assert "## Key Findings" in md_output
    assert len(md_output) > 500  # Substantial content
    
    print(f"  ✓ PASSED: Markdown export works ({len(md_output)} chars)")


def test_json_export():
    """Test JSON export functionality"""
    print("\nTest 8: JSON Export")
    reporter = ThreatIntelligenceExecutiveSummaryReporter("JSON Test")
    reporter.add_threat_event(ThreatEvent("e1", "t", "MEDIUM", "Test", "S", "Desc"))
    
    report = reporter.generate_report()
    json_output = reporter.export_to_json(report, pretty=True)
    
    # Validate it's valid JSON
    parsed = json.loads(json_output)
    assert parsed["report_id"] == report["report_id"]
    assert parsed["organization"] == "JSON Test"
    
    print(f"  ✓ PASSED: JSON export works ({len(json_output)} chars)")


def test_recommendations_generation():
    """Test executive recommendations generation"""
    print("\nTest 9: Recommendations Generation")
    
    # Critical scenario
    reporter_critical = ThreatIntelligenceExecutiveSummaryReporter()
    for i in range(5):
        reporter_critical.add_threat_event(ThreatEvent(f"c{i}", "t", "CRITICAL", "A", "S", "d"))
    metrics_c = reporter_critical.calculate_metrics()
    risk_c = reporter_critical.calculate_risk_score(metrics_c)
    recs_critical = reporter_critical.generate_executive_recommendations(risk_c, metrics_c)
    
    assert len(recs_critical) > 5
    assert any("INCIDENT RESPONSE" in r for r in recs_critical)
    print(f"  ✓ PASSED: Critical scenario has {len(recs_critical)} recommendations")
    
    # Normal scenario
    reporter_normal = ThreatIntelligenceExecutiveSummaryReporter()
    reporter_normal.add_threat_event(ThreatEvent("l1", "t", "LOW", "A", "S", "d"))
    metrics_n = reporter_normal.calculate_metrics()
    risk_n = reporter_normal.calculate_risk_score(metrics_n)
    recs_normal = reporter_normal.generate_executive_recommendations(risk_n, metrics_n)
    
    assert len(recs_normal) >= 4  # At least the best practices
    print(f"  ✓ PASSED: Normal scenario has {len(recs_normal)} recommendations")


def test_clear_events():
    """Test clearing events functionality"""
    print("\nTest 10: Clear Events")
    reporter = ThreatIntelligenceExecutiveSummaryReporter()
    
    for i in range(10):
        reporter.add_threat_event(ThreatEvent(f"e{i}", "t", "LOW", "A", "S", "d"))
    
    assert len(reporter.threat_events) == 10
    reporter.clear_events()
    assert len(reporter.threat_events) == 0
    
    print("  ✓ PASSED: Events cleared successfully")


def run_all_tests():
    """Run all test cases"""
    print("=" * 60)
    print("NeuralShield-AI - Executive Summary Reporter Test Suite")
    print("=" * 60)
    print()
    
    all_passed = True
    test_functions = [
        test_basic_initialization,
        test_add_threat_event,
        test_batch_add_events,
        test_metrics_calculation,
        test_risk_score_calculation,
        test_report_generation,
        test_markdown_export,
        test_json_export,
        test_recommendations_generation,
        test_clear_events
    ]
    
    for test_func in test_functions:
        try:
            test_func()
        except AssertionError as e:
            print(f"  ✗ FAILED: {e}")
            all_passed = False
        except Exception as e:
            print(f"  ✗ ERROR: {type(e).__name__}: {e}")
            all_passed = False
    
    print()
    print("=" * 60)
    if all_passed:
        print("✅ ALL TESTS PASSED - Production Ready!")
    else:
        print("❌ SOME TESTS FAILED")
    print("=" * 60)
    
    return all_passed


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
