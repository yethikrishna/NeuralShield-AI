#!/usr/bin/env python3
"""
Test Suite for NeuralShield MITRE Heatmap Executive Dashboard
Production-Grade Testing

This test suite validates all core functionality:
- Alert ingestion and deduplication
- MITRE mapping accuracy
- Risk score calculation
- Heatmap generation
- Executive summary generation
- JSON export functionality

Author: NeuralShield AI Team
Version: 1.0.0
Date: June 2026
"""

import json
import os
import sys
import tempfile
from typing import Dict, List, Any

# Add module path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "neural_shield"))

from threat_intelligence_mitre_heatmap_executive_dashboard_2026_june import (
    MITREHeatmapDashboard,
    MITRETactic,
    SeverityLevel,
    create_sample_dashboard,
)


def run_test(test_name: str, test_func) -> Dict[str, Any]:
    """Run a single test and return results"""
    try:
        result = test_func()
        return {
            "test": test_name,
            "passed": True,
            "result": result,
            "error": None,
        }
    except Exception as e:
        return {
            "test": test_name,
            "passed": False,
            "result": None,
            "error": str(e),
        }


def test_dashboard_initialization() -> bool:
    """Test dashboard initialization"""
    dashboard = MITREHeatmapDashboard()
    assert dashboard.alert_cache == {}
    assert len(dashboard.technique_counts) == 0
    assert len(dashboard.tactic_counts) == 0
    return True


def test_single_alert_ingestion() -> bool:
    """Test single alert ingestion"""
    dashboard = MITREHeatmapDashboard()
    alert = {
        "alert_id": "ALT-0001",
        "technique_id": "T1566",
        "severity": "HIGH",
        "timestamp": "2026-06-19T10:00:00Z",
        "source": "test",
    }
    result = dashboard.ingest_alert(alert)
    assert result is True
    assert len(dashboard.alert_cache) == 1
    assert dashboard.technique_counts["T1566"] == 1
    return True


def test_alert_deduplication() -> bool:
    """Test alert deduplication works"""
    dashboard = MITREHeatmapDashboard()
    alert = {
        "alert_id": "ALT-0001",
        "technique_id": "T1566",
        "severity": "HIGH",
        "timestamp": "2026-06-19T10:00:00Z",
    }
    # First ingestion
    result1 = dashboard.ingest_alert(alert)
    # Duplicate ingestion
    result2 = dashboard.ingest_alert(alert)
    
    assert result1 is True
    assert result2 is False  # Duplicate rejected
    assert len(dashboard.alert_cache) == 1
    return True


def test_invalid_alert_rejection() -> bool:
    """Test invalid alerts are rejected"""
    dashboard = MITREHeatmapDashboard()
    
    # Missing required field
    invalid_alert = {
        "alert_id": "ALT-0001",
        "technique_id": "T1566",
        # Missing severity and timestamp
    }
    result = dashboard.ingest_alert(invalid_alert)
    assert result is False
    
    # Unknown technique
    unknown_alert = {
        "alert_id": "ALT-0002",
        "technique_id": "T9999",  # Not in mapping
        "severity": "HIGH",
        "timestamp": "2026-06-19T10:00:00Z",
    }
    result2 = dashboard.ingest_alert(unknown_alert)
    assert result2 is False
    return True


def test_batch_ingestion() -> bool:
    """Test batch alert processing"""
    dashboard = MITREHeatmapDashboard()
    alerts = [
        {"alert_id": f"ALT-{i:04d}", "technique_id": "T1566", 
         "severity": "HIGH", "timestamp": f"2026-06-19T10:{i:02d}:00Z"}
        for i in range(5)
    ]
    stats = dashboard.ingest_alerts_batch(alerts)
    assert stats["success"] == 5
    assert stats["total"] == 5
    assert dashboard.technique_counts["T1566"] == 5
    return True


def test_risk_score_calculation() -> bool:
    """Test risk score calculation"""
    dashboard = MITREHeatmapDashboard()
    
    # Add critical alerts
    for i in range(3):
        dashboard.ingest_alert({
            "alert_id": f"ALT-{i:04d}",
            "technique_id": "T1059",
            "severity": "CRITICAL",
            "timestamp": f"2026-06-19T10:{i:02d}:00Z",
        })
    
    risk_score, level = dashboard.calculate_risk_score("T1059", 3)
    assert risk_score > 0
    assert level in [SeverityLevel.CRITICAL, SeverityLevel.HIGH, SeverityLevel.MEDIUM, SeverityLevel.LOW]
    assert isinstance(risk_score, float)
    return True


def test_heatmap_generation() -> bool:
    """Test heatmap data structure generation"""
    dashboard = MITREHeatmapDashboard()
    
    alerts = [
        {"alert_id": "ALT-0001", "technique_id": "T1566", "severity": "HIGH", "timestamp": "2026-06-19T10:00:00Z"},
        {"alert_id": "ALT-0002", "technique_id": "T1059", "severity": "CRITICAL", "timestamp": "2026-06-19T10:01:00Z"},
        {"alert_id": "ALT-0003", "technique_id": "T1071", "severity": "HIGH", "timestamp": "2026-06-19T10:02:00Z"},
    ]
    dashboard.ingest_alerts_batch(alerts)
    
    heatmap = dashboard.generate_heatmap()
    
    # Validate structure
    assert "metadata" in heatmap
    assert "heatmap_cells" in heatmap
    assert "tactic_summary" in heatmap
    assert "severity_distribution" in heatmap
    assert heatmap["metadata"]["total_alerts"] == 3
    assert len(heatmap["heatmap_cells"]) == 3
    return True


def test_executive_summary_generation() -> bool:
    """Test executive summary generation"""
    dashboard = MITREHeatmapDashboard()
    
    alerts = [
        {"alert_id": f"ALT-{i:04d}", "technique_id": tid, "severity": sev, 
         "timestamp": f"2026-06-19T10:{i:02d}:00Z"}
        for i, (tid, sev) in enumerate([
            ("T1566", "HIGH"), ("T1059", "CRITICAL"), 
            ("T1071", "HIGH"), ("T1110", "CRITICAL"),
        ])
    ]
    dashboard.ingest_alerts_batch(alerts)
    
    summary = dashboard.generate_executive_summary()
    
    assert summary.total_alerts_analyzed == 4
    assert summary.overall_threat_level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    assert isinstance(summary.risk_score, float)
    assert len(summary.recommendations) > 0
    assert len(summary.top_attack_vectors) > 0
    assert "trend_analysis" in summary.__dict__
    return True


def test_trend_detection() -> bool:
    """Test trend detection logic"""
    dashboard = MITREHeatmapDashboard()
    
    # Add multiple alerts for same technique
    for i in range(6):
        dashboard.ingest_alert({
            "alert_id": f"ALT-{i:04d}",
            "technique_id": "T1566",
            "severity": "HIGH",
            "timestamp": f"2026-06-19T10:{i:02d}:00Z",
        })
    
    trend = dashboard.determine_trend("T1566")
    assert trend in ["increasing", "decreasing", "stable"]
    return True


def test_json_export() -> bool:
    """Test JSON export functionality"""
    dashboard = MITREHeatmapDashboard()
    
    alerts = [
        {"alert_id": "ALT-0001", "technique_id": "T1566", "severity": "HIGH", "timestamp": "2026-06-19T10:00:00Z"},
        {"alert_id": "ALT-0002", "technique_id": "T1059", "severity": "CRITICAL", "timestamp": "2026-06-19T10:01:00Z"},
    ]
    dashboard.ingest_alerts_batch(alerts)
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        temp_path = f.name
    
    try:
        result = dashboard.export_dashboard_json(temp_path)
        assert result is True
        
        # Verify file exists and is valid JSON
        with open(temp_path, 'r') as f:
            exported = json.load(f)
        
        assert "heatmap" in exported
        assert "executive_summary" in exported
        assert "export_metadata" in exported
        return True
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)


def test_statistics_reporting() -> bool:
    """Test statistics reporting"""
    dashboard = MITREHeatmapDashboard()
    
    alerts = [
        {"alert_id": f"ALT-{i:04d}", "technique_id": tid, "severity": sev,
         "timestamp": f"2026-06-19T10:{i:02d}:00Z"}
        for i, (tid, sev) in enumerate([
            ("T1566", "HIGH"), ("T1566", "MEDIUM"),
            ("T1059", "CRITICAL"), ("T1071", "HIGH"),
        ])
    ]
    dashboard.ingest_alerts_batch(alerts)
    
    stats = dashboard.get_statistics()
    
    assert stats["total_alerts_processed"] == 4
    assert stats["unique_techniques"] == 3
    assert "severity_breakdown" in stats
    assert "top_techniques" in stats
    return True


def test_sample_dashboard_function() -> bool:
    """Test the sample dashboard creation function"""
    result = create_sample_dashboard()
    
    assert "processing_stats" in result
    assert "heatmap" in result
    assert "executive_summary" in result
    assert "dashboard_stats" in result
    assert result["processing_stats"]["success"] > 0
    return True


def test_tactic_mapping_correctness() -> bool:
    """Test MITRE tactic mapping accuracy"""
    dashboard = MITREHeatmapDashboard()
    
    # Test specific mappings
    test_cases = [
        ("T1566", MITRETactic.INITIAL_ACCESS),  # Phishing
        ("T1059", MITRETactic.EXECUTION),       # Command Interpreter
        ("T1071", MITRETactic.COMMAND_AND_CONTROL),  # C2
        ("T1110", MITRETactic.CREDENTIAL_ACCESS),    # Brute Force
    ]
    
    for technique_id, expected_tactic in test_cases:
        dashboard.ingest_alert({
            "alert_id": f"TEST-{technique_id}",
            "technique_id": technique_id,
            "severity": "HIGH",
            "timestamp": "2026-06-19T10:00:00Z",
        })
    
    heatmap = dashboard.generate_heatmap()
    
    # Verify tactics are correctly assigned
    tactics_found = set(cell["tactic"] for cell in heatmap["heatmap_cells"])
    for _, expected_tactic in test_cases:
        assert expected_tactic in tactics_found
    
    return True


def main() -> Dict[str, Any]:
    """Run all tests and generate report"""
    tests = [
        ("Dashboard Initialization", test_dashboard_initialization),
        ("Single Alert Ingestion", test_single_alert_ingestion),
        ("Alert Deduplication", test_alert_deduplication),
        ("Invalid Alert Rejection", test_invalid_alert_rejection),
        ("Batch Ingestion", test_batch_ingestion),
        ("Risk Score Calculation", test_risk_score_calculation),
        ("Heatmap Generation", test_heatmap_generation),
        ("Executive Summary Generation", test_executive_summary_generation),
        ("Trend Detection", test_trend_detection),
        ("JSON Export", test_json_export),
        ("Statistics Reporting", test_statistics_reporting),
        ("Sample Dashboard Function", test_sample_dashboard_function),
        ("Tactic Mapping Correctness", test_tactic_mapping_correctness),
    ]
    
    print("=" * 60)
    print("NeuralShield MITRE Heatmap Executive Dashboard - Test Suite")
    print("=" * 60)
    
    results = []
    for test_name, test_func in tests:
        print(f"\nRunning: {test_name}...", end=" ")
        result = run_test(test_name, test_func)
        results.append(result)
        
        if result["passed"]:
            print("PASSED")
        else:
            print(f"FAILED: {result['error']}")
    
    # Summary
    passed = sum(1 for r in results if r["passed"])
    total = len(results)
    
    print("\n" + "=" * 60)
    print(f"TEST SUMMARY: {passed}/{total} tests passed")
    print("=" * 60)
    
    report = {
        "test_run_timestamp": __import__("datetime").datetime.utcnow().isoformat() + "Z",
        "module": "threat_intelligence_mitre_heatmap_executive_dashboard",
        "total_tests": total,
        "passed_tests": passed,
        "failed_tests": total - passed,
        "pass_rate": round(passed / total * 100, 2),
        "test_results": results,
        "status": "SUCCESS" if passed == total else "PARTIAL_SUCCESS",
    }
    
    # Save results
    with open("test_results_mitre_heatmap_dashboard.json", "w") as f:
        json.dump(report, f, indent=2)
    
    print(f"\nResults saved to: test_results_mitre_heatmap_dashboard.json")
    
    return report


if __name__ == "__main__":
    main()
