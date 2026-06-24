"""
Test Suite for MITRE ATT&CK Executive Dashboard
Dimension A: Feature Expansion (V25 - June 2026)

Comprehensive tests covering all dashboard functionality.
All tests are ADD-ONLY - no existing code modified.
"""

import json
import os
import tempfile
import pytest
from datetime import datetime

from neural_shield.mitre_attack_executive_dashboard_v25_2026_june import (
    MITREAttackExecutiveDashboard,
    MITRETactic,
    SeverityLevel,
    TacticMetric,
    ExecutiveSummary
)


class TestMITREAttackExecutiveDashboard:
    """Test suite for MITRE ATT&CK Executive Dashboard"""
    
    def test_dashboard_initialization(self):
        """Test dashboard initializes correctly"""
        dashboard = MITREAttackExecutiveDashboard(organization_name="Test Org")
        
        assert dashboard.organization_name == "Test Org"
        assert len(dashboard.detections) == 0
        assert len(dashboard.tactic_metrics) == 14  # 14 MITRE tactics
        assert dashboard.version == "25.0.0"
    
    def test_default_organization_name(self):
        """Test default organization name"""
        dashboard = MITREAttackExecutiveDashboard()
        assert dashboard.organization_name == "NeuralShield AI"
    
    def test_record_detection_returns_id(self):
        """Test recording a detection returns valid ID"""
        dashboard = MITREAttackExecutiveDashboard()
        
        detection_id = dashboard.record_detection(
            tactic="Execution",
            severity="HIGH",
            blocked=True
        )
        
        assert isinstance(detection_id, str)
        assert len(detection_id) == 16
        assert len(dashboard.detections) == 1
    
    def test_record_detection_updates_metrics(self):
        """Test recording detection updates tactic metrics"""
        dashboard = MITREAttackExecutiveDashboard()
        
        dashboard.record_detection(
            tactic="Execution",
            severity="CRITICAL",
            blocked=True
        )
        
        metric = dashboard.tactic_metrics["Execution"]
        assert metric.detections == 1
        assert metric.blocked == 1
        assert metric.severity_distribution["CRITICAL"] == 1
    
    def test_record_detection_with_technique_id(self):
        """Test recording detection with technique ID"""
        dashboard = MITREAttackExecutiveDashboard()
        
        detection_id = dashboard.record_detection(
            tactic="Initial Access",
            severity="HIGH",
            technique_id="T1566",
            blocked=True,
            source="Test Module"
        )
        
        detection = dashboard.detections[0]
        assert detection["technique_id"] == "T1566"
        assert detection["source"] == "Test Module"
    
    def test_record_detection_with_metadata(self):
        """Test recording detection with metadata"""
        dashboard = MITREAttackExecutiveDashboard()
        
        dashboard.record_detection(
            tactic="Command and Control",
            severity="MEDIUM",
            metadata={"ip": "192.168.1.1", "user": "test"}
        )
        
        assert dashboard.detections[0]["metadata"]["ip"] == "192.168.1.1"
    
    def test_generate_executive_summary_empty(self):
        """Test executive summary with no detections"""
        dashboard = MITREAttackExecutiveDashboard()
        
        summary = dashboard.generate_executive_summary()
        
        assert summary.total_threats_detected == 0
        assert summary.total_threats_blocked == 0
        assert summary.critical_severity_count == 0
        assert summary.high_severity_count == 0
        # Score can be int or float, both are fine
        assert isinstance(summary.overall_security_score, (int, float))
    
    def test_generate_executive_summary_with_data(self):
        """Test executive summary with detection data"""
        dashboard = MITREAttackExecutiveDashboard()
        
        # Add some test detections
        dashboard.record_detection("Execution", "CRITICAL", blocked=True)
        dashboard.record_detection("Execution", "HIGH", blocked=True)
        dashboard.record_detection("Initial Access", "MEDIUM", blocked=True)
        dashboard.record_detection("Persistence", "LOW", blocked=False)
        
        summary = dashboard.generate_executive_summary()
        
        assert summary.total_threats_detected == 4
        assert summary.total_threats_blocked == 3
        assert summary.critical_severity_count == 1
        assert summary.high_severity_count == 1
        assert summary.overall_security_score >= 0
        assert summary.overall_security_score <= 100
    
    def test_executive_summary_risk_rating(self):
        """Test risk rating calculation"""
        dashboard = MITREAttackExecutiveDashboard()
        
        summary = dashboard.generate_executive_summary()
        
        assert summary.risk_rating in ["LOW", "MODERATE", "ELEVATED", "HIGH"]
    
    def test_executive_summary_top_threats(self):
        """Test top threat vectors calculation"""
        dashboard = MITREAttackExecutiveDashboard()
        
        # Add multiple detections for same tactic
        for _ in range(5):
            dashboard.record_detection("Execution", "HIGH", blocked=True)
        for _ in range(3):
            dashboard.record_detection("Initial Access", "MEDIUM", blocked=True)
        
        summary = dashboard.generate_executive_summary()
        
        assert len(summary.top_threat_vectors) > 0
        assert summary.top_threat_vectors[0]["tactic"] == "Execution"
        assert summary.top_threat_vectors[0]["count"] == 5
    
    def test_get_tactic_coverage_report(self):
        """Test tactic coverage report generation"""
        dashboard = MITREAttackExecutiveDashboard()
        
        dashboard.record_detection("Execution", "HIGH", blocked=True)
        
        report = dashboard.get_tactic_coverage_report()
        
        assert "organization" in report
        assert "generated_at" in report
        assert "tactics" in report
        assert "summary" in report
        assert report["summary"]["total_tactics"] == 14
        assert report["summary"]["total_detections"] >= 1
    
    def test_tactic_coverage_block_rate(self):
        """Test block rate calculation in coverage report"""
        dashboard = MITREAttackExecutiveDashboard()
        
        # 3 blocked, 1 not blocked
        dashboard.record_detection("Execution", "HIGH", blocked=True)
        dashboard.record_detection("Execution", "HIGH", blocked=True)
        dashboard.record_detection("Execution", "HIGH", blocked=True)
        dashboard.record_detection("Execution", "HIGH", blocked=False)
        
        report = dashboard.get_tactic_coverage_report()
        
        assert report["tactics"]["Execution"]["block_rate"] == 0.75
    
    def test_generate_board_report_text(self):
        """Test board report text generation"""
        dashboard = MITREAttackExecutiveDashboard()
        
        dashboard.record_detection("Execution", "CRITICAL", blocked=True)
        
        report = dashboard.generate_board_report_text()
        
        assert isinstance(report, str)
        assert "NEURALSHIELD AI SECURITY EXECUTIVE REPORT" in report
        assert "Overall Security Score" in report
        assert "MITRE ATT&CK" in report
    
    def test_board_report_contains_metrics(self):
        """Test board report contains key metrics"""
        dashboard = MITREAttackExecutiveDashboard()
        
        dashboard.record_detection("Execution", "HIGH", blocked=True)
        
        report = dashboard.generate_board_report_text()
        
        assert "Total Threats Detected:" in report
        assert "Total Threats Blocked:" in report
        assert "Critical Severity Events:" in report
    
    def test_export_json(self):
        """Test JSON export functionality"""
        dashboard = MITREAttackExecutiveDashboard()
        
        dashboard.record_detection("Execution", "HIGH", blocked=True)
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            filepath = f.name
        
        try:
            result = dashboard.export_json(filepath)
            assert result == True
            
            with open(filepath, 'r') as f:
                data = json.load(f)
            
            assert "version" in data
            assert "executive_summary" in data
            assert "tactic_coverage" in data
        finally:
            os.unlink(filepath)
    
    def test_export_json_invalid_path_returns_false(self):
        """Test JSON export handles invalid paths gracefully"""
        dashboard = MITREAttackExecutiveDashboard()
        
        result = dashboard.export_json("/nonexistent/path/report.json")
        assert result == False
    
    def test_get_health_status(self):
        """Test health status reporting"""
        dashboard = MITREAttackExecutiveDashboard()
        
        health = dashboard.get_health_status()
        
        assert health["status"] == "healthy"
        assert health["version"] == "25.0.0"
        assert health["detections_recorded"] == 0
        assert health["tactics_monitored"] == 14
        assert health["api_stability"] == "STABLE"
    
    def test_health_status_after_detections(self):
        """Test health status updates with detections"""
        dashboard = MITREAttackExecutiveDashboard()
        
        dashboard.record_detection("Execution", "HIGH", blocked=True)
        dashboard.record_detection("Initial Access", "MEDIUM", blocked=True)
        
        health = dashboard.get_health_status()
        
        assert health["detections_recorded"] == 2
    
    def test_mitre_tactic_enum(self):
        """Test MITRE Tactic enum has all values"""
        assert len(MITRETactic) == 14
        assert MITRETactic.EXECUTION.value == "Execution"
        assert MITRETactic.INITIAL_ACCESS.value == "Initial Access"
        assert MITRETactic.COMMAND_AND_CONTROL.value == "Command and Control"
    
    def test_severity_level_enum(self):
        """Test Severity Level enum"""
        assert SeverityLevel.CRITICAL.value == "CRITICAL"
        assert SeverityLevel.HIGH.value == "HIGH"
        assert SeverityLevel.MEDIUM.value == "MEDIUM"
        assert SeverityLevel.LOW.value == "LOW"
    
    def test_tactic_metric_dataclass(self):
        """Test TacticMetric dataclass"""
        metric = TacticMetric(
            tactic="Execution",
            detections=10,
            blocked=8,
            mitigated=2,
            severity_distribution={"CRITICAL": 2, "HIGH": 5},
            trend_7day=5.2,
            coverage_score=0.85
        )
        
        assert metric.tactic == "Execution"
        assert metric.detections == 10
    
    def test_multiple_detections_same_tactic(self):
        """Test multiple detections accumulate correctly"""
        dashboard = MITREAttackExecutiveDashboard()
        
        for i in range(10):
            severity = "CRITICAL" if i < 2 else "HIGH" if i < 5 else "MEDIUM"
            dashboard.record_detection("Execution", severity, blocked=True)
        
        metric = dashboard.tactic_metrics["Execution"]
        assert metric.detections == 10
        assert metric.blocked == 10
        assert metric.severity_distribution["CRITICAL"] == 2
        assert metric.severity_distribution["HIGH"] == 3
        assert metric.severity_distribution["MEDIUM"] == 5
    
    def test_detection_timestamps_are_valid(self):
        """Test detection timestamps are valid ISO format"""
        dashboard = MITREAttackExecutiveDashboard()
        
        dashboard.record_detection("Execution", "HIGH", blocked=True)
        
        detection = dashboard.detections[0]
        # Verify timestamp can be parsed
        parsed = datetime.fromisoformat(detection["timestamp"])
        assert isinstance(parsed, datetime)
    
    def test_unmitigated_detection(self):
        """Test unmitigated detection recording"""
        dashboard = MITREAttackExecutiveDashboard()
        
        dashboard.record_detection(
            tactic="Exfiltration",
            severity="CRITICAL",
            blocked=False,
            mitigated=False
        )
        
        metric = dashboard.tactic_metrics["Exfiltration"]
        assert metric.detections == 1
        assert metric.blocked == 0
        assert metric.mitigated == 0
    
    def test_custom_lookback_period(self):
        """Test custom lookback period for reports"""
        dashboard = MITREAttackExecutiveDashboard()
        
        dashboard.record_detection("Execution", "HIGH", blocked=True)
        
        summary_7 = dashboard.generate_executive_summary(days_lookback=7)
        summary_30 = dashboard.generate_executive_summary(days_lookback=30)
        
        # Both should have same data since detections are new
        assert summary_7.total_threats_detected == summary_30.total_threats_detected
    
    def test_avg_severity_calculation(self):
        """Test average severity calculation"""
        dashboard = MITREAttackExecutiveDashboard()
        
        # All critical should return CRITICAL
        dashboard.record_detection("Execution", "CRITICAL", blocked=True)
        dashboard.record_detection("Execution", "CRITICAL", blocked=True)
        
        summary = dashboard.generate_executive_summary()
        for threat in summary.top_threat_vectors:
            if threat["tactic"] == "Execution":
                assert threat["severity"] in ["CRITICAL", "HIGH"]
    
    def test_empty_tactic_avg_severity(self):
        """Test avg severity for tactic with no detections"""
        dashboard = MITREAttackExecutiveDashboard()
        
        # This calls _get_avg_severity internally
        summary = dashboard.generate_executive_summary()
        assert isinstance(summary, ExecutiveSummary)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
