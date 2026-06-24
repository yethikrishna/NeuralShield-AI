"""
Tests for MITRE Executive Dashboard Generator v25
Dimension A - Feature Expansion Tests
"""
import pytest
import json
import tempfile
import os
from datetime import datetime, timedelta, timezone
from neural_shield.feature_expansion_mitre_executive_dashboard_generator_v25_2026_june import (
    MITREExecutiveDashboardGenerator,
    RiskLevel,
    TacticCategory,
    TechniqueCoverage,
    ExecutiveSummary
)


class TestMITREExecutiveDashboardGenerator:
    """Test suite for MITRE Executive Dashboard Generator."""
    
    def test_initialization(self):
        """Test dashboard generator initialization."""
        dashboard = MITREExecutiveDashboardGenerator("Test Org")
        assert dashboard.organization_name == "Test Org"
        assert dashboard._generated_at is None
        assert len(dashboard._techniques) == 0
        assert len(dashboard._trend_data) == 0
    
    def test_default_organization(self):
        """Test default organization name."""
        dashboard = MITREExecutiveDashboardGenerator()
        assert dashboard.organization_name == "Enterprise"
    
    def test_add_technique_coverage(self):
        """Test adding technique coverage data."""
        dashboard = MITREExecutiveDashboardGenerator()
        
        dashboard.add_technique_coverage(
            technique_id="T1059",
            technique_name="Command and Scripting Interpreter",
            tactic=TacticCategory.EXECUTION,
            detection_count=150,
            prevention_count=120,
            risk_score=85.0
        )
        
        assert "T1059" in dashboard._techniques
        tech = dashboard._techniques["T1059"]
        assert tech.technique_id == "T1059"
        assert tech.detection_count == 150
        assert tech.prevention_count == 120
        assert tech.risk_score == 85.0
    
    def test_technique_coverage_percentage(self):
        """Test coverage percentage calculation."""
        tech = TechniqueCoverage(
            technique_id="T1001",
            technique_name="Test",
            tactic=TacticCategory.EXECUTION,
            detection_count=100,
            prevention_count=80
        )
        assert tech.get_coverage_percentage() == 80.0
    
    def test_technique_zero_coverage(self):
        """Test zero coverage case."""
        tech = TechniqueCoverage(
            technique_id="T1001",
            technique_name="Test",
            tactic=TacticCategory.EXECUTION
        )
        assert tech.get_coverage_percentage() == 0.0
    
    def test_risk_level_from_score(self):
        """Test risk level calculation from score."""
        assert RiskLevel.from_score(90) == RiskLevel.CRITICAL
        assert RiskLevel.from_score(75) == RiskLevel.HIGH
        assert RiskLevel.from_score(50) == RiskLevel.MEDIUM
        assert RiskLevel.from_score(20) == RiskLevel.LOW
        assert RiskLevel.from_score(5) == RiskLevel.UNKNOWN
    
    def test_add_trend_data_point(self):
        """Test adding trend data."""
        dashboard = MITREExecutiveDashboardGenerator()
        now = datetime.now(timezone.utc)
        
        dashboard.add_trend_data_point(now, detections=10, preventions=8, incidents=1, risk_score=65.0)
        
        assert len(dashboard._trend_data) == 1
        assert dashboard._trend_data[0].detections == 10
        assert dashboard._trend_data[0].risk_score == 65.0
    
    def test_add_incident(self):
        """Test adding security incidents."""
        dashboard = MITREExecutiveDashboardGenerator()
        now = datetime.now(timezone.utc)
        
        dashboard.add_incident(
            incident_id="INC-001",
            severity="critical",
            tactic="execution",
            technique="T1059",
            timestamp=now,
            resolved=True,
            resolution_time_minutes=45.0,
            threat_actor="APT-28",
            asset_impacted="web-server-01"
        )
        
        assert len(dashboard._incident_log) == 1
        assert dashboard._incident_log[0]["incident_id"] == "INC-001"
        assert dashboard._incident_log[0]["severity"] == "critical"
    
    def test_add_recommendation(self):
        """Test adding security recommendations."""
        dashboard = MITREExecutiveDashboardGenerator()
        
        dashboard.add_recommendation(
            title="Enable MFA",
            description="Implement multi-factor authentication",
            priority="high",
            effort="medium",
            impact="high",
            estimated_roi=75.0,
            category="authentication"
        )
        
        assert len(dashboard._recommendations) == 1
        assert dashboard._recommendations[0].title == "Enable MFA"
        assert dashboard._recommendations[0].priority == "high"
    
    def test_calculate_overall_score_empty(self):
        """Test overall score with empty data."""
        dashboard = MITREExecutiveDashboardGenerator()
        score = dashboard._calculate_overall_score()
        assert score == 50.0  # Default baseline
    
    def test_calculate_overall_score_with_data(self):
        """Test overall score calculation with data."""
        dashboard = MITREExecutiveDashboardGenerator()
        
        dashboard.add_technique_coverage(
            "T1059", "Command Execution", TacticCategory.EXECUTION,
            detection_count=100, prevention_count=90, risk_score=70.0
        )
        dashboard.add_technique_coverage(
            "T1078", "Valid Accounts", TacticCategory.INITIAL_ACCESS,
            detection_count=50, prevention_count=45, risk_score=80.0
        )
        
        score = dashboard._calculate_overall_score()
        assert 0 <= score <= 100
    
    def test_generate_heatmap_data(self):
        """Test heatmap generation."""
        dashboard = MITREExecutiveDashboardGenerator()
        
        dashboard.add_technique_coverage(
            "T1059", "Test", TacticCategory.EXECUTION,
            detection_count=100, prevention_count=85
        )
        
        heatmap = dashboard.generate_heatmap_data()
        assert "execution" in heatmap
        assert heatmap["execution"]["detections"] == 100
        assert heatmap["execution"]["preventions"] == 85
        assert "color" in heatmap["execution"]
    
    def test_generate_complete_dashboard(self):
        """Test complete dashboard generation."""
        dashboard = MITREExecutiveDashboardGenerator("Test Company")
        
        # Add techniques
        dashboard.add_technique_coverage(
            "T1059", "Command Execution", TacticCategory.EXECUTION,
            detection_count=100, prevention_count=90, risk_score=75.0
        )
        dashboard.add_technique_coverage(
            "T1078", "Valid Accounts", TacticCategory.INITIAL_ACCESS,
            detection_count=80, prevention_count=70, risk_score=85.0
        )
        
        # Add incidents
        now = datetime.now(timezone.utc)
        dashboard.add_incident("INC-001", "high", "execution", "T1059", now, True, 30.0)
        dashboard.add_incident("INC-002", "critical", "initial_access", "T1078", now, True, 60.0)
        
        # Add recommendations
        dashboard.add_recommendation("Patch Systems", "Apply critical patches", "high", "low", "high", 80.0)
        
        result = dashboard.generate_dashboard()
        
        assert result["dashboard_version"] == "v25"
        assert result["organization"] == "Test Company"
        assert "executive_summary" in result
        assert "mitre_heatmap" in result
        assert "recommendations" in result
        assert "incident_summary" in result
    
    def test_get_security_grade(self):
        """Test security grade calculation."""
        dashboard = MITREExecutiveDashboardGenerator()
        
        # Add high coverage techniques
        for i in range(5):
            dashboard.add_technique_coverage(
                f"T100{i}", f"Technique {i}", TacticCategory.EXECUTION,
                detection_count=100, prevention_count=95, risk_score=50.0
            )
        
        grade = dashboard.get_security_grade()
        assert grade in ["A", "B", "C", "D", "F"]
    
    def test_export_json(self):
        """Test JSON export functionality."""
        dashboard = MITREExecutiveDashboardGenerator()
        dashboard.add_technique_coverage(
            "T1059", "Test", TacticCategory.EXECUTION, 100, 90, 70.0
        )
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            temp_path = f.name
        
        try:
            dashboard.export_json(temp_path)
            
            with open(temp_path, 'r') as f:
                data = json.load(f)
            
            assert data["dashboard_version"] == "v25"
            assert "executive_summary" in data
        finally:
            os.unlink(temp_path)
    
    def test_top_risk_techniques(self):
        """Test top risk techniques sorting."""
        dashboard = MITREExecutiveDashboardGenerator()
        
        dashboard.add_technique_coverage("T1001", "Low Risk", TacticCategory.EXECUTION, 10, 5, risk_score=30.0)
        dashboard.add_technique_coverage("T1002", "High Risk", TacticCategory.EXECUTION, 50, 20, risk_score=90.0)
        dashboard.add_technique_coverage("T1003", "Medium Risk", TacticCategory.EXECUTION, 30, 15, risk_score=60.0)
        
        top_techs = dashboard._get_top_risk_techniques(limit=2)
        assert len(top_techs) == 2
        assert top_techs[0]["risk_score"] == 90.0
        assert top_techs[1]["risk_score"] == 60.0
    
    def test_incident_summary(self):
        """Test incident summary generation."""
        dashboard = MITREExecutiveDashboardGenerator()
        now = datetime.now(timezone.utc)
        
        dashboard.add_incident("INC-001", "critical", "execution", "T1059", now, True)
        dashboard.add_incident("INC-002", "high", "exfiltration", "T1041", now, True)
        dashboard.add_incident("INC-003", "medium", "discovery", "T1083", now, False)
        
        summary = dashboard._get_incident_summary()
        assert summary["total_incidents"] == 3
        assert summary["by_severity"]["critical"] == 1
        assert summary["by_severity"]["high"] == 1
    
    def test_prioritized_recommendations(self):
        """Test recommendation prioritization."""
        dashboard = MITREExecutiveDashboardGenerator()
        
        dashboard.add_recommendation("Low priority", "Test", "low", "low", "low", 10.0)
        dashboard.add_recommendation("Critical priority", "Test", "critical", "medium", "high", 90.0)
        dashboard.add_recommendation("High priority", "Test", "high", "low", "high", 70.0)
        
        recs = dashboard.generate_prioritized_recommendations()
        assert recs[0]["priority"] == "critical"
        assert recs[1]["priority"] == "high"
        assert recs[2]["priority"] == "low"
    
    def test_trend_analysis_empty(self):
        """Test trend analysis with no data."""
        dashboard = MITREExecutiveDashboardGenerator()
        trend = dashboard._generate_trend_analysis()
        assert trend["has_data"] is False
    
    def test_trend_analysis_with_data(self):
        """Test trend analysis with data."""
        dashboard = MITREExecutiveDashboardGenerator()
        base_time = datetime.now(timezone.utc)
        
        for i in range(5):
            dashboard.add_trend_data_point(
                base_time + timedelta(days=i),
                detections=10 - i,
                preventions=8,
                risk_score=70 - (i * 5)  # Improving trend
            )
        
        trend = dashboard._generate_trend_analysis()
        assert trend["has_data"] is True
        assert trend["data_points"] == 5
        assert trend["trend_direction"] == "improving"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
