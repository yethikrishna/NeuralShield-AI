"""
Test Suite for NeuralShield-AI MITRE Heatmap Visualizer
June 2026 - Production Grade Tests

Tests verify:
- Alert processing and aggregation
- Heatmap cell generation
- JSON/CSV export functionality
- Dashboard data structure generation
- Edge cases and error handling
"""

import pytest
import json
import os
import tempfile
from datetime import datetime, timedelta

from neural_shield.threat_intelligence_mitre_heatmap_visualizer_2026_june import (
    MITREHeatmapVisualizer,
    MITRETactic,
    SeverityLevel,
    HeatmapResult,
    HeatmapCell
)


class TestMITREHeatmapVisualizer:
    """Test suite for MITRE ATT&CK Heatmap Visualizer"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.visualizer = MITREHeatmapVisualizer()
    
    def test_initialization(self):
        """Test visualizer initialization"""
        assert self.visualizer is not None
        assert len(self.visualizer.technique_mapping) > 0
        assert len(self.visualizer.tactic_order) == 14
    
    def test_generate_sample_alerts(self):
        """Test sample alert generation"""
        alerts = self.visualizer.generate_sample_alerts(count=10)
        assert len(alerts) == 10
        assert all("technique_id" in alert for alert in alerts)
        assert all("severity" in alert for alert in alerts)
        assert all("timestamp" in alert for alert in alerts)
    
    def test_process_alerts_basic(self):
        """Test basic alert processing"""
        alerts = self.visualizer.generate_sample_alerts(count=50)
        result = self.visualizer.process_alerts(alerts, time_window_hours=24)
        
        assert isinstance(result, HeatmapResult)
        assert result.total_alerts == 50
        assert result.unique_techniques > 0
        assert len(result.cells) > 0
        assert 0 <= result.overall_risk_score <= 100
    
    def test_process_alerts_time_window_filtering(self):
        """Test time window filtering works correctly"""
        base_time = datetime.utcnow()
        
        # Create alerts at different time points
        alerts = [
            {
                "technique_id": "T1566",
                "severity": "high",
                "timestamp": (base_time - timedelta(hours=1)).isoformat() + "Z"
            },
            {
                "technique_id": "T1059",
                "severity": "medium",
                "timestamp": (base_time - timedelta(hours=48)).isoformat() + "Z"
            }
        ]
        
        # 24-hour window should only include first alert
        result = self.visualizer.process_alerts(alerts, time_window_hours=24)
        assert result.total_alerts == 1
        
        # 72-hour window should include both
        result = self.visualizer.process_alerts(alerts, time_window_hours=72)
        assert result.total_alerts == 2
    
    def test_heatmap_cell_generation(self):
        """Test heatmap cell data structure"""
        alerts = self.visualizer.generate_sample_alerts(count=20)
        result = self.visualizer.process_alerts(alerts)
        
        for cell in result.cells:
            assert isinstance(cell, HeatmapCell)
            assert cell.tactic in [t.value for t in MITRETactic]
            assert cell.count >= 1
            assert cell.severity_score > 0
            assert 0 <= cell.normalized_score <= 1.0
    
    def test_top_techniques(self):
        """Test top techniques identification"""
        alerts = self.visualizer.generate_sample_alerts(count=100)
        result = self.visualizer.process_alerts(alerts)
        
        assert len(result.top_techniques) <= 10
        assert all("technique_id" in t for t in result.top_techniques)
        assert all("risk_score" in t for t in result.top_techniques)
        
        # Verify descending order
        scores = [t["risk_score"] for t in result.top_techniques]
        assert scores == sorted(scores, reverse=True)
    
    def test_tactic_summary(self):
        """Test tactic summary statistics"""
        alerts = self.visualizer.generate_sample_alerts(count=50)
        result = self.visualizer.process_alerts(alerts)
        
        for tactic in MITRETactic:
            assert tactic.value in result.tactic_summary
            summary = result.tactic_summary[tactic.value]
            assert "alert_count" in summary
            assert "total_risk_score" in summary
            assert "coverage_percent" in summary
            assert 0 <= summary["coverage_percent"] <= 100
    
    def test_overall_risk_score(self):
        """Test overall risk score calculation"""
        # Empty alerts should give 0 risk
        result = self.visualizer.process_alerts([])
        assert result.overall_risk_score == 0
        
        # Many high-severity alerts should give high risk
        high_alerts = [
            {"technique_id": "T1566", "severity": "critical", "timestamp": datetime.utcnow().isoformat() + "Z"}
            for _ in range(20)
        ]
        result = self.visualizer.process_alerts(high_alerts)
        assert result.overall_risk_score >= 50
    
    def test_export_to_json(self):
        """Test JSON export functionality"""
        alerts = self.visualizer.generate_sample_alerts(count=30)
        result = self.visualizer.process_alerts(alerts)
        
        json_str = self.visualizer.export_to_json(result)
        data = json.loads(json_str)
        
        assert "metadata" in data
        assert "tactic_summary" in data
        assert "top_techniques" in data
        assert "heatmap_cells" in data
        assert data["metadata"]["total_alerts"] == 30
    
    def test_export_to_json_file(self):
        """Test JSON export to file"""
        alerts = self.visualizer.generate_sample_alerts(count=10)
        result = self.visualizer.process_alerts(alerts)
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            filepath = f.name
        
        try:
            self.visualizer.export_to_json(result, filepath)
            assert os.path.exists(filepath)
            
            with open(filepath, 'r') as f:
                data = json.load(f)
            assert data["metadata"]["total_alerts"] == 10
        finally:
            if os.path.exists(filepath):
                os.unlink(filepath)
    
    def test_export_to_csv(self):
        """Test CSV export functionality"""
        alerts = self.visualizer.generate_sample_alerts(count=10)
        result = self.visualizer.process_alerts(alerts)
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            filepath = f.name
        
        try:
            self.visualizer.export_to_csv(result, filepath)
            assert os.path.exists(filepath)
            
            with open(filepath, 'r') as f:
                lines = f.readlines()
            # Header + data rows
            assert len(lines) == len(result.cells) + 1
            assert "Tactic" in lines[0]
        finally:
            if os.path.exists(filepath):
                os.unlink(filepath)
    
    def test_generate_dashboard_data(self):
        """Test dashboard data generation"""
        alerts = self.visualizer.generate_sample_alerts(count=50)
        result = self.visualizer.process_alerts(alerts)
        
        dashboard = self.visualizer.generate_dashboard_data(result)
        
        assert "matrix_heatmap" in dashboard
        assert "risk_gauge" in dashboard
        assert "top_threats_barchart" in dashboard
        assert "tactic_distribution" in dashboard
        assert "summary_stats" in dashboard
        
        # Risk gauge structure
        assert "value" in dashboard["risk_gauge"]
        assert "level" in dashboard["risk_gauge"]
        assert dashboard["risk_gauge"]["level"] in ["critical", "high", "medium", "low"]
        
        # Summary stats
        assert dashboard["summary_stats"]["total_alerts"] == 50
    
    def test_severity_weighting(self):
        """Test severity weighting affects risk score"""
        critical_alerts = [
            {"technique_id": "T1566", "severity": "critical", "timestamp": datetime.utcnow().isoformat() + "Z"}
            for _ in range(5)
        ]
        low_alerts = [
            {"technique_id": "T1566", "severity": "low", "timestamp": datetime.utcnow().isoformat() + "Z"}
            for _ in range(5)
        ]
        
        result_critical = self.visualizer.process_alerts(critical_alerts)
        result_low = self.visualizer.process_alerts(low_alerts)
        
        # Critical alerts should have higher risk score
        assert result_critical.overall_risk_score > result_low.overall_risk_score
    
    def test_normalized_scores(self):
        """Test normalized scores are within valid range"""
        alerts = self.visualizer.generate_sample_alerts(count=100)
        result = self.visualizer.process_alerts(alerts)
        
        for cell in result.cells:
            assert 0.0 <= cell.normalized_score <= 1.0
    
    def test_empty_alerts_handling(self):
        """Test handling of empty alert list"""
        result = self.visualizer.process_alerts([])
        
        assert result.total_alerts == 0
        assert result.unique_techniques == 0
        assert len(result.cells) == 0
        assert result.overall_risk_score == 0
    
    def test_invalid_timestamp_handling(self):
        """Test handling of invalid timestamps"""
        alerts = [
            {"technique_id": "T1566", "severity": "high", "timestamp": "invalid-date"},
            {"technique_id": "T1059", "severity": "medium", "timestamp": datetime.utcnow().isoformat() + "Z"}
        ]
        
        result = self.visualizer.process_alerts(alerts)
        # Should process valid alert, skip invalid one
        assert result.total_alerts == 1
    
    def test_unknown_technique_handling(self):
        """Test handling of unknown technique IDs"""
        alerts = [
            {"technique_id": "T9999", "severity": "high", "timestamp": datetime.utcnow().isoformat() + "Z"}
        ]
        
        result = self.visualizer.process_alerts(alerts)
        assert result.total_alerts == 1
        assert result.unique_techniques == 1
        
        cell = result.cells[0]
        assert "Unknown" in cell.technique_name
    
    def test_technique_mapping_coverage(self):
        """Test all tactics have technique coverage"""
        tactics_covered = set()
        for tech_info in self.visualizer.technique_mapping.values():
            tactics_covered.add(tech_info["tactic"])
        
        # Should cover most tactics
        assert len(tactics_covered) >= 10


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
