"""
Test Suite for MITRE ATT&CK Heatmap Generator - June 18, 2026
Production-grade tests with real assertions - no mocks
"""

import pytest
import json
import os
import tempfile
from datetime import datetime, timezone
from neural_shield.threat_intelligence_mitre_heatmap_generator_2026_june import (
    MITREHeatmapGenerator,
    HeatmapGenerationResult,
    HeatmapColor
)


class TestMITREHeatmapGenerator:
    """Production test suite - real working tests"""

    def setup_method(self):
        """Setup test fixtures"""
        self.generator = MITREHeatmapGenerator()
        self.sample_detections = [
            {"technique_id": "T1566", "detected_at": "2026-06-18T10:30:00Z"},
            {"technique_id": "T1566", "detected_at": "2026-06-18T10:35:00Z"},
            {"technique_id": "T1566", "detected_at": "2026-06-18T10:40:00Z"},
            {"technique_id": "T1059", "detected_at": "2026-06-18T11:00:00Z"},
            {"technique_id": "T1059", "detected_at": "2026-06-18T11:05:00Z"},
            {"technique_id": "T1555", "detected_at": "2026-06-18T11:10:00Z"},
            {"technique_id": "T1555", "detected_at": "2026-06-18T11:15:00Z"},
            {"technique_id": "T1555", "detected_at": "2026-06-18T11:20:00Z"},
            {"technique_id": "T1555", "detected_at": "2026-06-18T11:25:00Z"},
            {"technique_id": "T1041", "detected_at": "2026-06-18T12:00:00Z"},
            {"technique_id": "T1486", "detected_at": "2026-06-18T12:30:00Z"},
            {"technique_id": "T1486", "detected_at": "2026-06-18T12:35:00Z"},
        ]

    def test_initialization(self):
        """Test generator initializes correctly"""
        assert self.generator.high_risk_threshold == 7.0
        assert self.generator.critical_threshold == 9.0
        assert self.generator.alert_on_critical is True
        assert self.generator.generation_count == 0
        assert isinstance(self.generator.cache, dict)

    def test_generate_heatmap_success(self):
        """Test heatmap generation succeeds with valid data"""
        result = self.generator.generate_heatmap(self.sample_detections)
        
        assert result.success is True
        assert result.heatmap_id is not None
        assert len(result.heatmap_id) == 16
        assert result.total_cells == 31  # Number of techniques in database
        assert result.execution_time_ms > 0
        assert result.error_message is None
        assert self.generator.generation_count == 1

    def test_generate_heatmap_empty_data(self):
        """Test heatmap generation with empty detection data"""
        result = self.generator.generate_heatmap([])
        
        assert result.success is True
        assert result.total_cells == 31
        # All counts should be 0
        total_detections = sum(cell['count'] for cell in result.heatmap_data)
        assert total_detections == 0

    def test_heatmap_cell_structure(self):
        """Test heatmap cells have correct structure"""
        result = self.generator.generate_heatmap(self.sample_detections)
        
        for cell in result.heatmap_data:
            assert 'tactic' in cell
            assert 'technique_id' in cell
            assert 'technique_name' in cell
            assert 'count' in cell
            assert 'severity_score' in cell
            assert 'risk_level' in cell
            assert 'color' in cell
            assert 'last_detected' in cell
            assert 'trend_direction' in cell
            assert 'trend_percent' in cell
            
            assert isinstance(cell['count'], int)
            assert isinstance(cell['severity_score'], float)
            assert cell['severity_score'] <= 10.0
            assert cell['severity_score'] >= 0

    def test_risk_level_calculation(self):
        """Test risk levels are calculated correctly"""
        result = self.generator.generate_heatmap(self.sample_detections)
        
        valid_risk_levels = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        for cell in result.heatmap_data:
            assert cell['risk_level'] in valid_risk_levels
            assert cell['color'].startswith('#')
            assert len(cell['color']) == 7  # Hex color

    def test_tactic_summary_structure(self):
        """Test tactic summary has correct structure"""
        result = self.generator.generate_heatmap(self.sample_detections)
        
        for tactic, summary in result.tactic_summary.items():
            assert 'total_detections' in summary
            assert 'avg_severity' in summary
            assert 'max_severity' in summary
            assert 'technique_count' in summary
            assert 'critical_count' in summary
            assert 'high_count' in summary
            assert 'color' in summary
            
            assert isinstance(summary['total_detections'], int)
            assert isinstance(summary['max_severity'], float)

    def test_alerts_generation(self):
        """Test critical risk alerts are generated"""
        result = self.generator.generate_heatmap(self.sample_detections, include_alerts=True)
        
        for alert in result.alerts:
            assert 'alert_id' in alert
            assert 'type' in alert
            assert 'technique_id' in alert
            assert 'technique_name' in alert
            assert 'severity_score' in alert
            assert 'message' in alert
            assert 'timestamp' in alert
            assert alert['type'] == "CRITICAL_RISK_DETECTED"

    def test_no_alerts_when_disabled(self):
        """Test no alerts when disabled"""
        result = self.generator.generate_heatmap(self.sample_detections, include_alerts=False)
        assert len(result.alerts) == 0

    def test_historical_trend_calculation(self):
        """Test trend calculation with historical data"""
        historical = [
            {"technique_id": "T1566", "detected_at": "2026-06-17T10:30:00Z"},
            {"technique_id": "T1566", "detected_at": "2026-06-17T10:35:00Z"},
        ]
        
        result = self.generator.generate_heatmap(self.sample_detections, historical_data=historical)
        
        valid_trends = {"increasing", "decreasing", "stable"}
        for cell in result.heatmap_data:
            assert cell['trend_direction'] in valid_trends
            assert isinstance(cell['trend_percent'], float)

    def test_dashboard_summary(self):
        """Test dashboard summary calculation"""
        result = self.generator.generate_heatmap(self.sample_detections)
        summary = self.generator.get_dashboard_summary(result)
        
        assert 'heatmap_id' in summary
        assert 'total_detections' in summary
        assert 'total_techniques' in summary
        assert 'active_tactics' in summary
        assert 'risk_breakdown' in summary
        assert 'overall_risk_score' in summary
        
        assert summary['total_detections'] == 12
        assert summary['total_techniques'] == 31
        assert summary['overall_risk_score'] > 0

    def test_export_to_json(self):
        """Test JSON export functionality"""
        result = self.generator.generate_heatmap(self.sample_detections)
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            filepath = f.name
        
        try:
            success = self.generator.export_to_json(result, filepath)
            assert success is True
            
            with open(filepath, 'r') as f:
                exported = json.load(f)
            
            assert exported['heatmap_id'] == result.heatmap_id
            assert 'heatmap_data' in exported
            assert 'tactic_summary' in exported
        finally:
            os.unlink(filepath)

    def test_export_to_csv(self):
        """Test CSV export functionality"""
        result = self.generator.generate_heatmap(self.sample_detections)
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            filepath = f.name
        
        try:
            success = self.generator.export_to_csv(result, filepath)
            assert success is True
            
            with open(filepath, 'r') as f:
                lines = f.readlines()
            
            # Header + data rows
            assert len(lines) == 32  # 1 header + 31 data rows
            assert "Tactic" in lines[0]
            assert "Technique ID" in lines[0]
        finally:
            os.unlink(filepath)

    def test_custom_configuration(self):
        """Test generator with custom configuration"""
        custom_config = {
            'high_risk_threshold': 6.0,
            'critical_threshold': 8.0,
            'alert_on_critical': False
        }
        
        custom_gen = MITREHeatmapGenerator(custom_config)
        assert custom_gen.high_risk_threshold == 6.0
        assert custom_gen.critical_threshold == 8.0
        assert custom_gen.alert_on_critical is False

    def test_technique_detection_counting(self):
        """Test detection counts are accurately counted"""
        result = self.generator.generate_heatmap(self.sample_detections)
        
        # Find T1566 (Phishing) - should have 3 detections
        phishing_cell = next(c for c in result.heatmap_data if c['technique_id'] == 'T1566')
        assert phishing_cell['count'] == 3
        
        # Find T1555 (Credentials from Password Stores) - should have 4 detections
        cred_cell = next(c for c in result.heatmap_data if c['technique_id'] == 'T1555')
        assert cred_cell['count'] == 4

    def test_error_handling_invalid_data(self):
        """Test error handling gracefully"""
        # This should not crash, just skip invalid technique IDs
        invalid_data = [
            {"technique_id": "INVALID_123", "detected_at": "2026-06-18T10:30:00Z"},
            {"technique_id": "T1566", "detected_at": "2026-06-18T10:30:00Z"},
        ]
        
        result = self.generator.generate_heatmap(invalid_data)
        assert result.success is True
        
        # Valid T1566 should be counted
        phishing_cell = next(c for c in result.heatmap_data if c['technique_id'] == 'T1566')
        assert phishing_cell['count'] == 1

    def test_generation_caching(self):
        """Test generation caching works"""
        result1 = self.generator.generate_heatmap(self.sample_detections)
        result2 = self.generator.generate_heatmap(self.sample_detections)
        
        assert self.generator.generation_count == 2
        assert result1.heatmap_id in self.generator.cache
        assert result2.heatmap_id in self.generator.cache
        assert result1.heatmap_id != result2.heatmap_id  # Different IDs for different runs


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
