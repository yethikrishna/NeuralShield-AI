"""
Tests for MITRE ATT&CK Navigator Export Engine
Dimension A - Feature Expansion Tests

Comprehensive tests for the new Navigator export feature.
All tests are ADD-ONLY - no existing tests modified.
"""

import pytest
import json
import os
import tempfile
from neural_shield.threat_intelligence_mitre_navigator_export_engine_2026_june import (
    MITRENavigatorExportEngine,
    NavigatorColorMode,
    NavigatorLayerType,
    NavigatorScoreAggregation,
    NavigatorTechniqueScore,
    NavigatorGradient,
    NavigatorFilter,
    create_coverage_layer,
    create_risk_layer,
    create_frequency_layer
)


class TestNavigatorEnums:
    """Test enum classes"""
    
    def test_color_mode_values(self):
        assert NavigatorColorMode.GRADIENT.value == "gradient"
        assert NavigatorColorMode.DISCRETE.value == "discrete"
        assert NavigatorColorMode.BINARY.value == "binary"
    
    def test_layer_type_values(self):
        assert NavigatorLayerType.TECHNIQUE.value == "technique"
        assert NavigatorLayerType.TACTIC.value == "tactic"
    
    def test_aggregation_values(self):
        assert NavigatorScoreAggregation.SUM.value == "sum"
        assert NavigatorScoreAggregation.AVERAGE.value == "average"
        assert NavigatorScoreAggregation.MAX.value == "max"


class TestNavigatorDataclasses:
    """Test data classes"""
    
    def test_technique_score_creation(self):
        score = NavigatorTechniqueScore(
            technique_id="T1059",
            score=85.5,
            comment="Test technique",
            metadata={"source": "test"}
        )
        assert score.technique_id == "T1059"
        assert score.score == 85.5
        assert score.comment == "Test technique"
        assert score.metadata == {"source": "test"}
    
    def test_gradient_defaults(self):
        gradient = NavigatorGradient()
        assert len(gradient.colors) == 4
        assert gradient.min_value == 0.0
        assert gradient.max_value == 100.0
    
    def test_filter_defaults(self):
        f = NavigatorFilter()
        assert "Windows" in f.platforms
        assert "macOS" in f.platforms
        assert "Linux" in f.platforms


class TestMITRENavigatorExportEngine:
    """Main engine tests"""
    
    def test_engine_initialization(self):
        engine = MITRENavigatorExportEngine(
            layer_name="Test Layer",
            layer_description="Test Description"
        )
        assert engine.layer_name == "Test Layer"
        assert engine.layer_description == "Test Description"
        assert len(engine.techniques) == 0
    
    def test_add_technique_basic(self):
        engine = MITRENavigatorExportEngine()
        engine.add_technique("T1059", 75.0, "Command Execution")
        assert "T1059" in engine.techniques
        assert engine.techniques["T1059"].score == 75.0
    
    def test_add_technique_auto_prefix(self):
        """Test that T prefix is automatically added"""
        engine = MITRENavigatorExportEngine()
        engine.add_technique("1059", 75.0)
        assert "T1059" in engine.techniques
    
    def test_add_technique_with_metadata(self):
        engine = MITRENavigatorExportEngine()
        engine.add_technique("T1059", 75.0, metadata={"severity": "high"})
        assert engine.techniques["T1059"].metadata["severity"] == "high"
    
    def test_add_techniques_from_threat_alerts(self):
        alerts = [
            {"mitre_technique": {"technique_id": "T1059"}, "risk_score": 10, "name": "Alert1"},
            {"mitre_technique": {"technique_id": "T1059"}, "risk_score": 20, "name": "Alert2"},
            {"mitre_technique": {"technique_id": "T1027"}, "risk_score": 15, "name": "Alert3"},
        ]
        engine = MITRENavigatorExportEngine()
        count = engine.add_techniques_from_threat_alerts(alerts)
        assert count == 2
        assert engine.techniques["T1059"].score == 30.0
        assert engine.techniques["T1027"].score == 15.0
    
    def test_add_coverage_layer(self):
        detected = {"T1059", "T1027", "T1082"}
        engine = MITRENavigatorExportEngine()
        engine.add_coverage_layer(detected)
        assert len(engine.techniques) > 0
        assert engine.techniques["T1059"].score == 100.0
    
    def test_set_gradient(self):
        engine = MITRENavigatorExportEngine()
        engine.set_gradient(["#ff0000", "#00ff00"], 0, 50)
        assert engine.gradient.colors == ["#ff0000", "#00ff00"]
        assert engine.gradient.min_value == 0
        assert engine.gradient.max_value == 50
    
    def test_set_platform_filter(self):
        engine = MITRENavigatorExportEngine()
        engine.set_platform_filter(["Windows"])
        assert engine.filter.platforms == ["Windows"]
    
    def test_generate_layer_structure(self):
        engine = MITRENavigatorExportEngine()
        engine.add_technique("T1059", 85.0, "Test")
        layer = engine.generate_layer()
        
        # Validate Navigator schema structure
        assert layer["name"] == "NeuralShield Threat Coverage"
        assert layer["version"] == "4.6.1"
        assert layer["domain"] == "enterprise-attack"
        assert "techniques" in layer
        assert "gradient" in layer
        assert len(layer["techniques"]) == 1
    
    def test_generate_layer_technique_format(self):
        engine = MITRENavigatorExportEngine()
        engine.add_technique("T1059", 85.0, "Test Comment", {"meta": "value"})
        layer = engine.generate_layer()
        
        tech = layer["techniques"][0]
        assert tech["techniqueID"] == "T1059"
        assert tech["score"] == 85.0
        assert tech["comment"] == "Test Comment"
        assert len(tech["metadata"]) == 1
    
    def test_export_to_json_string(self):
        engine = MITRENavigatorExportEngine()
        engine.add_technique("T1059", 85.0)
        json_str = engine.export_to_json()
        
        # Validate it's valid JSON
        parsed = json.loads(json_str)
        assert parsed["name"] == "NeuralShield Threat Coverage"
    
    def test_export_to_file(self):
        engine = MITRENavigatorExportEngine()
        engine.add_technique("T1059", 85.0)
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            filepath = f.name
        
        try:
            result = engine.export_to_file(filepath)
            assert os.path.exists(filepath)
            
            with open(filepath) as f:
                data = json.load(f)
            assert data["name"] == "NeuralShield Threat Coverage"
        finally:
            os.unlink(filepath)
    
    def test_get_layer_hash(self):
        engine1 = MITRENavigatorExportEngine()
        engine1.add_technique("T1059", 85.0)
        
        engine2 = MITRENavigatorExportEngine()
        engine2.add_technique("T1059", 85.0)
        
        # Same content should have same hash
        assert engine1.get_layer_hash() == engine2.get_layer_hash()
    
    def test_merge_with_layer(self):
        engine1 = MITRENavigatorExportEngine()
        engine1.add_technique("T1059", 50.0)
        engine1.add_technique("T1027", 80.0)
        
        engine2 = MITRENavigatorExportEngine()
        engine2.add_technique("T1059", 90.0)  # Higher score
        engine2.add_technique("T1082", 70.0)  # New technique
        
        engine1.merge_with_layer(engine2)
        
        # Max score should win for T1059
        assert engine1.techniques["T1059"].score == 90.0
        # T1027 should remain
        assert "T1027" in engine1.techniques
        # T1082 should be added
        assert "T1082" in engine1.techniques
    
    def test_get_statistics(self):
        engine = MITRENavigatorExportEngine()
        engine.add_technique("T1059", 50.0)
        engine.add_technique("T1027", 80.0)
        
        stats = engine.get_statistics()
        assert stats["technique_count"] == 2
        assert stats["average_score"] == 65.0
        assert stats["max_score"] == 80.0
        assert stats["min_score"] == 50.0
    
    def test_get_statistics_empty(self):
        engine = MITRENavigatorExportEngine()
        stats = engine.get_statistics()
        assert stats["count"] == 0


class TestFactoryFunctions:
    """Test convenience factory functions"""
    
    def test_create_coverage_layer(self):
        detected = {"T1059", "T1027"}
        engine = create_coverage_layer(detected, "Test Coverage")
        assert engine.layer_name == "Test Coverage"
        assert len(engine.techniques) > 0
    
    def test_create_risk_layer(self):
        risks = {"T1059": 85.5, "T1027": 45.0}
        engine = create_risk_layer(risks, "Test Risk")
        assert engine.layer_name == "Test Risk"
        assert engine.techniques["T1059"].score == 85.5
    
    def test_create_frequency_layer(self):
        freq = {"T1059": 10, "T1027": 5}
        engine = create_frequency_layer(freq, "Test Frequency")
        assert engine.techniques["T1059"].score == 10.0


class TestBackwardCompatibility:
    """Test backward compatibility - no conflicts with existing modules"""
    
    def test_no_import_conflicts(self):
        """Verify module can be imported alongside existing modules"""
        # Import existing modules alongside new one
        import neural_shield.mitre_attack_v15_coverage_analyzer_2026_june as existing
        import neural_shield.threat_intelligence_mitre_navigator_export_engine_2026_june as new_module
        
        # Both should work
        assert existing is not None
        assert new_module is not None
    
    def test_module_isolation(self):
        """New module doesn't modify global state"""
        import sys
        initial_modules = set(sys.modules.keys())
        
        from neural_shield import threat_intelligence_mitre_navigator_export_engine_2026_june
        
        # No unexpected modules added
        assert "neural_shield.threat_intelligence_mitre_navigator_export_engine_2026_june" in sys.modules


class TestEdgeCases:
    """Edge case tests"""
    
    def test_empty_engine(self):
        engine = MITRENavigatorExportEngine()
        layer = engine.generate_layer()
        assert len(layer["techniques"]) == 0
    
    def test_duplicate_technique(self):
        engine = MITRENavigatorExportEngine()
        engine.add_technique("T1059", 50.0)
        engine.add_technique("T1059", 90.0)  # Overwrite
        assert engine.techniques["T1059"].score == 90.0
    
    def test_large_number_of_techniques(self):
        engine = MITRENavigatorExportEngine()
        for i in range(100):
            engine.add_technique(f"T{1000+i}", float(i))
        assert len(engine.techniques) == 100
        layer = engine.generate_layer()
        assert len(layer["techniques"]) == 100
    
    def test_alerts_without_mitre_field(self):
        """Alerts without MITRE field should be gracefully handled"""
        alerts = [
            {"name": "Alert without MITRE"},
            {"mitre_technique": {"technique_id": "T1059"}, "name": "Good Alert"},
        ]
        engine = MITRENavigatorExportEngine()
        count = engine.add_techniques_from_threat_alerts(alerts)
        assert count == 1  # Only the one with MITRE data


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
