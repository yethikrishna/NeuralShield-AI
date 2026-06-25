"""
Test Suite for Threat Hunting Playbook Generator v83
Dimension A: Feature Expansion - Test Coverage
All tests verify production-grade functionality
"""
import pytest
import json
from neural_shield.feature_expansion_threat_hunting_playbook_generator_v83_2026_june import (
    ThreatHuntingPlaybookGenerator,
    generate_threat_hunting_playbook,
    get_supported_techniques,
    PlaybookType,
    SeverityLevel,
    HuntingPlaybook,
    HuntingStep
)


class TestThreatHuntingPlaybookGenerator:
    """Test suite for ThreatHuntingPlaybookGenerator class"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.generator = ThreatHuntingPlaybookGenerator()
    
    def test_initialization(self):
        """Test generator initialization"""
        assert self.generator.playbook_templates is not None
        assert self.generator.data_source_mappings is not None
        assert self.generator.tool_mappings is not None
        assert len(self.generator.playbook_templates) > 0
    
    def test_get_available_techniques(self):
        """Test getting available techniques list"""
        techniques = self.generator.get_available_techniques()
        assert isinstance(techniques, list)
        assert len(techniques) > 0
        assert "T1059" in techniques
        assert "T1027" in techniques
    
    def test_generate_playbook_existing_technique(self):
        """Test playbook generation for existing technique"""
        playbook = self.generator.generate_playbook("T1059")
        
        assert isinstance(playbook, HuntingPlaybook)
        assert playbook.playbook_id.startswith("PB-T1059-")
        assert "Command and Scripting Interpreter" in playbook.title
        assert len(playbook.mitre_techniques) > 0
        assert len(playbook.steps) > 0
        assert len(playbook.prerequisites) > 0
        assert len(playbook.success_criteria) > 0
        assert playbook.version == "1.0.0"
    
    def test_generate_playbook_with_subtechnique(self):
        """Test playbook generation with subtechnique ID"""
        playbook = self.generator.generate_playbook("T1059.001")
        
        assert isinstance(playbook, HuntingPlaybook)
        assert playbook.playbook_id.startswith("PB-T1059-")
        assert len(playbook.steps) > 0
    
    def test_generate_playbook_unknown_technique(self):
        """Test playbook generation for unknown technique (generic fallback)"""
        playbook = self.generator.generate_playbook("T9999")
        
        assert isinstance(playbook, HuntingPlaybook)
        assert "Generic" in playbook.title
        assert playbook.playbook_id.startswith("PB-GEN-")
        assert len(playbook.steps) > 0
    
    def test_playbook_step_structure(self):
        """Test that generated playbook steps have correct structure"""
        playbook = self.generator.generate_playbook("T1003")
        
        for step in playbook.steps:
            assert isinstance(step, HuntingStep)
            assert step.step_id is not None
            assert len(step.description) > 0
            assert len(step.data_sources) > 0
            assert len(step.tools) > 0
            assert len(step.expected_outcome) > 0
            assert isinstance(step.severity, SeverityLevel)
            assert step.estimated_time_minutes > 0
    
    def test_playbook_severity_levels(self):
        """Test that severity levels are properly set"""
        playbook = self.generator.generate_playbook("T1003")
        
        severities = [step.severity for step in playbook.steps]
        assert SeverityLevel.MEDIUM in severities or SeverityLevel.HIGH in severities
    
    def test_export_playbook_markdown(self):
        """Test markdown export functionality"""
        playbook = self.generator.generate_playbook("T1053")
        markdown = self.generator.export_playbook_markdown(playbook)
        
        assert isinstance(markdown, str)
        assert len(markdown) > 0
        assert "# " in markdown  # Header
        assert "## Description" in markdown
        assert "## Prerequisites" in markdown
        assert "## Hunting Procedures" in markdown
        assert "## Success Criteria" in markdown
    
    def test_export_playbook_json(self):
        """Test JSON export functionality"""
        playbook = self.generator.generate_playbook("T1046")
        json_output = self.generator.export_playbook_json(playbook)
        
        assert isinstance(json_output, str)
        parsed = json.loads(json_output)
        assert "playbook_id" in parsed
        assert "title" in parsed
        assert "steps" in parsed
        assert "mitre_techniques" in parsed
        assert isinstance(parsed["steps"], list)
        assert len(parsed["steps"]) > 0
    
    def test_playbook_type_enum(self):
        """Test PlaybookType enum values"""
        assert PlaybookType.TACTICAL.value == "tactical"
        assert PlaybookType.OPERATIONAL.value == "operational"
        assert PlaybookType.STRATEGIC.value == "strategic"
        assert PlaybookType.INCIDENT_RESPONSE.value == "incident_response"
        assert PlaybookType.THREAT_HUNTING.value == "threat_hunting"
    
    def test_severity_level_enum(self):
        """Test SeverityLevel enum values"""
        assert SeverityLevel.LOW.value == "low"
        assert SeverityLevel.MEDIUM.value == "medium"
        assert SeverityLevel.HIGH.value == "high"
        assert SeverityLevel.CRITICAL.value == "critical"
    
    def test_data_source_mappings_complete(self):
        """Test that all data source categories are present"""
        assert "process" in self.generator.data_source_mappings
        assert "network" in self.generator.data_source_mappings
        assert "file" in self.generator.data_source_mappings
        assert "registry" in self.generator.data_source_mappings
        assert "memory" in self.generator.data_source_mappings
    
    def test_tool_mappings_complete(self):
        """Test that all tool categories are present"""
        assert "endpoint" in self.generator.tool_mappings
        assert "network" in self.generator.tool_mappings
        assert "forensics" in self.generator.tool_mappings
        assert "siem" in self.generator.tool_mappings


class TestConvenienceFunctions:
    """Test suite for module-level convenience functions"""
    
    def test_generate_threat_hunting_playbook_object(self):
        """Test convenience function returning object"""
        result = generate_threat_hunting_playbook("T1059", output_format="object")
        assert isinstance(result, HuntingPlaybook)
    
    def test_generate_threat_hunting_playbook_markdown(self):
        """Test convenience function returning markdown"""
        result = generate_threat_hunting_playbook("T1059", output_format="markdown")
        assert isinstance(result, str)
        assert "# " in result
    
    def test_generate_threat_hunting_playbook_json(self):
        """Test convenience function returning JSON"""
        result = generate_threat_hunting_playbook("T1059", output_format="json")
        assert isinstance(result, str)
        parsed = json.loads(result)
        assert "playbook_id" in parsed
    
    def test_get_supported_techniques(self):
        """Test get_supported_techniques function"""
        techniques = get_supported_techniques()
        assert isinstance(techniques, list)
        assert len(techniques) > 0
        assert all(isinstance(t, str) for t in techniques)


class TestEdgeCases:
    """Test suite for edge cases and boundary conditions"""
    
    def setup_method(self):
        self.generator = ThreatHuntingPlaybookGenerator()
    
    def test_empty_technique_id(self):
        """Test handling of empty technique ID"""
        # Should fall back to generic playbook
        playbook = self.generator.generate_playbook("")
        assert isinstance(playbook, HuntingPlaybook)
        assert "Generic" in playbook.title
    
    def test_nonexistent_subtechnique(self):
        """Test nonexistent subtechnique"""
        playbook = self.generator.generate_playbook("T1059.999")
        assert isinstance(playbook, HuntingPlaybook)
        # Should still use T1059 base template
        assert "Command and Scripting" in playbook.title
    
    def test_playbook_step_estimated_time(self):
        """Test that all steps have reasonable estimated times"""
        playbook = self.generator.generate_playbook("T1027")
        
        for step in playbook.steps:
            assert step.estimated_time_minutes >= 5
            assert step.estimated_time_minutes <= 120
    
    def test_generic_playbook_structure(self):
        """Test generic playbook has minimum required structure"""
        playbook = self.generator.generate_playbook("T9999")
        
        assert len(playbook.steps) >= 2
        assert len(playbook.prerequisites) >= 1
        assert len(playbook.success_criteria) >= 1
        assert playbook.playbook_type == PlaybookType.THREAT_HUNTING


class TestIntegration:
    """Integration tests for end-to-end functionality"""
    
    def test_full_playbook_generation_workflow(self):
        """Test complete playbook generation workflow"""
        generator = ThreatHuntingPlaybookGenerator()
        
        # Get supported techniques
        techniques = generator.get_available_techniques()
        assert len(techniques) > 0
        
        # Generate playbook for each technique
        for technique in techniques[:3]:  # Test first 3 for speed
            playbook = generator.generate_playbook(technique)
            
            # Verify structure
            assert isinstance(playbook, HuntingPlaybook)
            assert len(playbook.steps) > 0
            
            # Export to all formats
            md = generator.export_playbook_markdown(playbook)
            json_str = generator.export_playbook_json(playbook)
            
            assert len(md) > 0
            assert len(json_str) > 0
            
            # Verify JSON is valid
            parsed = json.loads(json_str)
            assert parsed["playbook_id"] == playbook.playbook_id
    
    def test_all_techniques_generate_valid_playbooks(self):
        """Test that all template techniques generate valid playbooks"""
        generator = ThreatHuntingPlaybookGenerator()
        techniques = generator.get_available_techniques()
        
        for technique in techniques:
            playbook = generator.generate_playbook(technique)
            assert isinstance(playbook, HuntingPlaybook)
            assert playbook.title is not None
            assert len(playbook.steps) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
