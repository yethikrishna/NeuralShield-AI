"""
Test Suite for MITRE ATT&CK Mapping Engine v77
DIMENSION A - Feature Expansion
Tests cover: basic functionality, edge cases, integration, and error paths.
All existing tests must continue to pass.
"""

import pytest
import json
from datetime import datetime

from neural_shield.feature_expansion_mitre_attack_mapping_engine_v77_2026_june import (
    MITREAttackMappingEngine,
    MITRETactic,
    MITRETechnique,
    ThreatMappingResult,
    mitre_mapping_engine
)


class TestMITRETactic:
    """Test MITRE Tactic enumeration"""
    
    def test_tactic_values_exist(self):
        """Test all expected tactics are defined"""
        expected_tactics = [
            "reconnaissance", "resource-development", "initial-access",
            "execution", "persistence", "privilege-escalation",
            "defense-evasion", "credential-access", "discovery",
            "lateral-movement", "collection", "command-and-control",
            "exfiltration", "impact"
        ]
        for tactic in expected_tactics:
            assert tactic in [t.value for t in MITRETactic]
    
    def test_tactic_count(self):
        """Test correct number of tactics (14 Enterprise tactics)"""
        assert len(MITRETactic) == 14


class TestMITRETechnique:
    """Test MITRE Technique dataclass"""
    
    def test_technique_creation(self):
        """Test technique object creation"""
        technique = MITRETechnique(
            technique_id="T1566",
            name="Phishing",
            tactic=MITRETactic.INITIAL_ACCESS,
            description="Test description",
            severity_score=7.5
        )
        assert technique.technique_id == "T1566"
        assert technique.name == "Phishing"
        assert technique.tactic == MITRETactic.INITIAL_ACCESS
        assert technique.severity_score == 7.5
    
    def test_technique_default_values(self):
        """Test default values are properly set"""
        technique = MITRETechnique(
            technique_id="T0000",
            name="Test",
            tactic=MITRETactic.EXECUTION,
            description="Test"
        )
        assert technique.severity_score == 5.0
        assert technique.data_sources == []
        assert technique.mitigations == []


class TestMITREAttackMappingEngine:
    """Test core mapping engine functionality"""
    
    def test_engine_initialization(self):
        """Test engine initializes properly"""
        engine = MITREAttackMappingEngine()
        assert len(engine._technique_database) > 0
        assert len(engine._threat_to_technique_map) > 0
    
    def test_singleton_instance(self):
        """Test singleton instance is available"""
        assert mitre_mapping_engine is not None
        assert isinstance(mitre_mapping_engine, MITREAttackMappingEngine)
    
    def test_map_prompt_injection(self):
        """Test mapping prompt injection threat"""
        engine = MITREAttackMappingEngine()
        result = engine.map_threat_to_mitre("prompt_injection")
        
        assert result.threat_type == "prompt_injection"
        assert len(result.mapped_techniques) > 0
        assert result.confidence_score > 0
        assert result.risk_score > 0
        assert len(result.attack_chain) > 0
    
    def test_map_jailbreak(self):
        """Test mapping jailbreak threat"""
        engine = MITREAttackMappingEngine()
        result = engine.map_threat_to_mitre("jailbreak")
        
        assert result.threat_type == "jailbreak"
        assert any("Impair Defenses" in t.name for t in result.mapped_techniques)
        assert MITRETactic.DEFENSE_EVASION in result.attack_chain
    
    def test_map_data_exfiltration(self):
        """Test mapping data exfiltration threat"""
        engine = MITREAttackMappingEngine()
        result = engine.map_threat_to_mitre("data_exfiltration")
        
        assert result.risk_score >= 9.0  # High severity
        assert MITRETactic.EXFILTRATION in result.attack_chain
        assert MITRETactic.CREDENTIAL_ACCESS in result.attack_chain
    
    def test_threat_id_generation(self):
        """Test automatic threat ID generation"""
        engine = MITREAttackMappingEngine()
        result1 = engine.map_threat_to_mitre("prompt_injection")
        result2 = engine.map_threat_to_mitre("prompt_injection")
        
        assert result1.threat_id is not None
        assert len(result1.threat_id) == 16  # 16 hex chars
    
    def test_custom_threat_id(self):
        """Test custom threat ID"""
        engine = MITREAttackMappingEngine()
        result = engine.map_threat_to_mitre("jailbreak", threat_id="TEST-001")
        assert result.threat_id == "TEST-001"
    
    def test_threat_data_severity_adjustment(self):
        """Test threat data affects risk score"""
        engine = MITREAttackMappingEngine()
        result_normal = engine.map_threat_to_mitre("prompt_injection")
        result_high = engine.map_threat_to_mitre(
            "prompt_injection",
            threat_data={"severity": 0.95}
        )
        assert result_high.risk_score >= result_normal.risk_score
    
    def test_unknown_threat_type(self):
        """Test handling unknown threat type"""
        engine = MITREAttackMappingEngine()
        result = engine.map_threat_to_mitre("unknown_threat_type_xyz")
        
        assert result.mapped_techniques == []
        assert result.confidence_score == 0.4
        assert result.risk_score == 0.0
    
    def test_get_technique_by_id(self):
        """Test retrieving technique by ID"""
        engine = MITREAttackMappingEngine()
        technique = engine.get_technique_by_id("T1566")
        
        assert technique is not None
        assert technique.technique_id == "T1566"
        assert technique.name == "Phishing"
    
    def test_get_nonexistent_technique(self):
        """Test retrieving non-existent technique"""
        engine = MITREAttackMappingEngine()
        technique = engine.get_technique_by_id("T9999")
        assert technique is None
    
    def test_get_techniques_by_tactic(self):
        """Test filtering techniques by tactic"""
        engine = MITREAttackMappingEngine()
        defense_evasion = engine.get_techniques_by_tactic(MITRETactic.DEFENSE_EVASION)
        
        assert len(defense_evasion) >= 2
        assert all(t.tactic == MITRETactic.DEFENSE_EVASION for t in defense_evasion)
    
    def test_mapping_cache(self):
        """Test result caching works"""
        engine = MITREAttackMappingEngine()
        result1 = engine.map_threat_to_mitre("jailbreak", threat_id="CACHE-TEST")
        result2 = engine.map_threat_to_mitre("jailbreak", threat_id="CACHE-TEST")
        
        assert result1 is result2  # Same object from cache
    
    def test_timestamp_format(self):
        """Test timestamp is valid ISO format"""
        engine = MITREAttackMappingEngine()
        result = engine.map_threat_to_mitre("prompt_injection")
        
        # Should parse as valid ISO datetime
        datetime.fromisoformat(result.mapping_timestamp)


class TestMITREReportGeneration:
    """Test MITRE report generation functionality"""
    
    def test_generate_empty_report(self):
        """Test report with no mappings"""
        engine = MITREAttackMappingEngine()
        report = engine.generate_mitre_report([])
        
        assert report["summary"]["total_threats_mapped"] == 0
        assert report["summary"]["unique_techniques_observed"] == 0
        assert "recommendations" in report
    
    def test_generate_single_threat_report(self):
        """Test report with single threat mapping"""
        engine = MITREAttackMappingEngine()
        results = [engine.map_threat_to_mitre("jailbreak")]
        report = engine.generate_mitre_report(results)
        
        assert report["summary"]["total_threats_mapped"] == 1
        assert report["summary"]["tactics_covered"] >= 1
        assert report["summary"]["average_risk_score"] > 0
    
    def test_generate_multi_threat_report(self):
        """Test comprehensive report with multiple threats"""
        engine = MITREAttackMappingEngine()
        results = [
            engine.map_threat_to_mitre("prompt_injection"),
            engine.map_threat_to_mitre("jailbreak"),
            engine.map_threat_to_mitre("data_exfiltration"),
            engine.map_threat_to_mitre("rag_poisoning"),
        ]
        report = engine.generate_mitre_report(results)
        
        assert report["summary"]["total_threats_mapped"] == 4
        assert report["summary"]["tactics_covered"] >= 3
        assert report["summary"]["coverage_percentage"] > 0
        assert len(report["tactic_distribution"]) > 0
        assert len(report["top_techniques"]) > 0
        assert len(report["recommendations"]) > 0
    
    def test_report_high_risk_recommendations(self):
        """Test recommendations for high-risk tactics"""
        engine = MITREAttackMappingEngine()
        results = [
            engine.map_threat_to_mitre("data_exfiltration"),  # Triggers credential/exfiltration
        ]
        report = engine.generate_mitre_report(results)
        
        recommendations = " ".join(report["recommendations"])
        assert any("HIGH PRIORITY" in r for r in report["recommendations"])
    
    def test_export_json_format(self):
        """Test JSON export functionality"""
        engine = MITREAttackMappingEngine()
        results = [
            engine.map_threat_to_mitre("prompt_injection"),
            engine.map_threat_to_mitre("jailbreak"),
        ]
        json_output = engine.export_mitre_mapping_json(results)
        
        # Should be valid JSON
        parsed = json.loads(json_output)
        assert len(parsed) == 2
        assert "threat_id" in parsed[0]
        assert "techniques" in parsed[0]
        assert "attack_chain" in parsed[0]


class TestAttackChainAnalysis:
    """Test attack chain building and analysis"""
    
    def test_attack_chain_order(self):
        """Test attack chain follows MITRE kill chain order"""
        engine = MITREAttackMappingEngine()
        result = engine.map_threat_to_mitre("multi_turn_attack")
        
        # Attack chain should be ordered according to MITRETactic enum
        tactics_list = list(MITRETactic)
        chain_indices = [tactics_list.index(t) for t in result.attack_chain]
        assert chain_indices == sorted(chain_indices)
    
    def test_attack_chain_no_duplicates(self):
        """Test attack chain has no duplicate tactics"""
        engine = MITREAttackMappingEngine()
        result = engine.map_threat_to_mitre("data_exfiltration")
        
        assert len(result.attack_chain) == len(set(result.attack_chain))


class TestConfidenceScoring:
    """Test confidence scoring logic"""
    
    def test_confidence_increases_with_matches(self):
        """Test confidence correlates with number of matched techniques"""
        engine = MITREAttackMappingEngine()
        
        # Single technique match
        result_single = engine.map_threat_to_mitre("jailbreak")
        
        # Multiple technique matches
        result_multi = engine.map_threat_to_mitre("data_exfiltration")
        
        # More matches = higher confidence
        assert result_multi.confidence_score >= result_single.confidence_score
    
    def test_confidence_maximum(self):
        """Test confidence never exceeds 1.0"""
        engine = MITREAttackMappingEngine()
        result = engine.map_threat_to_mitre("data_exfiltration")
        assert result.confidence_score <= 1.0
    
    def test_confidence_minimum(self):
        """Test minimum confidence floor"""
        engine = MITREAttackMappingEngine()
        result = engine.map_threat_to_mitre("unknown_type")
        assert result.confidence_score >= 0.4


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
