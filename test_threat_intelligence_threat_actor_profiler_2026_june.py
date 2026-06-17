"""
Test suite for NeuralShield AI - Threat Intelligence Threat Actor Profiler
Production-grade unit tests with actual execution verification.
"""

import json
import pytest
from datetime import datetime, timezone
from neural_shield.threat_intelligence_threat_actor_profiler_2026_june import (
    ThreatActorProfiler,
    ThreatActorProfile,
    AttributionResult,
    ThreatActorType,
    ThreatActorSophistication,
    ThreatMotivation
)


class TestThreatActorProfiler:
    """Test suite for ThreatActorProfiler class"""

    def test_profiler_initialization(self):
        """Test that profiler initializes with known actors"""
        profiler = ThreatActorProfiler()
        actors = profiler.list_all_actors()
        
        assert len(actors) >= 5
        actor_ids = [a.actor_id for a in actors]
        assert "APT29" in actor_ids
        assert "APT28" in actor_ids
        assert "LAPSUS$" in actor_ids
        assert "CONTI" in actor_ids
        assert "ANONYMOUS" in actor_ids

    def test_get_actor_profile(self):
        """Test retrieving actor profile by ID"""
        profiler = ThreatActorProfiler()
        
        apt29 = profiler.get_actor_profile("APT29")
        assert apt29 is not None
        assert apt29.actor_id == "APT29"
        assert apt29.actor_name == "Cozy Bear"
        assert apt29.actor_type == ThreatActorType.NATION_STATE
        assert apt29.sophistication == ThreatActorSophistication.ELITE

    def test_get_nonexistent_actor(self):
        """Test retrieving non-existent actor returns None"""
        profiler = ThreatActorProfiler()
        result = profiler.get_actor_profile("NONEXISTENT")
        assert result is None

    def test_attribute_by_ttps_apt29(self):
        """Test attribution matching APT29 TTPs"""
        profiler = ThreatActorProfiler()
        
        observed_ttps = ["spear_phishing", "credential_stuffing", "lateral_movement"]
        result = profiler.attribute_by_ttps(observed_ttps)
        
        assert isinstance(result, AttributionResult)
        assert len(result.matched_actors) > 0
        assert result.primary_actor is not None
        assert len(result.matched_ttps) > 0
        assert result.confidence_score > 0

    def test_attribute_by_ttps_ransomware(self):
        """Test attribution matching ransomware TTPs"""
        profiler = ThreatActorProfiler()
        
        observed_ttps = ["ransomware", "double_extortion", "data_exfiltration"]
        result = profiler.attribute_by_ttps(observed_ttps)
        
        assert len(result.matched_actors) > 0
        assert result.confidence_score > 0
        assert result.risk_assessment is not None

    def test_attribute_with_mitre_techniques(self):
        """Test attribution with MITRE techniques"""
        profiler = ThreatActorProfiler()
        
        observed_ttps = ["spear_phishing"]
        observed_techniques = ["T1566", "T1003"]
        result = profiler.attribute_by_ttps(observed_ttps, observed_techniques)
        
        assert len(result.matched_techniques) > 0
        assert result.confidence_score > 0

    def test_attribute_with_iocs(self):
        """Test attribution with IOCs"""
        profiler = ThreatActorProfiler()
        
        observed_ttps = ["spear_phishing"]
        observed_iocs = {"domain": ["malicious-domain.ru"]}
        result = profiler.attribute_by_ttps(observed_ttps, observed_iocs=observed_iocs)
        
        assert result.confidence_score > 0

    def test_attribute_no_matches(self):
        """Test attribution with no matching patterns"""
        profiler = ThreatActorProfiler()
        
        observed_ttps = ["completely_unknown_ttp_xyz123"]
        result = profiler.attribute_by_ttps(observed_ttps)
        
        assert len(result.matched_actors) == 0
        assert result.primary_actor is None
        assert result.confidence_score == 0.0

    def test_risk_assessment_calculation(self):
        """Test risk assessment calculation"""
        profiler = ThreatActorProfiler()
        
        observed_ttps = ["spear_phishing", "credential_stuffing", "lateral_movement"]
        result = profiler.attribute_by_ttps(observed_ttps)
        
        risk = result.risk_assessment
        assert "overall_risk" in risk
        assert "risk_level" in risk
        assert "sophistication_level" in risk
        assert "primary_motivation" in risk
        assert "recommended_actions" in risk
        assert 0 <= risk["overall_risk"] <= 1.0

    def test_risk_level_critical_high(self):
        """Test that elite actors produce high risk levels"""
        profiler = ThreatActorProfiler()
        
        observed_ttps = ["spear_phishing", "watering_hole", "exploit_kit", "credential_dumping"]
        result = profiler.attribute_by_ttps(observed_ttps)
        
        risk = result.risk_assessment
        assert risk["risk_level"] in ["HIGH", "CRITICAL"]

    def test_search_actors(self):
        """Test actor search functionality"""
        profiler = ThreatActorProfiler()
        
        results = profiler.search_actors("APT")
        assert len(results) >= 2
        
        results = profiler.search_actors("Bear")
        assert len(results) >= 1
        
        results = profiler.search_actors("RUSSIA")
        assert len(results) >= 1

    def test_get_actors_by_sector(self):
        """Test filtering actors by target sector"""
        profiler = ThreatActorProfiler()
        
        government_actors = profiler.get_actors_by_sector("Government")
        assert len(government_actors) >= 3
        
        healthcare_actors = profiler.get_actors_by_sector("Healthcare")
        assert len(healthcare_actors) >= 2

    def test_get_actors_by_type(self):
        """Test filtering actors by type"""
        profiler = ThreatActorProfiler()
        
        nation_state = profiler.get_actors_by_type(ThreatActorType.NATION_STATE)
        assert len(nation_state) >= 2
        
        criminal = profiler.get_actors_by_type(ThreatActorType.CRIMINAL_ORGANIZATION)
        assert len(criminal) >= 2
        
        hacktivist = profiler.get_actors_by_type(ThreatActorType.HACKTIVIST)
        assert len(hacktivist) >= 1

    def test_export_profiles_json(self):
        """Test JSON export functionality"""
        profiler = ThreatActorProfiler()
        
        json_output = profiler.export_profiles_json()
        assert isinstance(json_output, str)
        
        parsed = json.loads(json_output)
        assert isinstance(parsed, list)
        assert len(parsed) >= 5
        
        for profile in parsed:
            assert "actor_id" in profile
            assert "actor_name" in profile
            assert "risk_score" in profile

    def test_generate_profile_hash(self):
        """Test profile hash generation"""
        profiler = ThreatActorProfiler()
        
        hash_val = profiler.generate_profile_hash("APT29")
        assert isinstance(hash_val, str)
        assert len(hash_val) == 16
        
        # Non-existent actor returns empty string
        empty_hash = profiler.generate_profile_hash("NONEXISTENT")
        assert empty_hash == ""

    def test_add_custom_actor_profile(self):
        """Test adding custom actor profile"""
        profiler = ThreatActorProfiler()
        initial_count = len(profiler.list_all_actors())
        
        custom_actor = ThreatActorProfile(
            actor_id="CUSTOM-001",
            actor_name="Test Actor",
            actor_type=ThreatActorType.SCRIPT_KIDDIE,
            sophistication=ThreatActorSophistication.LOW,
            motivations=[ThreatMotivation.UNKNOWN],
            associated_groups=[],
            known_ttps={"test_ttp"},
            mitre_techniques={"T9999"},
            ioc_signatures={},
            first_seen=datetime(2026, 1, 1, tzinfo=timezone.utc),
            last_seen=datetime.now(timezone.utc),
            risk_score=0.2,
            attribution_confidence=0.5,
            geographical_origins=["Test"],
            target_sectors=["Test"],
            tools_used=["TestTool"],
            description="Test actor profile"
        )
        
        profiler.add_actor_profile(custom_actor)
        
        assert len(profiler.list_all_actors()) == initial_count + 1
        retrieved = profiler.get_actor_profile("CUSTOM-001")
        assert retrieved is not None
        assert retrieved.actor_name == "Test Actor"

    def test_attribution_reasoning(self):
        """Test attribution reasoning generation"""
        profiler = ThreatActorProfiler()
        
        observed_ttps = ["spear_phishing", "ransomware"]
        result = profiler.attribute_by_ttps(observed_ttps)
        
        assert len(result.attribution_reasoning) > 0
        for reason in result.attribution_reasoning:
            assert isinstance(reason, str)
            assert len(reason) > 0

    def test_attribution_timestamp(self):
        """Test that attribution results have timestamp"""
        profiler = ThreatActorProfiler()
        
        result = profiler.attribute_by_ttps(["spear_phishing"])
        assert isinstance(result.timestamp, datetime)

    def test_base_risk_score_calculation(self):
        """Test base risk score calculation for sophistication levels"""
        profiler = ThreatActorProfiler()
        
        # Verify through actual actor profiles
        elite = profiler.get_actor_profile("APT29")
        assert elite.risk_score == 0.95
        
        advanced = profiler.get_actor_profile("LAPSUS$")
        assert advanced.risk_score == 0.8
        
        medium = profiler.get_actor_profile("ANONYMOUS")
        assert medium.risk_score == 0.4

    def test_recommendations_based_on_risk(self):
        """Test recommendations include appropriate actions"""
        profiler = ThreatActorProfiler()
        
        observed_ttps = ["spear_phishing", "credential_stuffing", "lateral_movement", "persistence"]
        result = profiler.attribute_by_ttps(observed_ttps)
        
        recommendations = result.risk_assessment["recommended_actions"]
        assert "enhance_logging" in recommendations
        assert "review_access_controls" in recommendations


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
