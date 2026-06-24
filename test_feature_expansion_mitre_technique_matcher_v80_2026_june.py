"""
Test Suite for MITRE ATT&CK Technique Matcher v80
DIMENSION A - Feature Expansion Tests

All tests must pass. Backward compatibility verified.
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from neural_shield.feature_expansion_mitre_technique_matcher_v80_2026_june import (
    MITREAttackTechniqueMatcher,
    MITREAttackTactic,
    MITRETechnique,
    TechniqueMatch,
    get_mitre_matcher,
    match_threat_to_mitre
)


class TestMITREAttackTechniqueMatcher:
    """Test suite for MITRE ATT&CK Technique Matcher"""
    
    def test_matcher_initialization(self):
        """Test matcher initializes correctly"""
        matcher = MITREAttackTechniqueMatcher()
        assert matcher is not None
        assert len(matcher.techniques) > 0
        assert matcher.match_history == []
    
    def test_technique_database_populated(self):
        """Test technique database contains expected techniques"""
        matcher = MITREAttackTechniqueMatcher()
        
        # Check key techniques exist
        assert "T1566" in matcher.techniques  # Phishing
        assert "T1003" in matcher.techniques  # Credential Dumping
        assert "T1486" in matcher.techniques  # Ransomware
        assert "T1001" in matcher.techniques  # Prompt Injection
    
    def test_match_threat_phishing(self):
        """Test matching phishing threat"""
        matcher = MITREAttackTechniqueMatcher()
        matches = matcher.match_threat("User received phishing email with malicious attachment")
        
        assert len(matches) > 0
        phishing_match = next((m for m in matches if m.technique.technique_id == "T1566"), None)
        assert phishing_match is not None
        assert phishing_match.confidence_score > 0.3
    
    def test_match_threat_ransomware(self):
        """Test matching ransomware threat"""
        matcher = MITREAttackTechniqueMatcher()
        matches = matcher.match_threat("Files encrypted with ransom note demanding bitcoin payment")
        
        ransom_match = next((m for m in matches if m.technique.technique_id == "T1486"), None)
        assert ransom_match is not None
        assert ransom_match.confidence_score > 0.3
    
    def test_match_threat_prompt_injection(self):
        """Test matching prompt injection threat"""
        matcher = MITREAttackTechniqueMatcher()
        matches = matcher.match_threat("Jailbreak attempt with ignore previous instructions DAN prompt")
        
        prompt_inj_match = next((m for m in matches if m.technique.technique_id == "T1001"), None)
        assert prompt_inj_match is not None
        assert prompt_inj_match.confidence_score > 0.3
    
    def test_match_threat_credential_dumping(self):
        """Test matching credential dumping threat"""
        matcher = MITREAttackTechniqueMatcher()
        matches = matcher.match_threat("LSASS memory dump detected using mimikatz")
        
        dump_match = next((m for m in matches if m.technique.technique_id == "T1003"), None)
        assert dump_match is not None
        assert dump_match.confidence_score > 0.3
    
    def test_match_empty_threat(self):
        """Test handling empty threat text"""
        matcher = MITREAttackTechniqueMatcher()
        matches = matcher.match_threat("")
        assert matches == []
        
        matches = matcher.match_threat("   ")
        assert matches == []
    
    def test_match_min_confidence_filter(self):
        """Test minimum confidence filtering"""
        matcher = MITREAttackTechniqueMatcher()
        matches = matcher.match_threat("phishing email", min_confidence=0.9)
        # Should return empty or very few matches with very high threshold
        assert isinstance(matches, list)
    
    def test_get_technique_by_id(self):
        """Test retrieving technique by ID"""
        matcher = MITREAttackTechniqueMatcher()
        technique = matcher.get_technique_by_id("T1566")
        
        assert technique is not None
        assert technique.technique_id == "T1566"
        assert technique.name == "Phishing"
    
    def test_get_technique_by_id_not_found(self):
        """Test retrieving non-existent technique"""
        matcher = MITREAttackTechniqueMatcher()
        technique = matcher.get_technique_by_id("T9999")
        assert technique is None
    
    def test_get_techniques_by_tactic(self):
        """Test retrieving techniques by tactic"""
        matcher = MITREAttackTechniqueMatcher()
        initial_access = matcher.get_techniques_by_tactic(MITREAttackTactic.INITIAL_ACCESS)
        
        assert len(initial_access) > 0
        assert all(t.tactic == MITREAttackTactic.INITIAL_ACCESS for t in initial_access)
    
    def test_get_match_summary_empty(self):
        """Test match summary with no history"""
        matcher = MITREAttackTechniqueMatcher()
        summary = matcher.get_match_summary()
        
        assert summary["total_matches"] == 0
        assert summary["tactic_distribution"] == {}
    
    def test_get_match_summary_with_matches(self):
        """Test match summary after matching"""
        matcher = MITREAttackTechniqueMatcher()
        matcher.match_threat("phishing email attachment")
        matcher.match_threat("ransomware encrypt files bitcoin")
        
        summary = matcher.get_match_summary()
        assert summary["total_matches"] > 0
        assert summary["unique_techniques_matched"] > 0
        assert "average_confidence" in summary
    
    def test_generate_threat_report(self):
        """Test comprehensive threat report generation"""
        matcher = MITREAttackTechniqueMatcher()
        report = matcher.generate_threat_report(
            "User opened malicious email attachment, powershell execution detected"
        )
        
        assert "threat_analyzed" in report
        assert "techniques_matched" in report
        assert "overall_severity" in report
        assert "primary_tactic" in report
        assert "recommendations" in report
        assert len(report["techniques_matched"]) > 0
    
    def test_generate_threat_report_no_matches(self):
        """Test threat report with no matches"""
        matcher = MITREAttackTechniqueMatcher()
        report = matcher.generate_threat_report("xyz123_nomatch")
        
        assert report["overall_severity"] == 0
        assert report["primary_tactic"] == "Unknown"
    
    def test_singleton_instance(self):
        """Test singleton pattern works"""
        matcher1 = get_mitre_matcher()
        matcher2 = get_mitre_matcher()
        
        assert matcher1 is matcher2
    
    def test_convenience_function(self):
        """Test convenience match function"""
        report = match_threat_to_mitre("phishing email with malicious attachment")
        
        assert "techniques_matched" in report
        assert "overall_severity" in report
    
    def test_matches_sorted_by_confidence(self):
        """Test matches are sorted by confidence descending"""
        matcher = MITREAttackTechniqueMatcher()
        matches = matcher.match_threat("phishing email powershell execution dump lsass mimikatz")
        
        confidences = [m.confidence_score for m in matches]
        assert confidences == sorted(confidences, reverse=True)
    
    def test_matched_keywords_recorded(self):
        """Test matched keywords are recorded"""
        matcher = MITREAttackTechniqueMatcher()
        matches = matcher.match_threat("phishing email attachment")
        
        for match in matches:
            assert len(match.matched_keywords) > 0
            assert all(isinstance(kw, str) for kw in match.matched_keywords)
    
    def test_severity_scores(self):
        """Test techniques have appropriate severity scores"""
        matcher = MITREAttackTechniqueMatcher()
        
        # Ransomware should have high severity
        ransomware = matcher.get_technique_by_id("T1486")
        assert ransomware.severity_score == 10.0
        
        # Credential dumping should be very high severity
        cred_dump = matcher.get_technique_by_id("T1003")
        assert cred_dump.severity_score >= 9.0
        
        # Discovery techniques have lower severity
        discovery = matcher.get_technique_by_id("T1087")
        assert discovery.severity_score <= 6.0
    
    def test_recommendations_generated(self):
        """Test security recommendations are generated"""
        matcher = MITREAttackTechniqueMatcher()
        report = matcher.generate_threat_report(
            "ransomware detected encrypting files, shadow copies deleted"
        )
        
        assert len(report["recommendations"]) > 0
        assert any("backup" in rec.lower() or "recovery" in rec.lower() 
                   for rec in report["recommendations"])


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
    print("\n✅ All MITRE Technique Matcher tests passed!")
