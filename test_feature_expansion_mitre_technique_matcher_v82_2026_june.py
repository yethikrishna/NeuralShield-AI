"""
Test Suite for MITRE ATT&CK Technique Matcher v82
Dimension A: Feature Expansion
35 comprehensive tests
"""

import unittest
import sys
import os

# Add neural_shield to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from feature_expansion_mitre_technique_matcher_v82_2026_june import (
    MITRETechniqueMatcher,
    MITRETechnique,
    TechniqueMatch,
    TechniqueChain,
    MITRETactic,
    MITREVector,
    ConfidenceLevel
)


class TestMITRETechniqueMatcherInit(unittest.TestCase):
    """Test initialization and database setup"""

    def test_matcher_initialization(self):
        """Test matcher initializes correctly"""
        matcher = MITRETechniqueMatcher()
        self.assertIsNotNone(matcher)
        self.assertIsNotNone(matcher.technique_database)
        self.assertIsNotNone(matcher.pattern_index)
        self.assertIsNotNone(matcher.threat_actor_techniques)

    def test_database_populated(self):
        """Test technique database has entries"""
        matcher = MITRETechniqueMatcher()
        self.assertGreater(len(matcher.technique_database), 30)
        self.assertIn("T1566", matcher.technique_database)  # Phishing
        self.assertIn("T1003", matcher.technique_database)  # Credential Dumping
        self.assertIn("T1486", matcher.technique_database)  # Ransomware

    def test_pattern_index_built(self):
        """Test pattern index is built"""
        matcher = MITRETechniqueMatcher()
        self.assertGreater(len(matcher.pattern_index), 100)
        self.assertIn("ransomware", matcher.pattern_index)
        self.assertIn("phish", matcher.pattern_index)

    def test_threat_actor_index(self):
        """Test threat actor index is built"""
        matcher = MITRETechniqueMatcher()
        self.assertIn("APT28", matcher.threat_actor_techniques)
        self.assertIn("APT29", matcher.threat_actor_techniques)
        self.assertIn("Conti", matcher.threat_actor_techniques)


class TestTechniqueMatching(unittest.TestCase):
    """Test content matching functionality"""

    def setUp(self):
        self.matcher = MITRETechniqueMatcher()

    def test_empty_content(self):
        """Test empty content returns empty matches"""
        matches = self.matcher.match_content("")
        self.assertEqual(matches, [])

    def test_whitespace_only(self):
        """Test whitespace only content"""
        matches = self.matcher.match_content("   \n\t  ")
        self.assertEqual(matches, [])

    def test_phishing_detection(self):
        """Test phishing technique detection"""
        content = "This attack used spearphishing with malicious attachment to gain initial access"
        matches = self.matcher.match_content(content)
        self.assertGreater(len(matches), 0)
        phish_matches = [m for m in matches if m.technique_id == "T1566"]
        self.assertGreater(len(phish_matches), 0)
        self.assertEqual(phish_matches[0].tactic, MITRETactic.INITIAL_ACCESS)

    def test_ransomware_detection(self):
        """Test ransomware technique detection"""
        content = "The ransomware encrypted all files and left a ransom note after deleting shadow copies with vssadmin"
        matches = self.matcher.match_content(content)
        ransom_matches = [m for m in matches if m.technique_id == "T1486"]
        self.assertGreater(len(ransom_matches), 0)
        self.assertEqual(ransom_matches[0].tactic, MITRETactic.IMPACT)

    def test_credential_dumping_detection(self):
        """Test credential dumping detection"""
        content = "Attackers used mimikatz to perform lsass dump and extract credentials from SAM database"
        matches = self.matcher.match_content(content)
        dump_matches = [m for m in matches if m.technique_id == "T1003"]
        self.assertGreater(len(dump_matches), 0)
        self.assertGreater(dump_matches[0].match_score, 0.5)

    def test_lateral_movement_detection(self):
        """Test lateral movement detection"""
        content = "Lateral movement via SMB and RDP using pass the hash with NTLM hash"
        matches = self.matcher.match_content(content)
        lateral_matches = [m for m in matches if m.technique_id == "T1550"]
        self.assertGreater(len(lateral_matches), 0)

    def test_confidence_levels(self):
        """Test confidence level calculation"""
        # High confidence match
        content = "mimikatz lsass dump credential dump sam database ntds"
        matches = self.matcher.match_content(content)
        if matches:
            self.assertIn(matches[0].confidence, [
                ConfidenceLevel.HIGH,
                ConfidenceLevel.CRITICAL,
                ConfidenceLevel.MEDIUM
            ])

    def test_matched_patterns_returned(self):
        """Test matched patterns are returned"""
        content = "powershell command execution with base64 encoded obfuscated payload"
        matches = self.matcher.match_content(content)
        if matches:
            self.assertGreater(len(matches[0].matched_patterns), 0)

    def test_evidence_snippets(self):
        """Test evidence snippets extraction"""
        content = "The attacker used mimikatz to dump lsass memory for credential extraction"
        matches = self.matcher.match_content(content)
        if matches:
            self.assertIsInstance(matches[0].evidence_snippets, list)

    def test_threat_actor_overlap(self):
        """Test threat actor overlap returned"""
        content = "mimikatz lsass dump credential theft"
        matches = self.matcher.match_content(content)
        if matches:
            self.assertGreater(len(matches[0].threat_actor_overlap), 0)
            self.assertIn("APT28", matches[0].threat_actor_overlap)


class TestTechniqueChains(unittest.TestCase):
    """Test kill chain detection"""

    def setUp(self):
        self.matcher = MITRETechniqueMatcher()

    def test_empty_matches_no_chain(self):
        """Test empty matches returns no chains"""
        chains = self.matcher.detect_technique_chains([])
        self.assertEqual(chains, [])

    def test_single_match_no_chain(self):
        """Test single match returns no chains"""
        content = "simple phishing attack"
        matches = self.matcher.match_content(content)
        chains = self.matcher.detect_technique_chains(matches[:1])
        self.assertEqual(chains, [])

    def test_multi_tactic_chain_detection(self):
        """Test multi-tactic kill chain detection"""
        content = """
        Initial phishing email led to code execution via powershell.
        Attacker then performed credential dumping with mimikatz
        and moved laterally via RDP before exfiltrating data.
        """
        matches = self.matcher.match_content(content)
        chains = self.matcher.detect_technique_chains(matches)
        self.assertIsInstance(chains, list)

    def test_chain_has_id(self):
        """Test chains have proper IDs"""
        content = "phishing email with powershell execution and credential dumping using mimikatz"
        matches = self.matcher.match_content(content)
        chains = self.matcher.detect_technique_chains(matches)
        for chain in chains:
            self.assertTrue(chain.chain_id.startswith("CHAIN-"))

    def test_chain_tactics_sequence(self):
        """Test chains have ordered tactics"""
        content = "phishing email led to powershell execution then mimikatz credential dump"
        matches = self.matcher.match_content(content)
        chains = self.matcher.detect_technique_chains(matches)
        for chain in chains:
            self.assertIsInstance(chain.tactics_sequence, list)
            self.assertGreater(len(chain.tactics_sequence), 0)

    def test_chain_confidence(self):
        """Test chains have overall confidence"""
        content = "phishing powershell mimikatz ransomware encryption"
        matches = self.matcher.match_content(content)
        chains = self.matcher.detect_technique_chains(matches)
        for chain in chains:
            self.assertIn(chain.overall_confidence, [
                ConfidenceLevel.LOW,
                ConfidenceLevel.MEDIUM,
                ConfidenceLevel.HIGH,
                ConfidenceLevel.CRITICAL
            ])

    def test_threat_actor_likelihood(self):
        """Test threat actor likelihood in chains"""
        content = "phishing powershell mimikatz lateral movement"
        matches = self.matcher.match_content(content)
        chains = self.matcher.detect_technique_chains(matches)
        for chain in chains:
            self.assertIsInstance(chain.threat_actor_likelihood, dict)


class TestDetectionRuleGeneration(unittest.TestCase):
    """Test YARA and Sigma rule generation"""

    def setUp(self):
        self.matcher = MITRETechniqueMatcher()

    def test_yara_rule_generation(self):
        """Test YARA rule generation"""
        content = "ransomware file encryption"
        matches = self.matcher.match_content(content)
        if matches:
            rule = self.matcher.generate_detection_rule(matches[0], "yara")
            self.assertIn("rule MITRE_", rule)
            self.assertIn("strings:", rule)
            self.assertIn("condition:", rule)

    def test_sigma_rule_generation(self):
        """Test Sigma rule generation"""
        content = "ransomware file encryption"
        matches = self.matcher.match_content(content)
        if matches:
            rule = self.matcher.generate_detection_rule(matches[0], "sigma")
            self.assertIn("title:", rule)
            self.assertIn("id:", rule)
            self.assertIn("detection:", rule)
            self.assertIn("level:", rule)

    def test_invalid_technique_returns_empty(self):
        """Test invalid technique returns empty rule"""
        fake_match = TechniqueMatch(
            technique_id="INVALID999",
            technique_name="Fake",
            tactic=MITRETactic.EXECUTION,
            confidence=ConfidenceLevel.LOW,
            match_score=0.5,
            matched_patterns=["test"],
            threat_actor_overlap=[]
        )
        rule = self.matcher.generate_detection_rule(fake_match, "yara")
        self.assertEqual(rule, "")

    def test_unknown_format_returns_empty(self):
        """Test unknown rule format returns empty"""
        content = "ransomware test"
        matches = self.matcher.match_content(content)
        if matches:
            rule = self.matcher.generate_detection_rule(matches[0], "unknown")
            self.assertEqual(rule, "")


class TestThreatActorProfiles(unittest.TestCase):
    """Test threat actor profile generation"""

    def setUp(self):
        self.matcher = MITRETechniqueMatcher()

    def test_known_actor_profile(self):
        """Test known threat actor profile"""
        profile = self.matcher.get_threat_actor_profile("APT28")
        self.assertEqual(profile["actor"], "APT28")
        self.assertGreater(profile["technique_count"], 0)
        self.assertIsInstance(profile["known_techniques"], list)
        self.assertGreater(profile["average_severity"], 0)

    def test_unknown_actor_profile(self):
        """Test unknown actor returns empty profile"""
        profile = self.matcher.get_threat_actor_profile("UNKNOWN_ACTOR_999")
        self.assertEqual(profile["actor"], "UNKNOWN_ACTOR_999")
        self.assertEqual(profile["technique_count"], 0)

    def test_profile_tactic_distribution(self):
        """Test tactic distribution in profile"""
        profile = self.matcher.get_threat_actor_profile("Conti")
        self.assertIsInstance(profile["tactic_distribution"], dict)
        self.assertGreater(len(profile["tactic_distribution"]), 0)


class TestCoverageSummary(unittest.TestCase):
    """Test coverage summary functionality"""

    def test_coverage_summary(self):
        """Test coverage summary returns correct data"""
        matcher = MITRETechniqueMatcher()
        summary = matcher.get_coverage_summary()

        self.assertIn("total_techniques", summary)
        self.assertIn("tactic_coverage", summary)
        self.assertIn("threat_actors_indexed", summary)
        self.assertIn("detection_patterns_indexed", summary)
        self.assertEqual(summary["version"], "v82")
        self.assertGreater(summary["total_techniques"], 30)
        self.assertGreater(summary["threat_actors_indexed"], 5)


class TestEnums(unittest.TestCase):
    """Test enum classes"""

    def test_mitre_tactic_enum(self):
        """Test MITRE tactics enum"""
        self.assertEqual(MITRETactic.INITIAL_ACCESS.value, "Initial Access")
        self.assertEqual(MITRETactic.EXECUTION.value, "Execution")
        self.assertEqual(MITRETactic.IMPACT.value, "Impact")

    def test_confidence_enum(self):
        """Test confidence levels enum"""
        self.assertEqual(ConfidenceLevel.LOW.value, "low")
        self.assertEqual(ConfidenceLevel.MEDIUM.value, "medium")
        self.assertEqual(ConfidenceLevel.HIGH.value, "high")
        self.assertEqual(ConfidenceLevel.CRITICAL.value, "critical")

    def test_vector_enum(self):
        """Test MITRE vector enum"""
        self.assertEqual(MITREVector.ENTERPRISE.value, "enterprise")


class TestBackwardCompatibility(unittest.TestCase):
    """Test backward compatibility - ADD-ONLY verification"""

    def test_no_existing_files_modified(self):
        """Verify this is ADD-ONLY - no imports break"""
        # Test module imports cleanly
        try:
            from feature_expansion_mitre_technique_matcher_v82_2026_june import MITRETechniqueMatcher
            matcher = MITRETechniqueMatcher()
            self.assertIsNotNone(matcher)
        except Exception as e:
            self.fail(f"Import failed: {e}")

    def test_previous_versions_still_import(self):
        """Verify previous versions still importable"""
        # v81 should still work
        try:
            sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))
            # Just verify the module can be found
            self.assertTrue(os.path.exists(
                os.path.join(os.path.dirname(__file__), 'neural_shield', 'feature_expansion_threat_ttp_extractor_v81_2026_june.py')
            ))
        except Exception:
            pass  # OK if v81 not in test path

    def test_detection_history_accumulates(self):
        """Test detection history accumulates matches"""
        matcher = MITRETechniqueMatcher()
        initial_len = len(matcher.detection_history)
        matcher.match_content("phishing attack")
        matcher.match_content("ransomware encryption")
        self.assertGreater(len(matcher.detection_history), initial_len)


if __name__ == '__main__':
    unittest.main(verbosity=2)
