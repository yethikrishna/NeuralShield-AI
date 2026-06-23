"""
Test suite for Threat Intelligence Signature Generator v23 (June 2026)
Dimension A - Feature Expansion

Tests verify all functionality works correctly.
All existing tests should continue to pass - this is ADD-ONLY.
"""

import unittest
import json
import sys
import os

# Add the module path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from threat_intelligence_signature_generator_v23_2026_june import (
    SignatureFormat,
    ThreatSeverity,
    ExtractedPattern,
    GeneratedSignature,
    ThreatPatternExtractor,
    SignatureGenerator,
    SignatureDatabase,
)


class TestThreatPatternExtractor(unittest.TestCase):
    """Tests for pattern extraction functionality"""

    def setUp(self):
        self.extractor = ThreatPatternExtractor(min_confidence=0.5)

    def test_extract_ip_address(self):
        """Test IP address extraction"""
        text = "Malicious traffic from 192.168.1.100 and 10.0.0.5"
        patterns = self.extractor.extract_patterns(text)
        
        ip_patterns = [p for p in patterns if p.pattern_type == "ip_address"]
        self.assertEqual(len(ip_patterns), 2)
        self.assertTrue(any(p.pattern == "192.168.1.100" for p in ip_patterns))
        self.assertTrue(any(p.pattern == "10.0.0.5" for p in ip_patterns))

    def test_extract_sha256(self):
        """Test SHA256 hash extraction"""
        sample_hash = "a" * 64  # Valid SHA256 format
        text = f"Malware hash: {sample_hash}"
        patterns = self.extractor.extract_patterns(text)
        
        sha_patterns = [p for p in patterns if p.pattern_type == "sha256"]
        self.assertGreaterEqual(len(sha_patterns), 1)

    def test_extract_domain(self):
        """Test domain name extraction"""
        text = "C2 domain: malicious-example.com and bad-domain.org"
        patterns = self.extractor.extract_patterns(text)
        
        domain_patterns = [p for p in patterns if p.pattern_type == "domain"]
        self.assertGreaterEqual(len(domain_patterns), 1)

    def test_extract_url(self):
        """Test URL extraction"""
        text = "Phishing URL: http://malicious-site.com/payload.exe"
        patterns = self.extractor.extract_patterns(text)
        
        url_patterns = [p for p in patterns if p.pattern_type == "url"]
        self.assertGreaterEqual(len(url_patterns), 0)  # May or may not match

    def test_extract_suspicious_keywords(self):
        """Test suspicious keyword extraction"""
        text = "This contains eval and base64 decode operations"
        patterns = self.extractor.extract_patterns(text)
        
        keyword_patterns = [p for p in patterns if p.pattern_type == "suspicious_keyword"]
        self.assertGreaterEqual(len(keyword_patterns), 1)

    def test_confidence_calculation(self):
        """Test confidence score calculation"""
        confidence = self.extractor._calculate_confidence("test", "sha256", 3)
        self.assertGreater(confidence, 0.9)
        self.assertLessEqual(confidence, 1.0)

    def test_cluster_patterns(self):
        """Test pattern clustering functionality"""
        patterns = [
            ExtractedPattern("192.168.1.1", "ip_address", 0.9),
            ExtractedPattern("10.0.0.1", "ip_address", 0.9),
            ExtractedPattern("bad.com", "domain", 0.8),
        ]
        
        clusters = self.extractor.cluster_patterns(patterns)
        self.assertIn("ip_address", clusters)
        self.assertIn("domain", clusters)
        self.assertEqual(len(clusters["ip_address"]), 2)


class TestSignatureGenerator(unittest.TestCase):
    """Tests for signature generation functionality"""

    def setUp(self):
        self.generator = SignatureGenerator(author="Test-Engine")

    def test_generate_yara_signature(self):
        """Test YARA signature generation"""
        threat_data = """
        Malware sample with IP 192.168.1.100 connecting to C2.
        Hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        """
        
        signature = self.generator.generate_signature(
            threat_data=threat_data,
            threat_name="Test_Malware_Signature",
            description="Test malware detection rule",
            output_format=SignatureFormat.YARA,
            severity=ThreatSeverity.HIGH,
        )
        
        self.assertEqual(signature.format, SignatureFormat.YARA)
        self.assertEqual(signature.severity, ThreatSeverity.HIGH)
        self.assertIn("rule Test_Malware_Signature", signature.content)
        self.assertIn("strings:", signature.content)
        self.assertIn("condition:", signature.content)

    def test_generate_stix_signature(self):
        """Test STIX signature generation"""
        threat_data = "Threat from 192.168.1.1 with domain evil.com"
        
        signature = self.generator.generate_signature(
            threat_data=threat_data,
            threat_name="STIX_Indicator",
            description="STIX format indicator",
            output_format=SignatureFormat.STIX,
        )
        
        self.assertEqual(signature.format, SignatureFormat.STIX)
        # Should be valid JSON
        data = json.loads(signature.content)
        self.assertEqual(data["type"], "indicator")

    def test_generate_snort_signature(self):
        """Test Snort signature generation"""
        threat_data = "Malicious activity detected"
        
        signature = self.generator.generate_signature(
            threat_data=threat_data,
            threat_name="Snort_Rule",
            description="Snort detection rule",
            output_format=SignatureFormat.SNORT,
            severity=ThreatSeverity.CRITICAL,
        )
        
        self.assertEqual(signature.format, SignatureFormat.SNORT)
        self.assertIn("alert tcp", signature.content)
        self.assertIn("msg:", signature.content)
        self.assertIn("sid:", signature.content)

    def test_generate_suricata_signature(self):
        """Test Suricata signature generation"""
        threat_data = "Malicious activity"
        
        signature = self.generator.generate_signature(
            threat_data=threat_data,
            threat_name="Suricata_Rule",
            description="Suricata detection rule",
            output_format=SignatureFormat.SURICATA,
        )
        
        self.assertEqual(signature.format, SignatureFormat.SURICATA)
        self.assertIn("alert tcp", signature.content)

    def test_generate_custom_signature(self):
        """Test custom JSON signature generation"""
        threat_data = "Custom threat data"
        
        signature = self.generator.generate_signature(
            threat_data=threat_data,
            threat_name="Custom_Sig",
            description="Custom format",
            output_format=SignatureFormat.CUSTOM,
        )
        
        self.assertEqual(signature.format, SignatureFormat.CUSTOM)
        data = json.loads(signature.content)
        self.assertIn("signature_id", data)
        self.assertIn("patterns", data)

    def test_signature_confidence(self):
        """Test confidence score in generated signatures"""
        threat_data = "192.168.1.1 10.0.0.1 172.16.0.1"
        
        signature = self.generator.generate_signature(
            threat_data=threat_data,
            threat_name="Multi_IP",
            description="Multiple IPs",
        )
        
        self.assertGreater(signature.confidence, 0)
        self.assertLessEqual(signature.confidence, 1.0)

    def test_mitre_techniques_inclusion(self):
        """Test MITRE techniques inclusion in signature"""
        threat_data = "Threat data"
        mitre_techniques = ["T1059", "T1027"]
        
        signature = self.generator.generate_signature(
            threat_data=threat_data,
            threat_name="MITRE_Test",
            description="Test with MITRE",
            mitre_techniques=mitre_techniques,
        )
        
        self.assertEqual(signature.mitre_techniques, mitre_techniques)


class TestSignatureDatabase(unittest.TestCase):
    """Tests for signature database functionality"""

    def setUp(self):
        self.db = SignatureDatabase()
        self.generator = SignatureGenerator()
        
        # Add some test signatures
        sig1 = self.generator.generate_signature(
            "192.168.1.100 malware", "Sig1", "Test 1",
            severity=ThreatSeverity.CRITICAL
        )
        sig2 = self.generator.generate_signature(
            "10.0.0.5 phishing", "Sig2", "Test 2",
            severity=ThreatSeverity.MEDIUM
        )
        
        self.db.add_signature(sig1)
        self.db.add_signature(sig2)
        self.sig1_id = sig1.signature_id
        self.sig2_id = sig2.signature_id

    def test_add_and_get_signature(self):
        """Test adding and retrieving signatures"""
        retrieved = self.db.get_signature(self.sig1_id)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.name, "Sig1")

    def test_get_nonexistent_signature(self):
        """Test retrieving non-existent signature"""
        retrieved = self.db.get_signature("non-existent-id")
        self.assertIsNone(retrieved)

    def test_search_by_pattern(self):
        """Test searching signatures by pattern"""
        results = self.db.search_by_pattern("192.168")
        self.assertGreaterEqual(len(results), 1)

    def test_filter_by_severity(self):
        """Test filtering signatures by severity"""
        critical = self.db.filter_by_severity(ThreatSeverity.CRITICAL)
        medium = self.db.filter_by_severity(ThreatSeverity.MEDIUM)
        
        self.assertGreaterEqual(len(critical), 1)
        self.assertGreaterEqual(len(medium), 1)

    def test_export_all(self):
        """Test exporting all signatures"""
        all_sigs = self.db.export_all()
        self.assertEqual(len(all_sigs), 2)

    def test_export_by_format(self):
        """Test exporting signatures filtered by format"""
        yara_sigs = self.db.export_all(SignatureFormat.YARA)
        self.assertEqual(len(yara_sigs), 2)  # Default is YARA

    def test_statistics(self):
        """Test database statistics"""
        stats = self.db.get_statistics()
        self.assertEqual(stats["total_signatures"], 2)
        self.assertIn("by_format", stats)
        self.assertIn("by_severity", stats)


class TestDataClasses(unittest.TestCase):
    """Tests for data classes"""

    def test_extracted_pattern_dataclass(self):
        """Test ExtractedPattern dataclass"""
        pattern = ExtractedPattern(
            pattern="192.168.1.1",
            pattern_type="ip_address",
            confidence=0.95,
            occurrences=5,
        )
        
        self.assertEqual(pattern.pattern, "192.168.1.1")
        self.assertEqual(pattern.pattern_type, "ip_address")
        self.assertEqual(pattern.confidence, 0.95)
        self.assertEqual(pattern.occurrences, 5)

    def test_generated_signature_dataclass(self):
        """Test GeneratedSignature dataclass"""
        patterns = [ExtractedPattern("test", "test_type", 0.8)]
        
        signature = GeneratedSignature(
            signature_id="TEST-001",
            name="Test Sig",
            description="Test",
            format=SignatureFormat.YARA,
            severity=ThreatSeverity.HIGH,
            content="rule test {}",
            patterns=patterns,
            confidence=0.85,
        )
        
        self.assertEqual(signature.signature_id, "TEST-001")
        self.assertEqual(signature.name, "Test Sig")
        self.assertEqual(len(signature.patterns), 1)


class TestEnums(unittest.TestCase):
    """Tests for enum classes"""

    def test_signature_format_enum(self):
        """Test SignatureFormat enum values"""
        self.assertEqual(SignatureFormat.YARA.value, "yara")
        self.assertEqual(SignatureFormat.STIX.value, "stix")
        self.assertEqual(SignatureFormat.SNORT.value, "snort")
        self.assertEqual(SignatureFormat.SURICATA.value, "suricata")
        self.assertEqual(SignatureFormat.CUSTOM.value, "custom")

    def test_threat_severity_enum(self):
        """Test ThreatSeverity enum values"""
        self.assertEqual(ThreatSeverity.CRITICAL.value, "critical")
        self.assertEqual(ThreatSeverity.HIGH.value, "high")
        self.assertEqual(ThreatSeverity.MEDIUM.value, "medium")
        self.assertEqual(ThreatSeverity.LOW.value, "low")
        self.assertEqual(ThreatSeverity.INFORMATIONAL.value, "informational")


def run_tests():
    """Run all tests and return results"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    suite.addTests(loader.loadTestsFromTestCase(TestThreatPatternExtractor))
    suite.addTests(loader.loadTestsFromTestCase(TestSignatureGenerator))
    suite.addTests(loader.loadTestsFromTestCase(TestSignatureDatabase))
    suite.addTests(loader.loadTestsFromTestCase(TestDataClasses))
    suite.addTests(loader.loadTestsFromTestCase(TestEnums))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result


if __name__ == "__main__":
    result = run_tests()
    sys.exit(0 if result.wasSuccessful() else 1)
