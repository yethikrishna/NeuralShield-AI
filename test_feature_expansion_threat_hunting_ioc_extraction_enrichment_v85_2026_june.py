"""
Test Suite for NeuralShield AI - Threat Hunting IOC Extraction & Enrichment Engine v85
DIMENSION A - FEATURE EXPANSION - TEST COVERAGE

This test suite validates the new IOC extraction and enrichment functionality.
All tests are ADD-ONLY - no existing tests are modified.
"""

import unittest
import json
from datetime import datetime

# Import the new feature module
from neural_shield.feature_expansion_threat_hunting_ioc_extraction_enrichment_v85_2026_june import (
    IOCTYPE,
    TLP,
    IOC,
    IOCPatternExtractor,
    IOCEnrichmentEngine,
    ThreatHuntingIOCManager,
    GeoIPData,
    ASNData,
)


class TestIOCPatternExtractor(unittest.TestCase):
    """Test IOC pattern extraction from text"""
    
    def setUp(self):
        self.extractor = IOCPatternExtractor()
    
    def test_extract_ipv4(self):
        """Test IPv4 address extraction"""
        text = "Malicious traffic detected from 8.8.8.8 and 1.1.1.1"
        iocs = self.extractor.extract_from_text(text)
        
        ipv4_iocs = [i for i in iocs if i.ioc_type == IOCTYPE.IPV4]
        self.assertEqual(len(ipv4_iocs), 2)
        values = {i.value for i in ipv4_iocs}
        self.assertIn("8.8.8.8", values)
        self.assertIn("1.1.1.1", values)
    
    def test_extract_ipv4_excludes_private(self):
        """Test that private IPs are excluded"""
        text = "Internal IP: 192.168.1.1, Loopback: 127.0.0.1"
        iocs = self.extractor.extract_from_text(text)
        ipv4_iocs = [i for i in iocs if i.ioc_type == IOCTYPE.IPV4]
        self.assertEqual(len(ipv4_iocs), 0)
    
    def test_extract_hashes(self):
        """Test hash extraction"""
        md5 = "d41d8cd98f00b204e9800998ecf8427e"
        sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        
        text = f"File hashes: MD5={md5}, SHA1={sha1}, SHA256={sha256}"
        iocs = self.extractor.extract_from_text(text)
        
        md5_iocs = [i for i in iocs if i.ioc_type == IOCTYPE.MD5]
        sha1_iocs = [i for i in iocs if i.ioc_type == IOCTYPE.SHA1]
        sha256_iocs = [i for i in iocs if i.ioc_type == IOCTYPE.SHA256]
        
        self.assertEqual(len(md5_iocs), 1)
        self.assertEqual(len(sha1_iocs), 1)
        self.assertEqual(len(sha256_iocs), 1)
    
    def test_extract_domains(self):
        """Test domain extraction"""
        text = "Contact admin@evil.com or visit https://malicious.com/payload"
        iocs = self.extractor.extract_from_text(text)
        
        domain_iocs = [i for i in iocs if i.ioc_type == IOCTYPE.DOMAIN]
        email_iocs = [i for i in iocs if i.ioc_type == IOCTYPE.EMAIL]
        
        self.assertGreaterEqual(len(domain_iocs), 1)
        self.assertEqual(len(email_iocs), 1)
        self.assertEqual(email_iocs[0].value, "admin@evil.com")
    
    def test_ioc_normalization(self):
        """Test IOC value normalization"""
        text = "EVIL.COM and D41D8CD98F00B204E9800998ECF8427E"
        iocs = self.extractor.extract_from_text(text)
        
        for ioc in iocs:
            if ioc.ioc_type == IOCTYPE.DOMAIN:
                self.assertEqual(ioc.value, "evil.com")
            if ioc.ioc_type == IOCTYPE.MD5:
                self.assertEqual(ioc.value, "d41d8cd98f00b204e9800998ecf8427e")
    
    def test_confidence_scores(self):
        """Test confidence score calculation"""
        text = "8.8.8.8 d41d8cd98f00b204e9800998ecf8427e test@example.com"
        iocs = self.extractor.extract_from_text(text)
        
        for ioc in iocs:
            self.assertGreater(ioc.confidence, 0)
            self.assertLessEqual(ioc.confidence, 1.0)
            
            if ioc.ioc_type == IOCTYPE.MD5:
                self.assertEqual(ioc.confidence, 0.95)
            if ioc.ioc_type == IOCTYPE.IPV4:
                self.assertEqual(ioc.confidence, 0.85)
            if ioc.ioc_type == IOCTYPE.EMAIL:
                self.assertEqual(ioc.confidence, 0.65)
    
    def test_deduplication(self):
        """Test that duplicate IOCs are deduplicated"""
        text = "8.8.8.8 8.8.8.8 8.8.8.8"
        iocs = self.extractor.extract_from_text(text)
        ipv4_iocs = [i for i in iocs if i.ioc_type == IOCTYPE.IPV4]
        self.assertEqual(len(ipv4_iocs), 1)


class TestIOCEnrichmentEngine(unittest.TestCase):
    """Test IOC enrichment engine"""
    
    def setUp(self):
        self.engine = IOCEnrichmentEngine()
    
    def test_enrich_ipv4(self):
        """Test IPv4 enrichment with GeoIP and ASN"""
        ioc = IOC(value="8.8.8.8", ioc_type=IOCTYPE.IPV4)
        enriched = self.engine.enrich_ioc(ioc)
        
        self.assertIn("geoip", enriched.enrichment)
        self.assertIn("asn", enriched.enrichment)
        self.assertEqual(enriched.enrichment["geoip"]["country_code"], "US")
        self.assertEqual(enriched.enrichment["asn"]["organization"], "Google LLC")
    
    def test_reputation_scoring(self):
        """Test reputation scoring"""
        ioc = IOC(value="d41d8cd98f00b204e9800998ecf8427e", ioc_type=IOCTYPE.MD5)
        enriched = self.engine.enrich_ioc(ioc)
        
        self.assertGreater(enriched.reputation_score, 0)
        self.assertLessEqual(enriched.reputation_score, 100)
        # File hashes should have higher default reputation
        self.assertEqual(enriched.reputation_score, 70.0)
    
    def test_reputation_levels(self):
        """Test reputation level classification"""
        level = self.engine._get_reputation_level(95)
        self.assertEqual(level, "CRITICAL")
        
        level = self.engine._get_reputation_level(70)
        self.assertEqual(level, "HIGH")
        
        level = self.engine._get_reputation_level(50)
        self.assertEqual(level, "MEDIUM")
        
        level = self.engine._get_reputation_level(5)
        self.assertEqual(level, "UNKNOWN")
    
    def test_mitre_technique_mapping(self):
        """Test MITRE ATT&CK technique mapping"""
        ioc = IOC(value="8.8.8.8", ioc_type=IOCTYPE.IPV4)
        enriched = self.engine.enrich_ioc(ioc)
        
        self.assertGreater(len(enriched.mitre_techniques), 0)
        self.assertIn("T1071", enriched.mitre_techniques)
    
    def test_tlp_classification(self):
        """Test TLP classification based on reputation"""
        tlp = self.engine._classify_tlp(95)
        self.assertEqual(tlp, TLP.RED)
        
        tlp = self.engine._classify_tlp(70)
        self.assertEqual(tlp, TLP.AMBER)
        
        tlp = self.engine._classify_tlp(10)
        self.assertEqual(tlp, TLP.WHITE)
    
    def test_extract_and_enrich(self):
        """Test combined extract and enrich workflow"""
        text = "Attack from 8.8.8.8 with hash d41d8cd98f00b204e9800998ecf8427e"
        iocs = self.engine.extract_and_enrich(text)
        
        self.assertGreater(len(iocs), 0)
        for ioc in iocs:
            self.assertIsNotNone(ioc.reputation_score)
            self.assertIn("reputation_level", ioc.enrichment)
    
    def test_batch_enrichment(self):
        """Test batch IOC enrichment"""
        iocs = [
            IOC(value="8.8.8.8", ioc_type=IOCTYPE.IPV4),
            IOC(value="1.1.1.1", ioc_type=IOCTYPE.IPV4),
        ]
        enriched = self.engine.enrich_batch(iocs)
        
        self.assertEqual(len(enriched), 2)
        for ioc in enriched:
            self.assertIn("geoip", ioc.enrichment)


class TestThreatHuntingIOCManager(unittest.TestCase):
    """Test main threat hunting IOC manager"""
    
    def setUp(self):
        self.manager = ThreatHuntingIOCManager()
    
    def test_process_threat_report(self):
        """Test full threat report processing"""
        report = """
        Threat Intelligence Report:
        - Malicious IP: 8.8.8.8
        - C2 Domain: evil.com
        - Malware Hash: d41d8cd98f00b204e9800998ecf8427e
        - Contact: attacker@evil.com
        """
        
        result = self.manager.process_threat_report(report, source="threat_feed")
        
        self.assertGreater(result["iocs_extracted"], 0)
        self.assertIn("summary", result)
        self.assertIn("iocs", result)
        self.assertEqual(result["source"], "threat_feed")
    
    def test_summary_statistics(self):
        """Test summary statistics generation"""
        report = "8.8.8.8 1.1.1.1 d41d8cd98f00b204e9800998ecf8427e"
        result = self.manager.process_threat_report(report)
        
        summary = result["summary"]
        self.assertIn("by_type", summary)
        self.assertIn("by_reputation", summary)
        self.assertIn("total_iocs", summary)
        self.assertIn("high_risk_count", summary)
    
    def test_export_json(self):
        """Test JSON export format"""
        report = "8.8.8.8 d41d8cd98f00b204e9800998ecf8427e"
        self.manager.process_threat_report(report)
        
        json_export = self.manager.export_iocs(format_type="json")
        data = json.loads(json_export)
        
        self.assertIsInstance(data, list)
        self.assertGreater(len(data), 0)
        
        for item in data:
            self.assertIn("value", item)
            self.assertIn("type", item)
            self.assertIn("reputation", item)
            self.assertIn("tlp", item)
    
    def test_export_csv(self):
        """Test CSV export format"""
        report = "8.8.8.8"
        self.manager.process_threat_report(report)
        
        csv_export = self.manager.export_iocs(format_type="csv")
        lines = csv_export.split("\n")
        
        self.assertGreater(len(lines), 1)
        self.assertEqual(lines[0], "value,type,confidence,reputation,tlp,source")
    
    def test_export_stix(self):
        """Test STIX export format"""
        report = "8.8.8.8 d41d8cd98f00b204e9800998ecf8427e"
        self.manager.process_threat_report(report)
        
        stix_export = self.manager.export_iocs(format_type="stix")
        data = json.loads(stix_export)
        
        self.assertEqual(data["type"], "bundle")
        self.assertIn("objects", data)
    
    def test_high_risk_iocs(self):
        """Test high-risk IOC filtering"""
        report = "8.8.8.8 d41d8cd98f00b204e9800998ecf8427e"
        self.manager.process_threat_report(report)
        
        high_risk = self.manager.get_high_risk_iocs(threshold=60)
        self.assertIsInstance(high_risk, list)
    
    def test_ioc_database_persistence(self):
        """Test IOC database persistence across multiple reports"""
        report1 = "8.8.8.8"
        report2 = "1.1.1.1"
        
        self.manager.process_threat_report(report1)
        count1 = len(self.manager.ioc_database)
        
        self.manager.process_threat_report(report2)
        count2 = len(self.manager.ioc_database)
        
        self.assertGreater(count2, count1)
    
    def test_ioc_update_on_repeat(self):
        """Test IOC update when seen in multiple reports"""
        report = "8.8.8.8"
        
        result1 = self.manager.process_threat_report(report)
        first_seen = list(self.manager.ioc_database.values())[0].first_seen
        
        # Process again
        result2 = self.manager.process_threat_report(report)
        last_seen = list(self.manager.ioc_database.values())[0].last_seen
        
        # Should still only have one IOC (deduplicated)
        self.assertEqual(len(self.manager.ioc_database), 1)
        # last_seen should be >= first_seen
        self.assertGreaterEqual(last_seen, first_seen)


class TestDataClasses(unittest.TestCase):
    """Test data class structures"""
    
    def test_ioc_dataclass(self):
        """Test IOC dataclass initialization"""
        ioc = IOC(value="test", ioc_type=IOCTYPE.IPV4, confidence=0.9)
        
        self.assertEqual(ioc.value, "test")
        self.assertEqual(ioc.ioc_type, IOCTYPE.IPV4)
        self.assertEqual(ioc.confidence, 0.9)
        self.assertIsInstance(ioc.first_seen, datetime)
        self.assertIsInstance(ioc.enrichment, dict)
    
    def test_geoip_dataclass(self):
        """Test GeoIP dataclass"""
        geoip = GeoIPData(country_code="US", country_name="United States")
        
        self.assertEqual(geoip.country_code, "US")
        self.assertEqual(geoip.country_name, "United States")
        self.assertEqual(geoip.city, "Unknown")  # default
    
    def test_asn_dataclass(self):
        """Test ASN dataclass"""
        asn = ASNData(asn=15169, asn_org="Google LLC")
        
        self.assertEqual(asn.asn, 15169)
        self.assertEqual(asn.asn_org, "Google LLC")


class TestEnumTypes(unittest.TestCase):
    """Test enumeration types"""
    
    def test_ioc_type_enum(self):
        """Test IOCTYPE enum values"""
        self.assertEqual(IOCTYPE.IPV4.value, "ipv4")
        self.assertEqual(IOCTYPE.MD5.value, "md5")
        self.assertEqual(IOCTYPE.SHA256.value, "sha256")
    
    def test_tlp_enum(self):
        """Test TLP enum values"""
        self.assertEqual(TLP.WHITE.value, "TLP:WHITE")
        self.assertEqual(TLP.RED.value, "TLP:RED")


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and boundary conditions"""
    
    def test_empty_text(self):
        """Test extraction from empty text"""
        engine = IOCEnrichmentEngine()
        iocs = engine.extract_and_enrich("")
        self.assertEqual(len(iocs), 0)
    
    def test_no_iocs_text(self):
        """Test text with no IOC patterns"""
        engine = IOCEnrichmentEngine()
        iocs = engine.extract_and_enrich("This is just normal text with no indicators")
        self.assertEqual(len(iocs), 0)
    
    def test_invalid_ip(self):
        """Test invalid IP handling"""
        extractor = IOCPatternExtractor()
        normalized = extractor._normalize_ioc("999.999.999.999", IOCTYPE.IPV4)
        self.assertIsNone(normalized)
    
    def test_export_min_reputation_filter(self):
        """Test export with minimum reputation filter"""
        manager = ThreatHuntingIOCManager()
        report = "8.8.8.8"
        manager.process_threat_report(report)
        
        # With very high threshold, should get empty
        export_high = manager.export_iocs(min_reputation=100)
        data = json.loads(export_high)
        self.assertEqual(len(data), 0)
    
    def test_invalid_export_format(self):
        """Test invalid export format raises error"""
        manager = ThreatHuntingIOCManager()
        with self.assertRaises(ValueError):
            manager.export_iocs(format_type="invalid_format")


if __name__ == "__main__":
    unittest.main(verbosity=2)
