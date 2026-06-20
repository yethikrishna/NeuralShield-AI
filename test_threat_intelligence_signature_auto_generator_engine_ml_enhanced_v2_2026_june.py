"""
Test Suite for Threat Intelligence Signature Auto-Generator ML Enhanced V2
June 20, 2026 - Production Release
"""

import json
import pytest
from neural_shield.threat_intelligence_signature_auto_generator_engine_ml_enhanced_v2_2026_june import (
    ThreatIntelSignatureGeneratorMLEnhancedV2,
    SignatureType,
    SignatureSeverity,
    SignatureQuality,
    IOCType,
    PatternExtractor,
    SignatureQualityScorer,
    create_signature_generator_v2,
    verify_signature_generator_v2
)


class TestPatternExtractor:
    """Tests for the PatternExtractor class"""
    
    def setup_method(self):
        self.extractor = PatternExtractor()
    
    def test_extract_ipv4_addresses(self):
        text = "Attack from 192.168.1.1 and 10.0.0.255"
        iocs = self.extractor.extract_iocs(text)
        ip_iocs = [i for i in iocs if i.ioc_type == IOCType.IP_ADDRESS]
        assert len(ip_iocs) == 2
        assert ip_iocs[0].value == "192.168.1.1"
        assert ip_iocs[1].value == "10.0.0.255"
    
    def test_extract_md5_hash(self):
        text = "Sample hash: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
        iocs = self.extractor.extract_iocs(text)
        md5_iocs = [i for i in iocs if i.ioc_type == IOCType.MD5]
        assert len(md5_iocs) == 1
        assert md5_iocs[0].value == "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
    
    def test_extract_sha256_hash(self):
        text = "SHA256: abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        iocs = self.extractor.extract_iocs(text)
        sha256_iocs = [i for i in iocs if i.ioc_type == IOCType.SHA256]
        assert len(sha256_iocs) == 1
    
    def test_extract_urls(self):
        text = "Malicious URL: http://evil.com/payload.exe"
        iocs = self.extractor.extract_iocs(text)
        url_iocs = [i for i in iocs if i.ioc_type == IOCType.URL]
        assert len(url_iocs) >= 1
    
    def test_extract_domains(self):
        text = "C2 domain: malicious-c2-server.com"
        iocs = self.extractor.extract_iocs(text)
        domain_iocs = [i for i in iocs if i.ioc_type == IOCType.DOMAIN]
        assert len(domain_iocs) >= 1
    
    def test_extract_malicious_keywords(self):
        text = "This exploit contains malware and uses CVE-2026-1234"
        indicators = self.extractor.extract_patterns(text)
        keyword_indicators = [i for i in indicators if i.indicator_type == "keyword"]
        assert len(keyword_indicators) >= 2  # exploit, malware, cve
    
    def test_extract_hex_patterns(self):
        text = "Shellcode: \\x90\\x90\\xcc"
        indicators = self.extractor.extract_patterns(text)
        hex_indicators = [i for i in indicators if i.pattern == "hex_encoding"]
        assert len(hex_indicators) == 1


class TestSignatureQualityScorer:
    """Tests for the SignatureQualityScorer class"""
    
    def setup_method(self):
        self.scorer = SignatureQualityScorer()
    
    def test_quality_score_calculation(self):
        from neural_shield.threat_intelligence_signature_auto_generator_engine_ml_enhanced_v2_2026_june import (
            GeneratedSignature, ThreatIndicator
        )
        from datetime import datetime, timezone
        
        signature = GeneratedSignature(
            signature_id="test-001",
            signature_type=SignatureType.YARA,
            name="Test Signature",
            description="A test signature with good metadata",
            content="rule test { strings: $a = \"test\" condition: $a }",
            severity=SignatureSeverity.HIGH,
            quality=SignatureQuality.EXPERIMENTAL,
            quality_score=0.0,
            indicators=[
                ThreatIndicator("exploit", "keyword", 0.9, 2),
                ThreatIndicator("malware", "keyword", 0.8, 1)
            ],
            false_positive_risk=0.1,
            tags=["malware", "exploit", "cve"],
            created_at=datetime.now(timezone.utc),
            version="1.0",
            references=["https://test.com"],
            platform_compatibility=["windows", "linux"]
        )
        
        score, quality = self.scorer.calculate_quality_score(signature)
        assert 0 <= score <= 1.0
        assert quality in [SignatureQuality.EXCELLENT, SignatureQuality.GOOD, 
                          SignatureQuality.FAIR, SignatureQuality.POOR, SignatureQuality.EXPERIMENTAL]


class TestThreatIntelSignatureGeneratorMLEnhancedV2:
    """Tests for the main signature generator class"""
    
    def setup_method(self):
        self.generator = ThreatIntelSignatureGeneratorMLEnhancedV2(max_workers=2)
    
    def test_single_signature_generation(self):
        threat_text = """
        New malware campaign detected. CVE-2026-9999 exploit in the wild.
        MD5: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6
        C2: 192.168.1.100, malicious-domain.com
        """
        
        signatures = self.generator.generate_signature(
            threat_text=threat_text,
            threat_name="Test_Malware_June2026",
            tags=["malware", "cve", "c2"],
            references=["https://security-advisory.com"]
        )
        
        assert len(signatures) > 0
        for sig in signatures:
            assert sig.signature_id is not None
            assert sig.name == "Test_Malware_June2026"
            assert sig.severity in [SignatureSeverity.CRITICAL, SignatureSeverity.HIGH,
                                   SignatureSeverity.MEDIUM]
            assert 0 <= sig.quality_score <= 1.0
            assert 0 <= sig.false_positive_risk <= 1.0
    
    def test_yara_signature_content(self):
        threat_text = "Malware with MD5: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6 IP: 10.0.0.1"
        
        signatures = self.generator.generate_signature(
            threat_text=threat_text,
            threat_name="YARA_Test",
            signature_types=[SignatureType.YARA]
        )
        
        assert len(signatures) == 1
        yara_sig = signatures[0]
        assert yara_sig.signature_type == SignatureType.YARA
        assert "rule " in yara_sig.content
        assert "strings:" in yara_sig.content
        assert "condition:" in yara_sig.content
    
    def test_ioc_signature_content(self):
        threat_text = "IP: 192.168.1.1 Domain: evil.com MD5: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
        
        signatures = self.generator.generate_signature(
            threat_text=threat_text,
            threat_name="IOC_Test",
            signature_types=[SignatureType.IOC]
        )
        
        assert len(signatures) == 1
        ioc_sig = signatures[0]
        assert ioc_sig.signature_type == SignatureType.IOC
        assert len(ioc_sig.content) > 0
    
    def test_batch_generation_sequential(self):
        threats = [
            {"text": "Phishing domain: phish1.com", "name": "Phish_1", "tags": ["phishing"]},
            {"text": "Ransomware IP: 10.0.0.1", "name": "Ransom_1", "tags": ["ransomware"]},
            {"text": "Exploit CVE-2026-0001 in the wild", "name": "Exploit_1", "tags": ["exploit"]}
        ]
        
        result = self.generator.generate_batch(threats, parallel=False)
        
        assert result.success is True
        assert result.total_generated > 0
        assert len(result.errors) == 0
        assert result.processing_time_ms > 0
        assert 0 <= result.average_quality_score <= 1.0
    
    def test_batch_generation_parallel(self):
        threats = [
            {"text": f"Threat {i}: domain{i}.com", "name": f"Threat_{i}"}
            for i in range(5)
        ]
        
        result = self.generator.generate_batch(threats, parallel=True)
        
        assert result.success is True
        assert result.total_generated > 0
        assert len(result.errors) == 0
    
    def test_export_json_format(self):
        signatures = self.generator.generate_signature(
            threat_text="Test threat with IP: 192.168.1.1",
            threat_name="Export_Test"
        )
        
        json_export = self.generator.export_signatures(signatures, "json")
        parsed = json.loads(json_export)
        
        assert isinstance(parsed, list)
        assert len(parsed) == len(signatures)
        assert "signature_id" in parsed[0]
        assert "type" in parsed[0]
        assert "quality_score" in parsed[0]
    
    def test_export_stix_format(self):
        signatures = self.generator.generate_signature(
            threat_text="Test threat",
            threat_name="STIX_Test"
        )
        
        stix_export = self.generator.export_signatures(signatures, "stix")
        parsed = json.loads(stix_export)
        
        assert "type" in parsed
        assert parsed["type"] == "bundle"
        assert "objects" in parsed
    
    def test_generation_stats(self):
        # Generate some signatures first
        for i in range(3):
            self.generator.generate_signature(
                threat_text=f"Test threat {i}",
                threat_name=f"Test_{i}"
            )
        
        stats = self.generator.get_generation_stats()
        
        assert stats["total_generated"] >= 3
        assert "by_type" in stats
        assert "by_quality" in stats
        assert "by_severity" in stats
        assert "average_quality" in stats
        assert "average_fp_risk" in stats
    
    def test_severity_determination(self):
        # High severity threat
        high_threat = "CVE-2026-1234 exploit with remote code execution"
        high_sigs = self.generator.generate_signature(high_threat, "High_Threat")
        assert high_sigs[0].severity in [SignatureSeverity.CRITICAL, SignatureSeverity.HIGH]
        
        # Low severity threat
        low_threat = "Suspicious domain: test.com"
        low_sigs = self.generator.generate_signature(low_threat, "Low_Threat")
        assert low_sigs[0].severity in [SignatureSeverity.LOW, SignatureSeverity.INFORMATIONAL, SignatureSeverity.MEDIUM]
    
    def test_false_positive_risk_assessment(self):
        # Low FP risk - many specific indicators
        low_fp_text = """
        CVE-2026-1234 exploit with MD5: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6
        IP: 192.168.1.100, Domain: specific-malware-c2.com
        Contains shellcode and privilege escalation
        """
        low_sigs = self.generator.generate_signature(low_fp_text, "Low_FP")
        assert low_sigs[0].false_positive_risk < 0.5
        
        # High FP risk - generic keywords only
        high_fp_text = "malware exploit vulnerability"
        high_sigs = self.generator.generate_signature(high_fp_text, "High_FP")
        # Generic keywords should have higher FP risk
        assert high_sigs[0].false_positive_risk >= 0.2


class TestFactoryAndVerification:
    """Tests for factory and verification functions"""
    
    def test_create_signature_generator_v2(self):
        generator = create_signature_generator_v2(max_workers=4)
        assert isinstance(generator, ThreatIntelSignatureGeneratorMLEnhancedV2)
        assert generator.max_workers == 4
    
    def test_verify_signature_generator_v2(self):
        result = verify_signature_generator_v2()
        
        assert result["success"] is True
        assert result["signatures_generated"] > 0
        assert result["batch_success"] is True
        assert result["batch_total"] > 0
        assert result["export_works"] is True
        assert result["stats_available"] is True
        assert isinstance(result["average_quality"], float)
        assert result["processing_time_ms"] > 0
        assert len(result["errors"]) == 0


def test_integration_full_workflow():
    """Full integration test of the complete workflow"""
    generator = create_signature_generator_v2()
    
    # Step 1: Generate signatures for multiple threat types
    all_signatures = []
    
    # Malware threat
    malware_sigs = generator.generate_signature(
        threat_text="""
        New ransomware variant detected. Encrypts user files.
        C2 servers: ransomware-c2.com, 172.16.0.50
        SHA256: abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890
        Uses privilege escalation and lateral movement.
        """,
        threat_name="Ransomware_June_2026_Variant",
        signature_types=[SignatureType.YARA, SignatureType.IOC, SignatureType.SNORT],
        tags=["ransomware", "encryption", "c2", "lateral-movement"],
        references=["https://cert.gov/advisory/2026-06"]
    )
    all_signatures.extend(malware_sigs)
    
    # Phishing threat
    phish_sigs = generator.generate_signature(
        threat_text="Phishing campaign targeting corporate emails. Domain: fake-bank-login.com",
        threat_name="Corporate_Phishing_June2026",
        signature_types=[SignatureType.IOC, SignatureType.REGEX],
        tags=["phishing", "email", "credential-theft"]
    )
    all_signatures.extend(phish_sigs)
    
    # Step 2: Verify all signatures have required fields
    for sig in all_signatures:
        assert sig.signature_id is not None
        assert sig.name is not None
        assert sig.content is not None
        assert sig.severity is not None
        assert sig.quality is not None
        assert 0 <= sig.quality_score <= 1
        assert 0 <= sig.false_positive_risk <= 1
    
    # Step 3: Export and verify
    json_export = generator.export_signatures(all_signatures, "json")
    assert len(json_export) > 0
    
    # Step 4: Get statistics
    stats = generator.get_generation_stats()
    assert stats["total_generated"] >= len(all_signatures)
    
    # Save test results
    test_results = {
        "test_timestamp": "2026-06-20T00:00:00Z",
        "total_signatures_generated": len(all_signatures),
        "by_type": stats.get("by_type", {}),
        "by_quality": stats.get("by_quality", {}),
        "average_quality_score": stats.get("average_quality", 0),
        "export_json_works": True,
        "all_tests_passed": True
    }
    
    with open("test_results_threat_intelligence_signature_auto_generator_engine_ml_enhanced_v2.json", "w") as f:
        json.dump(test_results, f, indent=2)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
