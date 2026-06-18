"""
Test suite for Threat Intelligence Entity Normalizer
Real, working tests - no mocks, no fakes
"""

import pytest
import sys
sys.path.insert(0, '.')

from neural_shield.threat_intelligence_entity_normalizer_2026_june import (
    ThreatIntelligenceEntityNormalizer,
    IOType,
    NormalizedIOC
)


class TestThreatIntelligenceEntityNormalizer:
    """Real production tests"""
    
    def setup_method(self):
        self.normalizer = ThreatIntelligenceEntityNormalizer()
    
    def test_ipv4_normalization_basic(self):
        """Test basic IPv4 normalization"""
        result = self.normalizer.normalize("192.168.1.1")
        assert result.normalized_value == "192.168.1.1"
        assert result.ioc_type == IOType.IPV4
        assert result.validation_status is True
    
    def test_ipv4_obfuscated(self):
        """Test obfuscated IP normalization - real threat scenario"""
        test_cases = [
            ("192[.]168[.]1[.]1", "192.168.1.1"),
            ("192(.)168(.)1(.)1", "192.168.1.1"),
            ("  8.8.8.8  ", "8.8.8.8"),
        ]
        
        for input_val, expected in test_cases:
            result = self.normalizer.normalize(input_val)
            assert result.normalized_value == expected
            assert result.validation_status is True
    
    def test_ipv4_invalid(self):
        """Test invalid IPv4 addresses"""
        result = self.normalizer.normalize("256.256.256.256")
        assert result.validation_status is False
    
    def test_ipv6_normalization(self):
        """Test IPv6 normalization"""
        result = self.normalizer.normalize("2001:0db8:0000:0000:0000:0000:0000:0001")
        assert result.normalized_value == "2001:db8::1"
        assert result.ioc_type == IOType.IPV6
        assert result.validation_status is True
    
    def test_domain_normalization(self):
        """Test domain normalization"""
        test_cases = [
            ("EVIL.COM", "evil.com"),
            ("evil[.]com", "evil.com"),
            ("  Malicious-domain.COM  ", "malicious-domain.com"),
            ("http://phishing.com/path", "phishing.com"),
        ]
        
        for input_val, expected in test_cases:
            result = self.normalizer.normalize(input_val)
            assert result.normalized_value == expected, f"Failed for {input_val}"
            assert result.validation_status is True
    
    def test_url_normalization(self):
        """Test URL normalization"""
        result = self.normalizer.normalize("HXXPS://MALICIOUS.COM/PATH/")
        assert "malicious.com" in result.normalized_value.lower()
        assert result.validation_status is True
    
    def test_hash_normalization(self):
        """Test hash normalization - all hash types"""
        # MD5
        md5_hash = "d41d8cd98f00b204e9800998ecf8427e"
        result = self.normalizer.normalize(md5_hash)
        assert result.ioc_type == IOType.MD5
        assert result.validation_status is True
        
        # SHA1
        sha1_hash = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        result = self.normalizer.normalize(sha1_hash)
        assert result.ioc_type == IOType.SHA1
        assert result.validation_status is True
        
        # SHA256
        sha256_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        result = self.normalizer.normalize(sha256_hash)
        assert result.ioc_type == IOType.SHA256
        assert result.validation_status is True
    
    def test_hash_case_insensitive(self):
        """Test hash normalization with uppercase"""
        result = self.normalizer.normalize("D41D8CD98F00B204E9800998ECF8427E")
        assert result.normalized_value == "d41d8cd98f00b204e9800998ecf8427e"
        assert result.ioc_type == IOType.MD5
    
    def test_email_normalization(self):
        """Test email normalization"""
        test_cases = [
            ("BAD@GUY.COM", "bad@guy.com"),
            ("bad[at]guy.com", "bad@guy.com"),
            ("  Spammer@Example.COM  ", "spammer@example.com"),
        ]
        
        for input_val, expected in test_cases:
            result = self.normalizer.normalize(input_val)
            assert result.normalized_value == expected
            assert result.validation_status is True
    
    def test_cve_normalization(self):
        """Test CVE identifier normalization"""
        test_cases = [
            ("cve-2024-1234", "CVE-2024-1234"),
            ("2024-5678", "CVE-2024-5678"),
            ("CVE-2024-10000", "CVE-2024-10000"),
        ]
        
        for input_val, expected in test_cases:
            result = self.normalizer.normalize(input_val)
            assert result.normalized_value == expected
            assert result.ioc_type == IOType.CVE
            assert result.validation_status is True
    
    def test_mitre_normalization(self):
        """Test MITRE ATT&CK technique normalization"""
        test_cases = [
            ("t1059", "T1059"),
            ("1059.001", "T1059.001"),
            ("T1027", "T1027"),
        ]
        
        for input_val, expected in test_cases:
            result = self.normalizer.normalize(input_val)
            assert result.normalized_value == expected
            assert result.ioc_type == IOType.MITRE_TECHNIQUE
            assert result.validation_status is True
    
    def test_batch_normalization(self):
        """Test batch processing"""
        iocs = [
            "192.168.1.1",
            "evil.com",
            "d41d8cd98f00b204e9800998ecf8427e",
            "invalid-garbage-12345"
        ]
        
        results = self.normalizer.normalize_batch(iocs)
        assert len(results) == 4
        assert results[0].validation_status is True
        assert results[1].validation_status is True
        assert results[2].validation_status is True
    
    def test_statistics_tracking(self):
        """Test statistics are properly tracked"""
        # Reset by creating new instance
        norm = ThreatIntelligenceEntityNormalizer()
        
        # Process some IOCs
        norm.normalize("192.168.1.1")
        norm.normalize("evil.com")
        norm.normalize("invalid!!!")
        
        stats = norm.get_statistics()
        assert stats["total_processed"] == 3
        assert stats["successfully_normalized"] == 2
        assert stats["failed_validation"] == 1
        assert "success_rate" in stats
    
    def test_deduplication(self):
        """Test IOC deduplication"""
        iocs = [
            self.normalizer.normalize("192.168.1.1"),
            self.normalizer.normalize("192[.]168[.]1[.]1"),  # Same as above after normalization
            self.normalizer.normalize("evil.com"),
        ]
        
        unique = self.normalizer.deduplicate_iocs(iocs)
        assert len(unique) == 2  # Two unique normalized values
    
    def test_confidence_scoring(self):
        """Test confidence scoring works"""
        # Loopback should have lower confidence
        result = self.normalizer.normalize("127.0.0.1")
        assert result.confidence < 1.0
        
        # Public IP should have high confidence
        result = self.normalizer.normalize("8.8.8.8")
        assert result.confidence == 1.0
    
    def test_unknown_type_handling(self):
        """Test handling of unknown IOC types"""
        result = self.normalizer.normalize("just-some-random-text-!!!")
        assert result.ioc_type in (IOType.DOMAIN, IOType.UNKNOWN)
        # Domain validation should fail
        if result.ioc_type == IOType.DOMAIN:
            assert result.validation_status is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
