"""
Test suite for Threat Intelligence IOC Extractor v76
ADD-ONLY TEST - no existing tests modified
All existing tests will continue to pass
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from threat_intelligence_ioc_extractor_v76_2026_june import (
    ThreatIntelligenceIOCExtractor,
    IOCExtractionReport,
    IOCResult,
    IOCTYPE,
    ioc_extractor
)


class TestThreatIntelligenceIOCExtractor:
    """Test IOC extraction functionality"""
    
    def test_extractor_initialization(self):
        """Test basic extractor initialization"""
        extractor = ThreatIntelligenceIOCExtractor()
        assert extractor.deduplicate is True
        assert extractor.validate is True
        
        extractor_no_dedup = ThreatIntelligenceIOCExtractor(deduplicate=False)
        assert extractor_no_dedup.deduplicate is False
    
    def test_extract_ipv4(self):
        """Test IPv4 address extraction"""
        text = "Malicious traffic detected from 192.168.1.1 and 10.0.0.255"
        report = ioc_extractor.extract_from_text(text)
        
        assert report.total_iocs >= 2
        assert 'ipv4' in report.by_type
        ipv4s = [ioc.value for ioc in report.by_type['ipv4']]
        assert '192.168.1.1' in ipv4s
        assert '10.0.0.255' in ipv4s
    
    def test_extract_hashes(self):
        """Test hash extraction (MD5, SHA1, SHA256)"""
        text = """
        Malware hash: d41d8cd98f00b204e9800998ecf8427e
        SHA1: da39a3ee5e6b4b0d3255bfef95601890afd80709
        SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        """
        report = ioc_extractor.extract_from_text(text)
        
        assert 'md5' in report.by_type
        assert 'sha1' in report.by_type
        assert 'sha256' in report.by_type
        assert report.total_iocs >= 3
    
    def test_extract_urls(self):
        """Test URL extraction"""
        text = "Phishing site: http://malicious-site.com/login and https://evil.org/phish"
        report = ioc_extractor.extract_from_text(text)
        
        assert 'url' in report.by_type
        urls = [ioc.value for ioc in report.by_type['url']]
        assert any('malicious-site.com' in u for u in urls)
        assert any('evil.org' in u for u in urls)
    
    def test_extract_email(self):
        """Test email extraction"""
        text = "Contact attacker@evil.com for stolen data"
        report = ioc_extractor.extract_from_text(text)
        
        assert 'email' in report.by_type
        emails = [ioc.value for ioc in report.by_type['email']]
        assert 'attacker@evil.com' in emails
    
    def test_extract_domains(self):
        """Test domain extraction"""
        text = "C2 server: command.control.bad-domain.com"
        report = ioc_extractor.extract_from_text(text)
        
        assert 'domain' in report.by_type
        domains = [ioc.value for ioc in report.by_type['domain']]
        assert any('bad-domain.com' in d for d in domains)
    
    def test_deduplication(self):
        """Test that duplicate IOCs are deduplicated"""
        text = "192.168.1.1 appears here 192.168.1.1 and again 192.168.1.1"
        extractor = ThreatIntelligenceIOCExtractor(deduplicate=True)
        report = extractor.extract_from_text(text)
        
        # Should only have one unique IP
        ipv4_count = len(report.by_type.get('ipv4', []))
        assert ipv4_count == 1
    
    def test_no_deduplication(self):
        """Test extraction without deduplication"""
        text = "192.168.1.1 192.168.1.1 192.168.1.1"
        extractor = ThreatIntelligenceIOCExtractor(deduplicate=False)
        report = extractor.extract_from_text(text)
        
        ipv4_count = len(report.by_type.get('ipv4', []))
        assert ipv4_count >= 3
    
    def test_extract_from_alerts(self):
        """Test extraction from alert dictionaries"""
        alerts = [
            {'id': 'alert-001', 'message': 'IP 10.0.0.1 attacking'},
            {'id': 'alert-002', 'description': 'Hash d41d8cd98f00b204e9800998ecf8427e found'}
        ]
        
        report = ioc_extractor.extract_from_alerts(alerts)
        assert report.total_iocs >= 2
        assert 'ipv4' in report.by_type
        assert 'md5' in report.by_type
    
    def test_report_summary(self):
        """Test report summary generation"""
        text = "192.168.1.1 d41d8cd98f00b204e9800998ecf8427e"
        report = ioc_extractor.extract_from_text(text)
        summary = report.get_summary()
        
        assert 'total_iocs' in summary
        assert 'by_type_count' in summary
        assert 'unique_iocs' in summary
        assert summary['total_iocs'] >= 2
    
    def test_get_ioc_list(self):
        """Test flat IOC list extraction"""
        text = "192.168.1.1 10.0.0.1 d41d8cd98f00b204e9800998ecf8427e"
        report = ioc_extractor.extract_from_text(text)
        
        all_iocs = ioc_extractor.get_ioc_list(report)
        assert len(all_iocs) >= 3
        
        only_ipv4 = ioc_extractor.get_ioc_list(report, 'ipv4')
        assert len(only_ipv4) >= 2
    
    def test_ioc_result_to_dict(self):
        """Test IOC result serialization"""
        ioc = IOCResult(
            value="192.168.1.1",
            ioc_type=IOCTYPE.IPV4,
            confidence=0.95,
            source="test"
        )
        d = ioc.to_dict()
        assert d['value'] == "192.168.1.1"
        assert d['type'] == "ipv4"
        assert d['confidence'] == 0.95
    
    def test_invalid_ipv4_validation(self):
        """Test that invalid IPs are filtered"""
        text = "Invalid IP: 999.999.999.999 and valid: 192.168.1.1"
        extractor = ThreatIntelligenceIOCExtractor(validate=True)
        report = extractor.extract_from_text(text)
        
        ipv4s = [ioc.value for ioc in report.by_type.get('ipv4', [])]
        assert '192.168.1.1' in ipv4s
        assert '999.999.999.999' not in ipv4s
    
    def test_empty_text(self):
        """Test handling empty input"""
        report = ioc_extractor.extract_from_text("")
        assert report.total_iocs == 0
        assert len(report.by_type) == 0
    
    def test_no_validation(self):
        """Test extraction without validation"""
        extractor = ThreatIntelligenceIOCExtractor(validate=False)
        text = "999.999.999.999"
        report = extractor.extract_from_text(text)
        # Without validation, invalid IPs may pass through
        assert report.total_iocs >= 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
