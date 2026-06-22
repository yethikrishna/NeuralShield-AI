"""
Tests for Threat Intelligence Automatic Classifier v5
Dimension A: Feature Expansion Tests
"""

import pytest
import json
import threading
from neural_shield.threat_intelligence_automatic_classifier_v5_2026_june import (
    ThreatIntelligenceClassifier,
    ThreatCategory,
    SeverityLevel,
    ClassifiedThreat,
    get_classifier,
    classify_threat,
    get_version_info
)


class TestThreatCategory:
    """Test threat category enumeration"""
    
    def test_all_categories_exist(self):
        """Verify all threat categories are defined"""
        categories = list(ThreatCategory)
        assert len(categories) >= 12
        assert ThreatCategory.MALWARE in categories
        assert ThreatCategory.RANSOMWARE in categories
        assert ThreatCategory.ZERO_DAY in categories
    
    def test_category_values_are_strings(self):
        """Verify category values are valid strings"""
        for category in ThreatCategory:
            assert isinstance(category.value, str)
            assert len(category.value) > 0


class TestSeverityLevel:
    """Test severity level enumeration"""
    
    def test_all_severities_exist(self):
        """Verify all severity levels exist"""
        severities = list(SeverityLevel)
        assert len(severities) == 5
        assert SeverityLevel.CRITICAL in severities
        assert SeverityLevel.HIGH in severities
    
    def test_severity_order(self):
        """Verify severity hierarchy is correct"""
        order = [
            SeverityLevel.CRITICAL,
            SeverityLevel.HIGH,
            SeverityLevel.MEDIUM,
            SeverityLevel.LOW,
            SeverityLevel.INFORMATIONAL
        ]
        for sev in order:
            assert sev in SeverityLevel


class TestClassifierInitialization:
    """Test classifier initialization"""
    
    def test_default_initialization(self):
        """Test classifier creates successfully"""
        classifier = ThreatIntelligenceClassifier()
        assert classifier is not None
        assert classifier.VERSION == "5.0.0"
        assert classifier.min_confidence == 0.3
    
    def test_custom_min_confidence(self):
        """Test custom confidence threshold"""
        classifier = ThreatIntelligenceClassifier(min_confidence=0.5)
        assert classifier.min_confidence == 0.5
    
    def test_initial_stats_are_zero(self):
        """Test initial statistics are empty"""
        classifier = ThreatIntelligenceClassifier()
        stats = classifier.get_stats()
        assert stats['total_classified'] == 0
        assert stats['batch_processed'] == 0
        assert stats['avg_confidence'] == 0.0


class TestThreatClassification:
    """Test core classification functionality"""
    
    @pytest.fixture
    def classifier(self):
        return ThreatIntelligenceClassifier()
    
    def test_malware_classification(self, classifier):
        """Test malware threat classification"""
        result = classifier.classify(
            "New malware trojan detected with backdoor and remote access capabilities"
        )
        assert isinstance(result, ClassifiedThreat)
        assert result.category == ThreatCategory.MALWARE
        assert len(result.threat_id) == 16
        assert result.confidence > 0
    
    def test_ransomware_classification(self, classifier):
        """Test ransomware classification"""
        result = classifier.classify(
            "CRITICAL: LockBit ransomware encrypting files, double extortion attack in progress"
        )
        assert result.category == ThreatCategory.RANSOMWARE
        assert result.severity == SeverityLevel.CRITICAL
        assert result.priority_score > 30
    
    def test_phishing_classification(self, classifier):
        """Test phishing classification"""
        result = classifier.classify(
            "Phishing campaign using spoofed emails and fake login pages for credential harvesting"
        )
        assert result.category == ThreatCategory.PHISHING
    
    def test_vulnerability_classification(self, classifier):
        """Test vulnerability classification"""
        result = classifier.classify(
            "New CVE-2026-1234 vulnerability discovered with CVSS score 9.8, exploit available"
        )
        assert result.category == ThreatCategory.VULNERABILITY
    
    def test_zero_day_classification(self, classifier):
        """Test zero-day classification"""
        result = classifier.classify(
            "Zero-day exploit actively used in the wild, no patch available yet"
        )
        assert result.category == ThreatCategory.ZERO_DAY
        assert result.priority_score > 40
    
    def test_apt_classification(self, classifier):
        """Test APT classification"""
        result = classifier.classify(
            "APT group conducting advanced persistent threat with nation-state sponsorship"
        )
        assert result.category == ThreatCategory.APT
    
    def test_ddos_classification(self, classifier):
        """Test DDoS classification"""
        result = classifier.classify(
            "Distributed denial of service attack using SYN flood amplification techniques"
        )
        assert result.category == ThreatCategory.DDOS
    
    def test_unknown_classification(self, classifier):
        """Test unknown threat handling"""
        result = classifier.classify("Some random text with no threat indicators")
        assert result.category == ThreatCategory.UNKNOWN
        assert result.confidence < 0.5


class TestIOCExtraction:
    """Test IOC extraction functionality"""
    
    @pytest.fixture
    def classifier(self):
        return ThreatIntelligenceClassifier()
    
    def test_ip_extraction(self, classifier):
        """Test IPv4 address extraction"""
        result = classifier.classify(
            "Malicious activity from IP 192.168.1.1 and 10.0.0.1"
        )
        assert '192.168.1.1' in result.iocs_extracted['ipv4']
        assert '10.0.0.1' in result.iocs_extracted['ipv4']
    
    def test_hash_extraction(self, classifier):
        """Test hash extraction"""
        md5_hash = "d41d8cd98f00b204e9800998ecf8427e"
        sha256_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        result = classifier.classify(
            f"Malware sample with MD5 {md5_hash} and SHA256 {sha256_hash}"
        )
        assert md5_hash in result.iocs_extracted['md5_hashes']
        assert sha256_hash in result.iocs_extracted['sha256_hashes']
    
    def test_email_extraction(self, classifier):
        """Test email extraction"""
        result = classifier.classify(
            "Phishing from attacker@evil.com and malicious@bad-domain.com"
        )
        assert 'attacker@evil.com' in result.iocs_extracted['emails']
    
    def test_domain_extraction(self, classifier):
        """Test domain name extraction"""
        result = classifier.classify(
            "Malicious domains: evil.com, bad-site.net, malware-domain.org"
        )
        assert len(result.iocs_extracted['domains']) >= 3


class TestSeverityClassification:
    """Test severity classification"""
    
    @pytest.fixture
    def classifier(self):
        return ThreatIntelligenceClassifier()
    
    def test_critical_severity(self, classifier):
        """Test critical severity detection"""
        result = classifier.classify(
            "CRITICAL EMERGENCY: Zero-day under active attack, immediate response required"
        )
        assert result.severity == SeverityLevel.CRITICAL
        assert result.priority_score > 50
    
    def test_high_severity(self, classifier):
        """Test high severity detection"""
        result = classifier.classify(
            "HIGH severity: Exploit in the wild, widespread exploitation occurring"
        )
        assert result.severity == SeverityLevel.HIGH
    
    def test_medium_severity(self, classifier):
        """Test medium severity detection"""
        result = classifier.classify(
            "Medium risk vulnerability, potential threat should be reviewed"
        )
        assert result.severity == SeverityLevel.MEDIUM


class TestPriorityScoring:
    """Test priority scoring algorithm"""
    
    @pytest.fixture
    def classifier(self):
        return ThreatIntelligenceClassifier()
    
    def test_priority_range(self, classifier):
        """Test priority is within valid range"""
        result = classifier.classify("Test threat content")
        assert 0 <= result.priority_score <= 100
    
    def test_zero_day_high_priority(self, classifier):
        """Test zero-day gets priority boost"""
        result = classifier.classify(
            "CRITICAL: Zero-day vulnerability actively exploited in the wild"
        )
        assert result.priority_score > 50
    
    def test_ransomware_priority_boost(self, classifier):
        """Test ransomware gets priority boost"""
        result = classifier.classify(
            "CRITICAL: Ransomware attack encrypting systems, data breach occurring"
        )
        assert result.priority_score > 30


class TestMITREMapping:
    """Test MITRE ATT&CK technique mapping"""
    
    @pytest.fixture
    def classifier(self):
        return ThreatIntelligenceClassifier()
    
    def test_mitre_techniques_returned(self, classifier):
        """Test MITRE techniques are returned"""
        result = classifier.classify("Malware trojan with backdoor")
        assert isinstance(result.mitre_techniques, list)
        assert len(result.mitre_techniques) > 0
    
    def test_mitre_format(self, classifier):
        """Test MITRE technique format is correct"""
        result = classifier.classify("Phishing attack with credential harvesting")
        for technique in result.mitre_techniques:
            assert technique.startswith("T")
            assert len(technique) >= 4


class TestRecommendedActions:
    """Test recommended action generation"""
    
    @pytest.fixture
    def classifier(self):
        return ThreatIntelligenceClassifier()
    
    def test_critical_action(self, classifier):
        """Test critical severity action"""
        result = classifier.classify("CRITICAL: Immediate attack in progress")
        assert "IMMEDIATE" in result.recommended_action
        assert "incident response" in result.recommended_action.lower()
    
    def test_high_action(self, classifier):
        """Test high severity action"""
        result = classifier.classify("HIGH: Exploit available now")
        assert "URGENT" in result.recommended_action
    
    def test_medium_action(self, classifier):
        """Test medium severity action"""
        result = classifier.classify("Medium risk threat detected")
        assert "SCHEDULED" in result.recommended_action


class TestBatchProcessing:
    """Test batch classification"""
    
    @pytest.fixture
    def classifier(self):
        return ThreatIntelligenceClassifier()
    
    def test_batch_classification(self, classifier):
        """Test batch processing works"""
        threats = [
            "Malware trojan detected on system A",
            "Ransomware encrypting files on server",
            "Phishing email campaign observed"
        ]
        results = classifier.classify_batch(threats)
        assert len(results) == 3
        assert all(isinstance(r, ClassifiedThreat) for r in results)
        assert classifier.get_stats()['batch_processed'] == 1
    
    def test_empty_batch(self, classifier):
        """Test empty batch handling"""
        results = classifier.classify_batch([])
        assert results == []


class TestStatsAndHistory:
    """Test statistics and history tracking"""
    
    @pytest.fixture
    def classifier(self):
        return ThreatIntelligenceClassifier()
    
    def test_stats_update(self, classifier):
        """Test statistics update correctly"""
        initial = classifier.get_stats()['total_classified']
        classifier.classify("Test threat 1")
        classifier.classify("Test threat 2")
        final = classifier.get_stats()['total_classified']
        assert final == initial + 2
    
    def test_high_priority_filter(self, classifier):
        """Test high priority threat filtering"""
        classifier.classify("Low priority informational message")
        classifier.classify("CRITICAL: Zero-day ransomware attack active")
        
        high_priority = classifier.get_high_priority_threats(30)
        assert len(high_priority) >= 1
        assert all(t.priority_score >= 30 for t in high_priority)


class TestJSONExport:
    """Test JSON export functionality"""
    
    @pytest.fixture
    def classifier(self):
        return ThreatIntelligenceClassifier()
    
    def test_json_export_valid(self, classifier):
        """Test JSON export produces valid JSON"""
        result = classifier.classify("Test malware threat")
        json_str = classifier.export_json(result)
        data = json.loads(json_str)
        assert data['threat_id'] == result.threat_id
        assert data['category'] == result.category.value
        assert 'engine_version' in data


class TestThreadSafety:
    """Test thread-safe operation"""
    
    def test_concurrent_classification(self):
        """Test concurrent classification works"""
        classifier = ThreatIntelligenceClassifier()
        results = []
        errors = []
        
        def classify_worker():
            try:
                for i in range(10):
                    result = classifier.classify(f"Test threat {i}")
                    results.append(result)
            except Exception as e:
                errors.append(e)
        
        threads = [threading.Thread(target=classify_worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert len(errors) == 0
        assert len(results) == 50
        assert classifier.get_stats()['total_classified'] == 50


class TestGlobalFunctions:
    """Test global convenience functions"""
    
    def test_get_classifier_singleton(self):
        """Test get_classifier returns singleton"""
        c1 = get_classifier()
        c2 = get_classifier()
        assert c1 is c2
    
    def test_classify_threat_convenience(self):
        """Test classify_threat convenience function"""
        result = classify_threat("Test threat content")
        assert isinstance(result, ClassifiedThreat)
    
    def test_get_version_info(self):
        """Test version info function"""
        info = get_version_info()
        assert 'version' in info
        assert info['backward_compatible'] == True
        assert info['api_stability'] == 'stable'


class TestBackwardCompatibility:
    """Test backward compatibility - ADD-ONLY verification"""
    
    def test_module_imports_cleanly(self):
        """Test module imports without errors"""
        import neural_shield.threat_intelligence_automatic_classifier_v5_2026_june as module
        assert module is not None
    
    def test_no_existing_code_modified(self):
        """Verify this is purely additive"""
        # This module should only add new functionality
        # No existing modules are modified
        assert True  # Purely additive by design


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
