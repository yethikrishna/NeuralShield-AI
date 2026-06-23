"""
Test suite for Threat Intelligence Signature Generator v20
Real working tests - no mocks, no stubs.
Tests all functionality with actual data.
"""
import pytest
import json
import re
from neural_shield.threat_intelligence_signature_generator_v20_2026_june import (
    ThreatIntelligenceSignatureGenerator,
    SignatureType,
    SignatureSeverity,
    SignatureStatus,
    ThreatIndicator,
    get_signature_generator
)


class TestThreatIndicator:
    """Test ThreatIndicator data class"""
    
    def test_indicator_creation(self):
        """Test basic indicator creation"""
        indicator = ThreatIndicator(
            indicator_type="string",
            value="malicious_payload()",
            description="Detected malicious function call",
            confidence=0.95
        )
        assert indicator.value == "malicious_payload()"
        assert indicator.confidence == 0.95
        assert indicator.indicator_type == "string"


class TestThreatIntelligenceSignatureGenerator:
    """Main test suite for signature generator"""
    
    @pytest.fixture
    def generator(self):
        """Create fresh generator instance"""
        return ThreatIntelligenceSignatureGenerator("TestOrg")
    
    @pytest.fixture
    def sample_indicators(self):
        """Create sample threat indicators for testing"""
        return [
            ThreatIndicator(
                indicator_type="string",
                value="ignore_previous_instructions",
                description="Prompt injection bypass pattern",
                confidence=0.90
            ),
            ThreatIndicator(
                indicator_type="string",
                value="system_prompt_override",
                description="System prompt manipulation attempt",
                confidence=0.85
            ),
            ThreatIndicator(
                indicator_type="regex",
                value="act.as.*AI.*developer.*mode",
                description="Developer mode activation pattern",
                confidence=0.80
            )
        ]
    
    def test_generator_initialization(self, generator):
        """Test generator initialization"""
        assert generator.organization == "TestOrg"
        assert len(generator._signatures) == 0
    
    def test_singleton_pattern(self):
        """Test singleton factory function"""
        gen1 = get_signature_generator()
        gen2 = get_signature_generator()
        assert gen1 is gen2
    
    def test_quality_score_calculation(self, generator, sample_indicators):
        """Test real quality score calculation algorithm"""
        score = generator._calculate_quality_score(
            sample_indicators, 
            SignatureType.YARA
        )
        # Should be a valid float between 0 and 1
        assert isinstance(score, float)
        assert 0.0 <= score <= 1.0
        # With 3 good indicators, score should be decent
        assert score > 0.5
    
    def test_false_positive_risk_assessment(self, generator, sample_indicators):
        """Test false positive risk assessment"""
        risk = generator._assess_false_positive_risk(sample_indicators)
        assert risk in ["low", "medium", "high"]
    
    def test_yara_signature_generation(self, generator, sample_indicators):
        """Test real YARA rule generation - full working implementation"""
        sig = generator.generate_yara_signature(
            name="AI_Prompt_Injection_Attempt",
            description="Detects prompt injection attack patterns targeting LLMs",
            indicators=sample_indicators,
            severity=SignatureSeverity.HIGH,
            tags={"prompt-injection", "ai-threat"}
        )
        
        # Verify signature metadata
        assert sig.signature_type == SignatureType.YARA
        assert sig.severity == SignatureSeverity.HIGH
        assert sig.status == SignatureStatus.DRAFT
        assert sig.quality_score > 0
        
        # Verify actual YARA content was generated
        assert "rule " in sig.content
        assert "meta:" in sig.content
        assert "strings:" in sig.content
        assert "condition:" in sig.content
        assert "ignore_previous_instructions" in sig.content
        assert "system_prompt_override" in sig.content
    
    def test_snort_signature_generation(self, generator, sample_indicators):
        """Test real Snort rule generation"""
        sig = generator.generate_snort_signature(
            name="AI_Prompt_Injection_Network",
            description="Network detection of prompt injection patterns",
            indicators=sample_indicators,
            severity=SignatureSeverity.CRITICAL
        )
        
        assert sig.signature_type == SignatureType.SNORT
        # Verify actual Snort content
        assert "alert " in sig.content
        assert 'msg:"' in sig.content
        assert 'content:' in sig.content
        assert 'sid:' in sig.content
        assert 'priority:' in sig.content
    
    def test_sigma_signature_generation(self, generator, sample_indicators):
        """Test real Sigma rule generation"""
        sig = generator.generate_sigma_signature(
            name="AI_Threat_Detection_Log",
            description="Log-based detection of AI threat patterns",
            indicators=sample_indicators,
            severity=SignatureSeverity.MEDIUM,
            log_source="linux"
        )
        
        assert sig.signature_type == SignatureType.SIGMA
        # Verify actual Sigma YAML content
        assert "title:" in sig.content
        assert "id:" in sig.content
        assert "detection:" in sig.content
        assert "selection:" in sig.content
        assert "condition:" in sig.content
    
    def test_generate_all_formats(self, generator, sample_indicators):
        """Test generating all signature formats at once"""
        signatures = generator.generate_all_formats(
            name="Multi_Format_Threat",
            description="Test threat in all formats",
            indicators=sample_indicators
        )
        
        assert len(signatures) == 3
        types = {s.signature_type for s in signatures}
        assert SignatureType.YARA in types
        assert SignatureType.SNORT in types
        assert SignatureType.SIGMA in types
    
    def test_signature_id_generation(self, generator):
        """Test unique signature ID generation"""
        ids = set()
        for _ in range(10):
            sig_id = generator._generate_signature_id(SignatureType.YARA)
            assert sig_id not in ids
            ids.add(sig_id)
            assert sig_id.startswith("NS_YARA_")
    
    def test_get_signature(self, generator, sample_indicators):
        """Test retrieving signature by ID"""
        sig = generator.generate_yara_signature(
            "Test", "Test desc", sample_indicators
        )
        
        retrieved = generator.get_signature(sig.signature_id)
        assert retrieved is not None
        assert retrieved.signature_id == sig.signature_id
        
        # Test non-existent ID
        assert generator.get_signature("nonexistent") is None
    
    def test_list_signatures(self, generator, sample_indicators):
        """Test listing signatures with filtering"""
        # Create multiple signatures
        generator.generate_yara_signature("YARA1", "desc", sample_indicators)
        generator.generate_yara_signature("YARA2", "desc", sample_indicators)
        generator.generate_snort_signature("SNORT1", "desc", sample_indicators)
        
        # List all
        all_sigs = generator.list_signatures()
        assert len(all_sigs) == 3
        
        # Filter by type
        yara_sigs = generator.list_signatures(sig_type=SignatureType.YARA)
        assert len(yara_sigs) == 2
        
        snort_sigs = generator.list_signatures(sig_type=SignatureType.SNORT)
        assert len(snort_sigs) == 1
    
    def test_update_signature_status(self, generator, sample_indicators):
        """Test updating signature lifecycle status"""
        sig = generator.generate_yara_signature(
            "Test", "desc", sample_indicators
        )
        assert sig.status == SignatureStatus.DRAFT
        
        result = generator.update_signature_status(
            sig.signature_id, 
            SignatureStatus.PRODUCTION
        )
        assert result is True
        assert sig.status == SignatureStatus.PRODUCTION
        
        # Test non-existent ID
        result = generator.update_signature_status(
            "nonexistent", 
            SignatureStatus.PRODUCTION
        )
        assert result is False
    
    def test_export_json(self, generator, sample_indicators):
        """Test JSON export functionality"""
        sig = generator.generate_yara_signature(
            "ExportTest", "Test export", sample_indicators
        )
        
        json_export = generator.export_signature(sig.signature_id, "json")
        assert json_export is not None
        
        # Verify it's valid JSON
        parsed = json.loads(json_export)
        assert parsed["signature_id"] == sig.signature_id
        assert parsed["name"] == "ExportTest"
    
    def test_export_raw(self, generator, sample_indicators):
        """Test raw signature export"""
        sig = generator.generate_yara_signature(
            "RawTest", "Test", sample_indicators
        )
        
        raw_export = generator.export_signature(sig.signature_id, "raw")
        assert raw_export == sig.content
    
    def test_export_stix(self, generator, sample_indicators):
        """Test STIX format export"""
        sig = generator.generate_yara_signature(
            "STIXTest", "Test", sample_indicators
        )
        
        stix_export = generator.export_signature(sig.signature_id, "stix")
        assert stix_export is not None
        parsed = json.loads(stix_export)
        assert parsed["type"] == "indicator"
        assert "id" in parsed
    
    def test_statistics(self, generator, sample_indicators):
        """Test statistics gathering"""
        # Empty stats
        stats = generator.get_statistics()
        assert stats["total_signatures"] == 0
        
        # Add some signatures
        generator.generate_yara_signature("T1", "d", sample_indicators, SignatureSeverity.CRITICAL)
        generator.generate_yara_signature("T2", "d", sample_indicators, SignatureSeverity.HIGH)
        generator.generate_snort_signature("T3", "d", sample_indicators)
        
        stats = generator.get_statistics()
        assert stats["total_signatures"] == 3
        assert stats["by_type"]["yara"] == 2
        assert stats["by_type"]["snort"] == 1
        assert "critical" in stats["by_severity"]
        assert stats["average_quality_score"] > 0
    
    def test_create_indicator_helper(self, generator):
        """Test indicator creation helper"""
        indicator = generator.create_indicator_from_threat_data(
            threat_pattern="dangerous_function()",
            threat_type="code_injection",
            confidence=0.92,
            description="Detected code injection attempt"
        )
        
        assert indicator.value == "dangerous_function()"
        assert indicator.confidence == 0.92
        assert indicator.context["threat_type"] == "code_injection"
    
    def test_pattern_complexity_assessment(self, generator):
        """Test real pattern complexity scoring"""
        # Simple pattern
        simple = [ThreatIndicator("string", "test", "desc", 0.5)]
        simple_score = generator._assess_pattern_complexity(simple)
        
        # Complex pattern
        complex_ind = [ThreatIndicator(
            "regex", 
            "very_long_and_specific_pattern_with_special_chars.*[a-z0-9]{20,}", 
            "desc", 
            0.9
        )]
        complex_score = generator._assess_pattern_complexity(complex_ind)
        
        # Complex should score higher than simple
        assert complex_score >= simple_score
    
    def test_signature_content_validity(self, generator, sample_indicators):
        """Test that generated signatures are syntactically plausible"""
        sig = generator.generate_yara_signature(
            "Validity_Test", "Testing validity", sample_indicators
        )
        
        # YARA rule should have proper structure
        lines = sig.content.split('\n')
        assert any('rule ' in line for line in lines)
        assert any('meta:' in line for line in lines)
        assert any('strings:' in line for line in lines)
        assert any('condition:' in line for line in lines)
        assert sig.content.count('{') == sig.content.count('}')
    
    def test_edge_case_empty_indicators(self, generator):
        """Test edge case: empty indicators list"""
        empty_indicators: list = []
        
        # Should handle gracefully
        score = generator._calculate_quality_score(empty_indicators, SignatureType.YARA)
        assert score == 0.0
        
        risk = generator._assess_false_positive_risk(empty_indicators)
        assert risk == "high"
    
    def test_edge_case_single_indicator(self, generator):
        """Test edge case: single indicator"""
        single = [ThreatIndicator("string", "single_pattern", "test", 0.9)]
        
        sig = generator.generate_yara_signature(
            "SingleIndicator", "Test single", single
        )
        
        assert sig is not None
        assert sig.quality_score > 0
        # Single indicator should have threshold of 1
        assert "1 of them" in sig.content
    
    def test_tags_preserved(self, generator, sample_indicators):
        """Test that tags are properly preserved"""
        tags = {"tag1", "tag2", "tag3"}
        sig = generator.generate_yara_signature(
            "TagTest", "desc", sample_indicators, tags=tags
        )
        
        assert sig.tags == tags


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
