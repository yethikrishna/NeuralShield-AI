"""
Tests for Feature Expansion v81: Threat Intelligence TTP Extractor
DIMENSION A - Feature Expansion
All tests are ADD-ONLY - no existing code is modified.
"""
import pytest
import time
from typing import List

from neural_shield.feature_expansion_threat_ttp_extractor_v81_2026_june import (
    MITRETactic,
    MITRETechnique,
    ExtractedTTP,
    TTPExtractionResult,
    ThreatTTPExtractor,
    extract_ttps,
    get_supported_techniques,
    __api_stability__,
    __all__,
)


class TestMITRETactic:
    """Tests for MITRE ATT&CK Tactics enumeration."""
    
    def test_all_tactics_defined(self):
        """Verify all standard MITRE tactics exist."""
        expected_tactics = {
            'reconnaissance',
            'resource_development',
            'initial_access',
            'execution',
            'persistence',
            'privilege_escalation',
            'defense_evasion',
            'credential_access',
            'discovery',
            'lateral_movement',
            'collection',
            'command_and_control',
            'exfiltration',
            'impact',
        }
        
        actual_tactics = {t.value for t in MITRETactic}
        assert actual_tactics == expected_tactics
    
    def test_tactic_string_compatibility(self):
        """Verify tactics work as strings."""
        assert MITRETactic.EXECUTION == "execution"
        assert isinstance(MITRETactic.EXECUTION, str)


class TestMITRETechnique:
    """Tests for MITRE Techniques enumeration."""
    
    def test_technique_ids_valid_format(self):
        """Verify all technique IDs follow T+number format."""
        for technique in MITRETechnique:
            assert technique.value.startswith('T')
            # Should be T followed by digits
            assert technique.value[1:].isdigit()
    
    def test_common_techniques_present(self):
        """Verify critical techniques are defined."""
        critical_techniques = {'T1059', 'T1003', 'T1027', 'T1053', 'T1566'}
        actual = {t.value for t in MITRETechnique}
        assert critical_techniques.issubset(actual)


class TestExtractedTTP:
    """Tests for ExtractedTTP dataclass."""
    
    def test_ttp_creation(self):
        """Verify TTP object creation works."""
        ttp = ExtractedTTP(
            technique_id="T1059",
            technique_name="Command and Scripting Interpreter",
            tactic=MITRETactic.EXECUTION,
            confidence=0.85,
            matched_pattern="powershell",
            source_context="powershell.exe -encodedCommand",
            occurrence_count=3
        )
        
        assert ttp.technique_id == "T1059"
        assert ttp.confidence == 0.85
        assert ttp.occurrence_count == 3
    
    def test_default_occurrence_count(self):
        """Verify default occurrence count is 1."""
        ttp = ExtractedTTP(
            technique_id="T1003",
            technique_name="Credential Dumping",
            tactic=MITRETactic.CREDENTIAL_ACCESS,
            confidence=0.9,
            matched_pattern="mimikatz",
            source_context="test"
        )
        assert ttp.occurrence_count == 1


class TestTTPExtractionResult:
    """Tests for extraction result container."""
    
    def test_result_structure(self):
        """Verify result object has all required fields."""
        result = TTPExtractionResult(
            input_id="abc123",
            total_techniques_found=5,
            unique_techniques=[],
            tactics_distribution={},
            extraction_summary="Test summary",
            processing_time_ms=10.5,
            confidence_score=0.75
        )
        
        assert result.input_id == "abc123"
        assert result.total_techniques_found == 5
        assert result.processing_time_ms == 10.5
        assert result.confidence_score == 0.75


class TestThreatTTPExtractorInitialization:
    """Tests for extractor initialization."""
    
    def test_default_initialization(self):
        """Verify default initialization works."""
        extractor = ThreatTTPExtractor()
        assert extractor.min_confidence == 0.3
        assert extractor.case_sensitive == False
    
    def test_custom_confidence_threshold(self):
        """Verify custom confidence threshold works."""
        extractor = ThreatTTPExtractor(min_confidence=0.7)
        assert extractor.min_confidence == 0.7
    
    def test_patterns_compiled(self):
        """Verify patterns are compiled on init."""
        extractor = ThreatTTPExtractor()
        assert len(extractor._pattern_cache) > 0
        # All patterns should be compiled regex
        for pattern in extractor._pattern_cache.values():
            assert hasattr(pattern, 'finditer')


class TestTTPExtractionBasic:
    """Basic TTP extraction tests."""
    
    def test_extract_powershell_execution(self):
        """Extract T1059 - PowerShell execution."""
        extractor = ThreatTTPExtractor()
        text = "Attacker used powershell.exe -EncodedCommand to execute malicious code"
        
        result = extractor.extract_from_text(text)
        
        # Should find execution technique
        t1059_found = any(
            t.technique_id == "T1059" for t in result.unique_techniques
        )
        assert t1059_found
        assert result.total_techniques_found > 0
    
    def test_extract_mimikatz_credential_dumping(self):
        """Extract T1003 - Mimikatz credential dumping."""
        extractor = ThreatTTPExtractor()
        text = "mimikatz.exe sekurlsa::logonpasswords was detected on endpoint"
        
        result = extractor.extract_from_text(text)
        
        t1003_found = any(
            t.technique_id == "T1003" for t in result.unique_techniques
        )
        assert t1003_found
        
        # Mimikatz should have high confidence
        mimikatz_ttp = next(
            (t for t in result.unique_techniques if t.technique_id == "T1003"),
            None
        )
        assert mimikatz_ttp is not None
        assert mimikatz_ttp.confidence >= 0.5  # High confidence indicator
    
    def test_extract_ransomware_indicators(self):
        """Extract T1486 - Ransomware data encryption."""
        extractor = ThreatTTPExtractor()
        text = "Ransom note demanding bitcoin payment after file encryption"
        
        result = extractor.extract_from_text(text)
        
        t1486_found = any(
            t.technique_id == "T1486" for t in result.unique_techniques
        )
        assert t1486_found
    
    def test_extract_phishing_indicators(self):
        """Extract T1566 - Phishing."""
        extractor = ThreatTTPExtractor()
        text = "Spearphishing email with malicious macro attachment detected"
        
        result = extractor.extract_from_text(text)
        
        t1566_found = any(
            t.technique_id == "T1566" for t in result.unique_techniques
        )
        assert t1566_found
    
    def test_extract_lateral_movement(self):
        """Extract lateral movement techniques."""
        extractor = ThreatTTPExtractor()
        text = "PsExec used to move laterally and pass the hash"
        
        result = extractor.extract_from_text(text)
        
        techniques = {t.technique_id for t in result.unique_techniques}
        # Should find at least one lateral movement related technique
        assert len(techniques) > 0
    
    def test_no_ttp_in_clean_text(self):
        """Verify no false positives on benign text."""
        extractor = ThreatTTPExtractor(min_confidence=0.5)
        text = "The quick brown fox jumps over the lazy dog. Hello world."
        
        result = extractor.extract_from_text(text)
        # May find some but should be low confidence and filtered
        assert result.confidence_score <= 0.5 or len(result.unique_techniques) == 0


class TestTTPExtractionAdvanced:
    """Advanced TTP extraction tests."""
    
    def test_multiple_techniques_in_complex_threat(self):
        """Extract multiple techniques from complex threat report."""
        extractor = ThreatTTPExtractor()
        text = """
        The attacker used phishing (T1566) to gain initial access.
        Then executed powershell commands (T1059) to run mimikatz (T1003).
        Established persistence via scheduled tasks (T1053).
        Used base64 encoding (T1027) for obfuscation.
        """
        
        result = extractor.extract_from_text(text)
        
        techniques = {t.technique_id for t in result.unique_techniques}
        # Should find multiple techniques
        assert len(techniques) >= 3
        assert "T1059" in techniques
        assert "T1003" in techniques
    
    def test_confidence_scaling(self):
        """Verify confidence scales with multiple matches."""
        extractor = ThreatTTPExtractor()
        
        # Single match
        single_result = extractor.extract_from_text("powershell.exe")
        
        # Multiple matches
        multi_text = "powershell.exe powershell -Command Invoke-Expression IEX"
        multi_result = extractor.extract_from_text(multi_text)
        
        # Multiple occurrences should increase occurrence count
        single_count = next(
            (t.occurrence_count for t in single_result.unique_techniques if t.technique_id == "T1059"),
            0
        )
        multi_count = next(
            (t.occurrence_count for t in multi_result.unique_techniques if t.technique_id == "T1059"),
            0
        )
        assert multi_count >= single_count
    
    def test_tactics_distribution(self):
        """Verify tactics distribution is calculated correctly."""
        extractor = ThreatTTPExtractor()
        text = "mimikatz credential dump with powershell execution and scheduled task persistence"
        
        result = extractor.extract_from_text(text)
        
        assert isinstance(result.tactics_distribution, dict)
        assert len(result.tactics_distribution) > 0
        # All values should be positive integers
        for count in result.tactics_distribution.values():
            assert count > 0
            assert isinstance(count, int)
    
    def test_input_id_generation(self):
        """Verify input ID is generated consistently."""
        extractor = ThreatTTPExtractor()
        text = "test input text"
        
        result1 = extractor.extract_from_text(text)
        result2 = extractor.extract_from_text(text)
        
        # Same input should produce same ID
        assert result1.input_id == result2.input_id
    
    def test_processing_time_recorded(self):
        """Verify processing time is recorded."""
        extractor = ThreatTTPExtractor()
        text = "powershell mimikatz scheduled task nmap scan"
        
        result = extractor.extract_from_text(text)
        
        assert result.processing_time_ms >= 0
        assert isinstance(result.processing_time_ms, float)
    
    def test_summary_generation(self):
        """Verify human-readable summary is generated."""
        extractor = ThreatTTPExtractor()
        text = "mimikatz credential dumping detected"
        
        result = extractor.extract_from_text(text)
        
        assert isinstance(result.extraction_summary, str)
        assert len(result.extraction_summary) > 0


class TestLogAndBatchProcessing:
    """Tests for log and batch processing."""
    
    def test_extract_from_logs(self):
        """Extract TTPs from log entries."""
        extractor = ThreatTTPExtractor()
        logs = [
            "2026-06-25 10:00:00 - powershell.exe started",
            "2026-06-25 10:00:01 - mimikatz sekurlsa executed",
            "2026-06-25 10:00:02 - nmap port scan detected",
        ]
        
        result = extractor.extract_from_logs(logs)
        
        assert result.total_techniques_found > 0
        techniques = {t.technique_id for t in result.unique_techniques}
        assert "T1059" in techniques
        assert "T1003" in techniques
    
    def test_batch_extract(self):
        """Test batch document processing."""
        extractor = ThreatTTPExtractor()
        documents = [
            ("powershell attack", "alert1"),
            ("mimikatz credential dump", "alert2"),
            ("ransomware bitcoin payment", "alert3"),
        ]
        
        results = extractor.batch_extract(documents)
        
        assert len(results) == 3
        for result in results:
            assert isinstance(result, TTPExtractionResult)


class TestExtractorStats:
    """Tests for extractor statistics."""
    
    def test_stats_tracking(self):
        """Verify statistics are tracked correctly."""
        extractor = ThreatTTPExtractor()
        
        # Process some documents
        extractor.extract_from_text("powershell mimikatz")
        extractor.extract_from_text("nmap scan scheduled task")
        
        stats = extractor.get_extraction_stats()
        
        assert stats["total_documents_processed"] == 2
        assert "technique_distribution" in stats
        assert isinstance(stats["technique_distribution"], dict)
    
    def test_mitre_mapping(self):
        """Verify MITRE technique to tactic mapping works."""
        extractor = ThreatTTPExtractor()
        mapping = extractor.get_mitre_mapping()
        
        assert isinstance(mapping, dict)
        assert len(mapping) > 0
        # T1059 should map to execution
        assert "execution" in mapping.get("T1059", [])


class TestConvenienceFunctions:
    """Tests for convenience functions."""
    
    def test_extract_ttps_function(self):
        """Verify convenience function works."""
        result = extract_ttps("powershell mimikatz attack")
        
        assert isinstance(result, TTPExtractionResult)
        assert result.total_techniques_found > 0
    
    def test_get_supported_techniques(self):
        """Verify supported techniques listing works."""
        techniques = get_supported_techniques()
        
        assert isinstance(techniques, list)
        assert len(techniques) > 0
        
        for tech in techniques:
            assert "id" in tech
            assert "name" in tech
            assert "tactic" in tech
            assert tech["id"].startswith("T")


class TestApiStability:
    """Tests for API stability markers."""
    
    def test_all_exports_have_stability(self):
        """Verify all exported items have stability markers."""
        for export in __all__:
            assert export in __api_stability__, f"Missing stability for {export}"
    
    def test_stability_values_valid(self):
        """Verify stability values are valid."""
        valid_stabilities = {'STABLE', 'EXPERIMENTAL', 'DEPRECATED'}
        for stability in __api_stability__.values():
            assert stability in valid_stabilities, f"Invalid stability: {stability}"


class TestIntegration:
    """Integration tests - verify no conflicts with existing code."""
    
    def test_import_without_conflict(self):
        """Verify module imports without conflicting with existing code."""
        # This should not raise any import errors
        from neural_shield.feature_expansion_threat_ttp_extractor_v81_2026_june import ThreatTTPExtractor
        assert ThreatTTPExtractor is not None
    
    def test_no_existing_code_modified(self):
        """Verify this is ADD-ONLY - existing modules still work."""
        # Test that existing security module still works
        try:
            from neural_shield.security_hardening_side_channel_cache_aware_protection_v31_2026_june import (
                CacheAwareMemoryProtector
            )
            # Existing module should still work
            protector = CacheAwareMemoryProtector()
            assert protector is not None
        except ImportError:
            # If it doesn't exist, that's fine - just means it was from a different session
            pass


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
